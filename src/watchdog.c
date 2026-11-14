// Note: _GNU_SOURCE is provided by the Makefile via -D_GNU_SOURCE.
//
// Phase 2 — parent-side watchdog thread: wall-clock timeout enforcement
// and cgroup v2 resource monitoring.  See include/watchdog.h for the
// lifecycle contract.
//
// Threading model:
//   * `running`, the result flags, and the last-observed stats are all
//     protected by ctx->mutex.
//   * The poll wait uses pthread_cond_timedwait() so watchdog_stop()
//     interrupts it immediately instead of waiting out a sleep().
//   * Timers use CLOCK_MONOTONIC.  On Linux the condvar is explicitly
//     configured with CLOCK_MONOTONIC too; other platforms fall back to
//     the default condvar clock (the timeout wait is then converted).
//   * Event callbacks are invoked WITHOUT the context lock held.  The
//     Phase 3 logger may write to a file and must never deadlock against
//     watchdog_get_stats()/watchdog_stop().

#include "watchdog.h"
#include "cgroups.h"   /* read_cgroup_stats() from libprocfs */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WD_NS_PER_SEC      1000000000LL
#define WD_US_PER_SEC      1000000LL
#define WD_MAX_POLL_EVENTS 4

/* One deferred event-callback invocation.  Built while the context lock
 * is held, emitted after it is released. */
typedef struct {
    const char *type;
    char        details[256];
} wd_event_t;

/* ------------------------------------------------------------------ */
/* Small time helpers                                                  */
/* ------------------------------------------------------------------ */

static clockid_t wd_mono_clock(void)
{
    return CLOCK_MONOTONIC;
}

static clockid_t wd_cond_clock(void)
{
#ifdef __linux__
    return CLOCK_MONOTONIC;
#else
    /* macOS/BSD lack pthread_condattr_setclock(CLOCK_MONOTONIC). */
    return CLOCK_REALTIME;
#endif
}

static void wd_clock_get(clockid_t clock, struct timespec *ts)
{
    if (clock_gettime(clock, ts) != 0) {
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    }
}

static bool wd_timespec_is_zero(const struct timespec *ts)
{
    return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

static double wd_diff_seconds(const struct timespec *later,
                              const struct timespec *earlier)
{
    return (double)(later->tv_sec - earlier->tv_sec) +
           (double)(later->tv_nsec - earlier->tv_nsec) / 1e9;
}

static int64_t wd_diff_usec(const struct timespec *later,
                            const struct timespec *earlier)
{
    int64_t sec  = (int64_t)later->tv_sec - (int64_t)earlier->tv_sec;
    int64_t nsec = (int64_t)later->tv_nsec - (int64_t)earlier->tv_nsec;
    return sec * WD_US_PER_SEC + nsec / 1000;
}

static void wd_add_ms(struct timespec *ts, uint32_t ms)
{
    ts->tv_sec  += (time_t)(ms / 1000);
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    while (ts->tv_nsec >= WD_NS_PER_SEC) {
        ts->tv_nsec -= WD_NS_PER_SEC;
        ts->tv_sec++;
    }
}

static void wd_add_seconds(struct timespec *ts, uint32_t seconds)
{
    ts->tv_sec += (time_t)seconds;
}

static bool wd_timespec_after(const struct timespec *a,
                              const struct timespec *b)
{
    if (a->tv_sec != b->tv_sec) return a->tv_sec > b->tv_sec;
    return a->tv_nsec > b->tv_nsec;
}

static uint32_t wd_poll_interval_ms(const watchdog_context_t *ctx)
{
    if (ctx->poll_interval_ms == 0)
        return WATCHDOG_POLL_INTERVAL_MS;
    if (ctx->poll_interval_ms < WATCHDOG_MIN_POLL_INTERVAL_MS)
        return WATCHDOG_MIN_POLL_INTERVAL_MS;
    if (ctx->poll_interval_ms > WATCHDOG_MAX_POLL_INTERVAL_MS)
        return WATCHDOG_MAX_POLL_INTERVAL_MS;
    return ctx->poll_interval_ms;
}

/* ------------------------------------------------------------------ */
/* Statistics / OOM helpers                                            */
/* ------------------------------------------------------------------ */

/*
 * Read the cgroup's memory.events `oom_kill` counter.  libprocfs does
 * not expose memory.events, so parse the two-column key/value file
 * here.  Returns -1 when the file cannot be read.
 */
static int wd_read_oom_kill(const char *cgroup_path, uint64_t *out)
{
    if (!cgroup_path || !out || cgroup_path[0] == '\0') return -1;

    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/memory.events", cgroup_path);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[128];
    int found = 0;
    uint64_t value = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long v = 0;
        if (sscanf(line, "oom_kill %llu", &v) == 1) {
            value = (uint64_t)v;
            found = 1;
            break;
        }
    }
    fclose(fp);
    if (!found) return -1;
    *out = value;
    return 0;
}

/* Refresh the cached stats.  Best-effort: a missing/unreadable cgroup
 * leaves the cache unchanged except for fields the read did fill. */
static void wd_refresh_stats_locked(watchdog_context_t *ctx)
{
    if (ctx->cgroup_path[0] == '\0') return;

    cgroup_stats_t stats;
    if (read_cgroup_stats(ctx->cgroup_path, &stats) != 0) return;

    ctx->memory_current_bytes = stats.memory_current_bytes;
    ctx->memory_peak_bytes    = stats.memory_peak_bytes;
    ctx->memory_max_bytes     = stats.memory_max_bytes;
    ctx->cpu_usage_usec       = stats.cpu_usage_usec;
    ctx->pids_current         = stats.pids_current;
    ctx->pids_max             = stats.pids_max;

    uint64_t oom = 0;
    if (wd_read_oom_kill(ctx->cgroup_path, &oom) == 0) {
        if (oom > ctx->last_oom_kill) {
            uint64_t delta = oom - ctx->last_oom_kill;
            ctx->oom_detected = true;
            ctx->oom_kill_count += delta;
        }
        ctx->last_oom_kill = oom;
    }
}

/* ------------------------------------------------------------------ */
/* Threshold logic (caller holds ctx->mutex)                           */
/* ------------------------------------------------------------------ */

static void wd_event_add(wd_event_t *events, int *count, int max,
                         const char *type, const char *fmt, ...)
{
    if (*count >= max) return;
    wd_event_t *ev = &events[*count];
    ev->type = type;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ev->details, sizeof(ev->details), fmt, ap);
    va_end(ap);
    (*count)++;
}

/*
 * One poll evaluation.  `events` collects at most `max_events` threshold
 * notifications for the caller to emit after unlocking.
 */
static void wd_poll_locked(watchdog_context_t *ctx,
                           wd_event_t *events, int *event_count, int max_events)
{
    struct timespec now;
    wd_clock_get(wd_mono_clock(), &now);

    wd_refresh_stats_locked(ctx);

    /* ---- memory threshold ---------------------------------------- */
    if (ctx->memory_warning_threshold > 0.0 &&
        ctx->memory_max_bytes != 0 &&
        ctx->memory_max_bytes != UINT64_MAX) {
        double ratio = (double)ctx->memory_current_bytes /
                       (double)ctx->memory_max_bytes;
        if (ratio >= ctx->memory_warning_threshold) {
            if (!ctx->memory_breach_logged) {
                ctx->memory_breach_logged = true;
                ctx->memory_breach_count++;
                wd_event_add(events, event_count, max_events,
                             "resource_breach",
                             "resource=memory current=%llu limit=%llu "
                             "threshold=%.2f percentage=%.3f",
                             (unsigned long long)ctx->memory_current_bytes,
                             (unsigned long long)ctx->memory_max_bytes,
                             ctx->memory_warning_threshold,
                             ratio * 100.0);
            }
        } else {
            /* Re-arm for a later spike after usage falls back. */
            ctx->memory_breach_logged = false;
        }
    }

    /* ---- CPU sustained threshold --------------------------------- */
    if (ctx->cpu_warning_threshold > 0.0 &&
        ctx->cpu_warning_duration_ms > 0) {
        if (ctx->have_last_poll) {
            int64_t wall_usec = wd_diff_usec(&now, &ctx->last_poll_time);
            if (wall_usec > 0) {
                double cpu = 0.0;
                if (ctx->cpu_usage_usec >= ctx->last_cpu_usage_usec) {
                    int64_t cpu_usec = (int64_t)(ctx->cpu_usage_usec -
                                                 ctx->last_cpu_usage_usec);
                    cpu = (double)cpu_usec / (double)wall_usec;
                    if (cpu > 1.0) cpu = 1.0;
                } else {
                    /* Counter reset / cgroup re-created: reseed. */
                    cpu = 0.0;
                }

                if (cpu >= ctx->cpu_warning_threshold) {
                    uint64_t elapsed_ms =
                        (uint64_t)(wall_usec / 1000);
                    if (elapsed_ms == 0) elapsed_ms = 1;
                    ctx->cpu_high_duration_ms += elapsed_ms;

                    if (ctx->cpu_high_duration_ms >=
                            ctx->cpu_warning_duration_ms &&
                        !ctx->cpu_breach_logged) {
                        ctx->cpu_breach_logged = true;
                        ctx->cpu_breach_count++;
                        wd_event_add(events, event_count, max_events,
                                     "resource_breach",
                                     "resource=cpu cpu=%.3f threshold=%.2f "
                                     "held=%llums",
                                     cpu, ctx->cpu_warning_threshold,
                                     (unsigned long long)
                                         ctx->cpu_high_duration_ms);
                    }
                } else {
                    ctx->cpu_high_duration_ms = 0;
                    ctx->cpu_breach_logged = false;
                }
            }
        }
        ctx->last_poll_time = now;
        ctx->last_cpu_usage_usec = ctx->cpu_usage_usec;
        ctx->have_last_poll = true;
    }
}

static void wd_emit_events(watchdog_context_t *ctx,
                           const wd_event_t *events, int count)
{
    if (!ctx->event_cb) return;
    for (int i = 0; i < count; i++) {
        ctx->event_cb(events[i].type, events[i].details,
                      ctx->event_userdata);
    }
}

/* ------------------------------------------------------------------ */
/* Timeout / kill sequence                                             */
/* ------------------------------------------------------------------ */

/* P2.10: SIGTERM goes to the child (the --init supervisor forwards it).
 * SIGKILL prefers cgroup.kill so descendants cannot survive, then falls
 * back to a direct PID kill.  Best-effort: ESRCH is not an error. */
static int wd_kill_container(watchdog_context_t *ctx, int sig)
{
    if (!ctx || ctx->child_pid <= 0) return -1;

    if (sig == SIGKILL && ctx->cgroup_path[0] != '\0') {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/cgroup.kill",
                         ctx->cgroup_path);
        if (n > 0 && (size_t)n < sizeof(path)) {
            int fd = open(path, O_WRONLY | O_CLOEXEC);
            if (fd >= 0) {
                ssize_t wrote = write(fd, "1", 1);
                close(fd);
                if (wrote == 1) return 0;
            }
        }
    }

    return kill(ctx->child_pid, sig);
}

/*
 * SIGTERM -> interruptible grace wait -> SIGKILL.  `running` remains
 * true during the grace wait so watchdog_stop() can interrupt it; when
 * stop wins the race (the child exited normally after SIGTERM) no
 * SIGKILL is sent.  Emits exactly one timeout_kill event at the end.
 */
static void wd_initiate_timeout_kill(watchdog_context_t *ctx)
{
    struct timespec now;
    wd_clock_get(wd_mono_clock(), &now);

    pthread_mutex_lock(&ctx->mutex);
    if (ctx->timeout_killed) {
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }
    ctx->timeout_killed = true;
    uint32_t timeout_seconds = ctx->timeout_seconds;
    uint32_t grace_seconds   = ctx->grace_period_seconds;
    double elapsed = wd_diff_seconds(&now, &ctx->start_time);
    pthread_mutex_unlock(&ctx->mutex);

    if (ctx->enable_debug) {
        fprintf(stderr,
                "[watchdog] timeout exceeded after %.3fs; sending SIGTERM\n",
                elapsed);
    }

    if (wd_kill_container(ctx, SIGTERM) < 0 && errno == ESRCH) {
        pthread_mutex_lock(&ctx->mutex);
        ctx->timeout_race_resolved = true;
        ctx->running = false;
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }

    /* Interruptible grace period.  The deadline uses the condvar clock. */
    struct timespec deadline;
    wd_clock_get(wd_cond_clock(), &deadline);
    wd_add_seconds(&deadline, grace_seconds);

    pthread_mutex_lock(&ctx->mutex);
    while (ctx->running) {
        struct timespec now_cond;
        wd_clock_get(wd_cond_clock(), &now_cond);
        if (!wd_timespec_after(&deadline, &now_cond)) break;

        struct timespec wait_for = deadline;
        int rc = pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &wait_for);
        if (rc == ETIMEDOUT) break;
    }
    bool stop_requested = !ctx->running;
    pthread_mutex_unlock(&ctx->mutex);

    bool used_grace = false;
    bool race_resolved = false;
    if (!stop_requested) {
        if (kill(ctx->child_pid, 0) == 0) {
            if (wd_kill_container(ctx, SIGKILL) == 0) {
                used_grace = true;
            }
        } else if (errno == ESRCH) {
            race_resolved = true;
        }
    } else {
        /* Container exited (or stop was requested) during the grace
         * period: no SIGKILL.  Distinguish a clean race from a lost
         * child where possible. */
        race_resolved = (kill(ctx->child_pid, 0) < 0 && errno == ESRCH);
    }

    pthread_mutex_lock(&ctx->mutex);
    ctx->grace_period_used    = used_grace;
    ctx->timeout_race_resolved = race_resolved;
    ctx->running = false;
    pthread_mutex_unlock(&ctx->mutex);

    if (ctx->enable_debug && used_grace) {
        fprintf(stderr,
                "[watchdog] child still alive after %us grace; sent SIGKILL\n",
                (unsigned)grace_seconds);
    }

    if (ctx->event_cb) {
        char details[256];
        snprintf(details, sizeof(details),
                 "timeout_seconds=%u elapsed_seconds=%.3f signal=%s "
                 "grace_period_used=%s",
                 (unsigned)timeout_seconds, elapsed,
                 used_grace ? "SIGKILL" : "SIGTERM",
                 used_grace ? "true" : "false");
        ctx->event_cb("timeout_kill", details, ctx->event_userdata);
    }
}

/* ------------------------------------------------------------------ */
/* Thread                                                              */
/* ------------------------------------------------------------------ */

static void *watchdog_thread_func(void *arg)
{
    watchdog_context_t *ctx = (watchdog_context_t *)arg;
    uint32_t poll_ms = wd_poll_interval_ms(ctx);

    for (;;) {
        struct timespec now;
        wd_clock_get(wd_mono_clock(), &now);

        pthread_mutex_lock(&ctx->mutex);
        if (!ctx->running) {
            pthread_mutex_unlock(&ctx->mutex);
            break;
        }

        /* Wake on the next poll, the timeout deadline, or an explicit
         * stop signal — whichever comes first. */
        struct timespec wake;
        wd_clock_get(wd_cond_clock(), &wake);
        wd_add_ms(&wake, poll_ms);

        bool timeout_due = false;
        if (ctx->timeout_seconds > 0 && !ctx->timeout_killed) {
            double elapsed = wd_diff_seconds(&now, &ctx->start_time);
            if (elapsed >= (double)ctx->timeout_seconds) {
                timeout_due = true;
            } else {
                uint32_t remaining_ms =
                    (uint32_t)(((double)ctx->timeout_seconds - elapsed) *
                               1000.0);
                struct timespec timeout_wake;
                wd_clock_get(wd_cond_clock(), &timeout_wake);
                wd_add_ms(&timeout_wake, remaining_ms);
                if (wd_timespec_after(&wake, &timeout_wake)) {
                    wake = timeout_wake;
                }
            }
        }
        pthread_mutex_unlock(&ctx->mutex);

        if (timeout_due) {
            wd_initiate_timeout_kill(ctx);
            break;
        }

        pthread_mutex_lock(&ctx->mutex);
        if (!ctx->running) {
            pthread_mutex_unlock(&ctx->mutex);
            break;
        }
        int rc = pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &wake);
        bool running = ctx->running;
        pthread_mutex_unlock(&ctx->mutex);

        if (!running) break;
        if (rc != 0 && rc != ETIMEDOUT) {
            /* Spurious/other wakeup: poll anyway, then loop. */
        }

        /* Re-check the timeout immediately (cond wait may have been
         * signalled early) and then poll cgroup stats. */
        wd_clock_get(wd_mono_clock(), &now);
        pthread_mutex_lock(&ctx->mutex);
        bool fire_timeout = false;
        if (ctx->timeout_seconds > 0 && !ctx->timeout_killed) {
            double elapsed = wd_diff_seconds(&now, &ctx->start_time);
            fire_timeout = elapsed >= (double)ctx->timeout_seconds;
        }
        pthread_mutex_unlock(&ctx->mutex);

        if (fire_timeout) {
            wd_initiate_timeout_kill(ctx);
            break;
        }

        wd_event_t events[WD_MAX_POLL_EVENTS];
        int event_count = 0;

        pthread_mutex_lock(&ctx->mutex);
        if (ctx->running) {
            wd_poll_locked(ctx, events, &event_count, WD_MAX_POLL_EVENTS);
        }
        pthread_mutex_unlock(&ctx->mutex);

        wd_emit_events(ctx, events, event_count);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int watchdog_start(watchdog_context_t *ctx)
{
    if (!ctx) return -1;
    if (ctx->child_pid <= 0) {
        ctx->error_code = EINVAL;
        snprintf(ctx->error_message, sizeof(ctx->error_message),
                 "watchdog_start: invalid child_pid %d", (int)ctx->child_pid);
        return -1;
    }

    if (!ctx->mutex_initialized) {
        int rc = pthread_mutex_init(&ctx->mutex, NULL);
        if (rc != 0) {
            ctx->error_code = rc;
            snprintf(ctx->error_message, sizeof(ctx->error_message),
                     "pthread_mutex_init failed: %s", strerror(rc));
            return -1;
        }
        ctx->mutex_initialized = true;
    }

    if (!ctx->cond_initialized) {
        pthread_condattr_t attr;
        int rc = pthread_condattr_init(&attr);
        if (rc != 0) {
            ctx->error_code = rc;
            snprintf(ctx->error_message, sizeof(ctx->error_message),
                     "pthread_condattr_init failed: %s", strerror(rc));
            return -1;
        }
#ifdef __linux__
        rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        if (rc != 0) {
            pthread_condattr_destroy(&attr);
            ctx->error_code = rc;
            snprintf(ctx->error_message, sizeof(ctx->error_message),
                     "pthread_condattr_setclock failed: %s", strerror(rc));
            return -1;
        }
#endif
        rc = pthread_cond_init(&ctx->cond, &attr);
        pthread_condattr_destroy(&attr);
        if (rc != 0) {
            ctx->error_code = rc;
            snprintf(ctx->error_message, sizeof(ctx->error_message),
                     "pthread_cond_init failed: %s", strerror(rc));
            return -1;
        }
        ctx->cond_initialized = true;
    }

    pthread_mutex_lock(&ctx->mutex);
    if (ctx->thread_started) {
        pthread_mutex_unlock(&ctx->mutex);
        return 0;   /* already running */
    }
    if (wd_timespec_is_zero(&ctx->start_time)) {
        wd_clock_get(wd_mono_clock(), &ctx->start_time);
    }
    ctx->running = true;
    pthread_mutex_unlock(&ctx->mutex);

    int rc = pthread_create(&ctx->thread, NULL, watchdog_thread_func, ctx);
    if (rc != 0) {
        pthread_mutex_lock(&ctx->mutex);
        ctx->running = false;
        pthread_mutex_unlock(&ctx->mutex);
        ctx->error_code = rc;
        snprintf(ctx->error_message, sizeof(ctx->error_message),
                 "pthread_create failed: %s", strerror(rc));
        return -1;
    }

    pthread_mutex_lock(&ctx->mutex);
    ctx->thread_started = true;
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

void watchdog_stop(watchdog_context_t *ctx)
{
    if (!ctx || !ctx->mutex_initialized) return;

    pthread_mutex_lock(&ctx->mutex);
    ctx->running = false;
    bool started = ctx->thread_started;
    ctx->thread_started = false;
    if (ctx->cond_initialized) {
        pthread_cond_broadcast(&ctx->cond);
    }
    pthread_mutex_unlock(&ctx->mutex);

    if (started) {
        pthread_join(ctx->thread, NULL);
    }
}

void watchdog_free(watchdog_context_t *ctx)
{
    if (!ctx) return;
    watchdog_stop(ctx);
    if (ctx->cond_initialized) {
        pthread_cond_destroy(&ctx->cond);
        ctx->cond_initialized = false;
    }
    if (ctx->mutex_initialized) {
        pthread_mutex_destroy(&ctx->mutex);
        ctx->mutex_initialized = false;
    }
    free(ctx);
}

bool watchdog_was_timeout_killed(const watchdog_context_t *ctx)
{
    if (!ctx) return false;
    if (ctx->mutex_initialized) {
        watchdog_context_t *mutable_ctx = (watchdog_context_t *)ctx;
        pthread_mutex_lock(&mutable_ctx->mutex);
        bool ret = ctx->timeout_killed;
        pthread_mutex_unlock(&mutable_ctx->mutex);
        return ret;
    }
    return ctx->timeout_killed;
}

void watchdog_get_stats(const watchdog_context_t *ctx, watchdog_stats_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!ctx) return;

    if (ctx->mutex_initialized) {
        watchdog_context_t *mutable_ctx = (watchdog_context_t *)ctx;
        pthread_mutex_lock(&mutable_ctx->mutex);
    }

    out->memory_current_bytes  = ctx->memory_current_bytes;
    out->memory_peak_bytes     = ctx->memory_peak_bytes;
    out->memory_max_bytes      = ctx->memory_max_bytes;
    out->cpu_usage_usec        = ctx->cpu_usage_usec;
    out->pids_current          = ctx->pids_current;
    out->pids_max              = ctx->pids_max;
    out->cpu_high_duration_ms  = ctx->cpu_high_duration_ms;
    out->memory_breach_count   = ctx->memory_breach_count;
    out->cpu_breach_count      = ctx->cpu_breach_count;
    out->oom_kill_count        = ctx->oom_kill_count;
    out->timeout_killed        = ctx->timeout_killed;
    out->grace_period_used     = ctx->grace_period_used;
    out->timeout_race_resolved = ctx->timeout_race_resolved;
    out->oom_detected          = ctx->oom_detected;
    out->error_code            = ctx->error_code;
    memcpy(out->error_message, ctx->error_message,
           sizeof(out->error_message));

    if (ctx->mutex_initialized) {
        watchdog_context_t *mutable_ctx = (watchdog_context_t *)ctx;
        pthread_mutex_unlock(&mutable_ctx->mutex);
    }
}

void watchdog_set_event_callback(watchdog_context_t *ctx,
                                 watchdog_event_cb cb,
                                 void *userdata)
{
    if (!ctx) return;
    if (ctx->mutex_initialized) {
        pthread_mutex_lock(&ctx->mutex);
        ctx->event_cb = cb;
        ctx->event_userdata = userdata;
        pthread_mutex_unlock(&ctx->mutex);
    } else {
        ctx->event_cb = cb;
        ctx->event_userdata = userdata;
    }
}

int watchdog_poll_once(watchdog_context_t *ctx)
{
    if (!ctx) return -1;

    wd_event_t events[WD_MAX_POLL_EVENTS];
    int event_count = 0;
    bool locked = ctx->mutex_initialized;

    if (locked) pthread_mutex_lock(&ctx->mutex);
    wd_poll_locked(ctx, events, &event_count, WD_MAX_POLL_EVENTS);
    if (locked) pthread_mutex_unlock(&ctx->mutex);

    wd_emit_events(ctx, events, event_count);
    return 0;
}

void watchdog_finalize_stats(watchdog_context_t *ctx)
{
    if (!ctx) return;

    bool locked = ctx->mutex_initialized;
    if (locked) pthread_mutex_lock(&ctx->mutex);

    /* Final stats read, but no threshold events: the container has
     * already exited, so a breach notification would be noise. */
    wd_refresh_stats_locked(ctx);

    if (locked) pthread_mutex_unlock(&ctx->mutex);
}
