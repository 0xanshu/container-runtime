#ifndef WATCHDOG_H
#define WATCHDOG_H

/*
 * Phase 2 — wall-clock timeout + cgroup resource watchdog.
 *
 * The watchdog runs in a parent-side pthread after clone(2).  It owns:
 *
 *   - wall-clock timeout enforcement: SIGTERM, grace period, SIGKILL
 *   - cgroup v2 polling: memory/CPU/PIDs stats + memory.events OOM count
 *   - threshold detection: memory ratio, sustained CPU, OOM
 *
 * It must never fail the container because monitoring failed: cgroup
 * reads are best-effort and a timeout-only run works with no cgroup.
 *
 * Lifecycle:
 *
 *   watchdog_context_t *wd = calloc(1, sizeof(*wd));
 *   wd->child_pid = pid;
 *   ...
 *   watchdog_start(wd);          // after clone, on the success path
 *   ...
 *   watchdog_stop(wd);           // after waitpid, before cgroup removal
 *   watchdog_finalize_stats(wd); // final OOM/stat read before removal
 *   watchdog_free(wd);           // in container_cleanup
 *
 * watchdog_start() is never called before clone: the child would inherit
 * pthread state.  Detached runs do not start a watchdog (the parent is
 * gone), and the CLI warns when a timeout is configured for `start`.
 */

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define WATCHDOG_POLL_INTERVAL_MS       100
#define WATCHDOG_MAX_GRACE_SECONDS      3600
#define WATCHDOG_MAX_POLL_INTERVAL_MS   60000
#define WATCHDOG_MIN_POLL_INTERVAL_MS   10
#define WATCHDOG_ERROR_MAX              256

/*
 * Event callback.  This is the Phase 3 integration point: the event
 * logger can install a callback that appends JSONL records.  It runs on
 * the watchdog thread (or the caller's thread for watchdog_poll_once)
 * and must not call back into the watchdog API.
 *
 * `details` is a short human-readable string, e.g.
 *   "cpu=0.95 threshold=0.80 held=5200ms"
 */
typedef void (*watchdog_event_cb)(const char *event_type,
                                  const char *details,
                                  void *userdata);

typedef struct watchdog_context {
    /* ---------- configuration (set before watchdog_start) ---------- */
    pid_t    child_pid;
    char     cgroup_path[PATH_MAX];
    char     container_id[64];

    uint32_t timeout_seconds;           /* 0 = no timeout */
    uint32_t grace_period_seconds;      /* SIGTERM -> SIGKILL delay */

    double   memory_warning_threshold;  /* 0.0-1.0, 0 = disabled */
    double   cpu_warning_threshold;     /* 0.0-1.0, 0 = disabled */
    uint32_t cpu_warning_duration_ms;   /* sustained CPU window */
    uint32_t poll_interval_ms;          /* 0 = WATCHDOG_POLL_INTERVAL_MS */

    bool     event_log_enabled;
    char     event_log_dir[PATH_MAX];
    bool     enable_debug;

    watchdog_event_cb event_cb;
    void             *event_userdata;

    /* ---------- thread plumbing ---------- */
    pthread_t       thread;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    bool            mutex_initialized;
    bool            cond_initialized;
    bool            thread_started;
    bool            running;             /* protected by mutex */

    /* ---------- timing / monitoring state ---------- */
    struct timespec start_time;          /* CLOCK_MONOTONIC at clone */
    struct timespec last_poll_time;
    bool            have_last_poll;
    uint64_t        last_cpu_usage_usec;

    uint64_t        cpu_high_duration_ms;
    bool            cpu_breach_logged;
    bool            memory_breach_logged;
    uint64_t        last_oom_kill;

    /* ---------- results ---------- */
    bool     timeout_killed;
    bool     grace_period_used;
    bool     timeout_race_resolved;
    bool     oom_detected;
    uint64_t memory_breach_count;
    uint64_t cpu_breach_count;
    uint64_t oom_kill_count;
    bool     event_log_failed;           /* Phase 3: append failed */
    int      error_code;
    char     error_message[WATCHDOG_ERROR_MAX];

    /* ---------- last observed cgroup stats ---------- */
    uint64_t memory_current_bytes;
    uint64_t memory_peak_bytes;
    uint64_t memory_max_bytes;
    uint64_t cpu_usage_usec;
    int      pids_current;
    int      pids_max;
} watchdog_context_t;

/* Public snapshot returned by watchdog_get_stats(). */
typedef struct {
    uint64_t memory_current_bytes;
    uint64_t memory_peak_bytes;
    uint64_t memory_max_bytes;
    uint64_t cpu_usage_usec;
    int      pids_current;
    int      pids_max;

    uint64_t cpu_high_duration_ms;
    uint64_t memory_breach_count;
    uint64_t cpu_breach_count;
    uint64_t oom_kill_count;

    bool timeout_killed;
    bool grace_period_used;
    bool timeout_race_resolved;
    bool oom_detected;
    bool event_log_failed;

    int  error_code;
    char error_message[WATCHDOG_ERROR_MAX];
} watchdog_stats_t;

/*
 * Start the watchdog thread.  The context must already be populated
 * with child_pid, limits/thresholds, and (optionally) cgroup_path.
 *
 * Returns 0 on success, -1 on invalid context or thread-creation
 * failure (error_code/error_message set).  Calling twice is a no-op.
 */
int watchdog_start(watchdog_context_t *ctx);

/*
 * Stop and join the watchdog thread.  Idempotent and safe on a context
 * whose thread was never started.  Does not destroy the mutex/cond or
 * free the context.
 */
void watchdog_stop(watchdog_context_t *ctx);

/*
 * Stop (if needed), destroy synchronization primitives, and free a
 * heap-allocated context.  Safe on NULL.  Do not call on a stack
 * context.
 */
void watchdog_free(watchdog_context_t *ctx);

/* True when the timeout sequence sent SIGTERM (or SIGKILL) to the child. */
bool watchdog_was_timeout_killed(const watchdog_context_t *ctx);

/*
 * Copy the latest observed stats/flags under the context lock.
 * Safe on a zeroed context and on a stopped watchdog.
 */
void watchdog_get_stats(const watchdog_context_t *ctx,
                        watchdog_stats_t *out);

/*
 * Install a Phase 3 event callback.  Safe before or after start.
 */
void watchdog_set_event_callback(watchdog_context_t *ctx,
                                 watchdog_event_cb cb,
                                 void *userdata);

/*
 * Poll the cgroup once and evaluate memory/CPU/OOM thresholds.  This is
 * exposed so tests can drive a fake cgroup directory without starting a
 * thread.  Returns 0 when nothing was read (empty cgroup_path or best-
 * effort read failure), -1 only on invalid arguments.
 */
int watchdog_poll_once(watchdog_context_t *ctx);

/*
 * Final best-effort stat + OOM read, without emitting threshold events.
 * Called by container_wait() after stop and before remove_cgroup() so
 * the cgroup files still exist.  Safe on a zeroed/stopped context and
 * when cgroup_path is empty.
 */
void watchdog_finalize_stats(watchdog_context_t *ctx);

#endif /* WATCHDOG_H */
