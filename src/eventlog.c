// Note: _GNU_SOURCE is provided by the Makefile via -D_GNU_SOURCE.
//
// Phase 3 — append-only JSONL event logging.  See include/eventlog.h.
//
// The hot path is deliberately tiny: constructors preformat one line,
// eventlog_append opens O_APPEND and performs exactly one write(2).
// A process-local mutex serializes writes from the watchdog thread and
// the container lifecycle thread so lines cannot interleave even on
// filesystems with weaker O_APPEND guarantees.

#include "eventlog.h"
#include "state.h"       /* mkdir_p(), PATH_MAX */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_mutex_t g_eventlog_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* JSON building helpers                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    bool   overflow;
} json_buf_t;

static void jb_init(json_buf_t *jb, char *buf, size_t cap)
{
    jb->buf = buf;
    jb->cap = cap;
    jb->len = 0;
    jb->overflow = false;
    if (cap > 0) buf[0] = '\0';
}

static bool jb_append(json_buf_t *jb, const char *s)
{
    size_t n = strlen(s);
    if (jb->overflow || jb->len + n >= jb->cap) {
        jb->overflow = true;
        return false;
    }
    memcpy(jb->buf + jb->len, s, n);
    jb->len += n;
    jb->buf[jb->len] = '\0';
    return true;
}

static bool jb_printf(json_buf_t *jb, const char *fmt, ...)
{
    if (jb->overflow || jb->len >= jb->cap) {
        jb->overflow = true;
        return false;
    }

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(jb->buf + jb->len, jb->cap - jb->len, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= jb->cap - jb->len) {
        jb->overflow = true;
        return false;
    }
    jb->len += (size_t)n;
    return true;
}

static bool jb_key(json_buf_t *jb, bool *first, const char *key)
{
    if (!*first) jb_append(jb, ",");
    *first = false;
    return jb_printf(jb, "\"%s\":", key);
}

static bool jb_kv_string(json_buf_t *jb, bool *first, const char *key,
                         const char *value)
{
    char escaped[EVENT_DETAILS_MAX];
    if (event_json_escape(value ? value : "", escaped, sizeof(escaped)) < 0) {
        jb->overflow = true;
        return false;
    }
    return jb_key(jb, first, key) &&
           jb_append(jb, "\"") &&
           jb_append(jb, escaped) &&
           jb_append(jb, "\"");
}

static bool jb_kv_uint(json_buf_t *jb, bool *first, const char *key,
                       uint64_t value)
{
    return jb_key(jb, first, key) &&
           jb_printf(jb, "%llu", (unsigned long long)value);
}

static bool jb_kv_int(json_buf_t *jb, bool *first, const char *key,
                      int64_t value)
{
    return jb_key(jb, first, key) &&
           jb_printf(jb, "%lld", (long long)value);
}

static bool jb_kv_double(json_buf_t *jb, bool *first, const char *key,
                         double value)
{
    return jb_key(jb, first, key) && jb_printf(jb, "%.6f", value);
}

static bool jb_kv_bool(json_buf_t *jb, bool *first, const char *key,
                       bool value)
{
    return jb_key(jb, first, key) &&
           jb_append(jb, value ? "true" : "false");
}

/* Finalize details; on overflow fall back to a still-valid object. */
static void event_finish(event_t *out, json_buf_t *jb)
{
    if (jb->overflow || !jb_append(jb, "}")) {
        snprintf(out->details, sizeof(out->details),
                 "{\"truncated\":true}");
        out->truncated = true;
    }

    out->json_line[0] = '\0';
    (void)event_format_json(out, out->json_line, sizeof(out->json_line));
}

static void event_init(event_t *out, event_type_t type,
                       const char *container_id)
{
    memset(out, 0, sizeof(*out));
    out->type = type;
    clock_gettime(CLOCK_REALTIME, &out->timestamp);
    snprintf(out->container_id, sizeof(out->container_id), "%s",
             container_id ? container_id : "");
}

/* ------------------------------------------------------------------ */
/* Public formatting helpers                                           */
/* ------------------------------------------------------------------ */

const char *event_type_to_string(event_type_t type)
{
    switch (type) {
        case EVENT_CONTAINER_START:  return "container_start";
        case EVENT_CONTAINER_EXIT:   return "container_exit";
        case EVENT_RESOURCE_BREACH:  return "resource_breach";
        case EVENT_TIMEOUT_KILL:     return "timeout_kill";
        case EVENT_OOM_KILL:         return "oom_kill";
        default:                     return "unknown";
    }
}

void event_format_timestamp(const struct timespec *ts, char *buf, size_t size)
{
    if (!buf || size == 0) return;
    buf[0] = '\0';
    if (!ts) return;

    struct tm tm;
    if (!gmtime_r(&ts->tv_sec, &tm)) return;

    long ms = ts->tv_nsec / 1000000L;
    if (ms < 0) ms = 0;
    if (ms > 999) ms = 999;

    snprintf(buf, size, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

int event_json_escape(const char *src, char *out, size_t out_size)
{
    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    if (!src) return 0;

    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
        char esc[8];
        const char *rep = NULL;
        char one[2] = { (char)*p, '\0' };

        switch (*p) {
            case '"':  rep = "\\\""; break;
            case '\\': rep = "\\\\"; break;
            case '\b': rep = "\\b";  break;
            case '\f': rep = "\\f";  break;
            case '\n': rep = "\\n";  break;
            case '\r': rep = "\\r";  break;
            case '\t': rep = "\\t";  break;
            default:
                if (*p < 0x20 || *p == 0x7f) {
                    snprintf(esc, sizeof(esc), "\\u%04x", *p);
                    rep = esc;
                } else {
                    /* >= 0x80 is passed through: valid UTF-8 sequences
                     * stay intact. */
                    rep = one;
                }
                break;
        }

        size_t n = strlen(rep);
        if (o + n >= out_size) {
            out[0] = '\0';
            return -1;
        }
        memcpy(out + o, rep, n);
        o += n;
    }
    out[o] = '\0';
    return 0;
}

static bool details_look_like_object(const char *details)
{
    if (!details || details[0] != '{') return false;
    size_t n = strlen(details);
    return n >= 2 && details[n - 1] == '}';
}

int event_format_json(const event_t *event, char *buf, size_t buf_size)
{
    if (!event || !buf || buf_size == 0) return -1;

    char timestamp[40];
    char esc_id[EVENT_CONTAINER_ID_MAX * 6 + 1];
    event_format_timestamp(&event->timestamp, timestamp, sizeof(timestamp));
    if (event_json_escape(event->container_id, esc_id, sizeof(esc_id)) < 0)
        return -1;

    const char *type = event_type_to_string(event->type);
    const char *details = details_look_like_object(event->details)
                              ? event->details
                              : "{\"truncated\":true}";

    int n = snprintf(buf, buf_size,
                     "{\"timestamp\":\"%s\",\"container_id\":\"%s\","
                     "\"event_type\":\"%s\",\"details\":%s}\n",
                     timestamp, esc_id, type, details);
    if (n >= 0 && (size_t)n < buf_size) {
        return event->truncated ? 1 : 0;
    }

    /* The full line did not fit.  Emit a reduced but still valid line
     * rather than a truncated (invalid) JSON fragment. */
    n = snprintf(buf, buf_size,
                 "{\"timestamp\":\"%s\",\"container_id\":\"%s\","
                 "\"event_type\":\"%s\",\"details\":{\"truncated\":true}}\n",
                 timestamp, esc_id, type);
    if (n < 0 || (size_t)n >= buf_size) {
        buf[0] = '\0';
        return -1;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Constructors                                                        */
/* ------------------------------------------------------------------ */

void event_container_start(event_t *out, const char *container_id,
                           const char *program, char *const *argv,
                           const char *policy_name, uid_t uid,
                           uint64_t memory_limit_bytes, double cpu_limit,
                           int64_t pids_limit, uint32_t timeout_seconds)
{
    if (!out) return;
    event_init(out, EVENT_CONTAINER_START, container_id);

    json_buf_t jb;
    jb_init(&jb, out->details, sizeof(out->details));
    bool first = true;

    jb_append(&jb, "{");
    jb_kv_string(&jb, &first, "program", program ? program : "");
    jb_key(&jb, &first, "argv");
    jb_append(&jb, "[");
    bool first_arg = true;
    if (argv) {
        for (int i = 0; argv[i]; i++) {
            char escaped[EVENT_DETAILS_MAX];
            if (event_json_escape(argv[i], escaped, sizeof(escaped)) < 0) {
                jb.overflow = true;
                break;
            }
            if (!first_arg) jb_append(&jb, ",");
            first_arg = false;
            jb_append(&jb, "\"");
            jb_append(&jb, escaped);
            jb_append(&jb, "\"");
        }
    }
    jb_append(&jb, "]");
    jb_kv_string(&jb, &first, "policy",
                 (policy_name && policy_name[0]) ? policy_name : "none");
    jb_kv_uint(&jb, &first, "user_id", (uint64_t)uid);

    jb_key(&jb, &first, "resource_limits");
    jb_append(&jb, "{");
    bool first_limit = true;
    jb_kv_uint(&jb, &first_limit, "memory_bytes", memory_limit_bytes);
    jb_kv_double(&jb, &first_limit, "cpu", cpu_limit);
    jb_kv_int(&jb, &first_limit, "pids", pids_limit);
    jb_kv_uint(&jb, &first_limit, "timeout", timeout_seconds);
    jb_append(&jb, "}");

    event_finish(out, &jb);
}

void event_container_exit(event_t *out, const char *container_id,
                          int exit_code, const char *exit_reason,
                          double wall_clock_seconds, double cpu_time_seconds,
                          uint64_t memory_peak_bytes)
{
    if (!out) return;
    event_init(out, EVENT_CONTAINER_EXIT, container_id);

    json_buf_t jb;
    jb_init(&jb, out->details, sizeof(out->details));
    bool first = true;

    jb_append(&jb, "{");
    jb_kv_int(&jb, &first, "exit_code", (int64_t)exit_code);
    jb_kv_string(&jb, &first, "exit_reason",
                 exit_reason ? exit_reason : "normal");
    jb_kv_double(&jb, &first, "wall_clock_seconds", wall_clock_seconds);
    jb_kv_double(&jb, &first, "cpu_time_seconds", cpu_time_seconds);
    jb_kv_uint(&jb, &first, "memory_peak_bytes", memory_peak_bytes);

    event_finish(out, &jb);
}

void event_resource_breach(event_t *out, const char *container_id,
                           const char *resource, double current_value,
                           double limit_value, double threshold,
                           double percentage)
{
    if (!out) return;
    event_init(out, EVENT_RESOURCE_BREACH, container_id);

    json_buf_t jb;
    jb_init(&jb, out->details, sizeof(out->details));
    bool first = true;

    jb_append(&jb, "{");
    jb_kv_string(&jb, &first, "resource",
                 resource ? resource : "unknown");
    jb_kv_double(&jb, &first, "current_value", current_value);
    jb_kv_double(&jb, &first, "limit_value", limit_value);
    jb_kv_double(&jb, &first, "threshold", threshold);
    jb_kv_double(&jb, &first, "percentage", percentage);

    event_finish(out, &jb);
}

void event_timeout_kill(event_t *out, const char *container_id,
                        uint32_t timeout_seconds, double elapsed_seconds,
                        const char *signal, bool grace_period_used)
{
    if (!out) return;
    event_init(out, EVENT_TIMEOUT_KILL, container_id);

    json_buf_t jb;
    jb_init(&jb, out->details, sizeof(out->details));
    bool first = true;

    jb_append(&jb, "{");
    jb_kv_uint(&jb, &first, "timeout_seconds", timeout_seconds);
    jb_kv_double(&jb, &first, "elapsed_seconds", elapsed_seconds);
    jb_kv_string(&jb, &first, "signal", signal ? signal : "SIGTERM");
    jb_kv_bool(&jb, &first, "grace_period_used", grace_period_used);

    event_finish(out, &jb);
}

void event_oom_kill(event_t *out, const char *container_id,
                    uint64_t memory_limit_bytes, uint64_t memory_peak_bytes,
                    int exit_code)
{
    if (!out) return;
    event_init(out, EVENT_OOM_KILL, container_id);

    json_buf_t jb;
    jb_init(&jb, out->details, sizeof(out->details));
    bool first = true;

    jb_append(&jb, "{");
    jb_kv_uint(&jb, &first, "memory_limit_bytes", memory_limit_bytes);
    jb_kv_uint(&jb, &first, "memory_peak_bytes", memory_peak_bytes);
    jb_kv_int(&jb, &first, "exit_code", (int64_t)exit_code);

    event_finish(out, &jb);
}

/* ------------------------------------------------------------------ */
/* Persistence                                                         */
/* ------------------------------------------------------------------ */

int eventlog_path(const char *log_dir, const char *container_id,
                  char *buf, size_t buf_size)
{
    if (!log_dir || log_dir[0] == '\0' ||
        !container_id || container_id[0] == '\0' ||
        !buf || buf_size == 0) {
        errno = EINVAL;
        return -1;
    }
    if (strchr(container_id, '/') || strchr(container_id, '\\') ||
        strstr(container_id, "..")) {
        errno = EINVAL;
        return -1;
    }

    int n = snprintf(buf, buf_size, "%s/%s.jsonl", log_dir, container_id);
    if (n < 0 || (size_t)n >= buf_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int eventlog_init(const char *log_dir, const char *container_id)
{
    char path[PATH_MAX];
    if (eventlog_path(log_dir, container_id, path, sizeof(path)) < 0)
        return -1;

    if (mkdir_p(log_dir, 0755) < 0)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) return -1;

    /* Enforce 0644 even with a restrictive umask (P3.11). */
    if (fchmod(fd, 0644) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    if (close(fd) < 0) return -1;
    return 0;
}

int eventlog_append(const char *log_dir, const char *container_id,
                    const event_t *event)
{
    if (!event) {
        errno = EINVAL;
        return -1;
    }

    char line[EVENT_LINE_MAX];
    int fmt = event_format_json(event, line, sizeof(line));
    if (fmt < 0) {
        errno = EINVAL;
        return -1;
    }
    if (fmt == 1 || event->truncated) {
        fprintf(stderr,
                "[eventlog] warning: event details truncated for %s\n",
                container_id ? container_id : "(unknown)");
    }

    char path[PATH_MAX];
    if (eventlog_path(log_dir, container_id, path, sizeof(path)) < 0)
        return -1;

    size_t len = strlen(line);
    int rc = -1;
    int saved_errno = 0;

    pthread_mutex_lock(&g_eventlog_mutex);

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        saved_errno = errno;
        goto out;
    }

    if (fchmod(fd, 0644) < 0) {
        saved_errno = errno;
        close(fd);
        goto out;
    }

    ssize_t n;
    do {
        n = write(fd, line, len);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        saved_errno = errno;
    } else if ((size_t)n != len) {
        /* A short write means the line is incomplete; do not retry it
         * as a second append (that would corrupt the JSONL boundary). */
        saved_errno = EIO;
    } else {
        rc = 0;
    }

    if (close(fd) < 0 && rc == 0) {
        saved_errno = errno;
        rc = -1;
    }

out:
    pthread_mutex_unlock(&g_eventlog_mutex);
    if (rc < 0) errno = saved_errno ? saved_errno : EIO;
    return rc;
}
