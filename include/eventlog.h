#ifndef EVENTLOG_H
#define EVENTLOG_H

/*
 * Phase 3 — append-only JSONL event logging.
 *
 * One file per container: <log_dir>/<container_id>.jsonl
 * Each line is exactly one JSON object:
 *
 *   {"timestamp":"2026-10-12T14:32:05.123Z","container_id":"a1b2c3d4e5f6",
 *    "event_type":"resource_breach","details":{...}}\n
 *
 * Event details are stored as an already-valid JSON object string so the
 * hot append path does no parsing or allocation.  Constructors in
 * eventlog.c build the details safely and fall back to
 * {"truncated":true} if a pathological input overflows the buffer.
 *
 * Writes are O_APPEND + one write(2), serialized by a process-local
 * mutex.  fsync() is deliberately not called per event (NFR: logging
 * overhead < 1%); the OS page cache is the durability boundary.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define EVENT_CONTAINER_ID_MAX 64
#define EVENT_DETAILS_MAX      2048
#define EVENT_LINE_MAX         8192
#define EVENT_ERROR_MAX        256

/* Default directory used when policy logging is enabled without an
 * explicit log_dir (requirements 3.3).  Kept in sync with
 * POLICY_DEFAULT_LOG_DIR in policy.h. */
#define EVENTLOG_DEFAULT_DIR   "/var/log/minicontainer/events"

typedef enum {
    EVENT_CONTAINER_START = 0,
    EVENT_CONTAINER_EXIT,
    EVENT_RESOURCE_BREACH,
    EVENT_TIMEOUT_KILL,
    EVENT_OOM_KILL,
    EVENT_TYPE_COUNT
} event_type_t;

typedef struct {
    event_type_t     type;
    struct timespec  timestamp;                    /* CLOCK_REALTIME */
    char             container_id[EVENT_CONTAINER_ID_MAX];
    char             details[EVENT_DETAILS_MAX];   /* JSON object text */
    char             json_line[EVENT_LINE_MAX];    /* preformatted line */
    bool             truncated;                    /* details overflowed */
} event_t;

/* Exact event names required by requirements 3.2. */
const char *event_type_to_string(event_type_t type);

/* Format a timestamp as YYYY-MM-DDTHH:MM:SS.mmmZ (UTC). */
void event_format_timestamp(const struct timespec *ts, char *buf, size_t size);

/*
 * Escape a UTF-8 string for a JSON string value.  Quotes, backslashes,
 * control characters, and other non-printable bytes are escaped; valid
 * UTF-8 passes through unchanged.
 *
 * Returns 0 on success, -1 when `out` is too small.
 */
int event_json_escape(const char *src, char *out, size_t out_size);

/*
 * Format one complete JSONL line (including trailing '\n') into `buf`.
 * Returns 0 on success, 1 when a reduced valid line had to be emitted
 * because the full details did not fit, -1 on invalid arguments or a
 * buffer too small for even the reduced line.
 */
int event_format_json(const event_t *event, char *buf, size_t buf_size);

/*
 * Convenience constructors.  Each resets `out`, sets the timestamp to
 * CLOCK_REALTIME, fills `details`, and preformats `json_line`.
 *
 * container_start details:
 *   program, argv, policy, user_id, resource_limits
 *   (resource_limits: memory_bytes, cpu, pids, timeout)
 */
void event_container_start(event_t *out, const char *container_id,
                           const char *program, char *const *argv,
                           const char *policy_name, uid_t uid,
                           uint64_t memory_limit_bytes, double cpu_limit,
                           int64_t pids_limit, uint32_t timeout_seconds);

/* exit_code, exit_reason, wall_clock_seconds, cpu_time_seconds,
 * memory_peak_bytes. */
void event_container_exit(event_t *out, const char *container_id,
                          int exit_code, const char *exit_reason,
                          double wall_clock_seconds, double cpu_time_seconds,
                          uint64_t memory_peak_bytes);

/* resource, current_value, limit_value, threshold, percentage. */
void event_resource_breach(event_t *out, const char *container_id,
                           const char *resource, double current_value,
                           double limit_value, double threshold,
                           double percentage);

/* timeout_seconds, elapsed_seconds, signal, grace_period_used. */
void event_timeout_kill(event_t *out, const char *container_id,
                        uint32_t timeout_seconds, double elapsed_seconds,
                        const char *signal, bool grace_period_used);

/* memory_limit_bytes, memory_peak_bytes, exit_code. */
void event_oom_kill(event_t *out, const char *container_id,
                    uint64_t memory_limit_bytes, uint64_t memory_peak_bytes,
                    int exit_code);

/*
 * Build <log_dir>/<container_id>.jsonl.  Rejects an empty ID or an ID
 * containing '/', '\\', or ".." so CLI input cannot escape the log dir.
 * Returns 0 on success, -1 on invalid input or truncation.
 */
int eventlog_path(const char *log_dir, const char *container_id,
                  char *buf, size_t buf_size);

/*
 * Create the log directory (mkdir -p, mode 0755) and the container's
 * JSONL file (mode 0644, O_APPEND).  Idempotent.  Returns 0 on success,
 * -1 with errno set on failure.
 */
int eventlog_init(const char *log_dir, const char *container_id);

/*
 * Append one preformatted line.  Opens O_APPEND, performs exactly one
 * write(2) of the complete line (retrying only when write returns -1 /
 * EINTR), and treats a short write as failure.  Returns 0 on success,
 * -1 on failure (errno preserved).
 */
int eventlog_append(const char *log_dir, const char *container_id,
                    const event_t *event);

#endif /* EVENTLOG_H */
