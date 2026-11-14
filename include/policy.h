#ifndef POLICY_H
#define POLICY_H

/*
 * Phase 1 — Policy file support.
 *
 * A policy is a JSON document that describes resource limits, warning
 * thresholds, hardening, and event-log settings for a container run.
 * Defaults live in policy_get_default(); a policy file overrides only
 * the fields it specifies.
 *
 * IMPORTANT: this header includes core.h (for container_config_t) but
 * core.h must NEVER include policy.h.  container_config_t is the only
 * shared ABI boundary between the policy module and the runtime.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "core.h"   /* container_config_t, PATH_MAX via state.h */

/* Policy metadata limits. */
#define POLICY_NAME_MAX        64
#define POLICY_VERSION_MAX     16
#define POLICY_DESCRIPTION_MAX 256

/* Error/warning storage. */
#define POLICY_ERROR_MAX       256
#define POLICY_MAX_WARNINGS    32
#define POLICY_WARNING_MAX     256

/* Built-in defaults (requirements 1.7).  Applied only in policy mode —
 * a legacy invocation with no --policy never calls policy_apply(). */
#define POLICY_DEFAULT_LOG_DIR                  "/var/log/minicontainer/events"
#define POLICY_DEFAULT_CPU_LIMIT                1.0
#define POLICY_DEFAULT_PIDS_LIMIT               100
#define POLICY_DEFAULT_TIMEOUT                  0
#define POLICY_DEFAULT_GRACE_PERIOD             10
#define POLICY_DEFAULT_MEMORY_WARNING           0.9
#define POLICY_DEFAULT_CPU_WARNING              0.8
#define POLICY_DEFAULT_CPU_WARNING_DURATION_MS  5000
#define POLICY_DEFAULT_POLL_INTERVAL_MS         100

/* Requirement 1.5: a non-zero memory limit below 1 MiB is invalid. */
#define POLICY_MIN_MEMORY_BYTES (1024ULL * 1024ULL)

/*
 * Parsed policy.  Fixed-size fields only — no heap ownership, so
 * policy_free() is a simple reset and the struct can live on the stack.
 *
 * timeout / grace_period / pids_limit are signed so validation can
 * distinguish "field omitted / zero" from "the file said -5".
 */
typedef struct {
    /* [policy] metadata. */
    char name[POLICY_NAME_MAX];
    char version[POLICY_VERSION_MAX];
    char description[POLICY_DESCRIPTION_MAX];
    char source_path[PATH_MAX];

    /* [resources]. */
    uint64_t memory_limit;      /* bytes, 0 = unlimited */
    double   cpu_limit;         /* fraction of one core, 0 = unlimited */
    int64_t  pids_limit;        /* 0 = unlimited */
    int64_t  timeout;           /* seconds, 0 = no timeout */
    int64_t  grace_period;      /* seconds before SIGKILL */

    /* [resources.thresholds]. */
    double   memory_warning_threshold;   /* 0.0-1.0, 0 = disabled */
    double   cpu_warning_threshold;      /* 0.0-1.0, 0 = disabled */
    uint32_t cpu_warning_duration_ms;
    uint32_t watchdog_poll_interval_ms;

    /* [security]. */
    bool enable_hardening;

    /* [logging]. */
    bool log_enabled;
    char log_dir[PATH_MAX];

    /* Validation state. */
    bool is_valid;
    char validation_error[POLICY_ERROR_MAX];
    char warnings[POLICY_MAX_WARNINGS][POLICY_WARNING_MAX];
    size_t warning_count;
} policy_t;

/*
 * Populate `out` with the built-in defaults from requirements 1.7.
 * Always succeeds; `out` must be non-NULL.
 */
void policy_get_default(policy_t *out);

/*
 * Load + parse + validate a policy file.
 *
 * On success: returns 0, out->is_valid == true, warnings populated.
 * On failure: returns -1, out->is_valid == false, and
 *             out->validation_error holds a printable message
 *             ("Policy file not found: ...", "Parse error at line N: ...",
 *              or a validation message).
 *
 * `out` is reset before any work, so it is safe to print its error on
 * failure.  JSON is the only supported format; a `.toml` path fails with
 * a clear "not available" message.
 */
int policy_load(const char *path, policy_t *out);

/*
 * Validate the in-memory struct.  Side-effect-free apart from updating
 * is_valid/validation_error, and repeatable (safe for `policy validate`).
 * Returns true when valid.
 */
bool policy_validate(policy_t *p);

/*
 * Apply a validated policy to a container configuration.
 *
 * Resource limits map onto cgroup_limits and enable_cgroup only when at
 * least one non-zero limit is present.  Hardening is enabled only when
 * the policy asks for it AND a rootfs is present (hardening needs its
 * own mount namespace).  Never called for legacy (non-policy) runs.
 *
 * Returns 0 on success, -1 on invalid arguments.
 */
int policy_apply(const policy_t *p, container_config_t *cfg);

/*
 * Reset all fields to zero.  Safe on a zeroed or partially populated
 * struct.
 */
void policy_free(policy_t *p);

/*
 * Print accumulated warnings to stderr, prefixed with "[policy]".
 * Does nothing when warning_count is 0.
 */
void policy_print_warnings(const policy_t *p);

/*
 * Append a formatted warning.  Silently drops the message when the
 * warning list is full (warnings must never fail a load).
 */
void policy_add_warning(policy_t *p, const char *fmt, ...);

/*
 * Shared human-readable memory parser used by both the CLI (--memory)
 * and the policy JSON parser.  Accepts bytes ("1048576") or a suffix
 * ("512M", "1G", "1.5M", "1MB", "1MiB").  Returns 0 on success and
 * stores the byte count in *out_bytes; -1 on malformed input.
 */
int policy_parse_memory_string(const char *str, uint64_t *out_bytes);

/*
 * Parse a policy JSON file into `p` (which must already hold defaults).
 * Exposed separately from policy_load() so the loader can keep file
 * discovery / format detection in one place.
 *
 * Returns 0 on success, -1 on a read or parse failure.  `err` receives a
 * printable "Parse error at line N: ..." message on syntax errors.
 */
int policy_json_parse_file(const char *path, policy_t *p,
                           char *err, size_t err_size);

#endif /* POLICY_H */
