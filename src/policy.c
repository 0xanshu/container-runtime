/*
 * policy.c — Phase 1 policy loading, validation, defaults, application.
 *
 * This module owns the policy lifecycle:
 *
 *   policy_get_default()  built-in defaults (requirements 1.7)
 *   policy_load()         stat/access + JSON parse + validate
 *   policy_validate()     value checks with the exact required messages
 *   policy_apply()        map policy_t onto container_config_t
 *   policy_free()         reset
 *
 * No heap ownership: policy_t uses fixed-size arrays.  The JSON parser
 * lives in policy_json.c.
 */

#include "policy.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static void copy_str(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0) return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static bool policy_fail(policy_t *p, const char *fmt, ...)
{
    if (!p) return false;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->validation_error, sizeof(p->validation_error), fmt, ap);
    va_end(ap);
    p->is_valid = false;
    return false;
}

void policy_add_warning(policy_t *p, const char *fmt, ...)
{
    if (!p || p->warning_count >= POLICY_MAX_WARNINGS) return;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->warnings[p->warning_count],
              POLICY_WARNING_MAX, fmt, ap);
    va_end(ap);
    p->warning_count++;
}

void policy_print_warnings(const policy_t *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->warning_count; i++) {
        fprintf(stderr, "[policy] warning: %s\n", p->warnings[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Defaults / free                                                     */
/* ------------------------------------------------------------------ */

void policy_get_default(policy_t *out)
{
    if (!out) return;

    memset(out, 0, sizeof(*out));
    copy_str(out->name, sizeof(out->name), "default");

    out->memory_limit             = 0;
    out->cpu_limit                = POLICY_DEFAULT_CPU_LIMIT;
    out->pids_limit               = POLICY_DEFAULT_PIDS_LIMIT;
    out->timeout                  = POLICY_DEFAULT_TIMEOUT;
    out->grace_period             = POLICY_DEFAULT_GRACE_PERIOD;

    out->memory_warning_threshold = POLICY_DEFAULT_MEMORY_WARNING;
    out->cpu_warning_threshold    = POLICY_DEFAULT_CPU_WARNING;
    out->cpu_warning_duration_ms  = POLICY_DEFAULT_CPU_WARNING_DURATION_MS;
    out->watchdog_poll_interval_ms = POLICY_DEFAULT_POLL_INTERVAL_MS;

    out->enable_hardening         = true;

    out->log_enabled              = true;
    copy_str(out->log_dir, sizeof(out->log_dir), POLICY_DEFAULT_LOG_DIR);

    out->is_valid                 = true;
    out->validation_error[0]      = '\0';
    out->warning_count            = 0;
}

void policy_free(policy_t *p)
{
    if (!p) return;
    memset(p, 0, sizeof(*p));
}

/* ------------------------------------------------------------------ */
/* Shared memory parser                                                */
/* ------------------------------------------------------------------ */

int policy_parse_memory_string(const char *str, uint64_t *out_bytes)
{
    if (!str || !out_bytes) return -1;

    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return -1;

    /* Reject an explicit sign: negative sizes are meaningless and JSON
     * sizes are non-negative. */
    if (*str == '-' || *str == '+') return -1;

    errno = 0;
    char *end = NULL;
    double value = strtod(str, &end);
    if (end == str || errno == ERANGE || !isfinite(value) || value < 0.0) {
        return -1;
    }

    const char *p = end;
    while (isspace((unsigned char)*p)) p++;

    uint64_t multiplier = 1;
    if (*p != '\0') {
        switch (toupper((unsigned char)*p)) {
            case 'K': multiplier = 1024ULL; break;
            case 'M': multiplier = 1024ULL * 1024ULL; break;
            case 'G': multiplier = 1024ULL * 1024ULL * 1024ULL; break;
            case 'T': multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL; break;
            case 'B': multiplier = 1ULL; break;
            default: return -1;
        }
        p++;
        /* Optional "i" and "B" for KiB/MiB/GiB spellings. */
        if (*p == 'i' || *p == 'I') p++;
        if (*p == 'b' || *p == 'B') p++;
        while (isspace((unsigned char)*p)) p++;
        if (*p != '\0') return -1;
    }

    long double bytes = (long double)value * (long double)multiplier;
    if (!isfinite((double)bytes) ||
        bytes < 0.0L ||
        bytes > (long double)UINT64_MAX) {
        return -1;
    }

    *out_bytes = (uint64_t)bytes;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Validation                                                          */
/* ------------------------------------------------------------------ */

bool policy_validate(policy_t *p)
{
    if (!p) return false;

    /* Recompute from the struct's fields every time so callers can fix
     * a value and re-validate (P1.12).  Parse failures never reach this
     * function: policy_load() returns before validating them. */
    p->is_valid = true;
    p->validation_error[0] = '\0';

    int cpu_count = get_nprocs();
    if (cpu_count < 1) cpu_count = 1;

    if (p->memory_limit != 0 &&
        p->memory_limit < POLICY_MIN_MEMORY_BYTES) {
        return policy_fail(p,
            "memory_limit must be at least 1MB or 0 for unlimited");
    }

    if (!isfinite(p->cpu_limit) ||
        p->cpu_limit < 0.0 ||
        p->cpu_limit > (double)cpu_count) {
        return policy_fail(p, "cpu_limit must be between 0.0 and %d",
                           cpu_count);
    }

    if (p->pids_limit < 0) {
        return policy_fail(p, "pids_limit must be non-negative");
    }

    if (p->timeout < 0) {
        return policy_fail(p, "timeout must be non-negative");
    }
    if (p->timeout > (int64_t)UINT32_MAX) {
        return policy_fail(p, "timeout is too large");
    }

    if (p->grace_period < 0) {
        return policy_fail(p, "grace_period must be non-negative");
    }
    if (p->grace_period > (int64_t)UINT32_MAX) {
        return policy_fail(p, "grace_period is too large");
    }

    if (!isfinite(p->memory_warning_threshold) ||
        p->memory_warning_threshold < 0.0 ||
        p->memory_warning_threshold > 1.0) {
        return policy_fail(p,
            "memory_warning_threshold must be between 0.0 and 1.0");
    }

    if (!isfinite(p->cpu_warning_threshold) ||
        p->cpu_warning_threshold < 0.0 ||
        p->cpu_warning_threshold > 1.0) {
        return policy_fail(p,
            "cpu_warning_threshold must be between 0.0 and 1.0");
    }

    if (p->watchdog_poll_interval_ms > 60000) {
        return policy_fail(p,
            "watchdog_poll_interval_ms must be between 0 and 60000");
    }

    if (p->log_enabled) {
        if (p->log_dir[0] == '\0') {
            return policy_fail(p,
                "log_dir must be set when logging is enabled");
        }
        if (p->log_dir[0] != '/') {
            return policy_fail(p, "log_dir must be an absolute path");
        }
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* Loading                                                             */
/* ------------------------------------------------------------------ */

int policy_load(const char *path, policy_t *out)
{
    if (!out) return -1;

    policy_get_default(out);

    if (!path || path[0] == '\0') {
        policy_fail(out, "Policy file not found: %s", path ? path : "");
        return -1;
    }

    /* Keep the caller's path for error messages and state metadata. */
    copy_str(out->source_path, sizeof(out->source_path), path);

    struct stat st;
    if (stat(path, &st) < 0) {
        if (errno == ENOENT) {
            policy_fail(out, "Policy file not found: %s", path);
        } else {
            policy_fail(out, "Cannot read policy file: %s", path);
        }
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        policy_fail(out, "Cannot read policy file: %s", path);
        return -1;
    }
    if (access(path, R_OK) < 0) {
        policy_fail(out, "Cannot read policy file: %s", path);
        return -1;
    }

    /* TOML is explicitly out of scope for this delivery.  Detect it
     * before parsing so the error is actionable rather than a generic
     * JSON syntax error. */
    const char *dot   = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (dot != NULL && (slash == NULL || dot > slash) &&
        strcasecmp(dot, ".toml") == 0) {
        policy_fail(out,
            "TOML policy support is not available; use JSON");
        return -1;
    }

    char err[POLICY_ERROR_MAX] = {0};
    if (policy_json_parse_file(path, out, err, sizeof(err)) < 0) {
        if (err[0] != '\0') {
            copy_str(out->validation_error,
                     sizeof(out->validation_error), err);
        } else {
            policy_fail(out, "Cannot read policy file: %s", path);
        }
        out->is_valid = false;
        return -1;
    }

    if (!policy_validate(out)) {
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Application                                                         */
/* ------------------------------------------------------------------ */

int policy_apply(const policy_t *p, container_config_t *cfg)
{
    if (!p || !cfg || !p->is_valid) return -1;

    bool any_limit = false;

    if (p->memory_limit > 0) {
        cfg->cgroup_limits.memory_limit = (size_t)p->memory_limit;
        any_limit = true;
    }

    if (p->cpu_limit > 0.0) {
        long quota = (long)(p->cpu_limit * 100000.0);
        /* Linux rejects cpu.max quotas below 1000us; clamp rather than
         * making an otherwise-valid policy fail at cgroup setup. */
        if (quota < 1000) quota = 1000;
        cfg->cgroup_limits.cpu_quota  = quota;
        cfg->cgroup_limits.cpu_period = 100000;
        any_limit = true;
    }

    if (p->pids_limit > 0) {
        cfg->cgroup_limits.pid_limit = (size_t)p->pids_limit;
        any_limit = true;
    }

    if (any_limit) {
        cfg->enable_cgroup = true;
    }

    cfg->timeout_seconds      = (uint32_t)p->timeout;
    cfg->grace_period_seconds = (uint32_t)p->grace_period;

    cfg->memory_warning_threshold   = p->memory_warning_threshold;
    cfg->cpu_warning_threshold      = p->cpu_warning_threshold;
    cfg->cpu_warning_duration_ms    = p->cpu_warning_duration_ms;
    cfg->watchdog_poll_interval_ms  = p->watchdog_poll_interval_ms;

    cfg->event_log_enabled = p->log_enabled;
    copy_str(cfg->event_log_dir, sizeof(cfg->event_log_dir), p->log_dir);

    copy_str(cfg->policy_name, sizeof(cfg->policy_name), p->name);
    cfg->policy_mode = true;

    /* D4: hardening needs a rootfs (and its mount namespace).  Policy
     * mode may request it, but never enable it without one. */
    if (p->enable_hardening) {
        if (cfg->rootfs_path != NULL) {
            cfg->enable_hardening = true;
        } else if (cfg->enable_debug) {
            fprintf(stderr,
                "[policy] enable_hardening requested but no rootfs is "
                "configured; hardening disabled\n");
        }
    }

    return 0;
}
