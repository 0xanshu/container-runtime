/*
 * cgroups.c — Linux cgroups v2 read-side helpers
 *
 * Reads cgroup resource statistics from /sys/fs/cgroup/. Provides the
 * read-side complement to minicontainer's write-side cgroup management
 * (see minicontainer/src/cgroup.c).
 *
 * Status: implemented in minicontainer Phase 8a.
 */

#include "cgroups.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>   /* PATH_MAX, unconditional — see §6.1 note */
#include <stdint.h>

#define CGROUP_LINE_MAX 256

/*
 * Read a single uint64_t value from a cgroup v2 single-value file.
 * Maps the literal string "max" to UINT64_MAX.
 * Returns 0 on success, -1 on any error (file missing, unparseable).
 */
static int read_cgroup_uint64(const char *path, uint64_t *value)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (strncmp(buf, "max", 3) == 0) {
        *value = UINT64_MAX;
        return 0;
    }

    char *endptr;
    errno = 0;
    unsigned long long parsed = strtoull(buf, &endptr, 10);
    if (errno != 0 || endptr == buf) {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 0;
}

/*
 * Read a single int value from a cgroup v2 single-value file.
 * Maps "max" to -1.
 * Returns 0 on success, -1 on any error.
 */
static int read_cgroup_int(const char *path, int *value)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (strncmp(buf, "max", 3) == 0) {
        *value = -1;
        return 0;
    }

    *value = atoi(buf);
    return 0;
}

/*
 * Parse cpu.stat key-value file. Extracts usage_usec, user_usec,
 * system_usec. Missing file is non-fatal (cpu controller may not be
 * enabled for this cgroup).
 */
static int read_cpu_stat(const char *cgroup_path, cgroup_stats_t *stats)
{
    char path[PATH_MAX];
    int written = snprintf(path, sizeof(path), "%s/cpu.stat", cgroup_path);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;  /* cpu controller not enabled — not fatal */
    }

    char line[CGROUP_LINE_MAX];
    while (fgets(line, sizeof(line), fp) != NULL) {
        uint64_t val;
        if (sscanf(line, "usage_usec %lu", &val) == 1) {
            stats->cpu_usage_usec = val;
            continue;
        }
        if (sscanf(line, "user_usec %lu", &val) == 1) {
            stats->cpu_user_usec = val;
            continue;
        }
        if (sscanf(line, "system_usec %lu", &val) == 1) {
            stats->cpu_system_usec = val;
            continue;
        }
    }
    fclose(fp);
    return 0;
}

int read_cgroup_stats(const char *cgroup_path, cgroup_stats_t *stats)
{
    if (cgroup_path == NULL || stats == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(stats, 0, sizeof(*stats));

    char path[PATH_MAX];
    int written;

    /* Memory controller */
    written = snprintf(path, sizeof(path), "%s/memory.current", cgroup_path);
    if (written > 0 && (size_t)written < sizeof(path)) {
        read_cgroup_uint64(path, &stats->memory_current_bytes);
    }

    written = snprintf(path, sizeof(path), "%s/memory.peak", cgroup_path);
    if (written > 0 && (size_t)written < sizeof(path)) {
        read_cgroup_uint64(path, &stats->memory_peak_bytes);
    }

    written = snprintf(path, sizeof(path), "%s/memory.max", cgroup_path);
    if (written > 0 && (size_t)written < sizeof(path)) {
        read_cgroup_uint64(path, &stats->memory_max_bytes);
    }

    /* CPU controller (key-value file) */
    read_cpu_stat(cgroup_path, stats);

    /* PIDs controller */
    written = snprintf(path, sizeof(path), "%s/pids.current", cgroup_path);
    if (written > 0 && (size_t)written < sizeof(path)) {
        read_cgroup_int(path, &stats->pids_current);
    }

    written = snprintf(path, sizeof(path), "%s/pids.max", cgroup_path);
    if (written > 0 && (size_t)written < sizeof(path)) {
        read_cgroup_int(path, &stats->pids_max);
    }

    return 0;
}

int get_pid_cgroup(pid_t pid, char *buf, size_t buflen)
{
    if (buf == NULL || buflen == 0) {
        errno = EINVAL;
        return -1;
    }

    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", (int)pid);

    FILE *fp = fopen(proc_path, "r");
    if (fp == NULL) {
        /* errno already set by fopen (likely ESRCH if PID gone) */
        return -1;
    }

    /*
     * cgroups v2 format is one line:
     *   0::/path/to/cgroup
     *
     * (v1 has multiple lines per controller; we ignore those.)
     */
    char line[PATH_MAX];
    int found = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "0::", 3) != 0) {
            continue;
        }

        /* Strip trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        /* Build absolute filesystem path */
        int written = snprintf(buf, buflen, "/sys/fs/cgroup%s", line + 3);
        if (written < 0 || (size_t)written >= buflen) {
            fclose(fp);
            errno = ENAMETOOLONG;
            return -1;
        }
        found = 1;
        break;
    }
    fclose(fp);

    if (!found) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}
