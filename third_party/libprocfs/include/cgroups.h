#ifndef CGROUPS_H
#define CGROUPS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Cgroup v2 statistics, populated by read_cgroup_stats().
 * Fields whose source file is missing or unreadable remain zero
 * (so callers can detect missing controllers by zero-checking).
 *
 * Special values:
 *   memory_max_bytes == UINT64_MAX   means "max" (unlimited)
 *   pids_max == -1                   means "max" (unlimited)
 */
typedef struct {
    uint64_t memory_current_bytes;
    uint64_t memory_peak_bytes;
    uint64_t memory_max_bytes;
    uint64_t cpu_usage_usec;
    uint64_t cpu_user_usec;
    uint64_t cpu_system_usec;
    int      pids_current;
    int      pids_max;
} cgroup_stats_t;

/*
 * Read all cgroup v2 stats from a cgroup directory.
 *
 * cgroup_path  Absolute path, e.g., "/sys/fs/cgroup/minicontainer_1234_5678"
 * stats        Output struct. Zeroed before population.
 *
 * Returns 0 on success (struct populated as far as files were readable),
 * -1 on argument error (NULL path/stats; sets errno=EINVAL).
 * Missing optional controller files are non-fatal — those fields stay zero.
 */
int read_cgroup_stats(const char *cgroup_path, cgroup_stats_t *stats);

/*
 * Resolve a PID to its cgroup v2 directory by reading /proc/<pid>/cgroup.
 *
 * pid     Target process
 * buf     Output buffer for absolute path, e.g.,
 *         "/sys/fs/cgroup/minicontainer_1234_5678"
 * buflen  Size of buf
 *
 * Returns 0 on success, -1 on error (PID gone, no v2 hierarchy,
 * buffer too small — errno is set: ESRCH/ENOENT/ENAMETOOLONG).
 *
 * Only the unified v2 hierarchy is supported. v1 entries (lines like
 * "1:name=systemd:/path") are ignored.
 */
int get_pid_cgroup(pid_t pid, char *buf, size_t buflen);

#endif /* CGROUPS_H */
