/*
 * test_cgroups.c - Unit tests for the cgroup v2 read-side helpers
 *
 * Tests read_cgroup_stats() and get_pid_cgroup(). The core parsing tests use a
 * synthetic cgroup directory of crafted files under /tmp, so they are
 * deterministic and need neither root nor a real cgroup mount. A live
 * get_pid_cgroup() check runs only on a cgroup v2 host (skipped otherwise).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "procfs.h"
#include "cgroups.h"

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        printf("Testing %s... ", name); \
        fflush(stdout); \
    } while(0)

#define ASSERT_TRUE(condition, msg) \
    do { \
        if (condition) { \
            printf("%s\n", TEST_PASS); \
            tests_passed++; \
        } else { \
            printf("%s (%s)\n", TEST_FAIL, msg); \
            tests_failed++; \
        } \
    } while(0)

#define ASSERT_EQ(actual, expected) \
    do { \
        if ((actual) == (expected)) { \
            printf("%s\n", TEST_PASS); \
            tests_passed++; \
        } else { \
            printf("%s (expected %d, got %d)\n", TEST_FAIL, \
                   (int)(expected), (int)(actual)); \
            tests_failed++; \
        } \
    } while(0)

/* Write content to <dir>/<name>. Returns 0 on success, -1 on error. */
static int write_file(const char *dir, const char *name, const char *content)
{
    char path[512];
    int written = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }

    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    fputs(content, fp);
    fclose(fp);
    return 0;
}

/* Remove <dir>/<name>, ignoring errors. */
static void remove_file(const char *dir, const char *name)
{
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) > 0) {
        unlink(path);
    }
}

/* ===== Argument validation ===== */

static void test_stats_null_path(void)
{
    TEST("read_cgroup_stats with NULL path");
    cgroup_stats_t stats;
    errno = 0;
    int ret = read_cgroup_stats(NULL, &stats);
    ASSERT_TRUE(ret == -1 && errno == EINVAL, "should fail with EINVAL");
}

static void test_stats_null_stats(void)
{
    TEST("read_cgroup_stats with NULL stats");
    errno = 0;
    int ret = read_cgroup_stats("/sys/fs/cgroup", NULL);
    ASSERT_TRUE(ret == -1 && errno == EINVAL, "should fail with EINVAL");
}

static void test_get_pid_cgroup_null_buf(void)
{
    TEST("get_pid_cgroup with NULL buffer");
    errno = 0;
    int ret = get_pid_cgroup(getpid(), NULL, 256);
    ASSERT_TRUE(ret == -1 && errno == EINVAL, "should fail with EINVAL");
}

static void test_get_pid_cgroup_zero_len(void)
{
    TEST("get_pid_cgroup with zero buffer length");
    char buf[256];
    errno = 0;
    int ret = get_pid_cgroup(getpid(), buf, 0);
    ASSERT_TRUE(ret == -1 && errno == EINVAL, "should fail with EINVAL");
}

static void test_get_pid_cgroup_nonexistent(void)
{
    TEST("get_pid_cgroup with non-existent PID");
    char buf[PATH_MAX];
    int ret = get_pid_cgroup(999999, buf, sizeof(buf));
    ASSERT_EQ(ret, -1);
}

/* ===== Live read on a cgroup v2 host ===== */

static void test_get_pid_cgroup_current(void)
{
    TEST("get_pid_cgroup on current process (v2)");

    if (access("/sys/fs/cgroup/cgroup.controllers", F_OK) != 0) {
        printf("SKIP: not a cgroup v2 host\n");
        return;
    }

    char buf[PATH_MAX];
    int ret = get_pid_cgroup(getpid(), buf, sizeof(buf));
    ASSERT_TRUE(ret == 0 && strncmp(buf, "/sys/fs/cgroup", 14) == 0,
                "should resolve to a /sys/fs/cgroup path");
}

/* ===== Synthetic-directory parsing (deterministic, no root needed) ===== */

static void test_synthetic_numeric_and_max(void)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "/tmp/libprocfs_cgtest_%d", (int)getpid());

    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        TEST("synthetic cgroup dir creation");
        ASSERT_TRUE(0, "mkdir failed");
        return;
    }

    write_file(dir, "memory.current", "12345\n");
    write_file(dir, "memory.peak",    "67890\n");
    write_file(dir, "memory.max",     "max\n");
    write_file(dir, "pids.current",   "7\n");
    write_file(dir, "pids.max",       "max\n");
    write_file(dir, "cpu.stat",
               "usage_usec 1000\nuser_usec 600\nsystem_usec 400\n");

    cgroup_stats_t stats;
    int ret = read_cgroup_stats(dir, &stats);

    TEST("read_cgroup_stats on synthetic dir returns 0");
    ASSERT_EQ(ret, 0);

    TEST("memory.current parsed");
    ASSERT_TRUE(stats.memory_current_bytes == 12345,
                "memory_current_bytes mismatch");

    TEST("memory.peak parsed");
    ASSERT_TRUE(stats.memory_peak_bytes == 67890,
                "memory_peak_bytes mismatch");

    TEST("memory.max \"max\" maps to UINT64_MAX");
    ASSERT_TRUE(stats.memory_max_bytes == UINT64_MAX,
                "memory_max_bytes should be UINT64_MAX");

    TEST("pids.current parsed");
    ASSERT_EQ(stats.pids_current, 7);

    TEST("pids.max \"max\" maps to -1");
    ASSERT_EQ(stats.pids_max, -1);

    TEST("cpu.stat usage_usec parsed");
    ASSERT_TRUE(stats.cpu_usage_usec == 1000, "cpu_usage_usec mismatch");

    TEST("cpu.stat user_usec parsed");
    ASSERT_TRUE(stats.cpu_user_usec == 600, "cpu_user_usec mismatch");

    TEST("cpu.stat system_usec parsed");
    ASSERT_TRUE(stats.cpu_system_usec == 400, "cpu_system_usec mismatch");

    /* Cleanup */
    remove_file(dir, "memory.current");
    remove_file(dir, "memory.peak");
    remove_file(dir, "memory.max");
    remove_file(dir, "pids.current");
    remove_file(dir, "pids.max");
    remove_file(dir, "cpu.stat");
    rmdir(dir);
}

static void test_synthetic_missing_files(void)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "/tmp/libprocfs_cgtest_empty_%d", (int)getpid());

    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        TEST("synthetic empty cgroup dir creation");
        ASSERT_TRUE(0, "mkdir failed");
        return;
    }

    cgroup_stats_t stats;
    int ret = read_cgroup_stats(dir, &stats);

    TEST("read_cgroup_stats on empty dir is non-fatal (returns 0)");
    ASSERT_EQ(ret, 0);

    TEST("missing controller files leave fields zeroed");
    ASSERT_TRUE(stats.memory_current_bytes == 0 &&
                stats.cpu_usage_usec == 0 &&
                stats.pids_current == 0,
                "fields should stay zero when files are absent");

    rmdir(dir);
}

int main(void)
{
    printf("\n=== Running cgroups Tests ===\n\n");

    test_stats_null_path();
    test_stats_null_stats();
    test_get_pid_cgroup_null_buf();
    test_get_pid_cgroup_zero_len();
    test_get_pid_cgroup_nonexistent();
    test_get_pid_cgroup_current();

    test_synthetic_numeric_and_max();
    test_synthetic_missing_files();

    printf("\n=== Test Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n", tests_passed + tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
