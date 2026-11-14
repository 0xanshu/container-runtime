// Phase 2 — tests/test_watchdog.c
//
// Unit tests for the parent-side watchdog.  No root and no real cgroup
// are required: timeout cases use ordinary host processes, and cgroup
// threshold logic is driven through a fake directory containing the v2
// files read_cgroup_stats()/watchdog expect.
//
// Every child is reaped with a bounded waitpid; a broken watchdog FAILS
// the test (and SIGKILLs the child) instead of hanging.

#include "watchdog.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "FAIL: %s — %s\n", __func__, msg);          \
            return 1;                                                   \
        }                                                               \
    } while (0)

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static pid_t spawn_sh(const char *script)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", script, (char *)NULL);
        _exit(127);
    }
    return pid;
}

/* Wait up to timeout_ms; on timeout SIGKILL the child so the test can
 * report a clean failure instead of hanging. */
static int wait_bounded(pid_t pid, int *status, int timeout_ms)
{
    int waited = 0;
    for (;;) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (waited >= timeout_ms) {
            kill(pid, SIGKILL);
            waitpid(pid, status, 0);
            return -1;
        }
        sleep_ms(10);
        waited += 10;
    }
}

static watchdog_context_t *make_watchdog(pid_t pid, uint32_t timeout,
                                         uint32_t grace)
{
    watchdog_context_t *wd = calloc(1, sizeof(*wd));
    if (!wd) return NULL;
    wd->child_pid = pid;
    wd->timeout_seconds = timeout;
    wd->grace_period_seconds = grace;
    wd->poll_interval_ms = 50;   /* faster unit-test feedback */
    clock_gettime(CLOCK_MONOTONIC, &wd->start_time);
    return wd;
}

/* Timeout sends SIGTERM and the child dies before the grace expires. */
static int test_timeout_terminates_child(void)
{
    pid_t pid = spawn_sh("sleep 30");
    CHECK(pid > 0, "spawn failed");

    watchdog_context_t *wd = make_watchdog(pid, 1, 2);
    CHECK(wd != NULL, "calloc failed");
    CHECK(watchdog_start(wd) == 0, "watchdog_start failed");

    int st = 0;
    CHECK(wait_bounded(pid, &st, 6000) == 0, "child was not terminated");
    watchdog_stop(wd);
    watchdog_finalize_stats(wd);

    CHECK(watchdog_was_timeout_killed(wd), "timeout_killed not set");
    CHECK(WIFSIGNALED(st), "child did not die by signal");
    CHECK(WTERMSIG(st) == SIGTERM, "expected SIGTERM from timeout sequence");
    CHECK(!wd->grace_period_used, "grace should not have been used");

    watchdog_free(wd);
    printf("PASS: test_timeout_terminates_child\n");
    return 0;
}

/* Child traps SIGTERM and exits cleanly inside the grace period: no
 * SIGKILL, no grace_period_used. */
static int test_graceful_exit_during_grace(void)
{
    pid_t pid = spawn_sh("trap 'exit 7' TERM; while :; do sleep 1; done");
    CHECK(pid > 0, "spawn failed");

    watchdog_context_t *wd = make_watchdog(pid, 1, 5);
    CHECK(wd != NULL, "calloc failed");
    CHECK(watchdog_start(wd) == 0, "watchdog_start failed");

    int st = 0;
    CHECK(wait_bounded(pid, &st, 6000) == 0, "child was not terminated");
    watchdog_stop(wd);
    watchdog_finalize_stats(wd);

    CHECK(watchdog_was_timeout_killed(wd), "timeout_killed not set");
    CHECK(WIFEXITED(st), "child should exit normally after trapping SIGTERM");
    CHECK(WEXITSTATUS(st) == 7, "trap handler exit code not preserved");
    CHECK(!wd->grace_period_used, "SIGKILL should not have been needed");

    watchdog_free(wd);
    printf("PASS: test_graceful_exit_during_grace\n");
    return 0;
}

/* Child ignores SIGTERM; watchdog escalates to SIGKILL after grace. */
static int test_sigkill_after_grace(void)
{
    pid_t pid = spawn_sh("trap '' TERM; while :; do :; done");
    CHECK(pid > 0, "spawn failed");

    watchdog_context_t *wd = make_watchdog(pid, 1, 1);
    CHECK(wd != NULL, "calloc failed");
    CHECK(watchdog_start(wd) == 0, "watchdog_start failed");

    int st = 0;
    CHECK(wait_bounded(pid, &st, 8000) == 0, "child was not escalated to SIGKILL");
    watchdog_stop(wd);
    watchdog_finalize_stats(wd);

    CHECK(watchdog_was_timeout_killed(wd), "timeout_killed not set");
    CHECK(WIFSIGNALED(st), "child did not die by signal");
    CHECK(WTERMSIG(st) == SIGKILL, "expected SIGKILL after grace");
    CHECK(wd->grace_period_used, "grace_period_used not set");

    watchdog_free(wd);
    printf("PASS: test_sigkill_after_grace\n");
    return 0;
}

/* timeout_seconds == 0 must leave a short-lived child alone. */
static int test_no_timeout(void)
{
    pid_t pid = spawn_sh("exit 0");
    CHECK(pid > 0, "spawn failed");

    watchdog_context_t *wd = make_watchdog(pid, 0, 0);
    CHECK(wd != NULL, "calloc failed");
    CHECK(watchdog_start(wd) == 0, "watchdog_start failed");

    int st = 0;
    CHECK(wait_bounded(pid, &st, 3000) == 0, "child did not exit");
    watchdog_stop(wd);

    CHECK(!watchdog_was_timeout_killed(wd), "timeout must stay disabled");
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child exit status changed");

    watchdog_free(wd);
    printf("PASS: test_no_timeout\n");
    return 0;
}

/* watchdog_stop() before the timeout joins cleanly and is idempotent. */
static int test_stop_before_timeout(void)
{
    pid_t pid = spawn_sh("sleep 30");
    CHECK(pid > 0, "spawn failed");

    watchdog_context_t *wd = make_watchdog(pid, 30, 5);
    CHECK(wd != NULL, "calloc failed");
    CHECK(watchdog_start(wd) == 0, "watchdog_start failed");

    sleep_ms(200);
    kill(pid, SIGTERM);

    int st = 0;
    CHECK(wait_bounded(pid, &st, 3000) == 0, "child did not exit after SIGTERM");

    watchdog_stop(wd);
    watchdog_stop(wd);   /* idempotent */

    CHECK(!watchdog_was_timeout_killed(wd), "no timeout should have fired");
    CHECK(!wd->running, "running must be false after stop");

    watchdog_free(wd);
    printf("PASS: test_stop_before_timeout\n");
    return 0;
}

/* Invalid context fails cleanly and never crashes. */
static int test_start_invalid_context(void)
{
    watchdog_context_t wd;
    memset(&wd, 0, sizeof(wd));

    CHECK(watchdog_start(&wd) == -1, "zero child_pid must be rejected");
    CHECK(wd.error_code != 0, "error_code not set");
    CHECK(wd.error_message[0] != '\0', "error_message not set");

    watchdog_stop(&wd);   /* safe on a never-started context */

    watchdog_stats_t stats;
    watchdog_get_stats(&wd, &stats);
    CHECK(stats.memory_peak_bytes == 0, "stats should be zeroed");

    printf("PASS: test_start_invalid_context\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fake-cgroup threshold tests                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    char type[32];
    char details[256];
} captured_event_t;

typedef struct {
    captured_event_t events[16];
    int count;
} capture_t;

static void capture_cb(const char *type, const char *details, void *userdata)
{
    capture_t *cap = userdata;
    if (cap->count >= (int)(sizeof(cap->events) / sizeof(cap->events[0])))
        return;
    snprintf(cap->events[cap->count].type,
             sizeof(cap->events[cap->count].type), "%s", type);
    snprintf(cap->events[cap->count].details,
             sizeof(cap->events[cap->count].details), "%s", details);
    cap->count++;
}

static int write_file(const char *dir, const char *name, const char *content)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    int rc = fputs(content, fp) < 0 ? -1 : 0;
    fclose(fp);
    return rc;
}

static int remove_fake_cgroup(const char *dir)
{
    static const char *files[] = {
        "memory.current", "memory.peak", "memory.max",
        "cpu.stat", "pids.current", "pids.max", "memory.events"
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
        if (n > 0 && (size_t)n < sizeof(path)) unlink(path);
    }
    return rmdir(dir);
}

static void set_poll_baseline(watchdog_context_t *wd, uint64_t cpu_usec,
                              int wall_ms)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    wd->last_poll_time = now;
    wd->last_poll_time.tv_nsec -= (long)wall_ms * 1000000L;
    while (wd->last_poll_time.tv_nsec < 0) {
        wd->last_poll_time.tv_nsec += 1000000000L;
        wd->last_poll_time.tv_sec--;
    }
    wd->last_cpu_usage_usec = cpu_usec;
    wd->have_last_poll = true;
}

static int test_thresholds_and_oom(void)
{
    char tmpl[] = "/tmp/mc-watchdog-XXXXXX";
    char *dir = mkdtemp(tmpl);
    CHECK(dir != NULL, "mkdtemp failed");

    CHECK(write_file(dir, "memory.current", "900\n") == 0, "memory.current");
    CHECK(write_file(dir, "memory.peak", "950\n") == 0, "memory.peak");
    CHECK(write_file(dir, "memory.max", "1000\n") == 0, "memory.max");
    CHECK(write_file(dir, "cpu.stat",
                     "usage_usec 200000\nuser_usec 0\nsystem_usec 0\n") == 0,
          "cpu.stat");
    CHECK(write_file(dir, "pids.current", "3\n") == 0, "pids.current");
    CHECK(write_file(dir, "pids.max", "10\n") == 0, "pids.max");
    CHECK(write_file(dir, "memory.events", "low 0\noom_kill 1\n") == 0,
          "memory.events");

    capture_t cap;
    memset(&cap, 0, sizeof(cap));

    watchdog_context_t wd;
    memset(&wd, 0, sizeof(wd));
    snprintf(wd.cgroup_path, sizeof(wd.cgroup_path), "%s", dir);
    wd.memory_warning_threshold = 0.80;
    wd.cpu_warning_threshold    = 0.80;
    wd.cpu_warning_duration_ms  = 100;
    wd.event_cb = capture_cb;
    wd.event_userdata = &cap;

    set_poll_baseline(&wd, 0, 100);
    CHECK(watchdog_poll_once(&wd) == 0, "poll_once failed");

    CHECK(wd.memory_breach_count == 1, "memory breach not detected");
    CHECK(wd.cpu_breach_count == 1, "sustained CPU breach not detected");
    CHECK(cap.count == 2, "expected memory + CPU events");
    CHECK(strcmp(cap.events[0].type, "resource_breach") == 0, "event type");
    CHECK(strstr(cap.events[0].details, "resource=memory") != NULL,
          "memory event details");
    CHECK(strstr(cap.events[1].details, "resource=cpu") != NULL,
          "cpu event details");

    CHECK(wd.oom_detected, "OOM kill not detected");
    CHECK(wd.oom_kill_count == 1, "OOM count wrong");
    CHECK(wd.memory_peak_bytes == 950, "peak bytes not captured");
    CHECK(wd.pids_current == 3 && wd.pids_max == 10, "pids stats wrong");

    /* Higher CPU usage, same breach window: cooldown must suppress a
     * duplicate event (memory likewise stays marked). */
    CHECK(write_file(dir, "cpu.stat",
                     "usage_usec 400000\nuser_usec 0\nsystem_usec 0\n") == 0,
          "cpu.stat update");
    set_poll_baseline(&wd, 200000, 100);
    CHECK(watchdog_poll_once(&wd) == 0, "second poll failed");
    CHECK(wd.cpu_breach_count == 1, "CPU breach event duplicated");
    CHECK(wd.memory_breach_count == 1, "memory breach event duplicated");
    CHECK(cap.count == 2, "no duplicate events expected");

    /* New OOM kill increments the running count. */
    CHECK(write_file(dir, "memory.events", "low 0\noom_kill 3\n") == 0,
          "memory.events update");
    CHECK(watchdog_poll_once(&wd) == 0, "third poll failed");
    CHECK(wd.oom_kill_count == 3, "OOM delta not accumulated");

    CHECK(remove_fake_cgroup(dir) == 0, "fake cgroup cleanup failed");
    printf("PASS: test_thresholds_and_oom\n");
    return 0;
}

static int test_below_thresholds(void)
{
    char tmpl[] = "/tmp/mc-watchdog-low-XXXXXX";
    char *dir = mkdtemp(tmpl);
    CHECK(dir != NULL, "mkdtemp failed");

    CHECK(write_file(dir, "memory.current", "500\n") == 0, "memory.current");
    CHECK(write_file(dir, "memory.max", "1000\n") == 0, "memory.max");
    CHECK(write_file(dir, "cpu.stat",
                     "usage_usec 10000\nuser_usec 0\nsystem_usec 0\n") == 0,
          "cpu.stat");

    capture_t cap;
    memset(&cap, 0, sizeof(cap));

    watchdog_context_t wd;
    memset(&wd, 0, sizeof(wd));
    snprintf(wd.cgroup_path, sizeof(wd.cgroup_path), "%s", dir);
    wd.memory_warning_threshold = 0.80;
    wd.cpu_warning_threshold    = 0.80;
    wd.cpu_warning_duration_ms  = 100;
    wd.event_cb = capture_cb;
    wd.event_userdata = &cap;

    set_poll_baseline(&wd, 0, 100);
    CHECK(watchdog_poll_once(&wd) == 0, "poll_once failed");

    CHECK(wd.memory_breach_count == 0, "false memory breach");
    CHECK(wd.cpu_breach_count == 0, "false CPU breach");
    CHECK(cap.count == 0, "no events expected below threshold");
    CHECK(!wd.oom_detected, "no OOM expected without memory.events");

    CHECK(remove_fake_cgroup(dir) == 0, "fake cgroup cleanup failed");
    printf("PASS: test_below_thresholds\n");
    return 0;
}

/* Empty cgroup_path means "no monitoring", not a failure. */
static int test_poll_without_cgroup(void)
{
    watchdog_context_t wd;
    memset(&wd, 0, sizeof(wd));
    CHECK(watchdog_poll_once(&wd) == 0, "empty cgroup should be a no-op");
    CHECK(watchdog_poll_once(NULL) == -1, "NULL poll should fail");

    watchdog_stats_t stats;
    watchdog_get_stats(NULL, &stats);
    CHECK(stats.memory_peak_bytes == 0, "NULL stats must be zeroed");

    printf("PASS: test_poll_without_cgroup\n");
    return 0;
}

int main(void)
{
    int rc = 0;
    printf("=== test_watchdog ===\n");
    rc |= test_timeout_terminates_child();
    rc |= test_graceful_exit_during_grace();
    rc |= test_sigkill_after_grace();
    rc |= test_no_timeout();
    rc |= test_stop_before_timeout();
    rc |= test_start_invalid_context();
    rc |= test_thresholds_and_oom();
    rc |= test_below_thresholds();
    rc |= test_poll_without_cgroup();
    if (rc == 0) {
        printf("\nAll watchdog tests passed!\n");
    }
    return rc;
}
