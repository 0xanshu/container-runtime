// Phase 3 — tests/test_eventlog.c
//
// Unit tests for the JSONL event module.  No root, no cgroup and no
// container runtime are required: everything runs against temporary
// directories.  The concurrency case exercises the process-local mutex
// that serializes watchdog-thread and lifecycle-thread appends.

#include "eventlog.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "FAIL: %s — %s\n", __func__, msg);          \
            return 1;                                                   \
        }                                                               \
    } while (0)

/* ------------------------------------------------------------------ */
/* Temp-directory helpers                                              */
/* ------------------------------------------------------------------ */

static int make_temp_dir(char *out, size_t size)
{
    const char *base = getenv("TMPDIR");
    if (!base || base[0] == '\0') base = "/tmp";

    int n = snprintf(out, size, "%s/minicontainer_eventlog_XXXXXX", base);
    if (n < 0 || (size_t)n >= size) return -1;
    return mkdtemp(out) ? 0 : -1;
}

static void rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return;

    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) {
                    continue;
                }
                char child[PATH_MAX];
                int n = snprintf(child, sizeof(child), "%s/%s",
                                 path, entry->d_name);
                if (n > 0 && (size_t)n < sizeof(child)) rm_rf(child);
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static char *read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long end = ftell(f);
    if (end < 0) { fclose(f); return NULL; }
    rewind(f);

    char *buf = malloc((size_t)end + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)end, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static size_t count_lines(const char *text)
{
    size_t n = 0;
    for (const char *p = text; *p; p++) {
        if (*p == '\n') n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Formatting tests                                                    */
/* ------------------------------------------------------------------ */

static int test_event_type_names(void)
{
    CHECK(strcmp(event_type_to_string(EVENT_CONTAINER_START),
                 "container_start") == 0, "container_start name");
    CHECK(strcmp(event_type_to_string(EVENT_CONTAINER_EXIT),
                 "container_exit") == 0, "container_exit name");
    CHECK(strcmp(event_type_to_string(EVENT_RESOURCE_BREACH),
                 "resource_breach") == 0, "resource_breach name");
    CHECK(strcmp(event_type_to_string(EVENT_TIMEOUT_KILL),
                 "timeout_kill") == 0, "timeout_kill name");
    CHECK(strcmp(event_type_to_string(EVENT_OOM_KILL),
                 "oom_kill") == 0, "oom_kill name");
    CHECK(strcmp(event_type_to_string(EVENT_TYPE_COUNT),
                 "unknown") == 0, "unknown type fallback");
    printf("PASS: test_event_type_names\n");
    return 0;
}

static int test_timestamp_format(void)
{
    char buf[40];

    struct timespec epoch = { 0, 0 };
    event_format_timestamp(&epoch, buf, sizeof(buf));
    CHECK(strcmp(buf, "1970-01-01T00:00:00.000Z") == 0,
          "epoch timestamp mismatch");

    struct timespec ts = { 1697123456, 123456789 };
    event_format_timestamp(&ts, buf, sizeof(buf));
    CHECK(strcmp(buf, "2023-10-12T15:10:56.123Z") == 0,
          "UTC millisecond timestamp mismatch");

    /* Truncated nanosecond part must still produce three digits. */
    ts.tv_nsec = 1;
    event_format_timestamp(&ts, buf, sizeof(buf));
    CHECK(strcmp(buf, "2023-10-12T15:10:56.000Z") == 0,
          "sub-millisecond timestamp should round down");

    printf("PASS: test_timestamp_format\n");
    return 0;
}

static int test_json_escaping(void)
{
    char out[256];

    CHECK(event_json_escape("a\"b\\c\nd\te\x01\x7f", out, sizeof(out)) == 0,
          "escape failed");
    CHECK(strcmp(out, "a\\\"b\\\\c\\nd\\te\\u0001\\u007f") == 0,
          "unexpected escape sequence");

    /* Valid UTF-8 bytes pass through unchanged. */
    CHECK(event_json_escape("caf\xC3\xA9", out, sizeof(out)) == 0,
          "UTF-8 escape failed");
    CHECK(strcmp(out, "caf\xC3\xA9") == 0, "UTF-8 bytes were altered");

    /* A too-small buffer fails cleanly and leaves an empty string. */
    CHECK(event_json_escape("abc", out, 3) == -1,
          "small buffer should fail");
    CHECK(out[0] == '\0', "small buffer should be cleared");

    printf("PASS: test_json_escaping\n");
    return 0;
}

static int test_format_json(void)
{
    event_t event;
    memset(&event, 0, sizeof(event));
    event.type = EVENT_RESOURCE_BREACH;
    event.timestamp.tv_sec = 0;
    event.timestamp.tv_nsec = 0;
    strcpy(event.container_id, "abc123");
    strcpy(event.details,
           "{\"resource\":\"memory\",\"percentage\":0.5}");

    char line[EVENT_LINE_MAX];
    int rc = event_format_json(&event, line, sizeof(line));
    CHECK(rc == 0, "event_format_json should succeed");

    const char *expected =
        "{\"timestamp\":\"1970-01-01T00:00:00.000Z\","
        "\"container_id\":\"abc123\","
        "\"event_type\":\"resource_breach\","
        "\"details\":{\"resource\":\"memory\",\"percentage\":0.5}}\n";
    CHECK(strcmp(line, expected) == 0, "line format mismatch");

    /* Non-object details are replaced by a still-valid object. */
    strcpy(event.details, "not-json");
    rc = event_format_json(&event, line, sizeof(line));
    CHECK(rc >= 0, "fallback formatting failed");
    CHECK(strstr(line, "\"details\":{\"truncated\":true}") != NULL,
          "missing truncation fallback");
    CHECK(line[strlen(line) - 1] == '\n', "missing trailing newline");

    /* A buffer too small for even the reduced line fails cleanly. */
    char tiny[8];
    rc = event_format_json(&event, tiny, sizeof(tiny));
    CHECK(rc == -1, "tiny buffer should fail");
    CHECK(tiny[0] == '\0', "tiny buffer should be cleared");

    printf("PASS: test_format_json\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Constructor schema tests                                            */
/* ------------------------------------------------------------------ */

static int test_constructor_fields(void)
{
    event_t event;
    char *argv[] = { (char *)"echo", (char *)"hello", NULL };

    event_container_start(&event, "id123", "/bin/echo", argv, "default",
                          1000, 536870912ULL, 0.5, 50, 300);
    CHECK(event.type == EVENT_CONTAINER_START, "start type");
    CHECK(strstr(event.details, "\"program\":\"/bin/echo\"") != NULL,
          "start program");
    CHECK(strstr(event.details, "\"argv\":[\"echo\",\"hello\"]") != NULL,
          "start argv");
    CHECK(strstr(event.details, "\"policy\":\"default\"") != NULL,
          "start policy");
    CHECK(strstr(event.details, "\"user_id\":1000") != NULL,
          "start user_id");
    CHECK(strstr(event.details, "\"memory_bytes\":536870912") != NULL,
          "start memory limit");
    CHECK(strstr(event.details, "\"pids\":50") != NULL, "start pids");
    CHECK(strstr(event.details, "\"timeout\":300") != NULL, "start timeout");
    CHECK(strstr(event.json_line, "\"event_type\":\"container_start\"") != NULL,
          "start json_line");
    CHECK(event.json_line[strlen(event.json_line) - 1] == '\n',
          "start json_line newline");

    event_container_exit(&event, "id123", 42, "normal", 1.25, 0.5, 1024);
    CHECK(event.type == EVENT_CONTAINER_EXIT, "exit type");
    CHECK(strstr(event.details, "\"exit_code\":42") != NULL, "exit code");
    CHECK(strstr(event.details, "\"exit_reason\":\"normal\"") != NULL,
          "exit reason");
    CHECK(strstr(event.details, "\"wall_clock_seconds\":1.250000") != NULL,
          "wall clock");
    CHECK(strstr(event.details, "\"cpu_time_seconds\":0.500000") != NULL,
          "cpu time");
    CHECK(strstr(event.details, "\"memory_peak_bytes\":1024") != NULL,
          "memory peak");

    event_resource_breach(&event, "id123", "memory", 471859200.0,
                          536870912.0, 0.9, 0.88);
    CHECK(event.type == EVENT_RESOURCE_BREACH, "breach type");
    CHECK(strstr(event.details, "\"resource\":\"memory\"") != NULL,
          "breach resource");
    CHECK(strstr(event.details, "\"current_value\":471859200.000000") != NULL,
          "breach current value");
    CHECK(strstr(event.details, "\"limit_value\":536870912.000000") != NULL,
          "breach limit value");
    CHECK(strstr(event.details, "\"threshold\":0.900000") != NULL,
          "breach threshold");
    CHECK(strstr(event.details, "\"percentage\":0.880000") != NULL,
          "breach percentage");

    event_timeout_kill(&event, "id123", 5, 5.05, "SIGKILL", true);
    CHECK(event.type == EVENT_TIMEOUT_KILL, "timeout type");
    CHECK(strstr(event.details, "\"timeout_seconds\":5") != NULL,
          "timeout seconds");
    CHECK(strstr(event.details, "\"elapsed_seconds\":5.050000") != NULL,
          "timeout elapsed");
    CHECK(strstr(event.details, "\"signal\":\"SIGKILL\"") != NULL,
          "timeout signal");
    CHECK(strstr(event.details, "\"grace_period_used\":true") != NULL,
          "timeout grace");

    event_oom_kill(&event, "id123", 536870912ULL, 550000000ULL, 137);
    CHECK(event.type == EVENT_OOM_KILL, "oom type");
    CHECK(strstr(event.details, "\"memory_limit_bytes\":536870912") != NULL,
          "oom limit");
    CHECK(strstr(event.details, "\"memory_peak_bytes\":550000000") != NULL,
          "oom peak");
    CHECK(strstr(event.details, "\"exit_code\":137") != NULL, "oom exit code");

    printf("PASS: test_constructor_fields\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Path + persistence tests                                            */
/* ------------------------------------------------------------------ */

static int test_eventlog_path(void)
{
    char path[PATH_MAX];
    CHECK(eventlog_path("/var/log/minicontainer/events", "abc123",
                        path, sizeof(path)) == 0, "valid path failed");
    CHECK(strcmp(path, "/var/log/minicontainer/events/abc123.jsonl") == 0,
          "path mismatch");

    const char *bad[] = { "", "../escape", "a/b", "a\\b", "..", "a..b" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(eventlog_path("/tmp", bad[i], path, sizeof(path)) == -1,
              "path traversal should be rejected");
    }

    char small[8];
    CHECK(eventlog_path("/tmp", "abc123", small, sizeof(small)) == -1,
          "short buffer should fail");

    printf("PASS: test_eventlog_path\n");
    return 0;
}

static int test_init_modes_and_idempotence(void)
{
    char base[PATH_MAX];
    CHECK(make_temp_dir(base, sizeof(base)) == 0, "mkdtemp failed");

    char dir[PATH_MAX], file[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/nested/events", base);
    CHECK(n > 0 && (size_t)n < sizeof(dir), "dir path truncated");
    n = snprintf(file, sizeof(file), "%s/abc123.jsonl", dir);
    CHECK(n > 0 && (size_t)n < sizeof(file), "file path truncated");

    mode_t old_umask = umask(0);
    int rc = eventlog_init(dir, "abc123");
    umask(old_umask);
    CHECK(rc == 0, "eventlog_init failed");

    struct stat st;
    CHECK(stat(dir, &st) == 0 && S_ISDIR(st.st_mode), "log dir missing");
    CHECK((st.st_mode & 0777) == 0755, "log dir should be 0755");
    CHECK(stat(file, &st) == 0 && S_ISREG(st.st_mode), "log file missing");
    CHECK((st.st_mode & 0777) == 0644, "log file should be 0644");

    /* Idempotent: a second init keeps the same empty file. */
    CHECK(eventlog_init(dir, "abc123") == 0, "second eventlog_init failed");
    CHECK(stat(file, &st) == 0 && st.st_size == 0, "file should stay empty");

    rm_rf(base);
    printf("PASS: test_init_modes_and_idempotence\n");
    return 0;
}

static int test_append_creates_second_line(void)
{
    char base[PATH_MAX];
    CHECK(make_temp_dir(base, sizeof(base)) == 0, "mkdtemp failed");

    char dir[PATH_MAX], file[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/events", base);
    snprintf(file, sizeof(file), "%s/id1.jsonl", dir);

    CHECK(eventlog_init(dir, "id1") == 0, "eventlog_init failed");

    event_t event;
    event_container_start(&event, "id1", "/bin/true", NULL, "none", 0,
                          0, 0.0, 0, 0);
    CHECK(eventlog_append(dir, "id1", &event) == 0, "first append failed");
    event_container_exit(&event, "id1", 0, "normal", 0.1, 0.0, 0);
    CHECK(eventlog_append(dir, "id1", &event) == 0, "second append failed");

    size_t len = 0;
    char *text = read_all(file, &len);
    CHECK(text != NULL, "read failed");
    CHECK(count_lines(text) == 2, "expected exactly two lines");
    CHECK(strstr(text, "\"event_type\":\"container_start\"") != NULL,
          "missing start line");
    CHECK(strstr(text, "\"event_type\":\"container_exit\"") != NULL,
          "missing exit line");
    CHECK(text[len - 1] == '\n', "file should end with newline");
    free(text);

    /* append() alone creates the file (init is advisory, not required). */
    char file2[PATH_MAX];
    snprintf(file2, sizeof(file2), "%s/id2.jsonl", dir);
    event_container_start(&event, "id2", "/bin/true", NULL, "none", 0,
                          0, 0.0, 0, 0);
    CHECK(eventlog_append(dir, "id2", &event) == 0, "append-create failed");
    CHECK(access(file2, F_OK) == 0, "id2 file was not created");

    rm_rf(base);
    printf("PASS: test_append_creates_second_line\n");
    return 0;
}

typedef struct {
    const char *dir;
    int         rc;
} conc_arg_t;

static void *concurrent_appender(void *raw)
{
    conc_arg_t *arg = (conc_arg_t *)raw;
    for (int i = 0; i < 100; i++) {
        event_t event;
        event_container_exit(&event, "conc123", i, "normal",
                             (double)i, 0.0, (uint64_t)i);
        if (eventlog_append(arg->dir, "conc123", &event) < 0) {
            arg->rc = -1;
            return NULL;
        }
    }
    arg->rc = 0;
    return NULL;
}

static int test_concurrent_appends(void)
{
    char base[PATH_MAX];
    CHECK(make_temp_dir(base, sizeof(base)) == 0, "mkdtemp failed");

    char dir[PATH_MAX], file[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/events", base);
    snprintf(file, sizeof(file), "%s/conc123.jsonl", dir);
    CHECK(eventlog_init(dir, "conc123") == 0, "eventlog_init failed");

    enum { THREADS = 4 };
    pthread_t threads[THREADS];
    conc_arg_t args[THREADS];
    for (int i = 0; i < THREADS; i++) {
        args[i].dir = dir;
        args[i].rc = -2;
        CHECK(pthread_create(&threads[i], NULL, concurrent_appender,
                             &args[i]) == 0, "pthread_create failed");
    }
    for (int i = 0; i < THREADS; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0, "pthread_join failed");
        CHECK(args[i].rc == 0, "concurrent append failed");
    }

    size_t len = 0;
    char *text = read_all(file, &len);
    CHECK(text != NULL, "read failed");
    CHECK(count_lines(text) == THREADS * 100, "lost or extra lines");

    /* Every line must be a complete, single JSON object. */
    size_t lines = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        lines++;
        CHECK(line[0] == '{', "line does not start with object");
        CHECK(line[strlen(line) - 1] == '}', "line does not end with object");
        CHECK(strstr(line, "\"event_type\":\"container_exit\"") != NULL,
              "line missing event type");
        /* Exactly one container_id key => no two fragments interleaved. */
        size_t occurrences = 0;
        for (const char *p = line; (p = strstr(p, "\"container_id\"")) != NULL;
             p += 14) {
            occurrences++;
        }
        CHECK(occurrences == 1, "interleaved line detected");
    }
    CHECK(lines == THREADS * 100, "strtok line count mismatch");
    free(text);

    rm_rf(base);
    printf("PASS: test_concurrent_appends\n");
    return 0;
}

static int test_failures_are_clean(void)
{
    char base[PATH_MAX];
    CHECK(make_temp_dir(base, sizeof(base)) == 0, "mkdtemp failed");

    char blocker[PATH_MAX], dir[PATH_MAX];
    snprintf(blocker, sizeof(blocker), "%s/not-a-directory", base);
    int fd = open(blocker, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0, "could not create blocker file");
    close(fd);

    snprintf(dir, sizeof(dir), "%s/sub", blocker);
    CHECK(eventlog_init(dir, "id1") == -1, "init should fail under a file");

    event_t event;
    event_container_start(&event, "id1", "/bin/true", NULL, "none", 0,
                          0, 0.0, 0, 0);
    CHECK(eventlog_append(dir, "id1", &event) == -1,
          "append should fail under a file");

    rm_rf(base);
    printf("PASS: test_failures_are_clean\n");
    return 0;
}

static int test_truncation_is_valid_json(void)
{
    char big[EVENT_DETAILS_MAX * 2];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    char *argv[] = { big, big, NULL };
    event_t event;
    event_container_start(&event, "id1", big, argv, big, 0, 0, 0.0, 0, 0);

    CHECK(event.truncated, "oversized event should set truncated");
    CHECK(strcmp(event.details, "{\"truncated\":true}") == 0,
          "overflow should fall back to valid JSON");
    CHECK(strstr(event.json_line, "\"details\":{\"truncated\":true}") != NULL,
          "json_line should carry the fallback");
    CHECK(event.json_line[strlen(event.json_line) - 1] == '\n',
          "json_line should still end with newline");

    printf("PASS: test_truncation_is_valid_json\n");
    return 0;
}

int main(void)
{
    int rc = 0;

    rc |= test_event_type_names();
    rc |= test_timestamp_format();
    rc |= test_json_escaping();
    rc |= test_format_json();
    rc |= test_constructor_fields();
    rc |= test_eventlog_path();
    rc |= test_init_modes_and_idempotence();
    rc |= test_append_creates_second_line();
    rc |= test_concurrent_appends();
    rc |= test_failures_are_clean();
    rc |= test_truncation_is_valid_json();

    if (rc == 0) {
        printf("\nAll eventlog tests passed!\n");
    }
    return rc;
}
