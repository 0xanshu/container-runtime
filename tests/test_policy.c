// Phase 1: tests/test_policy.c
// Exercises the policy module end-to-end without running a container:
//
//   policy_get_default()          built-in defaults
//   policy_load()                 stat/access, JSON parsing, validation
//   policy_validate()             every required error message
//   policy_apply()                mapping onto container_config_t
//   policy_parse_memory_string()  shared CLI/policy size syntax
//   policy_free()                 safe reset of zeroed/partial structs
//
// No root required: nothing here touches cgroups, namespaces, or the
// filesystem outside /tmp.

#include "policy.h"
#include "core.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "FAIL: %s — %s\n", __func__, msg);          \
            return 1;                                                   \
        }                                                               \
    } while (0)

#define FIXTURE_DIR "tests/fixtures/policies"

static bool approx(double a, double b)
{
    return fabs(a - b) < 1e-9;
}

/* Build a fixture path, tolerating `make test` from either the repo
 * root or the tests/ directory. */
static const char *fixture(const char *name, char *buf, size_t cap)
{
    snprintf(buf, cap, "%s/%s", FIXTURE_DIR, name);
    if (access(buf, R_OK) == 0) return buf;

    snprintf(buf, cap, "../%s/%s", FIXTURE_DIR, name);
    return buf;
}

/* Write a temporary file with the given extension and content. */
static int write_temp(const char *ext, const char *content,
                      char *path, size_t cap)
{
    snprintf(path, cap, "/tmp/mcpolicy_%ld.%s", (long)getpid(), ext);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(content);
    if (fwrite(content, 1, n, f) != n) {
        fclose(f);
        unlink(path);
        return -1;
    }
    fclose(f);
    return 0;
}

static void reset(policy_t *p)
{
    policy_get_default(p);
}

/* ------------------------------------------------------------------ */
/* Defaults / free                                                     */
/* ------------------------------------------------------------------ */

static int test_defaults(void)
{
    policy_t p;
    memset(&p, 0xAA, sizeof(p));
    policy_get_default(&p);

    CHECK(strcmp(p.name, "default") == 0, "default name");
    CHECK(p.memory_limit == 0, "memory default 0");
    CHECK(approx(p.cpu_limit, 1.0), "cpu default 1.0");
    CHECK(p.pids_limit == 100, "pids default 100");
    CHECK(p.timeout == 0, "timeout default 0");
    CHECK(p.grace_period == 10, "grace default 10");
    CHECK(approx(p.memory_warning_threshold, 0.9), "memory warning 0.9");
    CHECK(approx(p.cpu_warning_threshold, 0.8), "cpu warning 0.8");
    CHECK(p.cpu_warning_duration_ms == 5000, "cpu warning duration 5s");
    CHECK(p.watchdog_poll_interval_ms == 100, "poll interval 100ms");
    CHECK(p.enable_hardening, "hardening default true");
    CHECK(p.log_enabled, "logging default enabled");
    CHECK(strcmp(p.log_dir, "/var/log/minicontainer/events") == 0,
          "default log dir");
    CHECK(p.is_valid, "defaults are valid");
    CHECK(p.warning_count == 0, "no default warnings");
    CHECK(p.source_path[0] == '\0', "no source path yet");

    printf("PASS: test_defaults\n");
    return 0;
}

static int test_free(void)
{
    policy_t p;

    /* Zeroed struct. */
    memset(&p, 0, sizeof(p));
    policy_free(&p);
    CHECK(p.memory_limit == 0 && p.pids_limit == 0 &&
          p.log_dir[0] == '\0' && !p.is_valid,
          "free on zeroed struct");

    /* Fully populated struct. */
    policy_get_default(&p);
    snprintf(p.name, sizeof(p.name), "x");
    policy_add_warning(&p, "warning");
    policy_free(&p);
    CHECK(p.name[0] == '\0' && p.warning_count == 0 &&
          !p.is_valid && p.validation_error[0] == '\0',
          "free clears populated struct");

    /* NULL is a no-op. */
    policy_free(NULL);

    printf("PASS: test_free\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Shared memory parser                                                */
/* ------------------------------------------------------------------ */

static int test_memory_parser(void)
{
    uint64_t bytes = 0;

    struct {
        const char *input;
        uint64_t expected;
    } good[] = {
        {"1048576", 1048576ULL},
        {"0", 0ULL},
        {"512K", 512ULL * 1024ULL},
        {"10K", 10ULL * 1024ULL},
        {"1M", 1024ULL * 1024ULL},
        {"1.5M", 1572864ULL},
        {"512M", 512ULL * 1024ULL * 1024ULL},
        {"1G", 1024ULL * 1024ULL * 1024ULL},
        {"1MB", 1024ULL * 1024ULL},
        {"1MiB", 1024ULL * 1024ULL},
        {"  2G  ", 2ULL * 1024ULL * 1024ULL * 1024ULL},
    };

    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        bytes = 0;
        if (policy_parse_memory_string(good[i].input, &bytes) != 0 ||
            bytes != good[i].expected) {
            fprintf(stderr, "FAIL: memory parser '%s' -> %llu (want %llu)\n",
                    good[i].input, (unsigned long long)bytes,
                    (unsigned long long)good[i].expected);
            return 1;
        }
    }

    const char *bad[] = {
        NULL, "", " ", "-1M", "+1M", "M", "K", "1X", "1M junk",
        "999999999999999999999999999999",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bytes = 123;
        if (policy_parse_memory_string(bad[i], &bytes) == 0) {
            fprintf(stderr, "FAIL: memory parser accepted '%s'\n",
                    bad[i] ? bad[i] : "(null)");
            return 1;
        }
    }

    CHECK(policy_parse_memory_string("1M", NULL) == -1, "NULL out");
    CHECK(policy_parse_memory_string(NULL, &bytes) == -1, "NULL input");

    printf("PASS: test_memory_parser\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Loading                                                             */
/* ------------------------------------------------------------------ */

static int test_load_valid(void)
{
    char path[512];
    policy_t p;
    int rc = policy_load(fixture("valid.json", path, sizeof(path)), &p);

    CHECK(rc == 0, p.validation_error);
    CHECK(p.is_valid, "valid flag");
    CHECK(strcmp(p.name, "valid") == 0, "policy name");
    CHECK(strcmp(p.version, "1.0") == 0, "policy version");
    CHECK(strcmp(p.description, "Standard workload policy") == 0,
          "policy description");
    CHECK(p.memory_limit == 512ULL * 1024ULL * 1024ULL, "512M memory");
    CHECK(approx(p.cpu_limit, 0.5), "cpu 0.5");
    CHECK(p.pids_limit == 50, "pids 50");
    CHECK(p.timeout == 300, "timeout 300");
    CHECK(p.grace_period == 10, "grace 10");
    CHECK(approx(p.memory_warning_threshold, 0.9), "memory warning");
    CHECK(approx(p.cpu_warning_threshold, 0.8), "cpu warning");
    CHECK(p.cpu_warning_duration_ms == 5000, "duration converted to ms");
    CHECK(p.watchdog_poll_interval_ms == 100, "default poll interval");
    CHECK(p.enable_hardening, "hardening enabled");
    CHECK(p.log_enabled, "logging enabled");
    CHECK(strcmp(p.log_dir, "/var/log/minicontainer/events") == 0,
          "custom log dir");
    CHECK(p.warning_count == 0, "no warnings for known fields");
    CHECK(strcmp(p.source_path, path) == 0, "source path recorded");
    policy_free(&p);

    printf("PASS: test_load_valid\n");
    return 0;
}

static int test_load_minimal(void)
{
    char path[512];
    policy_t p;
    int rc = policy_load(fixture("minimal.json", path, sizeof(path)), &p);

    CHECK(rc == 0, p.validation_error);
    CHECK(strcmp(p.name, "minimal") == 0, "name");
    CHECK(p.memory_limit == 104857600ULL, "numeric memory");
    CHECK(p.pids_limit == 25, "pids");
    CHECK(p.timeout == 60, "timeout");
    /* Omitted fields keep the policy-mode defaults. */
    CHECK(approx(p.cpu_limit, 1.0), "cpu default");
    CHECK(p.grace_period == 10, "grace default");
    CHECK(p.enable_hardening, "hardening default");
    CHECK(p.log_enabled, "logging default");
    policy_free(&p);

    printf("PASS: test_load_minimal\n");
    return 0;
}

static int test_load_numeric_and_integer_cpu(void)
{
    const char *json =
        "{\"policy\":{\"name\":\"numeric\"},"
        "\"resources\":{\"memory\":268435456,\"cpu\":1,\"pids\":7}}";
    char path[256];
    CHECK(write_temp("json", json, path, sizeof(path)) == 0,
          "temp write failed");

    policy_t p;
    int rc = policy_load(path, &p);
    unlink(path);
    CHECK(rc == 0, p.validation_error);
    CHECK(p.memory_limit == 268435456ULL, "numeric byte memory");
    CHECK(approx(p.cpu_limit, 1.0), "integer cpu accepted");
    CHECK(p.pids_limit == 7, "pids");
    policy_free(&p);

    printf("PASS: test_load_numeric_and_integer_cpu\n");
    return 0;
}

static int test_load_default_legacy_fixture(void)
{
    char path[512];
    policy_t p;
    int rc = policy_load(fixture("default_legacy.json", path, sizeof(path)),
                          &p);
    CHECK(rc == 0, p.validation_error);
    CHECK(strcmp(p.name, "default-legacy") == 0, "name");
    CHECK(p.memory_limit == 0, "no memory limit");
    CHECK(approx(p.cpu_limit, 1.0), "default cpu");
    CHECK(p.pids_limit == 100, "default pids");
    CHECK(p.timeout == 0, "no timeout");
    policy_free(&p);

    printf("PASS: test_load_default_legacy_fixture\n");
    return 0;
}

static int test_load_errors(void)
{
    policy_t p;
    char path[512];

    /* Missing file. */
    snprintf(path, sizeof(path), "%s/does_not_exist.json", FIXTURE_DIR);
    CHECK(policy_load(path, &p) == -1, "missing file must fail");
    char expected[PATH_MAX + 64];
    snprintf(expected, sizeof(expected), "Policy file not found: %s", path);
    CHECK(strcmp(p.validation_error, expected) == 0,
          "missing-file message");
    CHECK(!p.is_valid, "invalid after missing file");

    /* A directory is not a readable policy file. */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", FIXTURE_DIR);
    CHECK(policy_load(dir, &p) == -1, "directory must fail");
    snprintf(expected, sizeof(expected), "Cannot read policy file: %s", dir);
    CHECK(strcmp(p.validation_error, expected) == 0,
          "directory message");

    /* TOML is explicitly unsupported. */
    char toml[256];
    CHECK(write_temp("toml", "{\"policy\":{}}", toml, sizeof(toml)) == 0,
          "temp toml write failed");
    int rc = policy_load(toml, &p);
    unlink(toml);
    CHECK(rc == -1, "toml must fail");
    CHECK(strcmp(p.validation_error,
                 "TOML policy support is not available; use JSON") == 0,
          "toml message");

    /* Unreadable file (skipped for root, which bypasses permissions). */
    if (geteuid() != 0) {
        char unreadable[256];
        CHECK(write_temp("json", "{\"policy\":{}}", unreadable,
                         sizeof(unreadable)) == 0,
              "temp unreadable write failed");
        CHECK(chmod(unreadable, 0000) == 0, "chmod failed");
        rc = policy_load(unreadable, &p);
        chmod(unreadable, 0600);
        unlink(unreadable);
        CHECK(rc == -1, "unreadable must fail");
        snprintf(expected, sizeof(expected), "Cannot read policy file: %s",
                 unreadable);
        CHECK(strcmp(p.validation_error, expected) == 0,
              "unreadable message");
    }

    printf("PASS: test_load_errors\n");
    return 0;
}

static int test_invalid_syntax(void)
{
    char path[512];
    policy_t p;
    int rc = policy_load(fixture("invalid_syntax.json", path, sizeof(path)),
                         &p);

    CHECK(rc == -1, "syntax error must fail");
    CHECK(!p.is_valid, "invalid flag");
    CHECK(strstr(p.validation_error, "Parse error at line ") != NULL,
          "error mentions line number");

    printf("PASS: test_invalid_syntax\n");
    return 0;
}

static int test_invalid_values_fixture(void)
{
    char path[512];
    policy_t p;
    int rc = policy_load(fixture("invalid_values.json", path, sizeof(path)),
                         &p);

    CHECK(rc == -1, "invalid values must fail");
    CHECK(strcmp(p.validation_error,
                 "memory_limit must be at least 1MB or 0 for unlimited") == 0,
          "first validation error is memory");

    printf("PASS: test_invalid_values_fixture\n");
    return 0;
}

static int test_parse_type_errors(void)
{
    struct {
        const char *json;
        const char *needle;
    } cases[] = {
        {"{\"resources\":{\"memory\":\"lots\"}}", "invalid memory value"},
        {"{\"resources\":{\"memory\":-5}}", "invalid memory value"},
        {"{\"resources\":{\"cpu\":\"fast\"}}", "invalid number"},
        {"{\"resources\":{\"pids\":1.5}}", "expected an integer"},
        {"{\"resources\":{\"pids\":\"10\"}}", "invalid number"},
        {"{\"security\":{\"enable_hardening\":\"yes\"}}",
         "expected true or false"},
        {"{\"policy\":{}} trailing", "trailing characters"},
        {"[]", "expected '{'"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char path[256];
        CHECK(write_temp("json", cases[i].json, path, sizeof(path)) == 0,
              "temp write failed");
        policy_t p;
        int rc = policy_load(path, &p);
        unlink(path);
        if (rc != -1) {
            fprintf(stderr, "FAIL: type case %zu unexpectedly succeeded\n", i);
            return 1;
        }
        if (strstr(p.validation_error, cases[i].needle) == NULL) {
            fprintf(stderr, "FAIL: type case %zu: '%s' lacks '%s'\n", i,
                    p.validation_error, cases[i].needle);
            return 1;
        }
    }

    printf("PASS: test_parse_type_errors\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Validation                                                          */
/* ------------------------------------------------------------------ */

static int test_validation_messages(void)
{
    policy_t p;
    char expected[256];
    int cpus = get_nprocs();
    if (cpus < 1) cpus = 1;

    reset(&p);
    p.memory_limit = 1024;
    CHECK(!policy_validate(&p), "small memory rejected");
    CHECK(strcmp(p.validation_error,
                 "memory_limit must be at least 1MB or 0 for unlimited") == 0,
          "small memory message");

    reset(&p);
    p.cpu_limit = -0.5;
    CHECK(!policy_validate(&p), "negative cpu rejected");
    snprintf(expected, sizeof(expected),
             "cpu_limit must be between 0.0 and %d", cpus);
    CHECK(strcmp(p.validation_error, expected) == 0, "negative cpu message");

    reset(&p);
    p.cpu_limit = (double)cpus + 1.0;
    CHECK(!policy_validate(&p), "too-large cpu rejected");
    CHECK(strcmp(p.validation_error, expected) == 0, "large cpu message");

    reset(&p);
    p.pids_limit = -5;
    CHECK(!policy_validate(&p), "negative pids rejected");
    CHECK(strcmp(p.validation_error,
                 "pids_limit must be non-negative") == 0, "pids message");

    reset(&p);
    p.timeout = -1;
    CHECK(!policy_validate(&p), "negative timeout rejected");
    CHECK(strcmp(p.validation_error,
                 "timeout must be non-negative") == 0, "timeout message");

    reset(&p);
    p.timeout = (int64_t)UINT32_MAX + 1;
    CHECK(!policy_validate(&p), "huge timeout rejected");
    CHECK(strcmp(p.validation_error, "timeout is too large") == 0,
          "huge timeout message");

    reset(&p);
    p.grace_period = -1;
    CHECK(!policy_validate(&p), "negative grace rejected");
    CHECK(strcmp(p.validation_error,
                 "grace_period must be non-negative") == 0, "grace message");

    reset(&p);
    p.grace_period = (int64_t)UINT32_MAX + 1;
    CHECK(!policy_validate(&p), "huge grace rejected");
    CHECK(strcmp(p.validation_error, "grace_period is too large") == 0,
          "huge grace message");

    reset(&p);
    p.memory_warning_threshold = 1.5;
    CHECK(!policy_validate(&p), "memory threshold rejected");
    CHECK(strcmp(p.validation_error,
                 "memory_warning_threshold must be between 0.0 and 1.0") == 0,
          "memory threshold message");

    reset(&p);
    p.cpu_warning_threshold = -0.1;
    CHECK(!policy_validate(&p), "cpu threshold rejected");
    CHECK(strcmp(p.validation_error,
                 "cpu_warning_threshold must be between 0.0 and 1.0") == 0,
          "cpu threshold message");

    reset(&p);
    p.watchdog_poll_interval_ms = 60001;
    CHECK(!policy_validate(&p), "poll interval rejected");
    CHECK(strcmp(p.validation_error,
                 "watchdog_poll_interval_ms must be between 0 and 60000") == 0,
          "poll interval message");

    reset(&p);
    p.log_enabled = true;
    p.log_dir[0] = '\0';
    CHECK(!policy_validate(&p), "empty log dir rejected");
    CHECK(strcmp(p.validation_error,
                 "log_dir must be set when logging is enabled") == 0,
          "empty log dir message");

    reset(&p);
    snprintf(p.log_dir, sizeof(p.log_dir), "relative/events");
    CHECK(!policy_validate(&p), "relative log dir rejected");
    CHECK(strcmp(p.validation_error, "log_dir must be an absolute path") == 0,
          "relative log dir message");

    /* Logging disabled: an empty/relative log_dir is harmless. */
    reset(&p);
    p.log_enabled = false;
    p.log_dir[0] = '\0';
    CHECK(policy_validate(&p), "disabled logging ignores log_dir");

    printf("PASS: test_validation_messages\n");
    return 0;
}

static int test_validation_is_repeatable(void)
{
    policy_t p;
    reset(&p);

    CHECK(policy_validate(&p), "first validate");
    CHECK(policy_validate(&p), "second validate");
    CHECK(p.is_valid, "still valid");

    p.cpu_limit = -1.0;
    CHECK(!policy_validate(&p), "invalid cpu");
    CHECK(!p.is_valid, "invalid flag set");

    p.cpu_limit = 1.0;
    CHECK(policy_validate(&p), "valid after fixing cpu");
    CHECK(p.is_valid, "valid flag restored");
    CHECK(p.validation_error[0] == '\0', "error cleared");

    printf("PASS: test_validation_is_repeatable\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Warnings                                                            */
/* ------------------------------------------------------------------ */

static int test_unknown_fields_warn(void)
{
    char path[512];
    policy_t p;
    int rc = policy_load(fixture("unknown_fields.json", path, sizeof(path)),
                         &p);

    CHECK(rc == 0, p.validation_error);
    CHECK(p.is_valid, "unknown fields do not invalidate");
    CHECK(p.warning_count > 0, "warnings recorded");
    CHECK(approx(p.memory_limit, 128.0 * 1024.0 * 1024.0), "known field kept");
    CHECK(p.enable_hardening, "known security field kept");
    CHECK(p.log_enabled, "known logging field kept");

    bool saw_syscalls = false;
    bool saw_section = false;
    bool saw_filesystem = false;
    for (size_t i = 0; i < p.warning_count; i++) {
        if (strstr(p.warnings[i], "blocked_syscalls") != NULL)
            saw_syscalls = true;
        if (strstr(p.warnings[i], "totally_unknown_section") != NULL)
            saw_section = true;
        if (strstr(p.warnings[i], "filesystem") != NULL)
            saw_filesystem = true;
    }
    CHECK(saw_syscalls, "dropped seccomp key warned");
    CHECK(saw_section, "unknown section warned");
    CHECK(saw_filesystem, "dropped filesystem key warned");

    /* Warnings must print without crashing (output goes to stderr). */
    policy_print_warnings(&p);
    policy_free(&p);

    printf("PASS: test_unknown_fields_warn\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Application                                                         */
/* ------------------------------------------------------------------ */

static int test_apply_mapping(void)
{
    char path[512];
    policy_t p;
    CHECK(policy_load(fixture("valid.json", path, sizeof(path)), &p) == 0,
          p.validation_error);

    container_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.rootfs_path = "/tmp";

    CHECK(policy_apply(&p, &cfg) == 0, "apply failed");
    CHECK(cfg.cgroup_limits.memory_limit == 512ULL * 1024ULL * 1024ULL,
          "memory mapped");
    CHECK(cfg.cgroup_limits.cpu_quota == 50000, "cpu quota mapped");
    CHECK(cfg.cgroup_limits.cpu_period == 100000, "cpu period mapped");
    CHECK(cfg.cgroup_limits.pid_limit == 50, "pids mapped");
    CHECK(cfg.enable_cgroup, "cgroup enabled");
    CHECK(cfg.timeout_seconds == 300, "timeout mapped");
    CHECK(cfg.grace_period_seconds == 10, "grace mapped");
    CHECK(approx(cfg.memory_warning_threshold, 0.9), "memory threshold");
    CHECK(approx(cfg.cpu_warning_threshold, 0.8), "cpu threshold");
    CHECK(cfg.cpu_warning_duration_ms == 5000, "cpu duration");
    CHECK(cfg.watchdog_poll_interval_ms == 100, "poll interval");
    CHECK(cfg.event_log_enabled, "logging enabled");
    CHECK(strcmp(cfg.event_log_dir, "/var/log/minicontainer/events") == 0,
          "log dir mapped");
    CHECK(strcmp(cfg.policy_name, "valid") == 0, "policy name mapped");
    CHECK(cfg.policy_mode, "policy mode set");
    CHECK(cfg.enable_hardening, "hardening enabled with rootfs");

    policy_free(&p);
    printf("PASS: test_apply_mapping\n");
    return 0;
}

static int test_apply_no_limits(void)
{
    policy_t p;
    reset(&p);
    p.memory_limit = 0;
    p.cpu_limit = 0.0;
    p.pids_limit = 0;
    p.enable_hardening = false;
    p.log_enabled = false;

    container_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    CHECK(policy_apply(&p, &cfg) == 0, "apply failed");
    CHECK(!cfg.enable_cgroup, "no cgroup without limits");
    CHECK(cfg.cgroup_limits.memory_limit == 0, "memory untouched");
    CHECK(cfg.cgroup_limits.cpu_quota == 0, "cpu untouched");
    CHECK(cfg.cgroup_limits.pid_limit == 0, "pids untouched");
    CHECK(!cfg.enable_hardening, "no hardening without rootfs");
    CHECK(!cfg.event_log_enabled, "logging disabled");
    CHECK(cfg.policy_mode, "policy mode still marks the run");

    printf("PASS: test_apply_no_limits\n");
    return 0;
}

static int test_apply_hardening_requires_rootfs(void)
{
    policy_t p;
    reset(&p);
    p.enable_hardening = true;
    p.log_enabled = false;

    container_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.rootfs_path = NULL;
    CHECK(policy_apply(&p, &cfg) == 0, "apply without rootfs");
    CHECK(!cfg.enable_hardening, "hardening needs a rootfs");

    memset(&cfg, 0, sizeof(cfg));
    cfg.rootfs_path = "/tmp";
    CHECK(policy_apply(&p, &cfg) == 0, "apply with rootfs");
    CHECK(cfg.enable_hardening, "hardening enabled with rootfs");

    printf("PASS: test_apply_hardening_requires_rootfs\n");
    return 0;
}

static int test_apply_rejects_bad_args(void)
{
    policy_t p;
    reset(&p);
    container_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    CHECK(policy_apply(NULL, &cfg) == -1, "NULL policy");
    CHECK(policy_apply(&p, NULL) == -1, "NULL config");

    p.is_valid = false;
    CHECK(policy_apply(&p, &cfg) == -1, "invalid policy");

    printf("PASS: test_apply_rejects_bad_args\n");
    return 0;
}

/* Legacy runs never call policy_apply.  A zero-initialized config must
 * keep every new field in its inert state. */
static int test_legacy_zero_init(void)
{
    container_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    CHECK(cfg.timeout_seconds == 0, "no timeout");
    CHECK(cfg.grace_period_seconds == 0, "no grace");
    CHECK(approx(cfg.memory_warning_threshold, 0.0), "no threshold");
    CHECK(approx(cfg.cpu_warning_threshold, 0.0), "no threshold");
    CHECK(cfg.cpu_warning_duration_ms == 0, "no duration");
    CHECK(cfg.watchdog_poll_interval_ms == 0, "no poll interval");
    CHECK(!cfg.event_log_enabled, "no event logging");
    CHECK(cfg.event_log_dir[0] == '\0', "no log dir");
    CHECK(cfg.policy_name[0] == '\0', "no policy name");
    CHECK(!cfg.policy_mode, "not policy mode");
    CHECK(!cfg.enable_cgroup, "no cgroup");
    CHECK(!cfg.enable_hardening, "no hardening");

    printf("PASS: test_legacy_zero_init\n");
    return 0;
}

/* P1.16: defaults < bundle < policy < explicit CLI.  This mirrors the
 * merge parse_run_flags performs: policy_apply fills the policy-owned
 * fields, then explicit CLI values (including zero) overwrite them. */
static int test_cli_override_semantics(void)
{
    char path[512];
    policy_t p;
    CHECK(policy_load(fixture("memory_100M.json", path, sizeof(path)), &p)
              == 0, p.validation_error);

    container_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cgroup_limits.memory_limit = 64ULL * 1024 * 1024; /* bundle value */

    /* Policy overrides the bundle value. */
    CHECK(policy_apply(&p, &cfg) == 0, "apply failed");
    CHECK(cfg.cgroup_limits.memory_limit == 100ULL * 1024 * 1024,
          "policy overrides bundle");
    CHECK(cfg.cgroup_limits.pid_limit == 100, "policy default pids");
    CHECK(cfg.cgroup_limits.cpu_quota == 100000, "policy default cpu");

    /* Explicit --memory 0 clears the policy value. */
    cfg.cgroup_limits.memory_limit = 0;
    /* Explicit --pids 10 overrides the policy value. */
    cfg.cgroup_limits.pid_limit = 10;
    CHECK(cfg.cgroup_limits.memory_limit == 0, "explicit zero wins");
    CHECK(cfg.cgroup_limits.pid_limit == 10, "explicit pids wins");

    /* Explicitly zeroing every limit disables the cgroup entirely. */
    cfg.cgroup_limits.memory_limit = 0;
    cfg.cgroup_limits.cpu_quota = 0;
    cfg.cgroup_limits.pid_limit = 0;
    cfg.enable_cgroup = (cfg.cgroup_limits.memory_limit != 0 ||
                         cfg.cgroup_limits.cpu_quota != 0 ||
                         cfg.cgroup_limits.pid_limit != 0);
    CHECK(!cfg.enable_cgroup, "all-zero limits disable cgroup");

    policy_free(&p);
    printf("PASS: test_cli_override_semantics\n");
    return 0;
}

static int test_all_fixtures_load(void)
{
    const char *names[] = {
        "valid.json", "minimal.json", "timeout_5s.json",
        "memory_100M.json", "pids_10.json", "pids_20.json",
        "with_logging.json", "student.json", "default_legacy.json",
        "unknown_fields.json",
    };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[512];
        policy_t p;
        if (policy_load(fixture(names[i], path, sizeof(path)), &p) != 0) {
            fprintf(stderr, "FAIL: fixture '%s': %s\n", names[i],
                    p.validation_error);
            return 1;
        }
        CHECK(p.is_valid, "fixture valid");
        policy_free(&p);
    }

    printf("PASS: test_all_fixtures_load\n");
    return 0;
}

static int test_fixture_values(void)
{
    char path[512];
    policy_t p;

    CHECK(policy_load(fixture("timeout_5s.json", path, sizeof(path)), &p)
              == 0, p.validation_error);
    CHECK(p.timeout == 5, "timeout fixture");
    policy_free(&p);

    CHECK(policy_load(fixture("memory_100M.json", path, sizeof(path)), &p)
              == 0, p.validation_error);
    CHECK(p.memory_limit == 100ULL * 1024 * 1024, "memory fixture");
    policy_free(&p);

    CHECK(policy_load(fixture("pids_10.json", path, sizeof(path)), &p)
              == 0, p.validation_error);
    CHECK(p.pids_limit == 10, "pids_10 fixture");
    policy_free(&p);

    CHECK(policy_load(fixture("pids_20.json", path, sizeof(path)), &p)
              == 0, p.validation_error);
    CHECK(p.pids_limit == 20, "pids_20 fixture");
    policy_free(&p);

    CHECK(policy_load(fixture("with_logging.json", path, sizeof(path)), &p)
              == 0, p.validation_error);
    CHECK(p.log_enabled, "with_logging enabled");
    CHECK(strcmp(p.log_dir, "/var/log/minicontainer/student-events") == 0,
          "with_logging dir");
    CHECK(p.cpu_warning_duration_ms == 3000, "with_logging duration");
    CHECK(p.watchdog_poll_interval_ms == 250, "with_logging poll");
    policy_free(&p);

    CHECK(policy_load(fixture("student.json", path, sizeof(path)), &p)
              == 0, p.validation_error);
    CHECK(strcmp(p.name, "student") == 0, "student name");
    CHECK(p.memory_limit == 512ULL * 1024ULL * 1024ULL, "student memory");
    CHECK(approx(p.cpu_limit, 0.5), "student cpu");
    CHECK(p.pids_limit == 50, "student pids");
    CHECK(p.timeout == 300, "student timeout");
    policy_free(&p);

    printf("PASS: test_fixture_values\n");
    return 0;
}

int main(void)
{
    int rc = 0;

    rc |= test_defaults();
    rc |= test_free();
    rc |= test_memory_parser();
    rc |= test_load_valid();
    rc |= test_load_minimal();
    rc |= test_load_numeric_and_integer_cpu();
    rc |= test_load_default_legacy_fixture();
    rc |= test_load_errors();
    rc |= test_invalid_syntax();
    rc |= test_invalid_values_fixture();
    rc |= test_parse_type_errors();
    rc |= test_validation_messages();
    rc |= test_validation_is_repeatable();
    rc |= test_unknown_fields_warn();
    rc |= test_apply_mapping();
    rc |= test_apply_no_limits();
    rc |= test_apply_hardening_requires_rootfs();
    rc |= test_apply_rejects_bad_args();
    rc |= test_legacy_zero_init();
    rc |= test_cli_override_semantics();
    rc |= test_fixture_values();
    rc |= test_all_fixtures_load();

    if (rc == 0) {
        printf("\nAll policy tests passed!\n");
    }
    return rc;
}
