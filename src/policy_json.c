/*
 * policy_json.c — Phase 1 JSON policy parser.
 *
 * A small, standalone recursive-descent JSON parser.  It is deliberately
 * separate from the Phase 8c OCI parser: policy files are a distinct
 * schema and touching oci.c for policy support would couple two
 * unrelated subsystems.
 *
 * Supported schema (all sections optional):
 *
 *   {
 *     "policy":    { "name", "version", "description" },
 *     "resources": { "memory", "cpu", "pids", "timeout", "grace_period",
 *                    "thresholds": { "memory_warning", "cpu_warning",
 *                                    "cpu_warning_duration",
 *                                    "cpu_warning_duration_ms",
 *                                    "poll_interval_ms" } },
 *     "security":  { "enable_hardening" },
 *     "logging":   { "enabled", "log_dir" }
 *   }
 *
 * Unknown sections/fields are skipped and recorded as warnings
 * (requirements 1.3).  In particular the dropped Phase 4/5 keys
 * (blocked_syscalls, seccomp_profile, log_seccomp_denials, filesystem,
 * network) warn and are ignored rather than pretending to be enforced.
 */

#include "policy.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLICY_JSON_MAX_FILE_SIZE (4U * 1024U * 1024U)

typedef struct {
    const char *buf;
    size_t len;
    size_t pos;
    int line;
    int col;
    char *err;
    size_t err_size;
    policy_t *p;
    bool failed;
} jp_t;

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

static void jp_error(jp_t *j, const char *fmt, ...)
{
    if (j->failed) return;
    j->failed = true;

    int prefix = snprintf(j->err, j->err_size,
                          "Parse error at line %d: ", j->line);
    if (prefix < 0) return;

    size_t used = (size_t)prefix < j->err_size
                ? (size_t)prefix : j->err_size - 1;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(j->err + used, j->err_size - used, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* Cursor helpers                                                      */
/* ------------------------------------------------------------------ */

static int jp_peek(const jp_t *j)
{
    if (j->pos >= j->len) return -1;
    return (unsigned char)j->buf[j->pos];
}

static void jp_next(jp_t *j)
{
    if (j->pos >= j->len) return;
    unsigned char c = (unsigned char)j->buf[j->pos++];
    if (c == '\n') {
        j->line++;
        j->col = 1;
    } else {
        j->col++;
    }
}

static void jp_skip_ws(jp_t *j)
{
    while (j->pos < j->len) {
        unsigned char c = (unsigned char)j->buf[j->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            jp_next(j);
        } else {
            break;
        }
    }
}

static bool jp_expect(jp_t *j, char expected)
{
    jp_skip_ws(j);
    int got = jp_peek(j);
    if (got != (unsigned char)expected) {
        if (got < 0) {
            jp_error(j, "expected '%c', got end of input", expected);
        } else {
            jp_error(j, "expected '%c', got '%c'", expected, got);
        }
        return false;
    }
    jp_next(j);
    return true;
}

/* ------------------------------------------------------------------ */
/* Strings                                                             */
/* ------------------------------------------------------------------ */

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool jp_read_hex4(jp_t *j, uint32_t *out)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int c = jp_peek(j);
        int h = c < 0 ? -1 : hex_value(c);
        if (h < 0) {
            jp_error(j, "invalid \\u escape");
            return false;
        }
        jp_next(j);
        v = (v << 4) | (uint32_t)h;
    }
    *out = v;
    return true;
}

static bool jp_parse_string(jp_t *j, char *out, size_t out_size)
{
    jp_skip_ws(j);
    if (jp_peek(j) != '"') {
        jp_error(j, "expected a string");
        return false;
    }
    jp_next(j);

    size_t used = 0;

    for (;;) {
        int c = jp_peek(j);
        if (c < 0) {
            jp_error(j, "unterminated string");
            return false;
        }
        jp_next(j);

        if (c == '"') break;
        if ((unsigned char)c < 0x20) {
            jp_error(j, "control character in string");
            return false;
        }

        if (c == '\\') {
            int e = jp_peek(j);
            if (e < 0) {
                jp_error(j, "unterminated escape sequence");
                return false;
            }
            jp_next(j);

            switch (e) {
                case '"':  c = '"';  break;
                case '\\': c = '\\'; break;
                case '/':  c = '/';  break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                case 'n':  c = '\n'; break;
                case 'r':  c = '\r'; break;
                case 't':  c = '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (!jp_read_hex4(j, &cp)) return false;

                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        /* High surrogate: require a following low one. */
                        int b1 = jp_peek(j);
                        if (b1 != '\\') {
                            jp_error(j, "invalid surrogate pair");
                            return false;
                        }
                        jp_next(j);
                        int b2 = jp_peek(j);
                        if (b2 != 'u') {
                            jp_error(j, "invalid surrogate pair");
                            return false;
                        }
                        jp_next(j);

                        uint32_t lo;
                        if (!jp_read_hex4(j, &lo)) return false;
                        if (lo < 0xDC00 || lo > 0xDFFF) {
                            jp_error(j, "invalid surrogate pair");
                            return false;
                        }
                        cp = 0x10000 + ((cp - 0xD800) << 10)
                                     + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        jp_error(j, "invalid surrogate pair");
                        return false;
                    }

                    char utf8[4];
                    int n;
                    if (cp < 0x80) {
                        utf8[0] = (char)cp;
                        n = 1;
                    } else if (cp < 0x800) {
                        utf8[0] = (char)(0xC0 | (cp >> 6));
                        utf8[1] = (char)(0x80 | (cp & 0x3F));
                        n = 2;
                    } else if (cp < 0x10000) {
                        utf8[0] = (char)(0xE0 | (cp >> 12));
                        utf8[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        utf8[2] = (char)(0x80 | (cp & 0x3F));
                        n = 3;
                    } else {
                        utf8[0] = (char)(0xF0 | (cp >> 18));
                        utf8[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
                        utf8[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        utf8[3] = (char)(0x80 | (cp & 0x3F));
                        n = 4;
                    }

                    if (out != NULL) {
                        if (used + (size_t)n + 1 > out_size) {
                            jp_error(j, "string value too long");
                            return false;
                        }
                        memcpy(out + used, utf8, (size_t)n);
                    }
                    used += (size_t)n;
                    continue;
                }
                default:
                    jp_error(j, "invalid escape '\\%c'", e);
                    return false;
            }
        }

        if (out != NULL) {
            if (used + 1 >= out_size) {
                jp_error(j, "string value too long");
                return false;
            }
            out[used] = (char)c;
        }
        used++;
    }

    if (out != NULL && out_size > 0) {
        out[used] = '\0';
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Numbers / literals                                                  */
/* ------------------------------------------------------------------ */

static bool jp_scan_number(jp_t *j, const char **tok, size_t *tok_len)
{
    jp_skip_ws(j);

    size_t i = j->pos;
    if (i >= j->len) {
        jp_error(j, "expected a number");
        return false;
    }

    if (j->buf[i] == '-') i++;

    size_t int_start = i;
    while (i < j->len && isdigit((unsigned char)j->buf[i])) i++;
    if (i == int_start) {
        jp_error(j, "invalid number");
        return false;
    }

    if (i < j->len && j->buf[i] == '.') {
        i++;
        size_t frac_start = i;
        while (i < j->len && isdigit((unsigned char)j->buf[i])) i++;
        if (i == frac_start) {
            jp_error(j, "invalid number");
            return false;
        }
    }

    if (i < j->len && (j->buf[i] == 'e' || j->buf[i] == 'E')) {
        i++;
        if (i < j->len && (j->buf[i] == '+' || j->buf[i] == '-')) i++;
        size_t exp_start = i;
        while (i < j->len && isdigit((unsigned char)j->buf[i])) i++;
        if (i == exp_start) {
            jp_error(j, "invalid number");
            return false;
        }
    }

    *tok     = j->buf + j->pos;
    *tok_len = i - j->pos;

    j->col += (int)(*tok_len);
    j->pos = i;
    return true;
}

static bool jp_parse_number(jp_t *j, double *out)
{
    const char *tok;
    size_t len;
    if (!jp_scan_number(j, &tok, &len)) return false;

    char tmp[128];
    if (len >= sizeof(tmp)) {
        jp_error(j, "number too long");
        return false;
    }
    memcpy(tmp, tok, len);
    tmp[len] = '\0';

    errno = 0;
    char *end = NULL;
    double v = strtod(tmp, &end);
    if (end == tmp || *end != '\0' || errno == ERANGE || !isfinite(v)) {
        jp_error(j, "invalid number");
        return false;
    }

    *out = v;
    return true;
}

static bool jp_parse_int64(jp_t *j, int64_t *out)
{
    const char *tok;
    size_t len;
    if (!jp_scan_number(j, &tok, &len)) return false;

    char tmp[64];
    if (len >= sizeof(tmp)) {
        jp_error(j, "integer too long");
        return false;
    }
    memcpy(tmp, tok, len);
    tmp[len] = '\0';

    if (strchr(tmp, '.') != NULL ||
        strchr(tmp, 'e') != NULL ||
        strchr(tmp, 'E') != NULL) {
        jp_error(j, "expected an integer");
        return false;
    }

    errno = 0;
    char *end = NULL;
    long long v = strtoll(tmp, &end, 10);
    if (end == tmp || *end != '\0' || errno == ERANGE) {
        jp_error(j, "invalid integer");
        return false;
    }

    *out = (int64_t)v;
    return true;
}

static bool jp_parse_u32(jp_t *j, uint32_t *out)
{
    int64_t v;
    if (!jp_parse_int64(j, &v)) return false;
    if (v < 0) {
        jp_error(j, "expected a non-negative integer");
        return false;
    }
    if (v > (int64_t)UINT32_MAX) {
        jp_error(j, "integer out of range");
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

static bool jp_parse_bool(jp_t *j, bool *out)
{
    jp_skip_ws(j);
    int c = jp_peek(j);
    if (c == 't') {
        if (j->pos + 4 > j->len ||
            memcmp(j->buf + j->pos, "true", 4) != 0) {
            jp_error(j, "invalid literal (expected true/false)");
            return false;
        }
        j->pos += 4;
        j->col += 4;
        *out = true;
        return true;
    }
    if (c == 'f') {
        if (j->pos + 5 > j->len ||
            memcmp(j->buf + j->pos, "false", 5) != 0) {
            jp_error(j, "invalid literal (expected true/false)");
            return false;
        }
        j->pos += 5;
        j->col += 5;
        *out = false;
        return true;
    }
    jp_error(j, "expected true or false");
    return false;
}

/* ------------------------------------------------------------------ */
/* Generic object/array skipping                                       */
/* ------------------------------------------------------------------ */

static bool jp_read_key(jp_t *j, char *key, size_t cap);

static bool jp_match_literal(jp_t *j, const char *literal)
{
    size_t n = strlen(literal);
    if (j->pos + n > j->len ||
        memcmp(j->buf + j->pos, literal, n) != 0) {
        jp_error(j, "invalid literal");
        return false;
    }
    j->pos += n;
    j->col += (int)n;
    return true;
}

static bool jp_skip_value(jp_t *j)
{
    jp_skip_ws(j);
    int c = jp_peek(j);
    if (c < 0) {
        jp_error(j, "unexpected end of input");
        return false;
    }

    if (c == '"') {
        return jp_parse_string(j, NULL, 0);
    }

    if (c == '{') {
        jp_next(j);
        jp_skip_ws(j);
        if (jp_peek(j) == '}') {
            jp_next(j);
            return true;
        }
        for (;;) {
            char key[256];
            if (!jp_read_key(j, key, sizeof(key))) return false;
            if (!jp_expect(j, ':')) return false;
            if (!jp_skip_value(j)) return false;

            jp_skip_ws(j);
            int d = jp_peek(j);
            if (d == ',') {
                jp_next(j);
                continue;
            }
            if (d == '}') {
                jp_next(j);
                return true;
            }
            jp_error(j, "expected ',' or '}' in object");
            return false;
        }
    }

    if (c == '[') {
        jp_next(j);
        jp_skip_ws(j);
        if (jp_peek(j) == ']') {
            jp_next(j);
            return true;
        }
        for (;;) {
            if (!jp_skip_value(j)) return false;

            jp_skip_ws(j);
            int d = jp_peek(j);
            if (d == ',') {
                jp_next(j);
                continue;
            }
            if (d == ']') {
                jp_next(j);
                return true;
            }
            jp_error(j, "expected ',' or ']' in array");
            return false;
        }
    }

    if (c == 't') return jp_match_literal(j, "true");
    if (c == 'f') return jp_match_literal(j, "false");
    if (c == 'n') return jp_match_literal(j, "null");

    double ignored;
    return jp_parse_number(j, &ignored);
}

static bool jp_read_key(jp_t *j, char *key, size_t cap)
{
    jp_skip_ws(j);
    if (jp_peek(j) != '"') {
        jp_error(j, "expected an object key string");
        return false;
    }
    return jp_parse_string(j, key, cap);
}

/* ------------------------------------------------------------------ */
/* Section parsers                                                     */
/* ------------------------------------------------------------------ */

static void pjson_copy(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0) return;
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static bool jp_unknown_field(jp_t *j, const char *prefix,
                             const char *key)
{
    policy_add_warning(j->p,
        "unknown policy field '%s.%s' (ignored)", prefix, key);
    return jp_skip_value(j);
}

/* Shared object iteration for one section. */
#define JP_OBJECT_LOOP(j, body)                                         \
    do {                                                                \
        if (!jp_expect((j), '{')) return false;                         \
        jp_skip_ws((j));                                                \
        if (jp_peek((j)) == '}') { jp_next((j)); return true; }         \
        for (;;) {                                                      \
            char key[128];                                              \
            if (!jp_read_key((j), key, sizeof(key))) return false;      \
            if (!jp_expect((j), ':')) return false;                     \
            body;                                                       \
            jp_skip_ws((j));                                            \
            int c = jp_peek((j));                                       \
            if (c == ',') { jp_next((j)); continue; }                   \
            if (c == '}') { jp_next((j)); return true; }                \
            jp_error((j), "expected ',' or '}' in object");             \
            return false;                                               \
        }                                                               \
    } while (0)

static bool parse_policy_section(jp_t *j)
{
    JP_OBJECT_LOOP(j, {
        if (strcmp(key, "name") == 0) {
            char v[POLICY_DESCRIPTION_MAX];
            if (!jp_parse_string(j, v, sizeof(v))) return false;
            pjson_copy(j->p->name, sizeof(j->p->name), v);
        } else if (strcmp(key, "version") == 0) {
            char v[POLICY_DESCRIPTION_MAX];
            if (!jp_parse_string(j, v, sizeof(v))) return false;
            pjson_copy(j->p->version, sizeof(j->p->version), v);
        } else if (strcmp(key, "description") == 0) {
            char v[POLICY_DESCRIPTION_MAX];
            if (!jp_parse_string(j, v, sizeof(v))) return false;
            pjson_copy(j->p->description,
                       sizeof(j->p->description), v);
        } else {
            if (!jp_unknown_field(j, "policy", key)) return false;
        }
    });
}

static bool parse_memory_value(jp_t *j, uint64_t *out)
{
    jp_skip_ws(j);
    if (jp_peek(j) == '"') {
        char s[128];
        if (!jp_parse_string(j, s, sizeof(s))) return false;
        if (policy_parse_memory_string(s, out) != 0) {
            jp_error(j, "invalid memory value '%s'", s);
            return false;
        }
        return true;
    }

    double d;
    if (!jp_parse_number(j, &d)) return false;
    if (d < 0.0 || floor(d) != d || d > (double)UINT64_MAX) {
        jp_error(j, "invalid memory value");
        return false;
    }
    *out = (uint64_t)d;
    return true;
}

static bool parse_thresholds_section(jp_t *j)
{
    JP_OBJECT_LOOP(j, {
        if (strcmp(key, "memory_warning") == 0) {
            if (!jp_parse_number(j,
                    &j->p->memory_warning_threshold)) return false;
        } else if (strcmp(key, "cpu_warning") == 0) {
            if (!jp_parse_number(j,
                    &j->p->cpu_warning_threshold)) return false;
        } else if (strcmp(key, "cpu_warning_duration") == 0) {
            double seconds;
            if (!jp_parse_number(j, &seconds)) return false;
            if (seconds < 0.0 ||
                seconds > (double)UINT32_MAX / 1000.0) {
                jp_error(j, "cpu_warning_duration out of range");
                return false;
            }
            j->p->cpu_warning_duration_ms =
                (uint32_t)(seconds * 1000.0);
        } else if (strcmp(key, "cpu_warning_duration_ms") == 0) {
            if (!jp_parse_u32(j,
                    &j->p->cpu_warning_duration_ms)) return false;
        } else if (strcmp(key, "poll_interval_ms") == 0) {
            if (!jp_parse_u32(j,
                    &j->p->watchdog_poll_interval_ms)) return false;
        } else {
            if (!jp_unknown_field(j, "resources.thresholds",
                                  key)) return false;
        }
    });
}

static bool parse_resources_section(jp_t *j)
{
    JP_OBJECT_LOOP(j, {
        if (strcmp(key, "memory") == 0) {
            if (!parse_memory_value(j, &j->p->memory_limit)) return false;
        } else if (strcmp(key, "cpu") == 0) {
            if (!jp_parse_number(j, &j->p->cpu_limit)) return false;
        } else if (strcmp(key, "pids") == 0) {
            if (!jp_parse_int64(j, &j->p->pids_limit)) return false;
        } else if (strcmp(key, "timeout") == 0) {
            if (!jp_parse_int64(j, &j->p->timeout)) return false;
        } else if (strcmp(key, "grace_period") == 0) {
            if (!jp_parse_int64(j, &j->p->grace_period)) return false;
        } else if (strcmp(key, "thresholds") == 0) {
            if (!parse_thresholds_section(j)) return false;
        } else {
            if (!jp_unknown_field(j, "resources", key)) return false;
        }
    });
}

static bool parse_security_section(jp_t *j)
{
    JP_OBJECT_LOOP(j, {
        if (strcmp(key, "enable_hardening") == 0) {
            if (!jp_parse_bool(j, &j->p->enable_hardening)) return false;
        } else {
            /* Includes the dropped blocked_syscalls / seccomp_profile /
             * filesystem / network keys. */
            if (!jp_unknown_field(j, "security", key)) return false;
        }
    });
}

static bool parse_logging_section(jp_t *j)
{
    JP_OBJECT_LOOP(j, {
        if (strcmp(key, "enabled") == 0) {
            if (!jp_parse_bool(j, &j->p->log_enabled)) return false;
        } else if (strcmp(key, "log_dir") == 0) {
            char v[PATH_MAX];
            if (!jp_parse_string(j, v, sizeof(v))) return false;
            pjson_copy(j->p->log_dir, sizeof(j->p->log_dir), v);
        } else {
            if (!jp_unknown_field(j, "logging", key)) return false;
        }
    });
}

static bool parse_document(jp_t *j)
{
    jp_skip_ws(j);
    if (!jp_expect(j, '{')) return false;

    jp_skip_ws(j);
    if (jp_peek(j) == '}') {
        jp_next(j);
        return true;
    }

    for (;;) {
        char key[128];
        if (!jp_read_key(j, key, sizeof(key))) return false;
        if (!jp_expect(j, ':')) return false;

        if (strcmp(key, "policy") == 0) {
            if (!parse_policy_section(j)) return false;
        } else if (strcmp(key, "resources") == 0) {
            if (!parse_resources_section(j)) return false;
        } else if (strcmp(key, "security") == 0) {
            if (!parse_security_section(j)) return false;
        } else if (strcmp(key, "logging") == 0) {
            if (!parse_logging_section(j)) return false;
        } else {
            policy_add_warning(j->p,
                "unknown policy section '%s' (ignored)", key);
            if (!jp_skip_value(j)) return false;
        }

        jp_skip_ws(j);
        int c = jp_peek(j);
        if (c == ',') {
            jp_next(j);
            continue;
        }
        if (c == '}') {
            jp_next(j);
            return true;
        }
        jp_error(j, "expected ',' or '}' in top-level object");
        return false;
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int policy_json_parse_file(const char *path, policy_t *p,
                           char *err, size_t err_size)
{
    if (!path || !p) return -1;

    if (err && err_size > 0) err[0] = '\0';

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (err && err_size > 0) {
            snprintf(err, err_size, "Cannot read policy file: %s", path);
        }
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        if (err && err_size > 0) {
            snprintf(err, err_size, "Cannot read policy file: %s", path);
        }
        return -1;
    }

    long size = ftell(f);
    if (size < 0 || (unsigned long)size > POLICY_JSON_MAX_FILE_SIZE) {
        fclose(f);
        if (err && err_size > 0) {
            snprintf(err, err_size,
                     "Cannot read policy file: %s (too large)", path);
        }
        return -1;
    }

    rewind(f);

    size_t len = (size_t)size;
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        if (err && err_size > 0) {
            snprintf(err, err_size, "Cannot read policy file: %s", path);
        }
        return -1;
    }

    size_t got = fread(buf, 1, len, f);
    fclose(f);
    if (got != len) {
        free(buf);
        if (err && err_size > 0) {
            snprintf(err, err_size, "Cannot read policy file: %s", path);
        }
        return -1;
    }
    buf[len] = '\0';

    jp_t j;
    memset(&j, 0, sizeof(j));
    j.buf      = buf;
    j.len      = len;
    j.pos      = 0;
    j.line     = 1;
    j.col      = 1;
    j.err      = err;
    j.err_size = err_size;
    j.p        = p;

    /* Skip an optional UTF-8 BOM. */
    if (len >= 3 &&
        (unsigned char)buf[0] == 0xEF &&
        (unsigned char)buf[1] == 0xBB &&
        (unsigned char)buf[2] == 0xBF) {
        j.pos = 3;
    }

    bool ok = parse_document(&j);
    if (ok) {
        jp_skip_ws(&j);
        if (jp_peek(&j) != -1) {
            jp_error(&j, "trailing characters after top-level object");
            ok = false;
        }
    }

    free(buf);

    if (!ok) {
        p->is_valid = false;
        if (err && err_size > 0) {
            if (err[0] == '\0') {
                snprintf(err, err_size, "Parse error in policy file");
            }
        }
        return -1;
    }

    return 0;
}
