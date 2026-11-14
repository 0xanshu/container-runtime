#!/usr/bin/env bash
# Phase 1 (P1.26): CLI smoke test for `minicontainer policy validate`.
#
# No root required — validation never touches cgroups or namespaces.
# Run from the repository root (make test does this).

set -u

BIN="${BIN:-./minicontainer}"
FIX="tests/fixtures/policies"
failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# Valid policy: exit 0, prints a confirmation.
if ! out=$("$BIN" policy validate "$FIX/valid.json" 2>&1); then
    fail "valid.json should exit 0 (output: $out)"
else
    case "$out" in
        *"is valid"*) ;;
        *) fail "valid.json output missing confirmation: $out" ;;
    esac
fi

# Invalid syntax: exit 1, mentions the parse line.
if out=$("$BIN" policy validate "$FIX/invalid_syntax.json" 2>&1); then
    fail "invalid_syntax.json should exit 1"
else
    case "$out" in
        *"Parse error at line "*) ;;
        *) fail "invalid_syntax.json lacks line info: $out" ;;
    esac
fi

# Invalid values: exit 1 with the exact required memory message.
if out=$("$BIN" policy validate "$FIX/invalid_values.json" 2>&1); then
    fail "invalid_values.json should exit 1"
else
    case "$out" in
        *"memory_limit must be at least 1MB or 0 for unlimited"*) ;;
        *) fail "invalid_values.json lacks required message: $out" ;;
    esac
fi

# Missing file: exit 1 with the exact required not-found message.
missing="$FIX/definitely_missing.json"
if out=$("$BIN" policy validate "$missing" 2>&1); then
    fail "missing file should exit 1"
else
    case "$out" in
        *"Policy file not found: $missing"*) ;;
        *) fail "missing file lacks required message: $out" ;;
    esac
fi

# Unknown fields warn but still succeed.
if ! out=$("$BIN" policy validate "$FIX/unknown_fields.json" 2>&1); then
    fail "unknown_fields.json should exit 0 (output: $out)"
else
    case "$out" in
        *"unknown policy field"*) ;;
        *) fail "unknown_fields.json should warn: $out" ;;
    esac
fi

# Usage error: no path.
if "$BIN" policy validate >/dev/null 2>&1; then
    fail "policy validate with no path should exit 1"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures policy CLI smoke test(s) failed" >&2
    exit 1
fi

echo "All policy CLI smoke tests passed!"
