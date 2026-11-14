#!/usr/bin/env bash
# Phase 2 — wall-clock timeout integration test.
#
# No root required: timeout-only runs do not create a cgroup or any
# namespace.  Exits non-zero on the first failure.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_timeout.sh ==="

# A quick command must be unaffected by a generous timeout.
out="$("$MC" run --timeout 5 /bin/sh -c 'echo quick-ok' 2>&1)" \
    || fail "quick command failed with timeout set"
echo "$out" | grep -q "quick-ok" || fail "quick command output missing"
echo "PASS: quick command completes before timeout"

# An infinite loop must be terminated at roughly the timeout boundary.
start=$(date +%s)
"$MC" run --timeout 1 /bin/sh -c 'while :; do :; done' >/dev/null 2>&1
rc=$?
elapsed=$(( $(date +%s) - start ))

[ "$rc" -ne 0 ] || fail "timed-out container unexpectedly exited 0"
[ "$rc" -eq 143 ] || [ "$rc" -eq 137 ] \
    || fail "expected SIGTERM (143) or SIGKILL (137), got $rc"
[ "$elapsed" -ge 1 ] || fail "container died before the timeout (${elapsed}s)"
[ "$elapsed" -le 5 ] || fail "container ran too long (${elapsed}s)"
echo "PASS: timeout terminated the infinite loop (rc=$rc, ${elapsed}s)"

# --timeout 0 disables the timeout explicitly (policy override path).
"$MC" run --timeout 0 /bin/sh -c 'exit 0' >/dev/null 2>&1 \
    || fail "--timeout 0 should behave as no timeout"
echo "PASS: --timeout 0 disables the timeout"

# Invalid values are rejected with a clear error.
if "$MC" run --timeout abc /bin/true >/dev/null 2>&1; then
    fail "non-numeric --timeout was accepted"
fi
if "$MC" run --timeout -1 /bin/true >/dev/null 2>&1; then
    fail "negative --timeout was accepted"
fi
if "$MC" run --timeout 4294967296 /bin/true >/dev/null 2>&1; then
    fail "oversized --timeout was accepted"
fi
if "$MC" run --grace-period 99999 /bin/true >/dev/null 2>&1; then
    fail "oversized --grace-period was accepted"
fi
echo "PASS: invalid timeout/grace values are rejected"

echo "All timeout tests passed!"
