#!/usr/bin/env bash
# Phase 2 — wall-clock timeout integration test.
#
# No root required: timeout-only runs do not create a cgroup or any
# namespace.  Exits non-zero on the first failure.
#
# Timed runs capture --debug output to $debug_log; fail() prints it, so a
# future flake (e.g. VM scheduling latency) is self-diagnosing instead of
# a bare "ran too long".
set -u

MC="${MC:-./minicontainer}"

work=$(mktemp -d) || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'rm -rf "$work"' EXIT
debug_log="$work/debug.log"
: > "$debug_log"

dump_debug() {
    [ -s "$debug_log" ] || return 0
    echo "--- debug output of the last timed run ---" >&2
    cat "$debug_log" >&2
    echo "--- end debug output ---" >&2
}

fail() { echo "FAIL: $*" >&2; dump_debug; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_timeout.sh ==="

# A quick command must be unaffected by a generous timeout.
out="$("$MC" run --debug --timeout 5 /bin/sh -c 'echo quick-ok' 2>&1)" \
    && quick_rc=0 || quick_rc=$?
printf '%s\n' "$out" > "$debug_log"
[ "$quick_rc" -eq 0 ] \
    || fail "quick command failed with timeout set (rc=$quick_rc)"
echo "$out" | grep -q "quick-ok" || fail "quick command output missing"
echo "PASS: quick command completes before timeout"

# An infinite loop must be terminated at roughly the timeout boundary.
#
# --grace-period 1 caps the worst case at ~2s (a SIGTERM-ignoring
# workload gets SIGKILL one second later), so the 5s ceiling flags real
# lateness instead of the 10s legacy default grace.  Grace escalation
# itself is covered separately by test_timeout_grace.sh.
start=$(date +%s)
"$MC" run --debug --timeout 1 --grace-period 1 \
    /bin/sh -c 'while :; do :; done' >"$debug_log" 2>&1
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
