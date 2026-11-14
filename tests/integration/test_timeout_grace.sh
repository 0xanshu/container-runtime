#!/usr/bin/env bash
# Phase 2 — graceful shutdown (SIGTERM -> grace -> SIGKILL) integration.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_timeout_grace.sh ==="

# The workload traps SIGTERM and exits 0 during the grace period.
out="$("$MC" run --timeout 1 --grace-period 5 \
    /bin/sh -c "trap 'echo term-trapped; exit 0' TERM; while :; do sleep 0.2; done" \
    2>&1)"
rc=$?
[ "$rc" -eq 0 ] || fail "trapping workload should exit 0, got $rc"
echo "$out" | grep -q "term-trapped" || fail "SIGTERM trap did not run"
echo "PASS: SIGTERM handled during grace period (no SIGKILL)"

# The workload ignores SIGTERM; the watchdog must escalate after 1s.
start=$(date +%s)
"$MC" run --timeout 1 --grace-period 1 \
    /bin/sh -c "trap '' TERM; while :; do :; done" >/dev/null 2>&1
rc=$?
elapsed=$(( $(date +%s) - start ))

[ "$rc" -eq 137 ] || fail "expected SIGKILL (137) after grace, got $rc"
[ "$elapsed" -ge 2 ] || fail "SIGKILL arrived before the grace period (${elapsed}s)"
[ "$elapsed" -le 6 ] || fail "grace escalation took too long (${elapsed}s)"
echo "PASS: SIGKILL fallback after grace (rc=$rc, ${elapsed}s)"

# --grace-period 0 is honored: SIGKILL immediately after SIGTERM.
"$MC" run --timeout 1 --grace-period 0 \
    /bin/sh -c "trap '' TERM; while :; do :; done" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 137 ] || fail "--grace-period 0 should SIGKILL, got $rc"
echo "PASS: --grace-period 0 sends SIGKILL immediately"

# --init: the PID-1 supervisor forwards SIGTERM to the workload.
out="$("$MC" run --init --timeout 1 --grace-period 5 \
    /bin/sh -c "trap 'echo init-trapped; exit 0' TERM; while :; do sleep 0.2; done" \
    2>&1)"
rc=$?
[ "$rc" -eq 0 ] || fail "--init workload should exit 0, got $rc"
echo "$out" | grep -q "init-trapped" || fail "--init did not forward SIGTERM"
echo "PASS: SIGTERM forwarded through --init supervisor"

echo "All grace-period tests passed!"
