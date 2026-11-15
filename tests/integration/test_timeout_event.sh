#!/usr/bin/env bash
# Phase 3 — timeout_kill event integration test.
#
# A foreground run with --timeout 1 and --grace-period 0 must SIGKILL the
# infinite loop and record exactly one timeout_kill event with the final
# signal and the grace-period flag.  No root or cgroup is required.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_timeout_event.sh ==="

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
logdir="$work/events"

"$MC" run --event-log "$logdir" --timeout 1 --grace-period 0 \
    /bin/sh -c "trap '' TERM; while :; do :; done" >/dev/null 2>&1
rc=$?

[ "$rc" -eq 137 ] || fail "expected SIGKILL exit 137, got $rc"

file=$(find "$logdir" -maxdepth 1 -name '*.jsonl' -print -quit 2>/dev/null)
[ -n "$file" ] || fail "no event log written"

grep -q '"event_type":"timeout_kill"' "$file" \
    || fail "timeout_kill event missing"
grep -q '"timeout_seconds":1' "$file" \
    || fail "timeout_seconds field missing/incorrect"
grep -q '"elapsed_seconds":' "$file" \
    || fail "elapsed_seconds field missing"
grep -q '"signal":"SIGKILL"' "$file" \
    || fail "SIGKILL signal field missing"
grep -q '"grace_period_used":true' "$file" \
    || fail "grace_period_used should be true after SIGKILL escalation"
grep -q '"event_type":"container_exit"' "$file" \
    || fail "container_exit event missing"
grep -q '"exit_reason":"timeout"' "$file" \
    || fail "container_exit should report reason 'timeout'"
echo "PASS: timeout_kill emitted with timeout/elapsed/signal/grace fields"

# A workload that handles SIGTERM and exits during the grace period
# must still log timeout_kill, but with signal=SIGTERM and no escalation.
grace_dir="$work/grace-events"
"$MC" run --event-log "$grace_dir" --timeout 1 --grace-period 5 \
    /bin/sh -c "trap 'exit 0' TERM; while :; do sleep 0.2; done" \
    >/dev/null 2>&1
rc=$?
[ "$rc" -eq 0 ] || fail "SIGTERM-trapping workload should exit 0, got $rc"

grace_file=$(find "$grace_dir" -maxdepth 1 -name '*.jsonl' -print -quit \
    2>/dev/null)
[ -n "$grace_file" ] || fail "no event log written for grace case"
grep -q '"event_type":"timeout_kill"' "$grace_file" \
    || fail "timeout_kill missing for graceful case"
grep -q '"signal":"SIGTERM"' "$grace_file" \
    || fail "graceful case should report SIGTERM"
grep -q '"grace_period_used":false' "$grace_file" \
    || fail "graceful case should not report SIGKILL escalation"
echo "PASS: SIGTERM-handled timeout reports signal=SIGTERM, no escalation"

echo "All timeout event tests passed!"
