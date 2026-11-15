#!/usr/bin/env bash
# Phase 3 — graceful event-log failure integration test.
#
# An unwritable log directory must produce exactly one warning, disable
# logging for that run, and never change the container's exit status or
# prevent timeout enforcement.  No root required: the log path is made
# invalid by placing it underneath a regular file.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_event_log_failure.sh ==="

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

blocker="$work/not-a-directory"
: > "$blocker"
bad_dir="$blocker/events"
out_file="$work/stdout"
err_file="$work/stderr"

"$MC" run --event-log "$bad_dir" /bin/sh -c 'echo failure-ok; exit 0' \
    >"$out_file" 2>"$err_file"
rc=$?

[ "$rc" -eq 0 ] || fail "event-log failure changed the exit status (got $rc)"
grep -q "failure-ok" "$out_file" || fail "workload output missing"

warnings=$(grep -c "eventlog" "$err_file" || true)
[ "$warnings" -eq 1 ] \
    || fail "expected exactly one eventlog warning, got $warnings"
grep -q "event logging disabled for this run" "$err_file" \
    || fail "warning does not say logging was disabled"
echo "PASS: unwritable directory warns once and the container still exits 0"

[ ! -e "$bad_dir" ] || fail "unexpected event log directory was created"

# The same failure must not stop timeout enforcement.
"$MC" run --event-log "$bad_dir" --timeout 1 --grace-period 0 \
    /bin/sh -c "trap '' TERM; while :; do :; done" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 137 ] || fail "timeout did not kill the container (got $rc)"
echo "PASS: timeout still works when event logging is unavailable"

# An invalid --event-log value is rejected at parse time.
if "$MC" run --event-log "" /bin/true >/dev/null 2>&1; then
    fail "empty --event-log value was accepted"
fi
echo "PASS: empty --event-log value is rejected"

echo "All event-log failure tests passed!"
