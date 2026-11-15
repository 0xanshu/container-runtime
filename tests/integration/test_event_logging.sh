#!/usr/bin/env bash
# Phase 3 — event logging integration test.
#
# No root required: the policy's cgroup limits are explicitly zeroed on
# the command line so the run does not need /sys/fs/cgroup write access.
# The policy only supplies the log directory and the policy name.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_event_logging.sh ==="

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

logdir="$work/events"
policy="$work/policy.json"

cat > "$policy" <<EOF
{
  "policy": {
    "name": "event-logging-test",
    "version": "1.0"
  },
  "logging": {
    "enabled": true,
    "log_dir": "$logdir"
  }
}
EOF

# --- policy-enabled logging -----------------------------------------
out="$("$MC" run --policy "$policy" --cpus 0 --pids 0 \
    /bin/sh -c 'echo logging-ok; exit 0' 2>&1)" \
    || fail "policy run failed: $out"
echo "$out" | grep -q "logging-ok" || fail "workload output missing"

file=$(find "$logdir" -maxdepth 1 -name '*.jsonl' -print -quit 2>/dev/null)
[ -n "$file" ] || fail "no <id>.jsonl file was created in $logdir"
echo "PASS: policy logging created $file"

grep -q '"event_type":"container_start"' "$file" \
    || fail "container_start event missing"
grep -q '"event_type":"container_exit"' "$file" \
    || fail "container_exit event missing"
grep -q '"exit_code":0' "$file" || fail "exit_code 0 missing"
grep -q '"exit_reason":"normal"' "$file" || fail "normal exit reason missing"
grep -q '"policy":"event-logging-test"' "$file" || fail "policy name missing"
grep -q '"program":"/bin/sh"' "$file" || fail "program missing"
grep -q '"user_id":' "$file" || fail "user_id missing"
echo "PASS: start/exit events carry the required fields"

# Every line must be one complete JSON object ending in a newline.
awk 'BEGIN { bad = 0 }
     { if ($0 !~ /^\{.*\}$/) bad = 1 }
     END { exit bad }' "$file" \
    || fail "event file contains a malformed line"
[ "$(tail -c 1 "$file" | od -An -t x1 | tr -d ' \n')" = "0a" ] \
    || fail "event file does not end with a newline"
echo "PASS: every event is one valid JSON object per line"

id=$(basename "$file" .jsonl)

# --- logs <id> with an explicit directory ---------------------------
logs_out="$("$MC" logs --event-log "$logdir" "$id" 2>&1)" \
    || fail "logs command failed"
echo "$logs_out" | grep -q "container_start" || fail "logs missing start"
echo "$logs_out" | grep -q "container_exit" || fail "logs missing exit"
echo "PASS: logs <id> prints the container's events"

# --- --event-log overrides the policy directory ---------------------
override="$work/override-events"
"$MC" run --policy "$policy" --cpus 0 --pids 0 --event-log "$override" \
    /bin/sh -c 'exit 0' >/dev/null 2>&1 || fail "override run failed"
override_file=$(find "$override" -maxdepth 1 -name '*.jsonl' -print -quit \
    2>/dev/null)
[ -n "$override_file" ] || fail "--event-log did not override policy log_dir"
echo "PASS: --event-log overrides the policy log directory"

# --- --no-event-log disables policy logging -------------------------
before=$(find "$logdir" -maxdepth 1 -name '*.jsonl' | wc -l)
"$MC" run --policy "$policy" --cpus 0 --pids 0 --no-event-log \
    /bin/sh -c 'exit 0' >/dev/null 2>&1 || fail "--no-event-log run failed"
after=$(find "$logdir" -maxdepth 1 -name '*.jsonl' | wc -l)
[ "$before" -eq "$after" ] || fail "--no-event-log still wrote an event file"
echo "PASS: --no-event-log disables policy logging"

# --- mutually exclusive flags are rejected --------------------------
if "$MC" run --event-log "$work/x" --no-event-log /bin/true >/dev/null 2>&1; then
    fail "--event-log with --no-event-log was accepted"
fi
echo "PASS: --event-log and --no-event-log are mutually exclusive"

echo "All event logging tests passed!"
