#!/usr/bin/env bash
# Phase 3 — `logs` / `events` query command integration test.
#
# No root required: runs use --event-log with a temporary directory and
# no cgroup/timeout, so only container_start/container_exit are written.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_logs_command.sh ==="

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
logdir="$work/events"
uid=$(id -u)

"$MC" run --event-log "$logdir" /bin/sh -c 'exit 0' >/dev/null 2>&1 \
    || fail "first run failed"
id_a=$(find "$logdir" -maxdepth 1 -name '*.jsonl' -print -quit \
    2>/dev/null | xargs -r basename -s .jsonl)
[ -n "$id_a" ] || fail "first run wrote no event log"

file_a="$logdir/$id_a.jsonl"

logs_out="$("$MC" logs --event-log "$logdir" "$id_a" 2>&1)" \
    || fail "logs command failed"
echo "$logs_out" | grep -q '"event_type": "container_start"' \
    || fail "pretty-printed logs missing container_start"
echo "$logs_out" | grep -q '"event_type": "container_exit"' \
    || fail "pretty-printed logs missing container_exit"
echo "PASS: logs <id> pretty-prints the JSONL events"

# Newest-first ordering needs a distinct timestamp, not just IDs.
sleep 1
"$MC" run --event-log "$logdir" /bin/sh -c 'exit 0' >/dev/null 2>&1 \
    || fail "second run failed"
id_b=$(find "$logdir" -maxdepth 1 -newer "$file_a" -name '*.jsonl' \
    -print -quit 2>/dev/null | xargs -r basename -s .jsonl)
[ -n "$id_b" ] || fail "second run wrote no event log"

events_out="$("$MC" events --event-log "$logdir" 2>&1)" \
    || fail "events command failed"
echo "$events_out" | grep -q "$id_a" || fail "events missing first container"
echo "$events_out" | grep -q "$id_b" || fail "events missing second container"

first_id=$(echo "$events_out" | awk 'NR > 1 { print $2; exit }')
[ "$first_id" = "$id_b" ] \
    || fail "events is not newest-first (first=$first_id, expected=$id_b)"
echo "PASS: events lists containers newest first"

rows=$("$MC" events --event-log "$logdir" --limit 1 2>/dev/null \
    | awk 'NR > 1' | wc -l | tr -d ' ')
[ "$rows" = "1" ] || fail "--limit 1 returned $rows rows"
echo "PASS: events --limit bounds the output"

if ! "$MC" events --event-log "$logdir" --user "$uid" 2>/dev/null \
        | grep -q "$id_a"; then
    fail "--user $uid did not match this user's events"
fi
if ! "$MC" events --event-log "$logdir" --user "$((uid + 1))" 2>/dev/null \
        | grep -q "No events found"; then
    fail "--user filter did not exclude events from another uid"
fi
echo "PASS: events --user filters by container_start user_id"

if "$MC" events --event-log "$logdir" --limit 0 >/dev/null 2>&1; then
    fail "--limit 0 was accepted"
fi
if "$MC" events --event-log "$logdir" --user nope >/dev/null 2>&1; then
    fail "non-numeric --user was accepted"
fi
echo "PASS: invalid --limit/--user values are rejected"

missing="000000000000"
"$MC" logs --event-log "$logdir" "$missing" >/dev/null 2>&1
[ $? -eq 1 ] || fail "logs for a missing container should exit 1"
err="$("$MC" logs --event-log "$logdir" "$missing" 2>&1)"
echo "$err" | grep -q "No event log for container $missing" \
    || fail "logs missing-container error text is wrong"
echo "PASS: logs reports a missing event log and exits 1"

if "$MC" logs --event-log "$logdir" "../escape" >/dev/null 2>&1; then
    fail "logs accepted a path-traversal container ID"
fi
echo "PASS: logs rejects path-traversal IDs"

echo "All logs/events command tests passed!"
