#!/usr/bin/env bash
# Phase 3 — oom_kill event integration test.
#
# Requires root and cgroup v2: the memory limit is enforced by the
# kernel.  Skips with a clear reason elsewhere.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*"; exit 0; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_oom_event.sh ==="

[ "$(id -u)" -eq 0 ] || skip "root required for cgroup memory limits"
[ -f /sys/fs/cgroup/cgroup.controllers ] \
    || skip "cgroup v2 not mounted at /sys/fs/cgroup"
[ -w /sys/fs/cgroup ] || skip "/sys/fs/cgroup is not writable"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
logdir="$work/events"
policy="$work/policy.json"

cat > "$policy" <<EOF
{
  "policy": {
    "name": "oom-event-test",
    "version": "1.0"
  },
  "resources": {
    "memory": "16M"
  },
  "logging": {
    "enabled": true,
    "log_dir": "$logdir"
  }
}
EOF

# Command substitution keeps the 64 MiB string resident in the shell,
# which exceeds the 16 MiB cgroup limit and forces an OOM kill.
"$MC" run --policy "$policy" --cpus 0 --pids 0 /bin/sh -c \
    'x=$(head -c 67108864 /dev/zero | tr "\0" "x"); sleep 1' \
    >/dev/null 2>&1
rc=$?

file=$(find "$logdir" -maxdepth 1 -name '*.jsonl' -print -quit 2>/dev/null)
[ -n "$file" ] || fail "no event log written"

grep -q '"event_type":"oom_kill"' "$file" \
    || fail "oom_kill event missing (rc=$rc)"
grep -q '"memory_limit_bytes":16777216' "$file" \
    || fail "oom_kill memory_limit_bytes missing/incorrect"
grep -q '"memory_peak_bytes":' "$file" \
    || fail "oom_kill memory_peak_bytes missing"
grep -q '"exit_code":' "$file" || fail "oom_kill exit_code missing"
grep -q '"event_type":"container_exit"' "$file" \
    || fail "container_exit event missing"
grep -q '"exit_reason":"oom"' "$file" \
    || fail "container_exit should report reason 'oom'"

if grep -q '"exit_code":137' "$file"; then
    echo "PASS: oom_kill emitted and exit code is 137"
else
    echo "PASS: oom_kill emitted (kernel did not report exit code 137; rc=$rc)"
fi

echo "All OOM event tests passed!"
