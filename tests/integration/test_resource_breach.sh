#!/usr/bin/env bash
# Phase 3 — resource_breach event integration test.
#
# Requires root and cgroup v2.  The policy deliberately sets a tiny
# memory warning threshold so ordinary shell startup exceeds it; this
# keeps the test from depending on allocator timing.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*"; exit 0; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_resource_breach.sh ==="

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
    "name": "resource-breach-test",
    "version": "1.0"
  },
  "resources": {
    "memory": "128M",
    "thresholds": {
      "memory_warning": 0.01,
      "poll_interval_ms": 100
    }
  },
  "logging": {
    "enabled": true,
    "log_dir": "$logdir"
  }
}
EOF

# 16 MiB resident string in a 128 MiB cgroup is far above the 1%
# threshold (1.28 MiB), and the sleep gives the watchdog time to poll.
"$MC" run --policy "$policy" --cpus 0 --pids 0 /bin/sh -c \
    'x=$(head -c 16777216 /dev/zero | tr "\0" "x"); sleep 1' \
    >/dev/null 2>&1
rc=$?

file=$(find "$logdir" -maxdepth 1 -name '*.jsonl' -print -quit 2>/dev/null)
[ -n "$file" ] || fail "no event log written"

grep -q '"event_type":"resource_breach"' "$file" \
    || fail "resource_breach event missing (rc=$rc)"

# The payload must identify the resource and carry the threshold math.
grep -q '"resource":"memory"' "$file" \
    || fail "resource_breach resource field missing"
grep -q '"current_value":' "$file" \
    || fail "resource_breach current_value missing"
grep -q '"limit_value":' "$file" \
    || fail "resource_breach limit_value missing"
grep -q '"threshold":0.010000' "$file" \
    || fail "resource_breach threshold missing/incorrect"
grep -q '"percentage":' "$file" \
    || fail "resource_breach percentage missing"
echo "PASS: resource_breach emitted with resource/current/limit/threshold/percentage"

echo "All resource breach tests passed!"
