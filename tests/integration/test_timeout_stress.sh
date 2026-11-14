#!/usr/bin/env bash
# Phase 2 — stress/regression: repeated short timed containers must not
# leave zombies behind or destabilize exit codes.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_timeout_stress.sh ==="

for i in $(seq 1 20); do
    "$MC" run --timeout 2 /bin/sh -c 'exit 0' >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 0 ] || fail "iteration $i exited $rc (expected 0)"
done
echo "PASS: 20 short timed containers exited 0"

# No zombie children of this shell remain.
zombies=$(ps -o stat=,ppid= -A 2>/dev/null | awk -v ppid="$$" '$1 ~ /^Z/ && $2 == ppid')
[ -z "$zombies" ] || fail "zombie process(es) left behind: $zombies"
echo "PASS: no zombie processes"

echo "All timeout stress tests passed!"
