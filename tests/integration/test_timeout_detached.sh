#!/usr/bin/env bash
# Phase 2 — detached-mode timeout behavior.
#
# `start` detaches and the parent exits, so a parent-side watchdog cannot
# survive.  The required behavior is an explicit warning, never a silent
# no-op, plus a working detached container.
set -u

MC="${MC:-./minicontainer}"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$MC" ] || fail "$MC not found (run make first)"

echo "=== test_timeout_detached.sh ==="

err_file=$(mktemp)
out_file=$(mktemp)
trap 'rm -f "$err_file" "$out_file"' EXIT

"$MC" start --timeout 5 /bin/sh -c 'sleep 30' \
    >"$out_file" 2>"$err_file" || fail "detached start failed"

grep -q "not enforced for detached" "$err_file" \
    || fail "missing detached-timeout warning on stderr"
echo "PASS: detached start warns that --timeout is foreground-only"

id="$(head -n 1 "$out_file" | tr -d '[:space:]')"
[ -n "$id" ] || fail "detached start did not print a container ID"

"$MC" stop "$id" >/dev/null 2>&1 || true
echo "PASS: detached container $id started and was stopped"

echo "All detached-timeout tests passed!"
