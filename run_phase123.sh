#!/usr/bin/env bash
#
# Phase 1-3 verification runner.
#
#   Phase 1  policy parsing / validation / application        (no root)
#   Phase 2  watchdog timeout + grace escalation              (no root)
#   Phase 3  JSONL event logging + logs/events CLI            (mostly no root)
#
# Usage:
#   ./run_phase123.sh
#
# Runs from any directory (cd's to its own location) and stops at the
# first failure, so the last "===" banner identifies the broken phase.
#
# The two cgroup-dependent Phase 3 tests need root + cgroup v2 and skip
# with a clear message on hosts that cannot support them.

set -euo pipefail
cd "$(dirname "$0")"

step() { echo; echo "=== $* ==="; }
run()  { "$@"; }

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Rebuild ./minicontainer as well as the test binaries. The integration
# scripts execute the CLI binary, and the test-only make targets do NOT
# relink it -- a stale ./minicontainer produced a phantom timeout failure
# once already.
step "Building minicontainer and Phase 1-3 test binaries"
make
make test_policy test_watchdog test_eventlog

step "Phase 1: policy unit tests (no root)"
run ./test_policy

step "Phase 1: policy CLI smoke tests (no root)"
run bash tests/test_policy_cli.sh

step "Phase 2: watchdog unit tests (no root)"
run ./test_watchdog

for t in timeout timeout_grace timeout_detached timeout_stress; do
    step "Phase 2 integration: $t"
    run bash "tests/integration/test_$t.sh"
done

step "Phase 3: eventlog unit tests (no root)"
run ./test_eventlog

for t in event_logging timeout_event logs_command event_log_failure; do
    step "Phase 3 integration: $t"
    run bash "tests/integration/test_$t.sh"
done

step "Phase 3: cgroup-dependent events (root + cgroup v2; SKIP otherwise)"
run $SUDO bash tests/integration/test_oom_event.sh
run $SUDO bash tests/integration/test_resource_breach.sh

echo
echo "PHASE 1-3: ALL PASSED"
