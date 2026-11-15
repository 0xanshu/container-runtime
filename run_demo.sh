#!/usr/bin/env bash
#
# Live end-to-end demo of minicontainer.
#
# Tells one story: an untrusted "student job" is launched through the
# runtime, then each isolation layer is turned on and made visible:
#
#   1  legacy foreground run
#   2  PID namespace (the workload becomes PID 1)
#   3  UTS namespace (private hostname)
#   4  mount namespace + private rootfs, and OverlayFS copy-on-write
#   5  cgroup v2 hard memory limit + OOM kill
#   6  wall-clock timeout enforced by the watchdog
#   7  JSON policy file -> enforced limits + JSONL audit trail
#   8  detached lifecycle: start / list / inspect / exec / stats / stop
#   9  hardening: capability drop + seccomp + no_new_privs
#  10  cleanup
#
# Usage:
#   ./run_demo.sh
#
# Parts 4-9 need root; the script re-executes itself under sudo when
# started unprivileged. Run `make` first so ./minicontainer exists.

set -u

SCRIPT_PATH=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
cd "$(dirname "$SCRIPT_PATH")"

if [ "$(id -u)" -ne 0 ]; then
    echo "[demo] namespaces, cgroups and the rootfs demo need root."
    echo "[demo] re-running under sudo (you may be prompted for a password)..."
    exec sudo -- bash "$SCRIPT_PATH" "$@"
fi

MC="$PWD/minicontainer"
if [ ! -x "$MC" ]; then
    echo "error: $MC not found — run 'make' first." >&2
    exit 1
fi

WORK=$(mktemp -d /tmp/minicontainer-demo.XXXXXX) || {
    echo "error: mktemp -d failed" >&2
    exit 1
}
trap 'rm -rf "$WORK"' EXIT

section() {
    printf '\n\n'
    printf '##################################################################\n'
    printf '# %s\n' "$*"
    printf '##################################################################\n'
}
note() { printf '   [note] %s\n' "$*"; }
show() { printf '\n$ %s\n' "$*"; "$@"; }

cgroup_ok=0
if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ -w /sys/fs/cgroup ]; then
    cgroup_ok=1
fi

# ------------------------------------------------------------------
section "0. Environment"
note "kernel:    $(uname -r)"
note "cpus:      $(nproc)"
note "cgroup v2: $([ "$cgroup_ok" -eq 1 ] && echo 'mounted and writable' || echo 'NOT available')"
note "binary:    $MC"
note "demo dir:  $WORK"

# ------------------------------------------------------------------
section "1. The simplest container (legacy invocation, no namespaces)"
note "same kernel, same /, same binaries — this is the Phase 0-7a path"
show "$MC" run /bin/sh -c \
    'echo "hello from minicontainer"; echo "hostname=$(hostname) pid=$$ uid=$(id -u)"'

# ------------------------------------------------------------------
section "2. PID namespace — the workload becomes PID 1"
note "host shell PID: $$"
show "$MC" run --pid /bin/sh -c \
    'echo "inside the container: pid=$$  <- namespace init"; echo "inside the container: ppid=$PPID"'
note "PID 1 ignores signals with no handler, which is why --init exists (see step 8)"

# ------------------------------------------------------------------
section "3. UTS namespace — a private hostname"
note "host hostname: $(hostname)"
show "$MC" run --pid --hostname demo-box /bin/sh -c \
    'echo "container hostname: $(hostname)"'
note "the host's hostname is unchanged: $(hostname)"

# ------------------------------------------------------------------
section "4. Mount namespace + private root filesystem"

# Minimal fallback if scripts/build_rootfs.sh cannot find every host
# binary it expects. Only sh/ls/cat/echo are actually needed by this demo.
build_minimal_rootfs() {
    local dest=./rootfs b src lib p
    rm -rf "$dest"
    mkdir -p "$dest"/bin "$dest"/lib "$dest"/lib64 "$dest"/proc "$dest"/tmp "$dest"/etc || return 1
    for b in sh ls cat echo sleep hostname id grep; do
        src=""
        for p in "/bin/$b" "/usr/bin/$b" "/sbin/$b" "/usr/sbin/$b"; do
            if [ -f "$p" ]; then
                src="$p"
                break
            fi
        done
        if [ -z "$src" ]; then
            src=$(which "$b" 2>/dev/null || true)
        fi
        [ -n "$src" ] && [ -f "$src" ] || continue
        cp "$src" "$dest/bin/$b" || return 1
        while IFS= read -r lib; do
            [ -n "$lib" ] && [ -f "$lib" ] || continue
            cp -n "$lib" "$dest/lib/" 2>/dev/null || true
        done < <(ldd "$src" 2>/dev/null | awk '/=> \// {print $3} /ld-linux/ {print $1}')
    done
    for lib in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2; do
        if [ -r "$lib" ]; then
            cp "$lib" "$dest/lib64/" 2>/dev/null || true
            break
        fi
    done
    [ -x "$dest/bin/sh" ]
}

rootfs_ok=1
if [ ! -d ./rootfs ]; then
    note "./rootfs is missing; building it with scripts/build_rootfs.sh (one time)"
    if ! bash scripts/build_rootfs.sh; then
        note "scripts/build_rootfs.sh failed; building a minimal demo rootfs instead"
        if ! build_minimal_rootfs; then
            note "minimal rootfs build failed — skipping sections 4 and 4b"
            rootfs_ok=0
        fi
    fi
fi

if [ "$rootfs_ok" -eq 1 ]; then
    show "$MC" run --rootfs ./rootfs /bin/sh -c \
        'echo "the container sees its own /:"; ls /; echo; echo "not the host /"'

    echo "host secret" > "$WORK/host-only.txt"
    note "host-only file created at $WORK/host-only.txt"
    show "$MC" run --rootfs ./rootfs /bin/sh -c \
        "ls '$WORK/host-only.txt' 2>&1 || echo 'not visible inside the container (correct)'"
else
    note "sections 4/4b need ./rootfs — skipped"
fi

# ------------------------------------------------------------------
section "4b. OverlayFS — writes land in a copy-on-write layer"
if [ "$rootfs_ok" -eq 1 ] && grep -qw overlay /proc/filesystems; then
    show "$MC" run --rootfs ./rootfs --overlay /bin/sh -c \
        'echo "written inside the container" > /demo-write.txt; cat /demo-write.txt'
    note "base rootfs after the run:"
    if [ -e ./rootfs/demo-write.txt ]; then
        echo "  UNEXPECTED: ./rootfs/demo-write.txt exists on the host"
    else
        echo "  ./rootfs/demo-write.txt is absent — the base image was never modified"
    fi
else
    note "no ./rootfs or no overlayfs support in this kernel — skipped"
fi

# ------------------------------------------------------------------
section "5. cgroup v2 — a hard memory limit and an OOM kill"
if [ "$cgroup_ok" -eq 1 ]; then
    oom_dir="$WORK/oom-events"
    note "16 MiB limit, workload tries to hold 64 MiB"
    show "$MC" run --memory 16M --pids 0 --cpus 0 --event-log "$oom_dir" \
        /bin/sh -c 'x=$(head -c 67108864 /dev/zero | tr "\0" "x"); echo "allocated"; sleep 1'
    rc=$?
    note "exit code $rc  (137 = SIGKILL after the kernel OOM-killed the workload)"
    oom_file=$(find "$oom_dir" -maxdepth 1 -name '*.jsonl' -print -quit 2>/dev/null)
    if [ -n "$oom_file" ]; then
        oom_id=$(basename "$oom_file" .jsonl)
        show "$MC" logs --event-log "$oom_dir" "$oom_id"
    else
        note "no event log written"
    fi
else
    note "cgroup v2 is not usable on this host — skipping the memory-limit demo"
fi

# ------------------------------------------------------------------
section "6. Wall-clock timeout — the watchdog stops a runaway job"
start=$(date +%s)
show "$MC" run --debug --timeout 3 --grace-period 2 /bin/sh -c \
    'echo "simulating a runaway job..."; while :; do :; done'
rc=$?
elapsed=$(( $(date +%s) - start ))
note "exit code $rc after ${elapsed}s  (143 = SIGTERM, 137 = SIGKILL after grace)"
note "look for the [watchdog] line above: it reports the exact deadline"

# ------------------------------------------------------------------
section "7. JSON policy file — enforced limits + JSONL audit log"
policy="$WORK/student-policy.json"
if [ "$cgroup_ok" -eq 1 ]; then
    cat > "$policy" <<EOF
{
  "policy": {
    "name": "demo-student",
    "version": "1.0",
    "description": "Limits for an untrusted student job"
  },
  "resources": {
    "memory": "64M",
    "pids": 32,
    "timeout": 4,
    "grace_period": 2,
    "thresholds": {
      "memory_warning": 0.01,
      "poll_interval_ms": 100
    }
  },
  "logging": {
    "enabled": true,
    "log_dir": "$WORK/policy-events"
  }
}
EOF
else
    note "no cgroup v2 — policy demo uses timeout + logging only"
    cat > "$policy" <<EOF
{
  "policy": { "name": "demo-student", "version": "1.0" },
  "resources": { "timeout": 4, "grace_period": 2 },
  "logging": { "enabled": true, "log_dir": "$WORK/policy-events" }
}
EOF
fi

show "$MC" policy validate "$policy"
ev_dir="$WORK/policy-events"
note "the workload sleeps 30s; the policy timeout is 4s"
show "$MC" run --policy "$policy" /bin/sh -c \
    'echo "student job started"; sleep 30'
rc=$?
note "exit code $rc"

policy_file=$(find "$ev_dir" -maxdepth 1 -name '*.jsonl' -print -quit 2>/dev/null)
if [ -n "$policy_file" ]; then
    policy_id=$(basename "$policy_file" .jsonl)
    show "$MC" events --event-log "$ev_dir" --limit 10
    show "$MC" logs --event-log "$ev_dir" "$policy_id"
    if command -v jq >/dev/null 2>&1; then
        printf '\nRaw JSONL, one event per line:\n'
        jq -c '{timestamp,event_type,details}' "$policy_file"
    fi
else
    note "no event log written — check the policy's logging.log_dir"
fi

# ------------------------------------------------------------------
section "8. Detached lifecycle — start / list / inspect / exec / stats / stop"
id=$("$MC" start --pid --init /bin/sh -c 'while :; do sleep 5; done')
note "started detached container: $id"
show "$MC" list

printf '\n$ %s inspect %s   (first 30 lines)\n' "$MC" "$id"
"$MC" inspect "$id" 2>&1 | sed -n '1,30p'

show "$MC" exec "$id" /bin/sh -c \
    'echo "exec joined the container: hostname=$(hostname) pid=$$"'
show "$MC" stats "$id"

printf '\n$ time %s stop %s\n' "$MC" "$id"
time "$MC" stop "$id"
note "--init forwards SIGTERM, so stop returns in well under a second"
show "$MC" list

# ------------------------------------------------------------------
section "9. Hardening — dropped capabilities, seccomp, no_new_privs"
if [ "$rootfs_ok" -eq 1 ]; then
    show "$MC" run --secure --rootfs ./rootfs --pid /bin/sh -c \
        'grep -E "^(CapEff|CapBnd|NoNewPrivs|Seccomp):" /proc/self/status'
    note "CapEff/CapBnd are a small subset of the host's"
    note "Seccomp: 2 means a filter is installed; NoNewPrivs: 1 blocks setuid escalation"
else
    note "Section 9 needs ./rootfs for --secure — skipped"
fi

# ------------------------------------------------------------------
section "10. Cleanup"
show "$MC" cleanup
note "temporary demo directory $WORK is removed on exit"
note "demo complete"
