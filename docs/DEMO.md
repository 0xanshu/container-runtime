# minicontainer live demo walkthrough

This document explains `run_demo.sh`: what it runs, what each section proves, and
what the output should look like. It is written so you can follow it on a Linux
VM with no prior context.

The demo tells one story — an untrusted "student job" is launched through
`minicontainer`, and each isolation layer is switched on and made visible:

1. legacy foreground run
2. PID namespace
3. UTS namespace
4. mount namespace + private root filesystem, and OverlayFS
5. cgroup v2 memory limit + OOM kill
6. wall-clock timeout enforced by the watchdog
7. JSON policy file → enforced limits + JSONL audit trail
8. detached lifecycle: start / list / inspect / exec / stats / stop
9. hardening: capability drop + seccomp + `no_new_privs`
10. cleanup

---

## 1. Prerequisites

| Requirement | Why |
|---|---|
| Linux kernel with namespaces (5.x+ recommended) | PID/UTS/mount namespaces and OverlayFS |
| Root access (or `sudo`) | mount namespaces, cgroups, rootfs |
| `make` and a C compiler | build `./minicontainer` |
| `cgroup` v2 **optional** | sections 5 and 7 use memory limits; they skip cleanly if unavailable |
| `overlayfs` **optional** | section 4b; skips if the kernel lacks it |
| `jq` **optional** | pretty-compacted JSONL output in section 7 |

Ubuntu 24.04+ rootless users may also need the one-time AppArmor profile
(`sudo make install-apparmor`). This demo runs as root, so it is not required,
but the runtime tests use it.

---

## 2. Run it

```bash
cd ~/anshu/container-runtime-main
make                 # builds ./minicontainer (required)
./run_demo.sh
```

Behaviour of the script:

- If started as a non-root user, it re-executes itself under `sudo` and prints
  a message first.
- If `./rootfs` is missing, it runs `scripts/build_rootfs.sh`. If that fails
  (for example because a host binary is absent), it builds a minimal rootfs
  with `sh`, `ls`, `cat`, and `echo` so sections 4/4b still work.
- It detects cgroup v2 and OverlayFS and skips only the affected sections.
- It works in `/tmp/minicontainer-demo.XXXXXX` and removes that directory on
  exit. Any remaining container state is swept with `minicontainer cleanup` at
  the end.
- Total runtime is roughly 15–30 seconds, dominated by the 3 s timeout in
  section 6 and the 4 s policy timeout in section 7.

Every step prints the exact command (`$ ...`) followed by its output, plus
`[note]` lines explaining what to look at.

---

## 3. Section-by-section

Output values such as container IDs, timestamps, and hostnames vary. Only the
shape and the highlighted behaviour matter.

### 0. Environment

```
[note] kernel:    6.x.x
[note] cpus:      2
[note] cgroup v2: mounted and writable
[note] binary:    /home/sid/container-runtime-main/minicontainer
```

What it tells you: whether sections 5 and 7 will actually run, and that the
demo is using the binary in this directory.

---

### 1. The simplest container

```
$ ./minicontainer run /bin/sh -c 'echo "hello from minicontainer"; ...'
hello from minicontainer
hostname=StargazerVM pid=12345 uid=0
```

No namespaces are requested. This is the legacy Phase 0–7a path: the workload
is a normal host process launched by the runtime.

---

### 2. PID namespace

```
[note] host shell PID: 4242

$ ./minicontainer run --pid /bin/sh -c 'echo "inside the container: pid=$$ ...'
inside the container: pid=1  <- namespace init
inside the container: ppid=0
```

What to observe: the shell is PID 1 **inside** the container while the host
shell keeps its own PID. Because PID 1 ignores signals that have no handler,
this is also why `--init` exists (section 8).

---

### 3. UTS namespace

```
[note] host hostname: StargazerVM

$ ./minicontainer run --pid --hostname demo-box ...
container hostname: demo-box

[note] the host's hostname is unchanged: StargazerVM
```

The container has a private hostname; `sethostname(2)` affected only its UTS
namespace.

---

### 4. Mount namespace + private root filesystem

```
$ ./minicontainer run --rootfs ./rootfs /bin/sh -c 'echo ...; ls /; ...'
the container sees its own /:
bin
etc
lib
lib64
proc
tmp

not the host /
```

Then a file is created under a host path and looked up inside the container:

```
$ ./minicontainer run --rootfs ./rootfs /bin/sh -c "ls '/tmp/minicontainer-demo.XXXX/host-only.txt' ..."
ls: cannot access '/tmp/minicontainer-demo.XXXX/host-only.txt': No such file or directory
not visible inside the container (correct)
```

What to observe: `--rootfs` auto-enables the mount and PID namespaces. The
container's `/` is the rootfs directory, not the host's `/`.

---

### 4b. OverlayFS copy-on-write

```
$ ./minicontainer run --rootfs ./rootfs --overlay /bin/sh -c \
    'echo "written inside the container" > /demo-write.txt; cat /demo-write.txt'
written inside the container

[note] base rootfs after the run:
  ./rootfs/demo-write.txt is absent — the base image was never modified
```

What to observe: the write succeeded inside the container but landed in the
overlay upper layer, not in the base rootfs. The upper/work directories live
under `./containers/` and are torn down after the run.

---

### 5. cgroup v2 — hard memory limit and OOM kill

```
[note] 16 MiB limit, workload tries to hold 64 MiB

$ ./minicontainer run --memory 16M --pids 0 --cpus 0 --event-log /tmp/... ...
Container killed by signal 9
[note] exit code 137  (137 = SIGKILL after the kernel OOM-killed the workload)
```

The run also writes an event log, which is printed:

```
Event log for container a1b2c3d4e5f6 (/tmp/.../oom-events/a1b2c3d4e5f6.jsonl):
{
  "timestamp": "2026-11-15T09:41:12.345Z",
  "container_id": "a1b2c3d4e5f6",
  "event_type": "container_start",
  "details": { ... }
}

{
  "timestamp": "2026-11-15T09:41:12.402Z",
  "container_id": "a1b2c3d4e5f6",
  "event_type": "oom_kill",
  "details": {
    "memory_limit_bytes": 16777216,
    "memory_peak_bytes": ...,
    "exit_code": 137
  }
}

{
  "timestamp": "2026-11-15T09:41:12.403Z",
  "container_id": "a1b2c3d4e5f6",
  "event_type": "container_exit",
  "details": {
    "exit_code": 137,
    "exit_reason": "oom",
    ...
  }
}
```

What to observe: the kernel, not the runtime, killed the process; the runtime
detected it from `memory.events` and recorded the audit trail.

If cgroup v2 is not mounted/writable, the section prints a skip note instead.

---

### 6. Wall-clock timeout

```
$ ./minicontainer run --debug --timeout 3 --grace-period 2 ...
[parent] Watchdog started (timeout=3s grace=2s)
simulating a runaway job...
[watchdog] timeout exceeded after 3.001s; sending SIGTERM
[parent] Child killed by signal: 15
Container killed by signal 15
[note] exit code 143 after 3s  (143 = SIGTERM, 137 = SIGKILL after grace)
```

What to observe: the `[watchdog]` line reports the measured elapsed time, not a
guess. If the workload ignored SIGTERM, a second line would report the SIGKILL
after the grace period.

---

### 7. JSON policy + audit trail

The script writes a policy file, validates it, then runs a job the policy should
stop:

```
$ ./minicontainer policy validate /tmp/.../student-policy.json
Policy /tmp/.../student-policy.json is valid

[note] the workload sleeps 30s; the policy timeout is 4s
$ ./minicontainer run --policy /tmp/.../student-policy.json /bin/sh -c '...'
student job started
Container killed by signal 15
[note] exit code 143
```

The policy is:

```json
{
  "policy": { "name": "demo-student", "version": "1.0" },
  "resources": {
    "memory": "64M",
    "pids": 32,
    "timeout": 4,
    "grace_period": 2,
    "thresholds": { "memory_warning": 0.01, "poll_interval_ms": 100 }
  },
  "logging": { "enabled": true, "log_dir": "/tmp/.../policy-events" }
}
```

Then the audit trail is queried:

```
$ ./minicontainer events --event-log /tmp/.../policy-events --limit 10
TIMESTAMP                 CONTAINER     EVENT
2026-11-15T09:41:20.001Z  a1b2c3d4e5f6  container_exit
2026-11-15T09:41:20.000Z  a1b2c3d4e5f6  timeout_kill
2026-11-15T09:41:18.500Z  a1b2c3d4e5f6  resource_breach
2026-11-15T09:41:16.001Z  a1b2c3d4e5f6  container_start
```

`logs <id>` pretty-prints the same file. The sequence to expect:

| Order | Event | Why |
|---|---|---|
| 1 | `container_start` | program, argv, policy name, uid, limits |
| 2 | `resource_breach` | shell startup exceeds the deliberately tiny 1% memory threshold |
| 3 | `timeout_kill` | policy timeout of 4 s fires |
| 4 | `container_exit` | `exit_reason: "timeout"`, exit code 143 |

If cgroup v2 is unavailable, the policy omits `memory`/`pids`/`thresholds`, so
`resource_breach` will not appear; start → timeout_kill → exit still do.

---

### 8. Detached lifecycle

```
[note] started detached container: 9f8e7d6c5b4a

$ ./minicontainer list
CONTAINER ID  PID     STARTED              COMMAND
9f8e7d6c5b4a  12345   2026-11-15T09:41:25  /bin/sh -c while :; do sleep 5; done
```

`inspect <id>` prints a live `/proc` + cgroup report (the demo shows the first
30 lines). `exec <id> ...` joins the container's namespaces:

```
exec joined the container: hostname=StargazerVM pid=3
```

`stats <id>` prints one resource snapshot. Then:

```
$ time ./minicontainer stop 9f8e7d6c5b4a
Stopped 9f8e7d6c5b4a

real    0m0.101s
```

What to observe: `stop` is fast because the container was started with
`--init`; the PID-1 supervisor forwards SIGTERM to the workload (`sleep`) so it
does not wait out the 10 s fallback timer. Without `--init`, stopping a PID-1
workload that ignores SIGTERM takes the full grace period and then SIGKILL.

---

### 9. Hardening

```
$ ./minicontainer run --secure --pid /bin/sh -c \
    'grep -E "^(CapEff|CapBnd|NoNewPrivs|Seccomp):" /proc/self/status'
CapBnd:    00000000a80425fb
CapEff:    00000000a80425fb
NoNewPrivs: 1
Seccomp:   2
```

What to observe:

- `CapEff`/`CapBnd` are the 14-capability Docker-style default set, not the
  host's full set.
- `NoNewPrivs: 1` prevents setuid binaries from gaining privileges.
- `Seccomp: 2` means a BPF filter is installed; disallowed syscalls return
  `EPERM` instead of killing the process.

---

### 10. Cleanup

```
$ ./minicontainer cleanup
Cleaned 0 stale resources
```

Removes state directories and cgroups left by crashed or detached containers.
The demo's temporary directory is removed by its own exit trap.

---

## 4. What a successful run looks like

A green run has:

- all ten section banners printed;
- `pid=1` in section 2 and `demo-box` in section 3;
- `./rootfs/demo-write.txt is absent` in section 4b;
- exit code `137` and an `oom_kill` event in section 5 (when cgroup v2 exists);
- `timeout exceeded after 3.00Xs` and code `143` in section 6;
- four event types in section 7's log (three without cgroup v2);
- a `stop` in well under a second in section 8;
- `Seccomp: 2` and `NoNewPrivs: 1` in section 9;
- no `UNEXPECTED:` line anywhere.

Sections may print `[note] ... skipped` for cgroup v2 or OverlayFS; that is
intentional, not a failure.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `error: ./minicontainer not found` | run `make` first |
| Section 5/7 says cgroup v2 not usable | bare-metal/VM with cgroup v2, not an unprivileged container; `/sys/fs/cgroup` must be writable |
| Section 4b skipped | kernel without OverlayFS (`grep overlay /proc/filesystems`) |
| Rootfs build fails | install the missing host binaries (`iproute2`, `python3`, `nano`) or let the minimal fallback run |
| `Failed to mount ...` under rootfs | AppArmor/userns restrictions on Ubuntu 24.04; run as root or `sudo make install-apparmor` |
| `exec` cannot join namespaces | the detached container must still be running; check `minicontainer list` |
| Event log empty | the policy's `logging.enabled` must be true, or pass `--event-log <dir>` |
| `No event log for container ...` | `logs` needs the same `--event-log` directory the run used |

---

## 6. Mapping to the build phases

| Demo section | Phase / feature |
|---|---|
| 1 | Phase 0–7a execution core, backward-compatible invocation |
| 2, 3, 4 | Phases 4 (namespaces), 2 (mount/overlay), 7a |
| 4b | OverlayFS copy-on-write |
| 5 | Phase 5 cgroups + Phase 3 `oom_kill` event |
| 6 | Phase 2 watchdog timeout/grace |
| 7 | Phase 1 policy + Phase 3 JSONL auditing |
| 8 | Phase 7b lifecycle + Phase 8b+ `--init` |
| 9 | Phase 8b hardening |
| 10 | Phase 7b cleanup |

---

## 7. Manual equivalent

Each section is just a command; the script only adds narration, temp
directories, and skip handling. For example, the audited policy run can be
reproduced by hand:

```bash
sudo mkdir -p /tmp/demo-events
cat > /tmp/demo-policy.json <<'EOF'
{
  "policy": { "name": "demo", "version": "1.0" },
  "resources": { "timeout": 4, "grace_period": 2 },
  "logging": { "enabled": true, "log_dir": "/tmp/demo-events" }
}
EOF

sudo ./minicontainer policy validate /tmp/demo-policy.json
sudo ./minicontainer run --policy /tmp/demo-policy.json /bin/sh -c 'sleep 30'

ID=$(basename /tmp/demo-events/*.jsonl .jsonl)
sudo ./minicontainer logs   --event-log /tmp/demo-events "$ID"
sudo ./minicontainer events --event-log /tmp/demo-events
```
