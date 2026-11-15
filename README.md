# minicontainer

A lightweight, production-grade container runtime built from first principles in C using raw Linux system calls.

---

## Overview

**minicontainer** is an educational, production-grade container runtime implemented from scratch in pure C. Instead of wrapping high-level tools like Docker, containerd, or runc, this project implements containerization from first principles using direct Linux kernel interfaces:
* **Linux Namespaces** (`clone`, `setns`, `unshare`) for process, mount, network, hostname, user, and IPC isolation.
* **OverlayFS** and `pivot_root` for copy-on-write container filesystems.
* **cgroup v2** for CPU, memory, process limits, and out-of-memory (OOM) handling.
* **JSON Policy Engine & Watchdog** for policy-driven workload quotas, wall-clock timeouts, and append-only JSONL audit logging.
* **Raw Syscall Hardening** with Linux capability dropping, `NO_NEW_PRIVS`, and hand-assembled Seccomp BPF filters (no `libcap` or `libseccomp` dependencies).
* **OCI Bundle Compliance** with a hand-rolled recursive-descent OCI `config.json` parser and runc-compatible state output.

---

## Features

### 1. Process & Namespace Isolation
- **PID Namespace (`--pid`)**: The workload runs as `PID 1` in an isolated process tree. Host processes are completely invisible and protected from signals.
- **UTS Namespace (`--hostname <name>`)**: Isolated system hostname without altering the host's identity.
- **Mount Namespace & Pivot Root (`--rootfs <path>`)**: Isolates the container filesystem using `pivot_root(2)`, unmounting the host root.
- **Network Namespace (`--net`)**: Dedicated network stack with a virtual ethernet (`veth`) pair, host NAT routing via `iptables`, and private container IP allocation.
- **User Namespace (`--user`)**: Rootless execution mapping unprivileged host user IDs to container `root` (UID 0).
- **IPC Namespace (`--ipc`)**: Independent System V IPC tables and POSIX message queues (`/dev/mqueue`).

### 2. Ephemeral Storage & Mounts
- **OverlayFS Copy-on-Write (`--overlay`)**: Keeps base images read-only; writes land in an ephemeral upper layer that is wiped on teardown.
- **Host Bind Mounts (`--volume host:container[:ro]`)**: Mounts host directories or files with two-step read-only remount protection (`MS_BIND | MS_REMOUNT | MS_RDONLY`).
- **File Descriptor Hygiene**: `close_inherited_fds()` prevents container escapes via leaked host file descriptors (defending against CVE-2024-21626 / CVE-2016-9962).

### 3. Resource Governance (cgroup v2)
- **Memory Ceiling (`--memory <limit>`)**: Enforces hard memory limits (e.g. `16M`, `512M`, `2G`). Automatically disables swap (`memory.swap.max=0`) so workloads cannot escape memory quotas.
- **CPU Quota (`--cpus <fraction>`)**: Sets CPU bandwidth limits via `cpu.max` (e.g. `0.5` = 50% of one core).
- **Process Cap (`--pids <max>`)**: Defends against fork bombs by limiting concurrent tasks via `pids.max`.
- **Race-Free Cgroup Attachment**: PIDs are added to cgroups *before* the child process is signaled to run, ensuring limits apply to the very first instruction.
- **Live Process Introspection**: Subcommands `inspect`, `stats`, `top`, and `netstat` driven by the vendored `libprocfs` static library.

### 4. Secure Workload Execution (Phases 1–3)
- **JSON Policy Engine (`--policy <file.json>`)**: Declarative policy files setting CPU, memory, PID quotas, timeouts, thresholds, and logging.
- **Precedence Hierarchy**: Strict priority ordering:
  $$\text{Built-in Defaults} < \text{OCI Bundle} < \text{Policy File} < \text{Explicit CLI Flags}$$
  Explicit flags always win, including explicit zeros (`--memory 0`, `--timeout 0`).
- **Policy Validation Subcommand**: `minicontainer policy validate <path>` checks policies without starting a container.
- **Wall-Clock Timeout Watchdog (`--timeout`, `--grace-period`)**: Parent-side supervisor thread monitors execution. Sends `SIGTERM` at deadline, waits grace period, and escalates to `SIGKILL` (using `cgroup.kill` so child processes cannot hide).
- **Append-Only JSONL Audit Trail (`--event-log <dir>`)**: High-integrity audit records (`container_start`, `container_exit`, `timeout_kill`, `oom_kill`, `resource_breach`) written using atomic single-write semantics (`O_APPEND` + process mutex).
- **Audit CLI**: `minicontainer logs <id>` pretty-prints one container's history; `minicontainer events` streams or summarizes recent events across containers.

### 5. Production Lifecycle & CLI Surface
- **Subcommand Architecture**: Full Docker-like CLI with `run`, `start`, `stop`, `exec`, `inspect`, `list`, `stats`, `top`, `netstat`, `cleanup`, `logs`, `events`, and `pull`.
- **Detached Containers (`start` / `-D`)**: Runs containers in background, stores state in `/run/minicontainer/<id>/state.json`, and records stdout/stderr to disk.
- **Interactive PTY (`--interactive` / `-i`)**: Dynamic allocation of container `devpts` pair, handed to host via UNIX domain socket `SCM_RIGHTS` for full terminal emulation (curses, vim, bash).
- **Namespace Joining (`exec <id> <cmd>`)**: Joins existing running containers using `setns(2)` without re-creating new namespaces.

### 6. Kernel Security Hardening & PID-1 Supervisor
- **Raw Capability Dropping**: Drops 24 of 38 Linux capabilities, retaining only a Docker-compliant 14-capability profile via raw `capset(2)` and `prctl(PR_CAPBSET_DROP)`.
- **`NO_NEW_PRIVS`**: Locks privileges before seccomp filter activation, preventing setuid binaries from escalating.
- **Raw Seccomp BPF Filter**: Hand-assembled 427-instruction BPF filter allow-listing 210 essential system calls with `EPERM` fallback (no `libseccomp` dependency).
- **In-Process `--init` Supervisor**: A lightweight, built-in tini-style init (PID 1) that forwards signals (`SIGTERM`, `SIGINT`, etc.), reaps orphaned zombie processes, and enables sub-second `stop` times.

### 7. OCI Bundle Support (Phase 8c)
- **OCI Bundle Execution (`--bundle <dir>`)**: Parses OCI Runtime Specification `config.json` via a hand-rolled recursive-descent JSON parser.
- **`pull <tag>` Subcommand**: Whitelist downloader for official root filesystems (`alpine`, `ubuntu`).
- **`oci-state.json`**: Writes a runc-compatible state file for integration with external container monitors.

---

## How to Run: Two Supported Methods

Because `minicontainer` relies directly on the Linux kernel (`clone(2)`, cgroup v2, `pivot_root`), it requires a Linux kernel to execute. You can run it either **natively on a Linux machine / VM** or **inside a Docker container on macOS / Windows**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Choose Your Environment                         │
├──────────────────────────────────┬─────────────────────────────────────┤
│   Method A: Native Linux / VM    │     Method B: Docker Container      │
│   (Ubuntu, Debian, RHEL, Arch)   │    (macOS, Windows, or Linux)       │
├──────────────────────────────────┼─────────────────────────────────────┤
│ • Direct bare-metal/KVM speed    │ • Zero VM setup on macOS            │
│ • Full cgroup v2 access          │ • Isolated development sandbox      │
│ • Recommended for complete tests │ • Requires --privileged flag        │
└──────────────────────────────────┴─────────────────────────────────────┘
```

---

### Method A: The Native Linux Way (Recommended)

Use this method if you are running directly on a Linux desktop, server, or cloud VM (e.g. Ubuntu 22.04 / 24.04).

#### 1. Prerequisites
Install build tools and utilities:
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y \
    build-essential gcc make git iproute2 procps bsdextrautils jq

# Fedora / RHEL
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git iproute procps-ng jq
```

#### 2. Clone and Build
Clone recursively so the vendored `third_party/libprocfs` submodule is initialized:
```bash
git clone --recursive https://github.com/PriyanshuLathi/minicontainer.git
cd minicontainer

# If cloned without --recursive:
git submodule update --init --recursive

# Build minicontainer
make
```

#### 3. Ubuntu 24.04+ One-Time AppArmor Setup (Rootless mode only)
Ubuntu 24.04 restricts unprivileged user namespaces by default. If running unprivileged (`--user`), load the AppArmor profile once:
```bash
sudo make install-apparmor
```

#### 4. Run the Live Showcase Demo
Run the automated 10-step interactive walkthrough:
```bash
./run_demo.sh
```
*(The script automatically re-executes with `sudo` if run as a regular user.)*

---

### Method B: Running Through Docker (Container in Container)

Use this method if you are on **macOS** or **Windows** and want to develop and run `minicontainer` without maintaining a separate Linux virtual machine.

#### 1. Prerequisites
* Start **Docker Desktop** (or Colima) on your machine.
* Verify Docker is responsive: `docker ps`.

#### 2. Build the Dev Container
A ready-to-use [Dockerfile](file:///Users/anshu/Developer/minicontainer/Dockerfile) is included in the repository root:
```bash
docker build -t minicontainer-dev .
```

#### 3. Start the Privileged Container
Because `minicontainer` creates nested containers, Docker must run with `--privileged` and host cgroup namespace enabled:

```bash
docker run --privileged --cgroupns=host \
    -v "$PWD":/workspace \
    -it minicontainer-dev bash
```

> [!NOTE]
> **For Apple Silicon (M1/M2/M3/M4) Users:**
> The default image runs in native `arm64` mode, where Phases 1–3 (Policies, Watchdog timeouts, Audit logs, Namespaces, Cgroups) work perfectly. If you want to test the raw x86_64 Seccomp filter in Section 9, add `--platform linux/amd64` to your `docker run` command.

#### 4. Build and Run Inside Docker
Inside the container shell:
```bash
# Compile minicontainer
make clean && make

# Run the live demo
./run_demo.sh

# Or run the full automated test suite
./run_phase123.sh
```

---

## Live Showcase Demo

To see all isolation, resource, and security layers in action, run:
```bash
./run_demo.sh
```

The demo executes a 10-step progressive scenario telling the story of containing an **untrusted student job**:

| Step | Section | What It Proves |
|:---:|---|---|
| **0** | **Environment Detection** | Validates kernel version, CPU count, and cgroup v2 mount. |
| **1** | **Legacy Run** | Baseline host process execution with zero namespaces. |
| **2** | **PID Isolation (`--pid`)** | Workload runs as `PID 1` (`ppid=0`), invisible to host process tree. |
| **3** | **UTS Isolation (`--hostname`)** | Changes container hostname while host hostname stays untouched. |
| **4** | **Private RootFS (`--rootfs`)** | Container is locked to its own filesystem; host files are invisible. |
| **4b**| **OverlayFS (`--overlay`)** | Ephemeral writes land in a temporary upper layer; base image remains pristine. |
| **5** | **Cgroup Limits & OOM Kill** | 16 MiB memory cap terminates memory-hog workload with `SIGKILL` (exit code `137`). |
| **6** | **Watchdog Wall-Clock Timeout** | Supervisor stops runaway infinite loop at `3.004s` with `SIGTERM` (exit code `143`). |
| **7** | **JSON Policy & Audit Log** | Validates policy file, enforces quotas, and generates append-only JSONL audit logs. |
| **8** | **Detached Container Lifecycle** | Tests `start`, `list`, `inspect`, `exec` namespace join, and `0.11s` clean `stop` via `--init`. |
| **9** | **Hardening (`--secure`)** | Drops capabilities, sets `NoNewPrivs: 1`, and activates `Seccomp: 2`. |
| **10**| **Clean Teardown** | Wipes all temporary state, cgroups, and mount points. |

For a complete walkthrough and manual command equivalents, see [docs/DEMO.md](docs/DEMO.md).

---

## Project Structure

```
minicontainer/
├── include/
│   ├── cli.h                 # CLI parser, subcommand dispatcher, argument structs
│   ├── core.h                # container_config_t, container_start(), container_wait()
│   ├── policy.h              # Phase 1: JSON policy parsing, validation, and defaults
│   ├── watchdog.h            # Phase 2: Watchdog thread, timeout enforcement, cgroup polling
│   ├── eventlog.h            # Phase 3: JSONL event logging constructors and append API
│   ├── state.h               # Container state files (/run/minicontainer/<id>/state.json)
│   ├── cgroup.h              # cgroup v2 memory, CPU, PID limit setup and swap control
│   ├── mount.h               # Rootfs setup, pivot_root(), bind mounts, devpts
│   ├── overlay.h             # OverlayFS upper/work directory lifecycle
│   ├── net.h                 # Network namespace veth pair, IP allocation, routing
│   ├── uts.h                 # UTS and User namespace UID/GID mappings
│   ├── pty.h                 # Pseudo-terminal allocation and SCM_RIGHTS descriptor handoff
│   ├── hardening.h           # Capability dropping, NO_NEW_PRIVS, Seccomp BPF filter
│   ├── init.h                # Phase 8b+: Built-in tini-style PID-1 supervisor
│   ├── inspector.h           # Process and cgroup inspector (libprocfs bridge)
│   ├── oci.h                 # Phase 8c: OCI config.json recursive-descent parser
│   ├── pull.h                # Phase 8c: Whitelisted rootfs downloader
│   ├── cleanup.h             # Stale resource garbage collection
│   └── env.h                 # Minimal container environment builder
├── src/
│   ├── main.c                # Subcommand dispatcher and implicit-run fallback
│   ├── cli.c                 # Command implementations (run, start, stop, exec, etc.)
│   ├── core.c                # Execution core (parent clone coordination, child setup)
│   ├── policy.c              # JSON policy loader and validation logic
│   ├── watchdog.c            # Background timeout and cgroup threshold monitor
│   ├── eventlog.c            # High-integrity append-only JSONL audit trail
│   ├── state.c               # Atomic state file operations (.tmp + rename)
│   ├── cgroup.c              # Write-side cgroup v2 controller interface
│   ├── mount.c               # Filesystem isolation, mount flags, and pivot_root
│   ├── overlay.c             # OverlayFS mount, upper/work directory management
│   ├── net.c                 # veth network pair provisioning and iptables NAT
│   ├── uts.c                 # Hostname isolation and user namespace mapping
│   ├── pty.c                 # Interactive PTY master/slave handling
│   ├── hardening.c           # Raw syscall capability drop & Seccomp BPF filter
│   ├── init.c                # PID-1 signal forwarder and zombie process reaper
│   ├── inspector.c           # Live introspection for inspect, stats, top, netstat
│   ├── oci.c                 # OCI config.json to container_config_t translator
│   ├── pull.c                # Rootfs image fetcher (alpine, ubuntu)
│   ├── cleanup.c             # Sweep stale cgroups, veths, and state directories
│   └── env.c                 # Sanitized container environment variables
├── tests/
│   ├── test_policy.c         # Phase 1: Policy parser, validation, and override tests
│   ├── test_watchdog.c       # Phase 2: Watchdog timeout, grace period, and cgroup tests
│   ├── test_eventlog.c       # Phase 3: JSONL formatting, concurrency, and persistence tests
│   ├── test_core.c           # Execution core regression tests
│   ├── test_state.c          # State serialization and atomicity tests
│   ├── test_cgroup.c         # cgroup v2 limits tests
│   ├── test_net.c            # Network namespace tests
│   ├── test_mount.c          # Filesystem isolation tests
│   ├── test_overlay.c        # OverlayFS copy-on-write tests
│   ├── test_uts.c            # UTS and user namespace tests
│   ├── test_init.c           # PID-1 signal forwarding and zombie reaping tests
│   ├── test_hardening.c      # Capability and Seccomp enforcement tests
│   ├── test_cli.c            # CLI parser unit tests
│   ├── test_oci.c            # OCI bundle translation tests
│   ├── test_pull.c           # Rootfs download verification tests
│   ├── fixtures/             # Test JSON policies and bundles
│   └── integration/          # Phase 1-3 integration shell test suites
├── scripts/
│   └── build_rootfs.sh       # Minimal rootfs builder from host binaries
├── docs/
│   ├── DEMO.md               # Live showcase walkthrough and troubleshooting
│   ├── event-logging.md      # Detailed Phase 3 event logging specification
│   └── decisions.md          # Complete architectural decision and bug log
├── third_party/
│   └── libprocfs/            # Standalone static library for /proc & cgroup v2 inspection
├── Dockerfile                # Multi-platform development and test container
├── Makefile                  # Build system with unified helper aggregation
├── run_demo.sh               # 10-step interactive live showcase
└── run_phase123.sh           # Automated Phase 1-3 test suite runner
```

---

## Architecture & Execution Pipeline

`minicontainer` executes containers through a strictly ordered, multi-stage synchronization pipeline:

```
[CLI / Policy]
      │
      ▼
container_start() ─── creates sync pipe & cgroups
      │
      ├──────────────────────────────┐
      │                              │
[Parent Process]               [Child Process] (clone)
      │                              │
1. Add Child PID to cgroup           │ (blocked reading sync pipe)
2. Start Watchdog thread             │
3. Write state.json                  │
4. Signal sync pipe unblock ─────────┼───► 1. Unshare / Join namespaces
      │                              │     2. Set up devpts & bind mounts
      ▼                              │     3. pivot_root() into RootFS
container_wait()                     │     4. Apply Seccomp & Cap Drop
      │                              │     5. execve(workload)
      │                              ▼
      │                     [Workload Process (PID 1)]
      │                              │
      ├──────────────────────────────┘
      │
5. Reap exit status (waitpid)
6. Watchdog stops & samples cgroup stats
7. Write JSONL audit exit event
8. container_cleanup() removes cgroups & mounts
```

### Precedence Model
Resource settings follow a deterministic precedence order:
$$\text{Built-in Defaults} \longrightarrow \text{OCI Bundle} \longrightarrow \text{Policy File} \longrightarrow \text{Explicit CLI Flags}$$

* Built-in defaults provide safe baselines (e.g. 10 s grace period).
* An OCI bundle supplies base container image settings.
* A JSON policy (`--policy`) layers organization-level limits.
* Explicit CLI flags (`--memory`, `--timeout`, `--cpus`) clobber all prior values. Explicit zeros (such as `--memory 0` or `--timeout 0`) explicitly clear quotas.

---

## CLI Reference & Examples

### Subcommands

| Subcommand | Description | Example |
|---|---|---|
| `run` | Run a container synchronously in the foreground | `minicontainer run --pid /bin/sh` |
| `start` | Start a detached background container | `minicontainer start -D --rootfs ./rootfs /bin/sh` |
| `stop` | Gracefully terminate a running container | `minicontainer stop <id>` |
| `exec` | Join namespaces of a running container | `minicontainer exec <id> /bin/sh` |
| `list` | List all active containers | `minicontainer list` |
| `inspect` | Live process, socket, and cgroup report | `minicontainer inspect <id>` |
| `stats` | One-shot resource utilization snapshot | `minicontainer stats <id>` |
| `top` | Display container process tree | `minicontainer top <id>` |
| `netstat` | Display container open network sockets | `minicontainer netstat <id>` |
| `cleanup` | Garbage collect stale state, cgroups, veths | `minicontainer cleanup` |
| `policy validate` | Verify a JSON policy document | `minicontainer policy validate policy.json` |
| `logs` | Pretty-print container audit events | `minicontainer logs <id>` |
| `events` | Query recent audit events across containers | `minicontainer events --limit 20` |
| `pull` | Download base rootfs (`alpine`, `ubuntu`) | `minicontainer pull alpine` |

---

### Command Examples

#### 1. Interactive Isolated Shell with Private Hostname
```bash
sudo ./minicontainer run --pid --hostname demo-box --rootfs ./rootfs --overlay -i /bin/sh
```

#### 2. Detached Background Container with Fast Init Shutdown
```bash
# Start background worker with --init supervisor
CID=$(sudo ./minicontainer start -D --init --rootfs ./rootfs /bin/sh -c 'sleep 300')
echo "Started container: $CID"

# Check status
sudo ./minicontainer list
sudo ./minicontainer inspect "$CID"

# Stop container (shuts down in ~0.10s thanks to --init signal forwarding)
sudo ./minicontainer stop "$CID"
```

#### 3. Enforcing Wall-Clock Timeout Watchdog
```bash
# Runs a job capped at 5 seconds with a 2-second grace period
sudo ./minicontainer run --timeout 5 --grace-period 2 /bin/sh -c 'while true; do sleep 1; done'
# Exits with status 143 (SIGTERM sent by watchdog)
```

#### 4. JSON Policy Enforcement & Audit Trail
Create a policy file (`student.json`):
```json
{
  "policy": {
    "name": "restricted-student",
    "version": "1.0"
  },
  "resources": {
    "memory": "64M",
    "pids": 30,
    "timeout": 10,
    "grace_period": 2
  },
  "logging": {
    "enabled": true,
    "log_dir": "/var/log/minicontainer/events"
  }
}
```

Validate and execute:
```bash
# Validate policy
./minicontainer policy validate student.json

# Run under policy
sudo ./minicontainer run --policy student.json /bin/sh -c 'sleep 20'

# Query the audit event stream
./minicontainer events --limit 5

# View full container audit history
./minicontainer logs <container_id>
```

---

## Testing & Verification

The test suite contains **15 unit test binaries** and **over 20 integration test scripts**.

```bash
# Build and run all unit tests
make test

# Run specific Phase 1–3 test suites
make test_policy       # JSON parser, schema validation, override rules
make test_watchdog     # Watchdog timeout, grace period, cgroup threshold
make test_eventlog     # JSONL formatting, concurrency, persistence

# Run the complete Linux integration test suite (requires root / sudo)
sudo ./run_phase123.sh

# Check for memory leaks
make valgrind
```

---

## Exit Code Conventions

| Exit Code | Reason |
|:---:|---|
| `0` | Success / Normal exit |
| `1` | Command-line syntax error, invalid policy, or runtime failure |
| `127` | Command binary not found in container rootfs (`execve` ENOENT) |
| `137` | Process killed by `SIGKILL` (e.g. cgroup OOM killer or watchdog grace escalation: `128 + 9`) |
| `143` | Process killed by `SIGTERM` (e.g. watchdog timeout reached: `128 + 15`) |

---

## Contributing & License

Contributions are welcome! Please ensure all unit tests pass (`make test`) and your changes maintain zero external runtime dependencies.

Released under the **MIT License**.
See [LICENSE](LICENSE) for details.
