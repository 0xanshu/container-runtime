# libprocfs

A small, **static** C library for reading Linux process and cgroup state from
`/proc` and the cgroup v2 hierarchy (`/sys/fs/cgroup`). No dependencies, no
shared object — just `libprocfs.a` and two headers.

## Provenance

libprocfs is **extracted from [`process-inspector`](https://github.com/Enginerd-2019/pinspect)**
(`pinspect`) — a standalone `/proc`-parsing CLI written first. The proc-reading
code was lifted out and rebuilt as a reusable static library so that other
projects can consume it. `process-inspector` remains a complete standalone
project; it links libprocfs only through an opt-in `make check-libprocfs`
target that proves the extraction is clean.

The cgroup v2 **read** side (`cgroups.h` / `cgroups.c`) is new code written for
this library — `process-inspector` did not have it.

## Consumers

- **[minicontainer](https://github.com/Enginerd-2019/minicontainer)** — an
  educational container runtime; vendors libprocfs as a git submodule and uses
  it for its `inspect` / `stats` / `top` / `netstat` subcommands.
- **process-inspector** — the donor project; links libprocfs via its opt-in
  reuse-demonstration target.

## API

Two headers:

- `procfs.h` — process status, file descriptors, threads, and `/proc/net`
  socket correlation: `read_proc_status`, `enumerate_fds`, `enumerate_threads`,
  `find_process_sockets`, plus helpers (`parse_pid`, `build_proc_path`, …).
- `cgroups.h` — cgroup v2 statistics: `read_cgroup_stats` (memory / cpu / pids,
  with the literal `"max"` mapped to `UINT64_MAX` / `-1`) and `get_pid_cgroup`
  (resolve a PID to its cgroup v2 directory).

```c
#include "procfs.h"
#include "cgroups.h"
```

## Build

```sh
make            # builds libprocfs.a
make test       # builds + runs the unit tests (under ASan/UBSan)
make clean
```

### Flag / sanitizer policy

The library compiles under `-Wall -Wextra -Werror -pedantic -std=c11` with no
command-line feature-test macros; sources that use POSIX.1-2008 interfaces
carry their own `#define _POSIX_C_SOURCE 200809L`. Address/UB sanitizers are
applied **only** to the test target — the shipped `libprocfs.a` is
sanitizer-free so it links cleanly into non-sanitized consumers.

## Requirements

Linux with cgroup v2 (the unified hierarchy). `get_pid_cgroup()` returns
`ENOENT` on cgroup v1-only systems.