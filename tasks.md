# Task List — Secure Workload Execution for minicontainer

**Source documents:** `design.md`, `requirements.md` (also mirrored under `.kiro/specs/secure-workload-execution/`)
**Target:** Policy, wall-clock timeout/watchdog, and JSONL event logging on top of the existing Phase 8c runtime. The existing Phase 8b seccomp profile is used as-is; policy-extended syscalls and multi-user support are out of scope.
**Status key:** `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked · `[-]` intentionally deferred

---

## 0. Scope, Decisions, and Environment

### 0.1 Scope

Required for the feature:

- **Phase 1 — Policy file loading, validation, defaults, and application** (requirements 1.1–1.7)
- **Phase 2 — Wall-clock timeout, graceful shutdown, watchdog thread** (requirements 2.1–2.4)
- **Phase 3 — JSONL event logging, event types, log query commands** (requirements 3.1–3.5)
- **CLI integration** (requirements 6.1–6.3)
- **Non-functional requirements** NFR1–NFR4
- Existing test-suite regression preservation

**Out of scope for this delivery (dropped):**

- **Policy-extended seccomp** (`blocked_syscalls`, `seccomp_profile`, `log_seccomp_denials`): the existing Phase 8b seccomp profile remains; policy may only enable/disable hardening. These keys are treated as unknown: warn and ignore, never silently claim enforcement.
- **Multi-user support** (requirements 7.1–7.3), delegated cgroups, and the supervisor daemon. Only the root-privilege limitation is documented.
- TOML support — JSON is the required and only policy format.
- Detached `start` timeout/exit monitoring — foreground `run` is the supported path; document the limitation.
- Policy filesystem/network enforcement (`readonly_paths`, `masked_paths`, `allowed_ports`, `allow_outbound`, `denied_hosts`) — unsupported keys warn and are ignored; no enforcement.

### 0.2 Decisions to confirm before/while implementing

These are the places where the design and requirements need a concrete resolution. The recommended choice is listed first.

| ID | Decision | Recommended resolution |
|----|----------|------------------------|
| D1 | Policy format order | **Confirmed: JSON only for this delivery.** Keep `policy_load()` format-agnostic so TOML can be added later without changing callers. |
| D2 | Precedence | `built-in defaults < OCI bundle < policy file < explicit CLI flags`. Explicit flags must be tracked by presence, not just non-zero value, so `--timeout 0`, `--memory 0`, etc. can disable a policy value. |
| D3 | Default policy vs backward compatibility | **Confirmed: policy-mode gating.** Legacy invocation (`no --policy`, no new flags) behaves exactly as today. `--policy` activates policy mode and applies defaults + file values. A standalone `--timeout`/`--event-log` applies only that feature and must not silently enable unrelated cgroup limits or hardening. |
| D4 | Default hardening | Keep `policy_get_default().enable_hardening = true` per requirements 1.7, but only apply it in policy mode **and** when a rootfs is present. Without a rootfs, auto-disable with a debug warning. Do not change legacy `--rootfs` runs unless `--policy` or `--secure` was passed. |
| D5 | Watchdog ownership | Heap-allocate `watchdog_context_t`; store the pointer in `container_result_t`/`container_context_t`. Start in `container_start()` after clone + cgroup membership; stop in `container_wait()`; free in `container_cleanup()`. Never put a stack pointer into the returned result. |
| D6 | Detached containers | **Confirmed: foreground-only.** Foreground `run` gets the watchdog. Detached `start` logs `container_start` only and warns that timeout/exit monitoring is foreground-only. Do not silently claim detached timeout support. |
| D7 | Kill scope | SIGTERM the direct child (works with `--init` forwarding). For SIGKILL, use `cgroup.kill` when a cgroup exists and the kernel supports it, to catch descendants; otherwise `kill(child_pid, SIGKILL)`. |
| D8 | Event-log failures | Non-fatal (NFR2): warn to stderr and disable event logging for that run, then continue. |
| D9 | Exit reason precedence | `timeout > oom > signal > normal` when filling `container_exit`. |

### 0.3 Environment prerequisites

- **Linux host required.** The current workspace is macOS/darwin; `clone(2)`, cgroup v2, seccomp, and `/proc` code cannot be built or tested here.
- Linux kernel 4.5+ for cgroup v2; `cgroup.kill` needs 5.14+ (fallback required).
- Root/sudo for cgroup, mount, PID/userns integration tests; the unit-test subset should stay unprivileged where possible.
- `iproute2` for network tests; `strace` for diagnosing syscall failures.
- A rootfs for integration tests (`scripts/build_rootfs.sh` / existing `./rootfs`). Real-workload tests need Python/GCC/Node/Java inside the rootfs; skip with a clear message if absent.
- `pthread` support. Add `-pthread` to compile/link flags for correctness even where glibc folds it into libc.

### 0.4 Baseline tasks

- [ ] **T0.1 — Establish a Linux build/test environment.** Use a Linux VM, container, or CI runner with cgroup v2 mounted. Record `uname -a`, kernel version, `stat -fc %T /sys/fs/cgroup`, and whether the shell is root. Confirm `/sys/fs/cgroup/cgroup.controllers` exists.
- [ ] **T0.2 — Baseline the existing code.** On Linux run `make clean all`, then the existing `make test` suite (or the relevant root/unprivileged subsets). Record any pre-existing failures so they are not blamed on this feature.
- [ ] **T0.3 — Confirm the public surfaces to extend.** Re-read `include/core.h`, `src/core.c`, `src/cli.c`, `src/hardening.c`, `src/cgroup.c`, `src/state.c`, `include/inspector.h`, and `Makefile`. Confirm no in-flight user changes will be overwritten.
- [x] **T0.4 — Confirm the open decisions D1–D9** with the project owner. Confirmed: JSON-only (D1), policy-mode gating (D3), foreground-only detached monitoring (D6). Confirmed dropped: policy-extended seccomp, multi-user support, and TOML.

---

## 1. Phase 1 — Policy File + Basic Resource Limits

**Goal:** `--policy ./policy.json` loads, validates, defaults, and applies memory/CPU/PID/timeout/security/logging settings; CLI flags override policy; invalid files produce clear errors; legacy runs are unchanged.

### 1.1 Shared types and configuration plumbing

- [ ] **P1.1 — Add policy-derived runtime fields to `container_config_t`.** In `include/core.h`, add only the fields the runtime needs (avoid a `core.h -> policy.h` include cycle):
  - `uint32_t timeout_seconds;`
  - `uint32_t grace_period_seconds;`
  - `double memory_warning_threshold;`
  - `double cpu_warning_threshold;`
  - `uint32_t cpu_warning_duration_ms;`
  - `uint32_t watchdog_poll_interval_ms;`
  - `bool event_log_enabled;`
  - `char event_log_dir[PATH_MAX];`
  - `char policy_name[64];`
  - `bool policy_mode;` (true only when `--policy` was supplied)
- [ ] **P1.2 — Preserve zero-initialization guarantees.** Every new field must be safe when `container_config_t cfg = {0}` is used by existing tests and callers. No new unconditional cgroup/hardening activation.
- [ ] **P1.3 — Decide where shared parsing helpers live.** Move/duplicate the human-readable memory parser (`"512M"`, `"1G"`, bytes) into a reusable function (e.g. `policy_parse_memory_string()` in `policy.h` or a tiny `units.c`) and use it from both `cli.c` and `policy.c` so CLI and policy accept the same syntax.

### 1.2 Policy module API and data model

- [ ] **P1.4 — Create `include/policy.h`** with:
  - `policy_t` using fixed-size fields (no heap ownership) to keep `policy_free()` simple: metadata, resource limits, thresholds, hardening enable flag, logging, `is_valid`, `validation_error[256]`, warning list/count.
  - Declarations: `policy_load`, `policy_validate`, `policy_apply`, `policy_get_default`, `policy_free`, and `policy_print_warnings`.
- [ ] **P1.5 — Create `src/policy.c`** with the public API, default values, validation, application mapping, and warning handling.
- [ ] **P1.6 — Ensure `policy.h` may include `core.h` but `core.h` must not include `policy.h`.** Keep `container_config_t` as the only shared ABI boundary.

### 1.3 JSON policy parser (required path)

- [ ] **P1.7 — Implement a dedicated policy JSON parser** (new `src/policy_json.c` or static helpers in `policy.c`). Do not destabilize the existing OCI parser; a standalone recursive-descent parser is acceptable and lower risk.
  - Supports objects, arrays, strings (with escapes), integers, doubles, booleans, and `null`.
  - Tracks line/column for parse errors.
  - Accepts sections `policy`, `resources`, `resources.thresholds`, `security`, and `logging` as nested JSON objects.
  - Accepts `memory` as a string (`"512M"`) or number (bytes); `cpu` as integer or double; `pids`/`timeout`/`grace_period` as integers.
  - Unknown sections/fields (including the dropped `blocked_syscalls`, `seccomp_profile`, `log_seccomp_denials`, filesystem/network keys) are skipped recursively and recorded as warnings (requirements 1.3: unknown fields warn, do not fail).
  - Reports parse failure as `"Parse error at line N: ..."` and sets `is_valid=false`.
- [ ] **P1.8 — Implement file discovery and format detection in `policy_load()`.**
  - `stat`/`access` first: exact errors `"Policy file not found: <path>"` and `"Cannot read policy file: <path>"`.
  - Extension `.json` → JSON parser; `.toml` → clear `"TOML policy support is not available; use JSON"` error.
  - No extension: try JSON; report the JSON parse error if it fails.
  - Call `policy_validate()` before returning success.
- [ ] **P1.9 — Implement `policy_get_default()` exactly as requirements 1.7:** memory 0, cpu 1.0, pids 100, timeout 0, grace 10, hardening true, logging enabled at `/var/log/minicontainer/events`. Document that these defaults are applied in **policy mode** per D3, not to legacy invocations.
- [ ] **P1.10 — Implement `policy_free()`** to zero/clear fields and reset validity. Fixed fields mean no heap free, but keep the function for future-proofing.

### 1.4 Validation

- [ ] **P1.11 — Implement `policy_validate()` with the exact required messages:**
  - Memory `< 1MB` and non-zero → `"memory_limit must be at least 1MB or 0 for unlimited"`.
  - CPU `< 0.0` or `> get_nprocs()` → `"cpu_limit must be between 0.0 and <N>"`.
  - PIDs `< 0` → `"pids_limit must be non-negative"`.
  - Grace period / timeout / thresholds out of range (`0.0–1.0` thresholds, non-negative durations, poll interval sane bounds).
- [ ] **P1.12 — Ensure validation is side-effect-free and repeatable** (`policy_validate` can be called manually by `policy validate`).
- [ ] **P1.13 — Implement warning handling:** warnings must not set `is_valid=false`; they should be printable by the CLI in both load and `policy validate` paths.

### 1.5 Application and precedence

- [ ] **P1.14 — Implement `policy_apply(const policy_t *, container_config_t *)`.**
  - Memory → `cgroup_limits.memory_limit`; CPU fraction → `cpu_quota = (long)(cpu * 100000)`, `cpu_period = 100000`; PIDs → `pid_limit`.
  - Set `enable_cgroup=true` only if at least one of memory/cpu/pids is non-zero.
  - Timeout/grace → new config fields.
  - Hardening → `enable_hardening` only if a rootfs is present (D4). The base Phase 8b seccomp profile is used unchanged.
  - Logging → `event_log_enabled`, `event_log_dir`.
  - Thresholds/poll interval → config fields.
  - Policy name → `policy_name`.
- [ ] **P1.15 — Implement explicit CLI override tracking.** In `parse_run_flags`, keep booleans like `timeout_set`, `grace_set`, `memory_set`, `cpu_set`, `pids_set`, `event_log_set`, `no_event_log_set`, `policy_set`, and apply CLI values after policy values. This fixes the existing “non-zero means set” limitation and satisfies requirements 6.3.
- [ ] **P1.16 — Define and test precedence:** defaults < bundle < policy < explicit CLI (D2). Add a debug print or test helper showing the effective values.
- [ ] **P1.17 — Add a compatibility guard:** if policy mode is off, `policy_apply` is never called. If policy mode is on but no rootfs is present, disable hardening with a debug warning.

### 1.6 CLI integration

- [ ] **P1.18 — Add `--policy <path>` to `parse_run_flags`.** Pre-scan it before the getopt loop (same pattern as `--bundle`) so policy values are loaded before flag overrides regardless of argument order.
- [ ] **P1.19 — Merge policy with bundle and CLI correctly.** Translate `--bundle` first, then apply policy, then explicit CLI overrides. Ensure `--bundle` + `--policy` is allowed and documented; do not let policy wipe bundle rootfs/namespace fields it does not own.
- [ ] **P1.20 — Add `policy validate <path>` subcommand.**
  - `include/cli.h`: `SUBCMD_POLICY`, `int cmd_policy(int argc, char *argv[]);`
  - `src/main.c`: dispatch.
  - `src/cli.c`: parse nested `validate`, call `policy_load`, print valid/invalid + warnings, exit 0/1.
- [ ] **P1.21 — Update `cli_usage()`** with `--policy` and `policy validate`.
- [ ] **P1.22 — Add policy metadata to state (recommended).** Extend `container_state_t` with `policy_name` and `event_log_dir` so later `logs`/`inspect` can find custom log locations. Keep old state.json files readable (missing fields default empty).

### 1.7 Tests, fixtures, build

- [ ] **P1.23 — Add fixtures under `tests/fixtures/policies/`:**
  - `valid.json` (memory `"512M"`, cpu `0.5`, pids `50`, timeout `300`, grace `10`, thresholds, hardening, logging)
  - `minimal.json` (only `name`, `memory`, `pids`, `timeout`)
  - `invalid_syntax.json`
  - `invalid_values.json` (memory `<1MB`, cpu out of range, negative pids)
  - `unknown_fields.json` (includes dropped seccomp/filesystem/network keys to prove they warn and are ignored)
  - `timeout_5s.json`, `memory_100M.json`, `pids_10.json`, `pids_20.json`, `with_logging.json`, `student.json`
  - `default_legacy.json` / a test that asserts legacy mode does not enable cgroups.
- [ ] **P1.24 — Add `tests/test_policy.c`** covering:
  - Valid load, all sections, string vs numeric memory, integer vs double CPU.
  - Invalid syntax with line information.
  - Not-found/unreadable exact errors.
  - Each validation error and exact message.
  - Unknown field warning (including dropped keys); no hard failure.
  - `policy_get_default` values.
  - `policy_apply` mapping for memory/cpu/pids/timeout/grace/hardening/logging.
  - Policy-mode vs legacy behavior (no cgroup/hardening auto-enable).
  - CLI-equivalent precedence tests via a small helper or integration test.
  - `policy_free` on zeroed/partial structs.
- [ ] **P1.25 — Add Makefile entries:** build `policy.o` and `policy_json.o` into `HELPER_OBJS`; add `test_policy` target and `make test` invocation; add `-pthread` (can be done now or in Phase 2).
- [ ] **P1.26 — Add a CLI/integration smoke test:** `./minicontainer policy validate tests/fixtures/policies/valid.json` exits 0; invalid exits 1 with the required message.
- [ ] **P1.27 — Regression check:** run existing `make test`; confirm legacy `./minicontainer /bin/echo hi` and `./minicontainer --rootfs ./rootfs /bin/echo hi` behave exactly as before (no new cgroup/hardening/log side effects).

**Phase 1 acceptance criteria**

- `minicontainer run --policy ./policy.json /bin/sh` loads and applies memory/CPU/PID/timeout values.
- Invalid policy files produce the required clear errors; unknown fields warn without failing.
- `policy validate` works without root.
- CLI flags override policy, including zero values used to disable limits.
- Legacy invocations have no new cgroup/hardening/log side effects.
- Existing tests continue to pass.

---

## 2. Phase 2 — Wall-Clock Timeout + Watchdog

**Goal:** Enforce a wall-clock timeout in a background thread, with SIGTERM → grace period → SIGKILL, clean thread shutdown, and no zombie threads/processes.

### 2.1 Watchdog API and context

- [ ] **P2.1 — Create `include/watchdog.h`** with `watchdog_context_t` and:
  - `int watchdog_start(watchdog_context_t *ctx);`
  - `void watchdog_stop(watchdog_context_t *ctx);`
  - `bool watchdog_was_timeout_killed(const watchdog_context_t *ctx);`
  - `void watchdog_get_stats(...)` for memory peak/CPU time if useful.
  - `WATCHDOG_POLL_INTERVAL_MS` default 100; allow policy override within sane bounds.
- [ ] **P2.2 — Context fields:** child PID, cgroup path, container ID, timeout, grace, thresholds, logging flags, event log dir, thread, `running`, mutex, cond, start/last-CPU timestamps, CPU high duration, last CPU total ns, timeout/grace/OOM flags, error code/message.
- [ ] **P2.3 — Use `pthread_cond_timedwait` with `CLOCK_MONOTONIC`** for the poll sleep and grace wait so `watchdog_stop()` can interrupt promptly. Do not use a blocking `sleep()` that ignores stop requests.
- [ ] **P2.4 — Use `_Atomic bool` or mutex-protected access for `running`**; avoid undefined behavior from concurrent plain `bool` reads/writes. Keep the style consistent with the codebase but correct.

### 2.2 Timeout and graceful shutdown

- [ ] **P2.5 — Record `start_time` immediately after `clone()` succeeds** in `container_start()` (`CLOCK_MONOTONIC`). Pass it into the watchdog context so elapsed time includes post-clone setup, matching requirement 2.1.
- [ ] **P2.6 — Implement timeout check:** if `timeout_seconds > 0` and elapsed >= timeout, set `timeout_killed`, log the timeout event (Phase 3 integration point), send SIGTERM.
- [ ] **P2.7 — Implement grace period:** wait `grace_period_seconds` interruptibly. If the child exits during the grace period, stop without SIGKILL and record that grace was used/clean. If still alive, send SIGKILL and record `grace_period_used=true`.
- [ ] **P2.8 — Avoid duplicate timeout events:** decide whether to log one event with the final signal/grace state or two events (SIGTERM then SIGKILL). Recommended: log one `timeout_kill` event when the sequence completes, plus optionally a debug trace. Do not emit contradictory duplicate events.
- [ ] **P2.9 — Handle ESRCH:** if `kill(pid, 0)`/`kill(pid, sig)` reports the process is gone, mark the timeout as race-resolved, stop cleanly, and do not send SIGKILL.
- [ ] **P2.10 — Implement kill scope (D7):** helper `watchdog_kill_container(ctx, sig)`:
  - SIGTERM: `kill(child_pid, SIGTERM)`; with `--init`, the supervisor forwards it.
  - SIGKILL: try writing `1` to `<cgroup_path>/cgroup.kill` if available; fall back to `kill(child_pid, SIGKILL)`.
  - If no cgroup and no PID namespace, document that descendants may survive; `--init` is the recommended mitigation.

### 2.3 Cgroup monitoring and thresholds

- [ ] **P2.11 — Implement cgroup stat polling** using existing `read_cgroup_stats()` from libprocfs:
  - `memory.current`, `memory.max`, `memory.peak`
  - `cpu.stat` (`usage_usec`)
  - `pids.current`, `pids.max`
  - Skip polling when `cgroup_path` is empty or unreadable; never fail the container because monitoring failed.
- [ ] **P2.12 — Implement CPU percentage calculation:** `delta_cpu_usec / delta_wall_usec`, where delta is between polls; clamp/report sensibly. Reset the baseline if counters go backwards.
- [ ] **P2.13 — Implement memory threshold detection:** if `memory.max != UINT64_MAX` and `current/max >= threshold`, log a `resource_breach` event.
- [ ] **P2.14 — Implement CPU sustained threshold:** increment `cpu_high_duration_ms` while above threshold; reset when below; log once when it reaches `cpu_warning_duration_ms`. Add a cooldown so it does not spam every 100 ms.
- [ ] **P2.15 — Optional PIDs threshold:** if a `pids_warning` threshold is added later, reuse the same breach/cooldown logic. Not required by the current schema.
- [ ] **P2.16 — Implement OOM detection:** read `memory.events` `oom_kill` counter (add a small helper in `cgroup.c`/`watchdog.c` because libprocfs does not expose it). Set `oom_detected`; `container_wait()` logs the `oom_kill` event after exit (Phase 3). Read before `remove_cgroup()` destroys the files.
- [ ] **P2.17 — Make threshold logic unit-testable:** either expose a `watchdog_poll_once()`/pure helper in the header or factor calculations into static-callable test hooks. Tests should be able to create a fake cgroup directory under a temp path with `memory.current`, `memory.max`, `cpu.stat`, `pids.current`, `pids.max`, `memory.events`.

### 2.4 Core integration

- [ ] **P2.18 — Heap-allocate the watchdog context in `container_start()`** after clone, user-ns mapping, network setup, cgroup add, and sync-write. Start the thread only on the success path; on failure, free the context.
- [ ] **P2.19 — Store the watchdog pointer in `container_result_t`/`container_context_t`.** Add `watchdog_context_t *watchdog;` (forward-declare the type in `core.h` to avoid a header cycle). Initialize to `NULL` via `{0}`.
- [ ] **P2.20 — Do not start a watchdog for `config->detach`.** `cmd_start` returns and the parent exits, so a thread cannot survive. If a timeout is configured for detached mode, print a clear warning that timeout enforcement is foreground-only. Confirmed scope: no monitor process in this delivery.
- [ ] **P2.21 — Stop the watchdog in `container_wait()` before reading final cgroup stats and before cgroup removal.** Ensure all paths (waitpid success, waitpid failure, signal) call `watchdog_stop()`.
- [ ] **P2.22 — Free the watchdog in `container_cleanup()`** after defensively stopping it if still running. Make it idempotent and safe on a zeroed result.
- [ ] **P2.23 — Preserve `container_exec()` semantics:** start + wait; the wrapper must still stop the watchdog and cleanup must free it. Existing tests that call `container_cleanup()` should not leak.
- [ ] **P2.24 — Do not start the watchdog before clone**; the child would inherit pthread state. Start it only in the parent after clone. This also keeps the child's post-fork path free of pthread locks.

### 2.5 CLI integration

- [ ] **P2.25 — Add `--timeout <seconds>` and `--grace-period <seconds>` flags** to `parse_run_flags`, with explicit presence tracking (`timeout_set`, `grace_set`) so `--timeout 0` disables a policy timeout and `--grace-period 0` is honored.
- [ ] **P2.26 — Validate CLI values:** non-negative, fit in `uint32_t`, reasonable bounds (e.g. grace <= 3600) with clear errors.
- [ ] **P2.27 — Update `cli_usage()`** with the new flags and the confirmed foreground-only limitation note for detached mode.
- [ ] **P2.28 — Ensure `--timeout` does not require a cgroup.** Timeout-only runs must work unprivileged (the watchdog uses the PID; resource thresholds are skipped without a cgroup).

### 2.6 Tests and build

- [ ] **P2.29 — Add `tests/test_watchdog.c`:**
  - Timeout kills a `sleep` child and sets `timeout_killed`.
  - Grace period: child traps SIGTERM and exits cleanly; no SIGKILL needed.
  - Child ignores SIGTERM; SIGKILL after grace; `grace_period_used=true`.
  - No timeout (`0`) leaves a short-lived child unaffected.
  - `watchdog_stop()` before timeout joins cleanly and leaves no thread.
  - `watchdog_start()` failure path (e.g. invalid context) sets error and does not crash.
  - Threshold logic with a fake cgroup directory: memory breach, CPU sustained breach, below-threshold no event, cooldown, OOM counter.
  - No zombie threads/processes after each case (`pthread_join`, `waitpid`).
- [ ] **P2.30 — Add integration tests under `tests/integration/`:**
  - `test_timeout.sh`: `--timeout 5` kills an infinite loop in ~5s; a quick `echo` completes before timeout.
  - `test_timeout_grace.sh`: SIGTERM-trap case; SIGKILL fallback case.
  - `test_timeout_detached.sh`: verify the documented behavior/warning for `start` (not silent failure).
- [ ] **P2.31 — Add a stress/regression test:** run 20 short timed containers in a loop; verify no zombie processes (`ps`), no leaked threads, and stable exit codes.
- [ ] **P2.32 — Update Makefile:** add `watchdog.o` to `HELPER_OBJS`, `test_watchdog` target, `-pthread` in `CFLAGS`/`LDFLAGS`, and `make test` invocation. Keep `make test` usable without root for the unit subset.
- [ ] **P2.33 — Verify no deadlock with `--init`:** timeout + `--init` should forward SIGTERM through the init supervisor and escalate to SIGKILL correctly.

**Phase 2 acceptance criteria**

- `--timeout 60` kills a long-running container; SIGTERM first, SIGKILL after grace.
- A container that exits before the timeout is unaffected.
- Watchdog starts/stops cleanly; no zombie threads/processes.
- Timeout works without cgroups; resource monitoring degrades gracefully without cgroups.
- Detached-mode behavior is explicit and documented.
- Existing tests pass.

---

## 3. Phase 3 — Event Logging

**Goal:** Append-only JSONL audit logs with `container_start`, `container_exit`, `timeout_kill`, `oom_kill`, and `resource_breach`; query via `logs`/`events`.

### 3.1 Event model and formatting

- [ ] **P3.1 — Create `include/eventlog.h` / `src/eventlog.c`.**
  - `event_type_t` for the five event types.
  - `event_t` with type, `struct timespec timestamp`, container ID, details JSON, and a preformatted line buffer.
  - Increase buffers from the design’s 512/1024 to safe values (e.g. `EVENT_DETAILS_MAX 2048`, `EVENT_LINE_MAX 4096` or 8192) and truncate safely with a warning.
- [ ] **P3.2 — Implement ISO-8601 UTC timestamps with milliseconds** (`YYYY-MM-DDTHH:MM:SS.mmmZ`) using `CLOCK_REALTIME` + `gmtime_r` + `snprintf`.
- [ ] **P3.3 — Implement `event_format_json()`** producing exactly one line:
  `{"timestamp":"...","container_id":"...","event_type":"...","details":{...}}\n`
- [ ] **P3.4 — Implement JSON string escaping** for program paths, argv, policy names, error messages, and any user-controlled text: quotes, backslashes, control chars, and non-printable bytes. Add unit tests for `"`, `\`, newline, tab, and UTF-8 pass-through.
- [ ] **P3.5 — Implement `event_type_to_string()`** with the exact names: `container_start`, `container_exit`, `resource_breach`, `timeout_kill`, `oom_kill`.
- [ ] **P3.6 — Implement convenience constructors** for each required event type, populating the exact details fields from the schema:
  - `container_start`: program, argv, policy, user_id, resource_limits.
  - `container_exit`: exit_code, exit_reason, wall_clock_seconds, cpu_time_seconds, memory_peak_bytes.
  - `resource_breach`: resource, current_value, limit_value, threshold, percentage.
  - `timeout_kill`: timeout_seconds, elapsed_seconds, signal, grace_period_used.
  - `oom_kill`: memory_limit_bytes, memory_peak_bytes, exit_code.

### 3.2 Persistence

- [ ] **P3.7 — Implement `eventlog_init(log_dir, container_id)`:** create the directory with `mkdir_p(log_dir, 0755)`; create `<log_dir>/<id>.jsonl` with `O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC`, mode `0644`; verify write access. Return -1 with a clear error on failure.
- [ ] **P3.8 — Implement `eventlog_append(log_dir, container_id, event)`:** open with `O_APPEND`, perform a **single** `write()` of the full line (atomic append for regular files), handle `EINTR`, treat short writes as failure, close. Do not use buffered stdio across threads.
- [ ] **P3.9 — Make concurrent writes safe:** watchdog thread and parent thread may append simultaneously. O_APPEND + single write is the primary guarantee; add a process-local mutex if testing shows interleaving on the target filesystem.
- [ ] **P3.10 — Do not `fsync()` per event** (performance NFR); document the durability trade-off. Optionally `fsync` on exit if configured.
- [ ] **P3.11 — Enforce file permissions:** ensure `0644` even with a restrictive umask (`fchmod` after open if necessary). Log directory `0755`.
- [ ] **P3.12 — Implement graceful degradation:** if init/append fails, warn once (stderr), disable logging for the run, and continue. Do not abort the container (NFR2).

### 3.3 Runtime integration

- [ ] **P3.13 — Add event-log metadata to `container_result_t`/`container_context_t`:** container ID, log dir, enabled flag, policy name, start time (monotonic), watchdog pointer, and final cgroup stats needed by `container_exit`.
- [ ] **P3.14 — Log `container_start`** in `container_start()` after clone succeeds (and cgroup membership is established if used). Include effective resource limits and policy name. Do not log before clone, to avoid events for containers that never launched.
- [ ] **P3.15 — Log `container_exit`** in `container_wait()` after `waitpid()` and after reading final cgroup stats (`memory.peak`, `cpu.stat`) but before `container_cleanup()` removes the cgroup.
  - Exit reason precedence: timeout > oom > signal > normal (D9).
  - Include `wall_clock_seconds`, `cpu_time_seconds`, `memory_peak_bytes`, `exit_code`.
  - For signal deaths, `exit_code = 128 + signal`.
- [ ] **P3.16 — Log `oom_kill`** when the cgroup `memory.events` `oom_kill` counter is > 0 or the watchdog marked `oom_detected`; include memory limit/peak and exit code. Log before cgroup removal.
- [ ] **P3.17 — Log `timeout_kill`** from the watchdog when the timeout sequence completes. Include the final signal and whether the grace period was used.
- [ ] **P3.18 — Log `resource_breach`** from the watchdog using the Phase 2 threshold logic and cooldown.
- [ ] **P3.19 — Detached `start` limitation:** log `container_start` only; document that `container_exit`/`timeout_kill` are foreground-only. Optionally log a `container_exit` event from `cmd_stop` when it stops a container.

### 3.4 CLI: `logs` and `events`

- [ ] **P3.20 — Add `SUBCMD_LOGS` / `cmd_logs`.** `minicontainer logs <id>`:
  - Resolve the log directory from state (`event_log_dir`) or the default; allow `--event-log <dir>` override.
  - If the file is missing: `"No event log for container <id>"`, exit 1.
  - Pretty-print each JSONL object in a human-readable indented form (minimal JSON pretty-printer that respects strings/escapes) or a formatted table; preserve raw-line fallback if parsing fails.
- [ ] **P3.21 — Add `SUBCMD_EVENTS` / `cmd_events`.** `minicontainer events [--user <uid>] [--limit N]`:
  - Scan `<log_dir>/*.jsonl`, read events, extract timestamp/container_id/event_type, optionally filter by `user_id` from `container_start`.
  - Sort newest first; default limit (e.g. 50); print a compact summary.
  - Handle unreadable/rotated files gracefully.
- [ ] **P3.22 — Update `main.c` dispatch, `parse_subcommand`, `cli.h`, and `cli_usage()`.**
- [ ] **P3.23 — Update `tests/test_cli.c`** for the new subcommands.

### 3.5 Tests

- [ ] **P3.24 — Add `tests/test_eventlog.c`:**
  - Formatting: valid single-line JSON, trailing newline, exact event type names.
  - Escaping: quotes/backslashes/newlines/tabs/UTF-8.
  - Timestamp format and UTC/millisecond precision.
  - Init creates dir/file with expected modes idempotently.
  - Append creates a second line, not overwrite.
  - Concurrent appends from two threads produce complete, non-interleaved lines.
  - Missing/unwritable directory returns -1 and does not crash.
  - Buffer truncation is safe and does not produce invalid JSON.
  - Constructor details fields match the schema.
- [ ] **P3.25 — Add integration tests under `tests/integration/`:**
  - `test_event_logging.sh`: run with a policy, assert `<id>.jsonl` exists, `container_start` and `container_exit` present, exit code correct.
  - `test_timeout_event.sh`: assert `timeout_kill` with timeout/elapsed/signal fields.
  - `test_oom_event.sh`: memory bomb, assert `oom_kill` and exit code 137 when available.
  - `test_resource_breach.sh`: run a memory/CPU workload above threshold, assert `resource_breach` (may be flaky; use generous thresholds).
  - `test_logs_command.sh`: `logs <id>` prints the events; `events` lists them newest first; `--user` filter works.
  - `test_event_log_failure.sh`: unwritable dir warns and container still runs.
- [ ] **P3.26 — Add Makefile entries:** `eventlog.o` in `HELPER_OBJS`, `test_eventlog` target, `make test` invocation.

### 3.6 Retention / rotation

- [ ] **P3.27 — Define the rotation strategy.** Per-container `<id>.jsonl` is the primary rotation boundary. Optionally add size-based rotation (`<id>.jsonl.1`) with a configurable max size, or an `events --prune`/`cleanup --logs` command. Do not silently grow unbounded logs.
- [ ] **P3.28 — Document retention and permissions** in README/docs (`/var/log/minicontainer/events`, 0755 dir, 0644 files, root-owned).

**Phase 3 acceptance criteria**

- Events are written to `<log_dir>/<id>.jsonl`, one valid JSON object per line.
- Required event types are logged with the specified details.
- `minicontainer logs <id>` and `events [--user]` work.
- Event log failures do not abort the container.
- No measurable performance problem for short-lived containers.

---

## 4. Cross-Cutting Verification

### 4.1 Integration test suite

- [ ] **X1.1 — Add `tests/integration/` scripts:**
  - Timeout enforcement and grace period.
  - Memory/PID/cgroup enforcement with policies.
  - Event logging and query commands.
  - CLI precedence (policy vs flags, zero-value overrides).
  - Legacy regression (`run` without policy behaves as before).
- [ ] **X1.2 — Add a test runner** that checks for root, cgroup v2, rootfs, and required binaries; prints SKIP with a reason instead of failing spuriously.
- [ ] **X1.3 — Add `make test-integration` and `make test-security` targets** separate from the fast unit suite.

### 4.2 Security tests

- [ ] **X2.1 — Add `tests/security/test_escape_attempts.sh`:** `/proc/1/root`, `mount`, `modprobe`, `mknod`, `chroot`, `unshare`, `ptrace` attempts under `--secure` + policy. These exercise the existing Phase 8b seccomp profile.
- [ ] **X2.2 — Add `tests/security/test_resource_abuse.sh`:** fork bomb, memory bomb, CPU bomb + timeout; verify the host survives and no orphan/zombie processes remain.
- [ ] **X2.3 — Add `tests/security/test_cve_patterns.sh`:** inherited fd cleanup (`/proc/self/fd`), proc mount flags (`nosuid,nodev,noexec`), and no host fd leakage.
- [ ] **X2.4 — Add a cleanup assertion helper:** after each test, `ps aux | grep minicontainer` should not show leaked containers, and `pgrep -P` should not show zombies.

### 4.3 Real workload validation

- [ ] **X3.1 — Verify Python, GCC, Java, Node.js, bash, and SQLite workloads under `--secure` + policy.** Record any `EPERM` syscall via `strace -f -e trace=%process` and either add a safe entry to the existing Phase 8b allow-list or document the limitation.
- [ ] **X3.2 — Add `tests/workloads/test_real_workloads.sh`** with SKIP logic when the rootfs lacks the interpreter/toolchain.
- [ ] **X3.3 — Add a matrix in the docs** (workload × base secure × notes), matching the design’s test plan.

### 4.4 Performance / NFR checks

- [ ] **X4.1 — Measure policy load time** for typical files; target < 5 ms.
- [ ] **X4.2 — Measure watchdog CPU overhead** over a 60 s idle + busy container; target < 1%.
- [ ] **X4.3 — Measure event logging overhead** for a short-lived container (~10 events); target < 1%.
- [ ] **X4.4 — Record results in `docs/decisions.md` or a new `docs/performance.md`.**

### 4.5 Documentation

- [ ] **X5.1 — Update `README.md`:**
  - New CLI flags: `--policy`, `--timeout`, `--grace-period`, `--event-log`, `--no-event-log`.
  - New subcommands: `logs`, `events`, `policy validate`.
  - Policy file schema (JSON only) with examples.
  - Event schema and log locations.
  - Privilege model: cgroup resource limits require root.
  - Limitations: detached watchdog, root requirement, and that policy-extended syscalls, filesystem/network policy, multi-user support, and TOML are not supported. Unsupported policy keys warn and are ignored.
- [ ] **X5.2 — Update `docs/decisions.md`:**
  - Policy format choice (JSON only).
  - Precedence model.
  - Policy-mode gating vs legacy behavior.
  - Watchdog lifetime/ownership.
  - Detached-container limitation.
  - Dropped scope: policy-extended seccomp, multi-user/delegated cgroups, TOML.
  - Error log entries for bugs found during implementation.
- [ ] **X5.3 — Add example policies under `examples/policies/`** (minimal, student, research) and reference them from README. Do not install to `/etc` automatically.
- [ ] **X5.4 — Update `make help`** with the new test targets and example commands.

### 4.6 Final regression and release checklist

- [ ] **X6.1 — `make clean all` on Linux with zero warnings** (`-Wall -Wextra`).
- [ ] **X6.2 — Existing `make test` passes** (or only pre-existing failures from T0.2 remain).
- [ ] **X6.3 — New unit tests pass unprivileged** where possible; root-required tests pass as root.
- [ ] **X6.4 — New integration/security tests pass** on a cgroup-v2 Linux host with a suitable rootfs.
- [ ] **X6.5 — Manual acceptance commands from requirements 6.2 / Appendix A pass:**
  - `minicontainer run --policy ... --timeout ...`
  - `minicontainer logs <id>`
  - `minicontainer events --user <uid>`
  - `minicontainer policy validate <path>`
- [ ] **X6.6 — No orphan processes, zombie processes, leaked threads, or leaked cgroups** after the full suite.
- [ ] **X6.7 — Review the diff for accidental repo changes** (especially `.kiro/`, generated build artifacts, and the libprocfs submodule).
- [ ] **X6.8 — Confirm the final scope** against requirements 1–3, 6.1–6.3, and NFR1–NFR4; list every out-of-scope item in the README/decisions doc with a rationale.

---

## 5. Suggested Execution Order

1. **T0** — Linux environment + baseline.
2. **P1.1–P1.6** — shared types, policy API, include-cycle guard.
3. **P1.7–P1.27** — JSON parser, validation, defaults, application, CLI, tests.
4. **P2.1–P2.33** — watchdog + timeout, with unit tests.
5. **P3.1–P3.28** — event model, persistence, runtime integration, query commands, tests.
6. **X1–X6** — integration/security/workloads/docs/perf/regression.

---

## 6. Definition of Done

- [ ] Policy mode loads/validates/applies JSON policies.
- [ ] CLI precedence is explicit and tested, including zero-value overrides.
- [ ] Wall-clock timeout works with SIGTERM → grace → SIGKILL; no zombie threads/processes.
- [ ] Watchdog is heap-owned, started after clone/cgroup membership, stopped before cgroup cleanup.
- [ ] Event logs are valid JSONL with the required event types and details.
- [ ] `logs`, `events`, and `policy validate` work.
- [ ] Event-log and monitoring failures degrade gracefully.
- [ ] Existing CLI behavior, the Phase 8b seccomp profile, and tests are preserved (policy-mode gating).
- [ ] README, decisions, examples, and limitations are documented.
- [ ] Required integration/security tests pass on Linux; performance targets are measured.
- [ ] Policy-extended seccomp, multi-user support, and TOML are documented as explicitly out of scope, not silently missing.

---

## 7. Risks and Known Limitations to Document

| Risk / limitation | Mitigation / documentation |
|---|---|
| Detached `start` cannot keep a watchdog thread alive | Foreground-only timeout; document; consider a monitor process later. |
| Cgroups require root | Document; delegated cgroups are out of scope. |
| Seccomp filter is x86_64-only (existing Phase 8b) | Keep the existing guard; document; porting needs arch-specific numbers and `AUDIT_ARCH` handling. |
| Policy-extended syscall blocking is not supported | Existing Phase 8b profile remains; policy seccomp keys warn and are ignored; document. |
| Event log directory may be unwritable unprivileged | Warn and disable logging; per-user log dirs are out of scope. |
| Timeout kill of descendants without a cgroup/PID namespace | Use `cgroup.kill` when available; recommend `--init`; document. |
| Policy “default hardening/logging/pids” could break legacy runs | Policy-mode gating (D3); document the interpretation. |
| OOM/PSI counters vary by kernel | Read what is available; skip gracefully; test on the target kernel. |
| Real-workload tests need a rich rootfs | Skip with a clear message; document required tools. |
| Integration tests are root-heavy | Separate `make test-integration`/`test-security`; keep `make test` fast. |

---

## 8. Files Expected to Change

**New**

- `include/policy.h`, `src/policy.c`, `src/policy_json.c` (or parser in `policy.c`)
- `include/watchdog.h`, `src/watchdog.c`
- `include/eventlog.h`, `src/eventlog.c`
- `tests/test_policy.c`, `tests/test_watchdog.c`, `tests/test_eventlog.c`
- `tests/fixtures/policies/*.json`
- `tests/integration/*.sh`, `tests/security/*.sh`, `tests/workloads/*.sh`
- `examples/policies/*.json`
- `docs/performance.md` (optional)

**Modified**

- `include/core.h` — new policy/watchdog/event-log fields
- `include/cli.h`, `src/cli.c`, `src/main.c` — flags, subcommands, precedence
- `src/core.c` — watchdog/event integration, child_args snapshot
- `include/cgroup.h`, `src/cgroup.c` — OOM counter helper and better permission errors
- `include/state.h`, `src/state.c` — policy/log metadata
- `include/inspector.h`, `src/inspector.c` — if logs/stats integration needs it
- `tests/test_cli.c` — new subcommands
- `Makefile` — new objects, `-pthread`, test targets
- `README.md`, `docs/decisions.md` — documentation
- `include/cleanup.h`, `src/cleanup.c` — optional log/cgroup cleanup integration
