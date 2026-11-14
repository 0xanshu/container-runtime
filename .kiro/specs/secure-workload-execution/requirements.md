# Requirements Document

## Introduction

This document specifies the requirements for extending minicontainer with policy, monitoring, and enforcement layers for multi-user shared computing infrastructure. Requirements are derived from the technical design document and organized by feature area.

The goal is to enable educational institutions and shared computing facilities to safely execute untrusted programs while maintaining resource efficiency and operational visibility.

## Requirements

---

## Feature 1: Policy File Loading and Application

### 1.1 Policy File Format Support

**Requirement**: The system shall support policy files in JSON format (with TOML as an optional enhancement).

**Rationale**: JSON reuses the existing Phase 8c OCI parser, reducing implementation complexity. TOML offers better human-readability for administrators.

**Acceptance Criteria**:

- Policy files with `.json` extension are parsed using the existing JSON parser
- Invalid JSON produces clear error messages indicating the parse failure location
- (Optional) Policy files with `.toml` extension are parsed using tomlc99 library

### 1.2 Policy File Discovery

**Requirement**: The system shall load policy files from explicit paths specified via CLI flag.

**Acceptance Criteria**:

- `--policy <path>` flag accepts absolute or relative paths to policy files
- Non-existent policy files produce error: "Policy file not found: <path>"
- Unreadable policy files produce error: "Cannot read policy file: <path>"

### 1.3 Policy File Structure

**Requirement**: Policy files shall define resource limits, security settings, and logging configuration in a structured format.

**Acceptance Criteria**:

- Policy file contains sections: `[policy]` (metadata), `[resources]`, `[security]`, `[logging]`
- Each section is optional; missing sections use default values
- Unknown fields produce warnings but do not cause parse failure

### 1.4 Resource Limit Specification

**Requirement**: Policy files shall specify resource limits including memory, CPU, PID count, and timeout.

**Acceptance Criteria**:

- `memory` field accepts human-readable format (e.g., "512M", "1G") or bytes
- `cpu` field accepts decimal fraction (0.5 = 50% of one core) or whole number
- `pids` field accepts integer for maximum process count
- `timeout` field accepts integer seconds for wall-clock timeout (0 = unlimited)
- `grace_period` field accepts integer seconds before SIGKILL after SIGTERM

### 1.5 Policy Validation

**Requirement**: The system shall validate policy values before applying them.

**Acceptance Criteria**:

- Memory limit < 1MB produces error: "memory_limit must be at least 1MB or 0 for unlimited"
- CPU limit < 0.0 or > CPU count produces error: "cpu_limit must be between 0.0 and <N>"
- PID limit < 0 produces error: "pids_limit must be non-negative"
- Unknown syscall names in `blocked_syscalls` produce error: "Unknown syscall: <name>"

### 1.6 Policy Application

**Requirement**: The system shall apply policy values to container configuration.

**Acceptance Criteria**:

- `memory` maps to `container_config_t.cgroup_limits.memory_limit`
- `cpu` maps to `container_config_t.cgroup_limits.cpu_quota/period`
- `pids` maps to `container_config_t.cgroup_limits.pid_limit`
- `timeout` maps to new `container_config_t.timeout` field
- `enable_hardening` maps to `container_config_t.enable_hardening`
- CLI flags override policy values when both are specified

### 1.7 Default Policy

**Requirement**: When no policy file is specified, the system shall use sensible defaults.

**Acceptance Criteria**:

- Default memory limit: 0 (unlimited)
- Default CPU limit: 1.0 (one full core)
- Default PID limit: 100
- Default timeout: 0 (unlimited)
- Default grace period: 10 seconds
- Default hardening: true
- Default logging: enabled at `/var/log/minicontainer/events`

---

## Feature 2: Wall-Clock Timeout Enforcement

### 2.1 Timeout Specification

**Requirement**: The system shall enforce wall-clock time limits on container execution.

**Acceptance Criteria**:

- `--timeout <seconds>` CLI flag sets timeout (overrides policy)
- Timeout of 0 means no timeout (container runs indefinitely)
- Timeout applies to wall-clock time, not CPU time
- Timeout countdown starts when container process is created (after clone)

### 2.2 Graceful Shutdown

**Requirement**: The system shall attempt graceful shutdown before forceful termination.

**Acceptance Criteria**:

- When timeout expires, send SIGTERM to container process
- Wait `grace_period` seconds (default: 10)
- If process still alive, send SIGKILL
- Log the shutdown sequence (SIGTERM sent, SIGKILL sent, or clean exit)

### 2.3 Watchdog Thread Architecture

**Requirement**: Timeout enforcement shall run in a separate thread to avoid blocking.

**Acceptance Criteria**:

- Watchdog thread starts after `clone()` in parent process
- Thread polls at 100ms intervals to check timeout
- Thread can be stopped cleanly when container exits
- No zombie threads remain after container termination

### 2.4 Watchdog Thread Safety

**Requirement**: The watchdog thread shall coordinate safely with container lifecycle.

**Acceptance Criteria**:

- Thread uses mutex/condition variables for synchronization
- Thread checks `running` flag before each poll iteration
- `watchdog_stop()` waits for thread to exit via `pthread_join`
- Thread cleanup happens even on error paths

---

## Feature 3: Event Logging

### 3.1 Event Log Format

**Requirement**: The system shall write events in JSON Lines (JSONL) format.

**Acceptance Criteria**:

- Each event is a single-line JSON object
- Events are appended atomically (no partial writes)
- Each event includes: `timestamp` (ISO 8601), `container_id`, `event_type`, `details`
- Log files are named `<container_id>.jsonl`

### 3.2 Event Types

**Requirement**: The system shall log the following event types.

**Acceptance Criteria**:

- `container_start`: Logged when container begins execution
- `container_exit`: Logged when container terminates
- `timeout_kill`: Logged when container is killed due to timeout
- `oom_kill`: Logged when container is OOM-killed by kernel
- `resource_breach`: Logged when resource usage exceeds warning threshold
- (Optional) `syscall_denied`: Logged when seccomp denies a syscall

### 3.3 Event Log Location

**Requirement**: Event logs shall be stored in a dedicated directory.

**Acceptance Criteria**:

- Default location: `/var/log/minicontainer/events/`
- Directory is created if it doesn't exist
- `--event-log <dir>` flag overrides default location
- `--no-event-log` flag disables event logging entirely

### 3.4 Event Log Content

**Requirement**: Events shall capture sufficient detail for auditing and debugging.

**Acceptance Criteria**:

- `container_start` includes: program path, arguments, policy name, user ID, resource limits
- `container_exit` includes: exit code, exit reason, wall-clock time, CPU time, memory peak
- `timeout_kill` includes: timeout value, elapsed time, signal used, grace period used
- `oom_kill` includes: memory limit, estimated memory peak
- `resource_breach` includes: resource type, current value, limit value, percentage

### 3.5 Event Log Query

**Requirement**: The system shall provide a CLI interface to query event logs.

**Acceptance Criteria**:

- `minicontainer logs <id>` prints events for a specific container
- Output is human-readable (indented JSON or formatted text)
- `minicontainer events [--user <uid>]` lists recent events across containers
- Events are sorted by timestamp (newest first)

---

## Feature 4: Extended Seccomp from Policy

### 4.1 Syscall Blocking Specification

**Requirement**: Policy files shall specify additional syscalls to block beyond the base profile.

**Acceptance Criteria**:

- `blocked_syscalls` field accepts array of syscall names
- Syscall names are architecture-independent (e.g., "reboot", "mount")
- Unknown syscall names produce validation error
- Empty array or missing field means no additional blocking

### 4.2 Two-Layer Seccomp Approach

**Requirement**: The system shall apply additional syscall blocking without regenerating the base BPF program.

**Acceptance Criteria**:

- Base seccomp filter (Phase 8b) is applied first
- If `blocked_syscalls` is non-empty, a second filter is applied
- Second filter checks only blocked syscalls and returns `SECCOMP_RET_ERRNO | EPERM`
- Second filter is generated at runtime from policy

### 4.3 Seccomp Denial Logging (Optional)

**Requirement**: The system shall attempt to log seccomp denials.

**Acceptance Criteria**:

- If kernel supports `SECCOMP_RET_LOG`, use it for blocked syscalls
- Otherwise, log denials post-mortem by inspecting kernel audit log
- Denial events include: syscall name, syscall number, error code

---

## Feature 5: Resource Monitoring

### 5.1 Cgroup Stat Polling

**Requirement**: The watchdog thread shall poll cgroup statistics for monitoring.

**Acceptance Criteria**:

- Read `memory.current` and `memory.max` from cgroup v2 filesystem
- Read `cpu.stat` for CPU usage tracking
- Read `pids.current` for process count
- Poll interval: 100ms (configurable in policy)

### 5.2 Resource Threshold Breach Detection

**Requirement**: The system shall detect when resource usage exceeds warning thresholds.

**Acceptance Criteria**:

- `memory_warning_threshold` (0.0-1.0) triggers event when memory usage exceeds percentage
- `cpu_warning_threshold` (0.0-1.0) triggers event when CPU usage exceeds percentage
- `cpu_warning_duration` filters transient CPU spikes (only log if sustained)
- Threshold of 0.0 disables detection for that resource

### 5.3 OOM Kill Detection

**Requirement**: The system shall detect and log OOM kills.

**Acceptance Criteria**:

- Read `memory.events` cgroup file for `oom_kill` counter
- If `oom_kill > 0` after container exit, log `oom_kill` event
- OOM detection happens in `container_wait()` after process termination

---

## Feature 6: CLI Integration

### 6.1 New CLI Flags

**Requirement**: The system shall add new CLI flags for policy and monitoring control.

**Acceptance Criteria**:

- `--policy <path>`: Path to policy file (JSON or TOML)
- `--timeout <seconds>`: Override timeout from policy
- `--grace-period <seconds>`: Override grace period from policy
- `--event-log <dir>`: Override event log directory
- `--no-event-log`: Disable event logging

### 6.2 New CLI Subcommands

**Requirement**: The system shall add new CLI subcommands for log viewing.

**Acceptance Criteria**:

- `minicontainer logs <id>`: Print event log for container
- `minicontainer events [--user <uid>]`: List recent events
- `minicontainer policy validate <path>`: Validate policy file without running

### 6.3 CLI Flag Precedence

**Requirement**: CLI flags shall take precedence over policy values.

**Acceptance Criteria**:

- If `--timeout` is set, use it regardless of policy timeout
- If `--memory` is set, use it regardless of policy memory limit
- Policy values are applied only for fields not set via CLI

---

## Feature 7: Multi-User Support (Phase 5, Optional)

### 7.1 Per-User State Directories

**Requirement**: Container state shall be isolated per-user.

**Acceptance Criteria**:

- State directory: `/run/minicontainer/<uid>/<container_id>/`
- Event logs: `/var/log/minicontainer/events/<uid>/<container_id>.jsonl`
- Users can only access their own state directories

### 7.2 Delegated Cgroups

**Requirement**: The system shall support running containers as unprivileged users with pre-delegated cgroups.

**Acceptance Criteria**:

- Admin setup script creates per-user cgroup subtrees: `/sys/fs/cgroup/minicontainer/user_<uid>/`
- Users can create containers within their subtree
- Resource limits apply within the subtree constraints

### 7.3 Unprivileged Container Execution

**Requirement**: Users shall be able to run containers without sudo when cgroups are delegated.

**Acceptance Criteria**:

- `minicontainer run --user --policy ./policy.json /bin/sh` works without sudo
- User cannot exceed subtree resource limits
- Error message if cgroup subtree not configured: "No delegated cgroup found for user <uid>"

---

## Non-Functional Requirements

### NFR1: Performance

**Requirement**: The system shall not significantly degrade container performance.

**Acceptance Criteria**:

- Policy loading: < 5ms for typical policy file
- Watchdog polling: < 1% CPU overhead
- Event logging: < 1% overhead for typical workload (10 events/container)
- Seccomp filter extension: < 5% syscall overhead

### NFR2: Reliability

**Requirement**: The system shall handle errors gracefully without crashing.

**Acceptance Criteria**:

- Invalid policy files produce error messages, not crashes
- Watchdog thread failures are logged, container continues
- Event log write failures are logged, container continues
- No zombie processes or threads after container termination

### NFR3: Security

**Requirement**: The system shall not introduce new security vulnerabilities.

**Acceptance Criteria**:

- Policy files are read with least privilege
- Event logs are written with appropriate permissions (0644)
- Watchdog thread cannot be exploited to gain privileges
- Seccomp extension does not weaken the base profile

### NFR4: Compatibility

**Requirement**: The system shall maintain backward compatibility with existing minicontainer usage.

**Acceptance Criteria**:

- All existing CLI flags continue to work
- Containers without policy run with default settings
- Existing test suite passes without modification
- New features are opt-in via new flags

---

## Implementation Phases

### Phase 1: Policy File + Basic Resource Limits (2 weeks)

- Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
- Deliverables: `policy.h/c`, `--policy` flag, policy validation, policy application

### Phase 2: Wall-Clock Timeout + Watchdog (2 weeks)

- Requirements: 2.1, 2.2, 2.3, 2.4
- Deliverables: `watchdog.h/c`, `--timeout` flag, graceful shutdown, thread safety

### Phase 3: Event Logging (2 weeks)

- Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
- Deliverables: `eventlog.h/c`, JSONL writer, event types, `logs` subcommand

### Phase 4: Extended Seccomp from Policy (2 weeks)

- Requirements: 4.1, 4.2, 4.3
- Deliverables: `blocked_syscalls` parsing, two-layer seccomp, denial logging

### Phase 5: Multi-User Support (2 weeks, optional)

- Requirements: 7.1, 7.2, 7.3
- Deliverables: Per-user directories, delegated cgroups setup script, unprivileged execution

---

## Constraints and Assumptions

### Constraints

1. **Root Required for Cgroups**: Cgroup operations require root privileges. Phase 1-4 document this requirement; Phase 5 explores delegated cgroups.

2. **Linux Kernel Version**: Requires Linux kernel 4.5+ for cgroup v2; 4.14+ for `SECCOMP_RET_LOG` (optional feature).

3. **No Supervisor Daemon**: A supervisor daemon (minicontainerd) is out of scope for this project.

4. **Single-Host Deployment**: No distributed or multi-node support.

### Assumptions

1. **Trusted Administrators**: Administrators configuring policy files are trusted.

2. **Cooperative Users**: Users are not actively malicious; the goal is to prevent accidental resource abuse.

3. **Existing Hardening**: Phase 8b seccomp and capability dropping provide baseline security.

4. **Container Workloads**: Workloads are typical student/research programs (Python, Java, C/C++, etc.), not system services.

---

## Glossary

- **Policy File**: Configuration file specifying resource limits, security settings, and logging options.
- **Watchdog Thread**: Background thread that monitors container execution and enforces timeout.
- **JSONL**: JSON Lines format; one JSON object per line.
- **Seccomp**: Linux kernel feature for filtering system calls.
- **Cgroup v2**: Linux kernel feature for resource control (memory, CPU, PIDs).
- **Grace Period**: Time between SIGTERM and SIGKILL during timeout shutdown.
- **OOM Kill**: Kernel terminating a process due to out-of-memory condition.

---

## Document History

| Version | Date       | Author                | Changes                                           |
| ------- | ---------- | --------------------- | ------------------------------------------------- |
| 1.0     | 2026-10-12 | Requirements Document | Initial requirements derived from design document |
