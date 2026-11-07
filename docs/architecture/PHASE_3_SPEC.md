# TAVIK Phase 3 — Architecture & Implementation Specification
## Resource Governance & Linux Security Controls

**Status:** Draft / Specification  
**Target Milestone:** Phase 3 (`v0.3.0`)  
**Prerequisite:** Phase 2 Runtime Stabilization (`v0.2.0-runtime-stabilized`)  

---

## 1. Executive Summary

Phase 2 established true container isolation (dedicated PID namespaces, `pivot_root` filesystem isolation, private mount propagation, and synchronized startup via named FIFO).

Phase 3 implements the security and resource governance pillars required for production-ready multi-tenant container workloads:
1. **cgroups v2 Resource Governance (`crates/tavik-cgroups`)**: Unified hierarchy enforcement for CPU, memory, swap, PID limits, and atomic container termination (`cgroup.kill`).
2. **Linux Privilege Governance (`crates/tavik-security`)**: Capability bounding set restrictions, ambient capabilities, user namespace ID shifting, and `PR_SET_NO_NEW_PRIVS`.
3. **Seccomp BPF Syscall Filtering (`crates/tavik-security`)**: BPF filter generation enforcing default-deny or default-errno profiles for dangerous Linux syscalls.
4. **OCI Runtime Integration (`crates/tavik-runtime`)**: Seamless orchestration inside the `tavikr` lifecycle applied in strict deterministic order prior to workload execution.

---

## 2. Component Architecture

```
                                  +---------------------------------------+
                                  |            tavik daemon / CLI         |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |         crates/tavik-runtime          |
                                  |           (tavikr executor)           |
                                  +---------------------------------------+
                                          |                       |
                                          v                       v
                    +-----------------------------+   +-------------------------------+
                    |    crates/tavik-cgroups     |   |    crates/tavik-security      |
                    +-----------------------------+   +-------------------------------+
                    | - Unified hierarchy cgroup2 |   | - Capabilities (bounding/eff) |
                    | - cpu.max / cpu.weight      |   | - prctl(PR_SET_NO_NEW_PRIVS)  |
                    | - memory.max / swap.max     |   | - Seccomp BPF filters         |
                    | - pids.max (fork bomb guard)|   | - Secure default OCI profile  |
                    | - cgroup.kill / cleanup     |   +-------------------------------+
                    +-----------------------------+
```

---

## 3. Order of Implementation

To ensure non-breaking verification and systematic debugging, Phase 3 is executed in 6 sequential steps:

### Step 1: `crates/tavik-cgroups` — Unified cgroup v2 Engine
- **Hierarchy Detection**: Discover mount point of `cgroup2` filesystem (standard `/sys/fs/cgroup`).
- **Subtree Control**: Ensure parent controllers (`+cpu +memory +pids +io`) are enabled in `/sys/fs/cgroup/cgroup.subtree_control` and intermediate `/sys/fs/cgroup/tavik/cgroup.subtree_control`.
- **Cgroup Creation**: Create dedicated container group at `/sys/fs/cgroup/tavik/<container_id>`.
- **Resource Limits**:
  - `cpu.max`: Parse OCI `quota` and `period` (write `"<quota> <period>"`, or `"max <period>"`).
  - `cpu.weight`: Translate OCI `shares` to v2 weight (`1 + ((shares - 2) * 9999) / 262142`).
  - `memory.max`: Set byte ceiling for anonymous and page-cache allocations.
  - `memory.swap.max`: Set swap allocation ceiling.
  - `pids.max`: Set process ceiling to prevent PID exhaustion / fork bombs.
- **Process Enrollment**: Atomically enroll container host PID into `<cgroup>/cgroup.procs`.
- **Cgroup Destruction**: Utilize `cgroup.kill` (write `1`) to terminate any lingering processes, followed by removing the cgroup directory.

### Step 2: `crates/tavik-security` — Linux Capabilities Management
- **Representation**: Define all standard POSIX and Linux capabilities (`CAP_CHOWN` through `CAP_CHECKPOINT_RESTORE`).
- **Bounding Set Dropping**: Iterate all 64 potential capabilities; if not present in the OCI bounding set, drop via `prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)`.
- **Inheritable / Permitted / Effective**: Apply exact 64-bit capability bitmasks via `syscall(SYS_capset, &header, &data)` for the container init process.
- **Default Profile**: Supply standard safe OCI container capability defaults (whitelisting 14 common capabilities and dropping dangerous capabilities such as `CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`, `CAP_SYS_PTRACE`, `CAP_SYS_BOOT`, `CAP_SYS_MODULE`).

### Step 3: Privilege Escalation Barrier (`no_new_privs`)
- Guarantee call to `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is strictly invoked before setting up seccomp or dropping capabilities, ensuring setuid/setgid binaries inside the rootfs cannot acquire additional ambient privileges.

### Step 4: `crates/tavik-security` — Seccomp BPF Engine
- **Architecture Validation**: Validate `seccomp.architectures` against host audit architecture (`AUDIT_ARCH_AARCH64` / `AUDIT_ARCH_X86_64`).
- **BPF Bytecode Assembly**:
  - Construct classic BPF (`sock_filter` / `sock_fprog`) instructions in pure Rust without requiring heavy C external library dependencies (e.g. `libseccomp`).
  - Implement instruction sequence:
    1. Validate architecture (`BPF_LD | BPF_W | BPF_ABS`, offset `offsetof(seccomp_data, arch)`).
    2. Load syscall number (`BPF_LD | BPF_W | BPF_ABS`, offset `offsetof(seccomp_data, nr)`).
    3. Match against blacklist/whitelist rules.
    4. For conditional argument matches: load argument high/low words and compare.
    5. Return action: `SECCOMP_RET_ALLOW`, `SECCOMP_RET_ERRNO(err)`, or `SECCOMP_RET_KILL_PROCESS`.
- **Loading Filter**: Execute `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.
- **Default Profile**: Provide default OCI seccomp filter blocking dangerous syscalls (e.g., `sys_kexec_load`, `sys_reboot`, `sys_bpf`, `sys_init_module`, `sys_delete_module`, `sys_ptrace`).

### Step 5: Runtime Integration in `crates/tavik-runtime`
Integrate into the two-stage execution architecture:
1. **Trampoline (`tavikr init`)**:
   - Detect and create cgroup v2 group `/sys/fs/cgroup/tavik/<id>`.
   - Apply resource limits (`cpu.max`, `memory.max`, `pids.max`).
   - Fork container init child.
   - Trampoline writes `child_pid` to `/sys/fs/cgroup/tavik/<id>/cgroup.procs`.
   - Trampoline waits on child `ready` signal.
2. **Child Init**:
   - Namespaces unshared, `pivot_root` executed, old root detached.
   - Child signals trampoline `ready`.
   - Child blocks on `start_fifo`.
   - Upon start signal receipt:
     1. Close remaining fds (`close_range(3, ...)`).
     2. Apply `no_new_privs`.
     3. Apply Seccomp BPF filter.
     4. Drop capability bounding set and set permitted/effective caps.
     5. Execute workload via `execve`.

### Step 6: Empirical Integration Test Suite
Implement end-to-end integration tests on Linux ARM64:
- **`test_cgroups_pids_limit`**: Configure `pids.max = 5`. Verify that a recursive background fork loop terminates with `Resource temporarily unavailable` (`EAGAIN`) without hanging host.
- **`test_cgroups_memory_limit`**: Set `memory.max = 32MB`. Verify memory counter accounting and OOM-kill behavior.
- **`test_capabilities_dropping`**: Verify that attempting a privileged operation (e.g., modifying system hostname without `CAP_SYS_ADMIN` / `CAP_SYS_BOOT`) fails with `EPERM`.
- **`test_seccomp_filter_blocks_syscall`**: Configure a seccomp rule blocking `getppid` or `reboot` with `EPERM`. Verify container process receives `EPERM` when calling the blocked syscall.
