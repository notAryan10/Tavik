# TAVIK Architectural Specification

## 1. Overview & Vision

**TAVIK** is an independent, next-generation, Rust-native, OCI-compatible container engine engineered for maximum performance, minimal storage footprint, rock-solid reliability, and security by default.

### Tagline
> *Containers. Without the overhead.*

### Core Pillars
1. **Performance First**: Zero unnecessary abstractions, minimal syscalls, sub-millisecond container initialization, efficient async IPC, and high concurrency.
2. **Intelligent Storage**: Digest-addressed layer storage, cross-image deduplication, native OverlayFS copy-on-write trees, and future lazy pulling.
3. **Intelligent Build Engine**: Incremental DAG execution with content-hash cache keys, parallel stage scheduling, and cache mounts.
4. **Security by Default**: Unprivileged/rootless by design, strict namespace isolation (PID, Mount, Network, UTS, IPC, User), cgroups v2 resource quotas, seccomp filters, dropped Linux capabilities, and no-new-privileges.
5. **Clean Developer Experience**: Fast and ergonomic CLI (`tavik`), robust daemon supervision (`tavikd`), structured diagnostics, and transparent state inspection.

---

## 2. Workspace & Crate Hierarchy

```text
tavik/
├── Cargo.toml
├── rust-toolchain.toml
├── crates/
│   ├── tavik-common/          # Foundational types, IPC protocol framing, system detection, error handling
│   ├── tavik-core/            # Process supervision, container state machine, persistent storage engine
│   ├── tavik-daemon/          # `tavikd` server, Unix socket listener, RPC router, background tasks
│   ├── tavik-cli/             # `tavik` CLI client, terminal UI, Clap parser, human/JSON output
│   ├── tavik-runtime/         # OCI bundle executor (`tavikr`), namespaces, cgroups v2, pivot_root
│   ├── tavik-image/           # OCI image manifest, index, config parsing, registry distribution v2 client
│   ├── tavik-storage/         # Content-addressable storage (CAS), layer tar unpacker, OverlayFS driver
│   ├── tavik-network/         # Bridge, veth pairs, netns management, IPAM, port forwarding
│   ├── tavik-builder/         # Dockerfile parser, multi-stage build DAG, cache evaluator
│   ├── tavik-security/        # Seccomp BPF filters, Linux capabilities, rootless uid/gid maps
│   └── tavik-observability/   # Tracing telemetry, structured logging, container metrics
├── docs/                      # Architecture, specifications, security, development guides
├── tests/                     # Integration, unit, security, and performance test suites
└── scripts/                   # Development, testing, and deployment scripts
```

---

## 3. Communication Architecture & IPC Protocol

The CLI (`tavik`) communicates with the daemon (`tavikd`) over a high-performance Unix domain socket (`/var/run/tavik/tavik.sock` for system/root daemon, `~/.tavik/run/tavik.sock` for rootless user daemon).

### Protocol Framing
To avoid arbitrary length allocations and protect against DoS attacks, messages are framed using length-delimited JSON:
- **Header**: 4 bytes (Big-Endian `u32`) indicating payload byte length (capped at 16 MiB).
- **Payload**: UTF-8 encoded JSON matching `tavik_common::protocol::Request` and `tavik_common::protocol::Response`.

### Request & Response Contracts
Every request contains:
- `id`: Unique request UUID.
- `action`: Specific operation (`Ping`, `Info`, `ProcessStart`, `ProcessStop`, `ProcessList`, `ProcessInspect`, `Shutdown`).
- `params`: Typed payload for the action.

Every response returns:
- `id`: Matching request UUID.
- `result`: `Ok(Value)` or `Err(TavikError)`.

---

## 4. State Management & Process Supervision

### State Persistence Model
- The state of managed workloads and containers is persisted in `$TAVIK_STATE_DIR/state/` (e.g. `~/.tavik/state/workloads/`).
- State modifications are atomic: state files are written to a temporary sibling file and committed via atomic `rename(2)` to eliminate partial writes upon crashes.
- Upon daemon restart, the state directory is reconciled against active OS PIDs via `sysinfo`/`procfs` to accurately detect processes that terminated while the daemon was offline.

### Process Supervision Loop
- The daemon maintains an asynchronous in-memory supervision table with event channels.
- Child processes are supervised using Tokio's asynchronous process runtime with signal trapping (`SIGCHLD`, `SIGTERM`, `SIGINT`).
- Exit codes, termination signals, and output streams are logged and timestamped with sub-millisecond precision.

---

## 5. Container Isolation & Runtime Design (Linux vs. Cross-Platform)

TAVIK is natively engineered for Linux.
- **Linux Execution**: Utilizes `unshare(2)` / `clone3(2)`, cgroups v2 (`/sys/fs/cgroup/tavik`), `pivot_root(2)`, `mount(2)` (MS_PRIVATE, MS_REC, OverlayFS), and Seccomp filters.
- **Host Detection & Graceful Fallback**: When compiled or executed on non-Linux hosts (such as macOS or Windows), TAVIK detects host capabilities honestly. Foundation process supervision and daemon IPC operate natively across Unix environments, while container isolation subsystems clearly report required Linux kernel features and provide actionable VM/WSL2 configuration guidance.

---

## 6. OCI Compliance Trajectory

TAVIK adheres strictly to Open Container Initiative standards:
1. **OCI Runtime Spec** (v1.2.0): Runtime bundle layout (`config.json`, `rootfs/`), container lifecycle hooks (`create`, `start`, `kill`, `delete`).
2. **OCI Image Spec** (v1.1.0): Content hashes (`sha256`), descriptor objects, image manifests, index/manifest lists, layer tarballs.
3. **OCI Distribution Spec** (v1.1.0): Registry HTTP API v2 for pushing and pulling blobs and manifests with standard token/basic authentication.
