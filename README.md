# TAVIK

**Containers. Without the overhead.**

TAVIK is a next-generation, high-performance, Rust-native container engine designed from the ground up for speed, storage efficiency, security, and OCI specification conformance.

---

## Features

- **Blazing Fast**: Engineered with Rust and asynchronous I/O (`tokio`) for sub-millisecond process and container supervision.
- **Strict OCI Conformance**: Designed against OCI Runtime, Image, and Distribution specifications.
- **Robust IPC**: Fast, framed Unix domain socket protocol for client-daemon communication with message validation.
- **Atomic Persistence**: Crash-resilient workload state storage using transactional file replacements.
- **Security-First**: Designed for rootless execution, cgroups v2 resource quotas, seccomp filtering, and Linux namespace isolation.
- **Cross-Platform Foundation**: Core daemon, IPC, and process supervision run cross-platform (Linux & macOS for development), with strict Linux kernel requirements enforced for container isolation.

---

## Quick Start

### 1. Build TAVIK
```bash
cargo build --release
```

### 2. Start the Daemon (`tavikd`)
```bash
./target/release/tavikd --foreground
```

### 3. Use the CLI (`tavik`)
In another terminal:
```bash
# Check version and engine info
./target/release/tavik version
./target/release/tavik info

# Run a supervised task (foundation supervision)
./target/release/tavik run-task -- /bin/echo "Hello from Tavik engine"

# List workloads
./target/release/tavik ps

# Inspect a workload
./target/release/tavik inspect <task-id>

# Stop a running workload
./target/release/tavik stop <task-id>
```

---

## Architecture

See [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) for full design specifications and [ROADMAP.md](ROADMAP.md) for the development phase trajectory.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
