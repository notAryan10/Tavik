# TAVIK Development Guide

## Prerequisites
- Rust 1.80+ (stable toolchain)
- Cargo, rustfmt, and clippy
- Linux kernel 5.15+ for full OCI container execution (cgroups v2, namespaces, overlayfs)
  - On macOS/Windows: macOS can build and run `tavik`, `tavikd`, and process supervision workloads for foundation development; native container isolation requires Linux or a Linux VM.

## Workspace Layout
- `crates/tavik-common`: Common types, error definitions, IPC protocol, host system detection.
- `crates/tavik-core`: Process supervisor, persistent state store, lifecycle state machine.
- `crates/tavik-daemon`: `tavikd` server binary, Unix socket IPC listener, background supervisor.
- `crates/tavik-cli`: `tavik` CLI client binary.

## Building
```bash
cargo build --workspace
```

## Running the Daemon
```bash
# Start daemon in foreground
cargo run --bin tavikd -- --foreground

# Or via CLI
cargo run --bin tavik -- daemon --foreground
```

## Running the CLI
```bash
cargo run --bin tavik -- info
cargo run --bin tavik -- version
cargo run --bin tavik -- ps
cargo run --bin tavik -- run-task -- /bin/echo "Hello from Tavik supervisor!"
```

## Running Tests
```bash
cargo test --workspace
```
