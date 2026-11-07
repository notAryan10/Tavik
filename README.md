<h1 align="center"> TAVIK </h1>

<p align="center">
  <strong>Containers. Without the overhead.</strong>
  <br />
  A performance-first, Rust-native, OCI-compatible container engine.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-orange?logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-informational" alt="Platform" />
  <img src="https://img.shields.io/badge/OCI-Compatibility%20In%20Development-blue" alt="OCI compatibility in development" />
  <img src="https://img.shields.io/badge/Status-Early%20Development-yellow" alt="Early development" />
  <img src="https://img.shields.io/badge/License-See%20LICENSE-lightgrey" alt="License" />
</p>

---

## What is TAVIK?

**TAVIK** is an independent, Rust-native container engine designed to make container execution faster, storage more efficient, builds smarter, and container infrastructure more secure.

Inspired by the capabilities of existing container technologies, TAVIK aims to build a modern container engine from the ground up, without depending on Docker Engine.

Its architecture is designed around the Open Container Initiative (OCI) standards, enabling compatibility with the broader container ecosystem.

Rather than simply recreating Docker, TAVIK aims to rethink how a container engine should manage processes, images, filesystems, resources, and execution.

### Our vision

Build a container engine that combines:

- High-performance container execution.
- Intelligent image and filesystem storage.
- Incremental and parallel image builds.
- Secure Linux isolation.
- Lightweight process and lifecycle management.
- OCI compatibility.
- A clean developer experience.

**The goal is simple: less overhead, smarter execution, and better resource utilization.**

---

## Why TAVIK?

Container technology has transformed software development, but there are still opportunities to improve the underlying experience.

TAVIK is being designed to address several areas:

| Area | TAVIK's direction |
|---|---|
| Container startup | Minimize initialization and execution overhead |
| Image storage | Content-addressable storage and layer deduplication |
| Build performance | Dependency-aware caching and parallel execution |
| Image distribution | Efficient pulling and future lazy-loading support |
| Security | Rootless execution and Linux security controls |
| Resource management | Native cgroups v2 integration |
| Observability | Built-in container and performance diagnostics |
| Architecture | Modular Rust implementation |

These are development objectives, not claims of measured performance improvements.

---

## Core Technologies

TAVIK is built using Rust and established Linux technologies.

| Component | Technology |
|---|---|
| Primary language | Rust |
| Async runtime | Tokio |
| CLI | Clap |
| Serialization | Serde |
| IPC | Unix Domain Sockets |
| Runtime isolation | Linux namespaces |
| Resource management | cgroups v2 |
| Filesystem | OverlayFS |
| Image format | OCI Image Specification |
| Runtime interface | OCI Runtime Specification |
| Registry communication | OCI Distribution Specification |
| Hashing | SHA-256 |
| Compression | gzip / zstd |

The implementation will prioritize established technologies and interoperable standards over unnecessary custom infrastructure.

---

## Architecture

TAVIK follows a modular Rust workspace architecture.

```text
                       TAVIK
                         |
              +----------+----------+
              |                     |
           tavik CLI             tavikd
              |                     |
              +----------+----------+
                         |
                     tavik-core
                         |
       +-----------------+------------------+
       |                 |                  |
   Runtime            Storage             Images
   tavikr           Image Layers       OCI Registry
       |                 |                  |
       +-----------------+------------------+
                         |
                  Linux Kernel
                         |
       +-----------------+------------------+
       |                 |                  |
   Namespaces          cgroups           OverlayFS
       |                 |                  |
       +-----------------+------------------+
                         |
                   Containers
```

### Main components

| Component | Responsibility |
|---|---|
| `tavik-cli` | Command-line interface |
| `tavik-daemon` | Background service and IPC |
| `tavik-core` | Lifecycle management and orchestration |
| `tavik-runtime` | OCI runtime and Linux isolation |
| `tavik-image` | OCI image and registry operations |
| `tavik-storage` | Content-addressable storage and snapshots |
| `tavik-builder` | Incremental image building |
| `tavik-network` | Container networking |
| `tavik-security` | Runtime security controls |
| `tavik-observability` | Metrics, logging, and diagnostics |
| `tavik-common` | Shared types, errors, and protocols |

Some components are planned and will be introduced as their implementation milestones begin.

---

## Performance Engineering

Performance is the primary design objective of TAVIK.

### 1. Fast container execution

TAVIK aims to minimize unnecessary work during container initialization.

Areas of investigation include:

- Efficient process creation.
- Namespace initialization.
- Filesystem preparation.
- Reduced IPC overhead.
- Efficient resource allocation.
- Concurrent container startup.

### 2. Intelligent storage

TAVIK's planned storage architecture combines content-addressable storage with Linux filesystem technologies.

Planned capabilities:

- Content-addressable image blobs.
- Image-layer deduplication.
- OverlayFS snapshots.
- Copy-on-write filesystems.
- Storage reference tracking.
- Garbage collection.
- Efficient compression.

### 3. Intelligent builds

The planned build engine will focus on:

- Dependency-aware build graphs.
- Content-based cache keys.
- Incremental builds.
- Parallel execution.
- Reusable build caches.
- Multi-stage builds.
- Efficient build-context processing.

### 4. Lazy image loading

Future image acceleration work will investigate:

- eStargz.
- Stargz Snapshotter.
- Nydus.
- Remote filesystem snapshots.
- On-demand content retrieval.

TAVIK intends to build on established technologies wherever possible.

---

## Security

Security is a fundamental part of TAVIK's architecture.

The planned Linux security model includes:

- PID namespaces.
- Mount namespaces.
- User namespaces.
- Network namespaces.
- IPC namespaces.
- UTS namespaces.
- cgroups v2.
- Linux capabilities.
- Seccomp.
- Rootless container execution.
- Read-only root filesystem support.
- No-new-privileges.

TAVIK will prioritize least privilege, explicit isolation boundaries, safe filesystem handling, and secure daemon communication.

---

## Current Development Status

TAVIK is in early active development.

Development is organized into incremental phases.

| Phase | Description | Status |
|---|---|---|
| Phase 0 | Research and architecture | Complete |
| Phase 1 | Foundation engine | Complete |
| Phase 2 | OCI container runtime | Next |
| Phase 3 | Security and resource management | Planned |
| Phase 4 | Image and storage engine | Planned |
| Phase 5 | Incremental build engine | Planned |
| Phase 6 | Networking | Planned |
| Phase 7 | Advanced performance | Planned |
| Phase 8 | Production readiness | Planned |

### What currently works?

The completed foundation includes:

- Rust workspace.
- CLI application.
- Background daemon.
- Unix domain socket communication.
- Length-delimited JSON-RPC protocol.
- Persistent state storage.
- Process supervision.
- Process log capture.
- Signal escalation.
- Daemon recovery and lifecycle handling.
- System capability detection.
- Integration testing.

The current implementation provides process supervision, not yet full container isolation.

**Actual OCI container execution is the next development milestone.**

---

## Getting Started

### Requirements

For foundation development:

- Rust toolchain.
- Cargo.
- Git.
- A supported development environment.

For actual Linux container runtime development:

- Linux kernel.
- Linux namespaces.
- cgroups v2.
- Appropriate mount capabilities.
- OverlayFS support for the planned storage implementation.

macOS and Windows can be used as development hosts, but running Linux containers requires a Linux environment, such as a virtual machine.

### Clone the repository

```bash
git clone https://github.com/notAryan10/Tavik.git
cd Tavik
```

Replace `notAryan10` with the repository owner's GitHub username.

### Build the project

```bash
cargo build --workspace
```

### Run tests

```bash
cargo test --workspace
```

### Check formatting

```bash
cargo fmt --all -- --check
```

### Run Clippy

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the daemon

```bash
cargo run -p tavik-daemon
```

### Use the CLI

```bash
cargo run -p tavik-cli -- version
cargo run -p tavik-cli -- info
cargo run -p tavik-cli -- ping
cargo run -p tavik-cli -- ps
```

Available commands may evolve as development progresses. Consult the CLI help output for the current command set.

---

## Project Structure

```text
tavik/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── ROADMAP.md
├── SECURITY.md
├── CONTRIBUTING.md
│
├── crates/
│   ├── tavik-common/
│   ├── tavik-core/
│   ├── tavik-daemon/
│   ├── tavik-cli/
│   ├── tavik-runtime/
│   ├── tavik-image/
│   ├── tavik-storage/
│   ├── tavik-network/
│   ├── tavik-builder/
│   ├── tavik-security/
│   └── tavik-observability/
│
├── docs/
│   ├── architecture/
│   ├── development/
│   ├── specifications/
│   └── benchmarks/
│
└── tests/
    ├── integration/
    ├── compatibility/
    ├── security/
    └── performance/
```

The workspace will grow as additional subsystems are implemented.

---

## Benchmarking Philosophy

TAVIK is performance-oriented, but performance claims must be supported by reproducible measurements.

Planned comparisons include:

- Docker Engine.
- containerd.
- Podman.
- Youki.

Measurements will include:

- Cold and warm startup latency.
- Concurrent container startup.
- Image pulling.
- Build duration.
- Incremental build duration.
- Storage consumption.
- Memory overhead.
- CPU overhead.
- Networking performance.

Benchmarks will aim to use equivalent workloads, security settings, and system configurations.

Results will be documented with hardware, kernel, architecture, and test methodology.

---

## Inspiration and Related Projects

TAVIK builds on ideas and established technologies from the container ecosystem.

- [Open Container Initiative](https://opencontainers.org/)
- [Youki](https://github.com/containers/youki)
- [containerd](https://github.com/containerd/containerd)
- [BuildKit](https://github.com/moby/buildkit)
- [Stargz Snapshotter](https://github.com/containerd/stargz-snapshotter)
- [Nydus](https://github.com/dragonflyoss/nydus)

These projects are valuable references for architecture, interoperability, and systems engineering.

---

## Contributing

TAVIK is being developed incrementally, with an emphasis on correctness, performance, security, and maintainability.

Contributions, technical discussions, testing, and architectural feedback are welcome.

Before contributing, please read:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [DEVELOPMENT.md](docs/development/DEVELOPMENT.md)
- [SECURITY.md](SECURITY.md)

---

## Project Philosophy

TAVIK is not intended to be another container wrapper.

It is an attempt to build an independent container engine with a carefully engineered execution path, intelligent storage, and a modern systems architecture.

We believe container infrastructure can be made more efficient without sacrificing compatibility, isolation, or reliability.

**Less overhead. More control. Better execution.**

---

<p align="center">
  <strong>TAVIK</strong>
  <br />
  Containers. Without the overhead.
  <br /><br />
  Built with Rust.
</p>
