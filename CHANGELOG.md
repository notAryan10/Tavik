# Changelog

All notable changes to TAVIK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-07

### Added
- **`crates/tavik-runtime` (`tavikr`)**:
  - Implemented standard OCI Runtime Specification v1.2 data models (`Spec`, `Process`, `Root`, `Mount`, `Linux`, `ContainerState`).
  - Standalone `tavikr` OCI runtime binary supporting `create`, `start`, `state`, `kill`, `delete`, and `spec`.
  - OCI bundle parser and validator verifying `config.json` schema and `rootfs/` existence.
  - Linux namespace engine configuring `CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, and `CLONE_NEWNET`.
  - Mount namespace isolation making root private (`MS_REC | MS_PRIVATE`), bind mounting rootfs, and mounting `/proc` inside container namespace.
  - Inter-process synchronization via `UnixDatagram::pair()` for container init coordination.
- **Daemon OCI Integration**:
  - Extended IPC protocol with `ContainerCreate`, `ContainerStart`, `ContainerState`, `ContainerKill`, and `ContainerDelete` actions.
  - Added `ContainerExecutor` instance into `tavikd`.
- **CLI Commands**:
  - Added `tavik container <create|start|state|kill|rm|spec>` command family.
- **Integration Tests**:
  - Added `tests/integration/tests/oci_runtime_test.rs` covering OCI bundle validation, container state transitions, and daemon RPC.

## [0.1.0] - 2026-11-07

### Added
- Initial project architecture and workspace setup (`tavik-common`, `tavik-core`, `tavik-daemon`, `tavik-cli`).
- Length-delimited framing codec (`TavikCodec`, `TavikServerCodec`, `TavikClientCodec`) with 16 MiB safety cap.
- Atomic state store with rename-based persistence and boot-time PID reconciliation.
- Asynchronous process supervisor with stdout/stderr redirection and signal escalation.
- Daemon Unix domain socket server (`tavikd`).
- CLI client (`tavik`) supporting `version`, `info`, `ps`, `inspect`, `stop`, `run-task`, `ping`, and `shutdown`.
