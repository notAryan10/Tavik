# TAVIK Project Roadmap

## Phase 0: Research & Architecture (Completed)
- [x] Environment inspection and cross-platform verification.
- [x] Architectural documentation and workspace design.
- [x] Protocol and IPC framing specifications.
- [x] Security and isolation roadmap.

## Phase 1: Foundation Engine (Current)
- [x] Modular Rust workspace configuration.
- [x] `tavik-common`: Protocol, IPC framing, typed errors, host feature detection.
- [x] `tavik-core`: Atomic persistent state store, asynchronous process supervisor.
- [x] `tavik-daemon`: `tavikd` Unix domain socket server, signal handlers, RPC router.
- [x] `tavik-cli`: `tavik` CLI client (`version`, `info`, `daemon`, `ps`, `inspect`, `stop`, `run-task`).
- [x] Comprehensive unit and integration test suite.

## Phase 2: OCI Container Runtime (`tavikr`)
- [ ] OCI Runtime Specification v1.2 compliance.
- [ ] Rootfs preparation and `pivot_root` setup.
- [ ] Linux namespaces (PID, Mount, Network, UTS, IPC, User).
- [ ] Container init process and lifecycle state transitions (`creating`, `created`, `running`, `stopped`).
- [ ] Terminal allocation (PTY) and standard I/O forwarding.

## Phase 3: Resource Governance & Security Controls
- [ ] cgroups v2 resource controllers (cpu, memory, pids, io).
- [ ] Linux capabilities bounding, effective, and inheritable sets.
- [ ] Seccomp BPF syscall filtering with default deny/allow profiles.
- [ ] Rootless container execution and subuid/subgid mapping.
- [ ] Read-only rootfs and `no-new-privileges` flag enforcement.

## Phase 4: Image & Storage Engine
- [ ] OCI Image Specification v1.1 compliance (manifests, configs, indexes).
- [ ] OCI Distribution Specification v1.1 client (pull, push, auth).
- [ ] Content-Addressable Storage (CAS) for layers and blobs.
- [ ] Tar layer unpacker with path-traversal prevention.
- [ ] OverlayFS copy-on-write snapshot driver with layer deduplication.
- [ ] Storage garbage collection and disk quota accounting.

## Phase 5: Incremental Build Engine
- [ ] Dockerfile syntax parser and AST generator.
- [ ] Build dependency DAG execution.
- [ ] Content-addressable build caching with cache invalidation rules.
- [ ] Multi-stage build support and target filtering.
- [ ] Parallel step execution for independent layers.

## Phase 6: Container Networking
- [ ] Bridge networking and virtual Ethernet (`veth`) pair creation via Netlink.
- [ ] Network namespace configuration.
- [ ] IPAM (IP Address Management) and subnet allocation.
- [ ] Port mapping with iptables/nftables and NAT forwarding.
- [ ] Embedded DNS resolver for container service discovery.

## Phase 7: Advanced Performance & Lazy Pulling
- [ ] eStargz / Nydus lazy image pulling support.
- [ ] Zero-copy filesystem streaming.
- [ ] Sub-millisecond cold start optimization.
- [ ] High-density concurrent container startup profiling.

## Phase 8: Production Hardening
- [ ] Crash resilience and automated orphan reconciliation.
- [ ] Comprehensive fuzz testing of OCI parsing and IPC inputs.
- [ ] End-to-end compatibility test suite against official OCI test images.
- [ ] Production packaging (RPM, DEB, static binary distributions).
