# TAVIK Security Policy

## Security Model Overview
TAVIK is engineered from the ground up to prioritize isolation, boundary enforcement, and safe execution of containerized workloads.

### Key Security Commitments
1. **Never execute untrusted workloads as unconfined host processes.** Containers must have strict namespace isolation and resource constraints.
2. **Path Traversal Protection**: Archive extractors and layer unpackers must reject relative paths escaping rootfs boundaries (e.g., `../`, malicious symlinks).
3. **Digest Verification**: All pulled image blobs and manifests must have their cryptographic digests (SHA-256) strictly validated before unpacking or execution.
4. **Restricted Sockets**: Daemon Unix domain sockets default to `0600` or `0660` permissions restricted to the running user or `tavik` group.
5. **No File Descriptor Leaks**: File descriptors opened by the daemon must use `O_CLOEXEC` to prevent accidental inheritance by supervised processes.
6. **No-New-Privileges & Capability Dropping**: Supervised containers drop all non-essential Linux capabilities by default.

## Reporting Security Vulnerabilities
If you discover a security vulnerability within TAVIK, please do not open a public GitHub issue. Send a security report to `security@tavik.dev` detailing:
- The affected component/crate.
- A minimal reproducible example or proof-of-concept.
- Potential impact and suggested mitigations.
