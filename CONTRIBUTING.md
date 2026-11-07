# Contributing to TAVIK

Thank you for your interest in contributing to TAVIK!

## Development Guidelines
- All code must be written in Rust following the latest edition standards.
- Run `cargo fmt --all -- --check` and `cargo clippy --all-targets -- -D warnings` before submitting pull requests.
- All new features, bug fixes, and protocol changes must include unit and/or integration tests.
- Never use fake or mocked outputs in production code paths. Clearly report unimplemented features.
- Adhere to the OCI specifications (Runtime, Image, Distribution).
