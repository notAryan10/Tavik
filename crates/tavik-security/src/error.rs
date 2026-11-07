use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    #[error("Unknown Linux capability: '{0}'")]
    UnknownCapability(String),

    #[error(
        "Capability '{cap}' (value {value}) exceeds kernel supported cap_last_cap ({last_cap})"
    )]
    CapabilityExceedsKernelLastCap {
        cap: String,
        value: u32,
        last_cap: u32,
    },

    #[error("Failed to read kernel cap_last_cap: {0}")]
    KernelLastCapUnavailable(String),

    #[error("Syscall '{syscall}' failed: {os_error}")]
    SyscallFailed { syscall: String, os_error: String },

    #[error("Capability verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid capability configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Linux security capabilities require a Linux kernel")]
    UnsupportedPlatform,
}
