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

    #[error("Unknown Linux syscall: '{0}'")]
    UnknownSyscall(String),

    #[error("Unsupported seccomp architecture: '{0}'")]
    UnsupportedArchitecture(String),

    #[error("Unsupported seccomp action: '{0}'")]
    UnsupportedAction(String),

    #[error("Unsupported seccomp argument operator: '{0}'")]
    UnsupportedOperator(String),

    #[error("Seccomp program too large: {len} instructions (maximum {max})")]
    SeccompProgramTooLarge { len: usize, max: usize },

    #[error("Seccomp compilation failed: {0}")]
    SeccompCompilationError(String),

    #[error("Seccomp installation failed: {0}")]
    SeccompInstallError(String),

    #[error("Linux security capabilities require a Linux kernel")]
    UnsupportedPlatform,
}
