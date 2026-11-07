pub mod action;
pub mod architecture;
pub mod argument;
pub mod compiler;
pub mod install;
pub mod syscall;

pub use action::SeccompAction;
pub use architecture::SeccompArchitecture;
pub use argument::{SeccompArg, SeccompOperator};
pub use compiler::{SeccompCompiler, SockFilter, SockFprog, BPF_MAXINSNS};
pub use syscall::{SyscallResolver, SyscallRule};

use crate::error::SecurityError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Linux seccomp filter flags (passed to seccomp(SECCOMP_SET_MODE_FILTER, flags, ...)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeccompFlag {
    /// Synchronize all threads to the same seccomp filter tree (SECCOMP_FILTER_FLAG_TSYNC = 1).
    Tsync,
    /// Log all not-allowed syscalls (SECCOMP_FILTER_FLAG_LOG = 2).
    Log,
    /// Disable speculative execution side-channel mitigations (SECCOMP_FILTER_FLAG_SPEC_ALLOW = 4).
    SpecAllow,
}

impl std::str::FromStr for SeccompFlag {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "SECCOMP_FILTER_FLAG_TSYNC" | "TSYNC" => Ok(Self::Tsync),
            "SECCOMP_FILTER_FLAG_LOG" | "LOG" => Ok(Self::Log),
            "SECCOMP_FILTER_FLAG_SPEC_ALLOW" | "SPEC_ALLOW" => Ok(Self::SpecAllow),
            _ => Err(SecurityError::InvalidConfiguration(format!(
                "Unknown seccomp flag '{}'",
                s
            ))),
        }
    }
}

impl SeccompFlag {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tsync => "SECCOMP_FILTER_FLAG_TSYNC",
            Self::Log => "SECCOMP_FILTER_FLAG_LOG",
            Self::SpecAllow => "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
        }
    }

    pub const fn flag_bit(&self) -> u32 {
        match self {
            Self::Tsync => 1,     // SECCOMP_FILTER_FLAG_TSYNC
            Self::Log => 2,       // SECCOMP_FILTER_FLAG_LOG
            Self::SpecAllow => 4, // SECCOMP_FILTER_FLAG_SPEC_ALLOW
        }
    }
}

impl fmt::Display for SeccompFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for SeccompFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SeccompFlag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Self>().map_err(de::Error::custom)
    }
}

/// Complete OCI Seccomp configuration profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    /// Default action taken when a system call does not match any rule.
    pub default_action: SeccompAction,

    /// Error number returned if `default_action` is `SCMP_ACT_ERRNO`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_errno_ret: Option<u32>,

    /// Target architectures covered by this profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<SeccompArchitecture>,

    /// Filter flags (e.g. SECCOMP_FILTER_FLAG_TSYNC).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<SeccompFlag>,

    /// List of system call filtering rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<SyscallRule>,
}

impl SeccompProfile {
    /// Validates the structure and rules of the seccomp profile.
    pub fn validate(&self) -> Result<(), SecurityError> {
        for rule in &self.syscalls {
            rule.validate()?;
        }
        Ok(())
    }

    /// Calculates the combined bitmask of all declared seccomp flags.
    pub fn flags_mask(&self) -> u32 {
        let mut mask = 0;
        for flag in &self.flags {
            mask |= flag.flag_bit();
        }
        mask
    }
}
