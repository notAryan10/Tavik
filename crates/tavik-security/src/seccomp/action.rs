use crate::error::SecurityError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// OCI and Linux seccomp actions.
/// Each action corresponds to a Linux kernel SECCOMP_RET_* action code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SeccompAction {
    /// Kill the entire process immediately (SECCOMP_RET_KILL_PROCESS, 0x80000000).
    KillProcess,
    /// Kill the calling thread (SECCOMP_RET_KILL_THREAD, 0x00000000).
    KillThread,
    /// Alias for KillThread / KillProcess depending on kernel version (SCMP_ACT_KILL).
    Kill,
    /// Deliver a SIGSYS signal to the calling thread (SECCOMP_RET_TRAP, 0x00030000).
    Trap,
    /// Return the specified errno value (SECCOMP_RET_ERRNO, 0x00050000).
    Errno,
    /// Send notification to a tracer (SECCOMP_RET_TRACE, 0x7ff00000).
    Trace,
    /// Log the syscall invocation without blocking it (SECCOMP_RET_LOG, 0x7ffc0000).
    Log,
    /// Notify an unprivileged supervisor via userspace notification (SECCOMP_RET_USER_NOTIF, 0x7fc00000).
    Notify,
    /// Allow the syscall to proceed normally (SECCOMP_RET_ALLOW, 0x7fff0000).
    Allow,
}

impl std::str::FromStr for SeccompAction {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "SCMP_ACT_KILL_PROCESS" | "KILL_PROCESS" => Ok(Self::KillProcess),
            "SCMP_ACT_KILL_THREAD" | "KILL_THREAD" => Ok(Self::KillThread),
            "SCMP_ACT_KILL" | "KILL" => Ok(Self::Kill),
            "SCMP_ACT_TRAP" | "TRAP" => Ok(Self::Trap),
            "SCMP_ACT_ERRNO" | "ERRNO" => Ok(Self::Errno),
            "SCMP_ACT_TRACE" | "TRACE" => Ok(Self::Trace),
            "SCMP_ACT_LOG" | "LOG" => Ok(Self::Log),
            "SCMP_ACT_NOTIFY" | "NOTIFY" => Ok(Self::Notify),
            "SCMP_ACT_ALLOW" | "ALLOW" => Ok(Self::Allow),
            _ => Err(SecurityError::UnsupportedAction(s.to_string())),
        }
    }
}

impl SeccompAction {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::KillProcess => "SCMP_ACT_KILL_PROCESS",
            Self::KillThread => "SCMP_ACT_KILL_THREAD",
            Self::Kill => "SCMP_ACT_KILL",
            Self::Trap => "SCMP_ACT_TRAP",
            Self::Errno => "SCMP_ACT_ERRNO",
            Self::Trace => "SCMP_ACT_TRACE",
            Self::Log => "SCMP_ACT_LOG",
            Self::Notify => "SCMP_ACT_NOTIFY",
            Self::Allow => "SCMP_ACT_ALLOW",
        }
    }

    /// Returns the kernel BPF return value (SECCOMP_RET_*) for this action,
    /// combining with errno_ret if this is an Errno action.
    pub const fn bpf_ret_value(&self, errno_ret: Option<u32>) -> u32 {
        match self {
            Self::KillProcess => 0x8000_0000,
            Self::KillThread | Self::Kill => 0x0000_0000,
            Self::Trap => 0x0003_0000,
            Self::Errno => {
                let err = match errno_ret {
                    Some(e) => e & 0x0000_FFFF,
                    None => 1, // Default EPERM
                };
                0x0005_0000 | err
            }
            Self::Trace => 0x7ff0_0000,
            Self::Log => 0x7ffc_0000,
            Self::Notify => 0x7fc0_0000,
            Self::Allow => 0x7fff_0000,
        }
    }
}

impl fmt::Display for SeccompAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for SeccompAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SeccompAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Self>().map_err(de::Error::custom)
    }
}
