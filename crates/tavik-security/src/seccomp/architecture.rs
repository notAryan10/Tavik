use crate::error::SecurityError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Standard Linux audit architecture identifiers for seccomp filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeccompArchitecture {
    /// ARM 64-bit architecture (AUDIT_ARCH_AARCH64 = 0xC00000B7)
    Aarch64,
    /// x86 64-bit architecture (AUDIT_ARCH_X86_64 = 0xC000003E)
    X86_64,
}

impl std::str::FromStr for SeccompArchitecture {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "SCMP_ARCH_AARCH64" | "AARCH64" | "ARM64" => Ok(Self::Aarch64),
            "SCMP_ARCH_X86_64" | "X86_64" | "AMD64" | "X64" => Ok(Self::X86_64),
            _ => Err(SecurityError::UnsupportedArchitecture(s.to_string())),
        }
    }
}

impl SeccompArchitecture {
    /// Returns the canonical OCI architecture string name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aarch64 => "SCMP_ARCH_AARCH64",
            Self::X86_64 => "SCMP_ARCH_X86_64",
        }
    }

    /// Returns the Linux audit architecture constant passed in `seccomp_data.arch`.
    pub const fn audit_arch(&self) -> u32 {
        match self {
            // AUDIT_ARCH_AARCH64 = (EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
            // EM_AARCH64 = 183 (0xb7), __AUDIT_ARCH_64BIT = 0x80000000, __AUDIT_ARCH_LE = 0x40000000
            Self::Aarch64 => 0xC000_00B7,

            // AUDIT_ARCH_X86_64 = (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
            // EM_X86_64 = 62 (0x3e), __AUDIT_ARCH_64BIT = 0x80000000, __AUDIT_ARCH_LE = 0x40000000
            Self::X86_64 => 0xC000_003E,
        }
    }

    /// Detects the host machine's architecture at runtime.
    pub const fn current() -> Option<Self> {
        if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else {
            None
        }
    }
}

impl fmt::Display for SeccompArchitecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for SeccompArchitecture {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SeccompArchitecture {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Self>().map_err(de::Error::custom)
    }
}
