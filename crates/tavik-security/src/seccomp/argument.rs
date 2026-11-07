use crate::error::SecurityError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Comparison operators for OCI seccomp argument filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeccompOperator {
    /// Not equal (!=) (SCMP_CMP_NE)
    NotEqual,
    /// Less than (<) (SCMP_CMP_LT)
    LessThan,
    /// Less than or equal to (<=) (SCMP_CMP_LE)
    LessOrEqual,
    /// Equal (==) (SCMP_CMP_EQ)
    Equal,
    /// Greater than or equal to (>=) (SCMP_CMP_GE)
    GreaterOrEqual,
    /// Greater than (>) (SCMP_CMP_GT)
    GreaterThan,
    /// Masked equality ((arg & value_two) == value) (SCMP_CMP_MASKED_EQ)
    MaskedEqual,
}

impl std::str::FromStr for SeccompOperator {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "SCMP_CMP_NE" | "NE" | "!=" => Ok(Self::NotEqual),
            "SCMP_CMP_LT" | "LT" | "<" => Ok(Self::LessThan),
            "SCMP_CMP_LE" | "LE" | "<=" => Ok(Self::LessOrEqual),
            "SCMP_CMP_EQ" | "EQ" | "==" => Ok(Self::Equal),
            "SCMP_CMP_GE" | "GE" | ">=" => Ok(Self::GreaterOrEqual),
            "SCMP_CMP_GT" | "GT" | ">" => Ok(Self::GreaterThan),
            "SCMP_CMP_MASKED_EQ" | "MASKED_EQ" => Ok(Self::MaskedEqual),
            _ => Err(SecurityError::UnsupportedOperator(s.to_string())),
        }
    }
}

impl SeccompOperator {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotEqual => "SCMP_CMP_NE",
            Self::LessThan => "SCMP_CMP_LT",
            Self::LessOrEqual => "SCMP_CMP_LE",
            Self::Equal => "SCMP_CMP_EQ",
            Self::GreaterOrEqual => "SCMP_CMP_GE",
            Self::GreaterThan => "SCMP_CMP_GT",
            Self::MaskedEqual => "SCMP_CMP_MASKED_EQ",
        }
    }
}

impl fmt::Display for SeccompOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for SeccompOperator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SeccompOperator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Self>().map_err(de::Error::custom)
    }
}

/// An argument condition applied to a specific syscall parameter index (0..=5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompArg {
    /// 0-based syscall parameter index (Linux supports arguments 0 through 5).
    pub index: u32,

    /// Primary 64-bit comparison value.
    pub value: u64,

    /// Secondary 64-bit value (mask used for `SCMP_CMP_MASKED_EQ`).
    #[serde(default)]
    pub value_two: u64,

    /// The comparison operator.
    pub op: SeccompOperator,
}

impl SeccompArg {
    /// Validates that the argument parameter index is within the valid Linux range 0..=5.
    pub fn validate(&self) -> Result<(), SecurityError> {
        if self.index > 5 {
            return Err(SecurityError::InvalidConfiguration(format!(
                "Invalid seccomp argument index {}: Linux syscalls only have arguments 0 through 5",
                self.index
            )));
        }
        Ok(())
    }
}
