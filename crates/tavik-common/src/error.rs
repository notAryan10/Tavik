use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize, Clone)]
pub enum TavikError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Daemon not running or unreachable at socket: {0}")]
    DaemonUnreachable(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid state transition: {0}")]
    InvalidState(String),

    #[error("Process execution error: {0}")]
    Execution(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Unsupported platform or feature: {0}")]
    Unsupported(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for TavikError {
    fn from(err: std::io::Error) -> Self {
        TavikError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for TavikError {
    fn from(err: serde_json::Error) -> Self {
        TavikError::Serialization(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, TavikError>;
