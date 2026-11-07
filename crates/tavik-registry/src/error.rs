use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Invalid image reference '{0}': {1}")]
    InvalidReference(String, String),

    #[error("Invalid digest format: '{0}' (expected algorithm:hex)")]
    InvalidDigest(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Manifest not found for '{reference}': status {status}")]
    ManifestNotFound { reference: String, status: u16 },

    #[error("Blob not found for digest '{digest}': status {status}")]
    BlobNotFound { digest: String, status: u16 },

    #[error("Unsupported media type: '{0}'")]
    UnsupportedMediaType(String),

    #[error("Digest mismatch for '{digest}': expected {expected}, actual {actual}")]
    DigestMismatch {
        digest: String,
        expected: String,
        actual: String,
    },

    #[error("Platform '{os}/{arch}' not found in manifest index")]
    PlatformNotFound { os: String, arch: String },

    #[error("Registry protocol error: {0}")]
    Protocol(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
