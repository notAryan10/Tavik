use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Invalid digest format: '{0}' (expected sha256:<hex>)")]
    InvalidDigest(String),

    #[error("Unsupported digest algorithm: '{0}' (only sha256 is supported)")]
    UnsupportedAlgorithm(String),

    #[error("Blob not found: '{0}'")]
    BlobNotFound(String),

    #[error("Digest mismatch for '{digest}': expected {expected}, actual {actual}")]
    DigestMismatch {
        digest: String,
        expected: String,
        actual: String,
    },

    #[error("Size mismatch for '{digest}': expected {expected} bytes, actual {actual} bytes")]
    SizeMismatch {
        digest: String,
        expected: u64,
        actual: u64,
    },

    #[error("Image metadata error: {0}")]
    Metadata(String),

    #[error("Image not found: '{0}'")]
    ImageNotFound(String),

    #[error("Lock acquisition error: {0}")]
    Lock(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
