use std::path::PathBuf;
use thiserror::Error;

/// Errors produced during OCI image archive decoding, path sanitization, and whiteout processing.
#[derive(Debug, Error)]
pub enum ImageError {
    #[error("Path traversal rejected: entry '{path}' escapes rootfs boundary '{rootfs}'")]
    PathTraversal { path: PathBuf, rootfs: PathBuf },

    #[error("Symlink escape rejected: target '{target}' resolves outside rootfs '{rootfs}'")]
    SymlinkEscape { target: PathBuf, rootfs: PathBuf },

    #[error("Malformed OCI whiteout marker: '{0}'")]
    MalformedWhiteout(String),

    #[error("Unsupported archive entry type for '{path}'")]
    UnsupportedEntryType { path: PathBuf },

    #[error("Decompression limit exceeded: exceeded {limit} bytes")]
    DecompressionLimitExceeded { limit: u64 },

    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("Unsupported archive compression format")]
    UnsupportedCompression,

    #[error("Destination rootfs already exists: '{0}'")]
    DestinationAlreadyExists(PathBuf),

    #[error("Blob size mismatch for '{path}': expected {expected} bytes, found {actual} bytes")]
    BlobSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("Blob digest mismatch for '{path}': expected '{expected}', found actual '{actual}'")]
    BlobDigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("Invalid layer digest '{0}': digest must not be empty and must specify sha256 algorithm (sha256:<64-hex>)")]
    InvalidDigest(String),

    #[error("Invalid UID {uid} or GID {gid}: value cannot be represented safely")]
    InvalidOwnership { uid: u64, gid: u64 },

    #[error("Corrupt archive data: {0}")]
    CorruptArchive(String),

    #[error("Storage error: {0}")]
    Store(#[from] tavik_store::StoreError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
