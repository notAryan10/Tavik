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

    #[error("Corrupt archive data: {0}")]
    CorruptArchive(String),

    #[error("Storage error: {0}")]
    Store(#[from] tavik_store::StoreError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
