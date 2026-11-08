use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("Path traversal rejected: entry '{path}' resolves outside rootfs '{rootfs}'")]
    PathTraversal { path: PathBuf, rootfs: PathBuf },

    #[error("Symlink escape rejected: target '{target}' resolves outside rootfs '{rootfs}'")]
    SymlinkEscape { target: PathBuf, rootfs: PathBuf },

    #[error("Unsupported archive entry type for '{path}'")]
    UnsupportedEntryType { path: PathBuf },

    #[error("Decompression limit exceeded: exceeded {limit} bytes")]
    DecompressionLimitExceeded { limit: u64 },

    #[error("Unsupported archive compression format")]
    UnsupportedCompression,

    #[error("Corrupt archive: {0}")]
    CorruptArchive(String),

    #[error("Storage error: {0}")]
    Store(#[from] tavik_store::StoreError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
