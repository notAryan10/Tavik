use std::path::PathBuf;

/// Represents an OCI layer blob ready for sequential rootfs extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub digest: String,
    pub blob_path: PathBuf,
    pub size: u64,
}

impl Layer {
    pub fn new(digest: impl Into<String>, blob_path: impl Into<PathBuf>, size: u64) -> Self {
        Self {
            digest: digest.into(),
            blob_path: blob_path.into(),
            size,
        }
    }
}
