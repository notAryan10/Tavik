use std::path::PathBuf;

/// Represents an OCI layer blob ready for sequential rootfs extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub digest: String,
    pub blob_path: PathBuf,
    pub size: u64,
}
