use std::path::{Path, PathBuf};

/// Prefix for standard OCI whiteout files.
pub const WHITEOUT_PREFIX: &str = ".wh.";

/// Special filename indicating an opaque directory (all lower-layer entries hidden).
pub const WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

/// Represents an OCI whiteout marker encountered during layer unpacking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whiteout {
    /// Specific file or directory to remove from lower layers.
    Entry(PathBuf),
    /// Directory whose entire contents from lower layers must be hidden.
    Opaque(PathBuf),
}

impl Whiteout {
    /// Inspects an entry's path and determines if it represents an OCI whiteout marker.
    pub fn parse(path: &Path) -> Option<Self> {
        let file_name = path.file_name()?.to_str()?;
        let parent = path.parent().unwrap_or_else(|| Path::new(""));

        if file_name == WHITEOUT_OPAQUE {
            Some(Self::Opaque(parent.to_path_buf()))
        } else {
            file_name
                .strip_prefix(WHITEOUT_PREFIX)
                .map(|target_name| Self::Entry(parent.join(target_name)))
        }
    }
}
