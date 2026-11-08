use crate::error::ImageError;
use std::path::{Component, Path, PathBuf};

/// Prefix for standard OCI whiteout deletion markers.
pub const WHITEOUT_PREFIX: &str = ".wh.";

/// Special filename indicating an opaque directory marker.
pub const WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

/// Represents an OCI whiteout instruction parsed from an archive layer entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whiteout {
    /// Specific file or directory entry to remove from lower layers.
    Entry(PathBuf),
    /// Directory whose entire contents from lower layers must be made opaque.
    Opaque(PathBuf),
}

impl Whiteout {
    /// Parses an entry path into an OCI `Whiteout` marker, returning validated relative paths.
    ///
    /// Returns:
    /// - `Ok(Some(Whiteout::Opaque(parent)))`: if path ends in `.wh..wh..opq`
    /// - `Ok(Some(Whiteout::Entry(target)))`: if filename starts with `.wh.<name>`
    /// - `Ok(None)`: if the entry is an ordinary file/directory (not a whiteout)
    /// - `Err(ImageError::MalformedWhiteout)`: if marker is malformed (e.g. `.wh.`, traversal in name)
    /// - `Err(ImageError::PathTraversal)`: if parent directory path attempts traversal
    pub fn parse(entry_path: &Path) -> Result<Option<Self>, ImageError> {
        let file_name = match entry_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => return Ok(None),
        };

        if !file_name.starts_with(WHITEOUT_PREFIX) {
            return Ok(None);
        }

        // Validate parent directory components
        let raw_parent = entry_path.parent().unwrap_or_else(|| Path::new(""));
        let mut clean_parent = PathBuf::new();
        for comp in raw_parent.components() {
            match comp {
                Component::Normal(c) => clean_parent.push(c),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(ImageError::MalformedWhiteout(format!(
                        "Whiteout marker '{}' contains invalid parent directory components",
                        entry_path.display()
                    )));
                }
            }
        }

        if file_name == WHITEOUT_OPAQUE {
            // Root-level or nested opaque directory
            Ok(Some(Self::Opaque(clean_parent)))
        } else if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            // Reject malformed empty target (e.g. ".wh.")
            if target_name.is_empty() {
                return Err(ImageError::MalformedWhiteout(format!(
                    "Empty whiteout target in '{}'",
                    entry_path.display()
                )));
            }

            // Reject internal .wh..wh. prefixes that are not .wh..wh..opq
            if target_name.starts_with(WHITEOUT_PREFIX) {
                return Err(ImageError::MalformedWhiteout(format!(
                    "Invalid double-whiteout prefix in '{}'",
                    entry_path.display()
                )));
            }

            // Reject traversal in target name
            if target_name.contains('/')
                || target_name.contains('\\')
                || target_name == ".."
                || target_name == "."
            {
                return Err(ImageError::MalformedWhiteout(format!(
                    "Whiteout target '{}' contains path separator or traversal",
                    entry_path.display()
                )));
            }

            let target_path = clean_parent.join(target_name);
            Ok(Some(Self::Entry(target_path)))
        } else {
            Ok(None)
        }
    }
}
