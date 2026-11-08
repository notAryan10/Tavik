use crate::error::ImageError;
use std::path::{Component, Path, PathBuf};

/// Validates that an archive entry relative path does not escape the destination rootfs.
/// Rejects:
/// 1. Absolute paths.
/// 2. Parent directory components (`..`).
/// 3. Root directory components.
pub fn sanitize_entry_path(rootfs: &Path, entry_path: &Path) -> Result<PathBuf, ImageError> {
    for comp in entry_path.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ImageError::PathTraversal {
                    path: entry_path.to_path_buf(),
                    rootfs: rootfs.to_path_buf(),
                });
            }
        }
    }

    let joined = rootfs.join(entry_path);
    Ok(joined)
}

/// Validates that a symlink target does not point outside the rootfs.
pub fn validate_symlink_target(
    rootfs: &Path,
    symlink_dir: &Path,
    target: &Path,
) -> Result<(), ImageError> {
    let resolved = if target.is_absolute() {
        // Absolute symlinks inside a container rootfs are relative to the rootfs root
        let stripped = target.strip_prefix("/").unwrap_or(target);
        rootfs.join(stripped)
    } else {
        symlink_dir.join(target)
    };

    // Normalize components
    let mut normalized = PathBuf::new();
    for comp in resolved.components() {
        match comp {
            Component::ParentDir => {
                // If attempting to pop past rootfs, reject
                if normalized == rootfs {
                    return Err(ImageError::SymlinkEscape {
                        target: target.to_path_buf(),
                        rootfs: rootfs.to_path_buf(),
                    });
                }
                normalized.pop();
            }
            Component::Normal(c) => normalized.push(c),
            Component::RootDir => normalized.push("/"),
            _ => {}
        }
    }

    if !normalized.starts_with(rootfs) {
        return Err(ImageError::SymlinkEscape {
            target: target.to_path_buf(),
            rootfs: rootfs.to_path_buf(),
        });
    }

    Ok(())
}
