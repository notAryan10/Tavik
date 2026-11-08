use crate::archive::ArchiveReader;
use crate::error::ImageError;
use crate::filesystem::{normalize_symlink_target, sanitize_entry_path, SafeDir};
use crate::layer::Layer;
use crate::whiteout::Whiteout;
use std::fs::File;
use std::path::{Path, PathBuf};
use tar::EntryType;
use tracing::{debug, info};

struct EntryMetadata {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
}

/// Layer unpacker that safely extracts layers and processes OCI whiteout markers.
#[derive(Debug, Clone, Default)]
pub struct ImageUnpacker {
    decompression_limit: Option<u64>,
}

impl ImageUnpacker {
    pub fn new() -> Self {
        Self {
            decompression_limit: None,
        }
    }

    pub fn with_decompression_limit(mut self, limit: u64) -> Self {
        self.decompression_limit = Some(limit);
        self
    }

    /// Unpacks a single layer archive into the target rootfs directory.
    pub fn unpack_layer(&self, layer: &Layer, rootfs: &Path) -> Result<(), ImageError> {
        info!(
            "Unpacking layer '{}' into '{}'...",
            layer.digest,
            rootfs.display()
        );

        // 1. Validate blob file existence, type, and size
        let metadata = std::fs::metadata(&layer.blob_path).map_err(ImageError::Io)?;
        if !metadata.is_file() {
            return Err(ImageError::CorruptArchive(format!(
                "Layer blob '{}' is not a regular file",
                layer.blob_path.display()
            )));
        }
        if layer.size > 0 && metadata.len() != layer.size {
            return Err(ImageError::BlobSizeMismatch {
                path: layer.blob_path.clone(),
                expected: layer.size,
                actual: metadata.len(),
            });
        }

        // =========================================================================
        // Pass 1: Validate entries, paths, symlink targets, and collect whiteouts
        // =========================================================================
        let blob_file_pass1 = File::open(&layer.blob_path).map_err(ImageError::Io)?;
        let (_format1, stream1) = ArchiveReader::open(blob_file_pass1, self.decompression_limit)?;
        let mut archive1 = tar::Archive::new(stream1);
        archive1.set_ignore_zeros(false);

        let mut whiteouts = Vec::new();

        for entry_res in archive1.entries().map_err(ImageError::Io)? {
            let entry = entry_res.map_err(|e| ImageError::CorruptArchive(e.to_string()))?;
            let path = entry
                .path()
                .map_err(|e| ImageError::CorruptArchive(e.to_string()))?
                .into_owned();

            // Validate path cannot escape rootfs
            sanitize_entry_path(rootfs, &path)?;

            // Validate entry type & symlink/hardlink targets
            let entry_type = entry.header().entry_type();
            match entry_type {
                EntryType::Regular | EntryType::Continuous | EntryType::Directory => {}
                EntryType::Symlink => {
                    let target = entry
                        .link_name()
                        .map_err(|e| ImageError::CorruptArchive(e.to_string()))?
                        .ok_or_else(|| {
                            ImageError::CorruptArchive(format!(
                                "Missing symlink target for '{}'",
                                path.display()
                            ))
                        })?;
                    let link_parent = path.parent().unwrap_or_else(|| Path::new(""));
                    normalize_symlink_target(rootfs, link_parent, &target)?;
                }
                EntryType::Link => {
                    let target = entry
                        .link_name()
                        .map_err(|e| ImageError::CorruptArchive(e.to_string()))?
                        .ok_or_else(|| {
                            ImageError::CorruptArchive(format!(
                                "Missing hard link target for '{}'",
                                path.display()
                            ))
                        })?;
                    sanitize_entry_path(rootfs, &target)?;
                }
                _ => {
                    return Err(ImageError::UnsupportedEntryType { path });
                }
            }

            if let Some(wh) = Whiteout::parse(&path)? {
                whiteouts.push(wh);
            }
        }

        // =========================================================================
        // Apply whiteouts to existing lower-layer rootfs
        // =========================================================================
        let safe_dir = SafeDir::open_rootfs(rootfs)?;
        for wh in &whiteouts {
            match wh {
                Whiteout::Entry(target) => {
                    debug!("Applying whiteout deletion: {}", target.display());
                    safe_dir.remove_entry_at(target)?;
                }
                Whiteout::Opaque(dir) => {
                    debug!("Applying opaque whiteout: {}", dir.display());
                    safe_dir.remove_dir_contents_at(dir)?;
                }
            }
        }

        // =========================================================================
        // Pass 2: Extract ordinary entries, skipping whiteouts
        // =========================================================================
        let blob_file_pass2 = File::open(&layer.blob_path).map_err(ImageError::Io)?;
        let (_format2, stream2) = ArchiveReader::open(blob_file_pass2, self.decompression_limit)?;
        let mut archive2 = tar::Archive::new(stream2);
        archive2.set_ignore_zeros(false);

        let mut deferred_hardlinks: Vec<(PathBuf, PathBuf, EntryMetadata)> = Vec::new();
        let mut deferred_dir_metadata: Vec<(PathBuf, EntryMetadata)> = Vec::new();

        for entry_res in archive2.entries().map_err(ImageError::Io)? {
            let mut entry = entry_res.map_err(|e| ImageError::CorruptArchive(e.to_string()))?;
            let path = entry
                .path()
                .map_err(|e| ImageError::CorruptArchive(e.to_string()))?
                .into_owned();

            // Skip whiteout markers during extraction
            if Whiteout::parse(&path)?.is_some() {
                continue;
            }

            let header = entry.header();
            let mode = header.mode().unwrap_or(0o644);
            let uid = header.uid().unwrap_or(0) as u32;
            let gid = header.gid().unwrap_or(0) as u32;
            let mtime = header.mtime().unwrap_or(0) as i64;
            let meta = EntryMetadata {
                mode,
                uid,
                gid,
                mtime,
            };

            let entry_type = header.entry_type();
            match entry_type {
                EntryType::Directory => {
                    safe_dir.prepare_for_entry(&path, true)?;
                    // Create with temporary writable permission to allow children extraction
                    safe_dir.mkdir_at(&path, 0o700)?;
                    deferred_dir_metadata.push((path, meta));
                }
                EntryType::Regular | EntryType::Continuous => {
                    safe_dir.prepare_for_entry(&path, false)?;
                    let mut file = safe_dir.open_file_at(
                        &path,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        mode,
                    )?;
                    std::io::copy(&mut entry, &mut file).map_err(ImageError::Io)?;
                    drop(file);
                    safe_dir.set_metadata_at(&path, Some(mode), uid, gid, mtime)?;
                }
                EntryType::Symlink => {
                    let target = entry
                        .link_name()
                        .map_err(|e| ImageError::CorruptArchive(e.to_string()))?
                        .ok_or_else(|| {
                            ImageError::CorruptArchive(format!(
                                "Missing symlink target for '{}'",
                                path.display()
                            ))
                        })?;
                    safe_dir.prepare_for_entry(&path, false)?;
                    safe_dir.symlink_at(&target, &path)?;
                    safe_dir.set_metadata_at(&path, None, uid, gid, mtime)?;
                }
                EntryType::Link => {
                    let target = entry
                        .link_name()
                        .map_err(|e| ImageError::CorruptArchive(e.to_string()))?
                        .ok_or_else(|| {
                            ImageError::CorruptArchive(format!(
                                "Missing hard link target for '{}'",
                                path.display()
                            ))
                        })?;
                    if safe_dir.exists_at(&target)? {
                        safe_dir.prepare_for_entry(&path, false)?;
                        safe_dir.hardlink_at(&target, &path)?;
                        safe_dir.set_metadata_at(&path, Some(mode), uid, gid, mtime)?;
                    } else {
                        // Forward reference: queue for post-pass-2 extraction
                        deferred_hardlinks.push((target.into_owned(), path, meta));
                    }
                }
                _ => unreachable!("Pass 1 already validated entry types"),
            }
        }

        // =========================================================================
        // Process deferred hard links
        // =========================================================================
        for (source, dest, meta) in deferred_hardlinks {
            if !safe_dir.exists_at(&source)? {
                return Err(ImageError::CorruptArchive(format!(
                    "Unresolved hard link forward reference: '{}' points to non-existent source '{}'",
                    dest.display(),
                    source.display()
                )));
            }
            safe_dir.prepare_for_entry(&dest, false)?;
            safe_dir.hardlink_at(&source, &dest)?;
            safe_dir.set_metadata_at(&dest, Some(meta.mode), meta.uid, meta.gid, meta.mtime)?;
        }

        // =========================================================================
        // Apply directory metadata in reverse hierarchical order (deepest first)
        // =========================================================================
        deferred_dir_metadata.sort_by(|(p1, _), (p2, _)| {
            let c1 = p1.components().count();
            let c2 = p2.components().count();
            c2.cmp(&c1) // Descending: deepest first
        });

        for (dir_path, meta) in deferred_dir_metadata {
            safe_dir.set_metadata_at(&dir_path, Some(meta.mode), meta.uid, meta.gid, meta.mtime)?;
        }

        Ok(())
    }
}

/// Builds a merged root filesystem from an ordered slice of OCI layers.
#[derive(Debug, Clone, Default)]
pub struct RootfsBuilder {
    unpacker: ImageUnpacker,
}

impl RootfsBuilder {
    pub fn new() -> Self {
        Self {
            unpacker: ImageUnpacker::new(),
        }
    }

    pub fn with_decompression_limit(mut self, limit: u64) -> Self {
        self.unpacker = self.unpacker.with_decompression_limit(limit);
        self
    }

    /// Sequentially applies layers into the destination rootfs.
    pub fn build_rootfs(
        &self,
        layers: &[Layer],
        dest_rootfs: &Path,
    ) -> Result<PathBuf, ImageError> {
        info!(
            "Building rootfs from {} layers into '{}'...",
            layers.len(),
            dest_rootfs.display()
        );

        // 1. Avoid overwriting an existing destination unexpectedly
        if dest_rootfs.exists() {
            if let Ok(mut read_dir) = std::fs::read_dir(dest_rootfs) {
                if read_dir.next().is_some() {
                    return Err(ImageError::DestinationAlreadyExists(
                        dest_rootfs.to_path_buf(),
                    ));
                }
            } else {
                return Err(ImageError::DestinationAlreadyExists(
                    dest_rootfs.to_path_buf(),
                ));
            }
        }

        // 2. Ensure parent directory exists and is trusted
        let parent_dir = dest_rootfs.parent().unwrap_or_else(|| Path::new("."));
        if !parent_dir.exists() {
            std::fs::create_dir_all(parent_dir).map_err(ImageError::Io)?;
        }

        // 3. Create private staging rootfs in parent directory (guarantees same mount/device for atomic rename)
        let staging_name = format!(".staging-rootfs-{}", uuid::Uuid::new_v4());
        let staging_rootfs = parent_dir.join(staging_name);
        std::fs::create_dir_all(&staging_rootfs).map_err(ImageError::Io)?;

        // RAII Cleanup Guard for staging directory
        struct StagingGuard<'a> {
            path: &'a Path,
            active: bool,
        }
        impl<'a> Drop for StagingGuard<'a> {
            fn drop(&mut self) {
                if self.active && self.path.exists() {
                    let _ = std::fs::remove_dir_all(self.path);
                }
            }
        }
        let mut guard = StagingGuard {
            path: &staging_rootfs,
            active: true,
        };

        // 4. Apply layers sequentially in OCI layer order
        for layer in layers {
            self.unpacker.unpack_layer(layer, &staging_rootfs)?;
        }

        // 5. Publish completed rootfs atomically
        if dest_rootfs.exists() {
            std::fs::remove_dir(dest_rootfs).map_err(ImageError::Io)?;
        }
        std::fs::rename(&staging_rootfs, dest_rootfs).map_err(ImageError::Io)?;

        // Disarm guard since staging succeeded and was moved to dest_rootfs
        guard.active = false;

        Ok(dest_rootfs.to_path_buf())
    }
}
