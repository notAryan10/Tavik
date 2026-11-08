use crate::archive::ArchiveReader;
use crate::error::ImageError;
use crate::filesystem::{normalize_symlink_target, sanitize_entry_path, SafeDir};
use crate::layer::Layer;
use crate::whiteout::Whiteout;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use tar::EntryType;
use tracing::{debug, info};

struct EntryMetadata {
    mode: u32,
    uid: u64,
    gid: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

fn rename_no_replace(
    parent_fd: RawFd,
    staging_name: &CString,
    dest_name: &CString,
    dest_path: &Path,
) -> Result<(), ImageError> {
    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::renameat2(
            parent_fd,
            staging_name.as_ptr(),
            parent_fd,
            dest_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    #[cfg(target_os = "macos")]
    let ret = unsafe {
        extern "C" {
            fn renameatx_np(
                olddirfd: libc::c_int,
                oldpath: *const libc::c_char,
                newdirfd: libc::c_int,
                newpath: *const libc::c_char,
                flags: libc::c_uint,
            ) -> libc::c_int;
        }
        const RENAME_EXCL: libc::c_uint = 0x00000004;
        renameatx_np(
            parent_fd,
            staging_name.as_ptr(),
            parent_fd,
            dest_name.as_ptr(),
            RENAME_EXCL,
        )
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("Unsupported OS for atomic rename");

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Err(ImageError::DestinationAlreadyExists(
                dest_path.to_path_buf(),
            ));
        }
        return Err(ImageError::Io(err));
    }

    Ok(())
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

        // 1. Open layer blob exactly once using O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        let c_blob_path = CString::new(layer.blob_path.as_os_str().as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let raw_blob_fd = unsafe {
            libc::open(
                c_blob_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw_blob_fd < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let blob_file = unsafe { std::fs::File::from_raw_fd(raw_blob_fd) };

        // 2. Verify with fstat that it is a regular file
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret = unsafe { libc::fstat(blob_file.as_raw_fd(), &mut stat_buf) };
        if s_ret != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(ImageError::CorruptArchive(format!(
                "Layer blob '{}' is not a regular file",
                layer.blob_path.display()
            )));
        }

        // 3. Validate the expected compressed blob size
        let actual_size = stat_buf.st_size as u64;
        if layer.size > 0 && actual_size != layer.size {
            return Err(ImageError::BlobSizeMismatch {
                path: layer.blob_path.clone(),
                expected: layer.size,
                actual: actual_size,
            });
        }

        // 4. Verify Layer.digest against the actual compressed blob bytes (streaming in 64KB chunks)
        if !layer.digest.is_empty() {
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            let mut reader = &blob_file;
            let mut total_read = 0u64;
            loop {
                let n = reader.read(&mut buf).map_err(ImageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                total_read += n as u64;
            }

            if layer.size > 0 && total_read != layer.size {
                return Err(ImageError::BlobSizeMismatch {
                    path: layer.blob_path.clone(),
                    expected: layer.size,
                    actual: total_read,
                });
            }

            let actual_hex = hex::encode(hasher.finalize());
            let actual_digest = format!("sha256:{}", actual_hex);

            let expected_hex = layer
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&layer.digest);
            if !actual_hex.eq_ignore_ascii_case(expected_hex) {
                return Err(ImageError::BlobDigestMismatch {
                    path: layer.blob_path.clone(),
                    expected: layer.digest.clone(),
                    actual: actual_digest,
                });
            }
        }

        // Rewind to beginning of the blob
        (&blob_file)
            .seek(SeekFrom::Start(0))
            .map_err(ImageError::Io)?;

        // =========================================================================
        // Pass 1: Validate entries, paths, symlink targets, and collect whiteouts
        // =========================================================================
        let pass1_file = blob_file.try_clone().map_err(ImageError::Io)?;
        let (_format1, stream1) = ArchiveReader::open(pass1_file, self.decompression_limit)?;
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

        // Rewind blob file descriptor to start for Pass 2
        (&blob_file)
            .seek(SeekFrom::Start(0))
            .map_err(ImageError::Io)?;

        // Ensure blob wasn't modified between passes
        let mut stat_buf2: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret2 = unsafe { libc::fstat(blob_file.as_raw_fd(), &mut stat_buf2) };
        if s_ret2 != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        if stat_buf2.st_ino != stat_buf.st_ino
            || stat_buf2.st_size != stat_buf.st_size
            || stat_buf2.st_mtime != stat_buf.st_mtime
        {
            return Err(ImageError::CorruptArchive(format!(
                "Layer blob '{}' was modified between archive passes",
                layer.blob_path.display()
            )));
        }

        // =========================================================================
        // Pass 2: Extract ordinary entries, skipping whiteouts
        // =========================================================================
        let (_format2, stream2) = ArchiveReader::open(blob_file, self.decompression_limit)?;
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

            let (mode, uid, gid, mtime_sec, entry_type) = {
                let header = entry.header();
                (
                    header.mode().unwrap_or(0o644),
                    header.uid().unwrap_or(0),
                    header.gid().unwrap_or(0),
                    header.mtime().unwrap_or(0) as i64,
                    header.entry_type(),
                )
            };
            let mut mtime_nsec = 0i64;

            // Preserve supported PAX subsecond timestamp precision if available
            if let Ok(Some(pax)) = entry.pax_extensions() {
                for ext in pax.flatten() {
                    if ext.key() == Ok("mtime") {
                        if let Ok(val) = ext.value() {
                            if let Some((_, frac)) = val.split_once('.') {
                                let mut frac_str = frac.to_string();
                                if frac_str.len() > 9 {
                                    frac_str.truncate(9);
                                }
                                while frac_str.len() < 9 {
                                    frac_str.push('0');
                                }
                                if let Ok(ns) = frac_str.parse::<i64>() {
                                    mtime_nsec = ns;
                                }
                            }
                        }
                    }
                }
            }

            // Reject invalid UID/GID values that cannot be represented safely in POSIX
            if uid > (u32::MAX - 1) as u64 || gid > (u32::MAX - 1) as u64 {
                return Err(ImageError::InvalidOwnership { uid, gid });
            }

            let meta = EntryMetadata {
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
            };
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
                    safe_dir.set_metadata_at(&path, Some(mode), uid, gid, mtime_sec, mtime_nsec)?;
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
                    safe_dir.set_metadata_at(&path, None, uid, gid, mtime_sec, mtime_nsec)?;
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
                        safe_dir.set_metadata_at(
                            &path,
                            Some(mode),
                            uid,
                            gid,
                            mtime_sec,
                            mtime_nsec,
                        )?;
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
            safe_dir.set_metadata_at(
                &dest,
                Some(meta.mode),
                meta.uid,
                meta.gid,
                meta.mtime_sec,
                meta.mtime_nsec,
            )?;
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
            safe_dir.set_metadata_at(
                &dir_path,
                Some(meta.mode),
                meta.uid,
                meta.gid,
                meta.mtime_sec,
                meta.mtime_nsec,
            )?;
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

    /// Sequentially applies layers into the destination rootfs using descriptor-relative staging and atomic publication.
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

        let parent_path = dest_rootfs.parent().unwrap_or_else(|| Path::new("."));
        let dest_name = dest_rootfs.file_name().ok_or_else(|| {
            ImageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid dest_rootfs path",
            ))
        })?;

        // Ensure parent directory exists
        if !parent_path.exists() {
            std::fs::create_dir_all(parent_path).map_err(ImageError::Io)?;
        }

        // Open parent directory descriptor with O_RDONLY | O_DIRECTORY | O_CLOEXEC
        let c_parent_path = CString::new(parent_path.as_os_str().as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let parent_raw_fd = unsafe {
            libc::open(
                c_parent_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if parent_raw_fd < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let parent_fd = unsafe { OwnedFd::from_raw_fd(parent_raw_fd) };

        // Detect existing destinations without following symlinks (detects files, dirs, and dangling symlinks)
        let c_dest_name = CString::new(dest_name.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let mut dest_stat: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                c_dest_name.as_ptr(),
                &mut dest_stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if s_ret == 0 {
            // Destination already exists; never remove an existing destination
            return Err(ImageError::DestinationAlreadyExists(
                dest_rootfs.to_path_buf(),
            ));
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(ImageError::Io(err));
            }
        }

        // Create staging directory descriptor-relatively with explicit 0700 permissions
        let staging_name = format!(".staging-rootfs-{}", uuid::Uuid::new_v4());
        let c_staging_name = CString::new(staging_name.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let mk_ret =
            unsafe { libc::mkdirat(parent_fd.as_raw_fd(), c_staging_name.as_ptr(), 0o700) };
        if mk_ret != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        // Explicitly enforce 0700 permissions on staging directory via fchmod
        let staging_open = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_staging_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if staging_open >= 0 {
            unsafe { libc::fchmod(staging_open, 0o700) };
            unsafe { libc::close(staging_open) };
        }

        // Reliable RAII Cleanup Guard for staging directory
        struct StagingGuard {
            parent_fd: RawFd,
            staging_name: CString,
            active: bool,
        }
        impl Drop for StagingGuard {
            fn drop(&mut self) {
                if self.active {
                    let raw_staging = unsafe {
                        libc::openat(
                            self.parent_fd,
                            self.staging_name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if raw_staging >= 0 {
                        let _ = SafeDir::remove_dir_contents_fd(raw_staging);
                        unsafe { libc::close(raw_staging) };
                    }
                    unsafe {
                        libc::unlinkat(
                            self.parent_fd,
                            self.staging_name.as_ptr(),
                            libc::AT_REMOVEDIR,
                        );
                    }
                }
            }
        }
        let mut guard = StagingGuard {
            parent_fd: parent_fd.as_raw_fd(),
            staging_name: c_staging_name.clone(),
            active: true,
        };

        let staging_path = parent_path.join(&staging_name);

        // Apply layers sequentially in OCI layer order
        for layer in layers {
            self.unpacker.unpack_layer(layer, &staging_path)?;
        }

        // Ensure root staging directory permissions are accessible (0755) before publication
        let staging_open = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_staging_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if staging_open >= 0 {
            let mut root_stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(staging_open, &mut root_stat) } == 0 {
                // If staging root is still 0700, change to 0755 so container root is accessible
                if (root_stat.st_mode & 0o777) == 0o700 {
                    unsafe { libc::fchmod(staging_open, 0o755) };
                }
            }
            unsafe { libc::close(staging_open) };
        }

        // Publish completed rootfs with atomic no-replace semantics
        rename_no_replace(
            parent_fd.as_raw_fd(),
            &c_staging_name,
            &c_dest_name,
            dest_rootfs,
        )?;

        // Disarm guard since staging succeeded and was published to dest_rootfs
        guard.active = false;

        Ok(dest_rootfs.to_path_buf())
    }
}
