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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlobStatSnapshot {
    ino: libc::ino_t,
    dev: libc::dev_t,
    size: libc::off_t,
    mtime: libc::time_t,
    mtime_nsec: libc::c_long,
    ctime: libc::time_t,
    ctime_nsec: libc::c_long,
}

impl BlobStatSnapshot {
    fn from_stat(s: &libc::stat) -> Self {
        Self {
            ino: s.st_ino,
            dev: s.st_dev,
            size: s.st_size,
            mtime: s.st_mtime,
            #[cfg(target_os = "macos")]
            mtime_nsec: s.st_mtime_nsec,
            #[cfg(target_os = "linux")]
            mtime_nsec: s.st_mtime_nsec,
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            mtime_nsec: 0,
            ctime: s.st_ctime,
            #[cfg(target_os = "macos")]
            ctime_nsec: s.st_ctime_nsec,
            #[cfg(target_os = "linux")]
            ctime_nsec: s.st_ctime_nsec,
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            ctime_nsec: 0,
        }
    }
}

fn validate_layer_digest(digest: &str) -> Result<&str, ImageError> {
    if digest.trim().is_empty() {
        return Err(ImageError::InvalidDigest(
            "layer digest is empty".to_string(),
        ));
    }
    let (algo, hex_str) = digest
        .split_once(':')
        .ok_or_else(|| ImageError::InvalidDigest(digest.to_string()))?;

    if !algo.eq_ignore_ascii_case("sha256") {
        return Err(ImageError::InvalidDigest(format!(
            "unsupported digest algorithm '{algo}': only 'sha256' is supported"
        )));
    }

    if hex_str.len() != 64 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ImageError::InvalidDigest(format!(
            "invalid sha256 hex length or characters: '{digest}'"
        )));
    }

    Ok(hex_str)
}

fn compute_and_verify_blob_digest(
    file: &std::fs::File,
    expected_hex: &str,
    expected_size: u64,
    blob_path: &Path,
) -> Result<String, ImageError> {
    (&*file).seek(SeekFrom::Start(0)).map_err(ImageError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut reader = file;
    let mut total_read = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(ImageError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total_read += n as u64;
    }

    if expected_size > 0 && total_read != expected_size {
        return Err(ImageError::BlobSizeMismatch {
            path: blob_path.to_path_buf(),
            expected: expected_size,
            actual: total_read,
        });
    }

    let actual_hex = hex::encode(hasher.finalize());
    let actual_digest = format!("sha256:{}", actual_hex);

    if !actual_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(ImageError::BlobDigestMismatch {
            path: blob_path.to_path_buf(),
            expected: format!("sha256:{}", expected_hex),
            actual: actual_digest,
        });
    }

    (&*file).seek(SeekFrom::Start(0)).map_err(ImageError::Io)?;
    Ok(actual_digest)
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
#[derive(Clone, Default)]
pub struct ImageUnpacker {
    decompression_limit: Option<u64>,
    #[doc(hidden)]
    pub mid_pass_hook: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for ImageUnpacker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageUnpacker")
            .field("decompression_limit", &self.decompression_limit)
            .field("has_mid_pass_hook", &self.mid_pass_hook.is_some())
            .finish()
    }
}

impl ImageUnpacker {
    pub fn new() -> Self {
        Self {
            decompression_limit: None,
            mid_pass_hook: None,
        }
    }

    pub fn with_decompression_limit(mut self, limit: u64) -> Self {
        self.decompression_limit = Some(limit);
        self
    }

    #[doc(hidden)]
    pub fn set_mid_pass_hook<F: Fn() + Send + Sync + 'static>(&mut self, hook: F) {
        self.mid_pass_hook = Some(std::sync::Arc::new(hook));
    }

    /// Unpacks a single layer archive into the target rootfs directory.
    pub fn unpack_layer(&self, layer: &Layer, rootfs: &Path) -> Result<(), ImageError> {
        info!(
            "Unpacking layer '{}' into '{}'...",
            layer.digest,
            rootfs.display()
        );

        // 1. Mandatory SHA-256 digest format and algorithm validation
        let expected_hex = validate_layer_digest(&layer.digest)?;

        // 2. Open layer blob exactly once using O_RDONLY | O_CLOEXEC | O_NOFOLLOW
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

        // 3. Verify with fstat that it is a regular file
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

        // 4. Validate the expected compressed blob size
        let actual_size = stat_buf.st_size as u64;
        if layer.size > 0 && actual_size != layer.size {
            return Err(ImageError::BlobSizeMismatch {
                path: layer.blob_path.clone(),
                expected: layer.size,
                actual: actual_size,
            });
        }

        // Take snapshot of high-resolution timestamps, ctime, size, and inode before Pass 1
        let snap_before_pass1 = BlobStatSnapshot::from_stat(&stat_buf);

        // 5. Initial streaming SHA-256 digest verification before Pass 1
        compute_and_verify_blob_digest(&blob_file, expected_hex, layer.size, &layer.blob_path)?;

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

        // If a mid-pass hook is registered (for testing concurrent mutation), invoke it now.
        if let Some(ref hook) = self.mid_pass_hook {
            hook();
        }

        // Ensure blob wasn't modified between passes (high-resolution timestamps, ctime, size, inode)
        let mut stat_buf2: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret2 = unsafe { libc::fstat(blob_file.as_raw_fd(), &mut stat_buf2) };
        if s_ret2 != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let snap_between_passes = BlobStatSnapshot::from_stat(&stat_buf2);
        if snap_between_passes != snap_before_pass1 {
            return Err(ImageError::CorruptArchive(format!(
                "Layer blob '{}' was modified between archive passes (high-resolution metadata changed)",
                layer.blob_path.display()
            )));
        }

        // Also check if the path on disk was replaced by opening it afresh
        let mid_check_file = std::fs::File::open(&layer.blob_path).map_err(ImageError::Io)?;
        let mut stat_buf_path: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret_path = unsafe { libc::fstat(mid_check_file.as_raw_fd(), &mut stat_buf_path) };
        if s_ret_path != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let snap_path = BlobStatSnapshot::from_stat(&stat_buf_path);
        if snap_path != snap_before_pass1 {
            return Err(ImageError::CorruptArchive(format!(
                "Layer blob '{}' was replaced or modified on disk between archive passes",
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

        // =========================================================================
        // Post-Pass-2 Validation: Ensure blob was not modified during Pass 2
        // =========================================================================
        let post_file = std::fs::File::open(&layer.blob_path).map_err(ImageError::Io)?;
        let mut stat_buf3: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret3 = unsafe { libc::fstat(post_file.as_raw_fd(), &mut stat_buf3) };
        if s_ret3 != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let snap_after_pass2 = BlobStatSnapshot::from_stat(&stat_buf3);
        if snap_after_pass2 != snap_before_pass1 {
            return Err(ImageError::CorruptArchive(format!(
                "Layer blob '{}' was modified during Pass 2 (high-resolution metadata changed)",
                layer.blob_path.display()
            )));
        }

        // Re-verify SHA-256 digest after Pass 2
        compute_and_verify_blob_digest(&post_file, expected_hex, layer.size, &layer.blob_path)?;

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

        // Reliable RAII Cleanup Guard for staging directory: constructed immediately after mkdirat succeeds
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

        // Explicitly enforce 0700 permissions on staging directory via fchmod (propagate errors)
        let staging_open = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_staging_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if staging_open < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fchmod(staging_open, 0o700) };
        let chmod_err = if ret != 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        let close_ret = unsafe { libc::close(staging_open) };
        if let Some(err) = chmod_err {
            return Err(ImageError::Io(err));
        }
        if close_ret != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        let staging_path = parent_path.join(&staging_name);

        // Apply layers sequentially in OCI layer order
        for layer in layers {
            self.unpacker.unpack_layer(layer, &staging_path)?;
        }

        // Ensure root staging directory permissions are accessible (0755) before publication (propagate errors)
        let staging_open = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_staging_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if staging_open < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }
        let mut root_stat: libc::stat = unsafe { std::mem::zeroed() };
        let s_ret = unsafe { libc::fstat(staging_open, &mut root_stat) };
        if s_ret != 0 {
            let stat_err = std::io::Error::last_os_error();
            unsafe { libc::close(staging_open) };
            return Err(ImageError::Io(stat_err));
        }
        if (root_stat.st_mode & 0o777) == 0o700 {
            let ret = unsafe { libc::fchmod(staging_open, 0o755) };
            let chmod_err = if ret != 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            let close_ret = unsafe { libc::close(staging_open) };
            if let Some(err) = chmod_err {
                return Err(ImageError::Io(err));
            }
            if close_ret != 0 {
                return Err(ImageError::Io(std::io::Error::last_os_error()));
            }
        } else {
            let close_ret = unsafe { libc::close(staging_open) };
            if close_ret != 0 {
                return Err(ImageError::Io(std::io::Error::last_os_error()));
            }
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
