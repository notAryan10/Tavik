use crate::error::ImageError;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};

/// Sanitizes an archive entry path to ensure it cannot escape the extraction rootfs.
///
/// Rejects:
/// - Absolute paths (starting with `/`)
/// - Parent directory traversal (`..`)
/// - Platform prefixes (e.g. Windows drive letters)
/// - Empty paths
pub fn sanitize_entry_path(rootfs: &Path, entry_path: &Path) -> Result<PathBuf, ImageError> {
    let mut normalized = PathBuf::new();
    let mut has_components = false;

    for comp in entry_path.components() {
        match comp {
            Component::Normal(c) => {
                normalized.push(c);
                has_components = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ImageError::PathTraversal {
                    path: entry_path.to_path_buf(),
                    rootfs: rootfs.to_path_buf(),
                });
            }
        }
    }

    if !has_components {
        return Err(ImageError::PathTraversal {
            path: entry_path.to_path_buf(),
            rootfs: rootfs.to_path_buf(),
        });
    }

    Ok(rootfs.join(normalized))
}

/// Normalizes and validates symlink targets within an OCI container rootfs.
///
/// Rules:
/// - Absolute container symlinks (e.g. `/bin/busybox`) are valid inside container namespaces;
///   they are normalized relative to container root (`/`) without escaping.
/// - Relative symlinks (e.g. `../lib/libm.so`) are resolved relative to `link_dir_rel` (the directory
///   containing the link, relative to rootfs).
/// - If a relative or absolute symlink attempts to traverse above the container root,
///   it is strictly rejected with `ImageError::SymlinkEscape`.
pub fn normalize_symlink_target(
    rootfs: &Path,
    link_dir_rel: &Path,
    target: &Path,
) -> Result<PathBuf, ImageError> {
    if target.as_os_str().is_empty() {
        return Err(ImageError::SymlinkEscape {
            target: target.to_path_buf(),
            rootfs: rootfs.to_path_buf(),
        });
    }

    if target.is_absolute() {
        // Container absolute symlink: normalize starting from container root '/'
        let mut container_path = PathBuf::from("/");
        for comp in target.components() {
            match comp {
                Component::Normal(c) => container_path.push(c),
                Component::ParentDir => {
                    // In POSIX root, '/..' stays '/'
                    if container_path != Path::new("/") {
                        container_path.pop();
                    }
                }
                Component::RootDir | Component::CurDir => {}
                Component::Prefix(_) => {
                    return Err(ImageError::SymlinkEscape {
                        target: target.to_path_buf(),
                        rootfs: rootfs.to_path_buf(),
                    });
                }
            }
        }

        // Return container-normalized path (e.g. "/bin/busybox")
        Ok(container_path)
    } else {
        // Relative symlink: resolve starting from link's parent directory
        let mut resolved = link_dir_rel.to_path_buf();
        for comp in target.components() {
            match comp {
                Component::Normal(c) => resolved.push(c),
                Component::ParentDir => {
                    if resolved.as_os_str().is_empty() {
                        // Traversal escapes above container root!
                        return Err(ImageError::SymlinkEscape {
                            target: target.to_path_buf(),
                            rootfs: rootfs.to_path_buf(),
                        });
                    }
                    resolved.pop();
                }
                Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) => {
                    return Err(ImageError::SymlinkEscape {
                        target: target.to_path_buf(),
                        rootfs: rootfs.to_path_buf(),
                    });
                }
            }
        }

        Ok(target.to_path_buf())
    }
}

// -----------------------------------------------------------------------------
// Directory-Descriptor-Relative Filesystem Primitives
// -----------------------------------------------------------------------------
//
// SECURITY NOTICE:
// Lexical path validation alone CANNOT prevent Time-of-Check to Time-of-Use (TOCTOU)
// symlink races during archive extraction (for example, if a crafted archive introduces
// a symlink in an earlier entry that subsequent path lookups inadvertently follow).
//
// To achieve defense-in-depth, subsequent layer extraction must use directory-descriptor-relative
// operations (openat, mkdirat, symlinkat) with O_NOFOLLOW / AT_SYMLINK_NOFOLLOW and refuse
// to follow intermediate symlinks. tar::Archive::unpack() is intentionally forbidden.

enum ParentDir<'a> {
    Root(&'a OwnedFd),
    Descendant(OwnedFd),
}

impl<'a> ParentDir<'a> {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            ParentDir::Root(fd) => fd.as_raw_fd(),
            ParentDir::Descendant(fd) => fd.as_raw_fd(),
        }
    }
}

/// A safe directory descriptor wrapper for descriptor-relative filesystem operations.
#[derive(Debug)]
pub struct SafeDir {
    fd: OwnedFd,
    path: PathBuf,
}

impl SafeDir {
    /// Opens the rootfs directory with `O_DIRECTORY | O_CLOEXEC`.
    pub fn open_rootfs(rootfs: &Path) -> Result<Self, ImageError> {
        let c_path = CString::new(rootfs.as_os_str().as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let raw_fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self {
            fd,
            path: rootfs.to_path_buf(),
        })
    }

    /// Returns the rootfs directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the underlying raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Validates that a path is relative to the rootfs and does not attempt traversal.
    /// Rejects empty paths, absolute paths, parent directory components (`..`), and platform prefixes.
    fn validate_path<'a>(&self, path: &'a Path) -> Result<Vec<&'a std::ffi::OsStr>, ImageError> {
        if path.as_os_str().is_empty() {
            return Err(ImageError::PathTraversal {
                path: path.to_path_buf(),
                rootfs: self.path.clone(),
            });
        }

        let mut components = Vec::new();
        for comp in path.components() {
            match comp {
                Component::Normal(c) => components.push(c),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(ImageError::PathTraversal {
                        path: path.to_path_buf(),
                        rootfs: self.path.clone(),
                    });
                }
            }
        }

        if components.is_empty() {
            return Err(ImageError::PathTraversal {
                path: path.to_path_buf(),
                rootfs: self.path.clone(),
            });
        }

        Ok(components)
    }

    /// Resolves the directory descriptor of the immediate parent component-by-component
    /// using `O_DIRECTORY | O_NOFOLLOW`.
    ///
    /// If any intermediate component is a symbolic link or non-directory, this operation fails immediately
    /// (with ELOOP or ENOTDIR), guaranteeing that no intermediate symlinks are followed.
    fn resolve_parent_dir<'a>(
        &'a self,
        components: &[&'a std::ffi::OsStr],
        create_missing: bool,
    ) -> Result<(ParentDir<'a>, &'a std::ffi::OsStr), ImageError> {
        let (parent_comps, final_comp) = match components.split_last() {
            Some((last, rest)) => (rest, *last),
            None => {
                return Err(ImageError::PathTraversal {
                    path: PathBuf::new(),
                    rootfs: self.path.clone(),
                })
            }
        };

        if parent_comps.is_empty() {
            return Ok((ParentDir::Root(&self.fd), final_comp));
        }

        let mut current_raw = self.fd.as_raw_fd();
        let mut current_owned: Option<OwnedFd> = None;

        for comp in parent_comps {
            let c_comp = CString::new(comp.as_bytes()).map_err(|e| {
                ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
            })?;

            let mut next_raw = unsafe {
                libc::openat(
                    current_raw,
                    c_comp.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };

            if next_raw < 0 {
                let err = std::io::Error::last_os_error();

                // Explicitly check if the intermediate component is a symbolic link.
                // On macOS and some Linux systems, openat with O_DIRECTORY may return ENOTDIR
                // instead of ELOOP for a symlink. We must always fail with ELOOP on any intermediate symlink.
                let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
                let s_ret = unsafe {
                    libc::fstatat(
                        current_raw,
                        c_comp.as_ptr(),
                        &mut stat_buf,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if s_ret == 0 && (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    return Err(ImageError::Io(std::io::Error::from_raw_os_error(
                        libc::ELOOP,
                    )));
                }

                let is_not_found = err.kind() == std::io::ErrorKind::NotFound || s_ret != 0;
                let is_regular_file =
                    s_ret == 0 && (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFREG;

                if create_missing && (is_not_found || is_regular_file) {
                    if is_regular_file {
                        // Replacing an existing regular file from lower layer with a directory
                        unsafe { libc::unlinkat(current_raw, c_comp.as_ptr(), 0) };
                    }

                    let ret = unsafe { libc::mkdirat(current_raw, c_comp.as_ptr(), 0o700) };
                    if ret != 0 {
                        let mk_err = std::io::Error::last_os_error();
                        if mk_err.raw_os_error() != Some(libc::EEXIST) {
                            return Err(ImageError::Io(mk_err));
                        }
                    }
                    next_raw = unsafe {
                        libc::openat(
                            current_raw,
                            c_comp.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if next_raw < 0 {
                        return Err(ImageError::Io(std::io::Error::last_os_error()));
                    }
                } else {
                    return Err(ImageError::Io(err));
                }
            }

            let next_owned = unsafe { OwnedFd::from_raw_fd(next_raw) };
            current_raw = next_owned.as_raw_fd();
            current_owned = Some(next_owned);
        }

        let descendant = current_owned.expect("parent_comps was non-empty");
        Ok((ParentDir::Descendant(descendant), final_comp))
    }

    /// Checks if an entry at `rel_path` exists and whether it is a symlink (without following it).
    pub fn is_symlink_at(&self, rel_path: &Path) -> Result<bool, ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = match self.resolve_parent_dir(&components, false) {
            Ok(res) => res,
            Err(ImageError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(false)
            }
            Err(e) => return Err(e),
        };
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::fstatat(
                parent_dir.as_raw_fd(),
                c_final.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(ImageError::Io(err));
        }

        let is_symlink = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK;
        Ok(is_symlink)
    }

    /// Creates a directory relative to this directory descriptor without following symlinks.
    ///
    /// Verifies that any pre-existing entry is indeed a directory; existing symlinks
    /// or regular files are strictly rejected with ENOTDIR.
    pub fn mkdir_at(&self, rel_path: &Path, mode: u32) -> Result<(), ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components, true)?;
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let ret = unsafe {
            libc::mkdirat(
                parent_dir.as_raw_fd(),
                c_final.as_ptr(),
                mode as libc::mode_t,
            )
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                // Verify existing entry after EEXIST; never accept an existing symlink or regular file as a directory.
                let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
                let stat_ret = unsafe {
                    libc::fstatat(
                        parent_dir.as_raw_fd(),
                        c_final.as_ptr(),
                        &mut stat_buf,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if stat_ret != 0 {
                    return Err(ImageError::Io(std::io::Error::last_os_error()));
                }

                let is_dir = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR;
                if !is_dir {
                    return Err(ImageError::Io(std::io::Error::from_raw_os_error(
                        libc::ENOTDIR,
                    )));
                }
            } else {
                return Err(ImageError::Io(err));
            }
        }

        Ok(())
    }

    /// Creates a symlink at `link_rel` pointing to `target` relative to this directory descriptor.
    /// Rejects link locations and targets that attempt to escape the rootfs.
    pub fn symlink_at(&self, target: &Path, link_rel: &Path) -> Result<(), ImageError> {
        let components = self.validate_path(link_rel)?;
        let link_parent = link_rel.parent().unwrap_or_else(|| Path::new(""));
        let _ = normalize_symlink_target(&self.path, link_parent, target)?;

        let (parent_dir, final_comp) = self.resolve_parent_dir(&components, true)?;
        let c_target = CString::new(target.as_os_str().as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let c_link = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let ret =
            unsafe { libc::symlinkat(c_target.as_ptr(), parent_dir.as_raw_fd(), c_link.as_ptr()) };

        if ret != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Opens a file relative to this directory descriptor with `O_NOFOLLOW` to prevent symlink traversal.
    pub fn open_file_at(
        &self,
        rel_path: &Path,
        flags: i32,
        mode: u32,
    ) -> Result<std::fs::File, ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components, true)?;
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let safe_flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let raw_fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                c_final.as_ptr(),
                safe_flags,
                mode as libc::mode_t as libc::c_uint,
            )
        };
        if raw_fd < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        Ok(file)
    }

    /// Checks if an entry exists at `rel_path` without following symlinks.
    pub fn exists_at(&self, rel_path: &Path) -> Result<bool, ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = match self.resolve_parent_dir(&components, false) {
            Ok(res) => res,
            Err(ImageError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(false)
            }
            Err(e) => return Err(e),
        };
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::fstatat(
                parent_dir.as_raw_fd(),
                c_final.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };

        if ret == 0 {
            Ok(true)
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(ImageError::Io(err))
            }
        }
    }

    /// Creates a hard link at `link_rel` pointing to `source_rel` relative to this rootfs.
    /// Both source and destination paths are validated descriptor-by-descriptor without symlink following.
    pub fn hardlink_at(&self, source_rel: &Path, link_rel: &Path) -> Result<(), ImageError> {
        let src_comps = self.validate_path(source_rel)?;
        let dst_comps = self.validate_path(link_rel)?;

        let (src_parent_dir, src_final) = self.resolve_parent_dir(&src_comps, false)?;
        let (dst_parent_dir, dst_final) = self.resolve_parent_dir(&dst_comps, true)?;

        let c_src = CString::new(src_final.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let c_dst = CString::new(dst_final.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        // Unlink destination first if it already exists (replacement semantics)
        let _ = unsafe { libc::unlinkat(dst_parent_dir.as_raw_fd(), c_dst.as_ptr(), 0) };

        let ret = unsafe {
            libc::linkat(
                src_parent_dir.as_raw_fd(),
                c_src.as_ptr(),
                dst_parent_dir.as_raw_fd(),
                c_dst.as_ptr(),
                0,
            )
        };

        if ret != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Sets metadata (ownership, modification time, and permissions) at `rel_path` without following symlinks.
    pub fn set_metadata_at(
        &self,
        rel_path: &Path,
        mode: Option<u32>,
        uid: u32,
        gid: u32,
        mtime_sec: i64,
    ) -> Result<(), ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components, false)?;
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let parent_fd = parent_dir.as_raw_fd();

        // 1. Ownership (fchownat with AT_SYMLINK_NOFOLLOW)
        let ret = unsafe {
            libc::fchownat(
                parent_fd,
                c_final.as_ptr(),
                uid as libc::uid_t,
                gid as libc::gid_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            let is_unprivileged = unsafe { libc::geteuid() != 0 };
            if !(err.raw_os_error() == Some(libc::EPERM) && is_unprivileged) {
                return Err(ImageError::Io(err));
            }
        }

        // 2. Timestamps (utimensat with AT_SYMLINK_NOFOLLOW)
        let times = [
            libc::timespec {
                tv_sec: mtime_sec as libc::time_t,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: mtime_sec as libc::time_t,
                tv_nsec: 0,
            },
        ];
        let ret = unsafe {
            libc::utimensat(
                parent_fd,
                c_final.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ret != 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        // 3. Permissions (mode): applied if not a symlink
        if let Some(m) = mode {
            let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::fstatat(
                    parent_fd,
                    c_final.as_ptr(),
                    &mut stat_buf,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if ret == 0 && (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFLNK {
                let raw_open = unsafe {
                    libc::openat(
                        parent_fd,
                        c_final.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw_open >= 0 {
                    let ret = unsafe { libc::fchmod(raw_open, (m & 0o7777) as libc::mode_t) };
                    unsafe { libc::close(raw_open) };
                    if ret != 0 {
                        return Err(ImageError::Io(std::io::Error::last_os_error()));
                    }
                } else {
                    let ret = unsafe {
                        libc::fchmodat(parent_fd, c_final.as_ptr(), (m & 0o7777) as libc::mode_t, 0)
                    };
                    if ret != 0 {
                        return Err(ImageError::Io(std::io::Error::last_os_error()));
                    }
                }
            }
        }

        Ok(())
    }

    /// Prepares a destination path for writing a new entry, handling type replacement semantics.
    /// If an existing entry at `rel_path` has an incompatible type with `new_is_dir`, it is removed.
    pub fn prepare_for_entry(&self, rel_path: &Path, new_is_dir: bool) -> Result<(), ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = match self.resolve_parent_dir(&components, false) {
            Ok(res) => res,
            Err(ImageError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let parent_fd = parent_dir.as_raw_fd();
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::fstatat(
                parent_fd,
                c_final.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };

        if ret != 0 {
            return Ok(());
        }

        let existing_is_dir = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let existing_is_symlink = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK;

        if new_is_dir {
            if !existing_is_dir {
                // Replacing a file or symlink with a directory
                let ret = unsafe { libc::unlinkat(parent_fd, c_final.as_ptr(), 0) };
                if ret != 0 {
                    return Err(ImageError::Io(std::io::Error::last_os_error()));
                }
            }
        } else if existing_is_dir {
            // Replacing a directory with a file or symlink
            let raw_dir = unsafe {
                libc::openat(
                    parent_fd,
                    c_final.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw_dir >= 0 {
                let owned_dir = unsafe { OwnedFd::from_raw_fd(raw_dir) };
                Self::remove_dir_contents_fd(owned_dir.as_raw_fd())?;
            }
            let ret = unsafe { libc::unlinkat(parent_fd, c_final.as_ptr(), libc::AT_REMOVEDIR) };
            if ret != 0 {
                return Err(ImageError::Io(std::io::Error::last_os_error()));
            }
        } else if existing_is_symlink {
            // Replacing a symlink with a file, symlink, or hardlink
            let ret = unsafe { libc::unlinkat(parent_fd, c_final.as_ptr(), 0) };
            if ret != 0 {
                return Err(ImageError::Io(std::io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    /// Removes an entry (file, symlink, or directory tree) at `rel_path` descriptor-relatively.
    pub fn remove_entry_at(&self, rel_path: &Path) -> Result<(), ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = match self.resolve_parent_dir(&components, false) {
            Ok(res) => res,
            Err(ImageError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let parent_fd = parent_dir.as_raw_fd();
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::fstatat(
                parent_fd,
                c_final.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(ImageError::Io(err));
        }

        if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            let raw_dir = unsafe {
                libc::openat(
                    parent_fd,
                    c_final.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw_dir >= 0 {
                let owned_dir = unsafe { OwnedFd::from_raw_fd(raw_dir) };
                Self::remove_dir_contents_fd(owned_dir.as_raw_fd())?;
            }
            let ret = unsafe { libc::unlinkat(parent_fd, c_final.as_ptr(), libc::AT_REMOVEDIR) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(ImageError::Io(err));
                }
            }
        } else {
            let ret = unsafe { libc::unlinkat(parent_fd, c_final.as_ptr(), 0) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(ImageError::Io(err));
                }
            }
        }

        Ok(())
    }

    /// Recursively removes all contents inside a directory at `rel_path` descriptor-relatively,
    /// while leaving the directory itself intact.
    pub fn remove_dir_contents_at(&self, rel_path: &Path) -> Result<(), ImageError> {
        if rel_path.as_os_str().is_empty() {
            return Self::remove_dir_contents_fd(self.fd.as_raw_fd());
        }

        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = match self.resolve_parent_dir(&components, false) {
            Ok(res) => res,
            Err(ImageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let raw_dir = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                c_final.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw_dir < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(ImageError::Io(err));
        }

        let owned_dir = unsafe { OwnedFd::from_raw_fd(raw_dir) };
        Self::remove_dir_contents_fd(owned_dir.as_raw_fd())
    }

    fn remove_dir_contents_fd(dir_fd: RawFd) -> Result<(), ImageError> {
        let dup_fd = unsafe { libc::dup(dir_fd) };
        if dup_fd < 0 {
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        let dir_ptr = unsafe { libc::fdopendir(dup_fd) };
        if dir_ptr.is_null() {
            unsafe { libc::close(dup_fd) };
            return Err(ImageError::Io(std::io::Error::last_os_error()));
        }

        let mut entries = Vec::new();
        loop {
            let entry_ptr = unsafe { libc::readdir(dir_ptr) };
            if entry_ptr.is_null() {
                break;
            }
            let entry = unsafe { &*entry_ptr };
            let c_str = unsafe { std::ffi::CStr::from_ptr(entry.d_name.as_ptr()) };
            let name_bytes = c_str.to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            entries.push(c_str.to_owned());
        }
        unsafe { libc::closedir(dir_ptr) };

        for c_name in entries {
            let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::fstatat(
                    dir_fd,
                    c_name.as_ptr(),
                    &mut stat_buf,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if ret != 0 {
                continue;
            }

            if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                let child_raw = unsafe {
                    libc::openat(
                        dir_fd,
                        c_name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if child_raw >= 0 {
                    let child_owned = unsafe { OwnedFd::from_raw_fd(child_raw) };
                    Self::remove_dir_contents_fd(child_owned.as_raw_fd())?;
                }
                unsafe { libc::unlinkat(dir_fd, c_name.as_ptr(), libc::AT_REMOVEDIR) };
            } else {
                unsafe { libc::unlinkat(dir_fd, c_name.as_ptr(), 0) };
            }
        }

        Ok(())
    }

    /// Unlinks a file or symlink at `rel_path` relative to this directory descriptor without following symlinks.
    pub fn unlink_at(&self, rel_path: &Path) -> Result<(), ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = match self.resolve_parent_dir(&components, false) {
            Ok(res) => res,
            Err(ImageError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        let c_final = CString::new(final_comp.as_bytes()).map_err(|e| {
            ImageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

        let ret = unsafe { libc::unlinkat(parent_dir.as_raw_fd(), c_final.as_ptr(), 0) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(ImageError::Io(err));
            }
        }

        Ok(())
    }
}
