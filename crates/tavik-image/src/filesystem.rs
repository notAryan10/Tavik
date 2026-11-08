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

            let next_raw = unsafe {
                libc::openat(
                    current_raw,
                    c_comp.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };

            if next_raw < 0 {
                return Err(ImageError::Io(std::io::Error::last_os_error()));
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
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components)?;
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
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components)?;
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

        let (parent_dir, final_comp) = self.resolve_parent_dir(&components)?;
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
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components)?;
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

    /// Unlinks a file or symlink at `rel_path` relative to this directory descriptor without following symlinks.
    pub fn unlink_at(&self, rel_path: &Path) -> Result<(), ImageError> {
        let components = self.validate_path(rel_path)?;
        let (parent_dir, final_comp) = self.resolve_parent_dir(&components)?;
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
