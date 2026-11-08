use std::path::{Path, PathBuf};
use tavik_image::{normalize_symlink_target, sanitize_entry_path, ImageError, SafeDir};
use tempfile::tempdir;

#[test]
fn test_sanitize_entry_path_rejects_absolute_paths() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");

    let err = sanitize_entry_path(rootfs, Path::new("/etc/passwd")).unwrap_err();
    match err {
        ImageError::PathTraversal { path, .. } => assert_eq!(path, Path::new("/etc/passwd")),
        other => panic!("Expected PathTraversal, got {:?}", other),
    }

    let err2 = sanitize_entry_path(rootfs, Path::new("/bin/sh")).unwrap_err();
    assert!(matches!(err2, ImageError::PathTraversal { .. }));
}

#[test]
fn test_sanitize_entry_path_rejects_parent_traversal() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");

    let traversal_paths = [
        "../escape",
        "foo/../../escape",
        "../../etc/shadow",
        "a/b/../../../c",
        "..",
        "./../secret",
    ];

    for path_str in traversal_paths {
        let err = sanitize_entry_path(rootfs, Path::new(path_str)).unwrap_err();
        assert!(
            matches!(err, ImageError::PathTraversal { .. }),
            "Path '{}' should be rejected as traversal",
            path_str
        );
    }
}

#[test]
fn test_sanitize_entry_path_rejects_empty_paths() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");
    assert!(sanitize_entry_path(rootfs, Path::new("")).is_err());
    assert!(sanitize_entry_path(rootfs, Path::new(".")).is_err());
}

#[test]
fn test_sanitize_entry_path_permits_safe_relative_paths() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");

    let safe_paths = [
        ("etc/hosts", "/var/lib/tavik/rootfs/etc/hosts"),
        ("bin/busybox", "/var/lib/tavik/rootfs/bin/busybox"),
        ("usr/lib/libc.so", "/var/lib/tavik/rootfs/usr/lib/libc.so"),
        ("./var/log/app.log", "/var/lib/tavik/rootfs/var/log/app.log"),
    ];

    for (input, expected) in safe_paths {
        let sanitized = sanitize_entry_path(rootfs, Path::new(input)).unwrap();
        assert_eq!(sanitized, PathBuf::from(expected));
    }
}

#[test]
fn test_symlink_normalization_permits_container_absolute_symlinks() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");

    // Inside a container, symlinks pointing to /bin/busybox are valid container-level paths
    let target = Path::new("/bin/busybox");
    let norm = normalize_symlink_target(rootfs, Path::new("bin"), target).unwrap();
    assert_eq!(norm, PathBuf::from("/bin/busybox"));

    // Absolute container path with internal /.. stays clamped at container root /
    let target_traversal = Path::new("/../../bin/busybox");
    let norm2 = normalize_symlink_target(rootfs, Path::new("bin"), target_traversal).unwrap();
    assert_eq!(norm2, PathBuf::from("/bin/busybox"));
}

#[test]
fn test_symlink_normalization_permits_safe_relative_symlinks() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");

    // Relative symlink: /usr/bin/python -> ../bin/python3
    let target = Path::new("../bin/python3");
    let link_dir = Path::new("usr/bin");
    let norm = normalize_symlink_target(rootfs, link_dir, target).unwrap();
    assert_eq!(norm, PathBuf::from("../bin/python3"));

    // Sibling symlink: /bin/sh -> busybox
    let target2 = Path::new("busybox");
    let link_dir2 = Path::new("bin");
    let norm2 = normalize_symlink_target(rootfs, link_dir2, target2).unwrap();
    assert_eq!(norm2, PathBuf::from("busybox"));
}

#[test]
fn test_symlink_normalization_rejects_relative_escapes() {
    let rootfs = Path::new("/var/lib/tavik/rootfs");

    // Symlink in /bin trying to escape above container root: ../../etc/shadow
    let target = Path::new("../../etc/shadow");
    let link_dir = Path::new("bin");
    let err = normalize_symlink_target(rootfs, link_dir, target).unwrap_err();
    match err {
        ImageError::SymlinkEscape { target: t, .. } => assert_eq!(t, target),
        other => panic!("Expected SymlinkEscape, got {:?}", other),
    }

    // Symlink at container root trying to escape: ../outside
    let target2 = Path::new("../outside");
    let link_dir2 = Path::new("");
    let err2 = normalize_symlink_target(rootfs, link_dir2, target2).unwrap_err();
    assert!(matches!(err2, ImageError::SymlinkEscape { .. }));
}

#[test]
fn test_safe_dir_descriptor_relative_operations() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    // 1. mkdir_at
    safe_dir.mkdir_at(Path::new("etc"), 0o755).unwrap();
    assert!(rootfs.join("etc").is_dir());

    // 2. open_file_at
    use std::io::Write;
    let mut file = safe_dir
        .open_file_at(
            Path::new("etc/hostname"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
        .unwrap();
    file.write_all(b"tavik-container\n").unwrap();
    drop(file);

    let content = std::fs::read_to_string(rootfs.join("etc/hostname")).unwrap();
    assert_eq!(content, "tavik-container\n");

    // 3. symlink_at and is_symlink_at
    safe_dir
        .symlink_at(Path::new("etc/hostname"), Path::new("etc/host_link"))
        .unwrap();
    assert!(safe_dir.is_symlink_at(Path::new("etc/host_link")).unwrap());
    assert!(!safe_dir.is_symlink_at(Path::new("etc/hostname")).unwrap());

    // 4. unlink_at
    safe_dir.unlink_at(Path::new("etc/host_link")).unwrap();
    assert!(!rootfs.join("etc/host_link").exists());
}

#[test]
fn test_safe_dir_rejects_absolute_path_supplied_directly() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    let abs_paths = [
        Path::new("/etc/passwd"),
        Path::new("/root"),
        Path::new("/tmp/evil"),
    ];

    for path in abs_paths {
        assert!(matches!(
            safe_dir.open_file_at(path, libc::O_RDONLY, 0).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.mkdir_at(path, 0o755).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.symlink_at(Path::new("target"), path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.is_symlink_at(path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.unlink_at(path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
    }
}

#[test]
fn test_safe_dir_rejects_parent_traversal_supplied_directly() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    let traversal_paths = [
        Path::new("../secret"),
        Path::new("etc/../../secret"),
        Path::new(".."),
        Path::new("a/b/../../../escape"),
    ];

    for path in traversal_paths {
        assert!(matches!(
            safe_dir.open_file_at(path, libc::O_RDONLY, 0).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.mkdir_at(path, 0o755).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.symlink_at(Path::new("target"), path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.is_symlink_at(path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.unlink_at(path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
    }
}

#[test]
fn test_safe_dir_rejects_empty_paths_supplied_directly() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    let empty_paths = [Path::new(""), Path::new(".")];

    for path in empty_paths {
        assert!(matches!(
            safe_dir.open_file_at(path, libc::O_RDONLY, 0).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.mkdir_at(path, 0o755).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.symlink_at(Path::new("target"), path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.is_symlink_at(path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
        assert!(matches!(
            safe_dir.unlink_at(path).unwrap_err(),
            ImageError::PathTraversal { .. }
        ));
    }
}

#[test]
fn test_safe_dir_rejects_intermediate_symlink_pointing_outside_rootfs() {
    let temp = tempdir().unwrap();
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&outside_dir).unwrap();

    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    // Create an intermediate symlink pointing outside rootfs
    std::os::unix::fs::symlink(&outside_dir, rootfs.join("sym_outside")).unwrap();

    // Every operation attempting to traverse through this intermediate symlink must fail
    let path = Path::new("sym_outside/pwn.txt");

    assert!(safe_dir
        .open_file_at(path, libc::O_WRONLY | libc::O_CREAT, 0o644)
        .is_err());
    assert!(safe_dir
        .mkdir_at(Path::new("sym_outside/sub"), 0o755)
        .is_err());
    assert!(safe_dir
        .symlink_at(Path::new("target"), Path::new("sym_outside/link"))
        .is_err());
    assert!(safe_dir.is_symlink_at(path).is_err());
    assert!(safe_dir.unlink_at(path).is_err());

    // Verify nothing was touched or created in outside_dir
    assert!(!outside_dir.join("pwn.txt").exists());
    assert!(!outside_dir.join("sub").exists());
    assert!(!outside_dir.join("link").exists());
}

#[test]
fn test_safe_dir_rejects_intermediate_symlink_pointing_inside_rootfs() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    // Create a real directory and a symlink pointing to it inside rootfs
    safe_dir.mkdir_at(Path::new("internal_dir"), 0o755).unwrap();
    std::os::unix::fs::symlink("internal_dir", rootfs.join("sym_internal")).unwrap();

    // Every operation attempting to traverse through this intermediate symlink must fail
    let path = Path::new("sym_internal/pwn.txt");

    assert!(safe_dir
        .open_file_at(path, libc::O_WRONLY | libc::O_CREAT, 0o644)
        .is_err());
    assert!(safe_dir
        .mkdir_at(Path::new("sym_internal/sub"), 0o755)
        .is_err());
    assert!(safe_dir
        .symlink_at(Path::new("target"), Path::new("sym_internal/link"))
        .is_err());
    assert!(safe_dir.is_symlink_at(path).is_err());
    assert!(safe_dir.unlink_at(path).is_err());

    // Verify nothing was created inside internal_dir
    assert!(!rootfs.join("internal_dir").join("pwn.txt").exists());
    assert!(!rootfs.join("internal_dir").join("sub").exists());
    assert!(!rootfs.join("internal_dir").join("link").exists());
}

#[test]
fn test_safe_dir_mkdir_at_rejects_existing_symlink_or_regular_file() {
    let temp = tempdir().unwrap();
    let rootfs = temp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let safe_dir = SafeDir::open_rootfs(&rootfs).unwrap();

    // 1. Existing symlink
    safe_dir.mkdir_at(Path::new("target_dir"), 0o755).unwrap();
    std::os::unix::fs::symlink("target_dir", rootfs.join("sym_link")).unwrap();

    let err_symlink = safe_dir.mkdir_at(Path::new("sym_link"), 0o755).unwrap_err();
    match err_symlink {
        ImageError::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR)),
        other => panic!("Expected Io(ENOTDIR), got {:?}", other),
    }

    // 2. Existing regular file
    use std::io::Write;
    let mut f = safe_dir
        .open_file_at(Path::new("file.txt"), libc::O_WRONLY | libc::O_CREAT, 0o644)
        .unwrap();
    f.write_all(b"not a directory\n").unwrap();
    drop(f);

    let err_file = safe_dir.mkdir_at(Path::new("file.txt"), 0o755).unwrap_err();
    match err_file {
        ImageError::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR)),
        other => panic!("Expected Io(ENOTDIR), got {:?}", other),
    }

    // 3. Existing directory must succeed on repeated mkdir_at
    assert!(safe_dir.mkdir_at(Path::new("target_dir"), 0o755).is_ok());
}
