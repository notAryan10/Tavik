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
