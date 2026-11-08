use std::path::{Path, PathBuf};
use tavik_image::{ImageError, Whiteout};

#[test]
fn test_standard_nested_whiteout() {
    let parsed = Whiteout::parse(Path::new("etc/.wh.hosts")).unwrap();
    assert_eq!(parsed, Some(Whiteout::Entry(PathBuf::from("etc/hosts"))));

    let deep = Whiteout::parse(Path::new("usr/local/bin/.wh.old_tool")).unwrap();
    assert_eq!(
        deep,
        Some(Whiteout::Entry(PathBuf::from("usr/local/bin/old_tool")))
    );
}

#[test]
fn test_root_level_whiteout() {
    let parsed = Whiteout::parse(Path::new(".wh.deleted_file")).unwrap();
    assert_eq!(parsed, Some(Whiteout::Entry(PathBuf::from("deleted_file"))));
}

#[test]
fn test_nested_opaque_whiteout_marker() {
    let parsed = Whiteout::parse(Path::new("var/log/.wh..wh..opq")).unwrap();
    assert_eq!(parsed, Some(Whiteout::Opaque(PathBuf::from("var/log"))));
}

#[test]
fn test_root_level_opaque_whiteout_marker() {
    let parsed = Whiteout::parse(Path::new(".wh..wh..opq")).unwrap();
    assert_eq!(parsed, Some(Whiteout::Opaque(PathBuf::from(""))));
}

#[test]
fn test_non_whiteout_file_returns_none() {
    let regular_file = Whiteout::parse(Path::new("etc/passwd")).unwrap();
    assert_eq!(regular_file, None);

    let prefix_lookalike = Whiteout::parse(Path::new("bin/whiteout")).unwrap();
    assert_eq!(prefix_lookalike, None);

    let wh_in_middle = Whiteout::parse(Path::new("lib/lib.wh.so")).unwrap();
    assert_eq!(wh_in_middle, None);
}

#[test]
fn test_rejects_malformed_empty_whiteout_target() {
    let err = Whiteout::parse(Path::new(".wh.")).unwrap_err();
    assert!(matches!(err, ImageError::MalformedWhiteout(_)));

    let err2 = Whiteout::parse(Path::new("etc/.wh.")).unwrap_err();
    assert!(matches!(err2, ImageError::MalformedWhiteout(_)));
}

#[test]
fn test_rejects_malformed_double_whiteout_prefix() {
    // Only .wh..wh..opq is a valid opaque marker; anything else starting with .wh..wh. is malformed
    let err = Whiteout::parse(Path::new(".wh..wh.invalid")).unwrap_err();
    assert!(matches!(err, ImageError::MalformedWhiteout(_)));

    let err2 = Whiteout::parse(Path::new("etc/.wh..wh.bad")).unwrap_err();
    assert!(matches!(err2, ImageError::MalformedWhiteout(_)));
}

#[test]
fn test_rejects_traversal_in_whiteout_target_or_parent() {
    // Traversal in target
    let err1 = Whiteout::parse(Path::new(".wh..."));
    assert!(matches!(err1, Err(ImageError::MalformedWhiteout(_))));

    let err2 = Whiteout::parse(Path::new(".wh.."));
    assert!(matches!(err2, Err(ImageError::MalformedWhiteout(_))));

    // Traversal in parent directory
    let err3 = Whiteout::parse(Path::new("../.wh.foo"));
    assert!(matches!(err3, Err(ImageError::MalformedWhiteout(_))));

    let err4 = Whiteout::parse(Path::new("a/../../.wh.foo"));
    assert!(matches!(err4, Err(ImageError::MalformedWhiteout(_))));

    // Root directory component in parent
    let err5 = Whiteout::parse(Path::new("/.wh.foo"));
    assert!(matches!(err5, Err(ImageError::MalformedWhiteout(_))));
}
