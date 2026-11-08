use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tavik_image::config::{ContainerConfig, ImageConfiguration, ImageVolume};
use tavik_image::user::{resolve_user, ResolvedUser};
use tavik_image::ImageError;
use tempfile::tempdir;

fn setup_test_rootfs(
    passwd_content: Option<&str>,
    group_content: Option<&str>,
) -> tempfile::TempDir {
    let dir = tempdir().expect("Failed to create tempdir");
    let etc_dir = dir.path().join("etc");
    fs::create_dir_all(&etc_dir).expect("Failed to create etc directory");

    if let Some(content) = passwd_content {
        fs::write(etc_dir.join("passwd"), content).expect("Failed to write /etc/passwd");
    }
    if let Some(content) = group_content {
        fs::write(etc_dir.join("group"), content).expect("Failed to write /etc/group");
    }

    dir
}

// -----------------------------------------------------------------------------
// User Resolution Tests
// -----------------------------------------------------------------------------

#[test]
fn test_user_resolution_default_root_user() {
    let rootfs = setup_test_rootfs(None, None);

    // Rule 1: No specified user defaults to UID 0 and GID 0
    let user = resolve_user(rootfs.path(), None).expect("Default user resolution should succeed");
    assert_eq!(
        user,
        ResolvedUser {
            uid: 0,
            gid: 0,
            additional_gids: vec![],
            username: None,
            groupname: None,
        }
    );
}

#[test]
fn test_user_resolution_username_lookup() {
    let passwd = "root:x:0:0:root:/root:/bin/sh\nalice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let group = "root:x:0:\nalice:x:1001:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved =
        resolve_user(rootfs.path(), Some("alice")).expect("Username lookup should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1001,
            gid: 1001,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: Some("alice".to_string()),
        }
    );
}

#[test]
fn test_user_resolution_numeric_uid_lookup_found_in_passwd() {
    let passwd = "bob:x:1002:2002:Bob:/home/bob:/bin/bash\n";
    let group = "bobgrp:x:2002:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved =
        resolve_user(rootfs.path(), Some("1002")).expect("Numeric UID lookup should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1002,
            gid: 2002,
            additional_gids: vec![],
            username: Some("bob".to_string()),
            groupname: Some("bobgrp".to_string()),
        }
    );
}

#[test]
fn test_user_resolution_numeric_uid_lookup_not_in_passwd() {
    let group = "root:x:0:\n";
    let rootfs = setup_test_rootfs(None, Some(group));

    // Rule 3: Numeric UIDs are accepted even if no passwd entry exists.
    // Rule 5: When numeric UID has no passwd entry, default its GID to 0.
    let resolved =
        resolve_user(rootfs.path(), Some("9999")).expect("Unmapped numeric UID should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 9999,
            gid: 0,
            additional_gids: vec![],
            username: None,
            groupname: Some("root".to_string()),
        }
    );
}

#[test]
fn test_user_resolution_username_with_explicit_named_group() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let group = "alice:x:1001:\nstaff:x:5000:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved = resolve_user(rootfs.path(), Some("alice:staff"))
        .expect("Username with explicit named group should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1001,
            gid: 5000,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: Some("staff".to_string()),
        }
    );
}

#[test]
fn test_user_resolution_username_with_numeric_gid() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let group = "developers:x:7000:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    // Known GID
    let resolved = resolve_user(rootfs.path(), Some("alice:7000"))
        .expect("Username with known numeric GID should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1001,
            gid: 7000,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: Some("developers".to_string()),
        }
    );

    // Unmapped numeric GID
    let resolved_unmapped = resolve_user(rootfs.path(), Some("alice:8888"))
        .expect("Username with unmapped numeric GID should succeed");
    assert_eq!(
        resolved_unmapped,
        ResolvedUser {
            uid: 1001,
            gid: 8888,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: None,
        }
    );
}

#[test]
fn test_user_resolution_numeric_uid_with_named_group() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let group = "developers:x:7000:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved = resolve_user(rootfs.path(), Some("1001:developers"))
        .expect("Numeric UID with named group should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1001,
            gid: 7000,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: Some("developers".to_string()),
        }
    );
}

#[test]
fn test_user_resolution_numeric_uid_with_numeric_gid() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let group = "developers:x:7000:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved = resolve_user(rootfs.path(), Some("1001:7000"))
        .expect("Numeric UID with numeric GID should succeed");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1001,
            gid: 7000,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: Some("developers".to_string()),
        }
    );

    let resolved_unknown = resolve_user(rootfs.path(), Some("2000:3000"))
        .expect("Unmapped numeric UID:GID should succeed");
    assert_eq!(
        resolved_unknown,
        ResolvedUser {
            uid: 2000,
            gid: 3000,
            additional_gids: vec![],
            username: None,
            groupname: None,
        }
    );
}

#[test]
fn test_user_resolution_missing_username_fails() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let rootfs = setup_test_rootfs(Some(passwd), None);

    let err = resolve_user(rootfs.path(), Some("charlie")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("Unknown named user 'charlie'")),
        "Expected unknown user error, got: {err:?}"
    );
}

#[test]
fn test_user_resolution_missing_group_fails() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let group = "alice:x:1001:\n";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let err = resolve_user(rootfs.path(), Some("alice:nonexistent")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("Unknown named group 'nonexistent'")),
        "Expected unknown group error, got: {err:?}"
    );
}

#[test]
fn test_user_resolution_missing_passwd_file() {
    let rootfs = setup_test_rootfs(None, None);

    // Named user fails because passwd cannot be consulted
    let err = resolve_user(rootfs.path(), Some("alice")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("/etc/passwd file not found")),
        "Expected missing passwd error, got: {err:?}"
    );

    // Numeric UID succeeds without passwd
    let resolved = resolve_user(rootfs.path(), Some("1000"))
        .expect("Numeric UID should succeed without passwd");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1000,
            gid: 0,
            additional_gids: vec![],
            username: None,
            groupname: None,
        }
    );
}

#[test]
fn test_user_resolution_missing_group_file() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let rootfs = setup_test_rootfs(Some(passwd), None);

    // Named group fails because group file cannot be consulted
    let err = resolve_user(rootfs.path(), Some("alice:staff")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("/etc/group file not found")),
        "Expected missing group error, got: {err:?}"
    );

    // Numeric GID succeeds and supplementary groups default to empty
    let resolved = resolve_user(rootfs.path(), Some("alice:2000"))
        .expect("Numeric GID should succeed without group file");
    assert_eq!(
        resolved,
        ResolvedUser {
            uid: 1001,
            gid: 2000,
            additional_gids: vec![],
            username: Some("alice".to_string()),
            groupname: None,
        }
    );
}

#[test]
fn test_user_resolution_malformed_passwd_records() {
    let cases = [
        ("alice:x:1000\n", "expected exactly 7 fields"),
        (
            "alice:x:1000:1000::/home/alice\n",
            "expected exactly 7 fields",
        ), // 6 fields (truncated)
        (
            "alice:x:1000:1000::/home/alice:/bin/sh:extra\n",
            "expected exactly 7 fields",
        ), // 8 fields (overlong)
        (":x:1000:1000::/home/alice:/bin/sh\n", "username is empty"),
        (
            "alice:x:notanumber:1000::/home/alice:/bin/sh\n",
            "invalid numeric UID",
        ),
        (
            "alice:x:1000:notanumber::/home/alice:/bin/sh\n",
            "invalid numeric GID",
        ),
    ];

    for (passwd, expected_msg) in cases {
        let rootfs = setup_test_rootfs(Some(passwd), None);
        let err = resolve_user(rootfs.path(), Some("1000")).unwrap_err();
        assert!(
            matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains(expected_msg)),
            "Expected error containing '{expected_msg}', got: {err:?}"
        );
    }
}

#[test]
fn test_user_resolution_malformed_group_records() {
    let passwd = "alice:x:1001:1001::/home/alice:/bin/sh\n";
    let cases = [
        ("developers:x\n", "expected exactly 4 fields"), // 2 fields (truncated)
        ("developers:x:7000\n", "expected exactly 4 fields"), // 3 fields (truncated)
        (
            "developers:x:7000:alice:extra\n",
            "expected exactly 4 fields",
        ), // 5 fields (overlong)
        (":x:1001:\n", "groupname is empty"),
        ("developers:x:notanumber:\n", "invalid numeric GID"),
    ];

    for (group, expected_msg) in cases {
        let rootfs = setup_test_rootfs(Some(passwd), Some(group));
        let err = resolve_user(rootfs.path(), Some("alice")).unwrap_err();
        assert!(
            matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains(expected_msg)),
            "Expected error containing '{expected_msg}', got: {err:?}"
        );
    }
}

#[test]
fn test_user_resolution_valid_empty_fields_comments_and_blank_lines() {
    // Valid /etc/passwd with blank lines, comments, empty password, empty gecos, empty home, empty shell
    let passwd = "\
# This is a comment at the top
root:*:0:0:::

# Blank line above and comment here
alice::1001:1001::/home/alice:/bin/sh
bob:x:1002:1002:Bob Gecos::
";
    // Valid /etc/group with blank lines, comments, empty password, empty members
    let group = "\
# Group comment
root:x:0:
alice::1001:
developers:x:2000:
# Another comment
staff:*:3000:bob
";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let res_root =
        resolve_user(rootfs.path(), Some("root")).expect("Root resolution should succeed");
    assert_eq!(res_root.uid, 0);
    assert_eq!(res_root.gid, 0);
    assert_eq!(res_root.username, Some("root".to_string()));

    let res_alice =
        resolve_user(rootfs.path(), Some("alice")).expect("Alice resolution should succeed");
    assert_eq!(res_alice.uid, 1001);
    assert_eq!(res_alice.gid, 1001);

    let res_bob = resolve_user(rootfs.path(), Some("bob")).expect("Bob resolution should succeed");
    assert_eq!(res_bob.uid, 1002);
    assert_eq!(res_bob.gid, 1002);
    assert_eq!(res_bob.additional_gids, vec![3000]);
}

#[test]
fn test_user_resolution_fifo_passwd_and_group_fails_promptly() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Test FIFO for /etc/passwd
    {
        let dir = tempdir().expect("Failed to create tempdir");
        let etc_dir = dir.path().join("etc");
        fs::create_dir_all(&etc_dir).expect("Failed to create etc directory");
        let passwd_path = etc_dir.join("passwd");

        let c_path = CString::new(passwd_path.as_os_str().as_bytes()).unwrap();
        let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(res, 0, "mkfifo failed for passwd");

        let start = std::time::Instant::now();
        let err = resolve_user(dir.path(), Some("1000")).unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "Resolution on FIFO passwd took too long: {elapsed:?}"
        );
        assert!(
            matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("not a regular file")),
            "Expected non-regular file error, got: {err:?}"
        );
    }

    // Test FIFO for /etc/group
    {
        let dir = tempdir().expect("Failed to create tempdir");
        let etc_dir = dir.path().join("etc");
        fs::create_dir_all(&etc_dir).expect("Failed to create etc directory");
        let passwd_path = etc_dir.join("passwd");
        fs::write(passwd_path, "alice:x:1001:1001:Alice:/home/alice:/bin/sh\n")
            .expect("Failed to write passwd");
        let group_path = etc_dir.join("group");

        let c_path = CString::new(group_path.as_os_str().as_bytes()).unwrap();
        let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(res, 0, "mkfifo failed for group");

        let start = std::time::Instant::now();
        let err = resolve_user(dir.path(), Some("alice")).unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "Resolution on FIFO group took too long: {elapsed:?}"
        );
        assert!(
            matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("not a regular file")),
            "Expected non-regular file error for group, got: {err:?}"
        );
    }
}

#[test]
fn test_user_resolution_etc_as_regular_file_fails_loudly() {
    let dir = tempdir().expect("Failed to create tempdir");
    let etc_file = dir.path().join("etc");
    // Create /etc as a regular file rather than a directory
    fs::write(&etc_file, "this is a regular file, not a directory")
        .expect("Failed to write file at /etc");

    let err = resolve_user(dir.path(), Some("1000")).unwrap_err();
    assert!(
        matches!(err, ImageError::Io(ref e) if e.raw_os_error() == Some(libc::ENOTDIR)),
        "Expected ENOTDIR error for non-directory /etc, got: {err:?}"
    );
}

#[test]
fn test_safe_dir_read_file_to_string_limited_overflow_and_limits() {
    use tavik_image::SafeDir;

    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "hello world 12345").expect("Failed to write test file");

    let safe_dir = SafeDir::open_rootfs(dir.path()).expect("SafeDir open failed");

    // Arithmetic overflow on limit + 1: u64::MAX
    let err_overflow = safe_dir
        .read_file_to_string_limited(Path::new("test.txt"), u64::MAX)
        .unwrap_err();
    assert!(
        matches!(err_overflow, ImageError::InvalidConfiguration(ref msg) if msg.contains("overflows u64")),
        "Expected limit overflow error, got: {err_overflow:?}"
    );

    // Limit exceeded: file has 17 bytes, limit is 5 bytes
    let err_limit = safe_dir
        .read_file_to_string_limited(Path::new("test.txt"), 5)
        .unwrap_err();
    assert!(
        matches!(err_limit, ImageError::InvalidConfiguration(ref msg) if msg.contains("exceeds maximum allowed size")),
        "Expected size limit error, got: {err_limit:?}"
    );

    // Exact limit success: file has 17 bytes, limit is 17 bytes
    let content = safe_dir
        .read_file_to_string_limited(Path::new("test.txt"), 17)
        .expect("Exact limit should succeed")
        .expect("File should exist");
    assert_eq!(content, "hello world 12345");
}

#[test]
fn test_user_resolution_supplementary_group_membership_and_deduplication() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/sh\n";
    // alice belongs to docker (999), sudo (27), and admin (27 - duplicate GID), audio (29), video (44)
    let group = "\
root:x:0:
alice:x:1001:
docker:x:999:alice,bob
sudo:x:27:alice
admin:x:27:alice
audio:x:29:alice,charlie
video:x:44:alice
other:x:500:bob
";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved =
        resolve_user(rootfs.path(), Some("alice")).expect("User resolution should succeed");
    assert_eq!(resolved.uid, 1001);
    assert_eq!(resolved.gid, 1001);
    assert_eq!(resolved.username, Some("alice".to_string()));
    assert_eq!(resolved.groupname, Some("alice".to_string()));

    // Sorted and deduplicated supplementary groups: [27, 29, 44, 999]
    assert_eq!(resolved.additional_gids, vec![27, 29, 44, 999]);
}

#[test]
fn test_user_resolution_primary_gid_exclusion_from_supplementary() {
    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/sh\n";
    // Primary group is 1001. Even if alice is explicitly listed in members of group 1001, it must be excluded.
    let group = "\
alice:x:1001:alice
staff:x:1001:alice,bob
developers:x:2000:alice
";
    let rootfs = setup_test_rootfs(Some(passwd), Some(group));

    let resolved =
        resolve_user(rootfs.path(), Some("alice")).expect("User resolution should succeed");
    assert_eq!(resolved.gid, 1001);
    // 1001 excluded from additional_gids!
    assert_eq!(resolved.additional_gids, vec![2000]);
}

#[test]
fn test_user_resolution_empty_components_rejected() {
    let rootfs = setup_test_rootfs(None, None);

    let empty_cases = ["", ":", "user:", ":group"];
    for spec in empty_cases {
        let err = resolve_user(rootfs.path(), Some(spec)).unwrap_err();
        assert!(
            matches!(err, ImageError::InvalidConfiguration(_)),
            "Expected InvalidConfiguration for '{spec}', got: {err:?}"
        );
    }
}

#[test]
fn test_user_resolution_extra_colons_rejected() {
    let rootfs = setup_test_rootfs(None, None);

    let err = resolve_user(rootfs.path(), Some("alice:staff:extra")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("Extra colon separator")),
        "Expected extra colon error, got: {err:?}"
    );
}

#[test]
fn test_user_resolution_numeric_overflow_rejected() {
    let rootfs = setup_test_rootfs(None, None);

    // Overflowing UID > u32::MAX (4294967295)
    let err_uid = resolve_user(rootfs.path(), Some("4294967296")).unwrap_err();
    assert!(
        matches!(err_uid, ImageError::InvalidConfiguration(ref msg) if msg.contains("exceeds maximum allowed value")),
        "Expected numeric overflow error for UID, got: {err_uid:?}"
    );

    // Overflowing GID
    let err_gid = resolve_user(rootfs.path(), Some("1000:4294967296")).unwrap_err();
    assert!(
        matches!(err_gid, ImageError::InvalidConfiguration(ref msg) if msg.contains("exceeds maximum allowed value")),
        "Expected numeric overflow error for GID, got: {err_gid:?}"
    );
}

#[test]
fn test_user_resolution_null_bytes_rejected() {
    let rootfs = setup_test_rootfs(None, None);

    let err = resolve_user(rootfs.path(), Some("root\0bad")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("forbidden null byte")),
        "Expected null byte error, got: {err:?}"
    );
}

#[test]
fn test_user_resolution_unreadable_file_fails_loudly() {
    let dir = tempdir().expect("Failed to create tempdir");
    let etc_dir = dir.path().join("etc");
    fs::create_dir_all(&etc_dir).expect("Failed to create etc directory");
    let passwd_path = etc_dir.join("passwd");

    // Create /etc/passwd as a directory instead of a regular file
    fs::create_dir(&passwd_path).expect("Failed to create dir at passwd");

    // Unreadable / non-regular account file must fail loudly, not silently succeed as empty
    let err = resolve_user(dir.path(), Some("1000")).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("not a regular file")),
        "Expected non-regular file error, got: {err:?}"
    );
}

// -----------------------------------------------------------------------------
// Volume Declarations Tests
// -----------------------------------------------------------------------------

#[test]
fn test_volume_declarations_none_and_empty() {
    let config_none = ContainerConfig {
        volumes: None,
        ..Default::default()
    };
    assert_eq!(
        config_none.declared_volumes().expect("Should succeed"),
        vec![]
    );

    let config_empty = ContainerConfig {
        volumes: Some(HashMap::new()),
        ..Default::default()
    };
    assert_eq!(
        config_empty.declared_volumes().expect("Should succeed"),
        vec![]
    );
}

#[test]
fn test_volume_declarations_single_and_multiple_sorted() {
    let mut map = HashMap::new();
    map.insert("/var/lib/app".to_string(), serde_json::json!({}));
    let config_single = ContainerConfig {
        volumes: Some(map),
        ..Default::default()
    };
    assert_eq!(
        config_single.declared_volumes().expect("Should succeed"),
        vec![ImageVolume {
            destination: PathBuf::from("/var/lib/app"),
        }]
    );

    let mut multi_map = HashMap::new();
    multi_map.insert("/var/log".to_string(), serde_json::json!({}));
    multi_map.insert("/etc/config".to_string(), serde_json::json!({}));
    multi_map.insert("/data".to_string(), serde_json::json!({}));
    let config_multi = ContainerConfig {
        volumes: Some(multi_map),
        ..Default::default()
    };

    // Must be deterministically sorted
    assert_eq!(
        config_multi.declared_volumes().expect("Should succeed"),
        vec![
            ImageVolume {
                destination: PathBuf::from("/data"),
            },
            ImageVolume {
                destination: PathBuf::from("/etc/config"),
            },
            ImageVolume {
                destination: PathBuf::from("/var/log"),
            },
        ]
    );
}

#[test]
fn test_volume_declarations_root_path() {
    let mut map = HashMap::new();
    map.insert("/".to_string(), serde_json::json!({}));
    let config = ContainerConfig {
        volumes: Some(map),
        ..Default::default()
    };

    assert_eq!(
        config
            .declared_volumes()
            .expect("Root volume should succeed"),
        vec![ImageVolume {
            destination: PathBuf::from("/"),
        }]
    );
}

#[test]
fn test_volume_declarations_duplicate_handling() {
    let mut map = HashMap::new();
    map.insert("/data".to_string(), serde_json::json!({}));
    map.insert("/data/".to_string(), serde_json::json!({}));
    let config = ContainerConfig {
        volumes: Some(map),
        ..Default::default()
    };

    let volumes = config
        .declared_volumes()
        .expect("Duplicate normalization should succeed");
    assert_eq!(
        volumes,
        vec![ImageVolume {
            destination: PathBuf::from("/data"),
        }]
    );
}

#[test]
fn test_volume_declarations_rejects_invalid_and_relative_paths() {
    let invalid_cases = ["", "relative/path", "var/log", "foo"];

    for invalid in invalid_cases {
        let mut map = HashMap::new();
        map.insert(invalid.to_string(), serde_json::json!({}));
        let config = ContainerConfig {
            volumes: Some(map),
            ..Default::default()
        };

        let err = config.declared_volumes().unwrap_err();
        assert!(
            matches!(err, ImageError::InvalidConfiguration(_)),
            "Expected InvalidConfiguration for '{invalid}', got: {err:?}"
        );
    }
}

#[test]
fn test_volume_declarations_rejects_parent_traversal() {
    let traversal_cases = [
        "/var/../etc",
        "/data/../../etc/shadow",
        "/../escape",
        "/a/b/../..",
    ];

    for traversal in traversal_cases {
        let mut map = HashMap::new();
        map.insert(traversal.to_string(), serde_json::json!({}));
        let config = ContainerConfig {
            volumes: Some(map),
            ..Default::default()
        };

        let err = config.declared_volumes().unwrap_err();
        assert!(
            matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("forbidden parent traversal")),
            "Expected parent traversal error for '{traversal}', got: {err:?}"
        );
    }
}

#[test]
fn test_volume_declarations_rejects_null_bytes() {
    let mut map = HashMap::new();
    map.insert("/var/data\0/escape".to_string(), serde_json::json!({}));
    let config = ContainerConfig {
        volumes: Some(map),
        ..Default::default()
    };

    let err = config.declared_volumes().unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref msg) if msg.contains("forbidden null byte")),
        "Expected null byte error, got: {err:?}"
    );
}

#[test]
fn test_image_configuration_declared_volumes() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:4bcd2e1ae0b9f10740b30190f76ea773e168a65ec163466427f7194d5ed707a1"]
        },
        "config": {
            "Volumes": {
                "/var/log": {},
                "/data": {}
            }
        }
    }"#;

    let image_config: ImageConfiguration = json.parse().expect("Image config should parse");
    let volumes = image_config
        .declared_volumes()
        .expect("Volumes should be extracted");

    assert_eq!(
        volumes,
        vec![
            ImageVolume {
                destination: PathBuf::from("/data"),
            },
            ImageVolume {
                destination: PathBuf::from("/var/log"),
            },
        ]
    );

    // Image configuration without config section
    let json_no_config = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:4bcd2e1ae0b9f10740b30190f76ea773e168a65ec163466427f7194d5ed707a1"]
        }
    }"#;
    let image_config_no_c: ImageConfiguration =
        json_no_config.parse().expect("Image config should parse");
    assert_eq!(
        image_config_no_c
            .declared_volumes()
            .expect("Should succeed"),
        vec![]
    );
}
