use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tavik_core::image_service::{parse_signal, ImageService, ImageServiceError};
use tavik_image::config::ImageConfigOverrides;
use tavik_store::{ContentStore, ImageRecord};
use tempfile::tempdir;

fn detect_host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

fn create_tar_gz_layer(entries: &[(&str, &[u8], u32)]) -> (Vec<u8>, String) {
    let mut tar_builder = tar::Builder::new(Vec::new());

    for (name, data, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(*mode);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, *name, *data)
            .expect("Failed to append tar entry");
    }

    let uncompressed_tar = tar_builder.into_inner().expect("Failed to finish tar");
    let diff_id = format!("sha256:{}", hex::encode(Sha256::digest(&uncompressed_tar)));

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&uncompressed_tar)
        .expect("Failed to gzip layer");
    let compressed_bytes = encoder.finish().expect("Failed to finish gzip");

    (compressed_bytes, diff_id)
}

struct TestImageSetup {
    _temp: tempfile::TempDir,
    _store: Arc<ContentStore>,
    service: ImageService,
    reference: String,
    config_digest: String,
    _layer_digest: String,
    diff_id: String,
}

async fn setup_test_image(
    arch: &str,
    os: &str,
    user: Option<&str>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    stop_signal: Option<&str>,
) -> TestImageSetup {
    let temp = tempdir().expect("Failed to create tempdir");
    let store = Arc::new(ContentStore::new(temp.path()).expect("Failed to create ContentStore"));
    let service = ImageService::new(store.clone());

    let passwd_data = b"root:x:0:0:root:/root:/bin/sh\nalice:x:1001:1001:Alice:/home/alice:/bin/sh\nbob:x:1002:1002:Bob:/home/bob:/bin/sh\n";
    let group_data = b"root:x:0:\nalice:x:1001:\ndevelopers:x:2000:alice,bob\nstaff:x:3000:alice\n";
    let sh_script = b"#!/bin/sh\necho \"container running\"\n";

    let (layer_bytes, diff_id) = create_tar_gz_layer(&[
        ("etc/passwd", passwd_data, 0o644),
        ("etc/group", group_data, 0o644),
        ("bin/sh", sh_script, 0o755),
        ("app/data.txt", b"hello data\n", 0o644),
    ]);

    let (layer_digest, layer_size, _) = store
        .ingest_bytes(&layer_bytes, None)
        .await
        .expect("Failed to ingest layer");

    let mut config_json = serde_json::json!({
        "architecture": arch,
        "os": os,
        "config": {
            "Env": ["PATH=/bin:/usr/bin", "ENV_VAR=prod"],
            "WorkingDir": "/app",
            "Volumes": {
                "/var/log": {}
            },
            "Labels": {
                "maintainer": "tavik"
            }
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [diff_id]
        }
    });

    if let Some(u) = user {
        config_json["config"]["User"] = serde_json::json!(u);
    }
    if let Some(ep) = entrypoint {
        config_json["config"]["Entrypoint"] = serde_json::json!(ep);
    }
    if let Some(c) = cmd {
        config_json["config"]["Cmd"] = serde_json::json!(c);
    }
    if let Some(ss) = stop_signal {
        config_json["config"]["StopSignal"] = serde_json::json!(ss);
    }

    let config_bytes = serde_json::to_vec(&config_json).unwrap();
    let (config_digest, _, _) = store
        .ingest_bytes(&config_bytes, None)
        .await
        .expect("Failed to ingest config");

    let reference = "mytest:1.0".to_string();
    let record = ImageRecord {
        reference: reference.clone(),
        manifest_digest: "sha256:ba5eba5eba5eba5eba5eba5eba5eba5eba5eba5eba5eba5eba5eba5eba5eba5e"
            .to_string(),
        config_digest: config_digest.clone(),
        layer_digests: vec![layer_digest.clone()],
        size: layer_size,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store
        .metadata()
        .save_image(record)
        .await
        .expect("Failed to save image record");

    TestImageSetup {
        _temp: temp,
        _store: store,
        service,
        reference,
        config_digest,
        _layer_digest: layer_digest,
        diff_id,
    }
}

// -----------------------------------------------------------------------------
// Tests for Phase B: Image Configuration Loading & Platform Validation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_load_image_config_success() {
    let arch = detect_host_arch();
    let setup = setup_test_image(
        arch,
        "linux",
        Some("alice"),
        Some(vec!["/bin/sh".to_string()]),
        Some(vec!["-c".to_string(), "echo ok".to_string()]),
        Some("SIGQUIT"),
    )
    .await;

    let (record, config) = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .expect("Should load valid config");

    assert_eq!(record.reference, setup.reference);
    assert_eq!(record.config_digest, setup.config_digest);
    assert_eq!(config.os, "linux");
    assert_eq!(config.architecture, arch);
    assert_eq!(config.rootfs.diff_ids, vec![setup.diff_id]);
}

#[tokio::test]
async fn test_load_image_config_missing_image_fails() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    let err = setup
        .service
        .load_image_config("nonexistent:latest")
        .await
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::ImageNotFound(ref msg) if msg.contains("nonexistent:latest")),
        "Expected ImageNotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn test_load_image_config_os_mismatch_fails() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "windows", None, None, None, None).await;

    let err = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::IncompatiblePlatform { ref image_os, .. } if image_os == "windows"),
        "Expected IncompatiblePlatform for windows, got: {err:?}"
    );
}

#[tokio::test]
async fn test_load_image_config_arch_mismatch_fails() {
    let incompatible_arch = if detect_host_arch() == "arm64" {
        "s390x"
    } else {
        "riscv64"
    };

    let setup = setup_test_image(incompatible_arch, "linux", None, None, None, None).await;

    let err = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::IncompatiblePlatform { .. }),
        "Expected IncompatiblePlatform for arch mismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn test_verify_diff_ids_matches_and_detects_mismatch() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    let (record, config) = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .unwrap();

    // Verification succeeds with matching DiffID
    setup
        .service
        .verify_layer_diff_ids(&record, &config)
        .expect("DiffID verification should succeed");

    // Corrupt the diff_id in config
    let mut corrupt_config = config.clone();
    corrupt_config.rootfs.diff_ids[0] =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let err = setup
        .service
        .verify_layer_diff_ids(&record, &corrupt_config)
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::DiffIdMismatch { index: 0, .. }),
        "Expected DiffIdMismatch, got: {err:?}"
    );
}

// -----------------------------------------------------------------------------
// Tests for Phase C: Rootfs Assembly
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_assemble_rootfs_success_and_destination_collision() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    let (record, _) = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .unwrap();

    let bundle_dir = setup._temp.path().join("bundle1");
    let rootfs_dir = bundle_dir.join("rootfs");

    setup
        .service
        .assemble_rootfs(&record, &rootfs_dir)
        .expect("Rootfs assembly should succeed");

    // Verify extracted content
    assert!(rootfs_dir.join("etc/passwd").is_file());
    assert!(rootfs_dir.join("etc/group").is_file());
    assert!(rootfs_dir.join("bin/sh").is_file());
    assert!(rootfs_dir.join("app/data.txt").is_file());

    // Second assembly to existing destination must fail without overwriting
    let err = setup
        .service
        .assemble_rootfs(&record, &rootfs_dir)
        .unwrap_err();

    assert!(
        matches!(
            err,
            ImageServiceError::Image(tavik_image::ImageError::DestinationAlreadyExists(_))
        ),
        "Expected DestinationAlreadyExists, got: {err:?}"
    );
}

// -----------------------------------------------------------------------------
// Tests for Phase D, E, F, G: Spec Generation, Overrides, StopSignal, Volumes
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_create_bundle_end_to_end_user_and_spec_resolution() {
    let arch = detect_host_arch();
    let setup = setup_test_image(
        arch,
        "linux",
        Some("alice:developers"),
        Some(vec!["/bin/sh".to_string()]),
        Some(vec!["-c".to_string(), "echo hi".to_string()]),
        Some("SIGQUIT"),
    )
    .await;

    let bundle_dir = setup._temp.path().join("test_bundle_alice");

    let bundle_info = setup
        .service
        .create_bundle(&setup.reference, &bundle_dir, None, true)
        .await
        .expect("Create bundle should succeed");

    assert_eq!(bundle_info.bundle_dir, bundle_dir);
    assert_eq!(bundle_info.rootfs_dir, bundle_dir.join("rootfs"));

    // User resolution: alice (1001), group developers (2000)
    assert_eq!(bundle_info.resolved_user.uid, 1001);
    assert_eq!(bundle_info.resolved_user.gid, 2000);
    assert_eq!(
        bundle_info.resolved_user.username,
        Some("alice".to_string())
    );
    assert_eq!(
        bundle_info.resolved_user.groupname,
        Some("developers".to_string())
    );

    // Supplementary groups for alice in /etc/group (excluding primary gid 2000): staff (3000)
    assert_eq!(bundle_info.resolved_user.additional_gids, vec![3000]);

    // OCI Runtime Spec mapping
    let proc = bundle_info.spec.process.as_ref().unwrap();
    assert_eq!(proc.user.uid, 1001);
    assert_eq!(proc.user.gid, 2000);
    assert_eq!(proc.user.additional_gids, vec![3000]);
    assert_eq!(proc.args, vec!["/bin/sh", "-c", "echo hi"]);
    assert_eq!(proc.cwd, "/app");
    assert!(proc.env.iter().any(|e| e == "ENV_VAR=prod"));

    // Stop signal preserved
    assert_eq!(bundle_info.stop_signal, "SIGQUIT");
    assert_eq!(
        bundle_info.spec.annotations.get("tavik.stop_signal"),
        Some(&"SIGQUIT".to_string())
    );

    // Volumes exposed as metadata without host mount creation
    assert_eq!(bundle_info.declared_volumes.len(), 1);
    assert_eq!(
        bundle_info.declared_volumes[0].destination,
        PathBuf::from("/var/log")
    );
    assert!(bundle_info
        .spec
        .annotations
        .contains_key("tavik.image.volumes"));

    // config.json on disk
    let config_path = bundle_dir.join("config.json");
    assert!(config_path.is_file());
    let on_disk_spec: tavik_runtime::Spec =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(on_disk_spec.process.unwrap().user.uid, 1001);
}

#[tokio::test]
async fn test_create_bundle_command_override_behavior() {
    let arch = detect_host_arch();
    let setup = setup_test_image(
        arch,
        "linux",
        Some("root"),
        Some(vec!["/bin/sh".to_string()]),
        Some(vec!["-c".to_string(), "echo default".to_string()]),
        None,
    )
    .await;

    // 1. User command replaces image Cmd
    let bundle_dir1 = setup._temp.path().join("bundle_cmd_override");
    let overrides1 = ImageConfigOverrides {
        command: Some(vec!["-c".to_string(), "echo overridden".to_string()]),
        ..Default::default()
    };
    let info1 = setup
        .service
        .create_bundle(&setup.reference, &bundle_dir1, Some(&overrides1), false)
        .await
        .unwrap();
    assert_eq!(
        info1.spec.process.as_ref().unwrap().args,
        vec!["/bin/sh", "-c", "echo overridden"]
    );

    // 2. User entrypoint replaces image Entrypoint
    let bundle_dir2 = setup._temp.path().join("bundle_ep_override");
    let overrides2 = ImageConfigOverrides {
        entrypoint: Some(vec!["/bin/custom_sh".to_string()]),
        ..Default::default()
    };
    let info2 = setup
        .service
        .create_bundle(&setup.reference, &bundle_dir2, Some(&overrides2), false)
        .await
        .unwrap();
    assert_eq!(
        info2.spec.process.as_ref().unwrap().args,
        vec!["/bin/custom_sh", "-c", "echo default"]
    );

    // 3. Explicitly empty entrypoint leaves only command
    let bundle_dir3 = setup._temp.path().join("bundle_clear_ep");
    let overrides3 = ImageConfigOverrides {
        entrypoint: Some(vec![]),
        command: Some(vec!["sh".to_string(), "run.sh".to_string()]),
        ..Default::default()
    };
    let info3 = setup
        .service
        .create_bundle(&setup.reference, &bundle_dir3, Some(&overrides3), false)
        .await
        .unwrap();
    // Notice "sh" was resolved along container PATH to "/bin/sh"
    assert_eq!(
        info3.spec.process.as_ref().unwrap().args,
        vec!["/bin/sh", "run.sh"]
    );
}

#[tokio::test]
async fn test_executable_path_resolution_in_rootfs() {
    let temp = tempdir().unwrap();
    let rootfs_dir = temp.path().join("rootfs");
    let bin_dir = rootfs_dir.join("bin");
    let local_bin = rootfs_dir.join("usr/local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&local_bin).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // 1. First PATH entry /usr/local/bin contains a directory named "app_tool"
        let app_dir = local_bin.join("app_tool");
        std::fs::create_dir(&app_dir).unwrap();

        // 2. Second PATH entry /bin contains the actual executable "app_tool"
        let app_exec = bin_dir.join("app_tool");
        std::fs::write(&app_exec, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&app_exec, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 3. First PATH entry contains a non-executable file "script_tool" (mode 0644)
        let non_exec = local_bin.join("script_tool");
        std::fs::write(&non_exec, b"non-executable").unwrap();
        std::fs::set_permissions(&non_exec, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Second PATH entry contains the executable "script_tool" (mode 0755)
        let exec_script = bin_dir.join("script_tool");
        std::fs::write(&exec_script, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exec_script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 4. In-rootfs symlink: /usr/local/bin/sym_tool -> /bin/app_tool
        let sym_tool = local_bin.join("sym_tool");
        #[cfg(unix)]
        std::os::unix::fs::symlink("/bin/app_tool", &sym_tool).unwrap();

        let env = vec!["PATH=/usr/local/bin:/bin".to_string()];

        // App tool: first candidate is directory -> skips it -> selects /bin/app_tool!
        let res_app = ImageService::resolve_executable_path(&rootfs_dir, "app_tool", &env).unwrap();
        assert_eq!(res_app, "/bin/app_tool");

        // Script tool: first candidate is non-executable file -> skips it -> selects /bin/script_tool!
        let res_script =
            ImageService::resolve_executable_path(&rootfs_dir, "script_tool", &env).unwrap();
        assert_eq!(res_script, "/bin/script_tool");

        // Symlink tool: resolves through in-rootfs symlink!
        let res_sym = ImageService::resolve_executable_path(&rootfs_dir, "sym_tool", &env).unwrap();
        assert_eq!(res_sym, "/usr/local/bin/sym_tool");

        // Command not found preserves original command name
        let res_missing =
            ImageService::resolve_executable_path(&rootfs_dir, "nonexistent", &env).unwrap();
        assert_eq!(res_missing, "nonexistent");

        // Explicit relative path preserved as-is
        let res_rel = ImageService::resolve_executable_path(&rootfs_dir, "./my_cmd", &env).unwrap();
        assert_eq!(res_rel, "./my_cmd");
    }
}

#[tokio::test]
async fn test_stop_signal_parsing() {
    // Valid signals (symbolic with/without SIG prefix, and numeric)
    assert_eq!(parse_signal("SIGTERM").unwrap(), 15);
    assert_eq!(parse_signal("TERM").unwrap(), 15);
    assert_eq!(parse_signal("SIGKILL").unwrap(), 9);
    assert_eq!(parse_signal("KILL").unwrap(), 9);
    assert_eq!(parse_signal("SIGINT").unwrap(), 2);
    assert_eq!(parse_signal("INT").unwrap(), 2);
    assert_eq!(parse_signal("SIGQUIT").unwrap(), 3);
    assert_eq!(parse_signal("SIGHUP").unwrap(), 1);
    assert_eq!(parse_signal("SIGUSR1").unwrap(), 10);
    assert_eq!(parse_signal("SIGUSR2").unwrap(), 12);
    assert_eq!(parse_signal("SIGSTOP").unwrap(), 19);
    assert_eq!(parse_signal("SIGCONT").unwrap(), 18);
    assert_eq!(parse_signal("15").unwrap(), 15);
    assert_eq!(parse_signal("9").unwrap(), 9);
    assert_eq!(parse_signal("2").unwrap(), 2);
    assert_eq!(parse_signal("1").unwrap(), 1);
    assert_eq!(parse_signal("31").unwrap(), 31);
    assert_eq!(parse_signal("64").unwrap(), 64);

    // Invalid signals: unknown names, zero, negative, out of range, empty
    assert!(parse_signal("UNKNOWN").is_err());
    assert!(parse_signal("SIGINVALID").is_err());
    assert!(parse_signal("0").is_err());
    assert!(parse_signal("-1").is_err());
    assert!(parse_signal("-15").is_err());
    assert!(parse_signal("65").is_err());
    assert!(parse_signal("100").is_err());
    assert!(parse_signal("").is_err());
    assert!(parse_signal("   ").is_err());
}

#[tokio::test]
async fn test_config_blob_digest_corruption_detected() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    // Mutate the configuration blob in CAS store
    let config_path = setup._store.blob_path(&setup.config_digest).unwrap();
    let mut config_bytes = std::fs::read(&config_path).unwrap();
    if let Some(last) = config_bytes.last_mut() {
        *last ^= 0xFF;
    }
    std::fs::write(&config_path, &config_bytes).unwrap();

    let err = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            ImageServiceError::ConfigDigestMismatch {
                ref expected,
                ref actual
            } if expected == &setup.config_digest && actual != expected
        ),
        "Expected ConfigDigestMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn test_create_and_run_container_enforces_diff_id_verification() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    // Modify image config diff_ids to cause mismatch
    let corrupt_diff_id =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let config_json = serde_json::json!({
        "architecture": arch,
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": [corrupt_diff_id]
        },
        "config": {
            "Entrypoint": ["/bin/sh"],
            "Cmd": ["-c", "echo test"]
        }
    });

    let config_bytes = serde_json::to_vec(&config_json).unwrap();
    let (config_digest, _, _) = setup
        ._store
        .ingest_bytes(&config_bytes, None)
        .await
        .unwrap();

    let record = ImageRecord {
        reference: "mismatched-diffid:1.0".to_string(),
        manifest_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        config_digest,
        layer_digests: vec![setup._layer_digest.clone()],
        size: 100,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    setup._store.metadata().save_image(record).await.unwrap();

    let state_dir = setup._temp.path().join("state");
    let executor = tavik_runtime::ContainerExecutor::new(state_dir).unwrap();
    let bundle_dir = setup._temp.path().join("bundle_diffid_fail");

    let err = setup
        .service
        .create_and_run_container(
            &executor,
            "cont-diff-fail",
            "mismatched-diffid:1.0",
            &bundle_dir,
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::DiffIdMismatch { index: 0, .. }),
        "Expected DiffIdMismatch, got: {err:?}"
    );

    // Verify bundle directory was not created or was cleaned up
    assert!(!bundle_dir.exists());
}

#[tokio::test]
async fn test_bundle_atomic_publication_and_existing_sentinel() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    let dest_bundle = setup._temp.path().join("preexisting_bundle");
    std::fs::create_dir_all(&dest_bundle).unwrap();
    let sentinel_file = dest_bundle.join("sentinel.txt");
    std::fs::write(&sentinel_file, b"precious_data").unwrap();

    // Attempt create_bundle onto pre-existing directory must fail
    let err = setup
        .service
        .create_bundle(&setup.reference, &dest_bundle, None, false)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::DestinationAlreadyExists(ref p) if p == &dest_bundle),
        "Expected DestinationAlreadyExists, got: {err:?}"
    );

    // Sentinel file must be completely untouched!
    assert!(sentinel_file.exists());
    assert_eq!(std::fs::read(&sentinel_file).unwrap(), b"precious_data");

    // Failure during config resolution leaves no partial destination
    let fail_bundle = setup._temp.path().join("fail_bundle_no_dest");
    let bad_overrides = ImageConfigOverrides {
        entrypoint: Some(vec![]),
        command: Some(vec![]),
        ..Default::default()
    };
    let err2 = setup
        .service
        .create_bundle(&setup.reference, &fail_bundle, Some(&bad_overrides), false)
        .await
        .unwrap_err();

    assert!(matches!(err2, ImageServiceError::Image(_)));
    assert!(!fail_bundle.exists(), "No partial destination should exist");
}

#[tokio::test]
async fn test_bundle_creation_failure_cleans_up_state() {
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;

    let bundle_dir = setup._temp.path().join("failing_bundle");

    // Invalid override with empty command (no executable)
    let overrides = ImageConfigOverrides {
        entrypoint: Some(vec![]),
        command: Some(vec![]),
        ..Default::default()
    };

    let err = setup
        .service
        .create_bundle(&setup.reference, &bundle_dir, Some(&overrides), false)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ImageServiceError::Image(tavik_image::ImageError::InvalidConfiguration(ref msg)) if msg.contains("No executable specified")),
        "Expected InvalidConfiguration with no executable, got: {err:?}"
    );

    // Ensure the failed bundle directory was completely cleaned up!
    assert!(
        !bundle_dir.exists(),
        "Bundle directory {:?} should have been cleaned up on failure",
        bundle_dir
    );
}

#[tokio::test]
async fn test_create_and_run_container_linux_e2e() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful container execution test (requires root)");
            return;
        }

        let busybox_path = if std::path::Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else if std::path::Path::new("/bin/busybox").exists() {
            "/bin/busybox"
        } else {
            eprintln!("Skipping: busybox not found on host");
            return;
        };

        let busybox_bytes = std::fs::read(busybox_path).expect("Failed to read busybox");

        let arch = detect_host_arch();
        let temp = tempdir().unwrap();
        let store = Arc::new(ContentStore::new(temp.path().join("store")).await.unwrap());
        let service = ImageService::new(store.clone());

        let (layer_bytes, diff_id) = create_tar_gz_layer(&[
            ("bin/busybox", &busybox_bytes, 0o755),
            ("app/run.sh", b"#!/bin/busybox sh\necho test\n", 0o755),
            ("dev/null", b"", 0o666),
            ("etc/passwd", b"user:x:1001:2001:User:/app:/bin/sh\n", 0o644),
            (
                "etc/group",
                b"group:x:2001:\nsubgroup1:x:3001:user\nsubgroup2:x:3002:user\n",
                0o644,
            ),
        ]);

        let (layer_digest, layer_size, _) = store
            .ingest_bytes(&layer_bytes, None)
            .await
            .expect("Failed to ingest layer");

        let config_json = serde_json::json!({
            "architecture": arch,
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": [diff_id]
            },
            "config": {
                "User": "user",
                "WorkingDir": "/app",
                "Env": ["PATH=/nonexistent:/bin"],
                "Entrypoint": ["busybox", "sh", "-c"],
                "Cmd": ["busybox id -u > /uid.out && busybox id -g > /gid.out && busybox id -G > /gids.out && busybox pwd > /cwd.out && sleep 10"],
                "StopSignal": "SIGTERM"
            }
        });

        let config_bytes = serde_json::to_vec(&config_json).unwrap();
        let (config_digest, _, _) = store
            .ingest_bytes(&config_bytes, None)
            .await
            .expect("Failed to ingest config");

        let reference = "e2e-image:1.0".to_string();
        let record = ImageRecord {
            reference: reference.clone(),
            manifest_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            config_digest,
            layer_digests: vec![layer_digest],
            size: layer_size,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        store.metadata().save_image(record).await.unwrap();

        let state_dir = temp.path().join("state");
        let executor = tavik_runtime::ContainerExecutor::new(state_dir).unwrap();
        let bundle_dir = temp.path().join("bundle");
        let container_id = "e2e-image-cont-01";

        let running_state = service
            .create_and_run_container(&executor, container_id, &reference, &bundle_dir, None)
            .await
            .expect("Failed to create and run container");

        assert_eq!(
            running_state.status,
            tavik_runtime::ContainerStatus::Running
        );
        assert!(running_state.pid.is_some());

        // Wait a brief moment for container to execute id and pwd commands
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let rootfs = bundle_dir.join("rootfs");
        let uid_out = std::fs::read_to_string(rootfs.join("uid.out")).expect("uid.out must exist");
        let gid_out = std::fs::read_to_string(rootfs.join("gid.out")).expect("gid.out must exist");
        let gids_out =
            std::fs::read_to_string(rootfs.join("gids.out")).expect("gids.out must exist");
        let cwd_out = std::fs::read_to_string(rootfs.join("cwd.out")).expect("cwd.out must exist");

        // Verify container UID and GID match resolved user
        assert_eq!(uid_out.trim(), "1001", "Expected UID 1001");
        assert_eq!(gid_out.trim(), "2001", "Expected GID 2001");

        // Verify supplementary groups contain 2001, 3001, 3002 and NO host groups
        let groups: Vec<&str> = gids_out.split_whitespace().collect();
        assert!(groups.contains(&"2001"));
        assert!(groups.contains(&"3001"));
        assert!(groups.contains(&"3002"));
        assert_eq!(
            groups.len(),
            3,
            "Expected exactly 3 groups in container: {:?}",
            groups
        );

        // Verify working directory
        assert_eq!(cwd_out.trim(), "/app", "Expected CWD /app");

        // Stop container using its configured stop signal
        service
            .stop_container(&executor, container_id)
            .expect("Failed to stop container");

        // Give process a moment to terminate
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let stopped_state = executor.load_state(container_id).unwrap();
        assert_eq!(
            stopped_state.status,
            tavik_runtime::ContainerStatus::Stopped
        );

        executor.delete(container_id, false).unwrap();
    }
}

#[tokio::test]
async fn test_invalid_working_directory_fails_linux() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful container execution test (requires root)");
            return;
        }

        let busybox_path = if std::path::Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else if std::path::Path::new("/bin/busybox").exists() {
            "/bin/busybox"
        } else {
            return;
        };

        let busybox_bytes = std::fs::read(busybox_path).unwrap();
        let arch = detect_host_arch();
        let temp = tempdir().unwrap();
        let store = Arc::new(ContentStore::new(temp.path().join("store")).await.unwrap());
        let service = ImageService::new(store.clone());

        let (layer_bytes, diff_id) = create_tar_gz_layer(&[
            ("bin/busybox", &busybox_bytes, 0o755),
            ("dev/null", b"", 0o666),
            ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
            ("etc/group", b"root:x:0:\n", 0o644),
        ]);

        let (layer_digest, layer_size, _) = store.ingest_bytes(&layer_bytes, None).await.unwrap();

        let config_json = serde_json::json!({
            "architecture": arch,
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": [diff_id]
            },
            "config": {
                "WorkingDir": "/nonexistent_invalid_cwd",
                "Entrypoint": ["/bin/busybox", "sh", "-c"],
                "Cmd": ["echo ok"]
            }
        });

        let config_bytes = serde_json::to_vec(&config_json).unwrap();
        let (config_digest, _, _) = store.ingest_bytes(&config_bytes, None).await.unwrap();

        let reference = "invalid-cwd-image:1.0".to_string();
        let record = ImageRecord {
            reference: reference.clone(),
            manifest_digest:
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            config_digest,
            layer_digests: vec![layer_digest],
            size: layer_size,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        store.metadata().save_image(record).await.unwrap();

        let state_dir = temp.path().join("state");
        let executor = tavik_runtime::ContainerExecutor::new(state_dir).unwrap();
        let bundle_dir = temp.path().join("bundle_bad_cwd");

        let err = service
            .create_and_run_container(&executor, "bad-cwd-cont", &reference, &bundle_dir, None)
            .await
            .unwrap_err();

        // Must fail closed due to invalid CWD during init
        assert!(matches!(err, ImageServiceError::Runtime(_)));
    }
}
