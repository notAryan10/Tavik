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
    let arch = detect_host_arch();
    let setup = setup_test_image(arch, "linux", None, None, None, None).await;
    let bundle_dir = setup._temp.path().join("bundle_path_res");
    let rootfs_dir = bundle_dir.join("rootfs");

    let (record, _) = setup
        .service
        .load_image_config(&setup.reference)
        .await
        .unwrap();
    setup.service.assemble_rootfs(&record, &rootfs_dir).unwrap();

    let env = vec!["PATH=/usr/bin:/bin".to_string()];

    // Unqualified "sh" resolves to "/bin/sh" inside rootfs
    let resolved = ImageService::resolve_executable_path(&rootfs_dir, "sh", &env).unwrap();
    assert_eq!(resolved, "/bin/sh");

    // Explicit path "/bin/sh" preserved as-is
    let explicit = ImageService::resolve_executable_path(&rootfs_dir, "/bin/sh", &env).unwrap();
    assert_eq!(explicit, "/bin/sh");

    // Command not found in rootfs PATH preserves original name
    let unknown = ImageService::resolve_executable_path(&rootfs_dir, "unknown_tool", &env).unwrap();
    assert_eq!(unknown, "unknown_tool");
}

#[tokio::test]
async fn test_stop_signal_parsing() {
    assert_eq!(parse_signal("SIGTERM"), 15);
    assert_eq!(parse_signal("15"), 15);
    assert_eq!(parse_signal("SIGKILL"), 9);
    assert_eq!(parse_signal("9"), 9);
    assert_eq!(parse_signal("SIGINT"), 2);
    assert_eq!(parse_signal("SIGQUIT"), 3);
    assert_eq!(parse_signal("SIGUSR1"), 10);
    assert_eq!(parse_signal("SIGUSR2"), 12);
    assert_eq!(parse_signal("UNKNOWN"), 15); // Fallback to 15 (SIGTERM)
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

        let dev_null = b"";
        let (layer_bytes, diff_id) = create_tar_gz_layer(&[
            ("bin/busybox", &busybox_bytes, 0o755),
            ("dev/null", dev_null, 0o666),
            ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
            ("etc/group", b"root:x:0:\n", 0o644),
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
                "Entrypoint": ["/bin/busybox", "sh", "-c"],
                "Cmd": ["echo running_from_image > /test.out && sleep 10"],
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

        // Wait a brief moment for container to execute echo
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let out_file = bundle_dir.join("rootfs").join("test.out");
        assert!(
            out_file.exists(),
            "Expected /test.out to exist inside container rootfs"
        );
        let content = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(content.trim(), "running_from_image");

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
