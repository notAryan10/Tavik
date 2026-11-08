use tavik_image::{ImageConfiguration, ImageError};
use tempfile::NamedTempFile;

#[test]
fn test_valid_oci_image_configuration() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "variant": "v8",
        "os.version": "1.0",
        "os.features": ["win32k"],
        "created": "2026-11-08T10:00:00Z",
        "author": "TAVIK Team <team@tavik.dev>",
        "config": {
            "User": "1000:1000",
            "ExposedPorts": {
                "8080/tcp": {}
            },
            "Env": [
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "APP_ENV=production"
            ],
            "Entrypoint": ["/usr/bin/entrypoint.sh"],
            "Cmd": ["server", "--port", "8080"],
            "Volumes": {
                "/var/data": {},
                "/etc/tavik": {}
            },
            "WorkingDir": "/app",
            "Labels": {
                "org.opencontainers.image.title": "test-app",
                "org.opencontainers.image.version": "1.0.0"
            },
            "StopSignal": "SIGTERM"
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [
                "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
                "sha256:776e0a96996d915998a4421b4a69cf4f20ea4b8069a57253457bf4b9c1d6ff17"
            ]
        },
        "history": [
            {
                "created": "2026-11-08T09:00:00Z",
                "created_by": "ADD layer1 /",
                "comment": "base layer"
            },
            {
                "created": "2026-11-08T09:30:00Z",
                "created_by": "RUN apt-get update",
                "empty_layer": true
            }
        ]
    }"#;

    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    assert_eq!(config.architecture, "arm64");
    assert_eq!(config.os, "linux");
    assert_eq!(config.variant.as_deref(), Some("v8"));
    assert_eq!(config.os_version.as_deref(), Some("1.0"));
    assert_eq!(config.os_features, Some(vec!["win32k".to_string()]));
    assert_eq!(config.created.as_deref(), Some("2026-11-08T10:00:00Z"));
    assert_eq!(
        config.author.as_deref(),
        Some("TAVIK Team <team@tavik.dev>")
    );

    let container = config.config.as_ref().unwrap();
    assert_eq!(container.user.as_deref(), Some("1000:1000"));
    assert!(container
        .exposed_ports
        .as_ref()
        .unwrap()
        .contains_key("8080/tcp"));
    assert_eq!(container.working_dir.as_deref(), Some("/app"));
    assert_eq!(container.stop_signal.as_deref(), Some("SIGTERM"));
    assert_eq!(
        container.entrypoint.as_deref(),
        Some(&["/usr/bin/entrypoint.sh".to_string()][..])
    );
    assert_eq!(
        container.cmd.as_deref(),
        Some(
            &[
                "server".to_string(),
                "--port".to_string(),
                "8080".to_string()
            ][..]
        )
    );

    assert_eq!(config.rootfs.type_name, "layers");
    assert_eq!(config.rootfs.diff_ids.len(), 2);
    assert_eq!(config.history.as_ref().unwrap().len(), 2);
    assert_eq!(config.history.as_ref().unwrap()[1].empty_layer, Some(true));
}

#[test]
fn test_valid_docker_compatible_configuration() {
    let json = r#"{
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "user": "root",
            "exposed_ports": {
                "80/tcp": {}
            },
            "env": ["LANG=C.UTF-8"],
            "entrypoint": ["/bin/sh"],
            "cmd": ["-c", "echo hello"],
            "volumes": {"/data": {}},
            "working_dir": "/root",
            "labels": {"app": "demo"},
            "stop_signal": "15",
            "args_escaped": true
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": [
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ]
        }
    }"#;

    use std::io::Write;
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(json.as_bytes()).unwrap();

    let config = ImageConfiguration::from_file(tmp.path()).unwrap();
    assert_eq!(config.architecture, "amd64");
    assert_eq!(config.os, "linux");

    let container = config.config.as_ref().unwrap();
    assert_eq!(container.user.as_deref(), Some("root"));
    assert_eq!(container.working_dir.as_deref(), Some("/root"));
    assert_eq!(container.stop_signal.as_deref(), Some("15"));
    assert_eq!(container.args_escaped, Some(true));
    assert!(container.volumes.as_ref().unwrap().contains_key("/data"));
    assert_eq!(
        container.env.as_deref(),
        Some(&["LANG=C.UTF-8".to_string()][..])
    );
}

#[test]
fn test_missing_required_fields() {
    // Missing architecture
    let json1 = r#"{
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []}
    }"#;
    assert!(ImageConfiguration::from_bytes(json1.as_bytes()).is_err());

    // Missing os
    let json2 = r#"{
        "architecture": "arm64",
        "rootfs": {"type": "layers", "diff_ids": []}
    }"#;
    assert!(ImageConfiguration::from_bytes(json2.as_bytes()).is_err());

    // Missing rootfs
    let json3 = r#"{
        "architecture": "arm64",
        "os": "linux"
    }"#;
    assert!(ImageConfiguration::from_bytes(json3.as_bytes()).is_err());
}

#[test]
fn test_invalid_architecture_and_os_metadata() {
    let base = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []}
    }"#;
    let mut config: ImageConfiguration = serde_json::from_str(base).unwrap();

    // Empty architecture
    config.architecture = "".to_string();
    let err = config.validate().unwrap_err();
    assert!(matches!(err, ImageError::InvalidConfiguration(_)));

    // Whitespace architecture
    config.architecture = "   ".to_string();
    let err = config.validate().unwrap_err();
    assert!(matches!(err, ImageError::InvalidConfiguration(_)));

    // Empty OS
    config.architecture = "arm64".to_string();
    config.os = "".to_string();
    let err = config.validate().unwrap_err();
    assert!(matches!(err, ImageError::InvalidConfiguration(_)));

    // Whitespace OS
    config.os = "\t  \n".to_string();
    let err = config.validate().unwrap_err();
    assert!(matches!(err, ImageError::InvalidConfiguration(_)));
}

#[test]
fn test_invalid_rootfs_type() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "overlay",
            "diff_ids": []
        }
    }"#;
    let err = ImageConfiguration::from_bytes(json.as_bytes()).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref s) if s.contains("expected 'layers'"))
    );
}

#[test]
fn test_invalid_diff_ids() {
    // 1. Missing sha256 prefix
    let json1 = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"]
        }
    }"#;
    let err = ImageConfiguration::from_bytes(json1.as_bytes()).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref s) if s.contains("must specify sha256 algorithm"))
    );

    // 2. Short digest length
    let json2 = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:1234abcd"]
        }
    }"#;
    let err = ImageConfiguration::from_bytes(json2.as_bytes()).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref s) if s.contains("exactly 64 lowercase hexadecimal"))
    );

    // 3. Uppercase hex
    let json3 = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:5F70BF18A086007016E948B04AED3B82103A36BEA41755B6CDDFAF10ACE3C6EF"]
        }
    }"#;
    let err = ImageConfiguration::from_bytes(json3.as_bytes()).unwrap_err();
    assert!(matches!(err, ImageError::InvalidConfiguration(_)));

    // 4. Non-hex characters
    let json4 = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:zz70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"]
        }
    }"#;
    let err = ImageConfiguration::from_bytes(json4.as_bytes()).unwrap_err();
    assert!(matches!(err, ImageError::InvalidConfiguration(_)));
}

#[test]
fn test_missing_and_null_config() {
    // Config omitted
    let json_omitted = r#"{
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config1 = ImageConfiguration::from_bytes(json_omitted.as_bytes()).unwrap();
    assert!(config1.config.is_none());

    // Config null
    let json_null = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": null,
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config2 = ImageConfiguration::from_bytes(json_null.as_bytes()).unwrap();
    assert!(config2.config.is_none());
}

#[test]
fn test_null_entrypoint_and_cmd() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": {
            "Entrypoint": null,
            "Cmd": null
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    let container = config.config.unwrap();
    assert!(container.entrypoint.is_none());
    assert!(container.cmd.is_none());
}

#[test]
fn test_empty_entrypoint_and_cmd() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": {
            "Entrypoint": [],
            "Cmd": []
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    let container = config.config.unwrap();
    assert_eq!(container.entrypoint, Some(vec![]));
    assert_eq!(container.cmd, Some(vec![]));
}

#[test]
fn test_environment_parsing_and_empty_values() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": {
            "Env": [
                "PATH=/usr/bin",
                "FOO=bar",
                "EMPTY_VAL=",
                "EQUALS_IN_VAL=a=b=c"
            ]
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    let envs = config.config.unwrap().env.unwrap();
    assert_eq!(envs.len(), 4);
    assert_eq!(envs[2], "EMPTY_VAL=");
    assert_eq!(envs[3], "EQUALS_IN_VAL=a=b=c");
}

#[test]
fn test_malformed_environment_entries() {
    let check_env = |env_entry: &str| {
        let json = format!(
            r#"{{
                "architecture": "arm64",
                "os": "linux",
                "config": {{
                    "Env": ["{env_entry}"]
                }},
                "rootfs": {{
                    "type": "layers",
                    "diff_ids": []
                }}
            }}"#
        );
        ImageConfiguration::from_bytes(json.as_bytes())
    };

    // Missing '='
    let err1 = check_env("KEY_WITHOUT_EQUALS").unwrap_err();
    assert!(
        matches!(err1, ImageError::InvalidConfiguration(ref s) if s.contains("must follow KEY=VALUE format"))
    );

    // Empty key name
    let err2 = check_env("=VALUE").unwrap_err();
    assert!(
        matches!(err2, ImageError::InvalidConfiguration(ref s) if s.contains("variable name cannot be empty"))
    );

    // Empty string
    let err3 = check_env("").unwrap_err();
    assert!(matches!(err3, ImageError::InvalidConfiguration(_)));
}

#[test]
fn test_volume_map_parsing_and_valid_paths() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": {
            "Volumes": {
                "/var/log": {},
                "/data": null,
                "/etc/ssl/certs": {"comment": "certificates"}
            }
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    let vols = config.config.unwrap().volumes.unwrap();
    assert_eq!(vols.len(), 3);
    assert!(vols.contains_key("/var/log"));
    assert!(vols.contains_key("/data"));
    assert!(vols.contains_key("/etc/ssl/certs"));
}

#[test]
fn test_invalid_volume_paths() {
    let check_vol = |vol_path: &str| {
        let json = format!(
            r#"{{
                "architecture": "arm64",
                "os": "linux",
                "config": {{
                    "Volumes": {{
                        "{vol_path}": {{}}
                    }}
                }},
                "rootfs": {{
                    "type": "layers",
                    "diff_ids": []
                }}
            }}"#
        );
        ImageConfiguration::from_bytes(json.as_bytes())
    };

    // Relative path (missing leading '/')
    let err1 = check_vol("data/store").unwrap_err();
    assert!(
        matches!(err1, ImageError::InvalidConfiguration(ref s) if s.contains("must be an absolute container path"))
    );

    // Parent directory traversal
    let err2 = check_vol("/var/../etc").unwrap_err();
    assert!(
        matches!(err2, ImageError::InvalidConfiguration(ref s) if s.contains("parent directory traversal '..' is forbidden"))
    );

    // Parent traversal at beginning or end
    let err3 = check_vol("/../var").unwrap_err();
    assert!(matches!(err3, ImageError::InvalidConfiguration(_)));
}

#[test]
fn test_labels_and_stopsignal() {
    let json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": {
            "Labels": {
                "maintainer": "TAVIK",
                "environment": "ci"
            },
            "StopSignal": "SIGQUIT"
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    let container = config.config.unwrap();
    let labels = container.labels.unwrap();
    assert_eq!(labels.get("maintainer").map(|s| s.as_str()), Some("TAVIK"));
    assert_eq!(labels.get("environment").map(|s| s.as_str()), Some("ci"));
    assert_eq!(container.stop_signal.as_deref(), Some("SIGQUIT"));

    // Empty StopSignal fails validation
    let empty_sig_json = r#"{
        "architecture": "arm64",
        "os": "linux",
        "config": {
            "StopSignal": "   "
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;
    let err = ImageConfiguration::from_bytes(empty_sig_json.as_bytes()).unwrap_err();
    assert!(
        matches!(err, ImageError::InvalidConfiguration(ref s) if s.contains("StopSignal must not be empty"))
    );
}

#[test]
fn test_unknown_extension_fields() {
    let json = r#"{
        "architecture": "amd64",
        "os": "linux",
        "docker_version": "24.0.5",
        "extra_custom_field": {
            "nested": "value"
        },
        "config": {
            "User": "root",
            "OnBuild": ["RUN echo built"],
            "NetworkDisabled": false
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        }
    }"#;

    // Must successfully parse and validate without error, ignoring unknown extension fields
    let config = ImageConfiguration::from_bytes(json.as_bytes()).unwrap();
    assert_eq!(config.architecture, "amd64");
    assert_eq!(
        config.config.as_ref().unwrap().user.as_deref(),
        Some("root")
    );
}

#[test]
fn test_invalid_json_fails_loudly() {
    let malformed_json = r#"{ "architecture": "arm64", "#;
    let err = ImageConfiguration::from_bytes(malformed_json.as_bytes()).unwrap_err();
    assert!(matches!(err, ImageError::Json(_)));
}
