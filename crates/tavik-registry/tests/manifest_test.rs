use tavik_registry::Manifest;

#[test]
fn test_parse_oci_manifest() {
    let manifest_json = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "size": 1472
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
                "size": 3401234
            }
        ]
    }"#;

    let parsed = Manifest::parse(
        manifest_json.as_bytes(),
        Some("application/vnd.oci.image.manifest.v1+json"),
    )
    .unwrap();
    match parsed {
        Manifest::Single(m) => {
            assert_eq!(m.schema_version, 2);
            assert_eq!(m.config.size, 1472);
            assert_eq!(m.layers.len(), 1);
            assert_eq!(m.layers[0].size, 3401234);
        }
        Manifest::Index(_) => panic!("Expected Manifest::Single, got Index"),
    }
}

#[test]
fn test_parse_oci_image_index_and_platform_lookup() {
    let index_json = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:amd64digest000000000000000000000000000000000000000000000000000000",
                "size": 528,
                "platform": {
                    "architecture": "amd64",
                    "os": "linux"
                }
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:arm64digest111111111111111111111111111111111111111111111111111111",
                "size": 528,
                "platform": {
                    "architecture": "arm64",
                    "os": "linux"
                }
            }
        ]
    }"#;

    let parsed = Manifest::parse(
        index_json.as_bytes(),
        Some("application/vnd.oci.image.index.v1+json"),
    )
    .unwrap();
    match &parsed {
        Manifest::Index(idx) => {
            assert_eq!(idx.manifests.len(), 2);
        }
        Manifest::Single(_) => panic!("Expected Manifest::Index"),
    }

    // Lookup linux/arm64
    let arm_desc = parsed
        .find_platform_descriptor("linux", "arm64", None)
        .unwrap()
        .expect("Should find arm64 platform");
    assert_eq!(
        arm_desc.digest,
        "sha256:arm64digest111111111111111111111111111111111111111111111111111111"
    );

    // Lookup linux/amd64
    let amd_desc = parsed
        .find_platform_descriptor("linux", "amd64", None)
        .unwrap()
        .expect("Should find amd64 platform");
    assert_eq!(
        amd_desc.digest,
        "sha256:amd64digest000000000000000000000000000000000000000000000000000000"
    );

    // Lookup missing platform
    assert!(parsed
        .find_platform_descriptor("windows", "amd64", None)
        .is_err());
}
