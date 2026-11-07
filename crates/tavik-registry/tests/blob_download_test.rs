use tavik_registry::{ImageReference, RegistryClient, RegistryError};
use tempfile::tempdir;

#[tokio::test]
async fn test_download_blob_stream_unsupported_algorithm() {
    let client = RegistryClient::new();
    let reference = ImageReference::parse("alpine").unwrap();
    let temp = tempdir().unwrap();
    let dest = temp.path().join("blob.bin");

    let err = client
        .download_blob_stream(
            &reference,
            "md5:0123456789abcdef0123456789abcdef",
            None,
            &dest,
        )
        .await
        .unwrap_err();

    match err {
        RegistryError::UnsupportedAlgorithm(algo) => assert_eq!(algo, "md5"),
        other => panic!("Expected UnsupportedAlgorithm, got {:?}", other),
    }

    assert!(!dest.exists());
}

#[tokio::test]
async fn test_download_blob_stream_invalid_digest_format() {
    let client = RegistryClient::new();
    let reference = ImageReference::parse("alpine").unwrap();
    let temp = tempdir().unwrap();
    let dest = temp.path().join("blob.bin");

    // Missing hex or invalid length
    let err = client
        .download_blob_stream(&reference, "sha256:short_hex", None, &dest)
        .await
        .unwrap_err();

    match err {
        RegistryError::InvalidDigest(_) => {}
        other => panic!("Expected InvalidDigest, got {:?}", other),
    }

    assert!(!dest.exists());
}

#[tokio::test]
async fn test_download_blob_stream_size_limit_exceeded() {
    let client = RegistryClient::new().with_max_blob_size(1024); // 1 KB limit
    let reference = ImageReference::parse("docker.io/library/alpine:latest").unwrap();
    let temp = tempdir().unwrap();
    let dest = temp.path().join("blob.bin");

    let layer_digest = "sha256:b90627b8f4292fd3cb63f0f27f0b11c37f04ba88ef3b78d4948ea0ace18c85e9";
    let err = client
        .download_blob_stream(&reference, layer_digest, None, &dest)
        .await
        .unwrap_err();

    match err {
        RegistryError::SizeExceeded { limit, actual } => {
            assert_eq!(limit, 1024);
            assert!(actual > 1024);
        }
        other => panic!("Expected SizeExceeded, got {:?}", other),
    }

    assert!(
        !dest.exists(),
        "Destination must not exist if size limit was exceeded"
    );
    let entries: Vec<_> = std::fs::read_dir(temp.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "Temporary file must be cleaned up on error"
    );
}

#[tokio::test]
async fn test_download_blob_stream_size_mismatch() {
    let client = RegistryClient::new();
    let reference = ImageReference::parse("docker.io/library/alpine:latest").unwrap();
    let temp = tempdir().unwrap();
    let dest = temp.path().join("blob.bin");

    let layer_digest = "sha256:b90627b8f4292fd3cb63f0f27f0b11c37f04ba88ef3b78d4948ea0ace18c85e9";
    let err = client
        .download_blob_stream(&reference, layer_digest, Some(999999), &dest)
        .await
        .unwrap_err();

    match err {
        RegistryError::SizeMismatch {
            digest,
            expected,
            actual,
        } => {
            assert_eq!(digest, layer_digest);
            assert_eq!(expected, 999999);
            assert_eq!(actual, 4_190_595);
        }
        other => panic!("Expected SizeMismatch, got {:?}", other),
    }

    assert!(!dest.exists());
    let entries: Vec<_> = std::fs::read_dir(temp.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "Temporary file must be cleaned up on error"
    );
}

#[tokio::test]
async fn test_live_download_alpine_layer_stream() {
    let client = RegistryClient::new();
    let reference = ImageReference::parse("docker.io/library/alpine:latest").unwrap();

    let temp = tempdir().unwrap();
    let dest = temp.path().join("layer.tar.gz");

    // Real Alpine Linux aarch64 / arm64 layer descriptor
    let layer_digest = "sha256:b90627b8f4292fd3cb63f0f27f0b11c37f04ba88ef3b78d4948ea0ace18c85e9";
    let expected_size = 4_190_595u64;

    let download_result = client
        .download_blob_stream(&reference, layer_digest, Some(expected_size), &dest)
        .await;

    match download_result {
        Ok(blob) => {
            println!(
                "Successfully downloaded layer blob: path={:?}, size={} bytes",
                blob.path, blob.size
            );

            assert_eq!(blob.digest, layer_digest);
            assert_eq!(blob.size, expected_size);
            assert_eq!(blob.path, dest);
            assert!(dest.exists(), "Destination file must exist after download");

            let metadata = std::fs::metadata(&dest).unwrap();
            assert_eq!(
                metadata.len(),
                expected_size,
                "File size on disk must equal expected size"
            );

            // Verify no stray .tmp files exist in destination directory
            let entries = std::fs::read_dir(temp.path()).unwrap();
            for entry in entries {
                let entry = entry.unwrap();
                let file_name = entry.file_name().to_string_lossy().to_string();
                assert!(
                    !file_name.contains(".tmp."),
                    "Found lingering temporary file: {}",
                    file_name
                );
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("429")
                || err_msg.contains("Too Many Requests")
                || err_msg.contains("dns error")
                || err_msg.contains("404")
            {
                eprintln!(
                    "Skipping live download test due to network/rate-limiting/upstream: {}",
                    err_msg
                );
            } else {
                panic!("Failed to download live Alpine layer: {}", e);
            }
        }
    }
}
