use tavik_registry::{ImageReference, RegistryClient};

#[tokio::test]
async fn test_live_resolve_docker_hub_alpine_manifest() {
    let client = RegistryClient::new();
    let reference = ImageReference::parse("docker.io/library/alpine:latest").unwrap();

    let result = client
        .resolve_manifest_for_platform(&reference, "linux", "arm64", None)
        .await;

    match result {
        Ok((manifest, digest)) => {
            println!("Successfully resolved alpine:latest to digest: {}", digest);
            println!("Config digest: {}", manifest.config.digest);
            println!("Layer count: {}", manifest.layers.len());

            assert!(
                !manifest.layers.is_empty(),
                "Manifest must contain at least 1 layer"
            );
            assert!(
                manifest.config.digest.starts_with("sha256:"),
                "Config digest must start with sha256:"
            );
            for (idx, layer) in manifest.layers.iter().enumerate() {
                println!(
                    "  Layer {}: digest={}, size={} bytes",
                    idx, layer.digest, layer.size
                );
                assert!(layer.digest.starts_with("sha256:"));
                assert!(layer.size > 0);
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            // Docker Hub rate limits anonymous pulls (HTTP 429) or offline network
            if err_msg.contains("429")
                || err_msg.contains("Too Many Requests")
                || err_msg.contains("dns error")
            {
                eprintln!(
                    "Skipping live Docker Hub test due to network/rate-limiting: {}",
                    err_msg
                );
            } else {
                panic!("Failed to resolve docker.io/library/alpine:latest: {}", e);
            }
        }
    }
}
