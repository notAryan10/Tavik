use tavik_registry::{pull_image, ImageReference, RegistryClient};
use tavik_store::ContentStore;
use tempfile::tempdir;

#[tokio::test]
async fn test_live_pull_alpine_and_cas_deduplication() {
    let client = RegistryClient::new();
    let reference = ImageReference::parse("docker.io/library/alpine:latest").unwrap();
    let temp = tempdir().unwrap();
    let store = ContentStore::new(temp.path()).unwrap();

    let target_os = "linux";
    let target_arch = "arm64";

    // --- Pull 1: Initial download and CAS ingestion ---
    let pull1_result = pull_image(&client, &store, &reference, target_os, target_arch, None).await;

    let res1 = match pull1_result {
        Ok(res) => res,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("429")
                || msg.contains("Too Many Requests")
                || msg.contains("dns error")
                || msg.contains("timeout")
            {
                eprintln!(
                    "Skipping live pull test due to network/rate-limiting: {}",
                    msg
                );
                return;
            } else {
                panic!("Initial pull of alpine:latest failed: {}", e);
            }
        }
    };

    println!(
        "Pull 1 succeeded: record={:?}, new_blobs={}, reused_blobs={}",
        res1.record, res1.newly_downloaded_blobs, res1.reused_blobs
    );

    // Initial pull should have downloaded at least 1 config blob and 1 layer blob
    assert!(
        res1.newly_downloaded_blobs >= 2,
        "Expected config + layer blobs downloaded"
    );
    assert_eq!(res1.reused_blobs, 0);

    // Verify both config and all layers exist in CAS and have valid hashes
    assert!(store.has_blob(&res1.record.config_digest));
    assert!(store
        .verify_blob_integrity(&res1.record.config_digest)
        .await
        .unwrap());

    for layer_digest in &res1.record.layer_digests {
        assert!(store.has_blob(layer_digest));
        assert!(store.verify_blob_integrity(layer_digest).await.unwrap());
    }

    // Verify metadata record was stored
    let saved_record = store
        .metadata()
        .get_image(&reference.canonical())
        .await
        .unwrap()
        .expect("ImageRecord must be saved in metadata");
    assert_eq!(saved_record.manifest_digest, res1.record.manifest_digest);
    assert_eq!(saved_record.config_digest, res1.record.config_digest);
    assert_eq!(saved_record.layer_digests, res1.record.layer_digests);

    // Count blob files on disk after Pull 1
    let blobs_dir = temp.path().join("blobs").join("sha256");
    let initial_blob_count = std::fs::read_dir(&blobs_dir).unwrap().count();
    assert_eq!(initial_blob_count, res1.newly_downloaded_blobs);

    // --- Pull 2: Re-pulling identical image -> 100% deduplicated ---
    let pull2_result = pull_image(&client, &store, &reference, target_os, target_arch, None).await;

    let res2 = match pull2_result {
        Ok(res) => res,
        Err(e) => {
            panic!("Second pull of alpine:latest failed: {}", e);
        }
    };

    println!(
        "Pull 2 succeeded: record={:?}, new_blobs={}, reused_blobs={}",
        res2.record, res2.newly_downloaded_blobs, res2.reused_blobs
    );

    // Pull 2 must NOT download any new blobs; all must be reused from CAS!
    assert_eq!(
        res2.newly_downloaded_blobs, 0,
        "No new blobs should be downloaded on repull"
    );
    assert_eq!(
        res2.reused_blobs, res1.newly_downloaded_blobs,
        "All blobs should be reused"
    );

    // Total blob count on disk must NOT have changed!
    let second_blob_count = std::fs::read_dir(&blobs_dir).unwrap().count();
    assert_eq!(
        initial_blob_count, second_blob_count,
        "No duplicate content blobs must be created on re-pull"
    );

    // Verify no temporary files remain in tmp/
    let tmp_dir = temp.path().join("tmp");
    let tmp_count = std::fs::read_dir(&tmp_dir).unwrap().count();
    assert_eq!(
        tmp_count, 0,
        "Store tmp/ directory must be empty after completion"
    );
}
