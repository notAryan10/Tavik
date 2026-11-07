use chrono::Utc;
use tavik_store::{ImageRecord, MetadataStore};
use tempfile::tempdir;

#[tokio::test]
async fn test_metadata_save_and_retrieve() {
    let temp = tempdir().unwrap();
    let meta_file = temp.path().join("images.json");
    let store = MetadataStore::new(&meta_file);

    let record = ImageRecord {
        reference: "docker.io/library/alpine:latest".to_string(),
        manifest_digest: "sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29"
            .to_string(),
        config_digest: "sha256:abbc135a7d3909a5eb6a56aac4c769cf15be025e3c9e226b8660f2b2b378158b"
            .to_string(),
        layer_digests: vec![
            "sha256:b90627b8f4292fd3cb63f0f27f0b11c37f04ba88ef3b78d4948ea0ace18c85e9".to_string(),
        ],
        size: 4190595,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    store.save_image(record.clone()).await.unwrap();

    // Query by reference
    let found = store
        .get_image("docker.io/library/alpine:latest")
        .await
        .unwrap()
        .expect("Should find image by reference");
    assert_eq!(found.reference, record.reference);
    assert_eq!(found.manifest_digest, record.manifest_digest);
    assert_eq!(found.size, 4190595);

    // Query by manifest digest
    let found_by_digest = store
        .get_image(&record.manifest_digest)
        .await
        .unwrap()
        .expect("Should find image by manifest digest");
    assert_eq!(found_by_digest.reference, record.reference);

    // List images
    let list = store.list_images().await.unwrap();
    assert_eq!(list.len(), 1);

    // Remove image
    let removed = store
        .remove_image("docker.io/library/alpine:latest")
        .await
        .unwrap();
    assert!(removed);

    let list_after = store.list_images().await.unwrap();
    assert!(list_after.is_empty());
}
