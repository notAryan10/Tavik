use tavik_store::ContentStore;
use tempfile::tempdir;

#[tokio::test]
async fn test_integrity_verification_and_corruption_detection() {
    let temp = tempdir().unwrap();
    let store = ContentStore::new(temp.path()).unwrap();

    let data = b"genuine uncorrupted blob payload data";
    let (digest, _, path) = store.ingest_bytes(data, None).await.unwrap();

    // Verification must pass on genuine blob
    assert!(store.verify_blob_integrity(&digest).await.unwrap());

    // Corrupt the blob on disk
    std::fs::write(&path, b"corrupted payload data!").unwrap();

    // Verification must now detect corruption
    assert!(!store.verify_blob_integrity(&digest).await.unwrap());
}

#[tokio::test]
async fn test_concurrent_ingestion_safety() {
    let temp = tempdir().unwrap();
    let store = std::sync::Arc::new(ContentStore::new(temp.path()).unwrap());

    let payload = vec![0x42u8; 1024 * 128]; // 128 KB
    let mut handles = Vec::new();

    // Launch 10 concurrent tasks all trying to ingest the exact same content
    for _ in 0..10 {
        let store_clone = store.clone();
        let payload_clone = payload.clone();
        let handle =
            tokio::spawn(async move { store_clone.ingest_bytes(&payload_clone, None).await });
        handles.push(handle);
    }

    let mut digests = Vec::new();
    for handle in handles {
        let res = handle.await.unwrap().unwrap();
        digests.push(res.0);
    }

    // All tasks must produce identical digest
    assert_eq!(digests.len(), 10);
    for d in &digests {
        assert_eq!(d, &digests[0]);
    }

    // Only 1 file must exist on disk
    let entries: Vec<_> = std::fs::read_dir(temp.path().join("blobs").join("sha256"))
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
}
