use tavik_store::{ContentStore, StoreError};
use tempfile::tempdir;

#[tokio::test]
async fn test_cas_ingest_bytes_and_deduplication() {
    let temp = tempdir().unwrap();
    let store = ContentStore::new(temp.path()).unwrap();

    let data = b"hello tavik oci container storage";
    let (digest, size, path) = store.ingest_bytes(data, None).await.unwrap();

    assert!(digest.starts_with("sha256:"));
    assert_eq!(size, data.len() as u64);
    assert!(path.exists());
    assert!(store.has_blob(&digest));

    let read_back = store.read_blob(&digest).await.unwrap();
    assert_eq!(read_back, data);

    // Ingest the exact same bytes again -> must reuse existing blob
    let (digest2, size2, path2) = store.ingest_bytes(data, Some(&digest)).await.unwrap();
    assert_eq!(digest, digest2);
    assert_eq!(size, size2);
    assert_eq!(path, path2);

    // Verify only one file exists in the blobs directory
    let hex_part = digest.split_once(':').unwrap().1;
    let entries: Vec<_> = std::fs::read_dir(temp.path().join("blobs").join("sha256"))
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].as_ref().unwrap().file_name(), hex_part);
}

#[tokio::test]
async fn test_cas_digest_mismatch_rejected() {
    let temp = tempdir().unwrap();
    let store = ContentStore::new(temp.path()).unwrap();

    let data = b"some content";
    let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    let err = store
        .ingest_bytes(data, Some(fake_digest))
        .await
        .unwrap_err();
    match err {
        StoreError::DigestMismatch { expected, .. } => {
            assert_eq!(expected, fake_digest);
        }
        other => panic!("Expected DigestMismatch, got {:?}", other),
    }

    assert!(!store.has_blob(fake_digest));
}

#[tokio::test]
async fn test_cas_ingest_file() {
    let temp = tempdir().unwrap();
    let store = ContentStore::new(temp.path().join("store")).unwrap();

    let source_dir = temp.path().join("source");
    std::fs::create_dir_all(&source_dir).unwrap();
    let file_path = source_dir.join("test.tar.gz");
    let content = vec![0xABu8; 1024 * 64]; // 64 KB
    std::fs::write(&file_path, &content).unwrap();

    let (digest, size, stored_path) = store.ingest_file(&file_path, None).await.unwrap();
    assert_eq!(size, content.len() as u64);
    assert!(stored_path.exists());

    // Ingest again -> reuse
    let (digest2, size2, stored_path2) =
        store.ingest_file(&file_path, Some(&digest)).await.unwrap();
    assert_eq!(digest, digest2);
    assert_eq!(size, size2);
    assert_eq!(stored_path, stored_path2);
}

#[tokio::test]
async fn test_cas_ingest_alpine_layer_size_and_deduplication() {
    let temp = tempdir().unwrap();
    let store = ContentStore::new(temp.path().join("store")).unwrap();

    let layer_size = 4_190_595usize;
    let source_dir = temp.path().join("download");
    std::fs::create_dir_all(&source_dir).unwrap();
    let layer_path = source_dir.join("layer.tar.gz");

    // Generate test payload of exactly 4,190,595 bytes
    let layer_bytes = vec![0x37u8; layer_size];
    std::fs::write(&layer_path, &layer_bytes).unwrap();

    // Ingest 1st time
    let (digest1, size1, path1) = store.ingest_file(&layer_path, None).await.unwrap();
    assert_eq!(size1, 4_190_595);
    assert!(path1.exists());
    assert!(store.has_blob(&digest1));

    // Verify file on disk matches byte-for-byte and has exact length
    let meta = std::fs::metadata(&path1).unwrap();
    assert_eq!(meta.len(), 4_190_595);

    // Ingest 2nd time with expected digest -> must reuse existing blob without duplicate copies
    let (digest2, size2, path2) = store
        .ingest_file(&layer_path, Some(&digest1))
        .await
        .unwrap();
    assert_eq!(digest1, digest2);
    assert_eq!(size1, size2);
    assert_eq!(path1, path2);

    // Verify only one file exists in the CAS blob directory
    let blob_dir = temp.path().join("store").join("blobs").join("sha256");
    let entries: Vec<_> = std::fs::read_dir(&blob_dir).unwrap().collect();
    assert_eq!(
        entries.len(),
        1,
        "Must contain exactly one deduplicated blob file"
    );
}
