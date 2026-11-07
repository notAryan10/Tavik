use crate::digest::{compute_sha256, compute_sha256_file, validate_sha256};
use crate::error::StoreError;
use crate::lock::KeyedLock;
use crate::metadata::MetadataStore;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::debug;

/// Content-Addressable Storage (CAS) for OCI image blobs and metadata.
#[derive(Debug)]
pub struct ContentStore {
    root: PathBuf,
    blobs_dir: PathBuf,
    tmp_dir: PathBuf,
    metadata: MetadataStore,
    locks: KeyedLock,
}

impl ContentStore {
    /// Initializes or opens a `ContentStore` at the specified root directory.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        let blobs_dir = root.join("blobs").join("sha256");
        let tmp_dir = root.join("tmp");
        let metadata_file = root.join("metadata").join("images.json");

        std::fs::create_dir_all(&blobs_dir)?;
        std::fs::create_dir_all(&tmp_dir)?;
        if let Some(parent) = metadata_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let metadata = MetadataStore::new(metadata_file);
        let locks = KeyedLock::new();

        Ok(Self {
            root,
            blobs_dir,
            tmp_dir,
            metadata,
            locks,
        })
    }

    /// Returns the root directory of the store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the metadata store handle.
    pub fn metadata(&self) -> &MetadataStore {
        &self.metadata
    }

    /// Resolves the absolute path for a blob identified by `sha256:<hex>`.
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf, StoreError> {
        let hex_str = validate_sha256(digest)?;
        Ok(self.blobs_dir.join(hex_str))
    }

    /// Checks if a blob exists in the store.
    pub fn has_blob(&self, digest: &str) -> bool {
        match self.blob_path(digest) {
            Ok(p) => p.exists(),
            Err(_) => false,
        }
    }

    /// Returns the size in bytes of a stored blob.
    pub async fn blob_size(&self, digest: &str) -> Result<u64, StoreError> {
        let path = self.blob_path(digest)?;
        if !path.exists() {
            return Err(StoreError::BlobNotFound(digest.to_string()));
        }
        let meta = tokio::fs::metadata(&path).await?;
        Ok(meta.len())
    }

    /// Ingests in-memory bytes into the content-addressable store.
    /// If `expected_digest` is provided, verifies that the computed hash matches before saving.
    /// Reuses existing valid blobs without rewriting.
    pub async fn ingest_bytes(
        &self,
        bytes: &[u8],
        expected_digest: Option<&str>,
    ) -> Result<(String, u64, PathBuf), StoreError> {
        let computed_digest = compute_sha256(bytes);
        if let Some(expected) = expected_digest {
            if computed_digest != expected {
                return Err(StoreError::DigestMismatch {
                    digest: expected.to_string(),
                    expected: expected.to_string(),
                    actual: computed_digest,
                });
            }
        }

        let _guard = self.locks.lock(&computed_digest).await;
        let final_path = self.blob_path(&computed_digest)?;

        // Deduplication: if blob already exists and is intact, return immediately
        if final_path.exists() {
            let meta = tokio::fs::metadata(&final_path).await?;
            if meta.len() == bytes.len() as u64 {
                debug!(
                    "Blob {} already exists; reusing without re-writing",
                    computed_digest
                );
                return Ok((computed_digest, meta.len(), final_path));
            }
        }

        // Write to temporary file in same filesystem
        let temp_path = self
            .tmp_dir
            .join(format!("blob.tmp.{}", uuid::Uuid::new_v4()));

        let write_res: Result<(), StoreError> = async {
            let mut file = tokio::fs::File::create(&temp_path).await?;
            file.write_all(bytes).await?;
            file.flush().await?;
            file.sync_all().await?;
            Ok(())
        }
        .await;

        if let Err(e) = write_res {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        // Atomic publish
        if let Err(e) = tokio::fs::rename(&temp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(StoreError::Io(e));
        }

        Ok((computed_digest, bytes.len() as u64, final_path))
    }

    /// Ingests a file from disk into the content-addressable store.
    /// Calculates SHA-256 integrity, verifies any expected digest, and moves/copies atomically.
    pub async fn ingest_file(
        &self,
        source_path: &Path,
        expected_digest: Option<&str>,
    ) -> Result<(String, u64, PathBuf), StoreError> {
        if !source_path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Source file {:?} not found", source_path),
            )));
        }

        let (computed_digest, size) = compute_sha256_file(source_path).await?;
        if let Some(expected) = expected_digest {
            if computed_digest != expected {
                return Err(StoreError::DigestMismatch {
                    digest: expected.to_string(),
                    expected: expected.to_string(),
                    actual: computed_digest,
                });
            }
        }

        let _guard = self.locks.lock(&computed_digest).await;
        let final_path = self.blob_path(&computed_digest)?;

        if final_path.exists() {
            let meta = tokio::fs::metadata(&final_path).await?;
            if meta.len() == size {
                debug!(
                    "Blob {} already exists; reusing without copying",
                    computed_digest
                );
                return Ok((computed_digest, size, final_path));
            }
        }

        let temp_path = self
            .tmp_dir
            .join(format!("blob.tmp.{}", uuid::Uuid::new_v4()));

        tokio::fs::copy(source_path, &temp_path).await?;

        if let Err(e) = tokio::fs::rename(&temp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(StoreError::Io(e));
        }

        Ok((computed_digest, size, final_path))
    }

    /// Reads a blob's full contents into memory.
    pub async fn read_blob(&self, digest: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path(digest)?;
        if !path.exists() {
            return Err(StoreError::BlobNotFound(digest.to_string()));
        }
        let data = tokio::fs::read(&path).await?;
        Ok(data)
    }

    /// Opens a blob file for async streaming reading.
    pub async fn open_blob(&self, digest: &str) -> Result<tokio::fs::File, StoreError> {
        let path = self.blob_path(digest)?;
        if !path.exists() {
            return Err(StoreError::BlobNotFound(digest.to_string()));
        }
        let file = tokio::fs::File::open(&path).await?;
        Ok(file)
    }

    /// Verifies the on-disk SHA-256 integrity of an existing blob.
    pub async fn verify_blob_integrity(&self, digest: &str) -> Result<bool, StoreError> {
        let path = self.blob_path(digest)?;
        if !path.exists() {
            return Ok(false);
        }
        let (actual_digest, _) = compute_sha256_file(&path).await?;
        Ok(actual_digest == digest)
    }

    /// Deletes a blob from the content-addressable store.
    pub async fn delete_blob(&self, digest: &str) -> Result<bool, StoreError> {
        let _guard = self.locks.lock(digest).await;
        let path = self.blob_path(digest)?;
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
