use crate::error::StoreError;
use crate::image_record::ImageRecord;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;

/// Manages image metadata records mapping references to manifests and layers.
#[derive(Debug)]
pub struct MetadataStore {
    file_path: PathBuf,
    lock: Mutex<()>,
}

impl MetadataStore {
    pub fn new<P: AsRef<Path>>(metadata_file: P) -> Self {
        Self {
            file_path: metadata_file.as_ref().to_path_buf(),
            lock: Mutex::new(()),
        }
    }

    /// Loads the images map from disk, returning an empty map if the file does not exist yet.
    async fn load_map(&self) -> Result<HashMap<String, ImageRecord>, StoreError> {
        if !self.file_path.exists() {
            return Ok(HashMap::new());
        }

        let content = tokio::fs::read(&self.file_path).await?;
        if content.is_empty() {
            return Ok(HashMap::new());
        }

        let map: HashMap<String, ImageRecord> = serde_json::from_slice(&content)?;
        Ok(map)
    }

    /// Atomically persists the images map to disk.
    async fn persist_map(&self, map: &HashMap<String, ImageRecord>) -> Result<(), StoreError> {
        if let Some(parent) = self.file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let data = serde_json::to_vec_pretty(map)?;
        let temp_path = self
            .file_path
            .with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));

        tokio::fs::write(&temp_path, &data).await?;
        tokio::fs::rename(&temp_path, &self.file_path).await?;
        Ok(())
    }

    /// Saves or updates an image record.
    pub async fn save_image(&self, record: ImageRecord) -> Result<(), StoreError> {
        let _guard = self.lock.lock().await;
        let mut map = self.load_map().await?;
        map.insert(record.reference.clone(), record);
        self.persist_map(&map).await
    }

    /// Retrieves an image record by reference or manifest digest.
    pub async fn get_image(&self, identifier: &str) -> Result<Option<ImageRecord>, StoreError> {
        let _guard = self.lock.lock().await;
        let map = self.load_map().await?;

        // Try exact reference match first
        if let Some(record) = map.get(identifier) {
            return Ok(Some(record.clone()));
        }

        // Try manifest digest match
        for record in map.values() {
            if record.manifest_digest == identifier {
                return Ok(Some(record.clone()));
            }
        }

        Ok(None)
    }

    /// Lists all stored image records.
    pub async fn list_images(&self) -> Result<Vec<ImageRecord>, StoreError> {
        let _guard = self.lock.lock().await;
        let map = self.load_map().await?;
        Ok(map.into_values().collect())
    }

    /// Removes an image record by reference. Returns true if the image was found and removed.
    pub async fn remove_image(&self, reference: &str) -> Result<bool, StoreError> {
        let _guard = self.lock.lock().await;
        let mut map = self.load_map().await?;
        let removed = map.remove(reference).is_some();
        if removed {
            self.persist_map(&map).await?;
        }
        Ok(removed)
    }
}
