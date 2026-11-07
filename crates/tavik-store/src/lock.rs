use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

/// Manages per-key async locks (e.g. per-digest lock during blob ingestion).
#[derive(Debug, Default, Clone)]
pub struct KeyedLock {
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl KeyedLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires an async lock for the given key (e.g. digest or file path).
    pub async fn lock(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut map = self.locks.lock().unwrap();
            map.entry(key.to_string())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };

        lock.lock_owned().await
    }
}
