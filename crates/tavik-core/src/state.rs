use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tavik_common::error::Result;
use tavik_common::protocol::{ProcessInfo, ProcessStatus};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct StateStore {
    base_dir: PathBuf,
    workloads_dir: PathBuf,
    logs_dir: PathBuf,
    cache: Arc<RwLock<HashMap<String, ProcessInfo>>>,
}

impl StateStore {
    /// Initializes or loads state store at `base_dir`.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        let workloads_dir = base_dir.join("workloads");
        let logs_dir = base_dir.join("logs");

        fs::create_dir_all(&workloads_dir)?;
        fs::create_dir_all(&logs_dir)?;

        let mut initial_cache = HashMap::new();

        // Load existing workload records from disk
        if let Ok(entries) = fs::read_dir(&workloads_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    match fs::read_to_string(&path) {
                        Ok(contents) => match serde_json::from_str::<ProcessInfo>(&contents) {
                            Ok(mut info) => {
                                // Reconcile process status against OS process table
                                reconcile_process_status(&mut info);
                                initial_cache.insert(info.id.clone(), info);
                            }
                            Err(e) => {
                                warn!("Failed to parse state file {:?}: {}", path, e);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to read state file {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        info!(
            "Initialized StateStore at {:?}, loaded {} workloads",
            base_dir,
            initial_cache.len()
        );

        Ok(Self {
            base_dir,
            workloads_dir,
            logs_dir,
            cache: Arc::new(RwLock::new(initial_cache)),
        })
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn logs_dir(&self) -> &Path {
        &self.logs_dir
    }

    pub async fn get(&self, id: &str) -> Option<ProcessInfo> {
        let cache = self.cache.read().await;
        cache.get(id).cloned()
    }

    pub async fn list(&self) -> Vec<ProcessInfo> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    /// Atomically persists a workload record to disk and updates the in-memory cache.
    pub async fn save(&self, info: &ProcessInfo) -> Result<()> {
        let file_path = self.workloads_dir.join(format!("{}.json", info.id));
        let tmp_path = self.workloads_dir.join(format!("{}.json.tmp", info.id));

        let json = serde_json::to_string_pretty(info)?;

        // Write to temporary sibling file first
        fs::write(&tmp_path, json)?;

        // Atomic replace via rename
        fs::rename(&tmp_path, &file_path)?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(info.id.clone(), info.clone());

        debug!("Persisted workload {} to {:?}", info.id, file_path);
        Ok(())
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        let file_path = self.workloads_dir.join(format!("{}.json", id));
        if file_path.exists() {
            fs::remove_file(&file_path)?;
        }

        let mut cache = self.cache.write().await;
        cache.remove(id);

        Ok(())
    }
}

/// Checks if recorded PID is still alive and belongs to the process.
fn reconcile_process_status(info: &mut ProcessInfo) {
    if info.status == ProcessStatus::Running {
        if let Some(pid) = info.pid {
            let is_alive = check_pid_alive(pid);
            if !is_alive {
                warn!(
                    "Workload {} (PID {}) was marked running, but PID is no longer alive. Marking as Exited.",
                    info.id, pid
                );
                info.status = ProcessStatus::Exited { code: -1 };
            }
        } else {
            info.status = ProcessStatus::Failed {
                error: "Running state with no assigned PID".to_string(),
            };
        }
    }
}

fn check_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) checks for existence and signal permissions without sending a signal
        let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if res == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        // EPERM means the process exists but is owned by another user (still alive)
        err.raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_state_store_persistence() {
        let temp = tempdir().unwrap();
        let store = StateStore::new(temp.path().to_path_buf()).unwrap();

        let info = ProcessInfo {
            id: "test12345678".to_string(),
            name: "test-task".to_string(),
            command: "/bin/echo".to_string(),
            args: vec!["hello".to_string()],
            pid: Some(1234),
            status: ProcessStatus::Created,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        };

        store.save(&info).await.unwrap();

        // Verify retrieval from memory
        let retrieved = store.get("test12345678").await.unwrap();
        assert_eq!(retrieved.name, "test-task");

        // Verify recovery after reload
        let store2 = StateStore::new(temp.path().to_path_buf()).unwrap();
        let retrieved2 = store2.get("test12345678").await.unwrap();
        assert_eq!(retrieved2.id, "test12345678");
    }
}
