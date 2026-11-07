use crate::spec::{ContainerState, ContainerStatus, Spec};
use std::fs;
use std::path::{Path, PathBuf};
use tavik_common::error::{Result, TavikError};
#[allow(unused_imports)]
use tracing::{info, warn};

pub struct ContainerExecutor {
    state_dir: PathBuf,
}

impl ContainerExecutor {
    pub fn new(state_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&state_dir)?;
        Ok(Self { state_dir })
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    fn container_dir(&self, id: &str) -> PathBuf {
        self.state_dir.join(id)
    }

    fn state_file_path(&self, id: &str) -> PathBuf {
        self.container_dir(id).join("state.json")
    }

    /// Loads the current container state from disk.
    pub fn load_state(&self, id: &str) -> Result<ContainerState> {
        let path = self.state_file_path(id);
        if !path.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' state not found at {:?}",
                id, path
            )));
        }

        let content = fs::read_to_string(&path)?;
        let mut state: ContainerState = serde_json::from_str(&content)?;

        // Reconcile PID liveness
        if state.status == ContainerStatus::Running {
            if let Some(pid) = state.pid {
                if !is_pid_alive(pid) {
                    state.status = ContainerStatus::Stopped;
                    let _ = self.save_state(&state);
                }
            }
        }

        Ok(state)
    }

    /// Atomically persists container state.
    pub fn save_state(&self, state: &ContainerState) -> Result<()> {
        let container_dir = self.container_dir(&state.id);
        fs::create_dir_all(&container_dir)?;

        let target_path = self.state_file_path(&state.id);
        let tmp_path = container_dir.join("state.json.tmp");

        let json = serde_json::to_string_pretty(state)?;
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &target_path)?;

        Ok(())
    }

    /// Creates an OCI container bundle instance (`create` command).
    pub fn create(&self, id: &str, bundle_dir: &Path) -> Result<ContainerState> {
        let container_dir = self.container_dir(id);
        if container_dir.exists() {
            return Err(TavikError::AlreadyExists(format!(
                "Container '{}' already exists",
                id
            )));
        }

        // Validate OCI configuration
        let spec = Spec::load_from_bundle(bundle_dir)?;
        let canonical_bundle = bundle_dir
            .canonicalize()
            .unwrap_or_else(|_| bundle_dir.to_path_buf());

        info!(
            "Creating OCI container '{}' from bundle {:?}",
            id, canonical_bundle
        );

        let initial_state = ContainerState {
            oci_version: spec.oci_version.clone(),
            id: id.to_string(),
            status: ContainerStatus::Creating,
            pid: None,
            bundle: canonical_bundle.clone(),
            annotations: spec.annotations.clone(),
            created_at: chrono::Utc::now(),
        };

        self.save_state(&initial_state)?;

        // Platform-specific container init creation
        let final_state = self.platform_create(id, &spec, &canonical_bundle, initial_state)?;
        self.save_state(&final_state)?;

        Ok(final_state)
    }

    /// Starts a created OCI container (`start` command).
    pub fn start(&self, id: &str) -> Result<ContainerState> {
        let mut state = self.load_state(id)?;

        if state.status != ContainerStatus::Created {
            return Err(TavikError::InvalidState(format!(
                "Cannot start container '{}': status is '{}' (expected 'created')",
                id, state.status
            )));
        }

        info!("Starting OCI container '{}'", id);
        self.platform_start(id, &state)?;

        state.status = ContainerStatus::Running;
        self.save_state(&state)?;

        Ok(state)
    }

    /// Sends a signal to the container process (`kill` command).
    pub fn kill(&self, id: &str, signal: i32) -> Result<()> {
        let state = self.load_state(id)?;

        let pid = state.pid.ok_or_else(|| {
            TavikError::InvalidState(format!("Container '{}' has no active PID", id))
        })?;

        info!(
            "Sending signal {} to container '{}' (PID {})",
            signal, id, pid
        );

        #[cfg(unix)]
        {
            let res = unsafe { libc::kill(pid as libc::pid_t, signal) };
            if res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(TavikError::Execution(format!(
                        "Failed to send signal {} to container PID {}: {}",
                        signal, pid, err
                    )));
                }
            }
            Ok(())
        }

        #[cfg(not(unix))]
        {
            let _ = (pid, signal);
            Err(TavikError::Unsupported(
                "Signal delivery is unsupported on non-Unix platforms".to_string(),
            ))
        }
    }

    /// Deletes a stopped container and its state directory (`delete` command).
    pub fn delete(&self, id: &str, force: bool) -> Result<()> {
        let state = self.load_state(id)?;

        if state.status == ContainerStatus::Running && !force {
            return Err(TavikError::InvalidState(format!(
                "Cannot delete running container '{}' without force flag",
                id
            )));
        }

        if state.status == ContainerStatus::Running && force {
            if let Some(pid) = state.pid {
                let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
        }

        let container_dir = self.container_dir(id);
        if container_dir.exists() {
            fs::remove_dir_all(&container_dir)?;
        }

        info!("Deleted container '{}'", id);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn platform_create(
        &self,
        id: &str,
        _spec: &Spec,
        _bundle: &Path,
        _state: ContainerState,
    ) -> Result<ContainerState> {
        let state_dir_str = self.state_dir.to_str().ok_or_else(|| {
            TavikError::Config("Invalid UTF-8 in state directory path".to_string())
        })?;

        if let Some(tavikr_bin) = find_tavikr_binary() {
            info!(
                "Launching container init via dedicated helper: {:?}",
                tavikr_bin
            );
            let status = std::process::Command::new(tavikr_bin)
                .args(["init", "--state-dir", state_dir_str, id])
                .status()
                .map_err(|e| {
                    TavikError::Execution(format!("Failed to spawn tavikr init helper: {}", e))
                })?;

            if !status.success() {
                return Err(TavikError::Execution(format!(
                    "tavikr init failed with exit status: {:?}",
                    status
                )));
            }
        } else {
            info!("Executing in-process container init trampoline");
            crate::init::run_init_trampoline(&self.state_dir, id)?;
        }

        self.load_state(id)
    }

    #[cfg(not(target_os = "linux"))]
    fn platform_create(
        &self,
        _id: &str,
        _spec: &Spec,
        _bundle: &Path,
        mut state: ContainerState,
    ) -> Result<ContainerState> {
        // Honest non-Linux reporting: bundle is validated and created, but isolated execution is marked as requiring Linux.
        warn!(
            "Platform is not Linux. OCI bundle validated, container created in non-isolated mode."
        );
        state.status = ContainerStatus::Created;
        Ok(state)
    }

    #[cfg(target_os = "linux")]
    fn platform_start(&self, id: &str, _state: &ContainerState) -> Result<()> {
        use std::io::Write;

        let start_fifo = self.container_dir(id).join("start.fifo");
        if !start_fifo.exists() {
            return Err(TavikError::InvalidState(format!(
                "Container '{}' start FIFO not found at {:?}",
                id, start_fifo
            )));
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&start_fifo)
            .map_err(|e| TavikError::Io(format!("Failed to open container start FIFO: {}", e)))?;

        file.write_all(b"1").map_err(|e| {
            TavikError::Io(format!(
                "Failed to write start signal to container FIFO: {}",
                e
            ))
        })?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn platform_start(&self, _id: &str, _state: &ContainerState) -> Result<()> {
        Err(TavikError::Unsupported(
            "OCI container namespace isolation and pivot_root execution require a Linux kernel."
                .to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn find_tavikr_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TAVIKR_PATH") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(cur) = std::env::current_exe() {
        if let Some(parent) = cur.parent() {
            let p1 = parent.join("tavikr");
            if p1.exists() {
                return Some(p1);
            }
            if let Some(grandparent) = parent.parent() {
                let p2 = grandparent.join("tavikr");
                if p2.exists() {
                    return Some(p2);
                }
            }
        }
    }
    None
}

fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if res == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        err.raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_executor_create_state_and_delete() {
        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let spec = Spec::default_linux();
        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-container-1";

        let created_state = executor.create(container_id, &bundle_dir).unwrap();
        assert_eq!(created_state.id, container_id);
        assert_eq!(created_state.status, ContainerStatus::Created);

        let loaded_state = executor.load_state(container_id).unwrap();
        assert_eq!(loaded_state.id, container_id);
        assert_eq!(loaded_state.status, ContainerStatus::Created);

        // Delete container
        executor.delete(container_id, false).unwrap();
        assert!(executor.load_state(container_id).is_err());
    }
}
