use crate::state::StateStore;
use chrono::Utc;
use std::collections::HashMap;
use std::fs::File;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tavik_common::error::{Result, TavikError};
use tavik_common::id::Id;
use tavik_common::protocol::{ProcessInfo, ProcessStartParams, ProcessStatus};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub struct ProcessSupervisor {
    store: StateStore,
    active_children: Arc<RwLock<HashMap<String, u32>>>,
}

impl ProcessSupervisor {
    pub fn new(store: StateStore) -> Self {
        Self {
            store,
            active_children: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn store(&self) -> &StateStore {
        &self.store
    }

    /// Spawns and supervises a new process workload.
    pub async fn spawn(&self, params: ProcessStartParams) -> Result<ProcessInfo> {
        let id = Id::generate();
        let name = params.name.unwrap_or_else(|| format!("proc-{}", id));

        info!(
            "Supervising new workload '{}' (id: {}): {} {:?}",
            name, id, params.command, params.args
        );

        let mut info = ProcessInfo {
            id: id.clone(),
            name,
            command: params.command.clone(),
            args: params.args.clone(),
            pid: None,
            status: ProcessStatus::Created,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        };

        // Prepare log file in logs directory
        let log_file_path = self.store.logs_dir().join(format!("{}.log", id));
        let log_file = File::create(&log_file_path).map_err(|e| {
            TavikError::Io(format!(
                "Failed to create workload log file at {:?}: {}",
                log_file_path, e
            ))
        })?;
        let log_err_file = log_file
            .try_clone()
            .map_err(|e| TavikError::Io(format!("Failed to clone log file descriptor: {}", e)))?;

        let mut cmd = tokio::process::Command::new(&params.command);
        cmd.args(&params.args);
        cmd.envs(&params.env);

        if let Some(wd) = &params.working_dir {
            cmd.current_dir(wd);
        }

        cmd.stdout(Stdio::from(log_file));
        cmd.stderr(Stdio::from(log_err_file));

        let mut child = cmd.spawn().map_err(|e| {
            TavikError::Execution(format!(
                "Failed to spawn process '{}': {}",
                params.command, e
            ))
        })?;

        let pid = child.id().ok_or_else(|| {
            TavikError::Execution("Failed to obtain child process PID".to_string())
        })?;

        info.pid = Some(pid);
        info.status = ProcessStatus::Running;
        info.started_at = Some(Utc::now());

        // Save running state
        self.store.save(&info).await?;
        self.active_children.write().await.insert(id.clone(), pid);

        // Spawn background task to supervise completion
        let store_clone = self.store.clone();
        let active_clone = self.active_children.clone();
        let id_clone = id.clone();

        tokio::spawn(async move {
            let wait_res = child.wait().await;
            active_clone.write().await.remove(&id_clone);

            let mut current = store_clone.get(&id_clone).await.unwrap_or(info);
            current.finished_at = Some(Utc::now());

            match wait_res {
                Ok(status) => {
                    let code = status.code().unwrap_or(-1);
                    current.exit_code = Some(code);
                    current.status = if code == 0 {
                        ProcessStatus::Exited { code: 0 }
                    } else {
                        ProcessStatus::Exited { code }
                    };
                    info!("Workload {} finished with exit code {}", id_clone, code);
                }
                Err(err) => {
                    error!("Workload {} wait error: {}", id_clone, err);
                    current.status = ProcessStatus::Failed {
                        error: err.to_string(),
                    };
                }
            }

            if let Err(e) = store_clone.save(&current).await {
                error!(
                    "Failed to update state for finished workload {}: {}",
                    id_clone, e
                );
            }
        });

        // Return current running process info
        self.store
            .get(&id)
            .await
            .ok_or_else(|| TavikError::NotFound(format!("Workload {} not found after spawn", id)))
    }

    /// Stops a running workload.
    pub async fn stop(&self, id: &str, signal: Option<i32>) -> Result<ProcessInfo> {
        let mut info =
            self.store.get(id).await.ok_or_else(|| {
                TavikError::NotFound(format!("Workload with ID '{}' not found", id))
            })?;

        if info.status != ProcessStatus::Running {
            return Ok(info);
        }

        let pid = info.pid.ok_or_else(|| {
            TavikError::InvalidState("Process is marked running but has no PID".to_string())
        })?;

        info!(
            "Sending termination signal to workload {} (PID {})",
            id, pid
        );

        #[cfg(unix)]
        {
            let sig = signal.unwrap_or(libc::SIGTERM);
            let res = unsafe { libc::kill(pid as libc::pid_t, sig) };
            if res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(TavikError::Execution(format!(
                        "Failed to signal PID {}: {}",
                        pid, err
                    )));
                }
            }

            // Wait briefly for process to gracefully exit
            let mut exited = false;
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let check = unsafe { libc::kill(pid as libc::pid_t, 0) };
                if check != 0 {
                    exited = true;
                    break;
                }
            }

            if !exited {
                warn!("PID {} did not exit on SIGTERM; sending SIGKILL", pid);
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
        }

        #[cfg(not(unix))]
        {
            let _ = signal;
            return Err(TavikError::Unsupported(
                "Process termination signals not supported on this platform".to_string(),
            ));
        }

        info.status = ProcessStatus::Stopped;
        info.finished_at = Some(Utc::now());
        self.store.save(&info).await?;
        self.active_children.write().await.remove(id);

        Ok(info)
    }

    pub async fn inspect(&self, id: &str) -> Result<ProcessInfo> {
        self.store
            .get(id)
            .await
            .ok_or_else(|| TavikError::NotFound(format!("Workload with ID '{}' not found", id)))
    }

    pub async fn list(&self) -> Vec<ProcessInfo> {
        self.store.list().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_supervisor_lifecycle() {
        let temp = tempdir().unwrap();
        let store = StateStore::new(temp.path().to_path_buf()).unwrap();
        let supervisor = ProcessSupervisor::new(store);

        let params = ProcessStartParams {
            command: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "echo 'sup test' && sleep 0.1".to_string()],
            env: HashMap::new(),
            working_dir: None,
            name: Some("test-run".to_string()),
        };

        let info = supervisor.spawn(params).await.unwrap();
        assert_eq!(info.status, ProcessStatus::Running);

        // Allow child to finish
        tokio::time::sleep(Duration::from_millis(250)).await;

        let inspected = supervisor.inspect(&info.id).await.unwrap();
        assert_eq!(inspected.status, ProcessStatus::Exited { code: 0 });
    }
}
