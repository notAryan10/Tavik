use crate::spec::{ContainerState, ContainerStatus, Spec};
use std::fs;
use std::path::{Path, PathBuf};
use tavik_common::error::{Result, TavikError};
#[allow(unused_imports)]
use tracing::{info, warn};

#[cfg(unix)]
pub(crate) struct StateLock {
    file: std::fs::File,
}

#[cfg(unix)]
impl StateLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| TavikError::Io(format!("Failed to open state lock file: {}", e)))?;

        let res =
            unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if res != 0 {
            return Err(TavikError::Io(format!(
                "Failed to acquire flock: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for StateLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(
                std::os::unix::io::AsRawFd::as_raw_fd(&self.file),
                libc::LOCK_UN,
            );
        }
    }
}

#[cfg(target_os = "linux")]
struct PidFd {
    fd: i32,
}

#[cfg(target_os = "linux")]
impl PidFd {
    fn open(pid: u32) -> Option<Self> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) as i32 };
        if fd >= 0 {
            Some(Self { fd })
        } else {
            None
        }
    }

    fn send_signal(&self, sig: i32) -> Result<()> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd,
                sig,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(TavikError::Execution(format!(
                "Failed to send signal {} via pidfd: {}",
                sig, err
            )));
        }
        Ok(())
    }

    fn wait_for_exit(&self, timeout: std::time::Duration) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        ret > 0 && (pfd.revents & libc::POLLIN != 0)
    }
}

#[cfg(target_os = "linux")]
impl Drop for PidFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

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

    pub fn container_dir(&self, id: &str) -> PathBuf {
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

    /// Atomically mutates and persists container state while holding a filesystem lock,
    /// enforcing strict lifecycle state transition rules.
    pub fn transition_state<F>(&self, id: &str, mutate: F) -> Result<ContainerState>
    where
        F: FnOnce(&mut ContainerState) -> Result<()>,
    {
        let container_dir = self.container_dir(id);
        fs::create_dir_all(&container_dir)?;

        #[cfg(unix)]
        let lock_path = container_dir.join("state.lock");
        #[cfg(unix)]
        let _lock = StateLock::acquire(&lock_path)?;

        let state_path = self.state_file_path(id);
        if !state_path.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' state not found at {:?}",
                id, state_path
            )));
        }

        let content = fs::read_to_string(&state_path)?;
        let mut state: ContainerState = serde_json::from_str(&content)?;
        let old_status = state.status;

        mutate(&mut state)?;

        // Enforce valid lifecycle state transitions
        match (old_status, state.status) {
            // Identity transitions are valid
            (s1, s2) if s1 == s2 => {}
            // Creating -> Created
            (ContainerStatus::Creating, ContainerStatus::Created) => {}
            // Created -> Starting
            (ContainerStatus::Created, ContainerStatus::Starting) => {}
            // Starting -> Running
            (ContainerStatus::Starting, ContainerStatus::Running) => {}
            // Starting -> Stopped (startup failed or short-lived process finished immediately)
            (ContainerStatus::Starting, ContainerStatus::Stopped) => {}
            // Running -> Stopped
            (ContainerStatus::Running, ContainerStatus::Stopped) => {}
            // Stopped is a terminal state! Can never transition back to Running or Starting
            (ContainerStatus::Stopped, ContainerStatus::Running) => {
                // Ignore late Running transition if supervisor already reaped child and marked Stopped
                state.status = ContainerStatus::Stopped;
            }
            (ContainerStatus::Stopped, ContainerStatus::Starting) => {
                return Err(TavikError::InvalidState(format!(
                    "Container '{}' has already stopped and cannot be started again",
                    id
                )));
            }
            (from, to) => {
                return Err(TavikError::InvalidState(format!(
                    "Invalid container state transition from '{}' to '{}'",
                    from, to
                )));
            }
        }

        let tmp_path = container_dir.join("state.json.tmp");
        let json = serde_json::to_string_pretty(&state)?;
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &state_path)?;

        Ok(state)
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
        let _final_state = match self.platform_create(id, &spec, &canonical_bundle, initial_state) {
            Ok(s) => s,
            Err(e) => {
                // Clean up failed container state directory so no stale Creating state is left behind
                let _ = fs::remove_dir_all(&container_dir);
                return Err(e);
            }
        };

        // Reload persisted state to guarantee synchronization
        self.load_state(id)
    }

    /// Starts a created OCI container (`start` command).
    pub fn start(&self, id: &str) -> Result<ContainerState> {
        let state = self.load_state(id)?;

        if state.status != ContainerStatus::Created {
            return Err(TavikError::InvalidState(format!(
                "Cannot start container '{}': status is '{}' (expected 'created')",
                id, state.status
            )));
        }

        info!("Starting OCI container '{}'", id);

        // 1. Mark transition from Created to Starting
        self.transition_state(id, |st| {
            st.status = ContainerStatus::Starting;
            Ok(())
        })?;

        // 2. Perform platform start (wakes child, verifies execve EOF with timeout)
        match self.platform_start(id, &state) {
            Ok(()) => {
                // Transition to Running (or preserve Stopped if short-lived child already exited and reaped)
                let final_state = self.transition_state(id, |st| {
                    if st.status != ContainerStatus::Stopped {
                        st.status = ContainerStatus::Running;
                    }
                    Ok(())
                })?;
                Ok(final_state)
            }
            Err(e) => {
                // If startup failed, mark state as Stopped, do NOT mark as Running!
                let _ = self.transition_state(id, |st| {
                    st.status = ContainerStatus::Stopped;
                    Ok(())
                });
                Err(e)
            }
        }
    }

    /// Stops a running container with graceful signal escalation (`stop` command).
    pub fn stop(
        &self,
        id: &str,
        signal: Option<i32>,
        grace_period: Option<std::time::Duration>,
    ) -> Result<ContainerState> {
        let state = self.load_state(id)?;

        if state.status == ContainerStatus::Stopped {
            return Ok(state);
        }

        if state.status != ContainerStatus::Running && state.status != ContainerStatus::Starting {
            return Err(TavikError::InvalidState(format!(
                "Cannot stop container '{}': status is '{}' (expected 'running')",
                id, state.status
            )));
        }

        let pid = state.pid.ok_or_else(|| {
            TavikError::InvalidState(format!("Container '{}' has no active PID", id))
        })?;

        let sig = signal.unwrap_or(libc::SIGTERM);

        // Reject signals that only suspend or resume the process
        #[cfg(unix)]
        {
            if matches!(
                sig,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGCONT | libc::SIGTTIN | libc::SIGTTOU
            ) {
                return Err(TavikError::InvalidState(format!(
                    "Signal {} suspends/resumes process and cannot be used to stop container '{}'",
                    sig, id
                )));
            }
        }

        info!(
            "Stopping container '{}' (PID {}) with signal {}",
            id, pid, sig
        );

        #[cfg(target_os = "linux")]
        {
            let timeout = grace_period.unwrap_or(std::time::Duration::from_secs(10));
            let pidfd = PidFd::open(pid);

            let mut terminated = false;
            if let Some(ref pfd) = pidfd {
                // Send stop signal via pidfd to prevent PID recycling
                pfd.send_signal(sig)?;
                // Wait for process termination
                if pfd.wait_for_exit(timeout) {
                    terminated = true;
                } else {
                    warn!(
                        "Container '{}' (PID {}) did not stop after {:?}; escalating to SIGKILL",
                        id, pid, timeout
                    );
                    pfd.send_signal(libc::SIGKILL)?;
                    if pfd.wait_for_exit(std::time::Duration::from_secs(2)) {
                        terminated = true;
                    }
                }
            } else {
                // Fallback for environments where pidfd_open is unavailable
                let res = unsafe { libc::kill(pid as libc::pid_t, sig) };
                if res != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::ESRCH) {
                        return Err(TavikError::Execution(format!(
                            "Failed to send stop signal {} to container PID {}: {}",
                            sig, pid, err
                        )));
                    }
                }

                let start_time = std::time::Instant::now();
                while start_time.elapsed() < timeout {
                    if !is_pid_alive(pid) {
                        terminated = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }

                if !terminated {
                    warn!(
                        "Container '{}' (PID {}) did not stop after {:?}; escalating to SIGKILL",
                        id, pid, timeout
                    );
                    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    let kill_start = std::time::Instant::now();
                    while kill_start.elapsed() < std::time::Duration::from_secs(2) {
                        if !is_pid_alive(pid) {
                            terminated = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                }
            }

            if !terminated {
                return Err(TavikError::Execution(format!(
                    "Container '{}' (PID {}) failed to terminate even after SIGKILL escalation",
                    id, pid
                )));
            }

            // Confirmed termination: transition state to Stopped
            let final_state = self.transition_state(id, |st| {
                st.status = ContainerStatus::Stopped;
                Ok(())
            })?;
            Ok(final_state)
        }

        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let res = unsafe { libc::kill(pid as libc::pid_t, sig) };
            if res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(TavikError::Execution(format!(
                        "Failed to send stop signal {} to container PID {}: {}",
                        sig, pid, err
                    )));
                }
            }

            let timeout = grace_period.unwrap_or(std::time::Duration::from_secs(10));
            let start_time = std::time::Instant::now();
            let mut terminated = false;

            while start_time.elapsed() < timeout {
                if !is_pid_alive(pid) {
                    terminated = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }

            if !terminated {
                let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                let kill_start = std::time::Instant::now();
                while kill_start.elapsed() < std::time::Duration::from_secs(2) {
                    if !is_pid_alive(pid) {
                        terminated = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }

            if !terminated {
                return Err(TavikError::Execution(format!(
                    "Container '{}' (PID {}) failed to terminate even after SIGKILL escalation",
                    id, pid
                )));
            }

            let final_state = self.transition_state(id, |st| {
                st.status = ContainerStatus::Stopped;
                Ok(())
            })?;
            Ok(final_state)
        }

        #[cfg(not(unix))]
        {
            let _ = (pid, sig, grace_period);
            Err(TavikError::Unsupported(
                "Container stop is unsupported on non-Unix platforms".to_string(),
            ))
        }
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

        #[cfg(target_os = "linux")]
        {
            if let Ok(cgroup_mgr) = tavik_cgroups::CgroupManager::new() {
                let _ = cgroup_mgr.destroy_container_cgroup(id);
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
        id: &str,
        _spec: &Spec,
        _bundle: &Path,
        _state: ContainerState,
    ) -> Result<ContainerState> {
        // Honest non-Linux reporting: bundle is validated and created, but isolated execution is marked as requiring Linux.
        warn!(
            "Platform is not Linux. OCI bundle validated, container created in non-isolated mode."
        );
        self.transition_state(id, |st| {
            st.status = ContainerStatus::Created;
            Ok(())
        })
    }

    #[cfg(target_os = "linux")]
    fn platform_start(&self, id: &str, _state: &ContainerState) -> Result<()> {
        use std::io::Write;

        let container_dir = self.container_dir(id);
        let start_fifo = container_dir.join("start.fifo");
        let exec_fifo = container_dir.join("exec.fifo");

        if !start_fifo.exists() {
            return Err(TavikError::InvalidState(format!(
                "Container '{}' start FIFO not found at {:?}",
                id, start_fifo
            )));
        }

        // 1. Open exec.fifo for reading BEFORE triggering start signal
        let exec_fifo_c = std::ffi::CString::new(exec_fifo.to_str().unwrap()).unwrap();
        let exec_read_fd =
            unsafe { libc::open(exec_fifo_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if exec_read_fd < 0 {
            return Err(TavikError::Io(format!(
                "Failed to open exec FIFO at {:?}: {}",
                exec_fifo,
                std::io::Error::last_os_error()
            )));
        }

        // 2. Open start FIFO and write start signal
        let mut file = match fs::OpenOptions::new().write(true).open(&start_fifo) {
            Ok(f) => f,
            Err(e) => {
                unsafe { libc::close(exec_read_fd) };
                return Err(TavikError::Io(format!(
                    "Failed to open container start FIFO: {}",
                    e
                )));
            }
        };

        if let Err(e) = file.write_all(b"1") {
            unsafe { libc::close(exec_read_fd) };
            return Err(TavikError::Io(format!(
                "Failed to write start signal to container FIFO: {}",
                e
            )));
        }

        // 3. Read execution status from exec.fifo
        // If execve() succeeds, fd 4 in child is closed by kernel via FD_CLOEXEC, yielding EOF (0 bytes).
        // If execve() or child pre-exec fails, child writes the error string and exits.
        let mut pfd = libc::pollfd {
            fd: exec_read_fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // Wait up to 15 seconds for startup handshake
        let poll_res = unsafe { libc::poll(&mut pfd, 1, 15000) };
        if poll_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(exec_read_fd) };
            return Err(TavikError::Io(format!("poll failed on exec.fifo: {}", err)));
        }
        if poll_res == 0 {
            unsafe { libc::close(exec_read_fd) };
            return Err(TavikError::Execution(format!(
                "Container '{}' startup timed out waiting for exec status",
                id
            )));
        }

        let mut err_buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = unsafe {
                libc::read(
                    exec_read_fd,
                    chunk.as_mut_ptr() as *mut libc::c_void,
                    chunk.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                unsafe { libc::close(exec_read_fd) };
                return Err(TavikError::Io(format!(
                    "Failed to read from exec.fifo: {}",
                    err
                )));
            }
            if n == 0 {
                break; // EOF: kernel closed fd on successful execve!
            }
            err_buf.extend_from_slice(&chunk[..n as usize]);
        }
        unsafe { libc::close(exec_read_fd) };

        if !err_buf.is_empty() {
            let err_msg = String::from_utf8_lossy(&err_buf);
            return Err(TavikError::Execution(format!(
                "Container '{}' failed during startup: {}",
                id, err_msg
            )));
        }

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
