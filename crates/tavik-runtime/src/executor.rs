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
        let parent = path.parent();
        if let Some(p) = parent {
            if !p.exists() {
                return Err(TavikError::NotFound(format!(
                    "Cannot acquire lock: directory {:?} does not exist",
                    p
                )));
            }
        }

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TavikError::NotFound(format!("State lock file {:?} not found: {}", path, e))
                } else {
                    TavikError::Io(format!("Failed to open state lock file: {}", e))
                }
            })?;

        let res =
            unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if res != 0 {
            return Err(TavikError::Io(format!(
                "Failed to acquire flock: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Verify that the file was not unlinked or retired between open and flock
        let mut st1: libc::stat = unsafe { std::mem::zeroed() };
        let mut st2: libc::stat = unsafe { std::mem::zeroed() };
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
        let fstat_res = unsafe { libc::fstat(fd, &mut st1) };
        if fstat_res != 0 {
            return Err(TavikError::Io(format!(
                "Failed to fstat lock file descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }

        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| TavikError::Config(format!("Invalid path for stat: {}", e)))?;
        let stat_res = unsafe { libc::stat(c_path.as_ptr(), &mut st2) };
        if stat_res != 0 || st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino {
            return Err(TavikError::NotFound(format!(
                "Lock file {:?} was unlinked or replaced before acquisition",
                path
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

    /// Reads state directly from disk without locking or side-effects.
    pub(crate) fn load_state_raw(&self, id: &str) -> Result<ContainerState> {
        let container_dir = self.container_dir(id);
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' not found",
                id
            )));
        }

        let path = self.state_file_path(id);
        if !path.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' state not found at {:?}",
                id, path
            )));
        }

        let content = fs::read_to_string(&path)?;
        let state: ContainerState = serde_json::from_str(&content)?;
        Ok(state)
    }

    /// Loads the current container state from disk, reconciling dead processes under StateLock if needed.
    pub fn load_state(&self, id: &str) -> Result<ContainerState> {
        let state = self.load_state_raw(id)?;

        // Reconcile PID liveness if running and process is dead
        if state.status == ContainerStatus::Running {
            if let Some(pid) = state.pid {
                if !is_pid_alive(pid) {
                    return self.reconcile_dead_process(id, pid);
                }
            }
        }

        Ok(state)
    }

    fn reconcile_dead_process(&self, id: &str, expected_pid: u32) -> Result<ContainerState> {
        let container_dir = self.container_dir(id);
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' not found",
                id
            )));
        }

        #[cfg(unix)]
        let lock_path = container_dir.join("state.lock");
        #[cfg(unix)]
        let _lock = StateLock::acquire(&lock_path)?;

        // Re-check directory and state existence under lock
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' not found",
                id
            )));
        }

        let mut state = self.load_state_raw(id)?;

        if state.status == ContainerStatus::Running
            && state.pid == Some(expected_pid)
            && !is_pid_alive(expected_pid)
        {
            #[cfg(target_os = "linux")]
            {
                if self.has_cgroup_ownership(id, &state) {
                    state.status = ContainerStatus::CleanupPending;
                } else {
                    state.status = ContainerStatus::Stopped;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                state.status = ContainerStatus::Stopped;
            }
            self.save_state(&state)?;
        }

        Ok(state)
    }

    /// Atomically persists container state. Never recreates a missing container directory.
    pub fn save_state(&self, state: &ContainerState) -> Result<()> {
        let container_dir = self.container_dir(&state.id);
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Cannot save state: container '{}' directory does not exist",
                state.id
            )));
        }

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
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' not found",
                id
            )));
        }

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
            // Created -> CleanupPending / Stopped
            (ContainerStatus::Created, ContainerStatus::CleanupPending) => {}
            (ContainerStatus::Created, ContainerStatus::Stopped) => {}
            // Starting -> Running
            (ContainerStatus::Starting, ContainerStatus::Running) => {}
            // Starting -> CleanupPending / Stopped
            (ContainerStatus::Starting, ContainerStatus::CleanupPending) => {}
            (ContainerStatus::Starting, ContainerStatus::Stopped) => {}
            // Running -> CleanupPending
            (ContainerStatus::Running, ContainerStatus::CleanupPending) => {}
            // Running -> Stopped
            (ContainerStatus::Running, ContainerStatus::Stopped) => {}
            // CleanupPending -> Stopped
            (ContainerStatus::CleanupPending, ContainerStatus::Stopped) => {}
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

        fs::create_dir_all(&container_dir)?;

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
                let cgroup_owner = container_dir.join("cgroup.owner");
                if cgroup_owner.exists() {
                    warn!(
                        "Container '{}' creation failed but cgroup cleanup was incomplete; preserving recovery metadata at {:?}",
                        id, container_dir
                    );
                    return Err(e);
                }
                // Clean up failed container state directory only if no recovery metadata remains
                let _ = fs::remove_dir_all(&container_dir);
                return Err(e);
            }
        };

        // Reload persisted state to guarantee synchronization
        self.load_state(id)
    }

    /// Starts a created OCI container (`start` command).
    pub fn start(&self, id: &str) -> Result<ContainerState> {
        info!("Starting OCI container '{}'", id);

        // 1. Atomic start: Validate Created -> Starting while holding StateLock
        let state = self.transition_state(id, |st| {
            if st.status != ContainerStatus::Created {
                return Err(TavikError::InvalidState(format!(
                    "Cannot start container '{}': status is '{}' (expected 'created')",
                    st.id, st.status
                )));
            }
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
                // Do not transition to Stopped in start() without confirmed termination.
                let cur = self.load_state(id)?;
                if cur.status == ContainerStatus::Stopped {
                    return Err(e);
                }
                // Unsuccessful CANCEL leaves container in Starting or reports error clearly
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

        if state.status != ContainerStatus::Running
            && state.status != ContainerStatus::Starting
            && state.status != ContainerStatus::CleanupPending
        {
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
            let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as u64;
            let control_sock = self.container_dir(id).join("control.sock");

            if control_sock.exists() {
                let cmd = format!("STOP {} {}", sig, timeout_ms);
                crate::init::send_control_command(&control_sock, &cmd)?;
                let final_state = self.load_state(id)?;
                if final_state.status != ContainerStatus::Stopped {
                    return Err(TavikError::Execution(format!(
                        "Supervisor acknowledged stop for container '{}', but state is '{}' (expected 'stopped')",
                        id, final_state.status
                    )));
                }
                return Ok(final_state);
            }

            let current = self.load_state(id)?;
            if current.status == ContainerStatus::Stopped {
                return Ok(current);
            }

            Err(TavikError::Execution(format!(
                "Container '{}' supervisor control channel unavailable and container not stopped",
                id
            )))
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

        #[cfg(target_os = "linux")]
        {
            let control_sock = self.container_dir(id).join("control.sock");
            if control_sock.exists() {
                crate::init::send_control_command(&control_sock, &format!("KILL {}", signal))?;
                return Ok(());
            }
            let state = self.load_state(id)?;
            if state.status == ContainerStatus::Stopped {
                return Err(TavikError::InvalidState(format!(
                    "Cannot signal container '{}': status is stopped",
                    id
                )));
            }
            Err(TavikError::Execution(format!(
                "Container '{}' supervisor control channel unavailable",
                id
            )))
        }

        #[cfg(all(unix, not(target_os = "linux")))]
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

    /// Checks whether the container owns a dedicated cgroup, persisting independently of the OCI bundle.
    pub fn has_cgroup_ownership(&self, id: &str, state: &ContainerState) -> bool {
        let container_dir = self.container_dir(id);
        let marker = container_dir.join("cgroup.owner");
        if marker.exists() {
            return true;
        }
        if state
            .annotations
            .get("io.tavik.cgroup.owned")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            return true;
        }
        // Fallback for backwards compatibility if bundle is accessible
        Spec::load_from_bundle(&state.bundle)
            .ok()
            .and_then(|s| s.linux)
            .and_then(|l| l.resources)
            .is_some()
    }

    /// Deletes a stopped container and its state directory (`delete` command).
    pub fn delete(&self, id: &str, force: bool) -> Result<()> {
        let container_dir = self.container_dir(id);
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' not found",
                id
            )));
        }

        let lock_path = container_dir.join("state.lock");

        // 1. Initial state inspection under StateLock
        let state = {
            let _lock = StateLock::acquire(&lock_path)?;
            self.load_state_raw(id)?
        };

        let is_running_or_starting = matches!(
            state.status,
            ContainerStatus::Running | ContainerStatus::Starting
        );

        if is_running_or_starting && !force {
            return Err(TavikError::InvalidState(format!(
                "Cannot delete container '{}' with status '{}' without force flag",
                id, state.status
            )));
        }

        let needs_cancellation = state.status == ContainerStatus::Created
            || (is_running_or_starting && force)
            || state.status == ContainerStatus::CleanupPending;

        if needs_cancellation {
            #[cfg(target_os = "linux")]
            {
                let control_sock = container_dir.join("control.sock");
                if !control_sock.exists() {
                    let cur_state = self.load_state_raw(id)?;
                    if cur_state.status != ContainerStatus::Stopped
                        && cur_state.status != ContainerStatus::CleanupPending
                    {
                        if cur_state.status == ContainerStatus::Created {
                            return Err(TavikError::Execution(format!(
                                "Cannot delete created container '{}': supervisor control socket is unreachable at {:?}",
                                id, control_sock
                            )));
                        } else if !force {
                            return Err(TavikError::Execution(format!(
                                "Cannot delete active container '{}': supervisor control socket is unreachable at {:?}",
                                id, control_sock
                            )));
                        }
                    }
                } else {
                    match crate::init::send_control_command(&control_sock, "CANCEL") {
                        Ok(resp) => {
                            if resp != "OK" && !resp.starts_with("OK ") {
                                return Err(TavikError::Execution(format!(
                                    "Supervisor returned non-OK response during delete cancellation: {:?}",
                                    resp
                                )));
                            }

                            let final_state = self.load_state_raw(id)?;
                            if final_state.status != ContainerStatus::Stopped
                                && final_state.status != ContainerStatus::CleanupPending
                            {
                                return Err(TavikError::Execution(format!(
                                    "Container '{}' remained in status '{}' after supervisor cancellation during delete",
                                    id, final_state.status
                                )));
                            }
                        }
                        Err(TavikError::DaemonUnreachable(_)) => {
                            // Supervisor has exited (connection refused on control socket).
                            if state.status == ContainerStatus::Created && !force {
                                return Err(TavikError::Execution(format!(
                                    "Cannot delete created container '{}': supervisor is unreachable at {:?}",
                                    id, control_sock
                                )));
                            }
                            if let Some(pid) = state.pid {
                                if is_pid_alive(pid) {
                                    if !force {
                                        return Err(TavikError::Execution(format!(
                                            "Cannot delete container '{}': process {} is still running but supervisor is dead",
                                            id, pid
                                        )));
                                    }
                                    unsafe {
                                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                                        let mut status = 0;
                                        libc::waitpid(
                                            pid as libc::pid_t,
                                            &mut status,
                                            libc::WNOHANG,
                                        );
                                    }
                                }
                            }
                            // Clean up stale socket so it does not block recovery
                            let _ = fs::remove_file(&control_sock);
                        }
                        Err(e) => {
                            return Err(TavikError::Execution(format!(
                                "Failed to stop container '{}' via supervisor during delete: {}",
                                id, e
                            )));
                        }
                    }
                }
            }

            #[cfg(all(unix, not(target_os = "linux")))]
            {
                if let Some(pid) = state.pid {
                    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                }
            }
        }

        // 2. Final deletion under StateLock
        if !container_dir.exists() {
            return Err(TavikError::NotFound(format!(
                "Container '{}' not found",
                id
            )));
        }

        let retired_dir = self
            .state_dir
            .join(format!(".retired-{}-{}", id, uuid::Uuid::new_v4()));

        {
            let _lock = StateLock::acquire(&lock_path)?;
            let final_state = match self.load_state_raw(id) {
                Ok(s) => s,
                Err(TavikError::NotFound(_)) => {
                    return Err(TavikError::NotFound(format!(
                        "Container '{}' not found",
                        id
                    )));
                }
                Err(e) => return Err(e),
            };

            #[cfg(all(unix, not(target_os = "linux")))]
            {
                let _ = final_state;
            }

            #[cfg(target_os = "linux")]
            {
                if final_state.status != ContainerStatus::Stopped
                    && final_state.status != ContainerStatus::CleanupPending
                    && !force
                {
                    return Err(TavikError::InvalidState(format!(
                        "Cannot delete container '{}' with status '{}' without force flag",
                        id, final_state.status
                    )));
                }

                let owns_cgroup = self.has_cgroup_ownership(id, &final_state);
                if owns_cgroup {
                    let cgroup_mgr = tavik_cgroups::CgroupManager::new().map_err(|e| {
                        TavikError::Execution(format!(
                            "Failed to initialize cgroup manager during deletion of '{}': {}",
                            id, e
                        ))
                    })?;

                    cgroup_mgr.destroy_container_cgroup(id).map_err(|e| {
                        TavikError::Execution(format!(
                            "Failed to destroy cgroup for container '{}' on delete: {}",
                            id, e
                        ))
                    })?;

                    // After cgroup is successfully destroyed, remove cgroup.owner marker
                    let owner_path = container_dir.join("cgroup.owner");
                    if owner_path.exists() {
                        fs::remove_file(&owner_path).map_err(|e| {
                            TavikError::Io(format!(
                                "Failed to remove cgroup.owner marker for container '{}': {}",
                                id, e
                            ))
                        })?;
                    }
                }
            }

            // Atomically retire container directory to prevent concurrent recreation/races
            fs::rename(&container_dir, &retired_dir).map_err(|e| {
                TavikError::Io(format!(
                    "Failed to retire container directory for '{}' ({:?} -> {:?}): {}",
                    id, container_dir, retired_dir, e
                ))
            })?;
        } // _lock dropped here

        // Clean up retired directory and propagate any filesystem errors truthfully
        fs::remove_dir_all(&retired_dir).map_err(|e| {
            TavikError::Io(format!(
                "Failed to remove retired container directory {:?}: {}",
                retired_dir, e
            ))
        })?;

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

        let tavikr_bin = find_tavikr_binary().ok_or_else(|| {
            TavikError::Execution(
                "Dedicated 'tavikr' runtime helper binary not found. A standalone single-threaded \
                 helper is required on Linux to ensure safe container initialization without \
                 multithreaded fork deadlocks."
                    .to_string(),
            )
        })?;

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
    fn abort_startup_and_cancel(&self, id: &str, orig_err: TavikError) -> Result<()> {
        let container_dir = self.container_dir(id);
        let control_sock = container_dir.join("control.sock");

        if !control_sock.exists() {
            if let Ok(st) = self.load_state(id) {
                if st.status == ContainerStatus::Stopped {
                    return Err(orig_err);
                }
            }
            return Err(TavikError::Execution(format!(
                "{}; additionally, mandatory startup cancellation failed: supervisor control socket missing at {:?}",
                orig_err, control_sock
            )));
        }

        match crate::init::send_control_command(&control_sock, "CANCEL") {
            Ok(resp) => {
                if resp != "OK" && !resp.starts_with("OK ") {
                    return Err(TavikError::Execution(format!(
                        "{}; additionally, mandatory startup cancellation failed: supervisor returned unexpected response {:?}",
                        orig_err, resp
                    )));
                }
            }
            Err(cancel_err) => {
                return Err(TavikError::Execution(format!(
                    "{}; additionally, mandatory startup cancellation failed: {}",
                    orig_err, cancel_err
                )));
            }
        }

        let final_state = self.load_state(id).map_err(|e| {
            TavikError::Execution(format!(
                "{}; additionally, failed to reload container state after cancellation: {}",
                orig_err, e
            ))
        })?;

        if final_state.status != ContainerStatus::Stopped {
            return Err(TavikError::Execution(format!(
                "{}; additionally, mandatory startup cancellation failed: container status is '{}' (expected 'stopped')",
                orig_err, final_state.status
            )));
        }

        Err(orig_err)
    }

    #[cfg(target_os = "linux")]
    fn platform_start(&self, id: &str, _state: &ContainerState) -> Result<()> {
        use std::io::Write;

        let container_dir = self.container_dir(id);
        let start_fifo = container_dir.join("start.fifo");
        let exec_fifo = container_dir.join("exec.fifo");

        if !start_fifo.exists() {
            let orig_err = TavikError::InvalidState(format!(
                "Container '{}' start FIFO not found at {:?}",
                id, start_fifo
            ));
            return self.abort_startup_and_cancel(id, orig_err);
        }

        // 1. Open exec.fifo for reading BEFORE triggering start signal
        let exec_fifo_c = std::ffi::CString::new(exec_fifo.to_str().unwrap()).unwrap();
        let exec_read_fd =
            unsafe { libc::open(exec_fifo_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if exec_read_fd < 0 {
            let orig_err = TavikError::Io(format!(
                "Failed to open exec FIFO at {:?}: {}",
                exec_fifo,
                std::io::Error::last_os_error()
            ));
            return self.abort_startup_and_cancel(id, orig_err);
        }

        // 2. Open start FIFO and write start signal
        let mut file = match fs::OpenOptions::new().write(true).open(&start_fifo) {
            Ok(f) => f,
            Err(e) => {
                unsafe { libc::close(exec_read_fd) };
                let orig_err =
                    TavikError::Io(format!("Failed to open container start FIFO: {}", e));
                return self.abort_startup_and_cancel(id, orig_err);
            }
        };

        if let Err(e) = file.write_all(b"1") {
            unsafe { libc::close(exec_read_fd) };
            let orig_err = TavikError::Io(format!(
                "Failed to write start signal to container FIFO: {}",
                e
            ));
            return self.abort_startup_and_cancel(id, orig_err);
        }

        // 3. Read execution status from exec.fifo
        // If execve() succeeds, fd 4 in child is closed by kernel via FD_CLOEXEC, yielding EOF (0 bytes).
        // If execve() or child pre-exec fails, child writes the error string and exits.
        let mut pfd = libc::pollfd {
            fd: exec_read_fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // Wait up to 15 seconds for startup handshake, retrying on EINTR
        let timeout = std::time::Duration::from_secs(15);
        let start_time = std::time::Instant::now();
        let mut poll_res = 0;
        let mut poll_err = None;

        while start_time.elapsed() < timeout {
            let rem_ms = (timeout.saturating_sub(start_time.elapsed()).as_millis() as i32).max(1);
            let pret = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
            if pret < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue; // Retry startup poll on EINTR
                }
                poll_res = pret;
                poll_err = Some(err);
                break;
            }
            if pret == 0 {
                poll_res = 0;
                break;
            }
            poll_res = pret;
            break;
        }

        if poll_res < 0 {
            unsafe { libc::close(exec_read_fd) };
            let orig_err = TavikError::Io(format!(
                "poll failed on exec.fifo: {}",
                poll_err.unwrap_or_else(std::io::Error::last_os_error)
            ));
            return self.abort_startup_and_cancel(id, orig_err);
        }

        if poll_res == 0 {
            unsafe { libc::close(exec_read_fd) };
            let orig_err = TavikError::Execution(format!(
                "Container '{}' startup timed out waiting for exec status",
                id
            ));
            return self.abort_startup_and_cancel(id, orig_err);
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
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue; // Retry read on EINTR
                }
                unsafe { libc::close(exec_read_fd) };
                let orig_err = TavikError::Io(format!("Failed to read from exec.fifo: {}", err));
                return self.abort_startup_and_cancel(id, orig_err);
            }
            if n == 0 {
                break; // EOF: kernel closed fd on successful execve!
            }
            err_buf.extend_from_slice(&chunk[..n as usize]);
        }
        unsafe { libc::close(exec_read_fd) };

        if !err_buf.is_empty() {
            let err_msg = String::from_utf8_lossy(&err_buf);
            let orig_err = TavikError::Execution(format!(
                "Container '{}' failed during startup: {}",
                id, err_msg
            ));
            return self.abort_startup_and_cancel(id, orig_err);
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
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_tavikr") {
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
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("tavikr");
            if candidate.exists() {
                return Some(candidate);
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
