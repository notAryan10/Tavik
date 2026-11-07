use crate::spec::{ContainerState, ContainerStatus, Spec};
use std::fs;
use std::path::{Path, PathBuf};
use tavik_common::error::{Result, TavikError};
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
        spec: &Spec,
        bundle: &Path,
        mut state: ContainerState,
    ) -> Result<ContainerState> {
        use std::os::unix::net::UnixDatagram;

        // Create socketpair for synchronization between parent runtime and child container init
        let (parent_sock, child_sock) = UnixDatagram::pair()
            .map_err(|e| TavikError::Io(format!("Failed to create IPC sync socketpair: {}", e)))?;

        let sync_dir = self.container_dir(id);
        let pid_file = sync_dir.join("container.pid");

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TavikError::Io(format!(
                "Failed to fork container process: {}",
                std::io::Error::last_os_error()
            )));
        }

        if pid == 0 {
            // In child process: configure isolation namespaces and enter jail
            drop(parent_sock);
            if let Err(e) = run_container_child(spec, bundle, child_sock) {
                eprintln!("[tavikr init error] {}", e);
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(0) };
        }

        // In parent runtime process:
        drop(child_sock);

        // Wait for child init process to signal it is prepared inside namespaces
        let mut buf = [0u8; 16];
        match parent_sock.recv(&mut buf) {
            Ok(n) if n > 0 && &buf[..n] == b"ready" => {
                info!("Container init PID {} reported ready in namespaces", pid);
            }
            Ok(_) | Err(_) => {
                return Err(TavikError::Execution(
                    "Container child failed to signal readiness".to_string(),
                ));
            }
        }

        fs::write(&pid_file, pid.to_string())?;

        state.pid = Some(pid as u32);
        state.status = ContainerStatus::Created;
        Ok(state)
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
    fn platform_start(&self, id: &str, state: &ContainerState) -> Result<()> {
        let pid = state.pid.ok_or_else(|| {
            TavikError::InvalidState(format!("Container '{}' has no recorded PID", id))
        })?;

        // Signal container child process to exec entrypoint via SIGCONT or IPC trigger
        let res = unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
        if res != 0 {
            return Err(TavikError::Execution(format!(
                "Failed to send start signal to container PID {}: {}",
                pid,
                std::io::Error::last_os_error()
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
fn run_container_child(
    spec: &Spec,
    bundle: &Path,
    sync_sock: std::os::unix::net::UnixDatagram,
) -> Result<()> {
    use std::ffi::CString;

    // 1. Unshare Linux namespaces
    let mut clone_flags = libc::CLONE_NEWNS;
    if let Some(linux) = &spec.linux {
        for ns in &linux.namespaces {
            match ns.ns_type {
                crate::spec::LinuxNamespaceType::Pid => clone_flags |= libc::CLONE_NEWPID,
                crate::spec::LinuxNamespaceType::Ipc => clone_flags |= libc::CLONE_NEWIPC,
                crate::spec::LinuxNamespaceType::Uts => clone_flags |= libc::CLONE_NEWUTS,
                crate::spec::LinuxNamespaceType::Network => clone_flags |= libc::CLONE_NEWNET,
                _ => {}
            }
        }
    }

    if unsafe { libc::unshare(clone_flags) } != 0 {
        return Err(TavikError::Execution(format!(
            "Failed to unshare namespaces: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 2. Set Hostname
    if let Some(hostname) = &spec.hostname {
        let c_host = CString::new(hostname.as_str()).unwrap();
        unsafe {
            libc::sethostname(c_host.as_ptr(), hostname.len());
        }
    }

    // 3. Make mount namespace private
    let none_c = CString::new("none").unwrap();
    let slash_c = CString::new("/").unwrap();
    unsafe {
        libc::mount(
            std::ptr::null(),
            slash_c.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        );
    }

    // 4. Resolve and bind mount rootfs
    let root = spec
        .root
        .as_ref()
        .ok_or_else(|| TavikError::Config("Spec missing rootfs definition".to_string()))?;

    let rootfs_path = if Path::new(&root.path).is_absolute() {
        PathBuf::from(&root.path)
    } else {
        bundle.join(&root.path)
    };

    let c_rootfs = CString::new(rootfs_path.to_str().unwrap()).unwrap();
    unsafe {
        libc::mount(
            c_rootfs.as_ptr(),
            c_rootfs.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        );
    }

    // 5. Mount proc inside container rootfs
    let proc_target = rootfs_path.join("proc");
    let _ = fs::create_dir_all(&proc_target);
    let c_proc_target = CString::new(proc_target.to_str().unwrap()).unwrap();
    let proc_type = CString::new("proc").unwrap();
    unsafe {
        libc::mount(
            proc_type.as_ptr(),
            c_proc_target.as_ptr(),
            proc_type.as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            std::ptr::null(),
        );
    }

    // 6. Chroot into rootfs
    unsafe {
        if libc::chroot(c_rootfs.as_ptr()) != 0 {
            return Err(TavikError::Execution(format!(
                "Failed to chroot into container rootfs: {}",
                std::io::Error::last_os_error()
            )));
        }
        let slash = CString::new("/").unwrap();
        libc::chdir(slash.as_ptr());
    }

    // 7. Signal readiness to parent runtime
    sync_sock
        .send(b"ready")
        .map_err(|e| TavikError::Io(format!("Failed to send readiness to parent: {}", e)))?;

    // 8. Pause until start signal received (SIGCONT or trigger)
    unsafe {
        libc::raise(libc::SIGSTOP);
    }

    // 9. Execute container process
    let proc = spec
        .process
        .as_ref()
        .ok_or_else(|| TavikError::Config("Spec missing process definition".to_string()))?;

    let c_args: Vec<CString> = proc
        .args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut c_args_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    c_args_ptrs.push(std::ptr::null());

    let c_envs: Vec<CString> = proc
        .env
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut c_envs_ptrs: Vec<*const libc::c_char> = c_envs.iter().map(|s| s.as_ptr()).collect();
    c_envs_ptrs.push(std::ptr::null());

    unsafe {
        libc::execve(c_args_ptrs[0], c_args_ptrs.as_ptr(), c_envs_ptrs.as_ptr());
    }

    Err(TavikError::Execution(format!(
        "Failed to execve container entrypoint: {}",
        std::io::Error::last_os_error()
    )))
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
