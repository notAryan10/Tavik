#[cfg(target_os = "linux")]
use crate::spec::{ContainerState, ContainerStatus, Spec};
#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use tavik_common::error::{Result, TavikError};

#[cfg(target_os = "linux")]
pub struct CgroupGuard {
    mgr: tavik_cgroups::CgroupManager,
    container_id: String,
    active: bool,
}

#[cfg(target_os = "linux")]
impl CgroupGuard {
    pub fn new(mgr: tavik_cgroups::CgroupManager, container_id: String) -> Self {
        Self {
            mgr,
            container_id,
            active: true,
        }
    }

    pub fn disarm(&mut self) {
        self.active = false;
    }

    pub fn manager(&self) -> &tavik_cgroups::CgroupManager {
        &self.mgr
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.mgr.destroy_container_cgroup(&self.container_id);
        }
    }
}

#[cfg(target_os = "linux")]
fn write_exec_error_and_exit(msg: &str) -> ! {
    unsafe {
        let _ = libc::write(3, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(1);
    }
}

#[cfg(target_os = "linux")]
pub fn run_init_trampoline(state_dir: &Path, id: &str) -> Result<()> {
    use std::ffi::CString;

    let container_dir = state_dir.join(id);
    let start_fifo_path = container_dir.join("start.fifo");
    let exec_fifo_path = container_dir.join("exec.fifo");
    let pid_file = container_dir.join("container.pid");

    let state_file = container_dir.join("state.json");
    let state_json = fs::read_to_string(&state_file).map_err(|e| {
        TavikError::Io(format!(
            "Failed to read state file at {:?}: {}",
            state_file, e
        ))
    })?;
    let state: ContainerState = serde_json::from_str(&state_json)?;
    let spec = Spec::load_from_bundle(&state.bundle)?;

    // 1. Prepare start FIFO for future start signal
    if start_fifo_path.exists() {
        let _ = fs::remove_file(&start_fifo_path);
    }
    let c_start_fifo = CString::new(start_fifo_path.to_str().unwrap()).unwrap();
    let fifo_res = unsafe { libc::mkfifo(c_start_fifo.as_ptr(), 0o600) };
    if fifo_res != 0 {
        return Err(TavikError::Io(format!(
            "Failed to create start FIFO at {:?}: {}",
            start_fifo_path,
            std::io::Error::last_os_error()
        )));
    }

    // 2. Prepare exec FIFO for startup execution synchronization
    if exec_fifo_path.exists() {
        let _ = fs::remove_file(&exec_fifo_path);
    }
    let c_exec_fifo = CString::new(exec_fifo_path.to_str().unwrap()).unwrap();
    let exec_res = unsafe { libc::mkfifo(c_exec_fifo.as_ptr(), 0o600) };
    if exec_res != 0 {
        let _ = fs::remove_file(&start_fifo_path);
        return Err(TavikError::Io(format!(
            "Failed to create exec FIFO at {:?}: {}",
            exec_fifo_path,
            std::io::Error::last_os_error()
        )));
    }

    // 3. Prepare handshake pipe between trampoline caller and supervisor
    let mut trampoline_pipe = [0i32; 2];
    if unsafe { libc::pipe(trampoline_pipe.as_mut_ptr()) } != 0 {
        let _ = fs::remove_file(&start_fifo_path);
        let _ = fs::remove_file(&exec_fifo_path);
        return Err(TavikError::Io(format!(
            "Failed to create trampoline handshake pipe: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 4. Fork dedicated background supervisor process
    let supervisor_pid = unsafe { libc::fork() };
    if supervisor_pid < 0 {
        let _ = fs::remove_file(&start_fifo_path);
        let _ = fs::remove_file(&exec_fifo_path);
        return Err(TavikError::Io(format!(
            "Failed to fork supervisor process: {}",
            std::io::Error::last_os_error()
        )));
    }

    if supervisor_pid > 0 {
        // --- TRAMPOLINE CALLER PROCESS ---
        unsafe { libc::close(trampoline_pipe[1]) };

        let mut buf = [0u8; 256];
        let n = unsafe {
            libc::read(
                trampoline_pipe[0],
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        unsafe { libc::close(trampoline_pipe[0]) };

        if n <= 0 || &buf[..2] != b"ok" {
            let err_msg = if n > 0 {
                String::from_utf8_lossy(&buf[..n as usize]).to_string()
            } else {
                "Container supervisor exited prematurely during creation".to_string()
            };
            return Err(TavikError::Execution(err_msg));
        }

        return Ok(());
    }

    // --- SUPERVISOR PROCESS (Child of caller, parent of container init) ---
    unsafe {
        libc::close(trampoline_pipe[0]);
        // Detach supervisor from controlling terminal
        libc::setsid();
    }

    // 5. Initialize cgroups v2 resource limits with fail-closed RAII cleanup guard
    let cgroup_guard = if let Some(linux) = &spec.linux {
        if linux.resources.is_some() {
            let mgr = match tavik_cgroups::CgroupManager::new() {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("Failed to initialize cgroups v2 manager: {}", e);
                    let _ =
                        unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                    unsafe { libc::_exit(1) };
                }
            };
            if let Err(e) = mgr.validate_cgroup_v2() {
                let msg = format!("Requested resources require cgroup v2: {}", e);
                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                unsafe { libc::_exit(1) };
            }
            if let Err(e) = mgr.create_container_cgroup(id) {
                let msg = format!("Failed to create cgroup for container '{}': {}", id, e);
                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                unsafe { libc::_exit(1) };
            }
            let guard = CgroupGuard::new(mgr, id.to_string());
            if let Some(resources) = &linux.resources {
                if let Err(e) = guard.manager().apply_resources(id, resources) {
                    let msg = format!("Failed to apply cgroup resources: {}", e);
                    let _ =
                        unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                    drop(guard);
                    unsafe { libc::_exit(1) };
                }
            }
            Some(guard)
        } else {
            None
        }
    } else {
        None
    };

    // 6. Unshare PID namespace
    // Calling unshare(CLONE_NEWPID) puts the NEXT child into the new PID namespace!
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        let msg = format!(
            "Failed to unshare PID namespace in supervisor: {}",
            std::io::Error::last_os_error()
        );
        let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
        drop(cgroup_guard);
        unsafe { libc::_exit(1) };
    }

    // 7. Prepare ready pipe for synchronous handshake between child init and supervisor
    let mut ready_pipe = [0i32; 2];
    if unsafe { libc::pipe(ready_pipe.as_mut_ptr()) } != 0 {
        let msg = format!(
            "Failed to create ready pipe: {}",
            std::io::Error::last_os_error()
        );
        let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
        drop(cgroup_guard);
        unsafe { libc::_exit(1) };
    }

    // 8. Fork container init process (this child is PID 1 in the new PID namespace!)
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        let msg = format!(
            "Failed to fork container init child: {}",
            std::io::Error::last_os_error()
        );
        let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
        drop(cgroup_guard);
        unsafe { libc::_exit(1) };
    }

    if child_pid == 0 {
        // --- CONTAINER INIT CHILD PROCESS (PID 1 in new PID namespace) ---
        unsafe {
            libc::close(trampoline_pipe[1]);
            libc::close(ready_pipe[0]);
        }
        run_container_init_child(
            &spec,
            &state.bundle,
            ready_pipe[1],
            &start_fifo_path,
            &exec_fifo_path,
        );
        unsafe { libc::_exit(1) };
    }

    // --- SUPERVISOR PROCESS CONTINUATION ---
    unsafe {
        libc::close(ready_pipe[1]);
    }

    // 9. Enroll child PID into cgroups v2 container group (FAIL-CLOSED)
    if let Some(guard) = &cgroup_guard {
        if let Err(e) = guard.manager().add_process(id, child_pid as u32) {
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(child_pid, &mut status, 0);
            }
            let msg = format!("Failed to enroll child PID {} in cgroup: {}", child_pid, e);
            let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
            drop(cgroup_guard);
            unsafe { libc::_exit(1) };
        }
    }

    // 10. Wait for child init process to signal readiness over pipe
    let mut buf = [0u8; 16];
    let n = unsafe {
        libc::read(
            ready_pipe[0],
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    unsafe {
        libc::close(ready_pipe[0]);
    }

    if n <= 0 || &buf[..n as usize] != b"ready\n" {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(child_pid, &mut status, 0);
        }
        let msg = format!("Container init child failed to signal readiness");
        let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
        drop(cgroup_guard);
        unsafe { libc::_exit(1) };
    }

    // 11. Record host PID and persist state as Created
    let _ = fs::write(&pid_file, child_pid.to_string());
    let mut updated_state = state;
    updated_state.status = ContainerStatus::Created;
    updated_state.pid = Some(child_pid as u32);
    if let Ok(json) = serde_json::to_string_pretty(&updated_state) {
        let _ = fs::write(&state_file, json);
    }

    // Ownership of cgroup transferred to running container lifecycle; disarm guard
    if let Some(mut guard) = cgroup_guard {
        guard.disarm();
    }

    // Signal successful creation to trampoline caller
    let _ = unsafe { libc::write(trampoline_pipe[1], b"ok\n".as_ptr() as _, 3) };
    unsafe { libc::close(trampoline_pipe[1]) };

    // --- SUPERVISORY LOOP ---
    // The supervisor remains active to reap the child and update state upon exit
    let mut status = 0;
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }

    // Child exited: update container state to Stopped
    if let Ok(content) = fs::read_to_string(&state_file) {
        if let Ok(mut st) = serde_json::from_str::<ContainerState>(&content) {
            st.status = ContainerStatus::Stopped;
            if let Ok(json) = serde_json::to_string_pretty(&st) {
                let _ = fs::write(&state_file, json);
            }
        }
    }

    // Destroy container cgroup on exit
    if let Ok(mgr) = tavik_cgroups::CgroupManager::new() {
        let _ = mgr.destroy_container_cgroup(id);
    }
    let _ = fs::remove_file(&start_fifo_path);
    let _ = fs::remove_file(&exec_fifo_path);

    unsafe { libc::_exit(0) };
}

#[cfg(target_os = "linux")]
fn run_container_init_child(
    spec: &Spec,
    bundle: &Path,
    ready_pipe_write_fd: i32,
    start_fifo_path: &Path,
    exec_fifo_path: &Path,
) {
    use std::ffi::CString;

    // 1. Open start FIFO with O_RDWR before pivot_root so open does not block
    let c_fifo = CString::new(start_fifo_path.to_str().unwrap()).unwrap();
    let fifo_fd = unsafe { libc::open(c_fifo.as_ptr(), libc::O_RDWR) };
    if fifo_fd < 0 {
        eprintln!("Failed to open start FIFO in child");
        unsafe { libc::_exit(1) };
    }

    // 2. Open exec FIFO with O_RDWR and dup2 to fixed descriptor 3 (FD_CLOEXEC)
    let c_exec_fifo = CString::new(exec_fifo_path.to_str().unwrap()).unwrap();
    let exec_fd = unsafe { libc::open(c_exec_fifo.as_ptr(), libc::O_RDWR) };
    if exec_fd < 0 {
        eprintln!("Failed to open exec FIFO in child");
        unsafe { libc::_exit(1) };
    }
    unsafe {
        if libc::dup2(exec_fd, 3) < 0 {
            libc::close(exec_fd);
            libc::_exit(1);
        }
        if exec_fd != 3 {
            libc::close(exec_fd);
        }
        libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC);
    }

    // 3. Unshare Mount, UTS, IPC, Network namespaces for the container
    let mut child_flags = libc::CLONE_NEWNS;
    if let Some(linux) = &spec.linux {
        for ns in &linux.namespaces {
            match ns.ns_type {
                crate::spec::LinuxNamespaceType::Ipc => child_flags |= libc::CLONE_NEWIPC,
                crate::spec::LinuxNamespaceType::Uts => child_flags |= libc::CLONE_NEWUTS,
                crate::spec::LinuxNamespaceType::Network => child_flags |= libc::CLONE_NEWNET,
                _ => {}
            }
        }
    }
    if unsafe { libc::unshare(child_flags) } != 0 {
        write_exec_error_and_exit(&format!(
            "Failed to unshare container namespaces: {}",
            std::io::Error::last_os_error()
        ));
    }

    // 4. Set Hostname
    if let Some(hostname) = &spec.hostname {
        let c_host = CString::new(hostname.as_str()).unwrap();
        unsafe {
            libc::sethostname(c_host.as_ptr(), hostname.len());
        }
    }

    // 5. Make mount namespace recursively private
    let slash = CString::new("/").unwrap();
    unsafe {
        if libc::mount(
            std::ptr::null(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            write_exec_error_and_exit(&format!(
                "Failed to make mount namespace private: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // 6. Resolve rootfs and bind mount it to itself
    let root = match &spec.root {
        Some(r) => r,
        None => write_exec_error_and_exit("Spec missing rootfs definition"),
    };
    let rootfs_path = if Path::new(&root.path).is_absolute() {
        PathBuf::from(&root.path)
    } else {
        bundle.join(&root.path)
    };

    let c_rootfs = match CString::new(rootfs_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => write_exec_error_and_exit("Invalid rootfs path"),
    };
    unsafe {
        if libc::mount(
            c_rootfs.as_ptr(),
            c_rootfs.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            write_exec_error_and_exit(&format!(
                "Failed to bind mount rootfs to itself: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // Mount proc inside container rootfs
    let proc_target = rootfs_path.join("proc");
    let _ = fs::create_dir_all(&proc_target);
    let c_proc_target = CString::new(proc_target.to_str().unwrap()).unwrap();
    let proc_type = CString::new("proc").unwrap();
    unsafe {
        let mount_res = libc::mount(
            proc_type.as_ptr(),
            c_proc_target.as_ptr(),
            proc_type.as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            std::ptr::null(),
        );
        if mount_res != 0 {
            write_exec_error_and_exit(&format!(
                "Failed to mount /proc inside container rootfs: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // pivot_root
    let old_root_rel = ".pivot_root";
    let old_root_path = rootfs_path.join(old_root_rel);
    let _ = fs::create_dir_all(&old_root_path);
    let c_old_root = CString::new(old_root_path.to_str().unwrap()).unwrap();

    unsafe {
        let ret = libc::syscall(libc::SYS_pivot_root, c_rootfs.as_ptr(), c_old_root.as_ptr());
        if ret != 0 {
            write_exec_error_and_exit(&format!(
                "pivot_root failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Chdir to new root
        if libc::chdir(slash.as_ptr()) != 0 {
            write_exec_error_and_exit(&format!(
                "chdir to new root failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Unmount old root
        let old_root_unmount = CString::new(format!("/{}", old_root_rel)).unwrap();
        if libc::umount2(old_root_unmount.as_ptr(), libc::MNT_DETACH) != 0 {
            write_exec_error_and_exit(&format!(
                "umount2 old root failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let _ = libc::rmdir(old_root_unmount.as_ptr());
    }

    let proc = match &spec.process {
        Some(p) => p,
        None => write_exec_error_and_exit("Spec missing process definition"),
    };

    // 7. Signal readiness to supervisor
    unsafe {
        libc::write(
            ready_pipe_write_fd,
            b"ready\n".as_ptr() as *const libc::c_void,
            6,
        );
        libc::close(ready_pipe_write_fd);
    }

    // 8. Block waiting for start signal on start FIFO
    let mut start_buf = [0u8; 1];
    let n = unsafe { libc::read(fifo_fd, start_buf.as_mut_ptr() as *mut libc::c_void, 1) };
    unsafe {
        libc::close(fifo_fd);
    }

    if n <= 0 {
        write_exec_error_and_exit("Start FIFO closed without receiving start signal");
    }

    // --- CONTAINER START LIFECYCLE: Strict Security Enforcement ---
    // 9. File descriptor sanitization: close all fds >= 4 (preserving stdin 0, stdout 1, stderr 2, exec_fd 3)
    unsafe {
        libc::close_range(4, !0u32, 0);
    }

    // 10. Parse capability sets if configured
    let cap_sets = if let Some(caps) = &proc.capabilities {
        match caps.to_capability_sets() {
            Ok(sets) => Some(sets),
            Err(e) => write_exec_error_and_exit(&format!("Failed to parse capability sets: {}", e)),
        }
    } else {
        None
    };

    // 11. If capability bounding set is configured, drop unrequested capabilities
    // while still root (UID 0) prior to any privilege transition.
    if let Some(sets) = &cap_sets {
        if let Some(bounding) = &sets.bounding {
            if let Err(e) = tavik_security::drop_bounding_set(bounding) {
                write_exec_error_and_exit(&format!("Failed to drop bounding capabilities: {}", e));
            }
        }
    }

    // 12. Privilege transition: supplementary groups, primary GID, primary UID (FAIL-CLOSED)
    if proc.user.uid > 0 {
        let keepcaps_res = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
        if keepcaps_res != 0 {
            write_exec_error_and_exit(&format!(
                "Failed to set PR_SET_KEEPCAPS: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // Set container supplementary groups (must exactly match additional_gids; empty clears inherited groups)
    let gids: Vec<libc::gid_t> = proc
        .user
        .additional_gids
        .iter()
        .map(|&g| g as libc::gid_t)
        .collect();
    let setgroups_res = unsafe {
        if gids.is_empty() {
            libc::setgroups(0, std::ptr::null())
        } else {
            libc::setgroups(gids.len(), gids.as_ptr())
        }
    };
    if setgroups_res != 0 {
        write_exec_error_and_exit(&format!(
            "Failed to set supplementary groups: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Unconditionally establish primary GID and UID (never rely on inherited launcher credentials)
    let setgid_res = unsafe { libc::setgid(proc.user.gid as libc::gid_t) };
    if setgid_res != 0 {
        write_exec_error_and_exit(&format!(
            "Failed to setgid to {}: {}",
            proc.user.gid,
            std::io::Error::last_os_error()
        ));
    }

    let setuid_res = unsafe { libc::setuid(proc.user.uid as libc::uid_t) };
    if setuid_res != 0 {
        write_exec_error_and_exit(&format!(
            "Failed to setuid to {}: {}",
            proc.user.uid,
            std::io::Error::last_os_error()
        ));
    }

    // 13. Apply thread capabilities (permitted, effective, inheritable, ambient)
    if let Some(sets) = &cap_sets {
        if let Err(e) = tavik_security::apply_thread_capabilities(sets) {
            write_exec_error_and_exit(&format!("Failed to apply thread capabilities: {}", e));
        }
    }

    if proc.user.uid > 0 {
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
        }
    }

    // 14. Security: PR_SET_NO_NEW_PRIVS barrier
    if proc.no_new_privileges {
        if let Err(e) = tavik_security::ensure_no_new_privs() {
            write_exec_error_and_exit(&format!("Failed to set PR_SET_NO_NEW_PRIVS: {}", e));
        }
    }

    // 15. Apply working directory under container credentials
    let c_cwd = match CString::new(proc.cwd.as_str()) {
        Ok(c) => c,
        Err(e) => write_exec_error_and_exit(&format!("Invalid working directory path: {}", e)),
    };
    if unsafe { libc::chdir(c_cwd.as_ptr()) } != 0 {
        write_exec_error_and_exit(&format!(
            "Failed to change working directory to '{}': {}",
            proc.cwd,
            std::io::Error::last_os_error()
        ));
    }

    // 16. Resolve executable command inside pivoted rootfs using container credentials BEFORE seccomp
    let raw_cmd = match proc.args.first() {
        Some(cmd) => cmd,
        None => write_exec_error_and_exit("Spec missing process arguments"),
    };

    if raw_cmd.is_empty() {
        write_exec_error_and_exit("Executable command in argv[0] cannot be empty");
    }

    let executable_c = if raw_cmd.contains('/') {
        let candidate = if raw_cmd.starts_with('/') {
            PathBuf::from(raw_cmd)
        } else {
            std::path::Path::new(&proc.cwd).join(raw_cmd)
        };
        let c_path = match CString::new(candidate.to_str().unwrap_or(raw_cmd.as_str())) {
            Ok(c) => c,
            Err(e) => write_exec_error_and_exit(&format!("Command contains null byte: {}", e)),
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(c_path.as_ptr(), &mut st) } != 0 {
            write_exec_error_and_exit(&format!(
                "Executable '{}' not found: {}",
                raw_cmd,
                std::io::Error::last_os_error()
            ));
        }

        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            write_exec_error_and_exit(&format!("Executable '{}' is a directory", raw_cmd));
        }

        if unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } != 0 {
            write_exec_error_and_exit(&format!(
                "Executable '{}' is not executable: {}",
                raw_cmd,
                std::io::Error::last_os_error()
            ));
        }

        c_path
    } else {
        let container_path = proc
            .env
            .iter()
            .find_map(|e| e.strip_prefix("PATH="))
            .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

        let mut found = None;
        for dir in container_path.split(':') {
            if dir.is_empty() {
                continue;
            }
            let candidate = if dir.starts_with('/') {
                std::path::Path::new(dir).join(raw_cmd)
            } else {
                std::path::Path::new(&proc.cwd).join(dir).join(raw_cmd)
            };
            let candidate_str = match candidate.to_str() {
                Some(s) => s,
                None => continue,
            };
            let c_cand = match CString::new(candidate_str) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // stat follows in-rootfs symlinks inside pivoted rootfs
            if unsafe { libc::stat(c_cand.as_ptr(), &mut st) } != 0 {
                continue;
            }

            // Reject directories
            if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                continue;
            }

            // Reject non-executable files under container credentials
            if unsafe { libc::access(c_cand.as_ptr(), libc::X_OK) } != 0 {
                continue;
            }

            found = Some(c_cand);
            break;
        }

        match found {
            Some(f) => f,
            None => write_exec_error_and_exit(&format!(
                "Executable '{}' not found in container PATH '{}'",
                raw_cmd, container_path
            )),
        }
    };

    // 17. Security: Seccomp BPF filter
    if let Some(linux) = &spec.linux {
        if let Some(seccomp_profile) = &linux.seccomp {
            if let Err(e) = tavik_security::apply_seccomp(seccomp_profile) {
                write_exec_error_and_exit(&format!("Failed to apply seccomp filter: {}", e));
            }
        }
    }

    // 18. execve entrypoint
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
        libc::execve(
            executable_c.as_ptr(),
            c_args_ptrs.as_ptr(),
            c_envs_ptrs.as_ptr(),
        );
    }

    write_exec_error_and_exit(&format!(
        "Failed to execve container entrypoint: {}",
        std::io::Error::last_os_error()
    ));
}

#[cfg(not(target_os = "linux"))]
pub fn run_init_trampoline(_state_dir: &Path, _id: &str) -> Result<()> {
    Err(TavikError::Unsupported(
        "Container init trampoline requires Linux".to_string(),
    ))
}
