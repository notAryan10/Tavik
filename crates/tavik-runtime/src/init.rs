#[cfg(target_os = "linux")]
use crate::spec::{ContainerState, ContainerStatus, Spec};
#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
use tavik_common::error::{Result, TavikError};

#[cfg(target_os = "linux")]
pub fn run_init_trampoline(state_dir: &Path, id: &str) -> Result<()> {
    use std::ffi::CString;

    let container_dir = state_dir.join(id);
    let start_fifo_path = container_dir.join("start.fifo");
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
    let c_fifo = CString::new(start_fifo_path.to_str().unwrap()).unwrap();
    let fifo_res = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
    if fifo_res != 0 {
        return Err(TavikError::Io(format!(
            "Failed to create start FIFO at {:?}: {}",
            start_fifo_path,
            std::io::Error::last_os_error()
        )));
    }

    // 2. Prepare ready pipe for synchronous handshake between child init and trampoline
    let mut ready_pipe = [0i32; 2];
    if unsafe { libc::pipe(ready_pipe.as_mut_ptr()) } != 0 {
        return Err(TavikError::Io(format!(
            "Failed to create ready pipe: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 3. Set up cgroups v2 resource limits if requested (FAIL-CLOSED)
    let cgroup_mgr = if let Some(linux) = &spec.linux {
        if linux.resources.is_some() {
            let mgr = tavik_cgroups::CgroupManager::new().map_err(|e| {
                TavikError::Execution(format!(
                    "Failed to initialize cgroups v2 manager for requested container resources: {}",
                    e
                ))
            })?;
            mgr.validate_cgroup_v2().map_err(|e| {
                TavikError::Execution(format!(
                    "Requested container resources require cgroup v2 support: {}",
                    e
                ))
            })?;
            mgr.create_container_cgroup(id).map_err(|e| {
                TavikError::Execution(format!(
                    "Failed to create cgroup for container '{}': {}",
                    id, e
                ))
            })?;
            if let Some(resources) = &linux.resources {
                mgr.apply_resources(id, resources).map_err(|e| {
                    TavikError::Execution(format!(
                        "Failed to apply cgroup resources for container '{}': {}",
                        id, e
                    ))
                })?;
            }
            Some(mgr)
        } else {
            tavik_cgroups::CgroupManager::new().ok()
        }
    } else {
        None
    };

    // 4. Unshare PID namespace in trampoline process
    // Note: Calling unshare(CLONE_NEWPID) puts the NEXT child into the new PID namespace!
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        return Err(TavikError::Execution(format!(
            "Failed to unshare PID namespace in trampoline: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 5. Fork container init process (this child is PID 1 in the new PID namespace!)
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(TavikError::Io(format!(
            "Failed to fork container init child: {}",
            std::io::Error::last_os_error()
        )));
    }

    if child_pid == 0 {
        // --- CHILD PROCESS (PID 1 in new PID namespace) ---
        unsafe {
            libc::close(ready_pipe[0]); // Close read end in child
        }
        if let Err(e) =
            run_container_init_child(&spec, &state.bundle, ready_pipe[1], &start_fifo_path)
        {
            eprintln!("[tavikr init child error] {}", e);
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::_exit(0) };
    }

    // --- TRAMPOLINE PARENT PROCESS ---
    unsafe {
        libc::close(ready_pipe[1]); // Close write end in parent
    }

    // Enroll child PID into cgroups v2 container group (FAIL-CLOSED)
    if let (Some(mgr), Some(linux)) = (&cgroup_mgr, &spec.linux) {
        if linux.resources.is_some() {
            if let Err(e) = mgr.add_process(id, child_pid as u32) {
                // Abort container creation immediately: kill child, cleanup cgroup, fail closed
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(child_pid, &mut status, 0);
                }
                let _ = mgr.destroy_container_cgroup(id);
                return Err(TavikError::Execution(format!(
                    "Failed to enroll container child PID {} in cgroup '{}': {}",
                    child_pid, id, e
                )));
            }
        }
    }

    // Wait for child to signal readiness over pipe
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
        return Err(TavikError::Execution(format!(
            "Container init child failed to signal readiness: {:?}",
            if n > 0 { &buf[..n as usize] } else { &[] }
        )));
    }

    // Record host PID and update state to Created
    fs::write(&pid_file, child_pid.to_string()).map_err(|e| {
        TavikError::Io(format!("Failed to write pid_file at {:?}: {}", pid_file, e))
    })?;

    let mut updated_state = state;
    updated_state.status = ContainerStatus::Created;
    updated_state.pid = Some(child_pid as u32);
    let json = serde_json::to_string_pretty(&updated_state)?;
    fs::write(&state_file, json).map_err(|e| {
        TavikError::Io(format!(
            "Failed to write state_file at {:?}: {}",
            state_file, e
        ))
    })?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn run_container_init_child(
    spec: &Spec,
    bundle: &Path,
    ready_pipe_write_fd: i32,
    start_fifo_path: &Path,
) -> Result<()> {
    use std::ffi::CString;
    use std::path::PathBuf;

    // 1. Open start FIFO with O_RDWR before pivot_root so open does not block
    let c_fifo = CString::new(start_fifo_path.to_str().unwrap()).unwrap();
    let fifo_fd = unsafe { libc::open(c_fifo.as_ptr(), libc::O_RDWR) };
    if fifo_fd < 0 {
        return Err(TavikError::Io(format!(
            "Failed to open start FIFO in child: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 2. Unshare Mount, UTS, IPC, Network namespaces for the container
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
        return Err(TavikError::Execution(format!(
            "Failed to unshare container namespaces in child: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 3. Set Hostname
    if let Some(hostname) = &spec.hostname {
        let c_host = CString::new(hostname.as_str()).unwrap();
        unsafe {
            libc::sethostname(c_host.as_ptr(), hostname.len());
        }
    }

    // 3. Make mount namespace recursively private
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
            return Err(TavikError::Execution(format!(
                "Failed to make mount namespace private: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    // 4. Resolve rootfs and bind mount it to itself
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
        if libc::mount(
            c_rootfs.as_ptr(),
            c_rootfs.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return Err(TavikError::Execution(format!(
                "Failed to bind mount rootfs to itself: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    // 5. Mount proc inside container rootfs
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
            return Err(TavikError::Execution(format!(
                "Failed to mount /proc inside container rootfs: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    // 6. pivot_root
    let old_root_rel = ".pivot_root";
    let old_root_path = rootfs_path.join(old_root_rel);
    let _ = fs::create_dir_all(&old_root_path);
    let c_old_root = CString::new(old_root_path.to_str().unwrap()).unwrap();

    unsafe {
        let ret = libc::syscall(libc::SYS_pivot_root, c_rootfs.as_ptr(), c_old_root.as_ptr());
        if ret != 0 {
            return Err(TavikError::Execution(format!(
                "pivot_root failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Chdir to new root
        if libc::chdir(slash.as_ptr()) != 0 {
            return Err(TavikError::Execution(format!(
                "chdir to new root failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Unmount old root
        let old_root_unmount = CString::new(format!("/{}", old_root_rel)).unwrap();
        if libc::umount2(old_root_unmount.as_ptr(), libc::MNT_DETACH) != 0 {
            return Err(TavikError::Execution(format!(
                "umount2 old root failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _ = libc::rmdir(old_root_unmount.as_ptr());
    }

    // 7. Change working directory
    let proc = spec
        .process
        .as_ref()
        .ok_or_else(|| TavikError::Config("Spec missing process definition".to_string()))?;

    let c_cwd = CString::new(proc.cwd.as_str()).unwrap_or_else(|_| slash.clone());
    unsafe {
        libc::chdir(c_cwd.as_ptr());
    }

    // 8. Signal readiness to trampoline
    unsafe {
        libc::write(
            ready_pipe_write_fd,
            b"ready\n".as_ptr() as *const libc::c_void,
            6,
        );
        libc::close(ready_pipe_write_fd);
    }

    // 9. Block waiting for start signal on start FIFO
    let mut start_buf = [0u8; 1];
    let n = unsafe { libc::read(fifo_fd, start_buf.as_mut_ptr() as *mut libc::c_void, 1) };
    unsafe {
        libc::close(fifo_fd);
    }

    if n <= 0 {
        return Err(TavikError::Execution(
            "Start FIFO closed without receiving start signal".to_string(),
        ));
    }

    // --- CONTAINER START LIFECYCLE: Strict Security Enforcement ---
    // 10. File descriptor sanitization: close all fds >= 3
    unsafe {
        libc::close_range(3, !0u32, 0);
    }

    // 11. Parse capability sets if configured
    let cap_sets = if let Some(caps) = &proc.capabilities {
        Some(caps.to_capability_sets().map_err(|e| {
            TavikError::Execution(format!("Failed to parse capability sets: {}", e))
        })?)
    } else {
        None
    };

    // 12. If capability bounding set is configured, drop unrequested capabilities
    // while still root (UID 0) prior to any privilege transition.
    // In Linux, PR_CAPBSET_DROP strictly requires CAP_SETPCAP.
    if let Some(sets) = &cap_sets {
        if let Some(bounding) = &sets.bounding {
            tavik_security::drop_bounding_set(bounding).map_err(|e| {
                TavikError::Execution(format!("Failed to drop bounding capabilities: {}", e))
            })?;
        }
    }

    // 13. Privilege transition: supplementary groups, GID, UID (FAIL-CLOSED)
    if proc.user.uid > 0 {
        // Enable PR_SET_KEEPCAPS so permitted capabilities are preserved across setuid().
        let keepcaps_res = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
        if keepcaps_res != 0 {
            return Err(TavikError::Execution(format!(
                "Failed to set PR_SET_KEEPCAPS: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    if !proc.user.additional_gids.is_empty() {
        let gids: Vec<libc::gid_t> = proc
            .user
            .additional_gids
            .iter()
            .map(|&g| g as libc::gid_t)
            .collect();
        let setgroups_res = unsafe { libc::setgroups(gids.len(), gids.as_ptr()) };
        if setgroups_res != 0 {
            return Err(TavikError::Execution(format!(
                "Failed to set supplementary groups: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    if proc.user.gid > 0 {
        let setgid_res = unsafe { libc::setgid(proc.user.gid as libc::gid_t) };
        if setgid_res != 0 {
            return Err(TavikError::Execution(format!(
                "Failed to setgid to {}: {}",
                proc.user.gid,
                std::io::Error::last_os_error()
            )));
        }
    }

    if proc.user.uid > 0 {
        let setuid_res = unsafe { libc::setuid(proc.user.uid as libc::uid_t) };
        if setuid_res != 0 {
            return Err(TavikError::Execution(format!(
                "Failed to setuid to {}: {}",
                proc.user.uid,
                std::io::Error::last_os_error()
            )));
        }
    }

    // 14. Apply thread capabilities (permitted, effective, inheritable, ambient)
    // Using apply_thread_capabilities ensures PR_CAPBSET_DROP is not attempted post-setuid.
    if let Some(sets) = &cap_sets {
        tavik_security::apply_thread_capabilities(sets).map_err(|e| {
            TavikError::Execution(format!("Failed to apply thread capabilities: {}", e))
        })?;
    }

    if proc.user.uid > 0 {
        // Clear PR_SET_KEEPCAPS so container process children do not retain keepcaps
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
        }
    }

    // 14. Security: PR_SET_NO_NEW_PRIVS barrier
    if proc.no_new_privileges {
        tavik_security::ensure_no_new_privs().map_err(|e| {
            TavikError::Execution(format!("Failed to set PR_SET_NO_NEW_PRIVS: {}", e))
        })?;
    }

    // 15. Security: Seccomp BPF filter
    // Applied as the FINAL security gate immediately before execve so all prior setup calls succeed
    if let Some(linux) = &spec.linux {
        if let Some(seccomp_profile) = &linux.seccomp {
            tavik_security::apply_seccomp(seccomp_profile).map_err(|e| {
                TavikError::Execution(format!("Failed to apply seccomp filter: {}", e))
            })?;
        }
    }

    // 15. execve entrypoint
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

    // Resolve binary path along the container's PATH if args[0] does not contain '/'
    // We are already inside the container rootfs post-pivot_root, so access checks
    // exclusively inspect the container filesystem and never touch host executables.
    let executable_c = if !proc.args[0].contains('/') {
        let container_path = proc
            .env
            .iter()
            .find_map(|e| e.strip_prefix("PATH="))
            .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

        let mut found_path = None;
        for dir in container_path.split(':') {
            if dir.is_empty() {
                continue;
            }
            let candidate = std::path::Path::new(dir).join(&proc.args[0]);
            if let Ok(c_cand) = CString::new(candidate.to_str().unwrap_or("")) {
                if unsafe { libc::access(c_cand.as_ptr(), libc::X_OK) } == 0 {
                    found_path = Some(c_cand);
                    break;
                }
            }
        }
        found_path.unwrap_or_else(|| c_args[0].clone())
    } else {
        c_args[0].clone()
    };

    unsafe {
        libc::execve(
            executable_c.as_ptr(),
            c_args_ptrs.as_ptr(),
            c_envs_ptrs.as_ptr(),
        );
    }

    Err(TavikError::Execution(format!(
        "Failed to execve container entrypoint: {}",
        std::io::Error::last_os_error()
    )))
}

#[cfg(not(target_os = "linux"))]
pub fn run_init_trampoline(_state_dir: &Path, _id: &str) -> Result<()> {
    Err(TavikError::Unsupported(
        "Container init trampoline requires Linux".to_string(),
    ))
}
