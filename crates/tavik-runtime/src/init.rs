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

    pub fn cleanup(&mut self, container_dir: &Path) -> std::result::Result<(), String> {
        if !self.active {
            return Ok(());
        }

        if container_dir.join(".simulate_cgroup_destroy_fail").exists() {
            return Err("Simulated cgroup destruction failure".to_string());
        }

        match self.mgr.destroy_container_cgroup(&self.container_id) {
            Ok(()) => {
                self.active = false;
                let owner_path = container_dir.join("cgroup.owner");
                if owner_path.exists() {
                    if let Err(e) = fs::remove_file(&owner_path) {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            return Err(format!(
                                "Failed to remove cgroup.owner marker for container '{}': {}",
                                self.container_id, e
                            ));
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                // If cleanup fails, preserve cgroup.owner and return observable error
                Err(format!(
                    "Explicit cgroup cleanup failed for container '{}': {}",
                    self.container_id, e
                ))
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = self.mgr.destroy_container_cgroup(&self.container_id) {
                eprintln!(
                    "CgroupGuard fallback cleanup failed for container '{}': {}",
                    self.container_id, e
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub const START_FIFO_FD: i32 = 3;
#[cfg(target_os = "linux")]
pub const EXEC_STATUS_FD: i32 = 4;

#[cfg(target_os = "linux")]
pub fn close_inherited_descriptors_above(min_fd: i32) {
    // 1. Try kernel close_range syscall
    if unsafe { libc::close_range(min_fd as libc::c_uint, !0u32, 0) } == 0 {
        return;
    }

    // 2. Fallback: inspect /proc/self/fd via getdents64
    let proc_fd_path = std::ffi::CString::new("/proc/self/fd").unwrap();
    let dir_fd = unsafe {
        libc::open(
            proc_fd_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dir_fd >= 0 {
        let mut buf = [0u8; 2048];
        loop {
            let n = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dir_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let mut pos = 0;
            while pos < n as usize {
                let d = unsafe { &*(buf.as_ptr().add(pos) as *const libc::dirent64) };
                let name_bytes = unsafe { std::ffi::CStr::from_ptr(d.d_name.as_ptr()).to_bytes() };
                if let Ok(name_str) = std::str::from_utf8(name_bytes) {
                    if let Ok(fd_num) = name_str.parse::<i32>() {
                        if fd_num >= min_fd && fd_num != dir_fd {
                            unsafe { libc::close(fd_num) };
                        }
                    }
                }
                pos += d.d_reclen as usize;
            }
        }
        unsafe { libc::close(dir_fd) };
        return;
    }

    // 3. Fallback to RLIMIT_NOFILE
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let max_fd = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
        rlim.rlim_cur.min(65536) as i32
    } else {
        4096
    };
    for fd in min_fd..max_fd {
        unsafe { libc::close(fd) };
    }
}

#[cfg(target_os = "linux")]
fn create_control_listener(sock_path: &Path) -> Result<i32> {
    use std::os::unix::ffi::OsStrExt;

    if sock_path.exists() {
        let _ = fs::remove_file(sock_path);
    }

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(TavikError::Io(format!(
            "Failed to create control socket: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = sock_path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(TavikError::Config(format!(
            "Control socket path {:?} exceeds max sockaddr_un length ({})",
            sock_path,
            addr.sun_path.len()
        )));
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(TavikError::Io(format!(
            "Failed to bind control socket at {:?}: {}",
            sock_path, err
        )));
    }

    if unsafe { libc::listen(fd, 8) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(TavikError::Io(format!(
            "Failed to listen on control socket: {}",
            err
        )));
    }

    Ok(fd)
}

#[cfg(target_os = "linux")]
pub fn send_control_command(sock_path: &Path, cmd: &str) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(TavikError::Io(format!(
            "Failed to create socket: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = sock_path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(TavikError::Config(format!(
            "Control socket path {:?} exceeds max sockaddr_un length",
            sock_path
        )));
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    if unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, len) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if err.raw_os_error() == Some(libc::ECONNREFUSED) {
            return Err(TavikError::DaemonUnreachable(format!(
                "Failed to connect to control socket at {:?}: connection refused (supervisor exited or socket is stale)",
                sock_path
            )));
        }
        return Err(TavikError::Io(format!(
            "Failed to connect to control socket at {:?}: {}",
            sock_path, err
        )));
    }

    let msg = format!("{}\n", cmd);
    let mut written = 0;
    while written < msg.len() {
        let n = unsafe {
            libc::write(
                fd,
                msg.as_ptr().add(written) as *const libc::c_void,
                msg.len() - written,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(TavikError::Io(format!(
                "Failed to write to control socket: {}",
                err
            )));
        }
        written += n as usize;
    }

    let mut resp = Vec::new();
    let mut buf = [0u8; 128];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(TavikError::Io(format!(
                "Failed to read from control socket: {}",
                err
            )));
        }
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n as usize]);
        if resp.contains(&b'\n') {
            break;
        }
        if resp.len() > 4096 {
            unsafe { libc::close(fd) };
            return Err(TavikError::Execution(
                "Control socket response exceeded maximum length (4096 bytes)".to_string(),
            ));
        }
    }
    unsafe { libc::close(fd) };

    parse_control_response(&resp)
}

#[cfg(target_os = "linux")]
pub fn parse_control_response(resp: &[u8]) -> Result<String> {
    if resp.is_empty() {
        return Err(TavikError::Execution(
            "Control socket returned empty response (peer closed connection without response)"
                .to_string(),
        ));
    }

    let newline_idx = resp.iter().position(|&b| b == b'\n').ok_or_else(|| {
        TavikError::Execution(format!(
            "Control socket response incomplete (missing newline delimiter): {:?}",
            String::from_utf8_lossy(resp)
        ))
    })?;

    let line = String::from_utf8_lossy(&resp[..newline_idx])
        .trim_end()
        .to_string();

    if line.starts_with("ERR") {
        return Err(TavikError::Execution(format!(
            "Supervisor control error: {}",
            line
        )));
    }

    if line == "OK" || line.starts_with("OK ") {
        return Ok(line);
    }

    Err(TavikError::Execution(format!(
        "Control socket returned malformed response (expected 'OK'): {:?}",
        line
    )))
}

#[cfg(target_os = "linux")]
pub fn read_control_command(client_fd: i32) -> std::io::Result<Option<String>> {
    let mut cmd_buf = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(client_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            if cmd_buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        cmd_buf.extend_from_slice(&buf[..n as usize]);
        if cmd_buf.contains(&b'\n') {
            break;
        }
        if cmd_buf.len() > 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Control command exceeds maximum length (1024 bytes)",
            ));
        }
    }

    if let Some(pos) = cmd_buf.iter().position(|&b| b == b'\n') {
        let cmd = String::from_utf8_lossy(&cmd_buf[..pos]).trim().to_string();
        Ok(Some(cmd))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Control command missing newline delimiter",
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn write_control_response(client_fd: i32, resp: &str) -> std::io::Result<()> {
    let bytes = resp.as_bytes();
    let mut written = 0;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                client_fd,
                bytes.as_ptr().add(written) as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        written += n as usize;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_ready_error_and_exit(ready_fd: i32, msg: &str) -> ! {
    unsafe {
        let _ = libc::write(ready_fd, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::close(ready_fd);
        libc::_exit(1);
    }
}

#[cfg(target_os = "linux")]
fn write_exec_error_and_exit(msg: &str) -> ! {
    unsafe {
        let _ = libc::write(
            EXEC_STATUS_FD,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
        );
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

    // 3. Prepare control socket for supervisor signaling and lifecycle management
    let control_sock_path = container_dir.join("control.sock");
    let control_listener_fd = match create_control_listener(&control_sock_path) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = fs::remove_file(&start_fifo_path);
            let _ = fs::remove_file(&exec_fifo_path);
            return Err(e);
        }
    };

    // 4. Prepare handshake pipe between trampoline caller and supervisor
    let mut trampoline_pipe = [0i32; 2];
    if unsafe { libc::pipe(trampoline_pipe.as_mut_ptr()) } != 0 {
        let _ = fs::remove_file(&start_fifo_path);
        let _ = fs::remove_file(&exec_fifo_path);
        let _ = fs::remove_file(&control_sock_path);
        unsafe { libc::close(control_listener_fd) };
        return Err(TavikError::Io(format!(
            "Failed to create trampoline handshake pipe: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 5. Fork dedicated background supervisor process
    let supervisor_pid = unsafe { libc::fork() };
    if supervisor_pid < 0 {
        let _ = fs::remove_file(&start_fifo_path);
        let _ = fs::remove_file(&exec_fifo_path);
        let _ = fs::remove_file(&control_sock_path);
        unsafe {
            libc::close(control_listener_fd);
            libc::close(trampoline_pipe[0]);
            libc::close(trampoline_pipe[1]);
        };
        return Err(TavikError::Io(format!(
            "Failed to fork supervisor process: {}",
            std::io::Error::last_os_error()
        )));
    }

    if supervisor_pid > 0 {
        // --- TRAMPOLINE CALLER PROCESS ---
        unsafe {
            libc::close(control_listener_fd);
            libc::close(trampoline_pipe[1]);
        };

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

    let sup_pid = unsafe { libc::getpid() as u32 };
    let sup_identity = match crate::ProcessIdentity::from_pid(sup_pid) {
        Ok(ident) => {
            if let Err(e) = ident.save_to(&container_dir.join("supervisor.identity")) {
                let msg = format!("Failed to save supervisor identity: {}", e);
                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                unsafe {
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                    libc::_exit(1);
                };
            }
            ident
        }
        Err(e) => {
            let msg = format!(
                "Failed to capture supervisor identity for PID {}: {}",
                sup_pid, e
            );
            let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
            unsafe {
                libc::close(control_listener_fd);
                let _ = fs::remove_file(&control_sock_path);
                libc::_exit(1);
            };
        }
    };

    // 6. Initialize cgroups v2 resource limits with fail-closed RAII cleanup guard
    let cgroup_guard = if let Some(linux) = &spec.linux {
        if linux.resources.is_some() {
            let mgr = match tavik_cgroups::CgroupManager::new() {
                Ok(m) => m,
                Err(e) => {
                    let msg = format!("Failed to initialize cgroups v2 manager: {}", e);
                    let _ =
                        unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                    unsafe {
                        libc::close(control_listener_fd);
                        let _ = fs::remove_file(&control_sock_path);
                        libc::_exit(1);
                    };
                }
            };
            if let Err(e) = mgr.validate_cgroup_v2() {
                let msg = format!("Requested resources require cgroup v2: {}", e);
                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                unsafe {
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                    libc::_exit(1);
                };
            }
            // Persist cgroup ownership intent BEFORE creating the cgroup
            let cgroup_owner_file = container_dir.join("cgroup.owner");
            if let Err(e) = fs::write(&cgroup_owner_file, b"1\n") {
                let msg = format!(
                    "Failed to record cgroup ownership intent for container '{}': {}",
                    id, e
                );
                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                unsafe {
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                    libc::_exit(1);
                };
            }
            let mut init_state = state.clone();
            init_state
                .annotations
                .insert("io.tavik.cgroup.owned".to_string(), "true".to_string());
            let json = match serde_json::to_string_pretty(&init_state) {
                Ok(j) => j,
                Err(e) => {
                    let msg = format!(
                        "Failed to serialize cgroup ownership state for container '{}': {}",
                        id, e
                    );
                    let _ =
                        unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                    let _ = fs::remove_file(&cgroup_owner_file);
                    unsafe {
                        libc::close(control_listener_fd);
                        let _ = fs::remove_file(&control_sock_path);
                        libc::_exit(1);
                    };
                }
            };
            let tmp = container_dir.join("state.json.tmp");
            if let Err(e) = fs::write(&tmp, json).and_then(|_| fs::rename(&tmp, &state_file)) {
                let msg = format!(
                    "Failed to persist cgroup ownership state for container '{}': {}",
                    id, e
                );
                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                let _ = fs::remove_file(&cgroup_owner_file);
                unsafe {
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                    libc::_exit(1);
                };
            }

            if let Err(e) = mgr.create_container_cgroup(id) {
                let mut cleanup_err_msg = None;
                match mgr.destroy_container_cgroup(id) {
                    Ok(()) => {
                        if let Err(remove_err) = fs::remove_file(&cgroup_owner_file) {
                            if remove_err.kind() != std::io::ErrorKind::NotFound {
                                cleanup_err_msg = Some(format!(
                                    "failed to remove cgroup.owner marker: {}",
                                    remove_err
                                ));
                            }
                        }
                    }
                    Err(destroy_err) => {
                        cleanup_err_msg =
                            Some(format!("failed to clean up cgroup: {}", destroy_err));
                    }
                }

                let msg = if let Some(c_err) = cleanup_err_msg {
                    format!(
                        "Failed to create cgroup for container '{}': {}; additionally {}",
                        id, e, c_err
                    )
                } else {
                    format!("Failed to create cgroup for container '{}': {}", id, e)
                };

                let _ = unsafe { libc::write(trampoline_pipe[1], msg.as_ptr() as _, msg.len()) };
                unsafe {
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                    libc::_exit(1);
                };
            }

            let mut guard = CgroupGuard::new(mgr, id.to_string());
            let simulate_apply_fail = container_dir
                .join(".simulate_apply_resources_fail")
                .exists();
            let apply_res = if simulate_apply_fail {
                Err(TavikError::Execution(
                    "Simulated resource application failure".to_string(),
                ))
            } else if let Some(resources) = &linux.resources {
                guard.manager().apply_resources(id, resources)
            } else {
                Ok(())
            };

            if let Err(e) = apply_res {
                let msg = format!("Failed to apply cgroup resources: {}", e);
                let mut full_msg = msg;
                if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                    full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
                }
                let _ = unsafe {
                    libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len())
                };
                unsafe {
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                    libc::_exit(1);
                };
            }
            Some(guard)
        } else {
            None
        }
    } else {
        None
    };

    // 7. Unshare PID namespace
    let simulate_unshare_fail = container_dir.join(".simulate_unshare_fail").exists();
    if simulate_unshare_fail || unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        let msg = format!(
            "Failed to unshare PID namespace in supervisor: {}",
            std::io::Error::last_os_error()
        );
        let mut full_msg = msg;
        if let Some(mut guard) = cgroup_guard {
            if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
            }
        }
        let _ = unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
        unsafe {
            libc::close(control_listener_fd);
            let _ = fs::remove_file(&control_sock_path);
            libc::_exit(1);
        };
    }

    // 8. Prepare ready pipe for synchronous handshake between child init and supervisor
    let mut ready_pipe = [0i32; 2];
    if unsafe { libc::pipe(ready_pipe.as_mut_ptr()) } != 0 {
        let msg = format!(
            "Failed to create ready pipe: {}",
            std::io::Error::last_os_error()
        );
        let mut full_msg = msg;
        if let Some(mut guard) = cgroup_guard {
            if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
            }
        }
        let _ = unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
        unsafe {
            libc::close(control_listener_fd);
            let _ = fs::remove_file(&control_sock_path);
            libc::_exit(1);
        };
    }

    // 9. Fork container init process (this child is PID 1 in the new PID namespace!)
    let simulate_child_setup_fail = container_dir.join(".simulate_child_setup_fail").exists();
    let child_pid = if simulate_child_setup_fail {
        -1
    } else {
        unsafe { libc::fork() }
    };
    if child_pid < 0 {
        let msg = format!(
            "Failed to fork container init child: {}",
            std::io::Error::last_os_error()
        );
        let mut full_msg = msg;
        if let Some(mut guard) = cgroup_guard {
            if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
            }
        }
        let _ = unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
        unsafe {
            libc::close(control_listener_fd);
            let _ = fs::remove_file(&control_sock_path);
            libc::_exit(1);
        };
    }

    if child_pid == 0 {
        // --- CONTAINER INIT CHILD PROCESS (PID 1 in new PID namespace) ---
        unsafe {
            libc::close(control_listener_fd);
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

    // Acquire pidfd immediately while supervisor is guaranteed to own the child
    let child_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) as i32 };
    let init_identity = match crate::ProcessIdentity::from_pid(child_pid as u32) {
        Ok(ident) => {
            if let Err(e) = ident.save_to(&container_dir.join("container.identity")) {
                let msg = format!("Failed to persist container init identity: {}", e);
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(child_pid, &mut status, 0);
                    if child_pidfd >= 0 {
                        libc::close(child_pidfd);
                    }
                    libc::close(control_listener_fd);
                    let _ = fs::remove_file(&control_sock_path);
                }
                let mut full_msg = msg;
                if let Some(mut guard) = cgroup_guard {
                    if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                        full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
                    }
                }
                let _ = unsafe {
                    libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len())
                };
                unsafe { libc::_exit(1) };
            }
            ident
        }
        Err(e) => {
            let msg = format!(
                "Failed to capture container init identity for child PID {}: {}",
                child_pid, e
            );
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(child_pid, &mut status, 0);
                if child_pidfd >= 0 {
                    libc::close(child_pidfd);
                }
                libc::close(control_listener_fd);
                let _ = fs::remove_file(&control_sock_path);
            }
            let mut full_msg = msg;
            if let Some(mut guard) = cgroup_guard {
                if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                    full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
                }
            }
            let _ =
                unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
            unsafe { libc::_exit(1) };
        }
    };
    if child_pidfd < 0 {
        let msg = format!(
            "Failed to acquire pidfd for child PID {}: {}",
            child_pid,
            std::io::Error::last_os_error()
        );
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(child_pid, &mut status, 0);
            libc::close(control_listener_fd);
            let _ = fs::remove_file(&control_sock_path);
        }
        let _ = fs::remove_file(container_dir.join("container.identity"));
        let mut full_msg = msg;
        if let Some(mut guard) = cgroup_guard {
            if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
            }
        }
        let _ = unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
        unsafe { libc::_exit(1) };
    }

    // 10. Enroll child PID into cgroups v2 container group (FAIL-CLOSED)
    let simulate_enroll_fail = container_dir.join(".simulate_enroll_fail").exists();
    if let Some(guard) = &cgroup_guard {
        let enroll_res = if simulate_enroll_fail {
            Err(TavikError::Execution(
                "Simulated cgroup enrollment failure".to_string(),
            ))
        } else {
            guard.manager().add_process(id, child_pid as u32)
        };
        if let Err(e) = enroll_res {
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(child_pid, &mut status, 0);
                libc::close(child_pidfd);
                libc::close(control_listener_fd);
                let _ = fs::remove_file(&control_sock_path);
            }
            let msg = format!("Failed to enroll child PID {} in cgroup: {}", child_pid, e);
            let mut full_msg = msg;
            if let Some(mut g) = cgroup_guard {
                if let Err(cleanup_err) = g.cleanup(&container_dir) {
                    full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
                }
            }
            let _ =
                unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
            unsafe { libc::_exit(1) };
        }
    }

    // 11. Wait for child init process to signal readiness over pipe
    let mut buf = [0u8; 512];
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
            libc::close(child_pidfd);
            libc::close(control_listener_fd);
            let _ = fs::remove_file(&control_sock_path);
        }
        let err_msg = if n > 0 {
            format!(
                "Container init child setup failed: {}",
                String::from_utf8_lossy(&buf[..n as usize])
            )
        } else {
            "Container init child exited prematurely without signaling readiness".to_string()
        };
        let mut full_msg = err_msg;
        if let Some(mut guard) = cgroup_guard {
            if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
            }
        }
        let _ = unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
        unsafe { libc::_exit(1) };
    }

    let owns_cgroup = cgroup_guard.is_some();

    // 12. Record host PID and persist state as Created (FAIL-CLOSED)
    let simulate_persist_fail = container_dir.join(".simulate_state_persist_fail").exists();
    let pid_write_res = fs::write(&pid_file, child_pid.to_string());
    let state_write_res = (|| -> Result<()> {
        if simulate_persist_fail {
            return Err(TavikError::Io(
                "Simulated state persistence failure".to_string(),
            ));
        }
        pid_write_res.map_err(|e| TavikError::Io(format!("Failed to write pid file: {}", e)))?;
        let lock_path = container_dir.join("state.lock");
        let _lock = crate::executor::StateLock::acquire(&lock_path)?;
        let mut updated_state = state;
        updated_state.status = ContainerStatus::Created;
        updated_state.pid = Some(child_pid as u32);
        updated_state.annotations.insert(
            "io.tavik.init.start_time".to_string(),
            init_identity.start_time.to_string(),
        );
        updated_state.annotations.insert(
            "io.tavik.supervisor.pid".to_string(),
            sup_identity.pid.to_string(),
        );
        updated_state.annotations.insert(
            "io.tavik.supervisor.start_time".to_string(),
            sup_identity.start_time.to_string(),
        );
        if owns_cgroup {
            updated_state
                .annotations
                .insert("io.tavik.cgroup.owned".to_string(), "true".to_string());
            let cgroup_owner_file = container_dir.join("cgroup.owner");
            fs::write(&cgroup_owner_file, b"1\n")?;
        }
        let tmp_file = container_dir.join("state.json.tmp");
        let json = serde_json::to_string_pretty(&updated_state)?;
        fs::write(&tmp_file, json)?;
        fs::rename(&tmp_file, &state_file)?;
        Ok(())
    })();

    if let Err(e) = state_write_res {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(child_pid, &mut status, 0);
            libc::close(child_pidfd);
            libc::close(control_listener_fd);
            let _ = fs::remove_file(&control_sock_path);
        }
        let msg = format!("Failed to persist Created container state: {}", e);
        let mut full_msg = msg;
        if let Some(mut guard) = cgroup_guard {
            if let Err(cleanup_err) = guard.cleanup(&container_dir) {
                full_msg = format!("{}; furthermore, {}", full_msg, cleanup_err);
            }
        }
        let _ = unsafe { libc::write(trampoline_pipe[1], full_msg.as_ptr() as _, full_msg.len()) };
        unsafe { libc::_exit(1) };
    }

    // Ownership of cgroup transferred to running container lifecycle; disarm guard
    if let Some(mut guard) = cgroup_guard {
        guard.disarm();
    }

    // Signal successful creation to trampoline caller
    let _ = unsafe { libc::write(trampoline_pipe[1], b"ok\n".as_ptr() as _, 3) };
    unsafe { libc::close(trampoline_pipe[1]) };

    // --- SUPERVISORY LOOP ---
    supervise_container_process(
        id,
        child_pid,
        child_pidfd,
        &container_dir,
        owns_cgroup,
        control_listener_fd,
    );
}

#[cfg(target_os = "linux")]
pub fn terminate_child_with_escalation(
    child_pid: i32,
    child_pidfd: i32,
    sig: i32,
    timeout: std::time::Duration,
    child_reaped: &mut bool,
) -> std::result::Result<(), String> {
    // 1. Send signal
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            child_pidfd,
            sig,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Treat ESRCH as already terminated only after confirming process state with waitpid(WNOHANG)
            let mut status = 0;
            let wres = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
            if wres == child_pid
                || (wres < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                *child_reaped = true;
                return Ok(());
            } else {
                return Err(format!(
                    "pidfd_send_signal returned ESRCH but waitpid(WNOHANG) could not confirm termination of PID {}: {}",
                    child_pid, err
                ));
            }
        } else {
            return Err(format!(
                "Failed to send signal {} to child PID {}: {}",
                sig, child_pid, err
            ));
        }
    }

    // 2. Poll child_pidfd for termination within timeout
    let mut pfd = libc::pollfd {
        fd: child_pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let start_time = std::time::Instant::now();
    let mut terminated = false;

    while start_time.elapsed() < timeout {
        let rem_ms = (timeout.saturating_sub(start_time.elapsed()).as_millis() as i32).max(1);
        let pret = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
        if pret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // Retry poll on EINTR
            }
            return Err(format!(
                "Poll failed on child pidfd during signal escalation: {}",
                err
            ));
        }
        if pret == 0 {
            break; // Timeout expired
        }
        if (pfd.revents & libc::POLLIN) != 0 {
            terminated = true;
            break;
        }
    }

    // 3. Escalate to SIGKILL if not terminated within timeout
    if !terminated {
        let kret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                child_pidfd,
                libc::SIGKILL,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        };
        if kret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                let mut status = 0;
                let wres = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                if wres == child_pid
                    || (wres < 0
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
                {
                    *child_reaped = true;
                    return Ok(());
                }
            }
            // Do not block indefinitely after unsuccessful SIGKILL delivery
            return Err(format!(
                "Failed to send SIGKILL to child PID {}: {}",
                child_pid, err
            ));
        }

        let kill_start = std::time::Instant::now();
        let kill_timeout = std::time::Duration::from_secs(2);
        let mut kill_terminated = false;

        while kill_start.elapsed() < kill_timeout {
            let rem_ms = (kill_timeout
                .saturating_sub(kill_start.elapsed())
                .as_millis() as i32)
                .max(1);
            let pret = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
            if pret < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue; // Retry poll on EINTR
                }
                return Err(format!("Poll failed on child pidfd after SIGKILL: {}", err));
            }
            if pret == 0 {
                break;
            }
            if (pfd.revents & libc::POLLIN) != 0 {
                kill_terminated = true;
                break;
            }
        }

        if !kill_terminated {
            return Err(format!(
                "Child PID {} failed to terminate within 2s after SIGKILL",
                child_pid
            ));
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run_supervisor_finalization(
    id: &str,
    child_pid: i32,
    container_dir: &Path,
    owns_cgroup: bool,
    start_fifo_path: &Path,
    exec_fifo_path: &Path,
    child_reaped: bool,
) -> std::result::Result<(), String> {
    let state_file = container_dir.join("state.json");
    let lock_path = container_dir.join("state.lock");

    // 1. Mark state as CleanupPending under StateLock so incomplete cleanup is observable
    {
        if container_dir
            .join(".simulate_cleanup_pending_fail")
            .exists()
        {
            return Err("Simulated CleanupPending persistence failure".to_string());
        }

        let _lock = crate::executor::StateLock::acquire(&lock_path)
            .map_err(|e| format!("Failed to acquire state lock for CleanupPending: {}", e))?;

        if !state_file.exists() {
            return Err(format!(
                "Cannot persist CleanupPending: state file {:?} does not exist",
                state_file
            ));
        }

        let content = fs::read_to_string(&state_file)
            .map_err(|e| format!("Failed to read state file for CleanupPending: {}", e))?;

        let mut st = serde_json::from_str::<ContainerState>(&content)
            .map_err(|e| format!("Failed to parse state JSON for CleanupPending: {}", e))?;

        if st.status != ContainerStatus::Stopped {
            st.status = ContainerStatus::CleanupPending;
            let tmp = container_dir.join("state.json.tmp");
            let json = serde_json::to_string_pretty(&st)
                .map_err(|e| format!("Failed to serialize CleanupPending state: {}", e))?;

            fs::write(&tmp, json)
                .map_err(|e| format!("Failed to write tmp state file for CleanupPending: {}", e))?;

            fs::rename(&tmp, &state_file)
                .map_err(|e| format!("Failed to replace state file for CleanupPending: {}", e))?;
        }
    }

    // 2. Enforce child reaping via waitpid
    if !child_reaped {
        let mut status = 0;
        loop {
            let res = unsafe { libc::waitpid(child_pid, &mut status, 0) };
            if res < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!(
                    "Supervisor failed to reap child PID {}: {}",
                    child_pid, err
                ));
            }
            if res == child_pid {
                break;
            } else {
                return Err(format!(
                    "waitpid returned unexpected PID {} (expected {})",
                    res, child_pid
                ));
            }
        }
    }

    // 3. Destroy container cgroup if owned by this supervisor
    if owns_cgroup {
        if container_dir.join(".simulate_cgroup_destroy_fail").exists() {
            return Err("Simulated cgroup destruction failure".to_string());
        }

        let mgr = tavik_cgroups::CgroupManager::new()
            .map_err(|e| format!("Failed to initialize cgroup manager: {}", e))?;
        mgr.destroy_container_cgroup(id)
            .map_err(|e| format!("Failed to destroy cgroup for container '{}': {}", id, e))?;
        let owner_path = container_dir.join("cgroup.owner");
        if owner_path.exists() {
            if let Err(e) = fs::remove_file(&owner_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(format!(
                        "Failed to remove cgroup.owner marker for container '{}': {}",
                        id, e
                    ));
                }
            }
        }
    }

    // 4. Remove FIFO files
    if start_fifo_path.exists() {
        if let Err(e) = fs::remove_file(start_fifo_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(format!(
                    "Failed to remove start FIFO at {:?}: {}",
                    start_fifo_path, e
                ));
            }
        }
    }
    if exec_fifo_path.exists() {
        if let Err(e) = fs::remove_file(exec_fifo_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(format!(
                    "Failed to remove exec FIFO at {:?}: {}",
                    exec_fifo_path, e
                ));
            }
        }
    }

    // 5. Check simulated state persistence failure
    if container_dir.join(".simulate_state_persist_fail").exists() {
        return Err("Simulated state persistence failure".to_string());
    }

    // 6. Persist final Stopped state to state.json under StateLock only after all cleanup succeeds
    {
        let _lock = crate::executor::StateLock::acquire(&lock_path)
            .map_err(|e| format!("Failed to acquire state lock: {}", e))?;

        let content = fs::read_to_string(&state_file)
            .map_err(|e| format!("Failed to read state file: {}", e))?;

        let mut st = serde_json::from_str::<ContainerState>(&content)
            .map_err(|e| format!("Failed to parse state JSON: {}", e))?;

        st.status = ContainerStatus::Stopped;
        let tmp_file = container_dir.join("state.json.tmp");
        let json = serde_json::to_string_pretty(&st)
            .map_err(|e| format!("Failed to serialize state JSON: {}", e))?;

        fs::write(&tmp_file, json).map_err(|e| format!("Failed to write tmp state file: {}", e))?;

        fs::rename(&tmp_file, &state_file)
            .map_err(|e| format!("Failed to replace state file: {}", e))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn finalize_supervisor(
    id: &str,
    child_pid: i32,
    child_pidfd: i32,
    control_listener_fd: i32,
    container_dir: &Path,
    owns_cgroup: bool,
    start_fifo_path: &Path,
    exec_fifo_path: &Path,
    control_sock_path: &Path,
    child_reaped: bool,
    client_fd: Option<i32>,
) -> ! {
    match run_supervisor_finalization(
        id,
        child_pid,
        container_dir,
        owns_cgroup,
        start_fifo_path,
        exec_fifo_path,
        child_reaped,
    ) {
        Ok(()) => {
            if let Some(cfd) = client_fd {
                let _ = write_control_response(cfd, "OK\n");
                unsafe { libc::close(cfd) };
            }
            unsafe {
                libc::close(child_pidfd);
                libc::close(control_listener_fd);
            }
            let _ = fs::remove_file(container_dir.join("supervisor.identity"));
            let _ = fs::remove_file(container_dir.join("container.identity"));
            let _ = fs::remove_file(control_sock_path);
            unsafe { libc::_exit(0) };
        }
        Err(err_msg) => {
            eprintln!(
                "CRITICAL: Supervisor finalization failed for container '{}': {}",
                id, err_msg
            );
            if let Some(cfd) = client_fd {
                let resp = format!("ERR {}\n", err_msg);
                let _ = write_control_response(cfd, &resp);
                unsafe { libc::close(cfd) };
            }
            unsafe {
                libc::close(child_pidfd);
                libc::close(control_listener_fd);
                libc::_exit(1);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn supervise_container_process(
    id: &str,
    child_pid: i32,
    child_pidfd: i32,
    container_dir: &Path,
    owns_cgroup: bool,
    control_listener_fd: i32,
) -> ! {
    let start_fifo_path = container_dir.join("start.fifo");
    let exec_fifo_path = container_dir.join("exec.fifo");
    let control_sock_path = container_dir.join("control.sock");

    loop {
        let mut pfds = [
            libc::pollfd {
                fd: control_listener_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: child_pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let poll_ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            eprintln!("Supervisor poll error on control and pidfd: {}", err);
            break;
        }

        // 1. Check for incoming control command
        if (pfds[0].revents & libc::POLLIN) != 0 {
            let client_fd = unsafe {
                libc::accept4(
                    control_listener_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if client_fd >= 0 {
                match read_control_command(client_fd) {
                    Ok(Some(cmd_str)) => {
                        if cmd_str.starts_with("KILL ") {
                            let sig_str = cmd_str.trim_start_matches("KILL ").trim();
                            if let Ok(sig) = sig_str.parse::<i32>() {
                                let ret = unsafe {
                                    libc::syscall(
                                        libc::SYS_pidfd_send_signal,
                                        child_pidfd,
                                        sig,
                                        std::ptr::null::<libc::c_void>(),
                                        0,
                                    )
                                };
                                if ret == 0 {
                                    let _ = write_control_response(client_fd, "OK\n");
                                } else {
                                    let err = std::io::Error::last_os_error();
                                    if err.raw_os_error() == Some(libc::ESRCH) {
                                        let mut status = 0;
                                        let wres = unsafe {
                                            libc::waitpid(child_pid, &mut status, libc::WNOHANG)
                                        };
                                        if wres == child_pid
                                            || (wres < 0
                                                && std::io::Error::last_os_error().raw_os_error()
                                                    == Some(libc::ECHILD))
                                        {
                                            let _ = write_control_response(client_fd, "OK\n");
                                        } else {
                                            let err_msg = format!(
                                                "ERR ESRCH but child PID {} not reaped\n",
                                                child_pid
                                            );
                                            let _ = write_control_response(client_fd, &err_msg);
                                        }
                                    } else {
                                        let err_msg = format!("ERR {}\n", err);
                                        let _ = write_control_response(client_fd, &err_msg);
                                    }
                                }
                            } else {
                                let _ = write_control_response(
                                    client_fd,
                                    "ERR Invalid signal number\n",
                                );
                            }
                            unsafe { libc::close(client_fd) };
                        } else if cmd_str.starts_with("STOP ") {
                            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
                            let sig = parts
                                .get(1)
                                .and_then(|s| s.parse::<i32>().ok())
                                .unwrap_or(libc::SIGTERM);
                            let timeout_ms = parts
                                .get(2)
                                .and_then(|s| s.parse::<i32>().ok())
                                .unwrap_or(10000);
                            let timeout = std::time::Duration::from_millis(timeout_ms as u64);

                            let mut child_reaped = false;
                            match terminate_child_with_escalation(
                                child_pid,
                                child_pidfd,
                                sig,
                                timeout,
                                &mut child_reaped,
                            ) {
                                Ok(()) => {
                                    finalize_supervisor(
                                        id,
                                        child_pid,
                                        child_pidfd,
                                        control_listener_fd,
                                        container_dir,
                                        owns_cgroup,
                                        &start_fifo_path,
                                        &exec_fifo_path,
                                        &control_sock_path,
                                        child_reaped,
                                        Some(client_fd),
                                    );
                                }
                                Err(e) => {
                                    let err_msg = format!("ERR {}\n", e);
                                    let _ = write_control_response(client_fd, &err_msg);
                                    unsafe { libc::close(client_fd) };
                                }
                            }
                        } else if cmd_str == "CANCEL" {
                            let mut child_reaped = false;
                            match terminate_child_with_escalation(
                                child_pid,
                                child_pidfd,
                                libc::SIGKILL,
                                std::time::Duration::from_millis(50),
                                &mut child_reaped,
                            ) {
                                Ok(()) => {
                                    finalize_supervisor(
                                        id,
                                        child_pid,
                                        child_pidfd,
                                        control_listener_fd,
                                        container_dir,
                                        owns_cgroup,
                                        &start_fifo_path,
                                        &exec_fifo_path,
                                        &control_sock_path,
                                        child_reaped,
                                        Some(client_fd),
                                    );
                                }
                                Err(e) => {
                                    let err_msg = format!("ERR {}\n", e);
                                    let _ = write_control_response(client_fd, &err_msg);
                                    unsafe { libc::close(client_fd) };
                                }
                            }
                        } else {
                            let err_msg = format!("ERR Unknown control command: {}\n", cmd_str);
                            let _ = write_control_response(client_fd, &err_msg);
                            unsafe { libc::close(client_fd) };
                        }
                    }
                    Ok(None) => {
                        unsafe { libc::close(client_fd) };
                    }
                    Err(e) => {
                        let err_msg = format!("ERR Malformed command: {}\n", e);
                        let _ = write_control_response(client_fd, &err_msg);
                        unsafe { libc::close(client_fd) };
                    }
                }
            }
        }

        // 2. Check for child termination
        if (pfds[1].revents & libc::POLLIN) != 0 {
            finalize_supervisor(
                id,
                child_pid,
                child_pidfd,
                control_listener_fd,
                container_dir,
                owns_cgroup,
                &start_fifo_path,
                &exec_fifo_path,
                &control_sock_path,
                false,
                None,
            );
        }
    }

    // In case supervisor event loop breaks unexpectedly, run finalization
    finalize_supervisor(
        id,
        child_pid,
        child_pidfd,
        control_listener_fd,
        container_dir,
        owns_cgroup,
        &start_fifo_path,
        &exec_fifo_path,
        &control_sock_path,
        false,
        None,
    );
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

    // Relocate ready_pipe_write_fd to descriptor >= 10 with FD_CLOEXEC
    let safe_ready_fd = unsafe { libc::fcntl(ready_pipe_write_fd, libc::F_DUPFD_CLOEXEC, 10) };
    if safe_ready_fd < 0 {
        eprintln!("Failed to relocate ready pipe fd");
        unsafe { libc::_exit(1) };
    }
    if safe_ready_fd != ready_pipe_write_fd {
        unsafe {
            libc::close(ready_pipe_write_fd);
        }
    }

    // 1. Open start FIFO with O_RDWR before pivot_root so open does not block
    let c_start_fifo = match CString::new(start_fifo_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => write_ready_error_and_exit(safe_ready_fd, "Invalid start FIFO path"),
    };
    let raw_start_fd = unsafe { libc::open(c_start_fifo.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw_start_fd < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to open start FIFO: {}", err),
        );
    }
    let safe_start_fd = unsafe { libc::fcntl(raw_start_fd, libc::F_DUPFD_CLOEXEC, 10) };
    if safe_start_fd < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to relocate start FIFO fd: {}", err),
        );
    }
    if safe_start_fd != raw_start_fd {
        unsafe {
            libc::close(raw_start_fd);
        }
    }

    // 2. Open exec FIFO with O_RDWR
    let c_exec_fifo = match CString::new(exec_fifo_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => write_ready_error_and_exit(safe_ready_fd, "Invalid exec FIFO path"),
    };
    let raw_exec_fd = unsafe { libc::open(c_exec_fifo.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw_exec_fd < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(safe_ready_fd, &format!("Failed to open exec FIFO: {}", err));
    }
    let safe_exec_fd = unsafe { libc::fcntl(raw_exec_fd, libc::F_DUPFD_CLOEXEC, 10) };
    if safe_exec_fd < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to relocate exec FIFO fd: {}", err),
        );
    }
    if safe_exec_fd != raw_exec_fd {
        unsafe {
            libc::close(raw_exec_fd);
        }
    }

    // Assign dedicated descriptors START_FIFO_FD (3) and EXEC_STATUS_FD (4)
    if unsafe { libc::dup2(safe_start_fd, START_FIFO_FD) } < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to dup2 start FIFO to fd {}: {}", START_FIFO_FD, err),
        );
    }
    unsafe {
        libc::close(safe_start_fd);
    }
    if unsafe { libc::fcntl(START_FIFO_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to set FD_CLOEXEC on start FIFO: {}", err),
        );
    }

    if unsafe { libc::dup2(safe_exec_fd, EXEC_STATUS_FD) } < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to dup2 exec FIFO to fd {}: {}", EXEC_STATUS_FD, err),
        );
    }
    unsafe {
        libc::close(safe_exec_fd);
    }
    if unsafe { libc::fcntl(EXEC_STATUS_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let err = std::io::Error::last_os_error();
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!("Failed to set FD_CLOEXEC on exec FIFO: {}", err),
        );
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
        write_ready_error_and_exit(
            safe_ready_fd,
            &format!(
                "Failed to unshare container namespaces: {}",
                std::io::Error::last_os_error()
            ),
        );
    }

    // 4. Set Hostname
    if let Some(hostname) = &spec.hostname {
        let c_host = match CString::new(hostname.as_str()) {
            Ok(c) => c,
            Err(_) => write_ready_error_and_exit(safe_ready_fd, "Invalid hostname"),
        };
        unsafe {
            if libc::sethostname(c_host.as_ptr(), hostname.len()) != 0 {
                write_ready_error_and_exit(
                    safe_ready_fd,
                    &format!("Failed to sethostname: {}", std::io::Error::last_os_error()),
                );
            }
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
            write_ready_error_and_exit(
                safe_ready_fd,
                &format!(
                    "Failed to make mount namespace private: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }
    }

    // 6. Resolve rootfs and bind mount it to itself
    let root = match &spec.root {
        Some(r) => r,
        None => write_ready_error_and_exit(safe_ready_fd, "Spec missing rootfs definition"),
    };
    let rootfs_path = if Path::new(&root.path).is_absolute() {
        PathBuf::from(&root.path)
    } else {
        bundle.join(&root.path)
    };

    let c_rootfs = match CString::new(rootfs_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => write_ready_error_and_exit(safe_ready_fd, "Invalid rootfs path"),
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
            write_ready_error_and_exit(
                safe_ready_fd,
                &format!(
                    "Failed to bind mount rootfs to itself: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }
    }

    // Mount proc inside container rootfs
    let proc_target = rootfs_path.join("proc");
    let _ = fs::create_dir_all(&proc_target);
    let c_proc_target = match CString::new(proc_target.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => write_ready_error_and_exit(safe_ready_fd, "Invalid proc target path"),
    };
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
            write_ready_error_and_exit(
                safe_ready_fd,
                &format!(
                    "Failed to mount /proc inside container rootfs: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }
    }

    // pivot_root
    let old_root_rel = ".pivot_root";
    let old_root_path = rootfs_path.join(old_root_rel);
    let _ = fs::create_dir_all(&old_root_path);
    let c_old_root = match CString::new(old_root_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => write_ready_error_and_exit(safe_ready_fd, "Invalid old root path"),
    };

    unsafe {
        let ret = libc::syscall(libc::SYS_pivot_root, c_rootfs.as_ptr(), c_old_root.as_ptr());
        if ret != 0 {
            write_ready_error_and_exit(
                safe_ready_fd,
                &format!("pivot_root failed: {}", std::io::Error::last_os_error()),
            );
        }

        // Chdir to new root
        if libc::chdir(slash.as_ptr()) != 0 {
            write_ready_error_and_exit(
                safe_ready_fd,
                &format!(
                    "chdir to new root failed: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }

        // Unmount old root
        let old_root_unmount = CString::new(format!("/{}", old_root_rel)).unwrap();
        if libc::umount2(old_root_unmount.as_ptr(), libc::MNT_DETACH) != 0 {
            write_ready_error_and_exit(
                safe_ready_fd,
                &format!(
                    "umount2 old root failed: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }
        let _ = libc::rmdir(old_root_unmount.as_ptr());
    }

    let proc = match &spec.process {
        Some(p) => p,
        None => write_ready_error_and_exit(safe_ready_fd, "Spec missing process definition"),
    };

    // 7. Signal readiness to supervisor
    unsafe {
        libc::write(safe_ready_fd, b"ready\n".as_ptr() as *const libc::c_void, 6);
        libc::close(safe_ready_fd);
    }

    // 8. Block waiting for start signal on START_FIFO_FD (fd 3)
    let mut start_buf = [0u8; 1];
    let n = unsafe {
        libc::read(
            START_FIFO_FD,
            start_buf.as_mut_ptr() as *mut libc::c_void,
            1,
        )
    };
    unsafe {
        libc::close(START_FIFO_FD);
    }

    if n <= 0 {
        write_exec_error_and_exit("Start FIFO closed without receiving start signal");
    }

    // --- CONTAINER START LIFECYCLE: Strict Security Enforcement ---
    // 9. File descriptor sanitization: close all fds >= 5 (preserving stdin 0, stdout 1, stderr 2, fd 3 closed, EXEC_STATUS_FD 4)
    close_inherited_descriptors_above(5);

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
