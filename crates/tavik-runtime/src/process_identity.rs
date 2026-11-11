use std::fs;
use std::path::Path;
use tavik_common::error::{Result, TavikError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

#[cfg(target_os = "linux")]
fn get_process_stat_linux(pid: u32) -> Result<(char, u64)> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&stat_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            TavikError::NotFound(format!("Process {} not found in procfs: {}", pid, e))
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            TavikError::Execution(format!(
                "Permission denied reading /proc/{}/stat: {}",
                pid, e
            ))
        } else {
            TavikError::Io(format!("Failed to read {}: {}", stat_path, e))
        }
    })?;

    let rparen = content.rfind(')').ok_or_else(|| {
        TavikError::Execution(format!(
            "Malformed /proc/{}/stat: missing closing paren",
            pid
        ))
    })?;

    let rest = content[rparen + 1..].trim_start();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        return Err(TavikError::Execution(format!(
            "Malformed /proc/{}/stat: expected >= 20 fields after comm, found {}",
            pid,
            fields.len()
        )));
    }

    let state_char = fields[0].chars().next().unwrap_or('?');
    let start_time: u64 = fields[19].parse().map_err(|e| {
        TavikError::Execution(format!(
            "Failed to parse starttime for process {} ('{}'): {}",
            pid, fields[19], e
        ))
    })?;

    Ok((state_char, start_time))
}

impl ProcessIdentity {
    pub fn new(pid: u32, start_time: u64) -> Self {
        Self { pid, start_time }
    }

    pub fn from_pid(pid: u32) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let (_state, start_time) = get_process_stat_linux(pid)?;
            Ok(Self { pid, start_time })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
            if res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    return Err(TavikError::NotFound(format!("Process {} not found", pid)));
                } else if err.raw_os_error() == Some(libc::EPERM) {
                    return Err(TavikError::Execution(format!(
                        "Permission denied checking process {}",
                        pid
                    )));
                }
            }
            Ok(Self { pid, start_time: 1 })
        }
    }

    /// Checks whether the exact original process is still alive.
    /// Returns:
    /// - Ok(true): Original process is alive (start time matches, not zombie)
    /// - Ok(false): Process does not exist or PID has been reused
    /// - Err(e): Verification failed due to permission or procfs error (fail-closed)
    pub fn is_alive(&self) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            match get_process_stat_linux(self.pid) {
                Ok((state, start_time)) => {
                    if start_time != self.start_time {
                        // PID reuse: original process has terminated
                        Ok(false)
                    } else if state == 'Z' || state == 'X' {
                        // Zombie / Dead: process has terminated
                        Ok(false)
                    } else {
                        // Exactly our original process is still running
                        Ok(true)
                    }
                }
                Err(TavikError::NotFound(_)) => Ok(false),
                Err(e) => Err(e),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut status = 0;
            let wait_res =
                unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if wait_res == self.pid as libc::pid_t {
                return Ok(false);
            }
            let res = unsafe { libc::kill(self.pid as libc::pid_t, 0) };
            if res == 0 {
                Ok(true)
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    Ok(false)
                } else if err.raw_os_error() == Some(libc::EPERM) {
                    Err(TavikError::Execution(format!(
                        "Permission denied checking process {}",
                        self.pid
                    )))
                } else {
                    Err(TavikError::Io(format!(
                        "Failed to check PID {}: {}",
                        self.pid, err
                    )))
                }
            }
        }
    }

    /// Safely terminates this process with SIGKILL only after verifying identity.
    /// Requires pidfd on Linux for race-free termination; fails closed with Unsupported if unavailable.
    /// Waits up to 2 seconds and confirms termination.
    pub fn kill_safe(&self) -> Result<()> {
        if !self.is_alive()? {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            let pfd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0) as libc::c_int };
            if pfd < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    if !self.is_alive()? {
                        return Ok(());
                    }
                    return Err(TavikError::Execution(format!(
                        "pidfd_open returned ESRCH but process {} identity check failed",
                        self.pid
                    )));
                } else if err.raw_os_error() == Some(libc::ENOSYS) {
                    return Err(TavikError::Unsupported(
                        "Safe race-free forced termination requires Linux SYS_pidfd_open support"
                            .into(),
                    ));
                } else {
                    return Err(TavikError::Io(format!(
                        "Failed to open pidfd for PID {}: {}",
                        self.pid, err
                    )));
                }
            }

            // Verify identity while holding pfd
            if !self.is_alive()? {
                unsafe { libc::close(pfd) };
                return Ok(());
            }

            let sig_ret = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pfd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::c_void>(),
                    0,
                )
            };

            if sig_ret != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(pfd) };
                if err.raw_os_error() == Some(libc::ESRCH) {
                    if !self.is_alive()? {
                        return Ok(());
                    }
                    return Err(TavikError::Execution(format!(
                        "pidfd_send_signal returned ESRCH but process {} identity check failed",
                        self.pid
                    )));
                } else if err.raw_os_error() == Some(libc::ENOSYS) {
                    return Err(TavikError::Unsupported(
                        "Safe race-free forced termination requires Linux SYS_pidfd_send_signal support".into(),
                    ));
                } else {
                    return Err(TavikError::Io(format!(
                        "pidfd_send_signal failed for PID {}: {}",
                        self.pid, err
                    )));
                }
            }

            // Wait up to 2000ms for confirmed termination using poll on pidfd
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
            let mut terminated = false;
            while std::time::Instant::now() < deadline {
                let rem_ms = (deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .as_millis() as i32)
                    .max(1);
                let mut pollfd = libc::pollfd {
                    fd: pfd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let poll_ret = unsafe { libc::poll(&mut pollfd, 1, rem_ms) };
                if poll_ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    unsafe { libc::close(pfd) };
                    return Err(TavikError::Io(format!("Failed to poll pidfd: {}", err)));
                }
                if poll_ret > 0
                    && (pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
                {
                    terminated = true;
                    break;
                }
                if !self.is_alive()? {
                    terminated = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            unsafe { libc::close(pfd) };

            if !terminated && self.is_alive()? {
                return Err(TavikError::Execution(format!(
                    "Process {} failed to terminate within timeout after pidfd SIGKILL",
                    self.pid
                )));
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let ret = unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(TavikError::Io(format!(
                        "Failed to send SIGKILL to PID {}: {}",
                        self.pid, err
                    )));
                }
            }

            // Wait up to 2000ms for confirmed termination
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
            while std::time::Instant::now() < deadline {
                let mut status = 0;
                let _ =
                    unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if !self.is_alive()? {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

            Err(TavikError::Execution(format!(
                "Process {} failed to terminate within timeout after SIGKILL",
                self.pid
            )))
        }
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, content)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let ident: Self = serde_json::from_str(&content)?;
        Ok(ident)
    }
}
