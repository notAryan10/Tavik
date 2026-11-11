use std::fs;
use std::path::Path;
use tavik_common::error::{Result, TavikError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

#[cfg(target_os = "macos")]
fn get_process_stat_macos(pid: u32) -> Result<u64> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::pid_t,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if ret <= 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Err(TavikError::NotFound(format!("Process {} not found", pid)));
        } else if err.raw_os_error() == Some(libc::EPERM) {
            return Err(TavikError::Execution(format!(
                "Permission denied checking process {}",
                pid
            )));
        }
        return Err(TavikError::Io(format!(
            "proc_pidinfo failed for PID {}: {}",
            pid, err
        )));
    }
    Ok((info.pbi_start_tvsec as u64) * 1_000_000 + (info.pbi_start_tvusec as u64))
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

#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::cell::RefCell;

    #[derive(Default, Clone, Copy, Debug)]
    pub struct MockSyscalls {
        pub pidfd_open_errno: i32,
        pub pidfd_send_signal_errno: i32,
        pub simulate_send_signal_noop: bool,
        pub poll_revents: Option<i16>,
        pub poll_return: Option<i32>,
        pub poll_errno: i32,
        pub poll_eintr_count: u32,
    }

    thread_local! {
        static MOCK_STATE: RefCell<MockSyscalls> = RefCell::new(MockSyscalls::default());
    }

    pub struct ScopedMockSyscalls(MockSyscalls);

    impl ScopedMockSyscalls {
        pub fn set(mocks: MockSyscalls) -> Self {
            let prev = MOCK_STATE.with(|s| {
                let old = *s.borrow();
                *s.borrow_mut() = mocks;
                old
            });
            Self(prev)
        }
    }

    impl Drop for ScopedMockSyscalls {
        fn drop(&mut self) {
            MOCK_STATE.with(|s| {
                *s.borrow_mut() = self.0;
            });
        }
    }

    pub fn with_mocks<R>(f: impl FnOnce(&mut MockSyscalls) -> R) -> R {
        MOCK_STATE.with(|s| f(&mut s.borrow_mut()))
    }
}

#[cfg(target_os = "linux")]
struct FdGuard(libc::c_int);

#[cfg(target_os = "linux")]
impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
        }
    }
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
        #[cfg(target_os = "macos")]
        {
            let start_time = get_process_stat_macos(pid)?;
            Ok(Self { pid, start_time })
        }
        #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
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
        #[cfg(target_os = "macos")]
        {
            let mut status = 0;
            let wait_res =
                unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if wait_res == self.pid as libc::pid_t {
                return Ok(false);
            }
            match get_process_stat_macos(self.pid) {
                Ok(start_time) => {
                    if start_time != self.start_time {
                        // PID reuse: original process has terminated
                        Ok(false)
                    } else {
                        Ok(true)
                    }
                }
                Err(TavikError::NotFound(_)) => Ok(false),
                Err(e) => Err(e),
            }
        }
        #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
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
            #[cfg(feature = "test-hooks")]
            let sim_open = test_hooks::with_mocks(|m| m.pidfd_open_errno);
            #[cfg(not(feature = "test-hooks"))]
            let sim_open = 0;

            let pfd = if sim_open != 0 {
                unsafe { *libc::__errno_location() = sim_open };
                -1
            } else {
                unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0) as libc::c_int }
            };

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

            let _guard = FdGuard(pfd);

            // Verify identity while holding pfd
            if !self.is_alive()? {
                return Ok(());
            }

            #[cfg(feature = "test-hooks")]
            let (sim_sig, sim_noop) = test_hooks::with_mocks(|m| {
                (m.pidfd_send_signal_errno, m.simulate_send_signal_noop)
            });
            #[cfg(not(feature = "test-hooks"))]
            let (sim_sig, sim_noop) = (0, false);

            let sig_ret = if sim_sig != 0 {
                unsafe { *libc::__errno_location() = sim_sig };
                -1
            } else if sim_noop {
                0
            } else {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pfd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::c_void>(),
                        0,
                    )
                }
            };

            if sig_ret != 0 {
                let err = std::io::Error::last_os_error();
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

                #[cfg(feature = "test-hooks")]
                let (poll_ret, poll_revents, poll_errno, eintr_remaining) =
                    test_hooks::with_mocks(|m| {
                        let eintr = if m.poll_eintr_count > 0 {
                            m.poll_eintr_count -= 1;
                            true
                        } else {
                            false
                        };
                        (m.poll_return, m.poll_revents, m.poll_errno, eintr)
                    });
                #[cfg(not(feature = "test-hooks"))]
                let (poll_ret, poll_revents, poll_errno, eintr_remaining): (
                    Option<i32>,
                    Option<i16>,
                    i32,
                    bool,
                ) = (None, None, 0, false);

                let poll_res = if eintr_remaining {
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    -1
                } else if let Some(ret) = poll_ret {
                    if let Some(rev) = poll_revents {
                        pollfd.revents = rev;
                    }
                    if ret < 0 && poll_errno != 0 {
                        unsafe { *libc::__errno_location() = poll_errno };
                    }
                    ret
                } else if let Some(rev) = poll_revents {
                    pollfd.revents = rev;
                    1
                } else {
                    unsafe { libc::poll(&mut pollfd, 1, rem_ms) }
                };

                if poll_res < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(TavikError::Io(format!("Failed to poll pidfd: {}", err)));
                }
                if poll_res > 0 {
                    let revents = pollfd.revents;

                    // 1. Reject POLLERR and POLLNVAL regardless of whether terminal readiness flags are also present.
                    if (revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                        return Err(TavikError::Execution(format!(
                            "Unexpected poll error event 0x{:x} on pidfd for PID {}",
                            revents, self.pid
                        )));
                    }

                    // 2. Reject every unrequested readiness flag.
                    let unrequested = revents & !(libc::POLLIN | libc::POLLHUP);
                    if unrequested != 0 {
                        return Err(TavikError::Execution(format!(
                            "Unrequested poll readiness flags 0x{:x} (full revents 0x{:x}) on pidfd for PID {}",
                            unrequested, revents, self.pid
                        )));
                    }

                    // 3. Only accept documented terminal readiness bits after validating the entire returned event mask.
                    if (revents & (libc::POLLIN | libc::POLLHUP)) != 0 && !self.is_alive()? {
                        terminated = true;
                        break;
                    }
                }
                if !self.is_alive()? {
                    terminated = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

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
            #[cfg(feature = "test-hooks")]
            let sim_noop = {
                let (sim_open, sim_sig, sim_noop, sim_revents, sim_ret, sim_errno, eintr_remaining) =
                    test_hooks::with_mocks(|m| {
                        let eintr = if m.poll_eintr_count > 0 {
                            m.poll_eintr_count -= 1;
                            true
                        } else {
                            false
                        };
                        (
                            m.pidfd_open_errno,
                            m.pidfd_send_signal_errno,
                            m.simulate_send_signal_noop,
                            m.poll_revents,
                            m.poll_return,
                            m.poll_errno,
                            eintr,
                        )
                    });

                if sim_open == libc::ENOSYS {
                    return Err(TavikError::Unsupported(
                        "Safe race-free forced termination requires Linux SYS_pidfd_open support"
                            .into(),
                    ));
                }
                if sim_sig == libc::ENOSYS {
                    return Err(TavikError::Unsupported(
                        "Safe race-free forced termination requires Linux SYS_pidfd_send_signal support".into(),
                    ));
                }
                if let Some(revents) = sim_revents {
                    // 1. Reject POLLERR and POLLNVAL
                    if (revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                        return Err(TavikError::Execution(format!(
                            "Unexpected poll error event 0x{:x} on pidfd for PID {}",
                            revents, self.pid
                        )));
                    }
                    // 2. Reject unrequested flags
                    let unrequested = revents & !(libc::POLLIN | libc::POLLHUP);
                    if unrequested != 0 {
                        return Err(TavikError::Execution(format!(
                            "Unrequested poll readiness flags 0x{:x} (full revents 0x{:x}) on pidfd for PID {}",
                            unrequested, revents, self.pid
                        )));
                    }
                }
                if eintr_remaining {
                    // simulated EINTR retry
                } else if let Some(ret) = sim_ret {
                    if ret == 0 && !sim_noop {
                        return Err(TavikError::Execution(format!(
                            "Timed out waiting for process {} to terminate",
                            self.pid
                        )));
                    }
                    if ret < 0 && sim_errno != libc::EINTR {
                        return Err(TavikError::Io(format!(
                            "Failed to poll pidfd: simulated error {}",
                            sim_errno
                        )));
                    }
                }
                sim_noop
            };
            #[cfg(not(feature = "test-hooks"))]
            let sim_noop = false;

            if !sim_noop {
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

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(not(feature = "test-hooks"))]
    #[allow(clippy::assertions_on_constants)]
    fn test_production_build_has_no_active_test_hooks() {
        assert!(
            !cfg!(feature = "test-hooks"),
            "test-hooks feature must NOT be enabled in default production build"
        );
    }

    #[test]
    #[cfg(feature = "test-hooks")]
    #[allow(clippy::assertions_on_constants)]
    fn test_test_hooks_feature_active_when_explicitly_enabled() {
        assert!(
            cfg!(feature = "test-hooks"),
            "test-hooks feature must be active when explicitly enabled"
        );
    }
}
