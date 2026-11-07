#[cfg(not(target_os = "linux"))]
use tavik_security::SecurityError;
use tavik_security::{ensure_no_new_privs, is_no_new_privs, set_no_new_privs};

#[test]
fn test_unsupported_platform_behavior() {
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(set_no_new_privs(), Err(SecurityError::UnsupportedPlatform));
        assert_eq!(is_no_new_privs(), Err(SecurityError::UnsupportedPlatform));
        assert_eq!(
            ensure_no_new_privs(),
            Err(SecurityError::UnsupportedPlatform)
        );
    }
}

#[test]
fn test_no_new_privs_lifecycle_and_fork_inheritance() {
    #[cfg(target_os = "linux")]
    {
        // Execute inside a dedicated child process to avoid mutating the test runner process
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "Failed to fork test child");

        if child_pid == 0 {
            // 1. Initial state check
            if is_no_new_privs().unwrap() {
                eprintln!("no_new_privs unexpectedly already enabled");
                unsafe { libc::_exit(1) };
            }

            // 2. Enable no_new_privs
            if let Err(e) = set_no_new_privs() {
                eprintln!("set_no_new_privs failed: {}", e);
                unsafe { libc::_exit(2) };
            }

            // 3. Verify enabled state
            if !is_no_new_privs().unwrap() {
                eprintln!("is_no_new_privs returned false after set_no_new_privs");
                unsafe { libc::_exit(3) };
            }

            // Verify via /proc/self/status
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            if !status.contains("NoNewPrivs:\t1") {
                eprintln!("/proc/self/status did not report NoNewPrivs: 1");
                unsafe { libc::_exit(4) };
            }

            // 4. Idempotency: Calling ensure_no_new_privs when already enabled succeeds
            if let Err(e) = ensure_no_new_privs() {
                eprintln!("ensure_no_new_privs failed on already-enabled state: {}", e);
                unsafe { libc::_exit(5) };
            }

            // 5. Fork inheritance: verify grandchild inherits no_new_privs
            let grandchild_pid = unsafe { libc::fork() };
            if grandchild_pid < 0 {
                eprintln!("Failed to fork grandchild");
                unsafe { libc::_exit(6) };
            }

            if grandchild_pid == 0 {
                // Grandchild process
                if !is_no_new_privs().unwrap() {
                    eprintln!("Grandchild did not inherit no_new_privs!");
                    unsafe { libc::_exit(7) };
                }
                let gc_status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                if !gc_status.contains("NoNewPrivs:\t1") {
                    eprintln!("Grandchild /proc/self/status did not report NoNewPrivs: 1");
                    unsafe { libc::_exit(8) };
                }
                unsafe { libc::_exit(0) };
            }

            let mut gc_status: i32 = 0;
            let wait_res = unsafe { libc::waitpid(grandchild_pid, &mut gc_status, 0) };
            if wait_res != grandchild_pid || libc::WEXITSTATUS(gc_status) != 0 {
                eprintln!(
                    "Grandchild failed with status: {}",
                    libc::WEXITSTATUS(gc_status)
                );
                unsafe { libc::_exit(9) };
            }

            unsafe { libc::_exit(0) };
        }

        let mut child_status: i32 = 0;
        let wait_res = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
        assert_eq!(wait_res, child_pid);
        assert!(libc::WIFEXITED(child_status));
        assert_eq!(
            libc::WEXITSTATUS(child_status),
            0,
            "Child process failed no_new_privs lifecycle verification"
        );
    }
}

#[test]
fn test_no_new_privs_exec_inheritance() {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;

        let out_file = format!("/tmp/no_new_privs_exec_test_{}.txt", std::process::id());
        let _ = std::fs::remove_file(&out_file);

        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "Failed to fork test child");

        if child_pid == 0 {
            // Enable no_new_privs
            if let Err(e) = set_no_new_privs() {
                eprintln!("set_no_new_privs failed: {}", e);
                unsafe { libc::_exit(1) };
            }

            // Execve into /bin/sh to write NoNewPrivs line to out_file
            let shell = CString::new("/bin/sh").unwrap();
            let arg0 = CString::new("sh").unwrap();
            let arg1 = CString::new("-c").unwrap();
            let cmd = format!("grep NoNewPrivs /proc/self/status > {} && exit 0", out_file);
            let arg2 = CString::new(cmd).unwrap();

            let args = [
                arg0.as_ptr(),
                arg1.as_ptr(),
                arg2.as_ptr(),
                std::ptr::null(),
            ];
            let envs = [std::ptr::null()];

            unsafe {
                libc::execve(shell.as_ptr(), args.as_ptr(), envs.as_ptr());
            }
            unsafe { libc::_exit(2) };
        }

        let mut child_status: i32 = 0;
        let wait_res = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
        assert_eq!(wait_res, child_pid);
        assert!(libc::WIFEXITED(child_status));
        assert_eq!(libc::WEXITSTATUS(child_status), 0);

        // Verify output written after execve
        let out_content =
            std::fs::read_to_string(&out_file).expect("Failed to read exec output file");
        let _ = std::fs::remove_file(&out_file);
        assert!(
            out_content.contains("NoNewPrivs:\t1"),
            "Exec did not preserve no_new_privs! Content: {}",
            out_content
        );
    }
}
