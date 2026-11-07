use tavik_security::error::SecurityError;
use tavik_security::seccomp::{
    apply_seccomp, install_seccomp_filter, SeccompAction, SeccompProfile, SockFilter,
};
#[cfg(target_os = "linux")]
use tavik_security::seccomp::{SeccompArg, SeccompOperator, SyscallRule};

#[test]
fn test_empty_program_rejected() {
    let empty: [SockFilter; 0] = [];
    let res = install_seccomp_filter(&empty, 0);
    assert!(res.is_err());
    match res {
        Err(SecurityError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("cannot be empty"));
        }
        other => panic!("Expected InvalidConfiguration, got {:?}", other),
    }
}

#[test]
fn test_unsupported_platform_behavior() {
    #[cfg(not(target_os = "linux"))]
    {
        let fake_prog = [SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        }];
        assert_eq!(
            install_seccomp_filter(&fake_prog, 0),
            Err(SecurityError::UnsupportedPlatform)
        );

        let profile = SeccompProfile {
            default_action: SeccompAction::Allow,
            default_errno_ret: None,
            architectures: vec![],
            flags: vec![],
            syscalls: vec![],
        };
        assert_eq!(
            apply_seccomp(&profile),
            Err(SecurityError::UnsupportedPlatform)
        );
    }
}

#[test]
fn test_kernel_seccomp_blocks_syscall_in_child() {
    #[cfg(target_os = "linux")]
    {
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "Failed to fork child process");

        if child_pid == 0 {
            // Verify getppid succeeds initially
            let initial_ppid = unsafe { libc::syscall(libc::SYS_getppid) };
            if initial_ppid <= 0 {
                eprintln!("Initial getppid failed");
                unsafe { libc::_exit(1) };
            }

            // Configure seccomp profile: Allow all, but return EPERM for getppid
            let profile = SeccompProfile {
                default_action: SeccompAction::Allow,
                default_errno_ret: None,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![SyscallRule {
                    names: vec!["getppid".to_string()],
                    action: SeccompAction::Errno,
                    errno_ret: Some(libc::EPERM as u32),
                    args: vec![],
                }],
            };

            if let Err(e) = apply_seccomp(&profile) {
                eprintln!("apply_seccomp failed in child: {}", e);
                unsafe { libc::_exit(2) };
            }

            // Verify getppid is now blocked with EPERM
            let blocked_ret = unsafe { libc::syscall(libc::SYS_getppid) };
            let err = std::io::Error::last_os_error();
            if blocked_ret != -1 || err.raw_os_error() != Some(libc::EPERM) {
                eprintln!(
                    "getppid did not return EPERM: ret={}, errno={:?}",
                    blocked_ret,
                    err.raw_os_error()
                );
                unsafe { libc::_exit(3) };
            }

            // Verify another syscall (e.g. getpid) still succeeds under default ALLOW
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            if pid <= 0 {
                eprintln!("getpid failed under default ALLOW");
                unsafe { libc::_exit(4) };
            }

            unsafe { libc::_exit(0) };
        }

        // Parent waits for child
        let mut status = 0;
        let wait_res = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        assert_eq!(wait_res, child_pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "Child failed with status: 0x{:x}",
            status
        );
    }
}

#[test]
fn test_kernel_seccomp_argument_filtering_in_child() {
    #[cfg(target_os = "linux")]
    {
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "Failed to fork child process");

        if child_pid == 0 {
            // Configure profile: Allow all, but block prctl if arg0 == PR_SET_NAME with EACCES
            let profile = SeccompProfile {
                default_action: SeccompAction::Allow,
                default_errno_ret: None,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![SyscallRule {
                    names: vec!["prctl".to_string()],
                    action: SeccompAction::Errno,
                    errno_ret: Some(libc::EACCES as u32),
                    args: vec![SeccompArg {
                        index: 0,
                        value: libc::PR_SET_NAME as u64,
                        value_two: 0,
                        op: SeccompOperator::Equal,
                    }],
                }],
            };

            if let Err(e) = apply_seccomp(&profile) {
                eprintln!("apply_seccomp failed in child: {}", e);
                unsafe { libc::_exit(2) };
            }

            // Call prctl(PR_SET_NAME, "test") -> MUST fail with EACCES
            let name = b"blocked\0";
            let ret = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
            let err = std::io::Error::last_os_error();
            if ret != -1 || err.raw_os_error() != Some(libc::EACCES) {
                eprintln!(
                    "prctl(PR_SET_NAME) did not return EACCES: ret={}, errno={:?}",
                    ret,
                    err.raw_os_error()
                );
                unsafe { libc::_exit(3) };
            }

            // Call prctl(PR_GET_DUMPABLE) -> MUST succeed because arg0 != PR_SET_NAME
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            if dumpable < 0 {
                eprintln!(
                    "prctl(PR_GET_DUMPABLE) unexpectedly failed: ret={}",
                    dumpable
                );
                unsafe { libc::_exit(4) };
            }

            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        let wait_res = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        assert_eq!(wait_res, child_pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "Child failed with status: 0x{:x}",
            status
        );
    }
}

#[test]
fn test_kernel_seccomp_kill_action_in_child() {
    #[cfg(target_os = "linux")]
    {
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "Failed to fork child process");

        if child_pid == 0 {
            // Configure profile: Allow all, but KILL_PROCESS on getppid
            let profile = SeccompProfile {
                default_action: SeccompAction::Allow,
                default_errno_ret: None,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![SyscallRule {
                    names: vec!["getppid".to_string()],
                    action: SeccompAction::KillProcess,
                    errno_ret: None,
                    args: vec![],
                }],
            };

            if let Err(e) = apply_seccomp(&profile) {
                eprintln!("apply_seccomp failed in child: {}", e);
                unsafe { libc::_exit(2) };
            }

            // Invoke getppid -> kernel must terminate child with SIGSYS
            unsafe {
                libc::syscall(libc::SYS_getppid);
            }

            // Should not reach here
            eprintln!("Child survived blocked syscall with KILL action!");
            unsafe { libc::_exit(99) };
        }

        let mut status = 0;
        let wait_res = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        assert_eq!(wait_res, child_pid);
        assert!(
            libc::WIFSIGNALED(status),
            "Expected child to be killed by signal, status: 0x{:x}",
            status
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGSYS,
            "Expected child to be killed by SIGSYS"
        );
    }
}

#[test]
fn test_kernel_seccomp_fork_inheritance() {
    #[cfg(target_os = "linux")]
    {
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "Failed to fork child process");

        if child_pid == 0 {
            // Apply filter in child
            let profile = SeccompProfile {
                default_action: SeccompAction::Allow,
                default_errno_ret: None,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![SyscallRule {
                    names: vec!["getppid".to_string()],
                    action: SeccompAction::Errno,
                    errno_ret: Some(libc::EPERM as u32),
                    args: vec![],
                }],
            };

            if let Err(e) = apply_seccomp(&profile) {
                eprintln!("apply_seccomp failed: {}", e);
                unsafe { libc::_exit(2) };
            }

            // Fork a grandchild to verify filter inheritance across fork()
            let grandchild_pid = unsafe { libc::fork() };
            if grandchild_pid < 0 {
                eprintln!("Grandchild fork failed");
                unsafe { libc::_exit(3) };
            }

            if grandchild_pid == 0 {
                // In grandchild: getppid must still be filtered with EPERM
                let res = unsafe { libc::syscall(libc::SYS_getppid) };
                let err = std::io::Error::last_os_error();
                if res != -1 || err.raw_os_error() != Some(libc::EPERM) {
                    eprintln!("Grandchild getppid returned {:?}, errno {:?}", res, err);
                    unsafe { libc::_exit(4) };
                }
                unsafe { libc::_exit(0) };
            }

            let mut grandchild_status = 0;
            let gwait = unsafe { libc::waitpid(grandchild_pid, &mut grandchild_status, 0) };
            if gwait != grandchild_pid
                || !libc::WIFEXITED(grandchild_status)
                || libc::WEXITSTATUS(grandchild_status) != 0
            {
                eprintln!("Grandchild failed with status 0x{:x}", grandchild_status);
                unsafe { libc::_exit(5) };
            }

            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        let wait_res = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        assert_eq!(wait_res, child_pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "Child failed with status 0x{:x}",
            status
        );
    }
}
