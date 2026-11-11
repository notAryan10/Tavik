use tavik_cgroups::{CgroupManager, CgroupResources, CpuResources, MemoryResources, PidResources};

#[test]
fn test_cgroup_path_and_id_validation() {
    let mgr = CgroupManager::new().unwrap();

    // Rejection of invalid container IDs
    assert!(mgr.validate_container_id("").is_err());
    assert!(mgr.validate_container_id("../escape").is_err());
    assert!(mgr.validate_container_id("sub/dir").is_err());
    assert!(mgr.validate_container_id("null\0byte").is_err());
    assert!(mgr.validate_container_id("valid-container-id.123").is_ok());

    // Rejection of parent path equal to root cgroup
    let root = std::path::PathBuf::from("/sys/fs/cgroup");
    assert!(CgroupManager::with_paths(root.clone(), root).is_err());
}

#[test]
fn test_cgroup_resources_serde() {
    let resources = CgroupResources {
        cpu: Some(CpuResources {
            weight: Some(500),
            period: Some(100_000),
            quota: Some(50_000),
        }),
        memory: Some(MemoryResources {
            limit: Some(1024 * 1024 * 64),
            high: Some(1024 * 1024 * 48),
            swap: Some(1024 * 1024 * 128),
        }),
        pids: Some(PidResources { limit: Some(100) }),
    };

    let json = serde_json::to_string_pretty(&resources).unwrap();
    let deserialized: CgroupResources = serde_json::from_str(&json).unwrap();
    assert_eq!(resources, deserialized);
}

#[test]
fn test_linux_cgroup_lifecycle() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful cgroups v2 lifecycle test (requires root)");
            return;
        }

        let mgr = CgroupManager::new().unwrap();
        if let Err(e) = mgr.validate_cgroup_v2() {
            eprintln!("Skipping cgroup test: {}", e);
            return;
        }

        let container_id = format!("tavik-unit-test-{}", std::process::id());

        // 1. Create container cgroup
        let cgroup_dir = mgr.create_container_cgroup(&container_id).unwrap();
        assert!(cgroup_dir.exists());

        // 2. Apply resource constraints
        let resources = CgroupResources {
            cpu: Some(CpuResources {
                weight: Some(200),
                period: Some(100_000),
                quota: Some(50_000), // 0.5 CPU
            }),
            memory: Some(MemoryResources {
                limit: Some(64 * 1024 * 1024), // 64 MB
                high: None,
                swap: None,
            }),
            pids: Some(PidResources { limit: Some(50) }),
        };

        mgr.apply_resources(&container_id, &resources).unwrap();

        // Verify interface files were written
        let cpu_max = std::fs::read_to_string(cgroup_dir.join("cpu.max")).unwrap();
        assert_eq!(cpu_max.trim(), "50000 100000");

        let cpu_weight = std::fs::read_to_string(cgroup_dir.join("cpu.weight")).unwrap();
        assert_eq!(cpu_weight.trim(), "200");

        let mem_max = std::fs::read_to_string(cgroup_dir.join("memory.max")).unwrap();
        assert_eq!(mem_max.trim(), (64 * 1024 * 1024).to_string());

        let pids_max = std::fs::read_to_string(cgroup_dir.join("pids.max")).unwrap();
        assert_eq!(pids_max.trim(), "50");

        // 3. Spawn a dedicated child process and enroll it in cgroup.procs
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("Failed to spawn dummy child process");
        let child_pid = child.id();

        mgr.add_process(&container_id, child_pid).unwrap();

        let procs = mgr.get_processes(&container_id).unwrap();
        assert!(procs.contains(&child_pid));

        // 4. Read stats
        let stats = mgr.read_stats(&container_id).unwrap();
        assert!(stats.pids_current.unwrap_or(0) >= 1);

        // 5. Destroy cgroup (verifying atomic cgroup.kill terminates the child process)
        mgr.destroy_container_cgroup(&container_id).unwrap();
        assert!(!cgroup_dir.exists());

        // Wait for child process to exit (reaped)
        let _ = child.wait();
    }
}

#[cfg(target_os = "linux")]
mod mock_tests {
    use super::*;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tavik_cgroups::CgroupSysOps;
    use tavik_common::error::{Result, TavikError};

    #[derive(Default)]
    struct MockCgroupSysOps {
        cgroup_kill_supported: AtomicBool,
        kill_cgroup_err: Mutex<Option<String>>,
        read_procs_queue: Mutex<VecDeque<Result<Vec<u32>>>>,
        in_cgroup_pids: Mutex<HashSet<u32>>,
        pidfd_open_results: Mutex<HashMap<u32, Result<libc::c_int>>>,
        pidfd_send_signal_err: Mutex<Option<TavikError>>,
        opened_pids: Mutex<Vec<u32>>,
        signaled_fds: Mutex<Vec<(libc::c_int, libc::c_int)>>,
        removed_dirs: Mutex<Vec<PathBuf>>,
        allocated_fds: Mutex<Vec<libc::c_int>>,
    }

    impl CgroupSysOps for MockCgroupSysOps {
        fn cgroup_kill_available(&self, _cgroup_dir: &Path) -> bool {
            self.cgroup_kill_supported.load(Ordering::SeqCst)
        }

        fn kill_cgroup(&self, _cgroup_dir: &Path) -> Result<()> {
            if let Some(err) = self.kill_cgroup_err.lock().unwrap().as_ref() {
                return Err(TavikError::Io(err.clone()));
            }
            Ok(())
        }

        fn read_procs(&self, _cgroup_dir: &Path) -> Result<Vec<u32>> {
            let mut queue = self.read_procs_queue.lock().unwrap();
            if let Some(res) = queue.pop_front() {
                res
            } else {
                Ok(Vec::new())
            }
        }

        fn is_process_in_cgroup(&self, pid: u32, _expected_rel_path: &Path) -> bool {
            self.in_cgroup_pids.lock().unwrap().contains(&pid)
        }

        fn pidfd_open(&self, pid: u32) -> Result<libc::c_int> {
            use std::os::unix::io::IntoRawFd;
            self.opened_pids.lock().unwrap().push(pid);
            if let Some(res) = self.pidfd_open_results.lock().unwrap().remove(&pid) {
                if let Ok(fd) = res {
                    self.allocated_fds.lock().unwrap().push(fd);
                    Ok(fd)
                } else {
                    res
                }
            } else {
                let file = std::fs::File::open("/dev/null").map_err(|e| {
                    TavikError::Io(format!("Failed to open /dev/null for mock pidfd: {}", e))
                })?;
                let raw_fd = file.into_raw_fd();

                // Allocate an available descriptor at or above 500 without overwriting any existing descriptor.
                let dup_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 500) };
                let dup_err = if dup_fd == -1 {
                    Some(std::io::Error::last_os_error())
                } else {
                    None
                };

                // Close original raw_fd whether duplication succeeded or failed
                unsafe {
                    libc::close(raw_fd);
                };

                if let Some(err) = dup_err {
                    return Err(TavikError::Io(format!(
                        "F_DUPFD_CLOEXEC for mock pidfd failed: {}",
                        err
                    )));
                }

                self.allocated_fds.lock().unwrap().push(dup_fd);
                Ok(dup_fd)
            }
        }

        fn pidfd_send_signal(&self, pidfd: libc::c_int, sig: libc::c_int) -> Result<()> {
            self.signaled_fds.lock().unwrap().push((pidfd, sig));
            if let Some(err) = self.pidfd_send_signal_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(())
        }

        fn remove_cgroup_dir(&self, cgroup_dir: &Path) -> Result<()> {
            self.removed_dirs
                .lock()
                .unwrap()
                .push(cgroup_dir.to_path_buf());
            let _ = std::fs::remove_dir(cgroup_dir);
            Ok(())
        }
    }

    fn setup_mock_manager() -> (tempfile::TempDir, Arc<MockCgroupSysOps>, CgroupManager) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cgroup");
        let parent = root.join("tavik");
        std::fs::create_dir_all(&parent).unwrap();

        let ops = Arc::new(MockCgroupSysOps::default());
        let mgr = CgroupManager::with_sys_ops(root, parent, ops.clone()).unwrap();
        (temp, ops, mgr)
    }

    #[test]
    fn test_cgroup_idempotent_cleanup() {
        let (_temp, _ops, mgr) = setup_mock_manager();
        // Destroying non-existent container cgroup returns Ok(())
        let res = mgr.destroy_container_cgroup("nonexistent");
        assert!(res.is_ok());
    }

    #[test]
    fn test_cgroup_procs_read_failure_fails_closed_and_preserves_dir() {
        let (_temp, ops, mgr) = setup_mock_manager();
        let container_id = "test-fail-read-procs";
        let cgroup_dir = mgr.parent_path().join(container_id);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
        ops.read_procs_queue
            .lock()
            .unwrap()
            .push_back(Err(TavikError::Io(
                "simulated io error reading procs".into(),
            )));

        let res = mgr.destroy_container_cgroup(container_id);
        assert!(res.is_err());
        match res {
            Err(TavikError::Io(msg)) => assert!(msg.contains("simulated io error")),
            other => panic!("Expected Io error, got: {:?}", other),
        }

        // Cgroup directory must be preserved
        assert!(cgroup_dir.exists());
        assert!(ops.removed_dirs.lock().unwrap().is_empty());
    }

    #[test]
    fn test_cgroup_fallback_unsupported_pidfd_open_preserves_dir() {
        let (_temp, ops, mgr) = setup_mock_manager();
        let container_id = "test-unsupported-pidfd-open";
        let cgroup_dir = mgr.parent_path().join(container_id);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
        ops.read_procs_queue
            .lock()
            .unwrap()
            .push_back(Ok(vec![101]));
        ops.in_cgroup_pids.lock().unwrap().insert(101);
        ops.pidfd_open_results.lock().unwrap().insert(
            101,
            Err(TavikError::Unsupported(
                "Safe cgroup process termination requires Linux SYS_pidfd_open support".into(),
            )),
        );

        let res = mgr.destroy_container_cgroup(container_id);
        assert!(matches!(res, Err(TavikError::Unsupported(_))));
        assert!(cgroup_dir.exists());
        assert!(ops.removed_dirs.lock().unwrap().is_empty());
    }

    #[test]
    fn test_cgroup_fallback_unsupported_pidfd_send_signal_preserves_dir() {
        let (_temp, ops, mgr) = setup_mock_manager();
        let container_id = "test-unsupported-pidfd-signal";
        let cgroup_dir = mgr.parent_path().join(container_id);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
        ops.read_procs_queue
            .lock()
            .unwrap()
            .push_back(Ok(vec![101]));
        ops.in_cgroup_pids.lock().unwrap().insert(101);
        *ops.pidfd_send_signal_err.lock().unwrap() = Some(TavikError::Unsupported(
            "Safe cgroup process termination requires Linux SYS_pidfd_send_signal support".into(),
        ));

        let res = mgr.destroy_container_cgroup(container_id);
        assert!(matches!(res, Err(TavikError::Unsupported(_))));
        assert!(cgroup_dir.exists());
        assert!(ops.removed_dirs.lock().unwrap().is_empty());
    }

    #[test]
    fn test_cgroup_fallback_membership_mismatch_skips_unowned_process() {
        let (_temp, ops, mgr) = setup_mock_manager();
        let container_id = "test-membership-mismatch";
        let cgroup_dir = mgr.parent_path().join(container_id);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
        // Initial list has 101 and 102
        ops.read_procs_queue
            .lock()
            .unwrap()
            .push_back(Ok(vec![101, 102]));
        // Subsequent poll shows empty
        ops.read_procs_queue.lock().unwrap().push_back(Ok(vec![]));

        // Only 102 is actually enrolled; 101 migrated out or PID was reused
        ops.in_cgroup_pids.lock().unwrap().insert(102);

        let res = mgr.destroy_container_cgroup(container_id);
        assert!(res.is_ok(), "Expected success, got: {:?}", res);

        let opened = ops.opened_pids.lock().unwrap();
        assert!(
            !opened.contains(&101),
            "Unowned PID 101 must not have been opened!"
        );
        assert!(opened.contains(&102), "Owned PID 102 must have been opened");

        assert!(!cgroup_dir.exists());
    }

    #[test]
    fn test_cgroup_fallback_successful_enumeration_and_termination() {
        let (_temp, ops, mgr) = setup_mock_manager();
        let container_id = "test-fallback-success";
        let cgroup_dir = mgr.parent_path().join(container_id);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
        ops.read_procs_queue
            .lock()
            .unwrap()
            .push_back(Ok(vec![201, 202]));
        ops.read_procs_queue.lock().unwrap().push_back(Ok(vec![]));

        ops.in_cgroup_pids.lock().unwrap().insert(201);
        ops.in_cgroup_pids.lock().unwrap().insert(202);

        let res = mgr.destroy_container_cgroup(container_id);
        assert!(res.is_ok(), "Expected success, got: {:?}", res);

        let signaled = ops.signaled_fds.lock().unwrap();
        assert_eq!(signaled.len(), 2, "Both processes must be signaled");
        assert_eq!(signaled[0].1, libc::SIGKILL);
        assert_eq!(signaled[1].1, libc::SIGKILL);

        assert!(!cgroup_dir.exists());
    }

    #[test]
    fn test_cgroup_remaining_processes_verification_fails() {
        let (_temp, ops, mgr) = setup_mock_manager();
        let container_id = "test-remaining-procs-fail";
        let cgroup_dir = mgr.parent_path().join(container_id);
        std::fs::create_dir_all(&cgroup_dir).unwrap();

        ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
        // Processes remain active after termination signal
        for _ in 0..12 {
            ops.read_procs_queue
                .lock()
                .unwrap()
                .push_back(Ok(vec![301]));
        }
        ops.in_cgroup_pids.lock().unwrap().insert(301);

        let res = mgr.destroy_container_cgroup(container_id);
        assert!(res.is_err());
        match res {
            Err(TavikError::Execution(msg)) => {
                assert!(msg.contains("still contains 1 active process(es)"));
            }
            other => panic!("Expected Execution error, got: {:?}", other),
        }

        assert!(cgroup_dir.exists());
    }

    #[test]
    fn test_cgroup_mock_pidfd_ownership_and_closure() {
        const SUBPROCESS_ENV: &str = "TAVIK_TEST_MOCK_PIDFD_SUBPROCESS";

        if std::env::var(SUBPROCESS_ENV).is_ok() {
            // Subprocess: execute descriptor ownership test body directly
            use std::os::unix::io::IntoRawFd;
            let (_temp, ops, mgr) = setup_mock_manager();
            let container_id = "test-mock-pidfd-closure";
            let cgroup_dir = mgr.parent_path().join(container_id);
            std::fs::create_dir_all(&cgroup_dir).unwrap();

            // Open an unrelated canary fd prior to test
            let canary_file = std::fs::File::open("/dev/null").expect("Failed to open canary file");
            let canary_fd = canary_file.into_raw_fd();

            ops.cgroup_kill_supported.store(false, Ordering::SeqCst);
            ops.read_procs_queue
                .lock()
                .unwrap()
                .push_back(Ok(vec![201, 202]));
            ops.read_procs_queue
                .lock()
                .unwrap()
                .push_back(Ok(Vec::new())); // second read after kill shows empty
            ops.in_cgroup_pids.lock().unwrap().insert(201);
            ops.in_cgroup_pids.lock().unwrap().insert(202);

            let res = mgr.destroy_container_cgroup(container_id);
            assert!(
                res.is_ok(),
                "destroy_container_cgroup must succeed: {:?}",
                res
            );

            let allocated = ops.allocated_fds.lock().unwrap().clone();
            assert_eq!(allocated.len(), 2, "Expected 2 allocated mock pidfds");

            // Assert all allocated descriptors have been closed by FdGuard
            for fd in allocated {
                let ret = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                assert_eq!(ret, -1, "Allocated fd {} must be closed by FdGuard", fd);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF),
                    "fcntl on closed fd {} must fail with EBADF",
                    fd
                );
            }

            // Assert unrelated canary fd opened prior to test remains valid
            let canary_ret = unsafe { libc::fcntl(canary_fd, libc::F_GETFD) };
            assert_ne!(
                canary_ret, -1,
                "Canary fd {} must remain open and valid",
                canary_fd
            );

            // Clean up canary fd
            unsafe { libc::close(canary_fd) };
            return;
        }

        // Parent: run the test body in a separately spawned test process using std::process::Command
        let current_exe = std::env::current_exe().expect("Failed to get current_exe");
        let output = std::process::Command::new(current_exe)
            .arg("mock_tests::test_cgroup_mock_pidfd_ownership_and_closure")
            .arg("--exact")
            .arg("--nocapture")
            .env(SUBPROCESS_ENV, "1")
            .output()
            .expect("Failed to spawn isolated test subprocess");

        assert!(
            output.status.success(),
            "Isolated mock pidfd ownership test failed with status: {:?}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
