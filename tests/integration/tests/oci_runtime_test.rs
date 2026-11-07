use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::Duration;
use tavik_cli::client::Client;
use tavik_daemon::DaemonServer;
use tavik_runtime::{ContainerExecutor, ContainerStatus, Spec};
use tempfile::tempdir;

#[test]
fn test_oci_bundle_validation_and_executor() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    // 1. Generate default OCI Linux spec and save to bundle
    let spec = Spec::default_linux();
    let config_path = bundle_dir.join("config.json");
    fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

    let executor = ContainerExecutor::new(state_dir).unwrap();
    let container_id = "oci-test-cont-01";

    // 2. Create container
    let state = executor.create(container_id, &bundle_dir).unwrap();
    assert_eq!(state.id, container_id);
    assert_eq!(state.status, ContainerStatus::Created);
    assert_eq!(state.bundle, bundle_dir.canonicalize().unwrap());

    // 3. Query state
    let loaded = executor.load_state(container_id).unwrap();
    assert_eq!(loaded.id, container_id);
    assert_eq!(loaded.status, ContainerStatus::Created);

    // 4. Delete container
    executor.delete(container_id, false).unwrap();
    assert!(executor.load_state(container_id).is_err());
}

#[tokio::test]
async fn test_daemon_oci_container_ipc() {
    let temp_dir = tempdir().unwrap();
    let socket_path = temp_dir.path().join("tavik_oci_test.sock");
    let state_dir = temp_dir.path().join("tavik_state");
    let bundle_dir = temp_dir.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    // Prepare OCI bundle
    let spec = Spec::default_linux();
    let config_path = bundle_dir.join("config.json");
    fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

    let server = DaemonServer::new(socket_path.clone(), state_dir.clone()).unwrap();
    let daemon_task = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = Client::new(socket_path);

    // 1. Request container create via daemon RPC
    let container_id = "daemon-cont-01".to_string();
    let bundle_path_str = bundle_dir.to_string_lossy().to_string();

    let create_resp = client
        .container_create(container_id.clone(), bundle_path_str)
        .await
        .expect("container_create failed");
    assert_eq!(create_resp["id"], "daemon-cont-01");
    assert_eq!(create_resp["status"], "created");

    // 2. Query container state via daemon RPC
    let state_resp = client
        .container_state(container_id.clone())
        .await
        .expect("container_state failed");
    assert_eq!(state_resp["id"], "daemon-cont-01");
    assert_eq!(state_resp["status"], "created");

    // 3. Delete container via daemon RPC
    let del_resp = client
        .container_delete(container_id.clone(), false)
        .await
        .expect("container_delete failed");
    assert!(del_resp.contains("deleted"));

    let _ = client.shutdown().await;
    let _ = daemon_task.await;
}

#[test]
fn test_linux_container_pid_namespace_and_lifecycle() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful container isolation test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        // Copy static busybox into container rootfs
        if Path::new("/usr/bin/busybox").exists() {
            fs::copy("/usr/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else if Path::new("/bin/busybox").exists() {
            fs::copy("/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else {
            panic!("busybox not found on host");
        }

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "echo $$ > /pid.txt && cat /proc/1/cmdline > /proc_cmdline.txt && test ! -d /home && echo \"isolated\" > /iso.txt && sleep 2".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-pid-iso-01";

        // 1. Create container
        let created_state = executor.create(container_id, &bundle_dir).unwrap();
        assert_eq!(created_state.status, ContainerStatus::Created);

        // Verify the command did NOT execute yet
        assert!(
            !rootfs.join("pid.txt").exists(),
            "Container command executed prematurely before start!"
        );

        // 2. Start container
        let started_state = executor.start(container_id).unwrap();
        assert_eq!(started_state.status, ContainerStatus::Running);

        // Wait up to 1.5 seconds for pid.txt to be created
        let mut pid_txt = None;
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("pid.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    pid_txt = Some(trimmed);
                    break;
                }
            }
        }

        let inner_pid = pid_txt.expect("pid.txt was not created by container init!");
        // The process INSIDE the PID namespace must see PID 1!
        assert_eq!(
            inner_pid, "1",
            "Container did not enter PID namespace: expected PID 1, got {}",
            inner_pid
        );

        // Verify filesystem isolation: /home on host must NOT exist inside container rootfs
        assert!(
            rootfs.join("iso.txt").exists(),
            "Filesystem isolation failed: host paths were visible or iso.txt not written"
        );

        // Verify container procfs isolation: /proc/1/cmdline inside container must reference busybox/sh
        let proc_cmdline = fs::read_to_string(rootfs.join("proc_cmdline.txt")).unwrap_or_default();
        assert!(
            proc_cmdline.contains("busybox") || proc_cmdline.contains("sh"),
            "Procfs isolation failed: expected container command in /proc/1/cmdline, got {:?}",
            proc_cmdline
        );

        // The host must see a host PID != 1
        let host_pid = started_state.pid.expect("Container must have host PID");
        assert_ne!(host_pid, 1, "Host PID cannot be 1");

        // Clean up
        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_cgroups_pids_limit() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful cgroup test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        // Limit pids to 5
        if let Some(linux) = &mut spec.linux {
            linux.resources = Some(tavik_cgroups::CgroupResources {
                pids: Some(tavik_cgroups::PidResources { limit: Some(5) }),
                cpu: None,
                memory: None,
            });
        }

        // Inside container: attempt to spawn 20 background processes.
        // The cgroup pids limit (5) must cause forks to fail.
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "fork_failed=0; for i in $(seq 1 20); do (/bin/busybox sleep 5 &) 2>/dev/null || { fork_failed=1; break; }; done; if [ $fork_failed -eq 1 ]; then echo \"fork_limited\" > /result.txt; else echo \"no_limit\" > /result.txt; fi; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-cgroup-pids-01";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        // Wait for result.txt
        let mut result = String::new();
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("result.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    result = trimmed;
                    break;
                }
            }
        }

        assert_eq!(
            result, "fork_limited",
            "Cgroup pids.max did not prevent fork bomb!"
        );

        // Verify cgroup tracking: processes in cgroup should be <= 5
        if let Ok(cgroup_mgr) = tavik_cgroups::CgroupManager::new() {
            if let Ok(procs) = cgroup_mgr.get_processes(container_id) {
                assert!(
                    procs.len() <= 5,
                    "Cgroup exceeded pids.max limit of 5: {:?}",
                    procs
                );
            }
        }

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_cgroups_memory_accounting() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful cgroup test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        // Limit memory to 32MB
        if let Some(linux) = &mut spec.linux {
            linux.resources = Some(tavik_cgroups::CgroupResources {
                memory: Some(tavik_cgroups::MemoryResources {
                    limit: Some(33554432), // 32 MB
                    high: None,
                    swap: Some(0),
                }),
                cpu: None,
                pids: None,
            });
        }

        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "echo \"running\" > /ready.txt && sleep 3".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-cgroup-mem-01";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        // Wait for container to start
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if rootfs.join("ready.txt").exists() {
                break;
            }
        }

        // Query cgroup stats
        let cgroup_mgr = tavik_cgroups::CgroupManager::new().unwrap();
        let stats = cgroup_mgr.read_stats(container_id).unwrap();
        assert!(
            stats.memory_current.is_some() && stats.memory_current.unwrap() > 0,
            "Cgroup memory accounting failed: stats={:?}",
            stats
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_capabilities_dropping() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful capability test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        // Drop CAP_SYS_ADMIN (and all caps except unprivileged ones)
        if let Some(proc) = &mut spec.process {
            proc.capabilities = Some(tavik_runtime::LinuxCapabilities {
                bounding: vec!["CAP_KILL".to_string(), "CAP_CHOWN".to_string()],
                effective: vec!["CAP_KILL".to_string(), "CAP_CHOWN".to_string()],
                permitted: vec!["CAP_KILL".to_string(), "CAP_CHOWN".to_string()],
                inheritable: vec![],
                ambient: vec![],
            });

            // Container attempts to change hostname (which requires CAP_SYS_ADMIN)
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "if /bin/busybox hostname hacked-host 2>/dev/null; then echo \"cap_leaked\" > /cap.txt; else echo \"cap_dropped\" > /cap.txt; fi; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-caps-drop-01";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        // Wait for cap.txt
        let mut result = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("cap.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    result = trimmed;
                    break;
                }
            }
        }

        assert_eq!(
            result, "cap_dropped",
            "Capability dropping failed: container without CAP_SYS_ADMIN changed hostname!"
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_seccomp_filter_blocks_syscall() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful seccomp test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        // Configure seccomp profile blocking mkdirat with EPERM
        if let Some(linux) = &mut spec.linux {
            linux.seccomp = Some(tavik_security::SeccompProfile {
                default_action: tavik_security::SeccompAction::Allow,
                default_errno_ret: None,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![tavik_security::SyscallRule {
                    names: vec!["mkdirat".to_string()],
                    action: tavik_security::SeccompAction::Errno,
                    errno_ret: Some(libc::EPERM as u32),
                    args: vec![],
                }],
            });
        }

        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "if /bin/busybox mkdir /blocked_dir 2>/dev/null; then echo \"seccomp_allowed\" > /sec.txt; else echo \"seccomp_blocked\" > /sec.txt; fi; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-seccomp-block-01";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        // Wait for sec.txt
        let mut result = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("sec.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    result = trimmed;
                    break;
                }
            }
        }

        assert_eq!(
            result, "seccomp_blocked",
            "Seccomp rule failed to block mkdirat syscall with EPERM"
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}
