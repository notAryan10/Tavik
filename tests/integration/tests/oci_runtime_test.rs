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

#[test]
fn test_privilege_transition_uid_gid_and_groups() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful privilege transition test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&tmp_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.user = tavik_runtime::spec::User {
                uid: 1000,
                gid: 1000,
                additional_gids: vec![1001],
            };
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "/bin/busybox id > /tmp/id.txt; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-priv-trans-01";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        // Wait for id.txt
        let mut id_output = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("tmp/id.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    id_output = trimmed;
                    break;
                }
            }
        }

        assert!(
            id_output.contains("uid=1000"),
            "Expected uid=1000, got: {:?}",
            id_output
        );
        assert!(
            id_output.contains("gid=1000"),
            "Expected gid=1000, got: {:?}",
            id_output
        );
        assert!(
            id_output.contains("groups=") && id_output.contains("1001"),
            "Expected supplementary group 1001 in id output, got: {:?}",
            id_output
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_combined_security_hardening() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful combined security test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&tmp_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();

        // 1. Cgroup limit
        if let Some(linux) = &mut spec.linux {
            linux.resources = Some(tavik_cgroups::CgroupResources {
                pids: Some(tavik_cgroups::PidResources { limit: Some(15) }),
                cpu: None,
                memory: None,
            });
            // 2. Seccomp blocking mkdirat
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

        // 3. User UID 1000 + Capabilities + NoNewPrivileges
        if let Some(proc) = &mut spec.process {
            proc.no_new_privileges = true;
            proc.user = tavik_runtime::spec::User {
                uid: 1000,
                gid: 1000,
                additional_gids: vec![],
            };
            proc.capabilities = Some(tavik_runtime::LinuxCapabilities {
                bounding: vec!["CAP_KILL".to_string()],
                effective: vec!["CAP_KILL".to_string()],
                permitted: vec!["CAP_KILL".to_string()],
                inheritable: vec![],
                ambient: vec![],
            });
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "if /bin/busybox mkdir /tmp/sec_dir 2>/dev/null; then echo \"leak\" > /tmp/hardened.txt; else echo \"hardened_ok\" > /tmp/hardened.txt; fi; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-hardened-comb-01";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        let mut result = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("tmp/hardened.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    result = trimmed;
                    break;
                }
            }
        }

        assert_eq!(
            result, "hardened_ok",
            "Hardened container failed: seccomp did not block mkdirat under non-root user"
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_exact_supplementary_group_isolation_empty() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&tmp_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.user = tavik_runtime::spec::User {
                uid: 1000,
                gid: 1000,
                additional_gids: vec![], // Empty additional_gids must clear inherited host groups!
            };
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "/bin/busybox id -G > /tmp/id_g.txt; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-empty-supp-groups";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        let mut id_output = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("tmp/id_g.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    id_output = trimmed;
                    break;
                }
            }
        }

        // When additional_gids is empty, only primary GID 1000 must be present
        let groups: Vec<&str> = id_output.split_whitespace().collect();
        assert_eq!(
            groups,
            vec!["1000"],
            "Expected only primary GID 1000, no inherited host supplementary groups. Got: {:?}",
            groups
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_exact_supplementary_group_isolation_multiple() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&tmp_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.user = tavik_runtime::spec::User {
                uid: 1000,
                gid: 1000,
                additional_gids: vec![1001, 1002, 1003],
            };
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "/bin/busybox id -G > /tmp/id_g.txt; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-multi-supp-groups";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        let mut id_output = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("tmp/id_g.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    id_output = trimmed;
                    break;
                }
            }
        }

        let mut groups: Vec<&str> = id_output.split_whitespace().collect();
        groups.sort();
        assert_eq!(
            groups,
            vec!["1000", "1001", "1002", "1003"],
            "Expected exact supplementary groups. Got: {:?}",
            groups
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_working_directory_validation_runtime() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let app_dir = rootfs.join("custom_app");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&app_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        // 1. Valid working directory
        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.cwd = "/custom_app".to_string();
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "/bin/busybox pwd > /custom_app/pwd.txt; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir.clone()).unwrap();
        let container_id = "test-valid-cwd";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        let mut pwd_output = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("custom_app/pwd.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    pwd_output = trimmed;
                    break;
                }
            }
        }
        assert_eq!(pwd_output, "/custom_app");
        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);

        // 2. Invalid working directory must fail during start when child applies cwd
        let bundle_bad = temp.path().join("bundle_bad");
        let rootfs_bad = bundle_bad.join("rootfs");
        fs::create_dir_all(rootfs_bad.join("bin")).unwrap();
        fs::copy(busybox_path, rootfs_bad.join("bin/busybox")).unwrap();

        let mut bad_spec = Spec::default_linux();
        if let Some(proc) = &mut bad_spec.process {
            proc.cwd = "/nonexistent_never_exists".to_string();
            proc.args = vec!["/bin/busybox".to_string(), "true".to_string()];
        }
        fs::write(
            bundle_bad.join("config.json"),
            serde_json::to_string_pretty(&bad_spec).unwrap(),
        )
        .unwrap();

        let _ = executor.create("test-bad-cwd", &bundle_bad).unwrap();
        let err = executor.start("test-bad-cwd").unwrap_err();
        assert!(matches!(err, tavik_common::error::TavikError::Execution(_)));
        let _ = executor.delete("test-bad-cwd", true);
    }
}

#[test]
fn test_working_directory_inaccessible_to_container_user() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let root_only_dir = rootfs.join("root_only");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&root_only_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            // root_only directory is mode 0700 (accessible ONLY to UID 0)
            let _ = fs::set_permissions(&root_only_dir, fs::Permissions::from_mode(0o700));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.cwd = "/root_only".to_string();
            proc.user = tavik_runtime::spec::User {
                uid: 1000,
                gid: 1000,
                additional_gids: vec![],
            };
            proc.args = vec!["/bin/busybox".to_string(), "true".to_string()];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-inaccessible-cwd";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        // Container start must fail because user UID 1000 cannot chdir into mode 0700 dir
        let start_res = executor.start(container_id);
        assert!(start_res.is_err());
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_container_creation_retry_with_same_id_after_failure() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_fail = temp.path().join("bundle_fail");
    fs::create_dir_all(&bundle_fail).unwrap();

    // Valid spec so Spec::load_from_bundle succeeds and Creating state is persisted,
    // but rootfs directory is omitted so platform_create fails!
    let mut fail_spec = Spec::default_linux();
    if let Some(root) = &mut fail_spec.root {
        root.path = "nonexistent_rootfs_dir".to_string();
    }
    fs::write(
        bundle_fail.join("config.json"),
        serde_json::to_string_pretty(&fail_spec).unwrap(),
    )
    .unwrap();

    let executor = ContainerExecutor::new(state_dir.clone()).unwrap();
    let container_id = "test-retry-creation-id";
    let container_dir = state_dir.join(container_id);

    // 1. Initial creation fails during platform_create after Creating state was persisted
    let first_res = executor.create(container_id, &bundle_fail);
    assert!(
        first_res.is_err(),
        "Creation should fail due to missing rootfs in platform_create"
    );

    // 2. Verify state and filesystem cleanup: no stale state, PID, or FIFO files remain
    assert!(
        !container_dir.exists(),
        "Container directory {:?} must be cleaned up on creation failure",
        container_dir
    );
    assert!(
        !container_dir.join("state.json").exists(),
        "stale state.json must not remain"
    );
    assert!(
        !container_dir.join("container.pid").exists(),
        "stale container.pid must not remain"
    );
    assert!(
        !container_dir.join("start.fifo").exists(),
        "stale start.fifo must not remain"
    );
    assert!(
        !container_dir.join("exec.fifo").exists(),
        "stale exec.fifo must not remain"
    );

    // 3. Setting up a valid bundle
    let bundle_valid = temp.path().join("bundle_valid");
    let rootfs_valid = bundle_valid.join("rootfs");
    fs::create_dir_all(&rootfs_valid).unwrap();
    let mut valid_spec = Spec::default_linux();
    if let Some(proc) = &mut valid_spec.process {
        proc.args = vec!["true".to_string()];
    }
    fs::write(
        bundle_valid.join("config.json"),
        serde_json::to_string_pretty(&valid_spec).unwrap(),
    )
    .unwrap();

    // 4. Retry with exact same container ID succeeds without ContainerAlreadyExists
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } == 0 {
            let second_res = executor.create(container_id, &bundle_valid);
            assert!(
                second_res.is_ok(),
                "Retry with same container_id should succeed after failed creation cleanup: {:?}",
                second_res.err()
            );
            let state = second_res.unwrap();
            assert_eq!(state.status, ContainerStatus::Created);
            let _ = executor.delete(container_id, true);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let second_res = executor.create(container_id, &bundle_valid);
        assert!(
            second_res.is_ok(),
            "Retry with same container_id should succeed on non-Linux: {:?}",
            second_res.err()
        );
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_explicit_uid_gid_zero_credential_transition() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let dev_dir = rootfs.join("dev");
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&tmp_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.user = tavik_runtime::spec::User {
                uid: 0,
                gid: 0,
                additional_gids: vec![],
            };
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "/bin/busybox id > /tmp/id_root.txt; sleep 1".to_string(),
            ];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-uid-zero-explicit";

        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let _ = executor.start(container_id).unwrap();

        let mut id_output = String::new();
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(content) = fs::read_to_string(rootfs.join("tmp/id_root.txt")) {
                let trimmed = content.trim().to_string();
                if !trimmed.is_empty() {
                    id_output = trimmed;
                    break;
                }
            }
        }

        assert!(
            id_output.contains("uid=0"),
            "Expected uid=0, got: {:?}",
            id_output
        );
        assert!(
            id_output.contains("gid=0"),
            "Expected gid=0, got: {:?}",
            id_output
        );

        let _ = executor.kill(container_id, 9);
        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_short_lived_process_startup_success() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful short-lived process test (requires root)");
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
        if let Some(proc) = &mut spec.process {
            // Short-lived process: true (exits immediately with code 0)
            proc.args = vec!["/bin/busybox".to_string(), "true".to_string()];
        }

        let config_path = bundle_dir.join("config.json");
        fs::write(&config_path, serde_json::to_string_pretty(&spec).unwrap()).unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let container_id = "test-short-lived-01";

        let created_state = executor.create(container_id, &bundle_dir).unwrap();
        assert_eq!(created_state.status, ContainerStatus::Created);

        // start() must succeed and must NOT report startup failure due to short-lived exit!
        let start_res = executor.start(container_id);
        assert!(
            start_res.is_ok(),
            "Starting short-lived process should succeed: {:?}",
            start_res.err()
        );

        // Sleep briefly for supervisor to reap child and persist Stopped
        std::thread::sleep(Duration::from_millis(100));
        let state = executor.load_state(container_id).unwrap();
        assert_eq!(state.status, ContainerStatus::Stopped);

        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_runtime_path_resolution_variants() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful runtime PATH test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let bundle_dir = temp.path().join("bundle");
        let rootfs = bundle_dir.join("rootfs");
        let bin_dir = rootfs.join("bin");
        let usr_bin = rootfs.join("usr/bin");
        let custom_bin = rootfs.join("custom_tools");
        let dev_dir = rootfs.join("dev");
        let tmp_dir = rootfs.join("tmp");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&usr_bin).unwrap();
        fs::create_dir_all(&custom_bin).unwrap();
        fs::create_dir_all(&dev_dir).unwrap();
        fs::create_dir_all(&tmp_dir).unwrap();
        let _ = fs::File::create(dev_dir.join("null"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dev_dir.join("null"), fs::Permissions::from_mode(0o666));
            let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777));
        }

        let busybox_path = if Path::new("/usr/bin/busybox").exists() {
            "/usr/bin/busybox"
        } else {
            "/bin/busybox"
        };
        fs::copy(busybox_path, bin_dir.join("busybox")).unwrap();

        // 1. In-rootfs symlink: /usr/bin/my_sh -> /bin/busybox
        #[cfg(unix)]
        std::os::unix::fs::symlink("/bin/busybox", usr_bin.join("my_sh")).unwrap();

        // 2. Custom tool in custom_tools: custom_echo -> /bin/busybox
        #[cfg(unix)]
        std::os::unix::fs::symlink("/bin/busybox", custom_bin.join("custom_echo")).unwrap();

        // 3. Malicious symlink targeting path outside rootfs
        #[cfg(unix)]
        std::os::unix::fs::symlink("../../../../../../etc/shadow", rootfs.join("bad_escape"))
            .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();

        // A. Bare executable resolved along multiple PATH entries
        let mut spec_bare = Spec::default_linux();
        if let Some(proc) = &mut spec_bare.process {
            proc.env = vec!["PATH=/nonexistent:/custom_tools:/bin".to_string()];
            proc.args = vec![
                "custom_echo".to_string(),
                "echo".to_string(),
                "bare_ok".to_string(),
            ];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec_bare).unwrap(),
        )
        .unwrap();

        let _ = executor.create("test-path-bare", &bundle_dir).unwrap();
        let res_bare = executor.start("test-path-bare");
        assert!(
            res_bare.is_ok(),
            "Bare executable in PATH should start successfully"
        );
        let _ = executor.delete("test-path-bare", true);

        // B. Symlinked executable inside rootfs
        let mut spec_sym = Spec::default_linux();
        if let Some(proc) = &mut spec_sym.process {
            proc.env = vec!["PATH=/usr/bin".to_string()];
            proc.args = vec!["my_sh".to_string(), "true".to_string()];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec_sym).unwrap(),
        )
        .unwrap();

        let _ = executor.create("test-path-sym", &bundle_dir).unwrap();
        let res_sym = executor.start("test-path-sym");
        assert!(
            res_sym.is_ok(),
            "Symlinked executable inside rootfs should start successfully"
        );
        let _ = executor.delete("test-path-sym", true);

        // C. Relative executable path ("./bin/busybox")
        let mut spec_rel = Spec::default_linux();
        if let Some(proc) = &mut spec_rel.process {
            proc.cwd = "/".to_string();
            proc.args = vec!["./bin/busybox".to_string(), "true".to_string()];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec_rel).unwrap(),
        )
        .unwrap();

        let _ = executor.create("test-path-rel", &bundle_dir).unwrap();
        let res_rel = executor.start("test-path-rel");
        assert!(
            res_rel.is_ok(),
            "Relative executable path should start successfully"
        );
        let _ = executor.delete("test-path-rel", true);

        // D. Missing executable fails startup
        let mut spec_missing = Spec::default_linux();
        if let Some(proc) = &mut spec_missing.process {
            proc.env = vec!["PATH=/bin".to_string()];
            proc.args = vec!["nonexistent_tool_12345".to_string()];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec_missing).unwrap(),
        )
        .unwrap();

        let _ = executor.create("test-path-missing", &bundle_dir).unwrap();
        let res_missing = executor.start("test-path-missing");
        assert!(res_missing.is_err(), "Missing executable must fail startup");
        let _ = executor.delete("test-path-missing", true);

        // E. Malicious symlink escape fails startup safely
        let mut spec_escape = Spec::default_linux();
        if let Some(proc) = &mut spec_escape.process {
            proc.args = vec!["/bad_escape".to_string()];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec_escape).unwrap(),
        )
        .unwrap();

        let _ = executor.create("test-path-escape", &bundle_dir).unwrap();
        let res_escape = executor.start("test-path-escape");
        assert!(
            res_escape.is_err(),
            "Malicious escaping symlink must fail startup safely"
        );
        let _ = executor.delete("test-path-escape", true);
    }
}

#[test]
fn test_stop_semantics_rejects_sigstop_and_escalates_sigkill() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let executor = ContainerExecutor::new(state_dir.clone()).unwrap();

    // 1. Verify stop rejects suspend/resume signals
    #[cfg(unix)]
    {
        // Container that does not exist or invalid state
        let err_stop = executor
            .stop("nonexistent", Some(libc::SIGSTOP), None)
            .unwrap_err();
        assert!(matches!(
            err_stop,
            tavik_common::error::TavikError::NotFound(_)
        ));
    }

    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful stop escalation test (requires root)");
            return;
        }

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

        // Workload that traps and ignores SIGTERM: requires SIGKILL escalation to stop!
        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "trap '' TERM; while true; do /bin/busybox sleep 1; done".to_string(),
            ];
        }

        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let container_id = "test-stop-escalate";
        let _ = executor.create(container_id, &bundle_dir).unwrap();
        let running_state = executor.start(container_id).unwrap();
        assert_eq!(running_state.status, ContainerStatus::Running);

        // Reject SIGSTOP
        let res_sigstop = executor.stop(container_id, Some(libc::SIGSTOP), None);
        assert!(matches!(
            res_sigstop,
            Err(tavik_common::error::TavikError::InvalidState(_))
        ));

        // Reject SIGCONT
        let res_sigcont = executor.stop(container_id, Some(libc::SIGCONT), None);
        assert!(matches!(
            res_sigcont,
            Err(tavik_common::error::TavikError::InvalidState(_))
        ));

        // Stop with short 100ms grace period: SIGTERM ignored -> escalates to SIGKILL!
        let stopped_state = executor
            .stop(
                container_id,
                Some(libc::SIGTERM),
                Some(Duration::from_millis(100)),
            )
            .expect("Stop with SIGKILL escalation must succeed");
        assert_eq!(stopped_state.status, ContainerStatus::Stopped);

        let loaded = executor.load_state(container_id).unwrap();
        assert_eq!(loaded.status, ContainerStatus::Stopped);

        let _ = executor.delete(container_id, true);
    }
}

#[test]
fn test_cgroup_failure_cleanup_raii() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful cgroup cleanup test (requires root)");
            return;
        }

        let mgr = match tavik_cgroups::CgroupManager::new() {
            Ok(m) => m,
            Err(_) => return,
        };

        let container_id = "test-cgroup-raii-cleanup";
        let cgroup_dir = match mgr.create_container_cgroup(container_id) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert!(cgroup_dir.exists());

        // Scope with active CgroupGuard: when dropped without disarm(), destroys cgroup!
        {
            let guard =
                tavik_runtime::init::CgroupGuard::new(mgr.clone(), container_id.to_string());
            assert_eq!(
                guard.manager().container_cgroup_dir(container_id).unwrap(),
                cgroup_dir
            );
            // Drop guard simulating failure before ownership transfer
        }

        assert!(
            !cgroup_dir.exists(),
            "Cgroup directory {:?} should have been automatically destroyed on guard drop",
            cgroup_dir
        );
    }
}
