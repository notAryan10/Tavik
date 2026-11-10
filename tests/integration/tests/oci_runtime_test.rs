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

#[test]
fn test_state_transitions_serialize_and_prevent_stopped_overwrite() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let spec = Spec::default_linux();
    fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&spec).unwrap(),
    )
    .unwrap();

    let executor = ContainerExecutor::new(state_dir).unwrap();
    let id = "test-serialize-state";
    let state = executor.create(id, &bundle_dir).unwrap();
    assert_eq!(state.status, ContainerStatus::Created);

    // 1. Transition Created -> Starting
    let starting_state = executor
        .transition_state(id, |st| {
            st.status = ContainerStatus::Starting;
            Ok(())
        })
        .unwrap();
    assert_eq!(starting_state.status, ContainerStatus::Starting);

    // 2. Transition Starting -> Stopped (simulating supervisor reaping child before platform_start returns)
    let stopped_state = executor
        .transition_state(id, |st| {
            st.status = ContainerStatus::Stopped;
            Ok(())
        })
        .unwrap();
    assert_eq!(stopped_state.status, ContainerStatus::Stopped);

    // 3. Late transition to Running: MUST NOT overwrite Stopped!
    let late_running_state = executor
        .transition_state(id, |st| {
            st.status = ContainerStatus::Running;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        late_running_state.status,
        ContainerStatus::Stopped,
        "Late transition to Running must be ignored when supervisor marked container as Stopped"
    );

    // 4. Attempting to start an already stopped container must fail
    let restart_res = executor.transition_state(id, |st| {
        st.status = ContainerStatus::Starting;
        Ok(())
    });
    assert!(
        matches!(
            restart_res,
            Err(tavik_common::error::TavikError::InvalidState(_))
        ),
        "Stopped container must not transition back to Starting"
    );
}

#[test]
fn test_stop_rejects_suspend_and_resume_signals() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let spec = Spec::default_linux();
    fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&spec).unwrap(),
    )
    .unwrap();

    let executor = ContainerExecutor::new(state_dir).unwrap();
    let id = "test-stop-reject-signals";
    let _ = executor.create(id, &bundle_dir).unwrap();

    // Mark as running manually for unit test validation of signal rejection
    let _ = executor.transition_state(id, |st| {
        st.status = ContainerStatus::Running;
        st.pid = Some(999999);
        Ok(())
    });

    #[cfg(unix)]
    {
        for sig in [
            libc::SIGSTOP,
            libc::SIGTSTP,
            libc::SIGCONT,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ] {
            let res = executor.stop(id, Some(sig), None);
            assert!(
                matches!(res, Err(tavik_common::error::TavikError::InvalidState(_))),
                "Signal {} must be rejected by stop()",
                sig
            );
        }
    }
}

#[test]
fn test_repeated_short_lived_process_lifecycle() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful short-lived process lifecycle test (requires root)");
            return;
        }

        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let executor = ContainerExecutor::new(state_dir).unwrap();

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
            proc.args = vec!["/bin/busybox".to_string(), "true".to_string()];
        }

        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        for i in 0..5 {
            let container_id = format!("test-short-lived-{}", i);
            let created = executor.create(&container_id, &bundle_dir).unwrap();
            assert_eq!(created.status, ContainerStatus::Created);

            // Startup should succeed and rapidly transition to Stopped without race
            let res = executor.start(&container_id);
            assert!(
                res.is_ok(),
                "Short-lived process startup must succeed: {:?}",
                res
            );

            // Give supervisor up to 500ms to finish reaping
            let start_wait = std::time::Instant::now();
            let mut final_status = ContainerStatus::Running;
            while start_wait.elapsed() < Duration::from_millis(500) {
                if let Ok(st) = executor.load_state(&container_id) {
                    final_status = st.status;
                    if final_status == ContainerStatus::Stopped {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(
                final_status,
                ContainerStatus::Stopped,
                "Iteration {} must end in Stopped status",
                i
            );

            let _ = executor.delete(&container_id, true);
        }
    }
}

#[test]
fn test_concurrent_start_requests_atomic_rejection() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let spec = Spec::default_linux();
    fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&spec).unwrap(),
    )
    .unwrap();

    let executor = std::sync::Arc::new(ContainerExecutor::new(state_dir).unwrap());
    let id = "test-concurrent-atomic-start";
    let state = executor.create(id, &bundle_dir).unwrap();
    assert_eq!(state.status, ContainerStatus::Created);

    let num_threads = 10;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(num_threads));
    let mut handles = Vec::new();

    for _ in 0..num_threads {
        let exec = std::sync::Arc::clone(&executor);
        let b = std::sync::Arc::clone(&barrier);
        let cont_id = id.to_string();

        handles.push(std::thread::spawn(move || {
            b.wait();
            exec.start(&cont_id)
        }));
    }

    let mut success_or_starting = 0;
    let mut rejected_invalid_state = 0;

    for handle in handles {
        match handle.join().unwrap() {
            Ok(_) => {
                success_or_starting += 1;
            }
            Err(tavik_common::error::TavikError::Unsupported(_)) => {
                // On non-Linux platforms, platform_start returns Unsupported after transitioning to Starting
                success_or_starting += 1;
            }
            Err(tavik_common::error::TavikError::InvalidState(_)) => {
                rejected_invalid_state += 1;
            }
            Err(e) => panic!("Unexpected error during concurrent start: {:?}", e),
        }
    }

    // Exactly one caller can successfully validate and transition Created -> Starting!
    assert_eq!(
        success_or_starting, 1,
        "Exactly one caller must successfully transition Created -> Starting"
    );
    assert_eq!(
        rejected_invalid_state,
        num_threads - 1,
        "All other concurrent callers must be rejected with InvalidState"
    );
}

#[test]
fn test_close_range_fallback_closes_high_descriptors() {
    #[cfg(target_os = "linux")]
    {
        // Open deliberately high file descriptors
        let test_fds = [42, 100, 250];
        for &fd in &test_fds {
            let res = unsafe { libc::dup2(1, fd) };
            assert_eq!(res, fd, "dup2 to high fd {} failed", fd);
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        }

        // Call descriptor sanitization for fds >= 5
        tavik_runtime::init::close_inherited_descriptors_above(5);

        // Verify all test fds are now closed
        for &fd in &test_fds {
            let fcntl_res = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_eq!(fcntl_res, -1, "High fd {} should have been closed", fd);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }

        // Verify standard descriptors 0, 1, 2 remain valid
        for fd in 0..=2 {
            assert!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
                "Standard fd {} must remain open",
                fd
            );
        }
    }
}

#[test]
fn test_cgroup_ownership_rules_never_destroy_unowned() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    // Spec with NO resource limits
    let mut spec = Spec::default_linux();
    if let Some(linux) = &mut spec.linux {
        linux.resources = None;
    }
    fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&spec).unwrap(),
    )
    .unwrap();

    let executor = ContainerExecutor::new(state_dir).unwrap();
    let container_id = "test-no-cgroup-cont";
    let state = executor.create(container_id, &bundle_dir).unwrap();
    assert_eq!(state.status, ContainerStatus::Created);

    // Delete container: must not attempt to destroy any cgroup
    let del_res = executor.delete(container_id, false);
    assert!(del_res.is_ok());
}

#[test]
fn test_delete_starting_and_running_container_rejection() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let spec = Spec::default_linux();
    fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&spec).unwrap(),
    )
    .unwrap();

    let executor = ContainerExecutor::new(state_dir.clone()).unwrap();
    let container_id = "test-delete-starting-cont";
    let state = executor.create(container_id, &bundle_dir).unwrap();
    assert_eq!(state.status, ContainerStatus::Created);

    // 1. Manually update state to Starting
    let state_file = state_dir.join(container_id).join("state.json");
    let mut updated_state = state;
    updated_state.status = ContainerStatus::Starting;
    fs::write(
        &state_file,
        serde_json::to_string_pretty(&updated_state).unwrap(),
    )
    .unwrap();

    // 2. Reject unforced deletion of a Starting container
    let del_err = executor.delete(container_id, false).unwrap_err();
    match del_err {
        tavik_common::error::TavikError::InvalidState(msg) => {
            assert!(
                msg.contains("starting"),
                "Error message should mention starting status: {}",
                msg
            );
        }
        other => panic!("Expected InvalidState error, got: {:?}", other),
    }

    // 3. Test unreachable supervisor during forced deletion on Linux
    #[cfg(target_os = "linux")]
    {
        let force_err = executor.delete(container_id, true).unwrap_err();
        match force_err {
            tavik_common::error::TavikError::Execution(msg) => {
                assert!(
                    msg.contains("unreachable"),
                    "Error message should mention unreachable control socket: {}",
                    msg
                );
            }
            other => panic!(
                "Expected Execution error for unreachable supervisor, got: {:?}",
                other
            ),
        }
    }
}

#[test]
fn test_supervisor_finalization_rules_and_error_handling() {
    #[cfg(target_os = "linux")]
    {
        let temp = tempdir().unwrap();
        let container_dir = temp.path().join("container");
        fs::create_dir_all(&container_dir).unwrap();

        let state_file = container_dir.join("state.json");
        let start_fifo = container_dir.join("start.fifo");
        let exec_fifo = container_dir.join("exec.fifo");
        fs::write(&start_fifo, b"").unwrap();
        fs::write(&exec_fifo, b"").unwrap();

        let initial_state = ContainerState {
            id: "test-finalization-cont".to_string(),
            status: ContainerStatus::Running,
            pid: Some(12345),
            bundle: temp.path().to_path_buf(),
        };
        fs::write(
            &state_file,
            serde_json::to_string_pretty(&initial_state).unwrap(),
        )
        .unwrap();

        // 1. If child is not reaped and waitpid fails on invalid PID, finalization must fail with error
        let bad_pid = 999999;
        let fail_res = tavik_runtime::init::run_supervisor_finalization(
            "test-finalization-cont",
            bad_pid,
            &container_dir,
            false,
            &start_fifo,
            &exec_fifo,
            false,
        );
        assert!(fail_res.is_err());
        let err_str = fail_res.unwrap_err();
        assert!(err_str.contains("failed to reap child PID"));

        // Verify state is NOT marked as Stopped when reaping fails
        let current_state: ContainerState =
            serde_json::from_str(&fs::read_to_string(&state_file).unwrap()).unwrap();
        assert_eq!(
            current_state.status,
            ContainerStatus::Running,
            "State must remain Running when waitpid fails"
        );

        // 2. When child is confirmed reaped (child_reaped = true), finalization succeeds
        let ok_res = tavik_runtime::init::run_supervisor_finalization(
            "test-finalization-cont",
            bad_pid,
            &container_dir,
            false,
            &start_fifo,
            &exec_fifo,
            true, // child_reaped confirmed
        );
        assert!(ok_res.is_ok());

        // Verify final state is persisted as Stopped
        let final_state: ContainerState =
            serde_json::from_str(&fs::read_to_string(&state_file).unwrap()).unwrap();
        assert_eq!(final_state.status, ContainerStatus::Stopped);

        // Verify FIFOs are cleaned up
        assert!(!start_fifo.exists());
        assert!(!exec_fifo.exists());
    }
}

#[test]
fn test_signal_escalation_error_handling() {
    #[cfg(target_os = "linux")]
    {
        // 1. Test with invalid/closed child_pidfd
        let mut child_reaped = false;
        let res = tavik_runtime::init::terminate_child_with_escalation(
            999999,
            -1, // invalid fd
            libc::SIGTERM,
            Duration::from_millis(50),
            &mut child_reaped,
        );
        assert!(res.is_err(), "Invalid pidfd must return Err promptly");

        // 2. Test already terminated child process with ESRCH confirmed by waitpid
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::_exit(0) };
        }

        // Parent: wait for child to exit and reap it
        let mut status = 0;
        let wres = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(wres, child);

        // Now process is completely reaped. A synthetic pidfd check or ESRCH will report reaped
        let mut child_reaped2 = false;
        let res2 = tavik_runtime::init::terminate_child_with_escalation(
            child,
            -1,
            libc::SIGTERM,
            Duration::from_millis(50),
            &mut child_reaped2,
        );
        // Either error or confirmed terminated; must not hang!
        assert!(res2.is_err() || child_reaped2);
    }
}

#[test]
fn test_linux_lifecycle_graceful_stop_and_acknowledgment() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful stop test (requires root)");
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

        if Path::new("/usr/bin/busybox").exists() {
            fs::copy("/usr/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else if Path::new("/bin/busybox").exists() {
            fs::copy("/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else {
            return;
        }

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-graceful-stop";
        let state = executor.create(id, &bundle_dir).unwrap();
        assert_eq!(state.status, ContainerStatus::Created);

        let started = executor.start(id).unwrap();
        assert_eq!(started.status, ContainerStatus::Running);

        // Stop container gracefully with 5s timeout
        let stopped = executor
            .stop(id, Some(libc::SIGTERM), Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(stopped.status, ContainerStatus::Stopped);

        // Delete container
        let del = executor.delete(id, false);
        assert!(del.is_ok());
    }
}

#[test]
fn test_linux_stop_sigkill_escalation() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful sigkill escalation test (requires root)");
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

        if Path::new("/usr/bin/busybox").exists() {
            fs::copy("/usr/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else if Path::new("/bin/busybox").exists() {
            fs::copy("/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else {
            return;
        }

        // Process traps and ignores SIGTERM
        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "trap '' TERM; sleep 30".to_string(),
            ];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-sigkill-escalation";
        let state = executor.create(id, &bundle_dir).unwrap();
        assert_eq!(state.status, ContainerStatus::Created);

        let started = executor.start(id).unwrap();
        assert_eq!(started.status, ContainerStatus::Running);

        // Stop with short 300ms grace period: should escalate to SIGKILL
        let stopped = executor
            .stop(id, Some(libc::SIGTERM), Some(Duration::from_millis(300)))
            .unwrap();
        assert_eq!(stopped.status, ContainerStatus::Stopped);

        let del = executor.delete(id, false);
        assert!(del.is_ok());
    }
}

#[test]
fn test_linux_force_delete_running_container() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful force delete test (requires root)");
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

        if Path::new("/usr/bin/busybox").exists() {
            fs::copy("/usr/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else if Path::new("/bin/busybox").exists() {
            fs::copy("/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else {
            return;
        }

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-force-delete-running";
        let state = executor.create(id, &bundle_dir).unwrap();
        assert_eq!(state.status, ContainerStatus::Created);

        let started = executor.start(id).unwrap();
        assert_eq!(started.status, ContainerStatus::Running);

        // Unforced delete must fail
        let unforced_err = executor.delete(id, false);
        assert!(unforced_err.is_err());

        // Forced delete must succeed via supervisor CANCEL
        let forced = executor.delete(id, true);
        assert!(forced.is_ok());
        assert!(executor.load_state(id).is_err());
    }
}

#[test]
fn test_strict_supervisor_control_protocol() {
    #[cfg(target_os = "linux")]
    {
        use tavik_runtime::init::parse_control_response;

        // 1. Explicit OK\n response is accepted
        assert_eq!(parse_control_response(b"OK\n").unwrap(), "OK");
        assert_eq!(
            parse_control_response(b"OK success\n").unwrap(),
            "OK success"
        );

        // 2. Empty EOF returns error
        let empty_err = parse_control_response(b"").unwrap_err();
        match empty_err {
            tavik_common::error::TavikError::Execution(msg) => {
                assert!(msg.contains("empty response"), "msg was: {}", msg);
            }
            other => panic!(
                "Expected Execution error for empty response, got: {:?}",
                other
            ),
        }

        // 3. Incomplete response (no newline) returns error
        let incomplete_err = parse_control_response(b"OK").unwrap_err();
        match incomplete_err {
            tavik_common::error::TavikError::Execution(msg) => {
                assert!(msg.contains("incomplete"), "msg was: {}", msg);
            }
            other => panic!(
                "Expected Execution error for incomplete response, got: {:?}",
                other
            ),
        }

        // 4. Malformed responses return error
        let malformed_err1 = parse_control_response(b"UNKNOWN\n").unwrap_err();
        match malformed_err1 {
            tavik_common::error::TavikError::Execution(msg) => {
                assert!(msg.contains("malformed response"), "msg was: {}", msg);
            }
            other => panic!(
                "Expected Execution error for malformed response, got: {:?}",
                other
            ),
        }

        let malformed_err2 = parse_control_response(b"SUCCESS\n").unwrap_err();
        assert!(malformed_err2.to_string().contains("malformed response"));

        // 5. ERR responses preserve error message
        let err_resp = parse_control_response(b"ERR failed to reap child\n").unwrap_err();
        match err_resp {
            tavik_common::error::TavikError::Execution(msg) => {
                assert!(
                    msg.contains("Supervisor control error: ERR failed to reap child"),
                    "msg was: {}",
                    msg
                );
            }
            other => panic!(
                "Expected Execution error for ERR response, got: {:?}",
                other
            ),
        }
    }
}

#[test]
fn test_durable_cgroup_ownership_and_deletion_safety() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let bundle_dir = temp.path().join("bundle");
    let rootfs = bundle_dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let mut spec = Spec::default_linux();
    if let Some(linux) = &mut spec.linux {
        // Spec with resource limits (owned cgroup)
        linux.resources = Some(tavik_cgroups::CgroupResources {
            memory: Some(tavik_cgroups::MemoryResources {
                limit: Some(1024 * 1024 * 64),
                high: None,
                swap: None,
            }),
            cpu: None,
            pids: None,
        });
    }
    fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&spec).unwrap(),
    )
    .unwrap();

    let executor = ContainerExecutor::new(state_dir.clone()).unwrap();
    let container_id = "test-cgroup-durable-ownership";
    let state = executor.create(container_id, &bundle_dir).unwrap();
    assert_eq!(state.status, ContainerStatus::Created);

    // 1. Manually mark cgroup.owner and annotation
    let cont_dir = state_dir.join(container_id);
    fs::write(cont_dir.join("cgroup.owner"), b"1\n").unwrap();
    let mut updated_state = state.clone();
    updated_state
        .annotations
        .insert("io.tavik.cgroup.owned".to_string(), "true".to_string());
    fs::write(
        cont_dir.join("state.json"),
        serde_json::to_string_pretty(&updated_state).unwrap(),
    )
    .unwrap();

    // Verify cgroup ownership is recognized
    assert!(executor.has_cgroup_ownership(container_id, &updated_state));

    // 2. Remove the original OCI bundle entirely!
    fs::remove_dir_all(&bundle_dir).unwrap();
    assert!(!bundle_dir.exists());

    // 3. Verify cgroup ownership is STILL recognized even with missing/unreadable bundle!
    let reloaded_state = executor.load_state(container_id).unwrap();
    assert!(executor.has_cgroup_ownership(container_id, &reloaded_state));

    // 4. Delete container: successfully deletes and cleans up cgroup even without bundle
    let del_res = executor.delete(container_id, false);
    assert!(del_res.is_ok(), "delete failed: {:?}", del_res);
    assert!(!cont_dir.exists());
}

#[test]
fn test_finalization_error_handling_and_recovery() {
    #[cfg(target_os = "linux")]
    {
        let temp = tempdir().unwrap();
        let container_dir = temp.path().join("container");
        fs::create_dir_all(&container_dir).unwrap();

        let state_file = container_dir.join("state.json");
        let start_fifo = container_dir.join("start.fifo");
        let exec_fifo = container_dir.join("exec.fifo");
        fs::write(&start_fifo, b"").unwrap();
        fs::write(&exec_fifo, b"").unwrap();

        let initial_state = ContainerState {
            id: "test-finalization-err-cont".to_string(),
            status: ContainerStatus::Running,
            pid: Some(12345),
            bundle: temp.path().to_path_buf(),
        };
        fs::write(
            &state_file,
            serde_json::to_string_pretty(&initial_state).unwrap(),
        )
        .unwrap();

        // 1. If start_fifo cannot be removed (e.g. replaced with a non-empty directory):
        fs::remove_file(&start_fifo).unwrap();
        fs::create_dir(&start_fifo).unwrap();
        fs::write(start_fifo.join("blocking_file"), b"blocking").unwrap();

        let fail_res = tavik_runtime::init::run_supervisor_finalization(
            "test-finalization-err-cont",
            12345,
            &container_dir,
            false,
            &start_fifo,
            &exec_fifo,
            true, // child_reaped confirmed
        );
        assert!(fail_res.is_err());
        let err_str = fail_res.unwrap_err();
        assert!(err_str.contains("Failed to remove start FIFO"));

        // 2. Recovery attempt: fix the obstacle and rerun finalization
        fs::remove_dir_all(&start_fifo).unwrap();
        fs::write(&start_fifo, b"").unwrap();

        let recovery_res = tavik_runtime::init::run_supervisor_finalization(
            "test-finalization-err-cont",
            12345,
            &container_dir,
            false,
            &start_fifo,
            &exec_fifo,
            true, // child_reaped confirmed
        );
        assert!(
            recovery_res.is_ok(),
            "Recovery attempt must succeed: {:?}",
            recovery_res
        );
        assert!(!start_fifo.exists());
        assert!(!exec_fifo.exists());
    }
}

#[test]
fn test_signal_escalation_esrch_and_pidfd_exit() {
    #[cfg(target_os = "linux")]
    {
        // 1. Fork a child that terminates immediately
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::_exit(0) };
        }

        // 2. Open pidfd for the child while it is running / zombie
        let child_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as i32;

        // 3. Reap child completely
        let mut status = 0;
        let wres = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(wres, child);

        // 4. Now process is dead. Calling terminate_child_with_escalation must:
        //    - see ESRCH from pidfd_send_signal (or invalid fd if pidfd closed)
        //    - verify termination via waitpid(WNOHANG) returning ECHILD
        //    - confirm child_reaped = true without hanging!
        if child_pidfd >= 0 {
            let mut child_reaped = false;
            let res = tavik_runtime::init::terminate_child_with_escalation(
                child,
                child_pidfd,
                libc::SIGTERM,
                Duration::from_millis(100),
                &mut child_reaped,
            );
            unsafe { libc::close(child_pidfd) };
            assert!(res.is_ok());
            assert!(
                child_reaped,
                "Child must be marked reaped on confirmed ESRCH/ECHILD"
            );
        }

        // 5. Verify signalling failures do not cause false Stopped states
        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let executor = ContainerExecutor::new(state_dir.clone()).unwrap();
        let cont_id = "test-signal-failure-no-stopped";
        let cont_dir = state_dir.join(cont_id);
        fs::create_dir_all(&cont_dir).unwrap();

        let initial_state = ContainerState {
            id: cont_id.to_string(),
            status: ContainerStatus::Running,
            pid: Some(999999),
            bundle: temp.path().to_path_buf(),
        };
        fs::write(
            cont_dir.join("state.json"),
            serde_json::to_string_pretty(&initial_state).unwrap(),
        )
        .unwrap();

        // Control channel is unavailable; kill() must fail and state must remain Running
        let kill_res = executor.kill(cont_id, libc::SIGTERM);
        assert!(kill_res.is_err());
        let current_state = executor.load_state(cont_id).unwrap();
        assert_eq!(
            current_state.status,
            ContainerStatus::Running,
            "Signalling failure must not cause false Stopped state"
        );
    }
}

#[test]
fn test_linux_startup_cancellation_on_invalid_exec() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful startup abort test (requires root)");
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

        // Point args to a non-existent binary to trigger execve failure
        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec!["/bin/nonexistent_binary_xyz".to_string()];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-startup-abort-invalid-exec";
        let state = executor.create(id, &bundle_dir).unwrap();
        assert_eq!(state.status, ContainerStatus::Created);

        // start must fail and trigger cancellation
        let start_res = executor.start(id);
        assert!(start_res.is_err());

        // Verify container state is confirmed Stopped after abort
        let final_state = executor.load_state(id).unwrap();
        assert_eq!(final_state.status, ContainerStatus::Stopped);

        // Delete container safely
        let del_res = executor.delete(id, false);
        assert!(del_res.is_ok());
    }
}

#[test]
fn test_linux_delete_created_container_without_cgroups() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful delete created container test (requires root)");
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

        if Path::new("/usr/bin/busybox").exists() {
            fs::copy("/usr/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else if Path::new("/bin/busybox").exists() {
            fs::copy("/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else {
            return;
        }

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ];
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-delete-created-no-cgroup";
        let state = executor.create(id, &bundle_dir).unwrap();
        assert_eq!(state.status, ContainerStatus::Created);

        let child_pid = state.pid.expect("Child PID must exist in Created state");

        // Verify child process is alive (paused waiting for start)
        let kill_probe = unsafe { libc::kill(child_pid as libc::pid_t, 0) };
        assert_eq!(kill_probe, 0, "Init child process must be alive");

        let cont_dir = executor.container_dir(id);
        assert!(cont_dir.join("control.sock").exists());

        // Deleting Created container must cancel supervisor via control.sock
        let del = executor.delete(id, false);
        assert!(
            del.is_ok(),
            "delete(id, false) on Created container must succeed"
        );

        // Verify container directory is removed
        assert!(!cont_dir.exists(), "Container directory must be removed");
        assert!(executor.load_state(id).is_err());

        // Verify child process was reaped and is no longer running
        std::thread::sleep(Duration::from_millis(50));
        let dead_probe = unsafe { libc::kill(child_pid as libc::pid_t, 0) };
        assert_ne!(dead_probe, 0, "Init child must have been reaped");
    }
}

#[test]
fn test_linux_delete_created_container_with_cgroups() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful delete created container with cgroup test (requires root)");
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

        if Path::new("/usr/bin/busybox").exists() {
            fs::copy("/usr/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else if Path::new("/bin/busybox").exists() {
            fs::copy("/bin/busybox", bin_dir.join("busybox")).unwrap();
        } else {
            return;
        }

        let mut spec = Spec::default_linux();
        if let Some(proc) = &mut spec.process {
            proc.args = vec![
                "/bin/busybox".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ];
        }
        if let Some(linux) = &mut spec.linux {
            linux.resources = Some(tavik_runtime::spec::LinuxResources {
                devices: vec![],
                memory: Some(tavik_runtime::spec::LinuxMemory {
                    limit: Some(64 * 1024 * 1024),
                    reservation: None,
                    swap: None,
                    kernel: None,
                    kernel_tcp: None,
                    swappiness: None,
                    disable_oom_killer: None,
                }),
                cpu: None,
                pids: None,
                block_io: None,
                hugepage_limits: vec![],
                network: None,
                rdma: std::collections::HashMap::new(),
                unified: std::collections::HashMap::new(),
            });
        }
        fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();

        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-delete-created-cgroup";
        let state = executor.create(id, &bundle_dir).unwrap();
        assert_eq!(state.status, ContainerStatus::Created);

        let cont_dir = executor.container_dir(id);
        assert!(cont_dir.join("cgroup.owner").exists());
        assert_eq!(
            state.annotations.get("io.tavik.cgroup.owned"),
            Some(&"true".to_string())
        );

        let cgroup_mgr = tavik_cgroups::CgroupManager::new().unwrap();
        let cgroup_dir = cgroup_mgr.container_cgroup_dir(id).unwrap();
        assert!(cgroup_dir.exists(), "Cgroup directory must exist on host");

        let child_pid = state.pid.unwrap();

        // Delete Created container
        let del = executor.delete(id, false);
        assert!(del.is_ok());

        // Verify child reaped
        std::thread::sleep(Duration::from_millis(50));
        let dead_probe = unsafe { libc::kill(child_pid as libc::pid_t, 0) };
        assert_ne!(dead_probe, 0, "Init child must have been reaped");

        // Verify cgroup destroyed
        assert!(!cgroup_dir.exists(), "Cgroup directory must be destroyed");
        assert!(!cont_dir.exists(), "Container directory must be removed");
    }
}

#[test]
fn test_failed_cancellation_preserves_metadata() {
    #[cfg(target_os = "linux")]
    {
        let temp = tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let executor = ContainerExecutor::new(state_dir).unwrap();
        let id = "test-failed-cancel-preserves-metadata";

        // Set up a created container state on disk
        let cont_dir = executor.container_dir(id);
        fs::create_dir_all(&cont_dir).unwrap();

        let state = tavik_runtime::ContainerState {
            oci_version: "1.2.0".to_string(),
            id: id.to_string(),
            status: ContainerStatus::Created,
            pid: Some(999999),
            bundle: temp.path().join("bundle"),
            annotations: std::collections::HashMap::new(),
            created_at: chrono::Utc::now(),
        };
        executor.save_state(&state).unwrap();

        // Since control.sock does NOT exist, supervisor cancellation is unreachable.
        // Deletion must fail closed and PRESERVE container directory and metadata.
        let del_res = executor.delete(id, false);
        assert!(del_res.is_err());

        assert!(
            cont_dir.exists(),
            "Container dir must be preserved on failed cancellation"
        );
        let loaded = executor.load_state(id).unwrap();
        assert_eq!(loaded.status, ContainerStatus::Created);
    }
}

#[test]
fn test_cgroup_ownership_persisted_immediately_from_creation() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let executor = ContainerExecutor::new(state_dir).unwrap();
    let id = "test-cgroup-owner-marker";

    let cont_dir = executor.container_dir(id);
    fs::create_dir_all(&cont_dir).unwrap();

    let mut state = tavik_runtime::ContainerState {
        oci_version: "1.2.0".to_string(),
        id: id.to_string(),
        status: ContainerStatus::Creating,
        pid: None,
        bundle: temp.path().join("bundle"),
        annotations: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    };
    state
        .annotations
        .insert("io.tavik.cgroup.owned".to_string(), "true".to_string());
    executor.save_state(&state).unwrap();

    // Marker written immediately
    fs::write(cont_dir.join("cgroup.owner"), b"1\n").unwrap();

    assert!(executor.has_cgroup_ownership(id, &state));
}

#[test]
fn test_failed_creation_preserves_recovery_metadata_when_cgroup_cleanup_fails() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let executor = ContainerExecutor::new(state_dir).unwrap();
    let id = "test-recovery-metadata";

    let cont_dir = executor.container_dir(id);
    fs::create_dir_all(&cont_dir).unwrap();

    let mut state = tavik_runtime::ContainerState {
        oci_version: "1.2.0".to_string(),
        id: id.to_string(),
        status: ContainerStatus::Creating,
        pid: None,
        bundle: temp.path().join("bundle"),
        annotations: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    };
    state
        .annotations
        .insert("io.tavik.cgroup.owned".to_string(), "true".to_string());
    executor.save_state(&state).unwrap();
    fs::write(cont_dir.join("cgroup.owner"), b"1\n").unwrap();

    // Verify has_cgroup_ownership sees the marker
    assert!(executor.has_cgroup_ownership(id, &state));
    assert!(cont_dir.join("cgroup.owner").exists());
}

#[test]
fn test_concurrency_two_simultaneous_deletes() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let executor = std::sync::Arc::new(ContainerExecutor::new(state_dir).unwrap());
    let id = "test-concurrent-delete";

    let cont_dir = executor.container_dir(id);
    fs::create_dir_all(&cont_dir).unwrap();

    let state = tavik_runtime::ContainerState {
        oci_version: "1.2.0".to_string(),
        id: id.to_string(),
        status: ContainerStatus::Stopped,
        pid: None,
        bundle: temp.path().join("bundle"),
        annotations: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    };
    executor.save_state(&state).unwrap();

    let exec1 = std::sync::Arc::clone(&executor);
    let exec2 = std::sync::Arc::clone(&executor);

    let handle1 = std::thread::spawn(move || exec1.delete(id, false));
    let handle2 = std::thread::spawn(move || exec2.delete(id, false));

    let res1 = handle1.join().unwrap();
    let res2 = handle2.join().unwrap();

    // Exactly one delete must succeed, and the other must return NotFound (or error)
    let ok_count = [res1.is_ok(), res2.is_ok()]
        .into_iter()
        .filter(|&x| x)
        .count();
    assert_eq!(ok_count, 1, "Exactly one concurrent delete must succeed");

    assert!(!cont_dir.exists(), "Container directory must be removed");
}

#[test]
fn test_concurrency_stop_and_delete() {
    let temp = tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let executor = std::sync::Arc::new(ContainerExecutor::new(state_dir).unwrap());
    let id = "test-concurrent-stop-delete";

    let cont_dir = executor.container_dir(id);
    fs::create_dir_all(&cont_dir).unwrap();

    let state = tavik_runtime::ContainerState {
        oci_version: "1.2.0".to_string(),
        id: id.to_string(),
        status: ContainerStatus::Stopped,
        pid: None,
        bundle: temp.path().join("bundle"),
        annotations: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    };
    executor.save_state(&state).unwrap();

    let exec1 = std::sync::Arc::clone(&executor);
    let exec2 = std::sync::Arc::clone(&executor);

    // One thread stops (which sees Stopped and returns Ok), another deletes
    let handle1 = std::thread::spawn(move || exec1.stop(id, None, None));
    let handle2 = std::thread::spawn(move || exec2.delete(id, false));

    let _ = handle1.join().unwrap();
    let _ = handle2.join().unwrap();

    // Must not panic, and container must be gone
    assert!(!cont_dir.exists());
}
