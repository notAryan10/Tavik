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
