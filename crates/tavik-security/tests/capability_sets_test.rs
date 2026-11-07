use tavik_security::{apply_capabilities, Capability, CapabilitySets, SecurityError};

#[test]
fn test_default_oci_and_empty_sets() {
    let def = CapabilitySets::default_oci();
    assert!(def.bounding.is_some());
    let bnd = def.bounding.as_ref().unwrap();
    assert!(bnd.contains(&Capability::CAP_CHOWN));
    assert!(bnd.contains(&Capability::CAP_KILL));
    assert!(!bnd.contains(&Capability::CAP_SYS_ADMIN));
    assert!(!bnd.contains(&Capability::CAP_SYS_BOOT));

    let empty = CapabilitySets::empty();
    assert_eq!(empty.bounding, Some(Vec::new()));
    assert_eq!(empty.effective, Some(Vec::new()));
}

#[test]
fn test_ambient_validation_rules() {
    // Ambient cap missing from permitted set should be rejected before any syscall
    let invalid_sets = CapabilitySets {
        bounding: Some(vec![Capability::CAP_CHOWN]),
        effective: Some(vec![Capability::CAP_CHOWN]),
        permitted: Some(vec![]), // Missing CAP_CHOWN
        inheritable: Some(vec![Capability::CAP_CHOWN]),
        ambient: Some(vec![Capability::CAP_CHOWN]),
    };

    match apply_capabilities(&invalid_sets) {
        Err(SecurityError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("missing from permitted set"));
        }
        other => panic!("Expected InvalidConfiguration error, got {:?}", other),
    }

    // Ambient cap missing from bounding set should also be rejected
    let invalid_sets2 = CapabilitySets {
        bounding: Some(vec![]), // Missing CAP_CHOWN
        effective: Some(vec![Capability::CAP_CHOWN]),
        permitted: Some(vec![Capability::CAP_CHOWN]),
        inheritable: Some(vec![Capability::CAP_CHOWN]),
        ambient: Some(vec![Capability::CAP_CHOWN]),
    };

    match apply_capabilities(&invalid_sets2) {
        Err(SecurityError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("missing from bounding set"));
        }
        other => panic!("Expected InvalidConfiguration error, got {:?}", other),
    }
}

#[test]
fn test_linux_capabilities_application_in_child_process() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping rootful capability kernel application test (requires root)");
            return;
        }

        // Test actual kernel modifications inside a dedicated child process
        // to protect the test runner / SSH session environment!
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "Failed to fork test child");

        if pid == 0 {
            // Child process: apply restricted capability set
            let target_caps = vec![Capability::CAP_CHOWN, Capability::CAP_KILL];
            let sets = CapabilitySets {
                bounding: Some(target_caps.clone()),
                effective: Some(target_caps.clone()),
                permitted: Some(target_caps),
                inheritable: Some(Vec::new()),
                ambient: Some(Vec::new()),
            };

            if let Err(e) = apply_capabilities(&sets) {
                eprintln!("Child apply_capabilities failed: {}", e);
                unsafe { libc::_exit(1) };
            }

            // Verify that a capability outside the set (e.g. CAP_SYS_ADMIN) is dropped
            // Check bounding set via PR_CAPBSET_READ (23)
            let has_sys_admin = unsafe {
                libc::prctl(
                    23,
                    Capability::CAP_SYS_ADMIN.value() as libc::c_ulong,
                    0,
                    0,
                    0,
                )
            };
            if has_sys_admin != 0 {
                eprintln!("CAP_SYS_ADMIN was not dropped from bounding set!");
                unsafe { libc::_exit(2) };
            }

            let has_chown =
                unsafe { libc::prctl(23, Capability::CAP_CHOWN.value() as libc::c_ulong, 0, 0, 0) };
            if has_chown != 1 {
                eprintln!("CAP_CHOWN is missing from bounding set!");
                unsafe { libc::_exit(3) };
            }

            unsafe { libc::_exit(0) };
        }

        // Parent process: wait for child
        let mut status: i32 = 0;
        let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(wait_res, pid);

        assert!(
            libc::WIFEXITED(status),
            "Child process crashed or was killed by signal"
        );
        let exit_code = libc::WEXITSTATUS(status);
        assert_eq!(
            exit_code, 0,
            "Child process failed capability verification with exit code {}",
            exit_code
        );
    }
}
