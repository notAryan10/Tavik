use crate::capability_map::{Capability, CapabilityMap};
use crate::error::SecurityError;
#[cfg(target_os = "linux")]
use std::fs;

/// Linux capability sets as specified by OCI Runtime Specification.
/// An `Option::None` indicates that the set should not be modified,
/// whereas `Option::Some(vec![])` indicates an explicitly empty capability set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySets {
    pub bounding: Option<Vec<Capability>>,
    pub effective: Option<Vec<Capability>>,
    pub permitted: Option<Vec<Capability>>,
    pub inheritable: Option<Vec<Capability>>,
    pub ambient: Option<Vec<Capability>>,
}

impl CapabilitySets {
    /// Returns the standard, safe default capability set recommended by OCI.
    pub fn default_oci() -> Self {
        let default_names = [
            "CAP_AUDIT_WRITE",
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_MKNOD",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_RAW",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ];
        let caps = CapabilityMap::parse_all(default_names).unwrap_or_default();
        Self {
            bounding: Some(caps.clone()),
            effective: Some(caps.clone()),
            permitted: Some(caps),
            inheritable: Some(Vec::new()),
            ambient: Some(Vec::new()),
        }
    }

    /// Returns an explicitly empty capability set (all capabilities dropped).
    pub fn empty() -> Self {
        Self {
            bounding: Some(Vec::new()),
            effective: Some(Vec::new()),
            permitted: Some(Vec::new()),
            inheritable: Some(Vec::new()),
            ambient: Some(Vec::new()),
        }
    }
}

/// Drops unrequested capabilities from the thread's bounding set.
/// In Linux, PR_CAPBSET_DROP requires CAP_SETPCAP in the thread's user namespace,
/// so this must be performed before transitioning to an unprivileged UID.
pub fn drop_bounding_set(bounding: &[Capability]) -> Result<(), SecurityError> {
    #[cfg(target_os = "linux")]
    {
        let last_cap = CapabilityMap::read_cap_last_cap()?;
        for c in 0..=last_cap {
            if let Some(cap) = Capability::from_u32(c) {
                if !bounding.contains(&cap) {
                    // PR_CAPBSET_READ = 23
                    let is_set = unsafe { libc::prctl(23, c as libc::c_ulong, 0, 0, 0) };
                    if is_set == 1 {
                        // PR_CAPBSET_DROP = 24
                        let drop_res = unsafe { libc::prctl(24, c as libc::c_ulong, 0, 0, 0) };
                        if drop_res != 0 {
                            return Err(SecurityError::SyscallFailed {
                                syscall: format!("prctl(PR_CAPBSET_DROP, {})", cap.name()),
                                os_error: std::io::Error::last_os_error().to_string(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = bounding;
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Linux capability ABI version 3 header.
#[cfg(target_os = "linux")]
#[repr(C)]
struct UserCapHeader {
    version: u32,
    pid: i32,
}

/// Linux capability ABI version 3 data word.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

/// Validates consistency of capability sets before attempting any syscalls.
/// Checks that ambient capabilities satisfy Linux kernel prerequisites:
/// each ambient capability must be present in permitted, inheritable, and bounding sets.
pub fn validate_capability_sets(sets: &CapabilitySets) -> Result<(), SecurityError> {
    if let Some(amb) = &sets.ambient {
        for cap in amb {
            if let Some(bnd) = &sets.bounding {
                if !bnd.contains(cap) {
                    return Err(SecurityError::InvalidConfiguration(format!(
                        "Ambient capability '{}' cannot be raised: missing from bounding set",
                        cap.name()
                    )));
                }
            }
            if let Some(prm) = &sets.permitted {
                if !prm.contains(cap) {
                    return Err(SecurityError::InvalidConfiguration(format!(
                        "Ambient capability '{}' cannot be raised: missing from permitted set",
                        cap.name()
                    )));
                }
            }
            if let Some(inh) = &sets.inheritable {
                if !inh.contains(cap) {
                    return Err(SecurityError::InvalidConfiguration(format!(
                        "Ambient capability '{}' cannot be raised: missing from inheritable set",
                        cap.name()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Applies the requested capability sets to the current calling process.
/// The operation is executed in strict order:
/// 1. Validation of ambient capability constraints.
/// 2. Dropping excluded capabilities from the bounding set (PR_CAPBSET_DROP).
/// 3. Applying thread capabilities (permitted, effective, inheritable, and ambient).
pub fn apply_capabilities(sets: &CapabilitySets) -> Result<(), SecurityError> {
    validate_capability_sets(sets)?;

    #[cfg(target_os = "linux")]
    {
        if let Some(bounding) = &sets.bounding {
            drop_bounding_set(bounding)?;
        }
        apply_thread_capabilities(sets)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sets;
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Applies thread-specific capability sets (permitted, effective, inheritable, and ambient)
/// and verifies the applied state.
/// Does NOT touch the bounding set (`PR_CAPBSET_DROP`), making this safe to call
/// both as root and after changing to an unprivileged UID (e.g., following `PR_SET_KEEPCAPS` and `setuid`).
pub fn apply_thread_capabilities(sets: &CapabilitySets) -> Result<(), SecurityError> {
    validate_capability_sets(sets)?;

    #[cfg(target_os = "linux")]
    {
        // 1. Clear Ambient Capabilities first
        // PR_CAP_AMBIENT_CLEAR_ALL = 4
        let clear_res = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, 4, 0, 0, 0) };
        if clear_res != 0 {
            let err = std::io::Error::last_os_error();
            // EINVAL may occur if the running kernel does not support ambient capabilities (pre-4.3)
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(SecurityError::SyscallFailed {
                    syscall: "prctl(PR_CAP_AMBIENT_CLEAR_ALL)".to_string(),
                    os_error: err.to_string(),
                });
            }
        }

        // 2. Query current capability sets if any set is omitted
        let header = UserCapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut current_data = [UserCapData::default(), UserCapData::default()];

        let capget_res =
            unsafe { libc::syscall(libc::SYS_capget, &header, current_data.as_mut_ptr()) };
        if capget_res != 0 {
            return Err(SecurityError::SyscallFailed {
                syscall: "capget".to_string(),
                os_error: std::io::Error::last_os_error().to_string(),
            });
        }

        let curr_eff =
            (current_data[0].effective as u64) | ((current_data[1].effective as u64) << 32);
        let curr_prm =
            (current_data[0].permitted as u64) | ((current_data[1].permitted as u64) << 32);
        let curr_inh =
            (current_data[0].inheritable as u64) | ((current_data[1].inheritable as u64) << 32);

        let target_eff = sets
            .effective
            .as_ref()
            .map(|c| CapabilityMap::to_mask(c.iter().copied()))
            .unwrap_or(curr_eff);
        let target_prm = sets
            .permitted
            .as_ref()
            .map(|c| CapabilityMap::to_mask(c.iter().copied()))
            .unwrap_or(curr_prm);
        let target_inh = sets
            .inheritable
            .as_ref()
            .map(|c| CapabilityMap::to_mask(c.iter().copied()))
            .unwrap_or(curr_inh);

        let new_data = [
            UserCapData {
                effective: target_eff as u32,
                permitted: target_prm as u32,
                inheritable: target_inh as u32,
            },
            UserCapData {
                effective: (target_eff >> 32) as u32,
                permitted: (target_prm >> 32) as u32,
                inheritable: (target_inh >> 32) as u32,
            },
        ];

        let capset_res = unsafe { libc::syscall(libc::SYS_capset, &header, new_data.as_ptr()) };
        if capset_res != 0 {
            return Err(SecurityError::SyscallFailed {
                syscall: "capset".to_string(),
                os_error: std::io::Error::last_os_error().to_string(),
            });
        }

        // 3. Raise requested Ambient capabilities
        if let Some(ambient) = &sets.ambient {
            for cap in ambient {
                // PR_CAP_AMBIENT_RAISE = 2
                let raise_res = unsafe {
                    libc::prctl(libc::PR_CAP_AMBIENT, 2, cap.value() as libc::c_ulong, 0, 0)
                };
                if raise_res != 0 {
                    return Err(SecurityError::SyscallFailed {
                        syscall: format!("prctl(PR_CAP_AMBIENT_RAISE, {})", cap.name()),
                        os_error: std::io::Error::last_os_error().to_string(),
                    });
                }
            }
        }

        // 4. Verification: Check /proc/self/status
        verify_applied_capabilities(sets)?;

        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sets;
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Re-applies the effective capability set after a UID transition.
/// In Linux, changing from UID 0 to non-zero clears effective capabilities even when
/// PR_SET_KEEPCAPS preserved permitted capabilities.
pub fn restore_effective_capabilities(sets: &CapabilitySets) -> Result<(), SecurityError> {
    #[cfg(target_os = "linux")]
    {
        if sets.effective.is_none() {
            return Ok(());
        }

        let header = UserCapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut current_data = [UserCapData::default(), UserCapData::default()];
        let capget_res =
            unsafe { libc::syscall(libc::SYS_capget, &header, current_data.as_mut_ptr()) };
        if capget_res != 0 {
            return Err(SecurityError::SyscallFailed {
                syscall: "capget".to_string(),
                os_error: std::io::Error::last_os_error().to_string(),
            });
        }

        let curr_prm =
            (current_data[0].permitted as u64) | ((current_data[1].permitted as u64) << 32);
        let target_eff = sets
            .effective
            .as_ref()
            .map(|c| CapabilityMap::to_mask(c.iter().copied()))
            .unwrap_or(curr_prm);

        // Effective must not exceed permitted
        let eff = target_eff & curr_prm;

        let new_data = [
            UserCapData {
                effective: eff as u32,
                permitted: current_data[0].permitted,
                inheritable: current_data[0].inheritable,
            },
            UserCapData {
                effective: (eff >> 32) as u32,
                permitted: current_data[1].permitted,
                inheritable: current_data[1].inheritable,
            },
        ];

        let capset_res = unsafe { libc::syscall(libc::SYS_capset, &header, new_data.as_ptr()) };
        if capset_res != 0 {
            return Err(SecurityError::SyscallFailed {
                syscall: "capset(restore_effective)".to_string(),
                os_error: std::io::Error::last_os_error().to_string(),
            });
        }

        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sets;
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Reads `/proc/self/status` and verifies that the process's active capabilities match the expected sets.
#[cfg(target_os = "linux")]
fn verify_applied_capabilities(sets: &CapabilitySets) -> Result<(), SecurityError> {
    let status_path = "/proc/self/status";
    let content = fs::read_to_string(status_path).map_err(|e| {
        SecurityError::VerificationFailed(format!("Failed to read {}: {}", status_path, e))
    })?;

    let mut cap_inh: Option<u64> = None;
    let mut cap_prm: Option<u64> = None;
    let mut cap_eff: Option<u64> = None;
    let mut cap_bnd: Option<u64> = None;
    let mut cap_amb: Option<u64> = None;

    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "CapInh" => cap_inh = u64::from_str_radix(val, 16).ok(),
                "CapPrm" => cap_prm = u64::from_str_radix(val, 16).ok(),
                "CapEff" => cap_eff = u64::from_str_radix(val, 16).ok(),
                "CapBnd" => cap_bnd = u64::from_str_radix(val, 16).ok(),
                "CapAmb" => cap_amb = u64::from_str_radix(val, 16).ok(),
                _ => {}
            }
        }
    }

    if let (Some(bounding), Some(actual_bnd)) = (&sets.bounding, cap_bnd) {
        let expected_mask = CapabilityMap::to_mask(bounding.iter().copied());
        if expected_mask != actual_bnd {
            return Err(SecurityError::VerificationFailed(format!(
                "Bounding set mismatch: expected 0x{:016x}, got 0x{:016x}",
                expected_mask, actual_bnd
            )));
        }
    }

    if let (Some(effective), Some(actual_eff)) = (&sets.effective, cap_eff) {
        let expected_mask = CapabilityMap::to_mask(effective.iter().copied());
        if expected_mask != actual_eff {
            return Err(SecurityError::VerificationFailed(format!(
                "Effective set mismatch: expected 0x{:016x}, got 0x{:016x}",
                expected_mask, actual_eff
            )));
        }
    }

    if let (Some(permitted), Some(actual_prm)) = (&sets.permitted, cap_prm) {
        let expected_mask = CapabilityMap::to_mask(permitted.iter().copied());
        if expected_mask != actual_prm {
            return Err(SecurityError::VerificationFailed(format!(
                "Permitted set mismatch: expected 0x{:016x}, got 0x{:016x}",
                expected_mask, actual_prm
            )));
        }
    }

    if let (Some(inheritable), Some(actual_inh)) = (&sets.inheritable, cap_inh) {
        let expected_mask = CapabilityMap::to_mask(inheritable.iter().copied());
        if expected_mask != actual_inh {
            return Err(SecurityError::VerificationFailed(format!(
                "Inheritable set mismatch: expected 0x{:016x}, got 0x{:016x}",
                expected_mask, actual_inh
            )));
        }
    }

    if let (Some(ambient), Some(actual_amb)) = (&sets.ambient, cap_amb) {
        let expected_mask = CapabilityMap::to_mask(ambient.iter().copied());
        if expected_mask != actual_amb {
            return Err(SecurityError::VerificationFailed(format!(
                "Ambient set mismatch: expected 0x{:016x}, got 0x{:016x}",
                expected_mask, actual_amb
            )));
        }
    }

    Ok(())
}
