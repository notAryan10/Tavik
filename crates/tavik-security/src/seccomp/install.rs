use crate::error::SecurityError;
use crate::no_new_privs::ensure_no_new_privs;
use crate::seccomp::architecture::SeccompArchitecture;
#[cfg(target_os = "linux")]
use crate::seccomp::compiler::SockFprog;
use crate::seccomp::compiler::{SeccompCompiler, SockFilter, BPF_MAXINSNS};
use crate::seccomp::SeccompProfile;

/// Installs a compiled BPF filter program into the calling thread.
///
/// # Security Preconditions
/// In order to load seccomp filters without `CAP_SYS_ADMIN`, `PR_SET_NO_NEW_PRIVS` must be set.
/// This function automatically calls `ensure_no_new_privs()` before attempting to install the filter.
///
/// # Kernel API
/// On Linux, it uses `seccomp(SECCOMP_SET_MODE_FILTER, flags, &fprog)`.
/// If `SYS_seccomp` is not supported (kernel < 3.17) and no flags were requested, it falls back
/// to `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog)`.
pub fn install_seccomp_filter(program: &[SockFilter], flags: u32) -> Result<(), SecurityError> {
    if program.is_empty() {
        return Err(SecurityError::InvalidConfiguration(
            "Seccomp program cannot be empty".to_string(),
        ));
    }

    if program.len() > BPF_MAXINSNS {
        return Err(SecurityError::SeccompProgramTooLarge {
            len: program.len(),
            max: BPF_MAXINSNS,
        });
    }

    // Ensure no_new_privs is active (or fail if unsupported)
    ensure_no_new_privs()?;

    #[cfg(target_os = "linux")]
    {
        let fprog = SockFprog {
            len: program.len() as u16,
            filter: program.as_ptr(),
        };

        unsafe {
            // Primary interface: seccomp(SECCOMP_SET_MODE_FILTER, flags, &fprog)
            let ret = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags as libc::c_ulong,
                &fprog as *const SockFprog,
            );

            if ret == 0 {
                return Ok(());
            }

            let err = std::io::Error::last_os_error();

            // If seccomp() returned ENOSYS and no flags were requested, fallback to prctl(PR_SET_SECCOMP)
            if err.raw_os_error() == Some(libc::ENOSYS) && flags == 0 {
                let prctl_ret = libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &fprog as *const SockFprog,
                );
                if prctl_ret == 0 {
                    return Ok(());
                }
                let prctl_err = std::io::Error::last_os_error();
                return Err(SecurityError::SeccompInstallError(format!(
                    "prctl(PR_SET_SECCOMP) fallback failed: {}",
                    prctl_err
                )));
            }

            Err(SecurityError::SeccompInstallError(format!(
                "seccomp(SECCOMP_SET_MODE_FILTER, flags=0x{:x}) failed: {}",
                flags, err
            )))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = flags;
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Validates, compiles, and installs an OCI `SeccompProfile` for the current platform.
pub fn apply_seccomp(profile: &SeccompProfile) -> Result<(), SecurityError> {
    profile.validate()?;

    let current_arch = SeccompArchitecture::current().ok_or_else(|| {
        SecurityError::UnsupportedArchitecture(std::env::consts::ARCH.to_string())
    })?;
    if !profile.architectures.is_empty() && !profile.architectures.contains(&current_arch) {
        return Err(SecurityError::InvalidConfiguration(format!(
            "Current architecture '{}' is not supported by profile architectures {:?}",
            current_arch, profile.architectures
        )));
    }

    let program = SeccompCompiler::compile(profile, current_arch)?;
    let flags = profile.flags_mask();
    install_seccomp_filter(&program, flags)
}
