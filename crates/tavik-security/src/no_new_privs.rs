use crate::error::SecurityError;

/// Enables the PR_SET_NO_NEW_PRIVS bit for the calling process.
/// Once enabled, no_new_privs cannot be unset, is inherited across fork(),
/// preserved across execve(), and prevents gaining privileges via setuid/setgid or file capabilities.
pub fn set_no_new_privs() -> Result<(), SecurityError> {
    #[cfg(target_os = "linux")]
    {
        // PR_SET_NO_NEW_PRIVS = 38
        let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if res != 0 {
            return Err(SecurityError::SyscallFailed {
                syscall: "prctl(PR_SET_NO_NEW_PRIVS, 1)".to_string(),
                os_error: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Checks whether the PR_SET_NO_NEW_PRIVS bit is currently enabled for the calling process.
pub fn is_no_new_privs() -> Result<bool, SecurityError> {
    #[cfg(target_os = "linux")]
    {
        // PR_GET_NO_NEW_PRIVS = 39
        let res = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if res < 0 {
            return Err(SecurityError::SyscallFailed {
                syscall: "prctl(PR_GET_NO_NEW_PRIVS)".to_string(),
                os_error: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(res == 1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SecurityError::UnsupportedPlatform)
    }
}

/// Ensures that PR_SET_NO_NEW_PRIVS is enabled, setting it if necessary and verifying the result.
pub fn ensure_no_new_privs() -> Result<(), SecurityError> {
    #[cfg(target_os = "linux")]
    {
        if !is_no_new_privs()? {
            set_no_new_privs()?;
        }
        if !is_no_new_privs()? {
            return Err(SecurityError::VerificationFailed(
                "no_new_privs remained disabled after setting PR_SET_NO_NEW_PRIVS".to_string(),
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SecurityError::UnsupportedPlatform)
    }
}
