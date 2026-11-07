use std::path::PathBuf;

pub const ENGINE_NAME: &str = "TAVIK";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB max payload frame

/// Resolves the default Unix domain socket path based on privileges and environment.
pub fn default_socket_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("TAVIK_SOCKET") {
        return PathBuf::from(env_path);
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            return PathBuf::from("/var/run/tavik/tavik.sock");
        }
    }

    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("tavik").join("tavik.sock");
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".tavik")
            .join("run")
            .join("tavik.sock");
    }

    PathBuf::from("/tmp/tavik.sock")
}

/// Resolves the default persistent state directory.
pub fn default_state_dir() -> PathBuf {
    if let Ok(env_path) = std::env::var("TAVIK_STATE_DIR") {
        return PathBuf::from(env_path);
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            return PathBuf::from("/var/lib/tavik");
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".tavik").join("state");
    }

    PathBuf::from("/tmp/tavik-state")
}
