use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub engine_name: String,
    pub engine_version: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub is_root: bool,
    pub cgroups_v2_available: bool,
    pub namespaces_available: bool,
    pub overlayfs_available: bool,
    pub isolation_ready: bool,
    pub state_dir: String,
    pub socket_path: String,
}

impl SystemInfo {
    pub fn detect(state_dir: &Path, socket_path: &Path) -> Self {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let (kernel, is_root) = get_os_details();
        let cgroups_v2_available = check_cgroups_v2();
        let namespaces_available = check_namespaces();
        let overlayfs_available = check_overlayfs();
        let isolation_ready = cgroups_v2_available && namespaces_available && overlayfs_available;

        Self {
            engine_name: crate::constants::ENGINE_NAME.to_string(),
            engine_version: crate::constants::ENGINE_VERSION.to_string(),
            os,
            kernel,
            arch,
            is_root,
            cgroups_v2_available,
            namespaces_available,
            overlayfs_available,
            isolation_ready,
            state_dir: state_dir.to_string_lossy().to_string(),
            socket_path: socket_path.to_string_lossy().to_string(),
        }
    }
}

fn get_os_details() -> (String, bool) {
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
        let kernel = if unsafe { libc::uname(uts.as_mut_ptr()) } == 0 {
            let uts = unsafe { uts.assume_init() };
            let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
            release.to_string_lossy().into_owned()
        } else {
            "unknown".to_string()
        };
        (kernel, is_root)
    }

    #[cfg(not(unix))]
    {
        ("unknown".to_string(), false)
    }
}

fn check_cgroups_v2() -> bool {
    #[cfg(target_os = "linux")]
    {
        // cgroup2 unified hierarchy typically mounted at /sys/fs/cgroup with cgroup.controllers
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn check_namespaces() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc/self/ns/pid").exists() && Path::new("/proc/self/ns/mnt").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn check_overlayfs() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(filesystems) = std::fs::read_to_string("/proc/filesystems") {
            return filesystems.contains("overlay");
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
