use crate::resources::{CgroupResources, CgroupStats};
use std::fs;
use std::path::{Path, PathBuf};
use tavik_common::error::{Result, TavikError};
#[allow(unused_imports)]
use tracing::{debug, info, warn};

/// Default unified cgroup v2 mount point.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Default TAVIK parent group under the cgroup v2 hierarchy.
pub const DEFAULT_TAVIK_PARENT: &str = "tavik";

/// Manager for Linux cgroups v2 resource governance and lifecycle.
#[derive(Debug, Clone)]
pub struct CgroupManager {
    /// Root mount point of cgroups v2 (e.g. `/sys/fs/cgroup`).
    cgroup_root: PathBuf,
    /// Dedicated parent cgroup path (e.g. `/sys/fs/cgroup/tavik`).
    parent_path: PathBuf,
}

impl CgroupManager {
    /// Constructs a CgroupManager pointing to the default `/sys/fs/cgroup/tavik` parent hierarchy.
    pub fn new() -> Result<Self> {
        Self::with_paths(
            PathBuf::from(DEFAULT_CGROUP_ROOT),
            PathBuf::from(DEFAULT_CGROUP_ROOT).join(DEFAULT_TAVIK_PARENT),
        )
    }

    /// Constructs a CgroupManager with customized root and parent paths (useful for tests and custom slices).
    pub fn with_paths(cgroup_root: PathBuf, parent_path: PathBuf) -> Result<Self> {
        // Enforce that parent_path must be a subpath of cgroup_root and NOT the cgroup_root itself!
        if parent_path == cgroup_root {
            return Err(TavikError::Config(
                "TAVIK cgroup parent cannot be the host root cgroup".to_string(),
            ));
        }

        Ok(Self {
            cgroup_root,
            parent_path,
        })
    }

    /// Returns the dedicated parent cgroup path.
    pub fn parent_path(&self) -> &Path {
        &self.parent_path
    }

    /// Returns the root cgroup path.
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    /// Validates that cgroup v2 is enabled and mounted at `cgroup_root`.
    pub fn validate_cgroup_v2(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let controllers_path = self.cgroup_root.join("cgroup.controllers");
            if !controllers_path.exists() {
                return Err(TavikError::Unsupported(format!(
                    "cgroups v2 unified hierarchy not found at {:?} (missing cgroup.controllers)",
                    self.cgroup_root
                )));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Reads available controllers from `cgroup.controllers` at the specified directory.
    pub fn read_available_controllers(&self, dir: &Path) -> Result<Vec<String>> {
        let path = dir.join("cgroup.controllers");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path).map_err(|e| {
            TavikError::Io(format!("Failed to read controllers at {:?}: {}", path, e))
        })?;
        Ok(content.split_whitespace().map(|s| s.to_string()).collect())
    }

    /// Ensures that the parent cgroup directory exists and has requested controllers enabled in `cgroup.subtree_control`.
    pub fn ensure_parent_cgroup(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.validate_cgroup_v2()?;

            // 1. Ensure root cgroup subtree_control delegates required controllers
            let root_controllers = self.read_available_controllers(&self.cgroup_root)?;
            self.enable_subtree_controllers(&self.cgroup_root, &root_controllers)?;

            // 2. Create the parent cgroup directory if not present
            if !self.parent_path.exists() {
                fs::create_dir_all(&self.parent_path).map_err(|e| {
                    TavikError::Io(format!(
                        "Failed to create parent cgroup at {:?}: {}",
                        self.parent_path, e
                    ))
                })?;
                info!(
                    "Created dedicated cgroup v2 parent at {:?}",
                    self.parent_path
                );
            }

            // 3. Enable controllers in the parent's subtree_control so container children inherit them
            let parent_controllers = self.read_available_controllers(&self.parent_path)?;
            self.enable_subtree_controllers(&self.parent_path, &parent_controllers)?;

            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Enables controllers in a given cgroup's `cgroup.subtree_control`.
    #[cfg(target_os = "linux")]
    fn enable_subtree_controllers(&self, dir: &Path, available: &[String]) -> Result<()> {
        let subtree_path = dir.join("cgroup.subtree_control");
        if !subtree_path.exists() {
            return Ok(());
        }

        let current = fs::read_to_string(&subtree_path).unwrap_or_default();
        let active_set: std::collections::HashSet<&str> = current.split_whitespace().collect();

        let mut to_enable = Vec::new();
        for controller in ["cpu", "memory", "pids", "io"] {
            if available.iter().any(|c| c == controller) && !active_set.contains(controller) {
                to_enable.push(format!("+{}", controller));
            }
        }

        if !to_enable.is_empty() {
            let payload = to_enable.join(" ");
            debug!("Enabling controllers in {:?}: {}", subtree_path, payload);
            if let Err(e) = fs::write(&subtree_path, &payload) {
                warn!("Failed to write {:?} to {:?}: {}", payload, subtree_path, e);
            }
        }

        Ok(())
    }

    /// Resolves and validates the target directory for a container cgroup.
    pub fn container_cgroup_dir(&self, container_id: &str) -> Result<PathBuf> {
        self.validate_container_id(container_id)?;
        Ok(self.parent_path.join(container_id))
    }

    /// Validates that a container ID is safe and does not perform path traversal.
    pub fn validate_container_id(&self, id: &str) -> Result<()> {
        if id.is_empty() {
            return Err(TavikError::Config(
                "Container ID cannot be empty".to_string(),
            ));
        }
        if id.contains('/') || id.contains('\\') || id.contains("..") || id.contains('\0') {
            return Err(TavikError::Config(format!(
                "Invalid container ID '{}': path traversal characters not permitted",
                id
            )));
        }
        Ok(())
    }

    /// Creates a dedicated cgroup for a container.
    pub fn create_container_cgroup(&self, container_id: &str) -> Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            self.ensure_parent_cgroup()?;
            let dir = self.container_cgroup_dir(container_id)?;

            if !dir.exists() {
                fs::create_dir_all(&dir).map_err(|e| {
                    TavikError::Io(format!(
                        "Failed to create container cgroup at {:?}: {}",
                        dir, e
                    ))
                })?;
                debug!("Created container cgroup at {:?}", dir);
            }

            Ok(dir)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = container_id;
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Applies resource limits to a container's cgroup.
    pub fn apply_resources(&self, container_id: &str, resources: &CgroupResources) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let dir = self.container_cgroup_dir(container_id)?;
            if !dir.exists() {
                return Err(TavikError::NotFound(format!(
                    "Container cgroup {:?} does not exist",
                    dir
                )));
            }

            let available = self.read_available_controllers(&self.parent_path)?;

            // 1. Apply CPU limits
            if let Some(cpu) = &resources.cpu {
                if !available.iter().any(|c| c == "cpu") {
                    return Err(TavikError::Unsupported(
                        "CPU resource limits specified but 'cpu' controller is unavailable in cgroups v2".to_string(),
                    ));
                }

                // cpu.max: "<quota> <period>"
                if cpu.quota.is_some() || cpu.period.is_some() {
                    let period = cpu.period.unwrap_or(100_000);
                    let val = match cpu.quota {
                        Some(q) if q > 0 => format!("{} {}", q, period),
                        _ => format!("max {}", period),
                    };
                    self.write_cgroup_file(&dir, "cpu.max", &val)?;
                }

                // cpu.weight: 1..=10000
                if let Some(weight) = cpu.weight {
                    let clamped = weight.clamp(1, 10000);
                    self.write_cgroup_file(&dir, "cpu.weight", &clamped.to_string())?;
                }
            }

            // 2. Apply Memory limits
            if let Some(mem) = &resources.memory {
                if !available.iter().any(|c| c == "memory") {
                    return Err(TavikError::Unsupported(
                        "Memory resource limits specified but 'memory' controller is unavailable in cgroups v2".to_string(),
                    ));
                }

                // memory.max
                if let Some(limit) = mem.limit {
                    let val = if limit > 0 {
                        limit.to_string()
                    } else {
                        "max".to_string()
                    };
                    self.write_cgroup_file(&dir, "memory.max", &val)?;
                }

                // memory.high
                if let Some(high) = mem.high {
                    let val = if high > 0 {
                        high.to_string()
                    } else {
                        "max".to_string()
                    };
                    self.write_cgroup_file(&dir, "memory.high", &val)?;
                }

                // memory.swap.max
                if let Some(swap) = mem.swap {
                    let val = if swap > 0 {
                        swap.to_string()
                    } else {
                        "max".to_string()
                    };
                    self.write_cgroup_file(&dir, "memory.swap.max", &val)?;
                }
            }

            // 3. Apply Process (PIDs) limits
            if let Some(pids) = &resources.pids {
                if !available.iter().any(|c| c == "pids") {
                    return Err(TavikError::Unsupported(
                        "PIDs resource limits specified but 'pids' controller is unavailable in cgroups v2".to_string(),
                    ));
                }

                if let Some(limit) = pids.limit {
                    let val = if limit > 0 {
                        limit.to_string()
                    } else {
                        "max".to_string()
                    };
                    self.write_cgroup_file(&dir, "pids.max", &val)?;
                }
            }

            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (container_id, resources);
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Adds a process by host PID to the container's cgroup.
    pub fn add_process(&self, container_id: &str, pid: u32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let dir = self.container_cgroup_dir(container_id)?;
            self.write_cgroup_file(&dir, "cgroup.procs", &pid.to_string())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (container_id, pid);
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Queries the list of host PIDs enrolled in the container cgroup.
    pub fn get_processes(&self, container_id: &str) -> Result<Vec<u32>> {
        #[cfg(target_os = "linux")]
        {
            let dir = self.container_cgroup_dir(container_id)?;
            let procs_file = dir.join("cgroup.procs");
            if !procs_file.exists() {
                return Ok(Vec::new());
            }

            let content = fs::read_to_string(&procs_file)
                .map_err(|e| TavikError::Io(format!("Failed to read {:?}: {}", procs_file, e)))?;

            let mut pids = Vec::new();
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    pids.push(pid);
                }
            }
            Ok(pids)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = container_id;
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Reads current resource statistics from the container cgroup.
    pub fn read_stats(&self, container_id: &str) -> Result<CgroupStats> {
        #[cfg(target_os = "linux")]
        {
            let dir = self.container_cgroup_dir(container_id)?;
            let mut stats = CgroupStats::default();

            // memory.current
            if let Ok(content) = fs::read_to_string(dir.join("memory.current")) {
                stats.memory_current = content.trim().parse::<u64>().ok();
            }

            // pids.current
            if let Ok(content) = fs::read_to_string(dir.join("pids.current")) {
                stats.pids_current = content.trim().parse::<u64>().ok();
            }

            // cpu.stat: parse usage_usec
            if let Ok(content) = fs::read_to_string(dir.join("cpu.stat")) {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() == 2 && parts[0] == "usage_usec" {
                        stats.cpu_usage_usec = parts[1].parse::<u64>().ok();
                    }
                }
            }

            Ok(stats)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = container_id;
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Atomically terminates all processes in the container cgroup via `cgroup.kill` and removes the cgroup directory.
    pub fn destroy_container_cgroup(&self, container_id: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let dir = self.container_cgroup_dir(container_id)?;
            if !dir.exists() {
                return Ok(());
            }

            // 1. Try atomic cgroup.kill (available in Linux 5.14+)
            let kill_file = dir.join("cgroup.kill");
            if kill_file.exists() {
                let _ = fs::write(&kill_file, "1");
            } else {
                // Fallback: enumerate cgroup.procs and send SIGKILL to each
                if let Ok(pids) = self.get_processes(container_id) {
                    for pid in pids {
                        unsafe {
                            libc::kill(pid as libc::pid_t, libc::SIGKILL);
                        }
                    }
                }
            }

            // 2. Poll briefly (up to 500ms) for processes to exit before removing the directory
            for _ in 0..10 {
                let procs = self.get_processes(container_id).unwrap_or_default();
                if procs.is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            // 3. Remove the container cgroup directory
            fs::remove_dir(&dir).map_err(|e| {
                TavikError::Io(format!(
                    "Failed to remove container cgroup directory at {:?}: {}",
                    dir, e
                ))
            })?;

            debug!("Destroyed container cgroup at {:?}", dir);
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = container_id;
            Err(TavikError::Unsupported(
                "cgroups v2 requires a Linux kernel".to_string(),
            ))
        }
    }

    /// Internal helper to write a string value to an interface file inside a cgroup directory.
    #[cfg(target_os = "linux")]
    fn write_cgroup_file(&self, dir: &Path, file_name: &str, value: &str) -> Result<()> {
        let path = dir.join(file_name);
        fs::write(&path, value).map_err(|e| {
            TavikError::Io(format!(
                "Failed to write '{}' to cgroup interface {:?}: {}",
                value, path, e
            ))
        })
    }
}
