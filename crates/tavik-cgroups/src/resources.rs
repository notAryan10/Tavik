use serde::{Deserialize, Serialize};

/// High-level resource constraints for a cgroups v2 container.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CgroupResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuResources>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryResources>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<PidResources>,
}

/// CPU resource governance settings for cgroups v2.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuResources {
    /// Relative CPU weight (1 to 10000, default is 100 in Linux cgroup v2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,

    /// CPU period in microseconds (e.g. 100000 = 100ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,

    /// CPU quota in microseconds per period (or -1/None for unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
}

/// Memory resource governance settings for cgroups v2.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryResources {
    /// Hard memory limit in bytes (or <= 0 for "max").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,

    /// Memory throttling watermark in bytes (memory.high).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<i64>,

    /// Swap memory limit in bytes (or <= 0 for "max").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
}

/// Process/thread concurrency limit to prevent fork bombs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PidResources {
    /// Maximum number of processes/threads in the cgroup (or <= 0 for "max").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

/// Current utilization statistics queried from cgroups v2 interfaces.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CgroupStats {
    /// Current memory usage in bytes (from `memory.current`).
    pub memory_current: Option<u64>,

    /// Current active processes in the cgroup (from `pids.current`).
    pub pids_current: Option<u64>,

    /// Total CPU usage in microseconds (from `cpu.stat` usage_usec).
    pub cpu_usage_usec: Option<u64>,
}
