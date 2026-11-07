use crate::error::SecurityError;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs;

/// A Linux capability representation identified by its bit index (0..=cap_last_cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(u32);

impl Capability {
    pub const CAP_CHOWN: Capability = Capability(0);
    pub const CAP_DAC_OVERRIDE: Capability = Capability(1);
    pub const CAP_DAC_READ_SEARCH: Capability = Capability(2);
    pub const CAP_FOWNER: Capability = Capability(3);
    pub const CAP_FSETID: Capability = Capability(4);
    pub const CAP_KILL: Capability = Capability(5);
    pub const CAP_SETGID: Capability = Capability(6);
    pub const CAP_SETUID: Capability = Capability(7);
    pub const CAP_SETPCAP: Capability = Capability(8);
    pub const CAP_LINUX_IMMUTABLE: Capability = Capability(9);
    pub const CAP_NET_BIND_SERVICE: Capability = Capability(10);
    pub const CAP_NET_BROADCAST: Capability = Capability(11);
    pub const CAP_NET_ADMIN: Capability = Capability(12);
    pub const CAP_NET_RAW: Capability = Capability(13);
    pub const CAP_IPC_LOCK: Capability = Capability(14);
    pub const CAP_IPC_OWNER: Capability = Capability(15);
    pub const CAP_SYS_MODULE: Capability = Capability(16);
    pub const CAP_SYS_RAWIO: Capability = Capability(17);
    pub const CAP_SYS_CHROOT: Capability = Capability(18);
    pub const CAP_SYS_PTRACE: Capability = Capability(19);
    pub const CAP_SYS_PACCT: Capability = Capability(20);
    pub const CAP_SYS_ADMIN: Capability = Capability(21);
    pub const CAP_SYS_BOOT: Capability = Capability(22);
    pub const CAP_SYS_NICE: Capability = Capability(23);
    pub const CAP_SYS_RESOURCE: Capability = Capability(24);
    pub const CAP_SYS_TIME: Capability = Capability(25);
    pub const CAP_SYS_TTY_CONFIG: Capability = Capability(26);
    pub const CAP_MKNOD: Capability = Capability(27);
    pub const CAP_LEASE: Capability = Capability(28);
    pub const CAP_AUDIT_WRITE: Capability = Capability(29);
    pub const CAP_AUDIT_CONTROL: Capability = Capability(30);
    pub const CAP_SETFCAP: Capability = Capability(31);
    pub const CAP_MAC_OVERRIDE: Capability = Capability(32);
    pub const CAP_MAC_ADMIN: Capability = Capability(33);
    pub const CAP_SYSLOG: Capability = Capability(34);
    pub const CAP_WAKE_ALARM: Capability = Capability(35);
    pub const CAP_BLOCK_SUSPEND: Capability = Capability(36);
    pub const CAP_AUDIT_READ: Capability = Capability(37);
    pub const CAP_PERFMON: Capability = Capability(38);
    pub const CAP_BPF: Capability = Capability(39);
    pub const CAP_CHECKPOINT_RESTORE: Capability = Capability(40);

    /// Constructs a Capability from an integer value if valid.
    pub const fn from_u32(val: u32) -> Option<Self> {
        if val <= 40 {
            Some(Capability(val))
        } else {
            None
        }
    }

    /// Returns the integer value/bit offset of the capability.
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Returns the standard canonical OCI/POSIX name (e.g. "CAP_CHOWN").
    pub const fn name(&self) -> &'static str {
        match self.0 {
            0 => "CAP_CHOWN",
            1 => "CAP_DAC_OVERRIDE",
            2 => "CAP_DAC_READ_SEARCH",
            3 => "CAP_FOWNER",
            4 => "CAP_FSETID",
            5 => "CAP_KILL",
            6 => "CAP_SETGID",
            7 => "CAP_SETUID",
            8 => "CAP_SETPCAP",
            9 => "CAP_LINUX_IMMUTABLE",
            10 => "CAP_NET_BIND_SERVICE",
            11 => "CAP_NET_BROADCAST",
            12 => "CAP_NET_ADMIN",
            13 => "CAP_NET_RAW",
            14 => "CAP_IPC_LOCK",
            15 => "CAP_IPC_OWNER",
            16 => "CAP_SYS_MODULE",
            17 => "CAP_SYS_RAWIO",
            18 => "CAP_SYS_CHROOT",
            19 => "CAP_SYS_PTRACE",
            20 => "CAP_SYS_PACCT",
            21 => "CAP_SYS_ADMIN",
            22 => "CAP_SYS_BOOT",
            23 => "CAP_SYS_NICE",
            24 => "CAP_SYS_RESOURCE",
            25 => "CAP_SYS_TIME",
            26 => "CAP_SYS_TTY_CONFIG",
            27 => "CAP_MKNOD",
            28 => "CAP_LEASE",
            29 => "CAP_AUDIT_WRITE",
            30 => "CAP_AUDIT_CONTROL",
            31 => "CAP_SETFCAP",
            32 => "CAP_MAC_OVERRIDE",
            33 => "CAP_MAC_ADMIN",
            34 => "CAP_SYSLOG",
            35 => "CAP_WAKE_ALARM",
            36 => "CAP_BLOCK_SUSPEND",
            37 => "CAP_AUDIT_READ",
            38 => "CAP_PERFMON",
            39 => "CAP_BPF",
            40 => "CAP_CHECKPOINT_RESTORE",
            _ => "CAP_UNKNOWN",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Static and dynamic mapping for Linux capability resolution and bitmask conversions.
pub struct CapabilityMap;

impl CapabilityMap {
    /// Reads `/proc/sys/kernel/cap_last_cap` to determine the maximum capability supported by the running kernel.
    pub fn read_cap_last_cap() -> Result<u32, SecurityError> {
        #[cfg(target_os = "linux")]
        {
            let path = "/proc/sys/kernel/cap_last_cap";
            let content = fs::read_to_string(path)
                .map_err(|e| SecurityError::KernelLastCapUnavailable(format!("{}: {}", path, e)))?;
            content.trim().parse::<u32>().map_err(|e| {
                SecurityError::KernelLastCapUnavailable(format!(
                    "Failed to parse {} content '{}': {}",
                    path, content, e
                ))
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Under non-Linux, default to standard capability ceiling (40)
            Ok(40)
        }
    }

    /// Resolves an OCI capability string name (e.g. "CAP_CHOWN" or "cap_chown") to a `Capability`.
    pub fn from_name(name: &str) -> Result<Capability, SecurityError> {
        let normalized = name.trim().to_uppercase();
        let cap = match normalized.as_str() {
            "CAP_CHOWN" | "CHOWN" => Capability::CAP_CHOWN,
            "CAP_DAC_OVERRIDE" | "DAC_OVERRIDE" => Capability::CAP_DAC_OVERRIDE,
            "CAP_DAC_READ_SEARCH" | "DAC_READ_SEARCH" => Capability::CAP_DAC_READ_SEARCH,
            "CAP_FOWNER" | "FOWNER" => Capability::CAP_FOWNER,
            "CAP_FSETID" | "FSETID" => Capability::CAP_FSETID,
            "CAP_KILL" | "KILL" => Capability::CAP_KILL,
            "CAP_SETGID" | "SETGID" => Capability::CAP_SETGID,
            "CAP_SETUID" | "SETUID" => Capability::CAP_SETUID,
            "CAP_SETPCAP" | "SETPCAP" => Capability::CAP_SETPCAP,
            "CAP_LINUX_IMMUTABLE" | "LINUX_IMMUTABLE" => Capability::CAP_LINUX_IMMUTABLE,
            "CAP_NET_BIND_SERVICE" | "NET_BIND_SERVICE" => Capability::CAP_NET_BIND_SERVICE,
            "CAP_NET_BROADCAST" | "NET_BROADCAST" => Capability::CAP_NET_BROADCAST,
            "CAP_NET_ADMIN" | "NET_ADMIN" => Capability::CAP_NET_ADMIN,
            "CAP_NET_RAW" | "NET_RAW" => Capability::CAP_NET_RAW,
            "CAP_IPC_LOCK" | "IPC_LOCK" => Capability::CAP_IPC_LOCK,
            "CAP_IPC_OWNER" | "IPC_OWNER" => Capability::CAP_IPC_OWNER,
            "CAP_SYS_MODULE" | "SYS_MODULE" => Capability::CAP_SYS_MODULE,
            "CAP_SYS_RAWIO" | "SYS_RAWIO" => Capability::CAP_SYS_RAWIO,
            "CAP_SYS_CHROOT" | "SYS_CHROOT" => Capability::CAP_SYS_CHROOT,
            "CAP_SYS_PTRACE" | "SYS_PTRACE" => Capability::CAP_SYS_PTRACE,
            "CAP_SYS_PACCT" | "SYS_PACCT" => Capability::CAP_SYS_PACCT,
            "CAP_SYS_ADMIN" | "SYS_ADMIN" => Capability::CAP_SYS_ADMIN,
            "CAP_SYS_BOOT" | "SYS_BOOT" => Capability::CAP_SYS_BOOT,
            "CAP_SYS_NICE" | "SYS_NICE" => Capability::CAP_SYS_NICE,
            "CAP_SYS_RESOURCE" | "SYS_RESOURCE" => Capability::CAP_SYS_RESOURCE,
            "CAP_SYS_TIME" | "SYS_TIME" => Capability::CAP_SYS_TIME,
            "CAP_SYS_TTY_CONFIG" | "SYS_TTY_CONFIG" => Capability::CAP_SYS_TTY_CONFIG,
            "CAP_MKNOD" | "MKNOD" => Capability::CAP_MKNOD,
            "CAP_LEASE" | "LEASE" => Capability::CAP_LEASE,
            "CAP_AUDIT_WRITE" | "AUDIT_WRITE" => Capability::CAP_AUDIT_WRITE,
            "CAP_AUDIT_CONTROL" | "AUDIT_CONTROL" => Capability::CAP_AUDIT_CONTROL,
            "CAP_SETFCAP" | "SETFCAP" => Capability::CAP_SETFCAP,
            "CAP_MAC_OVERRIDE" | "MAC_OVERRIDE" => Capability::CAP_MAC_OVERRIDE,
            "CAP_MAC_ADMIN" | "MAC_ADMIN" => Capability::CAP_MAC_ADMIN,
            "CAP_SYSLOG" | "SYSLOG" => Capability::CAP_SYSLOG,
            "CAP_WAKE_ALARM" | "WAKE_ALARM" => Capability::CAP_WAKE_ALARM,
            "CAP_BLOCK_SUSPEND" | "BLOCK_SUSPEND" => Capability::CAP_BLOCK_SUSPEND,
            "CAP_AUDIT_READ" | "AUDIT_READ" => Capability::CAP_AUDIT_READ,
            "CAP_PERFMON" | "PERFMON" => Capability::CAP_PERFMON,
            "CAP_BPF" | "BPF" => Capability::CAP_BPF,
            "CAP_CHECKPOINT_RESTORE" | "CHECKPOINT_RESTORE" => Capability::CAP_CHECKPOINT_RESTORE,
            _ => return Err(SecurityError::UnknownCapability(name.to_string())),
        };

        // Validate capability against the dynamic kernel ceiling
        let last_cap = Self::read_cap_last_cap()?;
        if cap.value() > last_cap {
            return Err(SecurityError::CapabilityExceedsKernelLastCap {
                cap: name.to_string(),
                value: cap.value(),
                last_cap,
            });
        }

        Ok(cap)
    }

    /// Validates and parses an iterator of capability string names into a sorted, deduplicated `Vec<Capability>`.
    pub fn parse_all<I, S>(names: I) -> Result<Vec<Capability>, SecurityError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut caps = Vec::new();
        for name in names {
            let cap = Self::from_name(name.as_ref())?;
            if !caps.contains(&cap) {
                caps.push(cap);
            }
        }
        caps.sort();
        Ok(caps)
    }

    /// Converts a collection of Capabilities into a 64-bit integer bitmask.
    pub fn to_mask<I>(caps: I) -> u64
    where
        I: IntoIterator<Item = Capability>,
    {
        let mut mask: u64 = 0;
        for cap in caps {
            if cap.value() < 64 {
                mask |= 1u64 << cap.value();
            }
        }
        mask
    }

    /// Reconstructs a collection of Capabilities from a 64-bit integer bitmask.
    pub fn from_mask(mask: u64) -> Vec<Capability> {
        let mut caps = Vec::new();
        for i in 0..=40 {
            if (mask & (1u64 << i)) != 0 {
                if let Some(cap) = Capability::from_u32(i) {
                    caps.push(cap);
                }
            }
        }
        caps
    }
}
