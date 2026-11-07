use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tavik_common::error::{Result, TavikError};

pub const OCI_SPEC_VERSION: &str = "1.2.0";

/// Standard OCI Container State (conforming to OCI Runtime Spec v1.2)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerState {
    pub oci_version: String,
    pub id: String,
    pub status: ContainerStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub bundle: PathBuf,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    Creating,
    Created,
    Running,
    Stopped,
}

impl std::fmt::Display for ContainerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "creating"),
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

/// Standard OCI Runtime Specification schema (config.json)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub oci_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(default)]
    pub terminal: bool,
    #[serde(default)]
    pub user: User,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: String,
    #[serde(default)]
    pub no_new_privileges: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<LinuxCapabilities>,
}

fn default_cwd() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    #[serde(default = "default_root_path")]
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
}

fn default_root_path() -> String {
    "rootfs".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mount_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<LinuxNamespace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uid_mappings: Vec<LinuxIdMapping>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gid_mappings: Vec<LinuxIdMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroups_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<tavik_cgroups::CgroupResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<tavik_security::SeccompProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub ns_type: LinuxNamespaceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LinuxNamespaceType {
    Pid,
    Network,
    Mount,
    Ipc,
    Uts,
    User,
    Cgroup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxIdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxCapabilities {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounding: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inheritable: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient: Vec<String>,
}

impl LinuxCapabilities {
    pub fn to_capability_sets(
        &self,
    ) -> std::result::Result<tavik_security::CapabilitySets, tavik_security::SecurityError> {
        let parse_set = |names: &[String]| -> std::result::Result<
            Option<Vec<tavik_security::Capability>>,
            tavik_security::SecurityError,
        > {
            if names.is_empty() {
                Ok(Some(Vec::new()))
            } else {
                let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                let caps = tavik_security::CapabilityMap::parse_all(refs)?;
                Ok(Some(caps))
            }
        };

        Ok(tavik_security::CapabilitySets {
            bounding: parse_set(&self.bounding)?,
            effective: parse_set(&self.effective)?,
            permitted: parse_set(&self.permitted)?,
            inheritable: parse_set(&self.inheritable)?,
            ambient: parse_set(&self.ambient)?,
        })
    }
}

impl Spec {
    /// Loads and validates an OCI configuration from a bundle path.
    pub fn load_from_bundle(bundle_dir: &Path) -> Result<Self> {
        let config_path = bundle_dir.join("config.json");
        if !config_path.exists() {
            return Err(TavikError::NotFound(format!(
                "OCI config.json not found in bundle at {:?}",
                bundle_dir
            )));
        }

        let content = std::fs::read_to_string(&config_path)?;
        let spec: Self = serde_json::from_str(&content).map_err(|e| {
            TavikError::Config(format!(
                "Failed to parse OCI config.json at {:?}: {}",
                config_path, e
            ))
        })?;

        spec.validate(bundle_dir)?;
        Ok(spec)
    }

    /// Validates OCI bundle constraints.
    pub fn validate(&self, bundle_dir: &Path) -> Result<()> {
        if self.oci_version.is_empty() {
            return Err(TavikError::Config(
                "OCI specification version cannot be empty".to_string(),
            ));
        }

        if let Some(proc) = &self.process {
            if proc.args.is_empty() {
                return Err(TavikError::Config(
                    "Container process args cannot be empty".to_string(),
                ));
            }
        } else {
            return Err(TavikError::Config(
                "Container process configuration is missing".to_string(),
            ));
        }

        // Validate rootfs directory existence
        if let Some(root) = &self.root {
            let rootfs_path = if Path::new(&root.path).is_absolute() {
                PathBuf::from(&root.path)
            } else {
                bundle_dir.join(&root.path)
            };

            if !rootfs_path.exists() {
                return Err(TavikError::NotFound(format!(
                    "Container root filesystem not found at {:?}",
                    rootfs_path
                )));
            }
        }

        Ok(())
    }

    /// Generates a standard default OCI Linux specification.
    pub fn default_linux() -> Self {
        Self {
            oci_version: OCI_SPEC_VERSION.to_string(),
            process: Some(Process {
                terminal: false,
                user: User {
                    uid: 0,
                    gid: 0,
                    additional_gids: vec![],
                },
                args: vec!["sh".to_string()],
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    "TERM=xterm".to_string(),
                ],
                cwd: "/".to_string(),
                no_new_privileges: true,
                capabilities: Some(LinuxCapabilities {
                    bounding: default_caps(),
                    effective: default_caps(),
                    permitted: default_caps(),
                    inheritable: vec![],
                    ambient: vec![],
                }),
            }),
            root: Some(Root {
                path: "rootfs".to_string(),
                readonly: false,
            }),
            hostname: Some("tavik-container".to_string()),
            mounts: vec![
                Mount {
                    destination: "/proc".to_string(),
                    mount_type: Some("proc".to_string()),
                    source: Some("proc".to_string()),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                    ],
                },
                Mount {
                    destination: "/dev".to_string(),
                    mount_type: Some("tmpfs".to_string()),
                    source: Some("tmpfs".to_string()),
                    options: vec![
                        "nosuid".to_string(),
                        "strictatime".to_string(),
                        "mode=755".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                Mount {
                    destination: "/dev/pts".to_string(),
                    mount_type: Some("devpts".to_string()),
                    source: Some("devpts".to_string()),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "newinstance".to_string(),
                        "ptmxmode=0666".to_string(),
                        "mode=0620".to_string(),
                    ],
                },
                Mount {
                    destination: "/dev/shm".to_string(),
                    mount_type: Some("tmpfs".to_string()),
                    source: Some("shm".to_string()),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "mode=1777".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                Mount {
                    destination: "/sys".to_string(),
                    mount_type: Some("sysfs".to_string()),
                    source: Some("sysfs".to_string()),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "ro".to_string(),
                    ],
                },
            ],
            linux: Some(Linux {
                namespaces: vec![
                    LinuxNamespace {
                        ns_type: LinuxNamespaceType::Pid,
                        path: None,
                    },
                    LinuxNamespace {
                        ns_type: LinuxNamespaceType::Mount,
                        path: None,
                    },
                    LinuxNamespace {
                        ns_type: LinuxNamespaceType::Ipc,
                        path: None,
                    },
                    LinuxNamespace {
                        ns_type: LinuxNamespaceType::Uts,
                        path: None,
                    },
                    LinuxNamespace {
                        ns_type: LinuxNamespaceType::Network,
                        path: None,
                    },
                ],
                uid_mappings: vec![],
                gid_mappings: vec![],
                cgroups_path: None,
                resources: None,
                seccomp: None,
            }),
            annotations: HashMap::new(),
        }
    }
}

fn default_caps() -> Vec<String> {
    vec![
        "CAP_AUDIT_WRITE".to_string(),
        "CAP_KILL".to_string(),
        "CAP_NET_BIND_SERVICE".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_spec_serialization() {
        let spec = Spec::default_linux();
        let json = serde_json::to_string_pretty(&spec).unwrap();
        let deserialized: Spec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn test_load_from_bundle() {
        let temp = tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        let spec = Spec::default_linux();
        let config_path = temp.path().join("config.json");
        std::fs::write(&config_path, serde_json::to_string(&spec).unwrap()).unwrap();

        let loaded = Spec::load_from_bundle(temp.path()).unwrap();
        assert_eq!(loaded.oci_version, OCI_SPEC_VERSION);
    }
}
