use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const OCI_MANIFEST_V1: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_IMAGE_INDEX_V1: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_CONFIG_JSON: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const OCI_LAYER_TAR_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
pub const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

pub const DOCKER_MANIFEST_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_MANIFEST_LIST_V2: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_CONTAINER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
pub const DOCKER_LAYER_TAR_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// OCI Content Descriptor pointing to a manifest, layer, or config blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub digest: String,

    pub size: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

/// OCI Platform definition specifying target architecture and OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,

    pub os: String,

    #[serde(rename = "os.version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    #[serde(rename = "os.features", skip_serializing_if = "Option::is_none")]
    pub os_features: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
}

impl Platform {
    /// Checks whether this platform matches the requested target OS, architecture, and optional variant.
    pub fn matches(&self, os: &str, arch: &str, variant: Option<&str>) -> bool {
        if self.os != os || self.architecture != arch {
            return false;
        }

        // If target specifies variant (e.g. v7 or v8 on arm), compare it
        if let Some(target_var) = variant {
            if let Some(self_var) = &self.variant {
                return self_var == target_var;
            }
        }

        true
    }
}
