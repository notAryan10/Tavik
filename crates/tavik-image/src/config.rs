use crate::error::ImageError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Top-level OCI Image Configuration specification (v1.0 / v1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfiguration {
    /// The CPU architecture which the binaries in this image are built to run on (e.g. "amd64", "arm64").
    pub architecture: String,

    /// The execution system which the binaries in this image are built to run on (e.g. "linux", "windows").
    pub os: String,

    /// Optional CPU architecture variant (e.g. "v7", "v8").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    /// Optional OS version required by this image.
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,

    /// Optional OS features required by this image.
    #[serde(
        rename = "os.features",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_features: Option<Vec<String>>,

    /// Combined date and time at which the image was created (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Gives the name and/or email address of the person or entity which created and is responsible for maintaining the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Execution parameters for a container created from this image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ContainerConfig>,

    /// The root filesystem description of the image.
    pub rootfs: RootFs,

    /// Describes the history of each layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<HistoryRecord>>,
}

/// Execution parameters for containers created from the OCI image.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// The username or UID (and optionally groupname or GID) which the container process runs as.
    #[serde(
        rename = "User",
        alias = "user",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub user: Option<String>,

    /// Set of ports to expose from the container (e.g. `"80/tcp": {}`).
    #[serde(
        rename = "ExposedPorts",
        alias = "exposed_ports",
        alias = "exposedPorts",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exposed_ports: Option<HashMap<String, serde_json::Value>>,

    /// List of environment variables in KEY=VALUE format.
    #[serde(
        rename = "Env",
        alias = "env",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub env: Option<Vec<String>>,

    /// List of arguments to use as the entrypoint for the container process.
    #[serde(
        rename = "Entrypoint",
        alias = "entrypoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint: Option<Vec<String>>,

    /// Default arguments to the entrypoint of the container.
    #[serde(
        rename = "Cmd",
        alias = "cmd",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cmd: Option<Vec<String>>,

    /// Set of directories describing where the container may expect volumes to be mounted.
    #[serde(
        rename = "Volumes",
        alias = "volumes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub volumes: Option<HashMap<String, serde_json::Value>>,

    /// Working directory of the entrypoint process in the container.
    #[serde(
        rename = "WorkingDir",
        alias = "working_dir",
        alias = "workingDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,

    /// Arbitrary key-value metadata for the container.
    #[serde(
        rename = "Labels",
        alias = "labels",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub labels: Option<HashMap<String, String>>,

    /// Signal to send to the container process when stopping it (e.g. "SIGTERM").
    #[serde(
        rename = "StopSignal",
        alias = "stop_signal",
        alias = "stopSignal",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_signal: Option<String>,

    /// Docker compatibility flag indicating whether command line arguments were already escaped on Windows.
    #[serde(
        rename = "ArgsEscaped",
        alias = "args_escaped",
        alias = "argsEscaped",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub args_escaped: Option<bool>,
}

/// Root filesystem metadata for an OCI image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootFs {
    /// Must be "layers".
    #[serde(rename = "type")]
    pub type_name: String,

    /// Ordered array of layer diffIDs (uncompressed layer digests).
    pub diff_ids: Vec<String>,
}

/// Record of an image layer's creation history.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HistoryRecord {
    /// Timestamp at which the layer was created (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Author of the layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Command that created this layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,

    /// Comment describing the layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Indicates if this layer did not generate any changes to the root filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_layer: Option<bool>,
}

impl ImageConfiguration {
    /// Parses and validates an OCI image configuration from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ImageError> {
        let config: Self = serde_json::from_slice(bytes)?;
        config.validate()?;
        Ok(config)
    }

    /// Parses and validates an OCI image configuration from a reader.
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, ImageError> {
        let config: Self = serde_json::from_reader(reader)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads and validates an OCI image configuration from a file on disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ImageError> {
        let bytes = std::fs::read(path.as_ref())?;
        Self::from_bytes(&bytes)
    }

    /// Validates the structural, semantic, and security rules of the configuration.
    pub fn validate(&self) -> Result<(), ImageError> {
        if self.architecture.trim().is_empty() {
            return Err(ImageError::InvalidConfiguration(
                "Image 'architecture' field must not be empty or whitespace".to_string(),
            ));
        }

        if self.os.trim().is_empty() {
            return Err(ImageError::InvalidConfiguration(
                "Image 'os' field must not be empty or whitespace".to_string(),
            ));
        }

        self.rootfs.validate()?;

        if let Some(ref config) = self.config {
            config.validate()?;
        }

        Ok(())
    }
}

impl std::str::FromStr for ImageConfiguration {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

impl RootFs {
    /// Validates the rootfs type and the format of every DiffID.
    pub fn validate(&self) -> Result<(), ImageError> {
        if self.type_name != "layers" {
            return Err(ImageError::InvalidConfiguration(format!(
                "Unsupported rootfs type '{}': expected 'layers'",
                self.type_name
            )));
        }

        for diff_id in &self.diff_ids {
            validate_diff_id(diff_id)?;
        }

        Ok(())
    }
}

impl ContainerConfig {
    /// Validates environment variable formatting and volume container paths.
    pub fn validate(&self) -> Result<(), ImageError> {
        // Validate Environment variables
        if let Some(ref envs) = self.env {
            for entry in envs {
                let Some((name, val)) = entry.split_once('=') else {
                    return Err(ImageError::InvalidConfiguration(format!(
                        "Malformed environment variable '{entry}': must follow KEY=VALUE format"
                    )));
                };

                if name.is_empty() {
                    return Err(ImageError::InvalidConfiguration(format!(
                        "Malformed environment variable '{entry}': variable name cannot be empty"
                    )));
                }

                if name.contains('\0') || val.contains('\0') {
                    return Err(ImageError::InvalidConfiguration(format!(
                        "Environment variable '{entry}' contains forbidden null byte"
                    )));
                }
            }
        }

        // Validate Volume declarations
        if let Some(ref vols) = self.volumes {
            for vol_path in vols.keys() {
                if vol_path.is_empty() {
                    return Err(ImageError::InvalidConfiguration(
                        "Volume mount path cannot be empty".to_string(),
                    ));
                }

                if !vol_path.starts_with('/') {
                    return Err(ImageError::InvalidConfiguration(format!(
                        "Invalid volume path '{vol_path}': must be an absolute container path starting with '/'"
                    )));
                }

                if vol_path.contains('\0') {
                    return Err(ImageError::InvalidConfiguration(format!(
                        "Volume path '{vol_path}' contains forbidden null byte"
                    )));
                }

                for comp in vol_path.split('/') {
                    if comp == ".." {
                        return Err(ImageError::InvalidConfiguration(format!(
                            "Invalid volume path '{vol_path}': parent directory traversal '..' is forbidden"
                        )));
                    }
                }
            }
        }

        // Validate StopSignal
        if let Some(ref sig) = self.stop_signal {
            if sig.trim().is_empty() {
                return Err(ImageError::InvalidConfiguration(
                    "StopSignal must not be empty or whitespace".to_string(),
                ));
            }
            if sig.contains('\0') {
                return Err(ImageError::InvalidConfiguration(
                    "StopSignal contains forbidden null byte".to_string(),
                ));
            }
        }

        // Validate WorkingDir
        if let Some(ref wd) = self.working_dir {
            if wd.contains('\0') {
                return Err(ImageError::InvalidConfiguration(
                    "WorkingDir contains forbidden null byte".to_string(),
                ));
            }
        }

        // Validate User
        if let Some(ref u) = self.user {
            if u.contains('\0') {
                return Err(ImageError::InvalidConfiguration(
                    "User contains forbidden null byte".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Validates that a DiffID adheres to the standard `sha256:<64-lowercase-hex>` syntax.
fn validate_diff_id(diff_id: &str) -> Result<(), ImageError> {
    let Some(hex_part) = diff_id.strip_prefix("sha256:") else {
        return Err(ImageError::InvalidConfiguration(format!(
            "Invalid DiffID '{diff_id}': must specify sha256 algorithm (sha256:<64-hex>)"
        )));
    };

    if hex_part.len() != 64
        || !hex_part
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(ImageError::InvalidConfiguration(format!(
            "Invalid DiffID '{diff_id}': sha256 digest must be exactly 64 lowercase hexadecimal characters"
        )));
    }

    Ok(())
}
