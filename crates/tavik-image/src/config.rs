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

/// Typed container volume declaration from image configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImageVolume {
    /// Container destination path where the volume should be mounted.
    pub destination: std::path::PathBuf,
}

/// Fully resolved, validated container execution configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveImageConfig {
    /// Final command-line arguments to execute inside the container (argv[0] is executable).
    pub args: Vec<String>,

    /// Final environment variables in KEY=VALUE format.
    pub env: Vec<String>,

    /// Final working directory for the container process.
    pub working_dir: String,

    /// Optional container user or UID[:GID] string.
    pub user: Option<String>,

    /// Signal to deliver to the container process when requesting graceful termination.
    pub stop_signal: String,
}

/// Container-creation overrides applied over an OCI image configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImageConfigOverrides {
    /// Overrides image Entrypoint. An explicit `Some(vec![])` clears the image Entrypoint.
    pub entrypoint: Option<Vec<String>>,

    /// Overrides image Cmd. An explicit `Some(vec![])` clears the image Cmd.
    pub command: Option<Vec<String>>,

    /// User-specified environment overrides in KEY=VALUE format.
    pub env: Vec<String>,

    /// Overrides image WorkingDir. Must be an absolute path.
    pub working_dir: Option<String>,

    /// Overrides image User. An empty string explicitly clears the user setting.
    pub user: Option<String>,

    /// Overrides image StopSignal.
    pub stop_signal: Option<String>,
}

impl ImageConfigOverrides {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entrypoint<I, S>(mut self, entrypoint: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoint = Some(entrypoint.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = Some(command.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_env<I, S>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.env = env.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_working_dir<S: Into<String>>(mut self, working_dir: S) -> Self {
        self.working_dir = Some(working_dir.into());
        self
    }

    pub fn with_user<S: Into<String>>(mut self, user: S) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_stop_signal<S: Into<String>>(mut self, stop_signal: S) -> Self {
        self.stop_signal = Some(stop_signal.into());
        self
    }
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

    /// Extracts, validates, and returns all declared volume destinations from this image configuration.
    pub fn declared_volumes(&self) -> Result<Vec<ImageVolume>, ImageError> {
        match self.config {
            Some(ref c) => c.declared_volumes(),
            None => Ok(Vec::new()),
        }
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

    /// Resolves image configuration against container-creation overrides to produce
    /// a deterministic, validated effective execution configuration.
    pub fn resolve(
        &self,
        overrides: &ImageConfigOverrides,
    ) -> Result<EffectiveImageConfig, ImageError> {
        // 1. Resolve Command and Arguments
        let effective_entrypoint: &[String] = match overrides.entrypoint.as_deref() {
            Some(custom) => custom,
            None => self
                .config
                .as_ref()
                .and_then(|c| c.entrypoint.as_deref())
                .unwrap_or(&[]),
        };

        let effective_cmd: &[String] = match overrides.command.as_deref() {
            Some(custom) => custom,
            None => self
                .config
                .as_ref()
                .and_then(|c| c.cmd.as_deref())
                .unwrap_or(&[]),
        };

        let args: Vec<String> = if !effective_entrypoint.is_empty() {
            let mut combined = Vec::with_capacity(effective_entrypoint.len() + effective_cmd.len());
            combined.extend_from_slice(effective_entrypoint);
            combined.extend_from_slice(effective_cmd);
            combined
        } else {
            effective_cmd.to_vec()
        };

        if args.is_empty() {
            return Err(ImageError::InvalidConfiguration(
                "No executable specified: both Entrypoint and Cmd are empty".to_string(),
            ));
        }

        if args[0].trim().is_empty() {
            return Err(ImageError::InvalidConfiguration(
                "Executable in argv[0] must not be empty or whitespace".to_string(),
            ));
        }

        for (idx, arg) in args.iter().enumerate() {
            if arg.contains('\0') {
                return Err(ImageError::InvalidConfiguration(format!(
                    "Argument at index {idx} contains forbidden null byte"
                )));
            }
        }

        // 2. Resolve Environment
        let image_env = self
            .config
            .as_ref()
            .and_then(|c| c.env.as_deref())
            .unwrap_or(&[]);

        let mut env_order: Vec<String> = Vec::new();
        let mut env_map: HashMap<String, String> = HashMap::new();

        for entry in image_env {
            let (k, v) = parse_env_entry(entry)?;
            if !env_map.contains_key(k) {
                env_order.push(k.to_string());
            }
            env_map.insert(k.to_string(), v.to_string());
        }

        for entry in &overrides.env {
            let (k, v) = parse_env_entry(entry)?;
            if !env_map.contains_key(k) {
                env_order.push(k.to_string());
            }
            env_map.insert(k.to_string(), v.to_string());
        }

        let env: Vec<String> = env_order
            .into_iter()
            .map(|k| {
                let v = &env_map[&k];
                format!("{k}={v}")
            })
            .collect();

        // 3. Resolve Working Directory
        let raw_wd = if let Some(ref override_wd) = overrides.working_dir {
            override_wd.as_str()
        } else if let Some(ref img_wd) = self.config.as_ref().and_then(|c| c.working_dir.as_deref())
        {
            if img_wd.is_empty() {
                "/"
            } else {
                img_wd
            }
        } else {
            "/"
        };

        if raw_wd.is_empty() || !raw_wd.starts_with('/') {
            return Err(ImageError::InvalidConfiguration(format!(
                "Invalid working directory '{raw_wd}': must be an absolute path starting with '/'"
            )));
        }

        if raw_wd.contains('\0') {
            return Err(ImageError::InvalidConfiguration(
                "Working directory contains forbidden null byte".to_string(),
            ));
        }

        for comp in raw_wd.split('/') {
            if comp == ".." {
                return Err(ImageError::InvalidConfiguration(format!(
                    "Invalid working directory '{raw_wd}': parent traversal '..' is forbidden"
                )));
            }
        }

        let working_dir = raw_wd.to_string();

        // 4. Resolve User
        let user = if let Some(ref override_user) = overrides.user {
            if override_user.trim().is_empty() {
                None // Explicitly cleared
            } else {
                if override_user.contains('\0') {
                    return Err(ImageError::InvalidConfiguration(
                        "User override contains forbidden null byte".to_string(),
                    ));
                }
                Some(override_user.clone())
            }
        } else if let Some(ref img_user) = self.config.as_ref().and_then(|c| c.user.as_deref()) {
            if img_user.trim().is_empty() {
                None
            } else {
                Some(img_user.to_string())
            }
        } else {
            None
        };

        // 5. Resolve StopSignal
        let raw_signal = if let Some(ref override_sig) = overrides.stop_signal {
            override_sig.as_str()
        } else if let Some(ref img_sig) =
            self.config.as_ref().and_then(|c| c.stop_signal.as_deref())
        {
            img_sig
        } else {
            "SIGTERM"
        };

        if raw_signal.trim().is_empty() {
            return Err(ImageError::InvalidConfiguration(
                "StopSignal must not be empty or whitespace".to_string(),
            ));
        }

        if raw_signal.contains('\0') {
            return Err(ImageError::InvalidConfiguration(
                "StopSignal contains forbidden null byte".to_string(),
            ));
        }

        let stop_signal = raw_signal.to_string();

        Ok(EffectiveImageConfig {
            args,
            env,
            working_dir,
            user,
            stop_signal,
        })
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
                parse_env_entry(entry)?;
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

    /// Extracts, validates, and returns all declared volume destinations from this container configuration.
    pub fn declared_volumes(&self) -> Result<Vec<ImageVolume>, ImageError> {
        let Some(ref volumes_map) = self.volumes else {
            return Ok(Vec::new());
        };

        let mut dests = Vec::with_capacity(volumes_map.len());
        for key in volumes_map.keys() {
            if key.is_empty() {
                return Err(ImageError::InvalidConfiguration(
                    "Volume declaration destination cannot be empty".to_string(),
                ));
            }
            if !key.starts_with('/') {
                return Err(ImageError::InvalidConfiguration(format!(
                    "Volume declaration destination '{key}' must be an absolute path starting with '/'"
                )));
            }
            if key.contains('\0') {
                return Err(ImageError::InvalidConfiguration(format!(
                    "Volume declaration destination '{key}' contains forbidden null byte"
                )));
            }
            for comp in key.split('/') {
                if comp == ".." {
                    return Err(ImageError::InvalidConfiguration(format!(
                        "Volume declaration destination '{key}' contains forbidden parent traversal '..'"
                    )));
                }
            }

            // Normalize path (removes redundant/trailing slashes while preserving root)
            let path = std::path::Path::new(key);
            let normalized: std::path::PathBuf = path.components().collect();

            dests.push(ImageVolume {
                destination: normalized,
            });
        }

        dests.sort();
        dests.dedup();
        Ok(dests)
    }
}

/// Parses and validates that an environment entry conforms to `KEY=VALUE` format.
fn parse_env_entry(entry: &str) -> Result<(&str, &str), ImageError> {
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

    Ok((name, val))
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
