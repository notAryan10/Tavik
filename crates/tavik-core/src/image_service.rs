use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tavik_common::error::TavikError;
use tavik_image::archive::ArchiveReader;
use tavik_image::config::{
    EffectiveImageConfig, ImageConfigOverrides, ImageConfiguration, ImageVolume,
};
use tavik_image::filesystem::SafeDir;
use tavik_image::layer::Layer;
use tavik_image::unpacker::RootfsBuilder;
use tavik_image::user::{resolve_user, ResolvedUser};
use tavik_image::ImageError;
use tavik_runtime::spec::{ContainerState, LinuxCapabilities, Process, Root, Spec, User};
use tavik_runtime::ContainerExecutor;
use tavik_store::{ContentStore, ImageRecord, StoreError};
use tracing::{debug, info};

#[derive(Debug, thiserror::Error)]
pub enum ImageServiceError {
    #[error("Image not found: {0}")]
    ImageNotFound(String),

    #[error(
        "Incompatible platform: image is {image_os}/{image_arch}, host is {host_os}/{host_arch}"
    )]
    IncompatiblePlatform {
        image_os: String,
        image_arch: String,
        host_os: String,
        host_arch: String,
    },

    #[error("DiffID mismatch at layer index {index}: expected {expected}, got {actual}")]
    DiffIdMismatch {
        index: usize,
        expected: String,
        actual: String,
    },

    #[error("Layer count mismatch: image has {layer_count} layers but {diff_id_count} DiffIDs")]
    LayerCountMismatch {
        layer_count: usize,
        diff_id_count: usize,
    },

    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    #[error("Image error: {0}")]
    Image(#[from] ImageError),

    #[error("Runtime error: {0}")]
    Runtime(#[from] TavikError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Information returned after an OCI runtime bundle is successfully assembled from an image.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleInfo {
    pub bundle_dir: PathBuf,
    pub rootfs_dir: PathBuf,
    pub spec: Spec,
    pub image_record: ImageRecord,
    pub image_config: ImageConfiguration,
    pub effective_config: EffectiveImageConfig,
    pub resolved_user: ResolvedUser,
    pub declared_volumes: Vec<ImageVolume>,
    pub stop_signal: String,
}

/// Reusable service that bridges content-addressable storage, image configuration,
/// rootfs assembly, and OCI runtime execution.
#[derive(Clone)]
pub struct ImageService {
    store: Arc<ContentStore>,
}

impl ImageService {
    pub fn new(store: Arc<ContentStore>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &ContentStore {
        &self.store
    }

    /// Loads image metadata from store, reads the verified image configuration blob,
    /// parses it with ImageConfiguration, and verifies structural and platform constraints.
    pub async fn load_image_config(
        &self,
        reference: &str,
    ) -> Result<(ImageRecord, ImageConfiguration), ImageServiceError> {
        let record = self
            .store
            .metadata()
            .get_image(reference)
            .await?
            .ok_or_else(|| ImageServiceError::ImageNotFound(reference.to_string()))?;

        debug!(
            "Loaded image record for '{}' with config digest {}",
            reference, record.config_digest
        );

        let config_bytes = self.store.read_blob(&record.config_digest).await?;
        let config = ImageConfiguration::from_bytes(&config_bytes)?;
        config.validate()?;

        Self::validate_platform(&config)?;

        // Ensure layer count matches DiffID count
        if record.layer_digests.len() != config.rootfs.diff_ids.len() {
            return Err(ImageServiceError::LayerCountMismatch {
                layer_count: record.layer_digests.len(),
                diff_id_count: config.rootfs.diff_ids.len(),
            });
        }

        Ok((record, config))
    }

    /// Validates that the image OS and architecture are compatible with the host system.
    pub fn validate_platform(config: &ImageConfiguration) -> Result<(), ImageServiceError> {
        let host_os = std::env::consts::OS;
        let host_arch = std::env::consts::ARCH;

        // Container runtime executes Linux containers
        if !config.os.eq_ignore_ascii_case("linux") {
            return Err(ImageServiceError::IncompatiblePlatform {
                image_os: config.os.clone(),
                image_arch: config.architecture.clone(),
                host_os: host_os.to_string(),
                host_arch: host_arch.to_string(),
            });
        }

        // Validate architecture compatibility
        let is_arch_compat = match host_arch {
            "aarch64" => {
                config.architecture.eq_ignore_ascii_case("arm64")
                    || config.architecture.eq_ignore_ascii_case("aarch64")
            }
            "x86_64" => {
                config.architecture.eq_ignore_ascii_case("amd64")
                    || config.architecture.eq_ignore_ascii_case("x86_64")
            }
            other => config.architecture.eq_ignore_ascii_case(other),
        };

        if !is_arch_compat {
            return Err(ImageServiceError::IncompatiblePlatform {
                image_os: config.os.clone(),
                image_arch: config.architecture.clone(),
                host_os: host_os.to_string(),
                host_arch: host_arch.to_string(),
            });
        }

        Ok(())
    }

    /// Verifies that the decompressed DiffIDs of all layers match the configuration rootfs diff_ids.
    pub fn verify_layer_diff_ids(
        &self,
        record: &ImageRecord,
        config: &ImageConfiguration,
    ) -> Result<(), ImageServiceError> {
        if record.layer_digests.len() != config.rootfs.diff_ids.len() {
            return Err(ImageServiceError::LayerCountMismatch {
                layer_count: record.layer_digests.len(),
                diff_id_count: config.rootfs.diff_ids.len(),
            });
        }

        for (idx, (layer_digest, expected_diff_id)) in record
            .layer_digests
            .iter()
            .zip(config.rootfs.diff_ids.iter())
            .enumerate()
        {
            let blob_path = self.store.blob_path(layer_digest)?;
            let file = fs::File::open(&blob_path)?;
            let (_, mut decompressed) = ArchiveReader::open(file, None)?;

            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = decompressed.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }

            let actual_diff_id = format!("sha256:{}", hex::encode(hasher.finalize()));
            if !actual_diff_id.eq_ignore_ascii_case(expected_diff_id) {
                return Err(ImageServiceError::DiffIdMismatch {
                    index: idx,
                    expected: expected_diff_id.clone(),
                    actual: actual_diff_id,
                });
            }
        }

        Ok(())
    }

    /// Assembles the container rootfs into `dest_rootfs` using ordered layers from `record`.
    /// Never overwrites an existing destination and cleans up staging on failure.
    pub fn assemble_rootfs(
        &self,
        record: &ImageRecord,
        dest_rootfs: &Path,
    ) -> Result<(), ImageServiceError> {
        let mut layers = Vec::with_capacity(record.layer_digests.len());
        for digest in &record.layer_digests {
            let blob_path = self.store.blob_path(digest)?;
            let meta = fs::metadata(&blob_path)?;
            layers.push(Layer::new(digest.clone(), blob_path, meta.len()));
        }

        info!(
            "Assembling rootfs from {} layers into '{}'",
            layers.len(),
            dest_rootfs.display()
        );

        RootfsBuilder::new().build_rootfs(&layers, dest_rootfs)?;
        Ok(())
    }

    /// Resolves executable command inside the container rootfs safely along the container's PATH.
    /// Never touches host process PATH or host executables.
    pub fn resolve_executable_path(
        rootfs_path: &Path,
        command: &str,
        env: &[String],
    ) -> Result<String, ImageServiceError> {
        if command.contains('/') {
            // Explicit relative or absolute path within rootfs
            return Ok(command.to_string());
        }

        let path_var = env
            .iter()
            .find_map(|e| e.strip_prefix("PATH="))
            .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

        let safe_dir = SafeDir::open_rootfs(rootfs_path)?;

        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let rel_dir = dir.trim_start_matches('/');
            let candidate_rel = Path::new(rel_dir).join(command);

            if let Ok(true) = safe_dir.exists_at(&candidate_rel) {
                let resolved = format!("{}/{}", dir.trim_end_matches('/'), command);
                debug!(
                    "Resolved container executable '{}' along container PATH to '{}'",
                    command, resolved
                );
                return Ok(resolved);
            }
        }

        // Fall back to original command name if not found in rootfs PATH
        Ok(command.to_string())
    }

    /// Builds a full OCI Runtime Specification from resolved image configuration.
    pub fn build_spec(
        &self,
        config: &ImageConfiguration,
        effective: &EffectiveImageConfig,
        user: &ResolvedUser,
        volumes: &[ImageVolume],
        rootfs_path: &Path,
    ) -> Result<Spec, ImageServiceError> {
        let mut spec = Spec::default_linux();

        if effective.args.is_empty() {
            return Err(ImageServiceError::Config(
                "Effective container command args cannot be empty".to_string(),
            ));
        }

        // Resolve executable path safely within rootfs
        let resolved_exec =
            Self::resolve_executable_path(rootfs_path, &effective.args[0], &effective.env)?;

        let mut final_args = effective.args.clone();
        final_args[0] = resolved_exec;

        let process = Process {
            terminal: false,
            user: User {
                uid: user.uid,
                gid: user.gid,
                additional_gids: user.additional_gids.clone(),
            },
            args: final_args,
            env: effective.env.clone(),
            cwd: effective.working_dir.clone(),
            no_new_privileges: true,
            capabilities: Some(LinuxCapabilities {
                bounding: default_caps(),
                effective: default_caps(),
                permitted: default_caps(),
                inheritable: vec![],
                ambient: vec![],
            }),
        };

        spec.process = Some(process);
        spec.root = Some(Root {
            path: "rootfs".to_string(),
            readonly: false,
        });

        // Populate metadata annotations
        let mut annotations = HashMap::new();
        annotations.insert(
            "tavik.image.architecture".to_string(),
            config.architecture.clone(),
        );
        annotations.insert("tavik.image.os".to_string(), config.os.clone());
        annotations.insert(
            "tavik.stop_signal".to_string(),
            effective.stop_signal.clone(),
        );
        annotations.insert(
            "org.opencontainers.image.stopSignal".to_string(),
            effective.stop_signal.clone(),
        );

        if let Ok(vols_json) = serde_json::to_string(&volumes) {
            annotations.insert("tavik.image.volumes".to_string(), vols_json);
        }

        if let Some(ref c) = config.config {
            if let Some(ref labels) = c.labels {
                for (k, v) in labels {
                    annotations.insert(format!("image.label.{}", k), v.clone());
                }
            }
        }

        spec.annotations = annotations;
        Ok(spec)
    }

    /// Assembles an OCI runtime bundle (rootfs + config.json) ready for execution.
    pub async fn create_bundle(
        &self,
        reference: &str,
        dest_bundle_dir: &Path,
        overrides: Option<&ImageConfigOverrides>,
        verify_diff_ids: bool,
    ) -> Result<BundleInfo, ImageServiceError> {
        let (record, config) = self.load_image_config(reference).await?;

        if verify_diff_ids {
            self.verify_layer_diff_ids(&record, &config)?;
        }

        fs::create_dir_all(dest_bundle_dir)?;

        let rootfs_dir = dest_bundle_dir.join("rootfs");
        if let Err(e) = self.assemble_rootfs(&record, &rootfs_dir) {
            // Clean up bundle directory on rootfs assembly failure
            let _ = fs::remove_dir_all(dest_bundle_dir);
            return Err(e);
        }

        let default_overrides = ImageConfigOverrides::default();
        let effective = match config.resolve(overrides.unwrap_or(&default_overrides)) {
            Ok(c) => c,
            Err(e) => {
                let _ = fs::remove_dir_all(dest_bundle_dir);
                return Err(ImageServiceError::Image(e));
            }
        };

        let user = match resolve_user(&rootfs_dir, effective.user.as_deref()) {
            Ok(u) => u,
            Err(e) => {
                let _ = fs::remove_dir_all(dest_bundle_dir);
                return Err(ImageServiceError::Image(e));
            }
        };

        let volumes = match config.declared_volumes() {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_dir_all(dest_bundle_dir);
                return Err(ImageServiceError::Image(e));
            }
        };

        let spec = match self.build_spec(&config, &effective, &user, &volumes, &rootfs_dir) {
            Ok(s) => s,
            Err(e) => {
                let _ = fs::remove_dir_all(dest_bundle_dir);
                return Err(e);
            }
        };

        // Write config.json atomically
        let config_json_path = dest_bundle_dir.join("config.json");
        let tmp_config_path = dest_bundle_dir.join("config.json.tmp");
        let spec_data = serde_json::to_vec_pretty(&spec).map_err(|e| {
            let _ = fs::remove_dir_all(dest_bundle_dir);
            ImageServiceError::Config(format!("Failed to serialize OCI config.json: {}", e))
        })?;

        if let Err(e) = fs::write(&tmp_config_path, &spec_data) {
            let _ = fs::remove_dir_all(dest_bundle_dir);
            return Err(ImageServiceError::Io(e));
        }

        if let Err(e) = fs::rename(&tmp_config_path, &config_json_path) {
            let _ = fs::remove_dir_all(dest_bundle_dir);
            return Err(ImageServiceError::Io(e));
        }

        let stop_signal = effective.stop_signal.clone();

        info!(
            "Successfully created OCI bundle at '{}' for image '{}'",
            dest_bundle_dir.display(),
            reference
        );

        Ok(BundleInfo {
            bundle_dir: dest_bundle_dir.to_path_buf(),
            rootfs_dir,
            spec,
            image_record: record,
            image_config: config,
            effective_config: effective,
            resolved_user: user,
            declared_volumes: volumes,
            stop_signal,
        })
    }

    /// High-level workflow: creates an OCI bundle and immediately creates and starts the container.
    pub async fn create_and_run_container(
        &self,
        executor: &ContainerExecutor,
        container_id: &str,
        reference: &str,
        bundle_dir: &Path,
        overrides: Option<&ImageConfigOverrides>,
    ) -> Result<ContainerState, ImageServiceError> {
        let bundle_info = self
            .create_bundle(reference, bundle_dir, overrides, false)
            .await?;
        let _state = executor.create(container_id, &bundle_info.bundle_dir)?;
        let running_state = executor.start(container_id)?;
        Ok(running_state)
    }

    /// Stops a container using its image-configured stop signal.
    pub fn stop_container(
        &self,
        executor: &ContainerExecutor,
        container_id: &str,
    ) -> Result<(), ImageServiceError> {
        let state = executor.load_state(container_id)?;
        let signal_str = state
            .annotations
            .get("tavik.stop_signal")
            .or_else(|| state.annotations.get("org.opencontainers.image.stopSignal"))
            .map(|s| s.as_str())
            .unwrap_or("SIGTERM");

        let signal_num = parse_signal(signal_str);
        executor.kill(container_id, signal_num)?;
        Ok(())
    }
}

pub fn parse_signal(sig: &str) -> i32 {
    match sig.to_uppercase().as_str() {
        "SIGTERM" | "15" => 15,
        "SIGKILL" | "9" => 9,
        "SIGINT" | "2" => 2,
        "SIGHUP" | "1" => 1,
        "SIGQUIT" | "3" => 3,
        "SIGSTOP" | "19" => 19,
        "SIGCONT" | "18" => 18,
        "SIGUSR1" | "10" => 10,
        "SIGUSR2" | "12" => 12,
        other => other.parse::<i32>().unwrap_or(15),
    }
}

fn default_caps() -> Vec<String> {
    vec![
        "CAP_CHOWN".to_string(),
        "CAP_DAC_OVERRIDE".to_string(),
        "CAP_FOWNER".to_string(),
        "CAP_FSETID".to_string(),
        "CAP_KILL".to_string(),
        "CAP_SETGID".to_string(),
        "CAP_SETUID".to_string(),
        "CAP_SETPCAP".to_string(),
        "CAP_NET_BIND_SERVICE".to_string(),
        "CAP_NET_RAW".to_string(),
        "CAP_SYS_CHROOT".to_string(),
        "CAP_MKNOD".to_string(),
        "CAP_AUDIT_WRITE".to_string(),
        "CAP_SETFCAP".to_string(),
    ]
}
