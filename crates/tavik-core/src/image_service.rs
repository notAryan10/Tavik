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
use tavik_image::layer::Layer;
use tavik_image::unpacker::RootfsBuilder;
use tavik_image::user::{resolve_user, ResolvedUser};
use tavik_image::ImageError;
use tavik_runtime::spec::{ContainerState, LinuxCapabilities, Process, Root, Spec, User};
use tavik_runtime::ContainerExecutor;
use tavik_store::{ContentStore, ImageRecord, StoreError};
use tracing::{debug, info, warn};

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

    #[error("Destination bundle directory already exists: '{0}'")]
    DestinationAlreadyExists(PathBuf),

    #[error("Configuration blob digest mismatch: expected '{expected}', got actual '{actual}'")]
    ConfigDigestMismatch { expected: String, actual: String },

    #[error("Invalid signal '{0}': {1}")]
    InvalidSignal(String, String),

    #[error("Unsupported operation or platform: {0}")]
    Unsupported(String),

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

        // Verify configuration blob integrity against record.config_digest
        let mut hasher = Sha256::new();
        hasher.update(&config_bytes);
        let actual_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
        if !actual_digest.eq_ignore_ascii_case(&record.config_digest) {
            return Err(ImageServiceError::ConfigDigestMismatch {
                expected: record.config_digest.clone(),
                actual: actual_digest,
            });
        }

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

    /// Returns the command name without inspecting the host filesystem.
    /// Real executable path lookup is strictly performed by the runtime init after pivot_root.
    pub fn resolve_executable_path(
        _rootfs_path: &Path,
        command: &str,
        _env: &[String],
    ) -> Result<String, ImageServiceError> {
        Ok(command.to_string())
    }

    /// Builds a full OCI Runtime Specification from resolved image configuration.
    pub fn build_spec(
        &self,
        config: &ImageConfiguration,
        effective: &EffectiveImageConfig,
        user: &ResolvedUser,
        volumes: &[ImageVolume],
        _rootfs_path: &Path,
    ) -> Result<Spec, ImageServiceError> {
        let mut spec = Spec::default_linux();

        if effective.args.is_empty() {
            return Err(ImageServiceError::Config(
                "Effective container command args cannot be empty".to_string(),
            ));
        }

        // Preserve process arguments exactly; executable lookup is strictly performed
        // inside the runtime after pivot_root with container credentials to prevent host filesystem probing.
        let final_args = effective.args.clone();

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
        if dest_bundle_dir.exists() {
            return Err(ImageServiceError::DestinationAlreadyExists(
                dest_bundle_dir.to_path_buf(),
            ));
        }

        let (record, config) = self.load_image_config(reference).await?;

        if verify_diff_ids {
            self.verify_layer_diff_ids(&record, &config)?;
        }

        let parent = dest_bundle_dir.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let dest_name = dest_bundle_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("bundle");
        let staging_dir = parent.join(format!(
            ".tmp-bundle-{}-{}",
            dest_name,
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&staging_dir)?;
        let mut staging_guard = StagingGuard::new(staging_dir.clone());

        let rootfs_dir = staging_dir.join("rootfs");
        self.assemble_rootfs(&record, &rootfs_dir)?;

        let default_overrides = ImageConfigOverrides::default();
        let effective = config.resolve(overrides.unwrap_or(&default_overrides))?;

        let user = resolve_user(&rootfs_dir, effective.user.as_deref())?;
        let volumes = config.declared_volumes()?;

        // Validate stop signal
        let _ = parse_signal(&effective.stop_signal)?;

        let spec = self.build_spec(&config, &effective, &user, &volumes, &rootfs_dir)?;

        let config_json_path = staging_dir.join("config.json");
        let spec_data = serde_json::to_vec_pretty(&spec).map_err(|e| {
            ImageServiceError::Config(format!("Failed to serialize OCI config.json: {}", e))
        })?;

        fs::write(&config_json_path, &spec_data)?;

        // Atomic publish using no-replace rename
        atomic_rename_noreplace(&staging_dir, dest_bundle_dir)?;
        staging_guard.disarm();

        let stop_signal = effective.stop_signal.clone();

        info!(
            "Successfully created OCI bundle at '{}' for image '{}'",
            dest_bundle_dir.display(),
            reference
        );

        Ok(BundleInfo {
            bundle_dir: dest_bundle_dir.to_path_buf(),
            rootfs_dir: dest_bundle_dir.join("rootfs"),
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
            .create_bundle(reference, bundle_dir, overrides, true)
            .await?;
        let _state = executor.create(container_id, &bundle_info.bundle_dir)?;
        let running_state = match executor.start(container_id) {
            Ok(s) => s,
            Err(e) => {
                if let Err(del_err) = executor.delete(container_id, true) {
                    warn!(
                        "Failed to delete container '{}' after start failure: {}",
                        container_id, del_err
                    );
                }
                return Err(ImageServiceError::Runtime(e));
            }
        };
        Ok(running_state)
    }

    /// Stops a container using its image-configured stop signal.
    pub fn stop_container(
        &self,
        executor: &ContainerExecutor,
        container_id: &str,
    ) -> Result<ContainerState, ImageServiceError> {
        self.stop_container_with_timeout(executor, container_id, None)
    }

    /// Stops a container using its image-configured stop signal with a configurable grace period.
    pub fn stop_container_with_timeout(
        &self,
        executor: &ContainerExecutor,
        container_id: &str,
        grace_period: Option<std::time::Duration>,
    ) -> Result<ContainerState, ImageServiceError> {
        let state = executor.load_state(container_id)?;
        let signal_str = state
            .annotations
            .get("tavik.stop_signal")
            .or_else(|| state.annotations.get("org.opencontainers.image.stopSignal"))
            .map(|s| s.as_str())
            .unwrap_or("SIGTERM");

        let signal_num = parse_signal(signal_str)?;
        let stopped_state = executor.stop(container_id, Some(signal_num), grace_period)?;
        Ok(stopped_state)
    }
}

struct StagingGuard {
    path: Option<PathBuf>,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn atomic_rename_noreplace(src: &Path, dst: &Path) -> Result<(), ImageServiceError> {
    if dst.exists() {
        return Err(ImageServiceError::DestinationAlreadyExists(
            dst.to_path_buf(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| ImageServiceError::Config(format!("Invalid path for rename: {}", e)))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| ImageServiceError::Config(format!("Invalid path for rename: {}", e)))?;

        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                c_src.as_ptr(),
                libc::AT_FDCWD,
                c_dst.as_ptr(),
                1u32, // RENAME_NOREPLACE
            )
        };

        if ret == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Err(ImageServiceError::DestinationAlreadyExists(
                dst.to_path_buf(),
            ));
        }

        // Fail closed! Never fall back to ordinary fs::rename
        return Err(ImageServiceError::Unsupported(format!(
            "Atomic no-replace rename failed or is unsupported on this filesystem: {}",
            err
        )));
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| ImageServiceError::Config(format!("Invalid path for rename: {}", e)))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| ImageServiceError::Config(format!("Invalid path for rename: {}", e)))?;

        extern "C" {
            fn renamex_np(
                from: *const libc::c_char,
                to: *const libc::c_char,
                flags: libc::c_uint,
            ) -> libc::c_int;
        }
        const RENAME_EXCL: libc::c_uint = 0x00000004;

        let ret = unsafe { renamex_np(c_src.as_ptr(), c_dst.as_ptr(), RENAME_EXCL) };
        if ret == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Err(ImageServiceError::DestinationAlreadyExists(
                dst.to_path_buf(),
            ));
        }

        Err(ImageServiceError::Unsupported(format!(
            "Atomic exclusive rename failed or is unsupported on this filesystem: {}",
            err
        )))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(ImageServiceError::Unsupported(
            "Atomic exclusive rename is not supported on this platform".to_string(),
        ))
    }
}

pub fn parse_signal(sig: &str) -> Result<i32, ImageServiceError> {
    let trimmed = sig.trim();
    if trimmed.is_empty() {
        return Err(ImageServiceError::InvalidSignal(
            sig.to_string(),
            "Signal cannot be empty".to_string(),
        ));
    }

    // Check if numeric
    if let Ok(num) = trimmed.parse::<i64>() {
        if num <= 0 {
            return Err(ImageServiceError::InvalidSignal(
                sig.to_string(),
                format!("Signal number must be positive (1..=64), got {num}"),
            ));
        }
        if num == 18 || num == 19 {
            return Err(ImageServiceError::InvalidSignal(
                sig.to_string(),
                "Process-control signals (STOP=19, CONT=18) cannot be used as container stop signals".to_string(),
            ));
        }
        if num > 64 {
            return Err(ImageServiceError::InvalidSignal(
                sig.to_string(),
                format!("Signal number {num} exceeds maximum supported signal (64)"),
            ));
        }
        return Ok(num as i32);
    }

    // Symbolic signal
    let normalized = trimmed.to_ascii_uppercase();
    let name = normalized.strip_prefix("SIG").unwrap_or(&normalized);

    if name == "STOP" || name == "CONT" {
        return Err(ImageServiceError::InvalidSignal(
            sig.to_string(),
            "Process-control signals (SIGSTOP, SIGCONT) cannot be used as container stop signals"
                .to_string(),
        ));
    }

    let signum = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" => 17,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        unknown => {
            return Err(ImageServiceError::InvalidSignal(
                sig.to_string(),
                format!("Unknown signal name: '{unknown}'"),
            ));
        }
    };

    Ok(signum)
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
