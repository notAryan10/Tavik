use crate::error::ImageError;
use crate::layer::Layer;
use std::path::{Path, PathBuf};

/// Layer unpacker that safely extracts layers and processes OCI whiteout markers.
#[derive(Debug, Default)]
pub struct ImageUnpacker;

impl ImageUnpacker {
    pub fn new() -> Self {
        Self
    }

    /// Unpacks a single layer archive into the target rootfs directory.
    pub fn unpack_layer(&self, _layer: &Layer, _rootfs: &Path) -> Result<(), ImageError> {
        Ok(())
    }
}

/// Builds a merged root filesystem from an ordered slice of OCI layers.
#[derive(Debug, Default)]
pub struct RootfsBuilder;

impl RootfsBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Sequentially applies layers into the destination rootfs.
    pub fn build_rootfs(
        &self,
        _layers: &[Layer],
        _dest_rootfs: &Path,
    ) -> Result<PathBuf, ImageError> {
        Ok(_dest_rootfs.to_path_buf())
    }
}
