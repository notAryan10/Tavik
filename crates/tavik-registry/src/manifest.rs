use crate::descriptor::{
    Descriptor, DOCKER_MANIFEST_LIST_V2, DOCKER_MANIFEST_V2, OCI_IMAGE_INDEX_V1, OCI_MANIFEST_V1,
};
use crate::error::RegistryError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An OCI Image Manifest describing an individual container image's config and layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    pub config: Descriptor,

    pub layers: Vec<Descriptor>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

/// An OCI Image Index (or Docker Manifest List) pointing to platform-specific manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImageIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    pub manifests: Vec<Descriptor>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

/// Represents either a single image manifest or a multi-platform image index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manifest {
    Single(Box<OciManifest>),
    Index(OciImageIndex),
}

impl Manifest {
    /// Parses raw JSON bytes into either an `OciManifest` or `OciImageIndex`.
    /// Inspects the optional content-type header or the JSON content structure.
    pub fn parse(bytes: &[u8], content_type: Option<&str>) -> Result<Self, RegistryError> {
        let clean_content_type = content_type
            .map(|ct| ct.split(';').next().unwrap_or("").trim())
            .unwrap_or("");

        // Check by explicit media type header first
        match clean_content_type {
            OCI_MANIFEST_V1 | DOCKER_MANIFEST_V2 => {
                let manifest: OciManifest = serde_json::from_slice(bytes)?;
                return Ok(Self::Single(Box::new(manifest)));
            }
            OCI_IMAGE_INDEX_V1 | DOCKER_MANIFEST_LIST_V2 => {
                let index: OciImageIndex = serde_json::from_slice(bytes)?;
                return Ok(Self::Index(index));
            }
            _ => {}
        }

        // Fallback: try parsing as Image Index (which has `manifests` array)
        if let Ok(index) = serde_json::from_slice::<OciImageIndex>(bytes) {
            if !index.manifests.is_empty() {
                return Ok(Self::Index(index));
            }
        }

        // Try parsing as Single Manifest (which has `config` and `layers`)
        let manifest: OciManifest = serde_json::from_slice(bytes)?;
        Ok(Self::Single(Box::new(manifest)))
    }

    /// If this is a multi-platform index, selects the manifest descriptor matching the target platform.
    /// If this is already a single manifest, returns None (the caller directly uses it).
    pub fn find_platform_descriptor(
        &self,
        target_os: &str,
        target_arch: &str,
        variant: Option<&str>,
    ) -> Result<Option<&Descriptor>, RegistryError> {
        match self {
            Self::Single(_) => Ok(None),
            Self::Index(index) => {
                let mut available = Vec::new();
                for desc in &index.manifests {
                    if let Some(p) = &desc.platform {
                        available.push(format!("{}/{}", p.os, p.architecture));
                        if p.matches(target_os, target_arch, variant) {
                            return Ok(Some(desc));
                        }
                    }
                }

                Err(RegistryError::PlatformNotFound {
                    os: target_os.to_string(),
                    arch: target_arch.to_string(),
                })
            }
        }
    }

    /// Returns the single manifest if this is a `Manifest::Single`.
    pub fn as_single(&self) -> Option<&OciManifest> {
        match self {
            Self::Single(m) => Some(m),
            Self::Index(_) => None,
        }
    }

    /// Returns the image index if this is a `Manifest::Index`.
    pub fn as_index(&self) -> Option<&OciImageIndex> {
        match self {
            Self::Single(_) => None,
            Self::Index(i) => Some(i),
        }
    }
}
