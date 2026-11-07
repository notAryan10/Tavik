pub mod auth;
pub mod client;
pub mod descriptor;
pub mod error;
pub mod manifest;
pub mod reference;

pub use auth::{AuthChallenge, AuthManager, RegistryCredentials};
pub use client::{DownloadedBlob, RegistryClient};
pub use descriptor::{
    Descriptor, Platform, DOCKER_CONTAINER_CONFIG, DOCKER_LAYER_TAR_GZIP, DOCKER_MANIFEST_LIST_V2,
    DOCKER_MANIFEST_V2, OCI_CONFIG_JSON, OCI_IMAGE_INDEX_V1, OCI_LAYER_TAR, OCI_LAYER_TAR_GZIP,
    OCI_LAYER_TAR_ZSTD, OCI_MANIFEST_V1,
};
pub use error::RegistryError;
pub use manifest::{Manifest, OciImageIndex, OciManifest};
pub use reference::ImageReference;
