use crate::client::RegistryClient;
use crate::error::RegistryError;
use crate::reference::ImageReference;
use chrono::Utc;
use tavik_store::{ContentStore, ImageRecord};
use tracing::{debug, info};

/// Result of an image pull operation into local content-addressable storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResult {
    pub record: ImageRecord,
    pub newly_downloaded_blobs: usize,
    pub reused_blobs: usize,
}

/// Orchestrates pulling an OCI image from a registry and ingesting all manifests,
/// configs, and layers into local content-addressable storage (CAS).
///
/// Ensures:
/// 1. Manifest is resolved for the target platform.
/// 2. Config and layer blobs are streamed, hashed with SHA-256, and verified.
/// 3. Blobs already present in CAS are reused without re-downloading.
/// 4. Temporary download files are cleaned up only after CAS ingestion succeeds.
/// 5. Image metadata is recorded as the final atomic operation once all content is verified.
pub async fn pull_image(
    client: &RegistryClient,
    store: &ContentStore,
    reference: &ImageReference,
    target_os: &str,
    target_arch: &str,
    target_variant: Option<&str>,
) -> Result<PullResult, RegistryError> {
    info!(
        "Resolving manifest for image '{}' on platform '{}/{}'...",
        reference, target_os, target_arch
    );

    // 1. Resolve manifest for the target platform
    let (manifest, manifest_digest) = client
        .resolve_manifest_for_platform(reference, target_os, target_arch, target_variant)
        .await?;

    let mut newly_downloaded_blobs = 0;
    let mut reused_blobs = 0;

    // 2. Download and ingest config blob
    let config_digest = &manifest.config.digest;
    if store.has_blob(config_digest) {
        debug!("Config blob {} already in CAS; reusing", config_digest);
        reused_blobs += 1;
    } else {
        debug!("Downloading config blob {}...", config_digest);
        let config_bytes = client.download_blob(reference, config_digest).await?;
        store
            .ingest_bytes(&config_bytes, Some(config_digest))
            .await?;
        newly_downloaded_blobs += 1;
    }

    // 3. Download and ingest each layer blob
    let mut layer_digests = Vec::with_capacity(manifest.layers.len());
    let mut total_size = manifest.config.size;

    for (idx, layer) in manifest.layers.iter().enumerate() {
        total_size += layer.size;
        layer_digests.push(layer.digest.clone());

        if store.has_blob(&layer.digest) {
            debug!(
                "Layer {} ({}) already present in CAS; skipping download",
                idx, layer.digest
            );
            reused_blobs += 1;
            continue;
        }

        debug!(
            "Streaming layer {} ({}, {} bytes)...",
            idx, layer.digest, layer.size
        );

        // Download to a temporary file in the store's tmp directory
        let temp_filename = format!("pull.tmp.{}", uuid::Uuid::new_v4());
        let temp_download_path = store.root().join("tmp").join(temp_filename);

        let dl_res = client
            .download_blob_stream(
                reference,
                &layer.digest,
                Some(layer.size),
                &temp_download_path,
            )
            .await;

        if let Err(e) = dl_res {
            let _ = tokio::fs::remove_file(&temp_download_path).await;
            return Err(e);
        }

        // Ingest into CAS with verification
        let ingest_res = store
            .ingest_file(&temp_download_path, Some(&layer.digest))
            .await;

        // Cleanup temporary download file after ingestion
        let _ = tokio::fs::remove_file(&temp_download_path).await;

        ingest_res?;
        newly_downloaded_blobs += 1;
    }

    // 4. Record image metadata entry as the final atomic operation
    let now = Utc::now();
    let record = ImageRecord {
        reference: reference.canonical(),
        manifest_digest,
        config_digest: config_digest.clone(),
        layer_digests,
        size: total_size,
        created_at: now,
        updated_at: now,
    };

    store.metadata().save_image(record.clone()).await?;

    info!(
        "Image '{}' successfully pulled and stored in CAS ({} bytes, {} new blobs, {} reused blobs)",
        reference, total_size, newly_downloaded_blobs, reused_blobs
    );

    Ok(PullResult {
        record,
        newly_downloaded_blobs,
        reused_blobs,
    })
}
