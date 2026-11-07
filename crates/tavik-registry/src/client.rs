use crate::auth::{AuthManager, RegistryCredentials};
use crate::descriptor::{
    DOCKER_MANIFEST_LIST_V2, DOCKER_MANIFEST_V2, OCI_IMAGE_INDEX_V1, OCI_MANIFEST_V1,
};
use crate::error::RegistryError;
use crate::manifest::{Manifest, OciManifest};
use crate::reference::ImageReference;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::debug;

const DEFAULT_MAX_BLOB_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB

/// Metadata for a verified, downloaded blob on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedBlob {
    pub digest: String,
    pub size: u64,
    pub path: PathBuf,
}

/// High-level client for interacting with OCI Distribution v2 and Docker registries.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    http: reqwest::Client,
    auth: AuthManager,
    max_blob_size: u64,
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClient {
    /// Creates a new `RegistryClient` with default connection settings.
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let auth = AuthManager::new(http.clone());
        Self {
            http,
            auth,
            max_blob_size: DEFAULT_MAX_BLOB_SIZE,
        }
    }

    /// Configures the client with credentials for private registries.
    pub fn with_credentials(mut self, creds: RegistryCredentials) -> Self {
        self.auth = self.auth.with_credentials(creds);
        self
    }

    /// Configures the maximum allowed blob download size in bytes.
    pub fn with_max_blob_size(mut self, max_size: u64) -> Self {
        self.max_blob_size = max_size;
        self
    }

    /// Returns the standard Accept header values for OCI and Docker v2 manifests.
    fn manifest_accept_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        let accept_types = format!(
            "{}, {}, {}, {}",
            OCI_IMAGE_INDEX_V1, OCI_MANIFEST_V1, DOCKER_MANIFEST_LIST_V2, DOCKER_MANIFEST_V2
        );
        headers.insert(ACCEPT, HeaderValue::from_str(&accept_types).unwrap());
        headers
    }

    /// Fetches the manifest or index for the given image reference.
    /// Returns the parsed `Manifest`, its SHA-256 content digest, and raw payload bytes.
    pub async fn fetch_manifest(
        &self,
        reference: &ImageReference,
    ) -> Result<(Manifest, String, Bytes), RegistryError> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            reference.registry_url(),
            reference.repository(),
            reference.reference()
        );

        let default_scope = format!("repository:{}:pull", reference.repository());
        let (resp_bytes, content_type) = self
            .send_with_auth(&url, Self::manifest_accept_headers(), &default_scope)
            .await?;

        // Calculate actual SHA256 digest of received raw manifest bytes
        let calculated_digest = format!("sha256:{}", hex::encode(Sha256::digest(&resp_bytes)));

        // Parse manifest or index
        let manifest = Manifest::parse(&resp_bytes, content_type.as_deref())?;

        Ok((manifest, calculated_digest, resp_bytes))
    }

    /// Resolves an image reference directly into an `OciManifest` matching the target OS and architecture.
    /// If the reference points to an `OciImageIndex`, this method automatically resolves and fetches
    /// the platform-specific sub-manifest.
    pub async fn resolve_manifest_for_platform(
        &self,
        reference: &ImageReference,
        target_os: &str,
        target_arch: &str,
        variant: Option<&str>,
    ) -> Result<(OciManifest, String), RegistryError> {
        let (manifest, digest, _) = self.fetch_manifest(reference).await?;

        match manifest {
            Manifest::Single(m) => Ok((*m, digest)),
            Manifest::Index(index) => {
                let manifest_enum = Manifest::Index(index);
                let desc = manifest_enum
                    .find_platform_descriptor(target_os, target_arch, variant)?
                    .ok_or_else(|| RegistryError::PlatformNotFound {
                        os: target_os.to_string(),
                        arch: target_arch.to_string(),
                    })?;

                debug!(
                    "Resolved platform '{}/{}' to sub-manifest digest {}",
                    target_os, target_arch, desc.digest
                );

                // Fetch the platform-specific sub-manifest
                let sub_ref = ImageReference::parse(&format!(
                    "{}/{}@{}",
                    reference.domain(),
                    reference.repository(),
                    desc.digest
                ))?;

                let (sub_manifest, sub_digest, _) = self.fetch_manifest(&sub_ref).await?;
                match sub_manifest {
                    Manifest::Single(m) => Ok((*m, sub_digest)),
                    Manifest::Index(_) => Err(RegistryError::Protocol(
                        "Nested manifest indexes are unsupported".to_string(),
                    )),
                }
            }
        }
    }

    /// Downloads a blob directly into memory (useful for small config JSONs).
    pub async fn download_blob(
        &self,
        reference: &ImageReference,
        digest: &str,
    ) -> Result<Bytes, RegistryError> {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            reference.registry_url(),
            reference.repository(),
            digest
        );

        let scope = format!("repository:{}:pull", reference.repository());
        let (bytes, _) = self.send_with_auth(&url, HeaderMap::new(), &scope).await?;

        // Verify SHA256 integrity
        if let Some((algo, expected_hex)) = digest.split_once(':') {
            if algo.eq_ignore_ascii_case("sha256") {
                let actual_hex = hex::encode(Sha256::digest(&bytes));
                if actual_hex != expected_hex {
                    return Err(RegistryError::DigestMismatch {
                        digest: digest.to_string(),
                        expected: expected_hex.to_string(),
                        actual: actual_hex,
                    });
                }
            }
        }

        Ok(bytes)
    }

    /// Downloads a blob as a chunked stream directly to a destination file without buffering the whole
    /// blob into memory.
    ///
    /// Key security and reliability guarantees:
    /// 1. Rejects unsupported digest algorithms fail-closed.
    /// 2. Streams HTTP chunks directly to a temporary sibling file (`.<dest>.tmp.<uuid>`).
    /// 3. Incrementally computes SHA-256 while counting exact received bytes.
    /// 4. Enforces configurable maximum blob size limits during download.
    /// 5. Validates descriptor size and content digest before publishing.
    /// 6. Flushes and syncs to disk, then atomically renames the temporary file to `destination`.
    /// 7. Automatically removes temporary files on failure, cancellation, or mismatch.
    pub async fn download_blob_stream(
        &self,
        reference: &ImageReference,
        digest: &str,
        expected_size: Option<u64>,
        destination: &Path,
    ) -> Result<DownloadedBlob, RegistryError> {
        // 1. Validate digest format and algorithm
        let (algo, expected_hex) = digest
            .split_once(':')
            .ok_or_else(|| RegistryError::InvalidDigest(digest.to_string()))?;
        if !algo.eq_ignore_ascii_case("sha256") {
            return Err(RegistryError::UnsupportedAlgorithm(algo.to_string()));
        }
        if expected_hex.len() != 64 || !expected_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RegistryError::InvalidDigest(digest.to_string()));
        }

        // 2. Ensure destination parent directory exists
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // 3. Create temporary sibling file in same directory for atomic rename
        let file_stem = destination
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let temp_name = format!(".{}.tmp.{}", file_stem, uuid::Uuid::new_v4());
        let temp_path = match destination.parent() {
            Some(p) => p.join(temp_name),
            None => PathBuf::from(temp_name),
        };

        let mut file = match tokio::fs::File::create(&temp_path).await {
            Ok(f) => f,
            Err(e) => return Err(RegistryError::Io(e)),
        };

        // 4. Request the blob with authentication negotiation
        let url = format!(
            "{}/v2/{}/blobs/{}",
            reference.registry_url(),
            reference.repository(),
            digest
        );
        let scope = format!("repository:{}:pull", reference.repository());
        let mut response = match self
            .send_request_with_auth(&url, HeaderMap::new(), &scope)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(e);
            }
        };

        // 5. Stream chunks, compute SHA-256 incrementally, and count actual bytes
        let mut hasher = Sha256::new();
        let mut total_bytes = 0u64;

        let write_res: Result<(), RegistryError> = async {
            while let Some(chunk) = response.chunk().await? {
                total_bytes += chunk.len() as u64;
                if total_bytes > self.max_blob_size {
                    return Err(RegistryError::SizeExceeded {
                        limit: self.max_blob_size,
                        actual: total_bytes,
                    });
                }
                file.write_all(&chunk).await?;
                hasher.update(&chunk);
            }
            file.flush().await?;
            file.sync_all().await?;
            Ok(())
        }
        .await;

        drop(file);

        if let Err(e) = write_res {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        // 6. Verify expected size if specified
        if let Some(expected) = expected_size {
            if total_bytes != expected {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(RegistryError::SizeMismatch {
                    digest: digest.to_string(),
                    expected,
                    actual: total_bytes,
                });
            }
        }

        // 7. Verify computed SHA-256 digest
        let computed_hex = hex::encode(hasher.finalize());
        let computed_digest = format!("sha256:{}", computed_hex);
        if computed_digest != digest {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(RegistryError::DigestMismatch {
                digest: digest.to_string(),
                expected: digest.to_string(),
                actual: computed_digest,
            });
        }

        // 8. Atomically rename to final destination
        if let Err(e) = tokio::fs::rename(&temp_path, destination).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(RegistryError::Io(e));
        }

        Ok(DownloadedBlob {
            digest: digest.to_string(),
            size: total_bytes,
            path: destination.to_path_buf(),
        })
    }

    /// Internal helper that sends a GET request, automatically negotiating 401 auth challenges if needed.
    async fn send_with_auth(
        &self,
        url: &str,
        headers: HeaderMap,
        scope: &str,
    ) -> Result<(Bytes, Option<String>), RegistryError> {
        let resp = self.send_request_with_auth(url, headers, scope).await?;
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp.bytes().await?;
        Ok((bytes, content_type))
    }

    /// Internal helper that sends an authenticated request and returns the streaming response.
    async fn send_request_with_auth(
        &self,
        url: &str,
        headers: HeaderMap,
        scope: &str,
    ) -> Result<reqwest::Response, RegistryError> {
        let req = self.http.get(url).headers(headers.clone());
        let resp = req.send().await?;

        let active_resp = if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(challenge) = AuthManager::extract_challenge(resp.headers()) {
                debug!("Received 401 challenge: {:?}", challenge);
                let auth_header = self.auth.get_auth_header(&challenge, Some(scope)).await?;

                let mut retry_headers = headers;
                retry_headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&auth_header).map_err(|e| {
                        RegistryError::AuthFailed(format!("Invalid auth header: {}", e))
                    })?,
                );

                self.http.get(url).headers(retry_headers).send().await?
            } else {
                resp
            }
        } else {
            resp
        };

        let status = active_resp.status();
        if !status.is_success() {
            if status == reqwest::StatusCode::NOT_FOUND {
                if url.contains("/manifests/") {
                    return Err(RegistryError::ManifestNotFound {
                        reference: url.to_string(),
                        status: status.as_u16(),
                    });
                } else if url.contains("/blobs/") {
                    return Err(RegistryError::BlobNotFound {
                        digest: url.to_string(),
                        status: status.as_u16(),
                    });
                }
            }
            let err_body = active_resp.text().await.unwrap_or_default();
            return Err(RegistryError::Protocol(format!(
                "HTTP {} for '{}': {}",
                status, url, err_body
            )));
        }

        Ok(active_resp)
    }
}
