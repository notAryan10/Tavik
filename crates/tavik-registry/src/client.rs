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
use tracing::debug;

/// High-level client for interacting with OCI Distribution v2 and Docker registries.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    http: reqwest::Client,
    auth: AuthManager,
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
        Self { http, auth }
    }

    /// Configures the client with credentials for private registries.
    pub fn with_credentials(mut self, creds: RegistryCredentials) -> Self {
        self.auth = self.auth.with_credentials(creds);
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

    /// Downloads a blob (config or layer) verified by its content digest.
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

    /// Internal helper that sends a GET request, automatically negotiating 401 auth challenges if needed.
    async fn send_with_auth(
        &self,
        url: &str,
        headers: HeaderMap,
        scope: &str,
    ) -> Result<(Bytes, Option<String>), RegistryError> {
        let req = self.http.get(url).headers(headers.clone());
        let resp = req.send().await?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
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

                let retry_resp = self.http.get(url).headers(retry_headers).send().await?;
                return self.handle_response(retry_resp, url).await;
            }
        }

        self.handle_response(resp, url).await
    }

    async fn handle_response(
        &self,
        resp: reqwest::Response,
        url: &str,
    ) -> Result<(Bytes, Option<String>), RegistryError> {
        let status = resp.status();
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
            let err_body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Protocol(format!(
                "HTTP {} for '{}': {}",
                status, url, err_body
            )));
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let bytes = resp.bytes().await?;
        Ok((bytes, content_type))
    }
}
