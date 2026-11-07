use crate::error::RegistryError;
use std::fmt;

const DEFAULT_REGISTRY: &str = "docker.io";
const DOCKER_REGISTRY_HOST: &str = "registry-1.docker.io";
const DEFAULT_TAG: &str = "latest";

/// Represents a parsed OCI / Docker image reference.
///
/// Format: `[domain/][namespace/]repository[:tag][@digest]`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageReference {
    domain: String,
    repository: String,
    tag: Option<String>,
    digest: Option<String>,
}

impl ImageReference {
    /// Parses an image reference string according to OCI and Docker conventions.
    pub fn parse(input: &str) -> Result<Self, RegistryError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(RegistryError::InvalidReference(
                input.to_string(),
                "Reference cannot be empty".to_string(),
            ));
        }

        // 1. Separate digest if present: `@<digest>`
        let (without_digest, digest) = match input.split_once('@') {
            Some((rest, d)) => {
                if !d.contains(':') {
                    return Err(RegistryError::InvalidReference(
                        input.to_string(),
                        format!(
                            "Digest must contain algorithm prefix (e.g. sha256:...), got '{}'",
                            d
                        ),
                    ));
                }
                (rest, Some(d.to_string()))
            }
            None => (input, None),
        };

        // 2. Separate tag if present: `:<tag>`
        // Be careful not to confuse port in domain (e.g. `localhost:5000/app`) with tag.
        let (name_part, tag) = match without_digest.rsplit_once(':') {
            Some((rest, t)) => {
                // If the colon is before the first slash or there is a slash after the colon,
                // this is a port, not a tag (e.g. `localhost:5000/repo` or `host:port/path`)
                if rest.contains('/') && !t.contains('/') {
                    (rest, Some(t.to_string()))
                } else if !rest.contains('/') {
                    // Could be `alpine:latest` or `localhost:5000`
                    // In docker convention, single name with colon is image:tag
                    (rest, Some(t.to_string()))
                } else {
                    (without_digest, None)
                }
            }
            None => (without_digest, None),
        };

        // 3. Separate domain and repository
        let (raw_domain, raw_repo) = match name_part.split_once('/') {
            Some((first, rest)) => {
                // If first component contains '.' or ':' or is 'localhost', it is a domain
                if first.contains('.') || first.contains(':') || first == "localhost" {
                    (first, rest)
                } else {
                    (DEFAULT_REGISTRY, name_part)
                }
            }
            None => (DEFAULT_REGISTRY, name_part),
        };

        let domain = match raw_domain {
            "index.docker.io" | "registry-1.docker.io" => DEFAULT_REGISTRY.to_string(),
            other => other.to_string(),
        };

        // 4. Normalize Docker Hub official repositories
        let repository = if domain == DEFAULT_REGISTRY && !raw_repo.contains('/') {
            format!("library/{}", raw_repo)
        } else {
            raw_repo.to_string()
        };

        // Validate repository path
        if repository.is_empty() || repository.starts_with('/') || repository.ends_with('/') {
            return Err(RegistryError::InvalidReference(
                input.to_string(),
                "Repository path cannot be empty or have leading/trailing slashes".to_string(),
            ));
        }

        // If neither tag nor digest is specified, default tag to "latest"
        let effective_tag = if tag.is_none() && digest.is_none() {
            Some(DEFAULT_TAG.to_string())
        } else {
            tag
        };

        Ok(Self {
            domain,
            repository,
            tag: effective_tag,
            digest,
        })
    }

    /// Returns the registry domain (e.g. `docker.io`, `ghcr.io`, `localhost:5000`).
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the normalized repository path (e.g. `library/alpine`, `org/repo`).
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the tag, if present.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Returns the content digest, if present.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    /// Returns the reference selector: digest if present, otherwise tag, otherwise "latest".
    pub fn reference(&self) -> &str {
        if let Some(d) = &self.digest {
            d.as_str()
        } else if let Some(t) = &self.tag {
            t.as_str()
        } else {
            DEFAULT_TAG
        }
    }

    /// Returns the base HTTPS or HTTP URL for the registry API.
    pub fn registry_url(&self) -> String {
        if self.domain == DEFAULT_REGISTRY {
            format!("https://{}", DOCKER_REGISTRY_HOST)
        } else if self.domain.starts_with("localhost") || self.domain.starts_with("127.0.0.1") {
            format!("http://{}", self.domain)
        } else {
            format!("https://{}", self.domain)
        }
    }

    /// Returns the canonical full reference string.
    pub fn canonical(&self) -> String {
        let mut s = format!("{}/{}", self.domain, self.repository);
        if let Some(t) = &self.tag {
            s.push(':');
            s.push_str(t);
        }
        if let Some(d) = &self.digest {
            s.push('@');
            s.push_str(d);
        }
        s
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical())
    }
}
