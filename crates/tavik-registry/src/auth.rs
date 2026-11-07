use crate::error::RegistryError;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::debug;

/// Represents an authentication challenge returned by a registry in a `Www-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub scheme: String,
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

impl AuthChallenge {
    /// Parses a `Www-Authenticate` header string into an `AuthChallenge`.
    pub fn parse(header_val: &str) -> Option<Self> {
        let trimmed = header_val.trim();
        let (scheme, rest) = trimmed.split_once(' ')?;
        let scheme = scheme.trim().to_string();

        let mut params = HashMap::new();
        // Parse key="value" or key=value separated by commas
        for item in rest.split(',') {
            if let Some((k, v)) = item.split_once('=') {
                let key = k.trim().to_lowercase();
                let val = v.trim().trim_matches('"').to_string();
                params.insert(key, val);
            }
        }

        let realm = params.remove("realm")?;
        let service = params.remove("service");
        let scope = params.remove("scope");

        Some(Self {
            scheme,
            realm,
            service,
            scope,
        })
    }
}

/// Token response returned by an OAuth2 or Docker token endpoint.
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    #[serde(rename = "expires_in")]
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

impl TokenResponse {
    fn extract_token(&self) -> Option<&str> {
        self.token.as_deref().or(self.access_token.as_deref())
    }
}

/// Registry credentials for authenticated access.
#[derive(Debug, Clone, Default)]
pub struct RegistryCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Token manager that acquires and caches Bearer tokens for registry scopes.
#[derive(Debug, Clone)]
pub struct AuthManager {
    http: reqwest::Client,
    credentials: Option<RegistryCredentials>,
    token_cache: Arc<Mutex<HashMap<String, String>>>,
}

impl AuthManager {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            credentials: None,
            token_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_credentials(mut self, creds: RegistryCredentials) -> Self {
        self.credentials = Some(creds);
        self
    }

    /// Acquires a valid Authorization header value (e.g. `Bearer <token>`) for the given challenge and scope.
    pub async fn get_auth_header(
        &self,
        challenge: &AuthChallenge,
        scope: Option<&str>,
    ) -> Result<String, RegistryError> {
        if challenge.scheme.eq_ignore_ascii_case("bearer") {
            let effective_scope = scope.or(challenge.scope.as_deref());
            let cache_key = format!(
                "{}|{}|{}",
                challenge.realm,
                challenge.service.as_deref().unwrap_or(""),
                effective_scope.unwrap_or("")
            );

            // Check cache
            {
                let cache = self.token_cache.lock().unwrap();
                if let Some(tok) = cache.get(&cache_key) {
                    return Ok(format!("Bearer {}", tok));
                }
            }

            // Request new token
            let mut req = self.http.get(&challenge.realm);
            if let Some(service) = &challenge.service {
                req = req.query(&[("service", service.as_str())]);
            }
            if let Some(sc) = effective_scope {
                req = req.query(&[("scope", sc)]);
            }

            // If credentials are provided, pass basic auth to the token endpoint
            if let Some(creds) = &self.credentials {
                if let (Some(u), Some(p)) = (&creds.username, &creds.password) {
                    req = req.basic_auth(u, Some(p));
                }
            }

            debug!("Requesting bearer token from {}", challenge.realm);
            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(RegistryError::AuthFailed(format!(
                    "Token request to '{}' failed with status {}: {}",
                    challenge.realm, status, body
                )));
            }

            let token_resp: TokenResponse = resp.json().await?;
            let token = token_resp.extract_token().ok_or_else(|| {
                RegistryError::AuthFailed("Token response missing token field".to_string())
            })?;

            // Store in cache
            {
                let mut cache = self.token_cache.lock().unwrap();
                cache.insert(cache_key, token.to_string());
            }

            Ok(format!("Bearer {}", token))
        } else if challenge.scheme.eq_ignore_ascii_case("basic") {
            if let Some(creds) = &self.credentials {
                if let (Some(u), Some(p)) = (&creds.username, &creds.password) {
                    let b64 = base64_encode(format!("{}:{}", u, p).as_bytes());
                    return Ok(format!("Basic {}", b64));
                }
            }
            Err(RegistryError::AuthFailed(
                "Basic auth required but no credentials provided".to_string(),
            ))
        } else {
            Err(RegistryError::AuthFailed(format!(
                "Unsupported auth scheme '{}'",
                challenge.scheme
            )))
        }
    }

    /// Extracts an `AuthChallenge` from HTTP response headers, if present.
    pub fn extract_challenge(headers: &HeaderMap) -> Option<AuthChallenge> {
        let auth_header = headers.get(reqwest::header::WWW_AUTHENTICATE)?;
        let auth_str = auth_header.to_str().ok()?;
        AuthChallenge::parse(auth_str)
    }
}

/// Simple RFC 4648 Base64 encoding for Basic auth without adding external base64 crate dependency.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as usize
        } else {
            0
        };

        out.push(TABLE[(b0 >> 2) & 0x3F] as char);
        out.push(TABLE[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);

        if i + 1 < input.len() {
            out.push(TABLE[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
        } else {
            out.push('=');
        }

        if i + 2 < input.len() {
            out.push(TABLE[b2 & 0x3F] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }
    out
}
