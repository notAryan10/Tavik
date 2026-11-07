use crate::error::StoreError;
use sha2::{Digest as Sha2Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// Validates that a string is a well-formed SHA-256 digest (`sha256:<64-hex>`).
pub fn validate_sha256(digest: &str) -> Result<&str, StoreError> {
    let (algo, hex_str) = digest
        .split_once(':')
        .ok_or_else(|| StoreError::InvalidDigest(digest.to_string()))?;

    if !algo.eq_ignore_ascii_case("sha256") {
        return Err(StoreError::UnsupportedAlgorithm(algo.to_string()));
    }

    if hex_str.len() != 64 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidDigest(digest.to_string()));
    }

    Ok(hex_str)
}

/// Computes the SHA-256 digest of in-memory bytes and returns formatted `sha256:<hex>`.
pub fn compute_sha256(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(hash))
}

/// Asynchronously computes the SHA-256 digest and size of a file on disk.
pub async fn compute_sha256_file(path: &Path) -> Result<(String, u64), StoreError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_bytes += n as u64;
    }

    let hash_hex = hex::encode(hasher.finalize());
    Ok((format!("sha256:{}", hash_hex), total_bytes))
}
