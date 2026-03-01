//! Cryptographic hashing primitives.
//!
//! Provides BLAKE3 (primary) and SHA-256 (compatibility) hashing for
//! infrastructure layer content. BLAKE3 is used for all internal composition;
//! SHA-256 is available for interop with OCI manifests and Nix store paths.

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fmt;

/// A BLAKE3 hash value (32 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Blake3Hash {
    /// Compute BLAKE3 hash of arbitrary bytes.
    pub fn digest(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    /// Compute BLAKE3 hash by concatenating two hashes (for Merkle nodes).
    pub fn combine(left: &Blake3Hash, right: &Blake3Hash) -> Self {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&left.0);
        combined.extend_from_slice(&right.0);
        Self::digest(&combined)
    }

    /// Create from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Return hex-encoded string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Return prefixed string (e.g., "blake3:abc123...").
    pub fn to_prefixed(&self) -> String {
        format!("blake3:{}", self.to_hex())
    }

    /// Parse from prefixed string.
    pub fn from_prefixed(s: &str) -> Result<Self, hex::FromHexError> {
        let hex_str = s.strip_prefix("blake3:").unwrap_or(s);
        Self::from_hex(hex_str)
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake3({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A SHA-256 hash value (32 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Hash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Sha256Hash {
    /// Compute SHA-256 hash of arbitrary bytes.
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Self(arr)
    }

    /// Create from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Return hex-encoded string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA256({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Hash arbitrary bytes with BLAKE3 and return hex string.
pub fn blake3_hex(data: &[u8]) -> String {
    Blake3Hash::digest(data).to_hex()
}

/// Hash a file's contents with BLAKE3.
pub async fn blake3_file(path: &std::path::Path) -> crate::error::Result<Blake3Hash> {
    let data = tokio::fs::read(path).await?;
    Ok(Blake3Hash::digest(&data))
}

/// Hash a string with BLAKE3.
pub fn blake3_str(s: &str) -> Blake3Hash {
    Blake3Hash::digest(s.as_bytes())
}

/// Serde helper for [u8; 32] as hex.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_deterministic() {
        let h1 = Blake3Hash::digest(b"hello world");
        let h2 = Blake3Hash::digest(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_different_inputs() {
        let h1 = Blake3Hash::digest(b"hello");
        let h2 = Blake3Hash::digest(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake3_combine_deterministic() {
        let a = Blake3Hash::digest(b"a");
        let b = Blake3Hash::digest(b"b");
        let c1 = Blake3Hash::combine(&a, &b);
        let c2 = Blake3Hash::combine(&a, &b);
        assert_eq!(c1, c2);
    }

    #[test]
    fn blake3_combine_order_matters() {
        let a = Blake3Hash::digest(b"a");
        let b = Blake3Hash::digest(b"b");
        let ab = Blake3Hash::combine(&a, &b);
        let ba = Blake3Hash::combine(&b, &a);
        assert_ne!(ab, ba);
    }

    #[test]
    fn hex_roundtrip() {
        let h = Blake3Hash::digest(b"test");
        let hex = h.to_hex();
        let h2 = Blake3Hash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn prefixed_roundtrip() {
        let h = Blake3Hash::digest(b"test");
        let prefixed = h.to_prefixed();
        assert!(prefixed.starts_with("blake3:"));
        let h2 = Blake3Hash::from_prefixed(&prefixed).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn sha256_deterministic() {
        let h1 = Sha256Hash::digest(b"hello world");
        let h2 = Sha256Hash::digest(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn serde_roundtrip() {
        let h = Blake3Hash::digest(b"serde test");
        let json = serde_json::to_string(&h).unwrap();
        let h2: Blake3Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, h2);
    }
}
