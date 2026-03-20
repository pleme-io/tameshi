//! Cryptographic hashing primitives.
//!
//! Provides BLAKE3 (primary) and SHA-256 (compatibility) hashing for
//! infrastructure layer content. BLAKE3 is used for all internal composition;
//! SHA-256 is available for interop with OCI manifests and Nix store paths.

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// A BLAKE3 hash value (32 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl AsRef<[u8]> for Blake3Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for Blake3Hash {
    type Err = const_hex::FromHexError;

    /// Parse from a hex string or a `blake3:`-prefixed hex string.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("blake3:").unwrap_or(s);
        Self::from_hex(hex_str)
    }
}

impl Blake3Hash {
    /// Compute BLAKE3 hash of arbitrary bytes.
    #[inline]
    #[must_use]
    pub fn digest(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    /// Compute BLAKE3 hash by concatenating two hashes (for Merkle nodes).
    #[inline]
    #[must_use]
    pub fn combine(left: &Blake3Hash, right: &Blake3Hash) -> Self {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&left.0);
        combined[32..].copy_from_slice(&right.0);
        Self::digest(&combined)
    }

    /// Create from hex string.
    ///
    /// Returns an error if the hex string is invalid or doesn't decode to exactly 32 bytes.
    pub fn from_hex(s: &str) -> Result<Self, const_hex::FromHexError> {
        let bytes = const_hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(const_hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Return hex-encoded string.
    #[inline]
    #[must_use]
    pub fn to_hex(&self) -> String {
        const_hex::encode(self.0)
    }

    /// Return prefixed string (e.g., "blake3:abc123...").
    #[inline]
    #[must_use]
    pub fn to_prefixed(&self) -> String {
        format!("blake3:{}", self.to_hex())
    }

    /// Parse from prefixed string.
    #[inline]
    pub fn from_prefixed(s: &str) -> Result<Self, const_hex::FromHexError> {
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

impl From<Blake3Hash> for String {
    fn from(hash: Blake3Hash) -> Self {
        hash.to_hex()
    }
}

impl From<&Blake3Hash> for String {
    fn from(hash: &Blake3Hash) -> Self {
        hash.to_hex()
    }
}

impl From<Blake3Hash> for [u8; 32] {
    fn from(hash: Blake3Hash) -> [u8; 32] {
        hash.0
    }
}

impl From<[u8; 32]> for Blake3Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl<'a> TryFrom<&'a str> for Blake3Hash {
    type Error = const_hex::FromHexError;

    /// Parse from a hex string or a `blake3:`-prefixed hex string.
    fn try_from(s: &'a str) -> std::result::Result<Self, Self::Error> {
        let hex_str = s.strip_prefix("blake3:").unwrap_or(s);
        Self::from_hex(hex_str)
    }
}

/// A SHA-256 hash value (32 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Hash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for Sha256Hash {
    type Err = const_hex::FromHexError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("sha256:").unwrap_or(s);
        Self::from_hex(hex_str)
    }
}

impl Sha256Hash {
    /// Compute SHA-256 hash of arbitrary bytes.
    #[inline]
    #[must_use]
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Self(arr)
    }

    /// Create from hex string.
    ///
    /// Returns an error if the hex string is invalid or doesn't decode to exactly 32 bytes.
    pub fn from_hex(s: &str) -> Result<Self, const_hex::FromHexError> {
        let bytes = const_hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(const_hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Return hex-encoded string.
    #[inline]
    #[must_use]
    pub fn to_hex(&self) -> String {
        const_hex::encode(self.0)
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
#[inline]
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    Blake3Hash::digest(data).to_hex()
}

/// Hash a file's contents with BLAKE3 using streaming 64KB buffers.
///
/// This avoids loading the entire file into memory, making it suitable
/// for large files (store paths, OCI layers, etc.).
pub fn blake3_file(path: &std::path::Path) -> crate::error::Result<Blake3Hash> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::with_capacity(65536, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(Blake3Hash(hasher.finalize().into()))
}

/// Hash a file's contents with BLAKE3 asynchronously.
///
/// Reads the file via tokio and hashes its contents. For very large files,
/// prefer [`blake3_file`] which uses streaming buffers.
pub async fn blake3_file_async(path: &std::path::Path) -> crate::error::Result<Blake3Hash> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::with_capacity(65536, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(Blake3Hash(hasher.finalize().into()))
}

/// Hash a string with BLAKE3.
#[inline]
#[must_use]
pub fn blake3_str(s: &str) -> Blake3Hash {
    Blake3Hash::digest(s.as_bytes())
}

/// Generic hasher trait for attestation hashing.
///
/// Enables consumers to use different hash algorithms while maintaining
/// a uniform interface. `Blake3Hasher` is the default implementation.
pub trait AttestationHasher: Send + Sync + Clone {
    /// The output type of the hash function.
    type Output: AsRef<[u8]> + Clone + Eq + std::fmt::Debug + Send + Sync;

    /// Hash arbitrary bytes.
    fn hash(data: &[u8]) -> Self::Output;

    /// Hash a file's contents using streaming buffers.
    fn hash_file(path: &std::path::Path) -> crate::error::Result<Self::Output>;

    /// Combine two hash outputs (for Merkle node construction).
    fn combine(a: &Self::Output, b: &Self::Output) -> Self::Output;

    /// Encode a hash output as a hex string.
    fn to_hex(output: &Self::Output) -> String;

    /// Decode a hex string into a hash output.
    fn from_hex(hex: &str) -> crate::error::Result<Self::Output>;
}

/// Blake3 implementation of `AttestationHasher`.
#[derive(Clone, Debug)]
pub struct Blake3Hasher;

impl AttestationHasher for Blake3Hasher {
    type Output = Blake3Hash;

    fn hash(data: &[u8]) -> Blake3Hash {
        Blake3Hash::digest(data)
    }

    fn hash_file(path: &std::path::Path) -> crate::error::Result<Blake3Hash> {
        blake3_file(path)
    }

    fn combine(a: &Blake3Hash, b: &Blake3Hash) -> Blake3Hash {
        Blake3Hash::combine(a, b)
    }

    fn to_hex(output: &Blake3Hash) -> String {
        output.to_hex()
    }

    fn from_hex(hex: &str) -> crate::error::Result<Blake3Hash> {
        Blake3Hash::from_hex(hex).map_err(|e| {
            crate::error::TameshiError::InvalidInput(format!("invalid hex: {e}"))
        })
    }
}

/// Serde helper for [u8; 32] as hex.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&const_hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = const_hex::decode(&s).map_err(serde::de::Error::custom)?;
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

    #[test]
    fn attestation_hasher_blake3_consistency() {
        let data = b"attestation hasher test";
        let direct = Blake3Hash::digest(data);
        let via_trait = Blake3Hasher::hash(data);
        assert_eq!(direct, via_trait);
    }

    #[test]
    fn attestation_hasher_combine() {
        let a = Blake3Hash::digest(b"a");
        let b = Blake3Hash::digest(b"b");
        let direct = Blake3Hash::combine(&a, &b);
        let via_trait = Blake3Hasher::combine(&a, &b);
        assert_eq!(direct, via_trait);
    }

    #[test]
    fn const_hex_encode_decode() {
        let original = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
                        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                        0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04,
                        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let encoded = const_hex::encode(original);
        let decoded = const_hex::decode(&encoded).unwrap();
        assert_eq!(&original[..], &decoded[..]);
    }

    #[test]
    fn attestation_hasher_hex_roundtrip() {
        let h = Blake3Hasher::hash(b"roundtrip");
        let hex_str = Blake3Hasher::to_hex(&h);
        let h2 = Blake3Hasher::from_hex(&hex_str).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn attestation_hasher_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.bin");
        std::fs::write(&file_path, b"file content for hasher trait").unwrap();
        let direct = blake3_file(&file_path).unwrap();
        let via_trait = Blake3Hasher::hash_file(&file_path).unwrap();
        assert_eq!(direct, via_trait);
    }

    #[test]
    fn blake3_from_string_conversion() {
        let h = Blake3Hash::digest(b"test");
        let s: String = h.clone().into();
        let h2 = Blake3Hash::from_hex(&s).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn blake3_from_ref_conversion() {
        let h = Blake3Hash::digest(b"ref-test");
        let s: String = (&h).into();
        assert_eq!(s, h.to_hex());
    }

    #[test]
    fn blake3_from_str_parse() {
        let h = Blake3Hash::digest(b"parse-test");
        let hex = h.to_hex();
        let parsed: Blake3Hash = hex.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn blake3_from_str_with_prefix() {
        let h = Blake3Hash::digest(b"prefixed-parse");
        let prefixed = h.to_prefixed();
        let parsed: Blake3Hash = prefixed.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn blake3_invalid_hex_errors() {
        let result = Blake3Hash::from_hex("not-valid-hex");
        assert!(result.is_err());
    }

    #[test]
    fn blake3_wrong_length_hex_errors() {
        let result = Blake3Hash::from_hex("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn sha256_hex_roundtrip() {
        let h = Sha256Hash::digest(b"sha256 roundtrip");
        let hex = h.to_hex();
        let h2 = Sha256Hash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn sha256_from_str_parse() {
        let h = Sha256Hash::digest(b"sha256 parse");
        let hex = h.to_hex();
        let parsed: Sha256Hash = hex.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn sha256_from_str_with_prefix() {
        let h = Sha256Hash::digest(b"sha256 prefix");
        let prefixed = format!("sha256:{}", h.to_hex());
        let parsed: Sha256Hash = prefixed.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn blake3_empty_input() {
        let h = Blake3Hash::digest(b"");
        assert_ne!(h, Blake3Hash([0u8; 32]));
    }

    #[test]
    fn blake3_large_input() {
        let data = vec![0xABu8; 1_000_000];
        let h1 = Blake3Hash::digest(&data);
        let h2 = Blake3Hash::digest(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_unicode_input() {
        let h = blake3_str("Hello, \u{4e16}\u{754c}!"); // "Hello, 世界!"
        assert_ne!(h, Blake3Hash::digest(b""));
    }

    #[test]
    fn blake3_file_nonexistent() {
        let result = blake3_file(std::path::Path::new("/nonexistent/path/file.bin"));
        assert!(result.is_err());
    }

    #[test]
    fn attestation_hasher_from_hex_invalid() {
        let result = Blake3Hasher::from_hex("zzz-invalid");
        assert!(result.is_err());
    }

    #[test]
    fn sha256_serde_roundtrip() {
        let h = Sha256Hash::digest(b"sha256 serde");
        let json = serde_json::to_string(&h).unwrap();
        let h2: Sha256Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn blake3_display_and_debug() {
        let h = Blake3Hash::digest(b"display");
        let display = format!("{h}");
        let debug = format!("{h:?}");
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(debug.starts_with("Blake3("));
    }

    #[test]
    fn sha256_display_and_debug() {
        let h = Sha256Hash::digest(b"display");
        let display = format!("{h}");
        let debug = format!("{h:?}");
        assert_eq!(display.len(), 64);
        assert!(debug.starts_with("SHA256("));
    }

    #[test]
    fn blake3_as_ref() {
        let h = Blake3Hash::digest(b"asref");
        let bytes: &[u8] = h.as_ref();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn blake3_hash_impl() {
        use std::collections::HashSet;
        let h1 = Blake3Hash::digest(b"a");
        let h2 = Blake3Hash::digest(b"b");
        let h3 = Blake3Hash::digest(b"a");
        let mut set = HashSet::new();
        set.insert(h1.clone());
        set.insert(h2);
        set.insert(h3);
        assert_eq!(set.len(), 2); // h1 and h3 are the same
    }

    // -- Property-based edge case tests --

    #[test]
    fn blake3_combine_not_commutative() {
        // Verify for many pairs that combine(a,b) != combine(b,a)
        for i in 0u8..50 {
            let a = Blake3Hash::digest(&[i]);
            let b = Blake3Hash::digest(&[i + 100]);
            let ab = Blake3Hash::combine(&a, &b);
            let ba = Blake3Hash::combine(&b, &a);
            assert_ne!(ab, ba, "combine must not be commutative for input {i}");
        }
    }

    #[test]
    fn blake3_empty_input_produces_defined_sentinel() {
        let h = Blake3Hash::digest(b"");
        // Empty input should produce a well-defined, non-zero hash
        assert_ne!(h, Blake3Hash([0u8; 32]));
        // Should be deterministic
        assert_eq!(h, Blake3Hash::digest(b""));
    }

    #[test]
    fn blake3_single_byte_inputs_all_distinct() {
        let mut hashes = std::collections::HashSet::new();
        for byte in 0u8..=255 {
            hashes.insert(Blake3Hash::digest(&[byte]));
        }
        assert_eq!(hashes.len(), 256, "Every single-byte input must produce a unique hash");
    }

    #[test]
    fn blake3_large_input_1000_items_no_panic() {
        let items: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("item-{i}").into_bytes())
            .collect();
        let mut combined = Vec::new();
        for item in &items {
            let h = Blake3Hash::digest(item);
            combined.extend_from_slice(&h.0);
        }
        let final_hash = Blake3Hash::digest(&combined);
        let final_hash2 = Blake3Hash::digest(&combined);
        assert_eq!(final_hash, final_hash2, "Large composite must be deterministic");
    }

    #[test]
    fn blake3_from_into_u8_32_roundtrip() {
        let h = Blake3Hash::digest(b"roundtrip-test");
        let bytes: [u8; 32] = h.clone().into();
        let h2: Blake3Hash = bytes.into();
        assert_eq!(h, h2);
    }

    #[test]
    fn blake3_try_from_str_valid() {
        let h = Blake3Hash::digest(b"try_from test");
        let hex = h.to_hex();
        let parsed: Blake3Hash = hex.as_str().try_into().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn blake3_try_from_str_with_prefix() {
        let h = Blake3Hash::digest(b"try_from prefix");
        let prefixed = h.to_prefixed();
        let parsed: Blake3Hash = prefixed.as_str().try_into().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn blake3_try_from_str_invalid() {
        let result: std::result::Result<Blake3Hash, _> = "zzz-invalid".try_into();
        assert!(result.is_err());
    }

    #[test]
    fn blake3_combine_idempotent_with_self() {
        let a = Blake3Hash::digest(b"self-combine");
        let aa = Blake3Hash::combine(&a, &a);
        // combine(a,a) should be a valid, deterministic hash but not equal to a
        assert_ne!(aa, a, "combine(a,a) should differ from a");
        let aa2 = Blake3Hash::combine(&a, &a);
        assert_eq!(aa, aa2, "combine(a,a) should be deterministic");
    }

    #[test]
    fn blake3_file_async_roundtrip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let file_path = dir.path().join("async-test.bin");
            tokio::fs::write(&file_path, b"async file content").await.unwrap();
            let h1 = blake3_file_async(&file_path).await.unwrap();
            let h2 = blake3_file(&file_path).unwrap();
            assert_eq!(h1, h2, "Async and sync file hashing must agree");
        });
    }

    #[test]
    fn sha256_wrong_length_hex_errors() {
        let result = Sha256Hash::from_hex("abcd");
        assert!(result.is_err());
    }
}
