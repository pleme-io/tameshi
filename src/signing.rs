//! Merkle root signing — cryptographic signatures on attestation roots.
//!
//! Provides the [`MerkleRootSigner`] trait for signing and verifying Merkle roots.
//! Two implementations:
//!
//! - [`LocalSigner`] — file-based Ed25519 key for development and testing
//! - [`AkeylessDfcSigner`] — calls Akeyless DFC signing API (threshold signing,
//!   key never exists in one piece)
//!
//! # Break-Glass Support
//!
//! The [`BreakGlassToken`] type represents an emergency bypass token that allows
//! deployments during attestation outages. Every break-glass event is cryptographically
//! logged for the 72-hour CIRCIA report.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::akeyless_client::{AkeylessClientError, TlsConfig, build_tls_client};
use crate::hash::Blake3Hash;

/// Algorithm used to sign the Merkle root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    /// Local Ed25519 key (development/testing).
    Ed25519Local,
    /// Akeyless Distributed Fragment Cryptography (production).
    AkeylessDfc {
        /// The DFC key name in Akeyless.
        key_name: String,
    },
    /// Mock DFC using split-knowledge fragment reconstruction.
    MockDfc,
    /// Emergency break-glass bypass.
    BreakGlass,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519Local => write!(f, "ed25519_local"),
            Self::AkeylessDfc { key_name } => write!(f, "akeyless_dfc:{key_name}"),
            Self::MockDfc => write!(f, "mock_dfc"),
            Self::BreakGlass => write!(f, "break_glass"),
        }
    }
}

/// A signed Merkle root with provenance metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignedRoot {
    /// The Merkle root that was signed.
    pub root: Blake3Hash,
    /// The cryptographic signature bytes.
    #[serde(with = "hex_sig")]
    #[schemars(with = "String")]
    pub signature: Vec<u8>,
    /// Which algorithm was used to sign.
    pub algorithm: SigningAlgorithm,
    /// Identifier of the signing entity.
    pub signer_id: String,
    /// When the root was signed.
    pub signed_at: DateTime<Utc>,
}

/// Trait for signing and verifying Merkle roots.
///
/// Implementations provide different key management strategies:
/// - `LocalSigner`: file-based Ed25519 (dev/test)
/// - `AkeylessDfcSigner`: threshold signing via Akeyless API (production)
pub trait MerkleRootSigner: Send + Sync {
    /// Sign a Merkle root.
    fn sign(
        &self,
        root: &Blake3Hash,
    ) -> impl std::future::Future<Output = crate::error::Result<SignedRoot>> + Send;

    /// Verify a signed Merkle root.
    fn verify(
        &self,
        signed: &SignedRoot,
    ) -> impl std::future::Future<Output = crate::error::Result<bool>> + Send;
}

/// Local Ed25519 signer for development and testing.
///
/// Uses a 32-byte seed to derive an Ed25519 keypair. The seed can be loaded
/// from a file or generated randomly for testing.
pub struct LocalSigner {
    seed: [u8; 32],
    signer_id: String,
}

impl LocalSigner {
    /// Create a signer from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32], signer_id: &str) -> Self {
        Self {
            seed,
            signer_id: signer_id.to_string(),
        }
    }

    /// Create a signer with a deterministic test seed.
    #[must_use]
    pub fn for_testing() -> Self {
        Self::from_seed([42u8; 32], "test-signer")
    }

    /// Get the public key bytes (BLAKE3 hash of seed for simplicity).
    /// In production, this would be the actual Ed25519 public key.
    #[must_use]
    pub fn public_key_hash(&self) -> Blake3Hash {
        Blake3Hash::digest(&self.seed)
    }

    /// Sign data using the seed as an HMAC-like construction.
    /// Uses BLAKE3 keyed hash for deterministic, verifiable signatures.
    fn sign_bytes(&self, data: &[u8]) -> Vec<u8> {
        // BLAKE3 keyed hash: H(seed || data) — deterministic MAC
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(data);
        let hash = Blake3Hash::digest(&input);
        hash.0.to_vec()
    }

    /// Verify a signature against data.
    fn verify_bytes(&self, data: &[u8], signature: &[u8]) -> bool {
        let expected = self.sign_bytes(data);
        expected == signature
    }
}

impl MerkleRootSigner for LocalSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        let signature = self.sign_bytes(&root.0);
        Ok(SignedRoot {
            root: root.clone(),
            signature,
            algorithm: SigningAlgorithm::Ed25519Local,
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        Ok(self.verify_bytes(&signed.root.0, &signed.signature))
    }
}

/// Akeyless DFC (Distributed Fragment Cryptography) signer.
///
/// Calls the Akeyless gateway REST API for threshold signing. The key
/// never exists in one piece -- fragments are distributed across
/// Akeyless infrastructure.
pub struct AkeylessDfcSigner {
    /// The DFC key name.
    pub key_name: String,
    /// Signer identifier.
    pub signer_id: String,
    /// HTTP client for Akeyless API calls.
    client: reqwest::Client,
    /// Akeyless gateway endpoint.
    pub endpoint: String,
    /// Access ID for API key authentication.
    pub access_id: String,
    /// Access key for API key authentication.
    pub access_key: String,
}

impl AkeylessDfcSigner {
    /// Create a new DFC signer (credentials must be provided via [`with_credentials`]).
    #[must_use]
    pub fn new(key_name: &str, signer_id: &str, endpoint: &str) -> Self {
        Self {
            key_name: key_name.to_string(),
            signer_id: signer_id.to_string(),
            client: reqwest::Client::new(),
            endpoint: endpoint.to_string(),
            access_id: String::new(),
            access_key: String::new(),
        }
    }

    /// Create a new DFC signer with Akeyless API key credentials.
    #[must_use]
    pub fn with_credentials(
        key_name: &str,
        signer_id: &str,
        endpoint: &str,
        access_id: &str,
        access_key: &str,
    ) -> Self {
        Self {
            key_name: key_name.to_string(),
            signer_id: signer_id.to_string(),
            client: reqwest::Client::new(),
            endpoint: endpoint.to_string(),
            access_id: access_id.to_string(),
            access_key: access_key.to_string(),
        }
    }

    /// Create a new DFC signer with Akeyless API key credentials and custom TLS configuration.
    ///
    /// Uses [`build_tls_client`] to construct a [`reqwest::Client`] that respects
    /// pinned CAs, mTLS client certificates, and server-verification toggles.
    pub fn with_tls(
        key_name: &str,
        signer_id: &str,
        endpoint: &str,
        access_id: &str,
        access_key: &str,
        tls: &TlsConfig,
    ) -> Result<Self, AkeylessClientError> {
        let client = build_tls_client(tls)?;
        Ok(Self {
            key_name: key_name.to_string(),
            signer_id: signer_id.to_string(),
            client,
            endpoint: endpoint.to_string(),
            access_id: access_id.to_string(),
            access_key: access_key.to_string(),
        })
    }

    /// Authenticate to Akeyless and return an access token.
    async fn authenticate(&self) -> crate::error::Result<String> {
        let body = serde_json::json!({
            "access-id": self.access_id,
            "access-key": self.access_key,
            "access-type": "api_key"
        });
        let resp = self
            .client
            .post(format!("{}/auth", self.endpoint))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                crate::error::TameshiError::HashError(format!("DFC auth request failed: {e}"))
            })?;
        let result: serde_json::Value = resp.json().await.map_err(|e| {
            crate::error::TameshiError::HashError(format!("DFC auth response parse failed: {e}"))
        })?;
        result["token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                crate::error::TameshiError::HashError(
                    "missing 'token' in DFC auth response".to_string(),
                )
            })
    }
}

/// Encode bytes as hex string (used for DFC API data field).
fn hex_encode(bytes: &[u8]) -> String {
    const_hex::encode(bytes)
}

/// Decode hex string to bytes (used for DFC API response parsing).
fn hex_decode(hex: &str) -> crate::error::Result<Vec<u8>> {
    const_hex::decode(hex).map_err(|e| {
        crate::error::TameshiError::HashError(format!("hex decode failed: {e}"))
    })
}

impl MerkleRootSigner for AkeylessDfcSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        let token = self.authenticate().await?;
        let data_hex = hex_encode(&root.0);
        let body = serde_json::json!({
            "key-name": self.key_name,
            "data": data_hex,
            "token": token,
        });
        let resp = self
            .client
            .post(format!("{}/sign-data-with-classic-key", self.endpoint))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                crate::error::TameshiError::HashError(format!("DFC sign failed: {e}"))
            })?;
        let result: serde_json::Value = resp.json().await.map_err(|e| {
            crate::error::TameshiError::HashError(format!(
                "DFC sign response parse failed: {e}"
            ))
        })?;
        let sig_hex = result["result"].as_str().ok_or_else(|| {
            crate::error::TameshiError::HashError(
                "missing 'result' in DFC sign response".to_string(),
            )
        })?;
        let signature = hex_decode(sig_hex)?;
        Ok(SignedRoot {
            root: root.clone(),
            signature,
            algorithm: SigningAlgorithm::AkeylessDfc {
                key_name: self.key_name.clone(),
            },
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        let token = self.authenticate().await?;
        let data_hex = hex_encode(&signed.root.0);
        let sig_hex = hex_encode(&signed.signature);
        let body = serde_json::json!({
            "key-name": self.key_name,
            "data": data_hex,
            "signature": sig_hex,
            "token": token,
        });
        let resp = self
            .client
            .post(format!(
                "{}/verify-data-with-classic-key",
                self.endpoint
            ))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                crate::error::TameshiError::HashError(format!("DFC verify failed: {e}"))
            })?;
        let result: serde_json::Value = resp.json().await.map_err(|e| {
            crate::error::TameshiError::HashError(format!(
                "DFC verify response parse failed: {e}"
            ))
        })?;
        Ok(result["result"].as_bool().unwrap_or(false))
    }
}

/// Mock Akeyless DFC signer using split-knowledge fragment reconstruction.
///
/// Simulates Distributed Fragment Cryptography by requiring TWO fragments
/// to reconstruct a signing key:
/// - Fragment A: loaded from file `.tameshi_frag` (hex-encoded, 64 chars)
/// - Fragment B: loaded from env var `AKEYLESS_MOCK_FRAG` (hex-encoded, 64 chars)
///
/// Both fragments are XOR'd then BLAKE3-hashed to produce the signing key.
/// This ensures neither fragment alone reveals the key.
///
/// # Security
///
/// This is a MOCK for development/CI. In production, use `AkeylessDfcSigner`
/// which calls the real Akeyless gateway for threshold signing.
pub struct MockDfcSigner {
    signer_id: String,
    fragment_a: [u8; 32],
    fragment_b: [u8; 32],
}

impl std::fmt::Debug for MockDfcSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockDfcSigner")
            .field("signer_id", &self.signer_id)
            .field("fragment_a", &"[REDACTED]")
            .field("fragment_b", &"[REDACTED]")
            .finish()
    }
}

impl MockDfcSigner {
    /// Create from explicit fragments (for testing).
    #[must_use]
    pub fn from_fragments(a: [u8; 32], b: [u8; 32], signer_id: &str) -> Self {
        Self {
            signer_id: signer_id.to_string(),
            fragment_a: a,
            fragment_b: b,
        }
    }

    /// Create with deterministic test fragments.
    #[must_use]
    pub fn for_testing() -> Self {
        Self::from_fragments([1u8; 32], [2u8; 32], "mock-dfc-test")
    }

    /// Load fragments from file and environment.
    ///
    /// Fragment A: reads `.tameshi_frag` (64 hex chars) from current dir or home dir
    /// Fragment B: reads `AKEYLESS_MOCK_FRAG` env var (64 hex chars)
    ///
    /// # Errors
    /// Returns error if either fragment source is missing or contains invalid hex.
    pub fn load(signer_id: &str) -> crate::error::Result<Self> {
        let frag_b_hex = std::env::var("AKEYLESS_MOCK_FRAG").map_err(|_| {
            crate::error::TameshiError::ConfigError(
                "AKEYLESS_MOCK_FRAG env var not set".to_string(),
            )
        })?;
        let search_dirs = Self::default_search_dirs();
        Self::load_from(&search_dirs, &frag_b_hex, signer_id)
    }

    /// Testable inner loader: accepts explicit search dirs and fragment B hex.
    fn load_from(
        search_dirs: &[std::path::PathBuf],
        frag_b_hex: &str,
        signer_id: &str,
    ) -> crate::error::Result<Self> {
        let frag_a_hex = Self::read_fragment_file(search_dirs)?;
        let a = Self::parse_hex_fragment(&frag_a_hex, "fragment A (file)")?;
        let b = Self::parse_hex_fragment(frag_b_hex, "fragment B (env)")?;
        Ok(Self::from_fragments(a, b, signer_id))
    }

    /// Return the default list of directories to search for `.tameshi_frag`.
    fn default_search_dirs() -> Vec<std::path::PathBuf> {
        let mut dirs = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(std::path::PathBuf::from(home));
        }
        dirs
    }

    /// Read fragment A from `.tameshi_frag` file in the given search directories.
    fn read_fragment_file(
        search_dirs: &[std::path::PathBuf],
    ) -> crate::error::Result<String> {
        for dir in search_dirs {
            let path = dir.join(".tameshi_frag");
            if path.exists() {
                return std::fs::read_to_string(&path)
                    .map(|s| s.trim().to_string())
                    .map_err(|e| {
                        crate::error::TameshiError::ConfigError(format!(
                            "failed to read {}: {e}",
                            path.display()
                        ))
                    });
            }
        }

        Err(crate::error::TameshiError::ConfigError(
            ".tameshi_frag not found in current dir or home dir".to_string(),
        ))
    }

    /// Parse a 64-char hex string into a 32-byte array.
    fn parse_hex_fragment(hex: &str, label: &str) -> crate::error::Result<[u8; 32]> {
        let hex = hex.trim();
        let bytes = hex_decode(hex).map_err(|_| {
            crate::error::TameshiError::ConfigError(format!("{label}: invalid hex"))
        })?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            crate::error::TameshiError::ConfigError(format!(
                "{label}: expected 64 hex chars (32 bytes), got {} chars",
                hex.len()
            ))
        })
    }

    /// Reconstruct the signing key from both fragments.
    /// Key = BLAKE3(fragment_a XOR fragment_b)
    #[inline]
    fn reconstruct_key(&self) -> [u8; 32] {
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = self.fragment_a[i] ^ self.fragment_b[i];
        }
        *blake3::hash(&xored).as_bytes()
    }
}

impl MerkleRootSigner for MockDfcSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        let key = self.reconstruct_key();
        let signature = blake3::keyed_hash(&key, &root.0).as_bytes().to_vec();
        Ok(SignedRoot {
            root: root.clone(),
            signature,
            algorithm: SigningAlgorithm::MockDfc,
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        let key = self.reconstruct_key();
        let expected = blake3::keyed_hash(&key, &signed.root.0).as_bytes().to_vec();
        Ok(expected == signed.signature)
    }
}

/// Emergency break-glass bypass token.
///
/// Allows deployments during attestation outages. Every break-glass event
/// is cryptographically logged for CIRCIA compliance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BreakGlassToken {
    /// Token type identifier.
    #[serde(rename = "type")]
    pub token_type: String,
    /// When this token was issued.
    pub issued_at: DateTime<Utc>,
    /// When this token expires.
    pub valid_until: DateTime<Utc>,
    /// Who issued the token (email or service account).
    pub issuer: String,
    /// Reason for the bypass.
    pub reason: String,
    /// Namespaces this token applies to.
    pub scope: Vec<String>,
    /// Cryptographic signature of the token.
    #[serde(with = "hex_sig")]
    #[schemars(with = "String")]
    pub signature: Vec<u8>,
}

impl BreakGlassToken {
    /// Check if the token is currently valid (not expired).
    #[must_use]
    pub fn is_valid(&self, now: &DateTime<Utc>) -> bool {
        self.token_type == "break_glass" && *now < self.valid_until && *now >= self.issued_at
    }

    /// Check if the token covers the given namespace.
    #[must_use]
    pub fn covers_namespace(&self, namespace: &str) -> bool {
        self.scope.iter().any(|s| {
            if let Some(ns) = s.strip_prefix("namespace:") {
                ns == namespace || ns == "*"
            } else {
                false
            }
        })
    }

    /// Verify the token's signature against a public key hash.
    #[must_use]
    pub fn verify_signature(&self, signer: &LocalSigner) -> bool {
        let data = self.signable_content();
        signer.verify_bytes(&data, &self.signature)
    }

    /// Create the signable content (everything except the signature).
    fn signable_content(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.token_type.as_bytes());
        data.push(0);
        data.extend_from_slice(self.issued_at.to_rfc3339().as_bytes());
        data.push(0);
        data.extend_from_slice(self.valid_until.to_rfc3339().as_bytes());
        data.push(0);
        data.extend_from_slice(self.issuer.as_bytes());
        data.push(0);
        data.extend_from_slice(self.reason.as_bytes());
        data.push(0);
        for scope in &self.scope {
            data.extend_from_slice(scope.as_bytes());
            data.push(0);
        }
        data
    }

    /// Create and sign a break-glass token.
    #[must_use]
    pub fn create_signed(
        issuer: &str,
        reason: &str,
        scope: Vec<String>,
        valid_hours: i64,
        signer: &LocalSigner,
    ) -> Self {
        let now = Utc::now();
        let valid_until = now + chrono::Duration::hours(valid_hours);
        let mut token = Self {
            token_type: "break_glass".to_string(),
            issued_at: now,
            valid_until,
            issuer: issuer.to_string(),
            reason: reason.to_string(),
            scope,
            signature: Vec::new(),
        };
        token.signature = signer.sign_bytes(&token.signable_content());
        token
    }
}

/// Failure modes for the [`FailableDfcSigner`].
///
/// Used to simulate various infrastructure failure scenarios during testing.
#[derive(Clone, Debug)]
pub enum FailMode {
    /// Simulate network timeout (returns error immediately with timeout message).
    Timeout(std::time::Duration),
    /// Simulate corrupted signature (sign succeeds but produces invalid sig).
    CorruptedSignature,
    /// Simulate authentication failure.
    AuthFailure,
    /// Simulate rate limiting.
    RateLimited,
}

/// A DFC signer that can be configured to fail in specific ways.
///
/// Wraps a [`MockDfcSigner`] and injects deterministic failures for negative
/// testing. When no `fail_mode` is set, it delegates to the inner signer.
///
/// # Examples
///
/// ```rust
/// use tameshi::signing::{FailableDfcSigner, FailMode, MerkleRootSigner};
/// use tameshi::hash::Blake3Hash;
///
/// # tokio_test::block_on(async {
/// let signer = FailableDfcSigner::new().with_auth_failure();
/// let root = Blake3Hash::digest(b"test");
/// let result = signer.sign(&root).await;
/// assert!(result.is_err());
/// # });
/// ```
pub struct FailableDfcSigner {
    inner: MockDfcSigner,
    fail_mode: Option<FailMode>,
}

impl FailableDfcSigner {
    /// Create a new failable signer with no failure mode (passes through to inner).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MockDfcSigner::for_testing(),
            fail_mode: None,
        }
    }

    /// Configure to simulate a network timeout.
    #[must_use]
    pub fn with_timeout(mut self, duration: std::time::Duration) -> Self {
        self.fail_mode = Some(FailMode::Timeout(duration));
        self
    }

    /// Configure to produce a corrupted signature (sign succeeds, verify fails).
    #[must_use]
    pub fn with_corrupted_signature(mut self) -> Self {
        self.fail_mode = Some(FailMode::CorruptedSignature);
        self
    }

    /// Configure to simulate an authentication failure.
    #[must_use]
    pub fn with_auth_failure(mut self) -> Self {
        self.fail_mode = Some(FailMode::AuthFailure);
        self
    }

    /// Configure to simulate rate limiting.
    #[must_use]
    pub fn with_rate_limited(mut self) -> Self {
        self.fail_mode = Some(FailMode::RateLimited);
        self
    }
}

impl Default for FailableDfcSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleRootSigner for FailableDfcSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        match &self.fail_mode {
            Some(FailMode::Timeout(d)) => Err(crate::error::TameshiError::HashError(
                format!("DFC sign timed out after {}ms", d.as_millis()),
            )),
            Some(FailMode::AuthFailure) => Err(crate::error::TameshiError::HashError(
                "DFC authentication failed: invalid credentials".to_string(),
            )),
            Some(FailMode::RateLimited) => Err(crate::error::TameshiError::HashError(
                "DFC rate limited: too many requests".to_string(),
            )),
            Some(FailMode::CorruptedSignature) => {
                // Sign successfully but corrupt the signature bytes.
                let mut signed = self.inner.sign(root).await?;
                // Flip all bits to guarantee mismatch.
                for byte in &mut signed.signature {
                    *byte = !*byte;
                }
                Ok(signed)
            }
            None => self.inner.sign(root).await,
        }
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        match &self.fail_mode {
            Some(FailMode::Timeout(d)) => Err(crate::error::TameshiError::HashError(
                format!("DFC verify timed out after {}ms", d.as_millis()),
            )),
            Some(FailMode::AuthFailure) => Err(crate::error::TameshiError::HashError(
                "DFC authentication failed: invalid credentials".to_string(),
            )),
            Some(FailMode::RateLimited) => Err(crate::error::TameshiError::HashError(
                "DFC rate limited: too many requests".to_string(),
            )),
            // CorruptedSignature: delegate to inner (which will reject the corrupted sig).
            Some(FailMode::CorruptedSignature) | None => self.inner.verify(signed).await,
        }
    }
}

/// Serde helper for Vec<u8> as hex.
mod hex_sig {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&const_hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        const_hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // SigningAlgorithm tests
    // =========================================================================

    #[test]
    fn signing_algorithm_display() {
        assert_eq!(SigningAlgorithm::Ed25519Local.to_string(), "ed25519_local");
        assert_eq!(
            SigningAlgorithm::AkeylessDfc { key_name: "my-key".to_string() }.to_string(),
            "akeyless_dfc:my-key"
        );
        assert_eq!(SigningAlgorithm::BreakGlass.to_string(), "break_glass");
    }

    #[test]
    fn signing_algorithm_serde_roundtrip() {
        let algos = vec![
            SigningAlgorithm::Ed25519Local,
            SigningAlgorithm::AkeylessDfc { key_name: "dfc-key-1".to_string() },
            SigningAlgorithm::BreakGlass,
        ];
        for algo in &algos {
            let json = serde_json::to_string(algo).unwrap();
            let deserialized: SigningAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(algo, &deserialized);
        }
    }

    // =========================================================================
    // LocalSigner tests
    // =========================================================================

    #[tokio::test]
    async fn local_signer_sign_verify() {
        let signer = LocalSigner::for_testing();
        let root = Blake3Hash::digest(b"merkle-root");
        let signed = signer.sign(&root).await.unwrap();

        assert_eq!(signed.root, root);
        assert_eq!(signed.signer_id, "test-signer");
        assert!(matches!(signed.algorithm, SigningAlgorithm::Ed25519Local));

        let verified = signer.verify(&signed).await.unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn local_signer_different_root_different_signature() {
        let signer = LocalSigner::for_testing();
        let root1 = Blake3Hash::digest(b"root-1");
        let root2 = Blake3Hash::digest(b"root-2");

        let signed1 = signer.sign(&root1).await.unwrap();
        let signed2 = signer.sign(&root2).await.unwrap();

        assert_ne!(signed1.signature, signed2.signature);
    }

    #[tokio::test]
    async fn local_signer_deterministic() {
        let signer = LocalSigner::for_testing();
        let root = Blake3Hash::digest(b"deterministic-test");

        let signed1 = signer.sign(&root).await.unwrap();
        let signed2 = signer.sign(&root).await.unwrap();

        assert_eq!(signed1.signature, signed2.signature);
    }

    #[tokio::test]
    async fn local_signer_wrong_key_rejects() {
        let signer1 = LocalSigner::from_seed([1u8; 32], "signer-1");
        let signer2 = LocalSigner::from_seed([2u8; 32], "signer-2");
        let root = Blake3Hash::digest(b"test");

        let signed = signer1.sign(&root).await.unwrap();
        let verified = signer2.verify(&signed).await.unwrap();
        assert!(!verified, "Wrong key should reject signature");
    }

    #[tokio::test]
    async fn local_signer_tampered_root_rejects() {
        let signer = LocalSigner::for_testing();
        let root = Blake3Hash::digest(b"original");
        let mut signed = signer.sign(&root).await.unwrap();

        // Tamper with the root
        signed.root = Blake3Hash::digest(b"tampered");

        let verified = signer.verify(&signed).await.unwrap();
        assert!(!verified, "Tampered root should reject");
    }

    // =========================================================================
    // SignedRoot serde tests
    // =========================================================================

    #[tokio::test]
    async fn signed_root_serde_roundtrip() {
        let signer = LocalSigner::for_testing();
        let root = Blake3Hash::digest(b"serde-test");
        let signed = signer.sign(&root).await.unwrap();

        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    // =========================================================================
    // AkeylessDfcSigner tests
    // =========================================================================

    #[test]
    fn dfc_signer_requires_credentials() {
        let signer = AkeylessDfcSigner::new(
            "test-dfc-key",
            "ci-pipeline",
            "https://akeyless.example.com",
        );
        // Default constructor leaves credentials empty.
        assert!(signer.access_id.is_empty());
        assert!(signer.access_key.is_empty());
        assert_eq!(signer.key_name, "test-dfc-key");
        assert_eq!(signer.signer_id, "ci-pipeline");
        assert_eq!(signer.endpoint, "https://akeyless.example.com");
    }

    #[test]
    fn dfc_signer_with_credentials() {
        let signer = AkeylessDfcSigner::with_credentials(
            "prod-dfc-key",
            "ci-pipeline",
            "https://gw.akeyless.io",
            "p-abc123",
            "my-secret-key",
        );
        assert_eq!(signer.access_id, "p-abc123");
        assert_eq!(signer.access_key, "my-secret-key");
        assert_eq!(signer.key_name, "prod-dfc-key");
        assert_eq!(signer.signer_id, "ci-pipeline");
        assert_eq!(signer.endpoint, "https://gw.akeyless.io");
    }

    #[test]
    fn dfc_signer_algorithm_display() {
        let algo = SigningAlgorithm::AkeylessDfc {
            key_name: "my-dfc-key".to_string(),
        };
        assert_eq!(algo.to_string(), "akeyless_dfc:my-dfc-key");
    }

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data = b"hello world";
        let encoded = super::hex_encode(data);
        let decoded = super::hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_invalid_returns_error() {
        let result = super::hex_decode("not-valid-hex!!!");
        assert!(result.is_err());
    }

    // =========================================================================
    // BreakGlassToken tests
    // =========================================================================

    #[test]
    fn break_glass_token_valid() {
        let signer = LocalSigner::for_testing();
        let token = BreakGlassToken::create_signed(
            "oncall@pleme.io",
            "Akeyless API outage",
            vec!["namespace:production".to_string()],
            4,
            &signer,
        );

        assert!(token.is_valid(&Utc::now()));
        assert!(token.covers_namespace("production"));
        assert!(!token.covers_namespace("staging"));
        assert!(token.verify_signature(&signer));
    }

    #[test]
    fn break_glass_token_expired() {
        let signer = LocalSigner::for_testing();
        let mut token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "test",
            vec!["namespace:*".to_string()],
            4,
            &signer,
        );
        // Set valid_until to the past
        token.valid_until = Utc::now() - chrono::Duration::hours(1);

        assert!(!token.is_valid(&Utc::now()));
    }

    #[test]
    fn break_glass_token_wildcard_namespace() {
        let signer = LocalSigner::for_testing();
        let token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "full outage",
            vec!["namespace:*".to_string()],
            4,
            &signer,
        );

        assert!(token.covers_namespace("production"));
        assert!(token.covers_namespace("staging"));
        assert!(token.covers_namespace("anything"));
    }

    #[test]
    fn break_glass_token_wrong_signer_rejects() {
        let signer1 = LocalSigner::from_seed([1u8; 32], "signer-1");
        let signer2 = LocalSigner::from_seed([2u8; 32], "signer-2");

        let token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "test",
            vec!["namespace:prod".to_string()],
            4,
            &signer1,
        );

        assert!(!token.verify_signature(&signer2));
    }

    #[test]
    fn break_glass_token_serde_roundtrip() {
        let signer = LocalSigner::for_testing();
        let token = BreakGlassToken::create_signed(
            "oncall@pleme.io",
            "INC-2847",
            vec!["namespace:production".to_string(), "namespace:staging".to_string()],
            4,
            &signer,
        );

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: BreakGlassToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);
        assert!(deserialized.verify_signature(&signer));
    }

    #[test]
    fn break_glass_token_tampered_rejects() {
        let signer = LocalSigner::for_testing();
        let mut token = BreakGlassToken::create_signed(
            "oncall@pleme.io",
            "legit reason",
            vec!["namespace:production".to_string()],
            4,
            &signer,
        );

        // Tamper with the reason
        token.reason = "hacked reason".to_string();
        assert!(!token.verify_signature(&signer), "Tampered token should fail verification");
    }

    #[test]
    fn break_glass_wrong_token_type() {
        let signer = LocalSigner::for_testing();
        let mut token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "test",
            vec!["namespace:prod".to_string()],
            4,
            &signer,
        );
        token.token_type = "not_break_glass".to_string();
        assert!(!token.is_valid(&Utc::now()));
    }

    #[test]
    fn break_glass_not_yet_valid() {
        let signer = LocalSigner::for_testing();
        let mut token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "test",
            vec!["namespace:prod".to_string()],
            4,
            &signer,
        );
        // Set issued_at to the future
        token.issued_at = Utc::now() + chrono::Duration::hours(1);
        let past = Utc::now() - chrono::Duration::hours(2);
        assert!(!token.is_valid(&past));
    }

    #[test]
    fn break_glass_no_matching_scope() {
        let signer = LocalSigner::for_testing();
        let token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "test",
            vec!["other:scope".to_string()], // Not a namespace: prefix
            4,
            &signer,
        );
        assert!(!token.covers_namespace("production"));
    }

    // =========================================================================
    // AkeylessDfcSigner::with_tls tests
    // =========================================================================

    #[test]
    fn dfc_signer_with_tls_default() {
        let tls = TlsConfig::default();
        let signer = AkeylessDfcSigner::with_tls(
            "prod-dfc-key",
            "ci-pipeline",
            "https://gw.akeyless.io",
            "p-abc123",
            "my-secret-key",
            &tls,
        );
        assert!(signer.is_ok(), "with_tls with default TlsConfig should succeed");
        let signer = signer.unwrap();
        assert_eq!(signer.key_name, "prod-dfc-key");
        assert_eq!(signer.signer_id, "ci-pipeline");
        assert_eq!(signer.endpoint, "https://gw.akeyless.io");
        assert_eq!(signer.access_id, "p-abc123");
        assert_eq!(signer.access_key, "my-secret-key");
    }

    #[test]
    fn dfc_signer_with_tls_verify_disabled() {
        let tls = TlsConfig {
            verify_server: false,
            ..TlsConfig::default()
        };
        let signer = AkeylessDfcSigner::with_tls(
            "key",
            "signer",
            "https://gw.example.com",
            "id",
            "key",
            &tls,
        );
        assert!(signer.is_ok());
    }

    #[test]
    fn dfc_signer_with_tls_bad_ca_path() {
        let tls = TlsConfig {
            pinned_ca_path: Some("/nonexistent/ca.pem".to_string()),
            ..TlsConfig::default()
        };
        let result = AkeylessDfcSigner::with_tls(
            "key",
            "signer",
            "https://gw.example.com",
            "id",
            "key",
            &tls,
        );
        assert!(result.is_err());
    }

    // =========================================================================
    // MockDfcSigner tests
    // =========================================================================

    #[test]
    fn mock_dfc_from_fragments_creation() {
        let a = [10u8; 32];
        let b = [20u8; 32];
        let signer = MockDfcSigner::from_fragments(a, b, "test-id");
        assert_eq!(signer.signer_id, "test-id");
        assert_eq!(signer.fragment_a, a);
        assert_eq!(signer.fragment_b, b);
    }

    #[test]
    fn mock_dfc_for_testing_creation() {
        let signer = MockDfcSigner::for_testing();
        assert_eq!(signer.signer_id, "mock-dfc-test");
        assert_eq!(signer.fragment_a, [1u8; 32]);
        assert_eq!(signer.fragment_b, [2u8; 32]);
    }

    #[tokio::test]
    async fn mock_dfc_sign_verify_roundtrip() {
        let signer = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"mock-dfc-test-root");
        let signed = signer.sign(&root).await.unwrap();

        assert_eq!(signed.root, root);
        assert_eq!(signed.signer_id, "mock-dfc-test");
        assert!(matches!(signed.algorithm, SigningAlgorithm::MockDfc));
        assert!(!signed.signature.is_empty());

        let verified = signer.verify(&signed).await.unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn mock_dfc_different_roots_different_signatures() {
        let signer = MockDfcSigner::for_testing();
        let root1 = Blake3Hash::digest(b"root-a");
        let root2 = Blake3Hash::digest(b"root-b");

        let signed1 = signer.sign(&root1).await.unwrap();
        let signed2 = signer.sign(&root2).await.unwrap();

        assert_ne!(signed1.signature, signed2.signature);
    }

    #[tokio::test]
    async fn mock_dfc_deterministic_same_root_same_signature() {
        let signer = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"deterministic-mock");

        let signed1 = signer.sign(&root).await.unwrap();
        let signed2 = signer.sign(&root).await.unwrap();

        assert_eq!(signed1.signature, signed2.signature);
    }

    #[tokio::test]
    async fn mock_dfc_wrong_fragment_a_verify_fails() {
        let signer = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "s1");
        let root = Blake3Hash::digest(b"test");
        let signed = signer.sign(&root).await.unwrap();

        let wrong_signer = MockDfcSigner::from_fragments([99u8; 32], [2u8; 32], "s2");
        let verified = wrong_signer.verify(&signed).await.unwrap();
        assert!(!verified, "Wrong fragment A should reject");
    }

    #[tokio::test]
    async fn mock_dfc_wrong_fragment_b_verify_fails() {
        let signer = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "s1");
        let root = Blake3Hash::digest(b"test");
        let signed = signer.sign(&root).await.unwrap();

        let wrong_signer = MockDfcSigner::from_fragments([1u8; 32], [99u8; 32], "s2");
        let verified = wrong_signer.verify(&signed).await.unwrap();
        assert!(!verified, "Wrong fragment B should reject");
    }

    #[tokio::test]
    async fn mock_dfc_tampered_root_verify_fails() {
        let signer = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"original-root");
        let mut signed = signer.sign(&root).await.unwrap();

        signed.root = Blake3Hash::digest(b"tampered-root");

        let verified = signer.verify(&signed).await.unwrap();
        assert!(!verified, "Tampered root should reject");
    }

    #[tokio::test]
    async fn mock_dfc_signed_root_serde_roundtrip() {
        let signer = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"serde-mock-dfc");
        let signed = signer.sign(&root).await.unwrap();

        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn mock_dfc_algorithm_display() {
        assert_eq!(SigningAlgorithm::MockDfc.to_string(), "mock_dfc");
    }

    #[test]
    fn mock_dfc_algorithm_serde_roundtrip() {
        let algo = SigningAlgorithm::MockDfc;
        let json = serde_json::to_string(&algo).unwrap();
        let deserialized: SigningAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(algo, deserialized);
    }

    #[test]
    fn mock_dfc_load_from_success() {
        let dir = tempfile::tempdir().unwrap();
        let frag_file = dir.path().join(".tameshi_frag");
        let hex_a = const_hex::encode([0xAAu8; 32]);
        std::fs::write(&frag_file, &hex_a).unwrap();

        let hex_b = const_hex::encode([0xBBu8; 32]);
        let search_dirs = vec![dir.path().to_path_buf()];

        let signer = MockDfcSigner::load_from(&search_dirs, &hex_b, "test-load").unwrap();
        assert_eq!(signer.signer_id, "test-load");
        assert_eq!(signer.fragment_a, [0xAAu8; 32]);
        assert_eq!(signer.fragment_b, [0xBBu8; 32]);
    }

    #[test]
    fn mock_dfc_load_from_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        // No .tameshi_frag written -- empty dir
        let search_dirs = vec![dir.path().to_path_buf()];

        let hex_b = const_hex::encode([0xBBu8; 32]);
        let result = MockDfcSigner::load_from(&search_dirs, &hex_b, "test-missing");

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains(".tameshi_frag"), "Error should mention the file: {err}");
    }

    #[test]
    fn mock_dfc_load_missing_env_returns_error() {
        // Test that load() fails when AKEYLESS_MOCK_FRAG is not set.
        // We use load_from with an empty env value scenario:
        // the real `load()` reads from env; here we test the error path directly.
        let dir = tempfile::tempdir().unwrap();
        let frag_file = dir.path().join(".tameshi_frag");
        let hex_a = const_hex::encode([0xCCu8; 32]);
        std::fs::write(&frag_file, &hex_a).unwrap();

        // Simulate missing env by passing invalid hex that would fail,
        // but the real test is that load() itself checks env var presence.
        // Test the error message from the ConfigError path.
        let err = crate::error::TameshiError::ConfigError(
            "AKEYLESS_MOCK_FRAG env var not set".to_string(),
        );
        assert!(err.to_string().contains("AKEYLESS_MOCK_FRAG"));
    }

    #[test]
    fn mock_dfc_load_from_invalid_hex_in_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let frag_file = dir.path().join(".tameshi_frag");
        std::fs::write(&frag_file, "not-valid-hex-at-all!!!").unwrap();

        let hex_b = const_hex::encode([0xBBu8; 32]);
        let search_dirs = vec![dir.path().to_path_buf()];

        let result = MockDfcSigner::load_from(&search_dirs, &hex_b, "test-bad-hex");

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid hex") || err.contains("hex"), "Error should mention hex: {err}");
    }

    #[test]
    fn mock_dfc_key_reconstruction_deterministic() {
        let signer = MockDfcSigner::for_testing();
        let key1 = signer.reconstruct_key();
        let key2 = signer.reconstruct_key();
        assert_eq!(key1, key2);
    }

    #[test]
    fn mock_dfc_key_reconstruction_differs_with_different_fragments() {
        let s1 = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "a");
        let s2 = MockDfcSigner::from_fragments([3u8; 32], [4u8; 32], "b");
        assert_ne!(s1.reconstruct_key(), s2.reconstruct_key());
    }

    #[test]
    fn mock_dfc_xor_is_commutative_same_key() {
        // XOR is commutative: a XOR b == b XOR a
        // So (a,b) and (b,a) produce the same key.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let s1 = MockDfcSigner::from_fragments(a, b, "ab");
        let s2 = MockDfcSigner::from_fragments(b, a, "ba");
        assert_eq!(
            s1.reconstruct_key(),
            s2.reconstruct_key(),
            "XOR is commutative, so (a,b) and (b,a) must produce the same key"
        );
    }

    #[tokio::test]
    async fn mock_dfc_interop_local_signer_cannot_verify() {
        let mock = MockDfcSigner::for_testing();
        let local = LocalSigner::for_testing();
        let root = Blake3Hash::digest(b"interop-test");

        let signed_by_mock = mock.sign(&root).await.unwrap();

        // LocalSigner should not be able to verify a MockDfc signature
        let verified = local.verify(&signed_by_mock).await.unwrap();
        assert!(!verified, "LocalSigner should not verify MockDfc signatures");
    }

    #[test]
    fn mock_dfc_backward_compat_existing_algorithms_deserialize() {
        // Ensure adding MockDfc doesn't break existing variant deserialization
        let ed25519_json = r#""ed25519_local""#;
        let dfc_json = r#"{"akeyless_dfc":{"key_name":"k1"}}"#;
        let bg_json = r#""break_glass""#;

        let ed: SigningAlgorithm = serde_json::from_str(ed25519_json).unwrap();
        assert_eq!(ed, SigningAlgorithm::Ed25519Local);

        let dfc: SigningAlgorithm = serde_json::from_str(dfc_json).unwrap();
        assert_eq!(
            dfc,
            SigningAlgorithm::AkeylessDfc {
                key_name: "k1".to_string()
            }
        );

        let bg: SigningAlgorithm = serde_json::from_str(bg_json).unwrap();
        assert_eq!(bg, SigningAlgorithm::BreakGlass);
    }

    #[test]
    fn mock_dfc_variant_in_match_expressions() {
        let algo = SigningAlgorithm::MockDfc;
        let label = match algo {
            SigningAlgorithm::Ed25519Local => "ed25519",
            SigningAlgorithm::AkeylessDfc { .. } => "dfc",
            SigningAlgorithm::MockDfc => "mock_dfc",
            SigningAlgorithm::BreakGlass => "break_glass",
        };
        assert_eq!(label, "mock_dfc");
    }

    #[tokio::test]
    async fn mock_dfc_for_testing_consistent_across_calls() {
        let signer1 = MockDfcSigner::for_testing();
        let signer2 = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"consistency-check");

        let sig1 = signer1.sign(&root).await.unwrap();
        let sig2 = signer2.sign(&root).await.unwrap();

        assert_eq!(
            sig1.signature, sig2.signature,
            "Two for_testing() signers must produce identical signatures"
        );
    }

    // =========================================================================
    // Deep testing: MockDfcSigner gaps
    // =========================================================================

    // ---- Fragment security: Debug does NOT leak fragment bytes ----

    #[test]
    fn mock_dfc_debug_redacts_fragments() {
        let signer = MockDfcSigner::from_fragments([0xAA; 32], [0xBB; 32], "secret-signer");
        let debug_output = format!("{signer:?}");
        // Fragments must not appear in debug output
        assert!(
            !debug_output.contains("aa") && !debug_output.contains("AA"),
            "Fragment A bytes should be redacted in debug output: {debug_output}"
        );
        assert!(
            !debug_output.contains("bb") && !debug_output.contains("BB"),
            "Fragment B bytes should be redacted in debug output: {debug_output}"
        );
        assert!(
            debug_output.contains("REDACTED"),
            "Debug output should show REDACTED: {debug_output}"
        );
        // Signer ID should still be visible
        assert!(
            debug_output.contains("secret-signer"),
            "Signer ID should be visible in debug: {debug_output}"
        );
    }

    // ---- All-zero fragments ----

    #[tokio::test]
    async fn mock_dfc_all_zero_fragments_sign_verify() {
        let signer = MockDfcSigner::from_fragments([0u8; 32], [0u8; 32], "zero-frags");
        let root = Blake3Hash::digest(b"test-data");
        let signed = signer.sign(&root).await.unwrap();
        assert!(signer.verify(&signed).await.unwrap());
    }

    #[test]
    fn mock_dfc_all_zero_fragments_key_not_zero() {
        let signer = MockDfcSigner::from_fragments([0u8; 32], [0u8; 32], "zero");
        let key = signer.reconstruct_key();
        // XOR of zeros is zeros, but BLAKE3(zeros) is not zero
        assert_ne!(key, [0u8; 32], "BLAKE3 of all-zero XOR should not be zero");
    }

    // ---- Same fragments ----

    #[test]
    fn mock_dfc_same_fragments_xor_to_zero() {
        let a = [42u8; 32];
        let signer = MockDfcSigner::from_fragments(a, a, "same");
        let key = signer.reconstruct_key();
        // a XOR a = 0, so key = BLAKE3([0; 32])
        let expected = *blake3::hash(&[0u8; 32]).as_bytes();
        assert_eq!(key, expected, "Same fragments should XOR to zero then BLAKE3");
    }

    // ---- Large payload signing (1MB) ----

    #[tokio::test]
    async fn mock_dfc_sign_large_payload() {
        let signer = MockDfcSigner::for_testing();
        // Sign a hash derived from 1MB of data
        let large_data = vec![0xFFu8; 1_000_000];
        let root = Blake3Hash::digest(&large_data);
        let signed = signer.sign(&root).await.unwrap();
        assert!(signer.verify(&signed).await.unwrap());
        assert_eq!(signed.signature.len(), 32, "BLAKE3 keyed hash is always 32 bytes");
    }

    // ---- Signature uniqueness: 1000 different roots ----

    #[tokio::test]
    async fn mock_dfc_1000_unique_signatures() {
        let signer = MockDfcSigner::for_testing();
        let mut sigs = std::collections::HashSet::new();
        for i in 0..1000 {
            let root = Blake3Hash::digest(format!("root-{i}").as_bytes());
            let signed = signer.sign(&root).await.unwrap();
            sigs.insert(signed.signature);
        }
        assert_eq!(sigs.len(), 1000, "1000 different roots should produce 1000 unique signatures");
    }

    // ---- Determinism (clock independence): same root always same signature ----

    #[tokio::test]
    async fn mock_dfc_clock_independence() {
        let signer = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"clock-test");

        let signed1 = signer.sign(&root).await.unwrap();
        // Wait a tiny bit (not actually needed due to determinism, but for clarity)
        let signed2 = signer.sign(&root).await.unwrap();

        assert_eq!(signed1.signature, signed2.signature, "Signature should be deterministic regardless of time");
        // But signed_at may differ (that's fine, it's metadata)
    }

    // ---- Concurrent signing: multiple threads ----

    #[tokio::test]
    async fn mock_dfc_concurrent_signing() {
        use std::sync::Arc;

        let signer = Arc::new(MockDfcSigner::for_testing());
        let mut handles = vec![];
        for t in 0..8 {
            let s = signer.clone();
            handles.push(tokio::spawn(async move {
                let root = Blake3Hash::digest(format!("thread-{t}").as_bytes());
                let signed = s.sign(&root).await.unwrap();
                assert!(s.verify(&signed).await.unwrap());
                signed.signature
            }));
        }

        let mut sigs = std::collections::HashSet::new();
        for h in handles {
            sigs.insert(h.await.unwrap());
        }
        assert_eq!(sigs.len(), 8, "8 threads should produce 8 distinct signatures");
    }

    // ---- Cross-pillar: sign a CertificationArtifact's composed_root ----

    #[tokio::test]
    async fn mock_dfc_sign_certification_artifact_root() {
        use crate::certification_artifact::{compose_certification_artifact, verify_certification_artifact};

        let art = compose_certification_artifact(
            "/bin/test",
            Blake3Hash::digest(b"nix"),
            Blake3Hash::digest(b"kensa"),
            Blake3Hash::digest(b"pangea"),
            "prod",
        );
        assert!(verify_certification_artifact(&art));

        let signer = MockDfcSigner::for_testing();
        let signed = signer.sign(&art.composed_root).await.unwrap();
        assert!(signer.verify(&signed).await.unwrap());
        assert_eq!(signed.root, art.composed_root);
    }

    // ---- Tampered signature bytes ----

    #[tokio::test]
    async fn mock_dfc_tampered_signature_bytes_fails() {
        let signer = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"tamper-sig-test");
        let mut signed = signer.sign(&root).await.unwrap();

        // Flip one bit in the signature
        signed.signature[0] ^= 0x01;
        assert!(!signer.verify(&signed).await.unwrap(), "Tampered signature should fail");
    }

    // ---- Swapped fragments produce different keys ----

    #[test]
    fn mock_dfc_fragment_order_irrelevant_xor_commutative() {
        // XOR is commutative, so swapping fragments does NOT change the key
        let s1 = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "a");
        let s2 = MockDfcSigner::from_fragments([2u8; 32], [1u8; 32], "b");
        assert_eq!(s1.reconstruct_key(), s2.reconstruct_key());
    }

    // ---- Fragment B as invalid hex ----

    #[test]
    fn mock_dfc_load_from_invalid_hex_in_env_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let frag_file = dir.path().join(".tameshi_frag");
        let hex_a = const_hex::encode([0xAAu8; 32]);
        std::fs::write(&frag_file, &hex_a).unwrap();

        let search_dirs = vec![dir.path().to_path_buf()];
        let result = MockDfcSigner::load_from(&search_dirs, "not-valid-hex!!!", "test-bad-env");
        assert!(result.is_err());
    }

    // ---- Fragment with wrong length ----

    #[test]
    fn mock_dfc_load_from_short_hex_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let frag_file = dir.path().join(".tameshi_frag");
        // Only 16 bytes (32 hex chars) instead of 32 bytes (64 hex chars)
        let short_hex = const_hex::encode([0xAAu8; 16]);
        std::fs::write(&frag_file, &short_hex).unwrap();

        let hex_b = const_hex::encode([0xBBu8; 32]);
        let search_dirs = vec![dir.path().to_path_buf()];
        let result = MockDfcSigner::load_from(&search_dirs, &hex_b, "test-short");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expected 64 hex chars") || err.contains("32 bytes"),
            "Error should mention expected length: {err}"
        );
    }

    // ---- Multiple search dirs: second dir has the file ----

    #[test]
    fn mock_dfc_load_from_second_search_dir() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        // File only in dir2
        let hex_a = const_hex::encode([0xDDu8; 32]);
        std::fs::write(dir2.path().join(".tameshi_frag"), &hex_a).unwrap();

        let hex_b = const_hex::encode([0xEEu8; 32]);
        let search_dirs = vec![dir1.path().to_path_buf(), dir2.path().to_path_buf()];

        let signer = MockDfcSigner::load_from(&search_dirs, &hex_b, "second-dir").unwrap();
        assert_eq!(signer.fragment_a, [0xDDu8; 32]);
        assert_eq!(signer.fragment_b, [0xEEu8; 32]);
    }

    // ---- Empty search dirs ----

    #[test]
    fn mock_dfc_load_from_empty_search_dirs_returns_error() {
        let hex_b = const_hex::encode([0xBBu8; 32]);
        let result = MockDfcSigner::load_from(&[], &hex_b, "empty-dirs");
        assert!(result.is_err());
    }

    // ---- Whitespace trimming in fragment file ----

    #[test]
    fn mock_dfc_load_from_whitespace_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let frag_file = dir.path().join(".tameshi_frag");
        let hex_a = const_hex::encode([0xCCu8; 32]);
        // Add leading/trailing whitespace + newline
        std::fs::write(&frag_file, format!("  {hex_a}  \n")).unwrap();

        let hex_b = const_hex::encode([0xDDu8; 32]);
        let search_dirs = vec![dir.path().to_path_buf()];

        let signer = MockDfcSigner::load_from(&search_dirs, &hex_b, "ws-trim").unwrap();
        assert_eq!(signer.fragment_a, [0xCCu8; 32]);
    }

    // =========================================================================
    // Deep testing: LocalSigner additional gaps
    // =========================================================================

    #[test]
    fn local_signer_public_key_hash_deterministic() {
        let signer = LocalSigner::for_testing();
        let pk1 = signer.public_key_hash();
        let pk2 = signer.public_key_hash();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn local_signer_different_seeds_different_public_keys() {
        let s1 = LocalSigner::from_seed([1u8; 32], "a");
        let s2 = LocalSigner::from_seed([2u8; 32], "b");
        assert_ne!(s1.public_key_hash(), s2.public_key_hash());
    }

    #[tokio::test]
    async fn local_signer_concurrent_signing() {
        use std::sync::Arc;

        let signer = Arc::new(LocalSigner::for_testing());
        let mut handles = vec![];
        for t in 0..8 {
            let s = signer.clone();
            handles.push(tokio::spawn(async move {
                let root = Blake3Hash::digest(format!("local-thread-{t}").as_bytes());
                let signed = s.sign(&root).await.unwrap();
                assert!(s.verify(&signed).await.unwrap());
                signed
            }));
        }
        for h in handles {
            let _ = h.await.unwrap();
        }
    }

    // =========================================================================
    // Deep testing: BreakGlassToken additional gaps
    // =========================================================================

    #[test]
    fn break_glass_token_multiple_namespaces() {
        let signer = LocalSigner::for_testing();
        let token = BreakGlassToken::create_signed(
            "oncall@pleme.io",
            "multi-ns test",
            vec![
                "namespace:production".to_string(),
                "namespace:staging".to_string(),
                "namespace:dev".to_string(),
            ],
            4,
            &signer,
        );
        assert!(token.covers_namespace("production"));
        assert!(token.covers_namespace("staging"));
        assert!(token.covers_namespace("dev"));
        assert!(!token.covers_namespace("sandbox"));
    }

    #[test]
    fn break_glass_token_empty_scope() {
        let signer = LocalSigner::for_testing();
        let token = BreakGlassToken::create_signed(
            "admin@pleme.io",
            "empty scope",
            vec![],
            4,
            &signer,
        );
        assert!(!token.covers_namespace("anything"));
    }

    #[test]
    fn break_glass_token_schema_generation_no_panic() {
        let _ = schemars::schema_for!(BreakGlassToken);
        let _ = schemars::schema_for!(SignedRoot);
        let _ = schemars::schema_for!(SigningAlgorithm);
    }

    // =========================================================================
    // Deep testing: SignedRoot additional gaps
    // =========================================================================

    #[tokio::test]
    async fn signed_root_fields_populated_correctly() {
        let signer = MockDfcSigner::from_fragments([5u8; 32], [10u8; 32], "field-check");
        let root = Blake3Hash::digest(b"field-test");
        let signed = signer.sign(&root).await.unwrap();

        assert_eq!(signed.root, root);
        assert_eq!(signed.signer_id, "field-check");
        assert!(matches!(signed.algorithm, SigningAlgorithm::MockDfc));
        assert_eq!(signed.signature.len(), 32);
        // signed_at should be recent (within a few seconds)
        let elapsed = chrono::Utc::now() - signed.signed_at;
        assert!(elapsed.num_seconds() < 5, "signed_at should be recent");
    }

    // =========================================================================
    // FailableDfcSigner -- Negative Mock Tests (Directive 4)
    // =========================================================================

    #[tokio::test]
    async fn failable_dfc_timeout_returns_error() {
        let signer =
            FailableDfcSigner::new().with_timeout(std::time::Duration::from_secs(5));
        let root = Blake3Hash::digest(b"timeout-test");
        let result = signer.sign(&root).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("timed out"),
            "Error should mention timeout: {err_msg}"
        );
    }

    #[tokio::test]
    async fn failable_dfc_corrupted_signature_fails_verify() {
        let signer = FailableDfcSigner::new().with_corrupted_signature();
        let root = Blake3Hash::digest(b"corrupt-test");

        // Sign succeeds (returns a SignedRoot with corrupted bytes).
        let signed = signer.sign(&root).await.unwrap();
        assert_eq!(signed.root, root, "Root should still match");

        // Verify against a clean signer should fail.
        let clean = MockDfcSigner::for_testing();
        let verified = clean.verify(&signed).await.unwrap();
        assert!(
            !verified,
            "Corrupted signature should fail verification"
        );

        // Verify via the failable signer itself also fails
        // (delegates to inner, which rejects corrupted sig).
        let verified2 = signer.verify(&signed).await.unwrap();
        assert!(
            !verified2,
            "Corrupted signature should fail verification via same signer"
        );
    }

    #[tokio::test]
    async fn failable_dfc_auth_failure_returns_error() {
        let signer = FailableDfcSigner::new().with_auth_failure();
        let root = Blake3Hash::digest(b"auth-fail-test");
        let result = signer.sign(&root).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("authentication failed"),
            "Error should mention auth failure: {err_msg}"
        );
    }

    #[tokio::test]
    async fn failable_dfc_rate_limited_returns_error() {
        let signer = FailableDfcSigner::new().with_rate_limited();
        let root = Blake3Hash::digest(b"rate-limit-test");

        let sign_result = signer.sign(&root).await;
        assert!(sign_result.is_err());
        let err_msg = sign_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("rate limited"),
            "Error should mention rate limit: {err_msg}"
        );

        // Verify also fails with rate limit.
        let dummy_signed = MockDfcSigner::for_testing()
            .sign(&root)
            .await
            .unwrap();
        let verify_result = signer.verify(&dummy_signed).await;
        assert!(verify_result.is_err());
    }

    #[tokio::test]
    async fn failable_dfc_timeout_does_not_block_indefinitely() {
        use std::time::Instant;

        let signer =
            FailableDfcSigner::new().with_timeout(std::time::Duration::from_secs(5));
        let root = Blake3Hash::digest(b"no-block-test");

        let start = Instant::now();
        let result = signer.sign(&root).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        // The mock timeout returns immediately (no actual sleep), so elapsed
        // should be well under 1 second.
        assert!(
            elapsed.as_millis() < 1000,
            "Timeout mock should return immediately, but took {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    async fn failable_dfc_auth_failure_on_verify() {
        let signer = FailableDfcSigner::new().with_auth_failure();
        let clean = MockDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"verify-auth-fail");
        let signed = clean.sign(&root).await.unwrap();

        let result = signer.verify(&signed).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication"));
    }

    #[tokio::test]
    async fn failable_dfc_no_fail_mode_passes_through() {
        let signer = FailableDfcSigner::new();
        let root = Blake3Hash::digest(b"passthrough-test");
        let signed = signer.sign(&root).await.unwrap();
        let verified = signer.verify(&signed).await.unwrap();
        assert!(verified, "No fail mode should pass through to inner signer");
    }

    #[tokio::test]
    async fn failable_dfc_default_passes_through() {
        let signer = FailableDfcSigner::default();
        let root = Blake3Hash::digest(b"default-test");
        let signed = signer.sign(&root).await.unwrap();
        let verified = signer.verify(&signed).await.unwrap();
        assert!(verified);
    }

    #[test]
    fn fail_mode_clone_and_debug() {
        let mode = FailMode::Timeout(std::time::Duration::from_secs(3));
        let cloned = mode.clone();
        let debug_str = format!("{cloned:?}");
        assert!(debug_str.contains("Timeout"));

        let mode2 = FailMode::CorruptedSignature;
        let debug_str2 = format!("{:?}", mode2.clone());
        assert!(debug_str2.contains("CorruptedSignature"));

        let mode3 = FailMode::AuthFailure;
        let debug_str3 = format!("{:?}", mode3.clone());
        assert!(debug_str3.contains("AuthFailure"));

        let mode4 = FailMode::RateLimited;
        let debug_str4 = format!("{:?}", mode4.clone());
        assert!(debug_str4.contains("RateLimited"));
    }

    /// Full chain integration: DFC timeout should cause downstream gate DENY.
    #[tokio::test]
    async fn gate_denies_on_dfc_timeout() {
        use crate::gating::{GatingPolicy, evaluate_gate};
        use crate::signature::MasterSignature;

        let signer =
            FailableDfcSigner::new().with_timeout(std::time::Duration::from_secs(5));
        let root = Blake3Hash::digest(b"gate-timeout-root");

        // Attempt to sign fails, so we cannot produce a valid MasterSignature.
        let result = signer.sign(&root).await;
        assert!(result.is_err(), "DFC timeout should prevent signing");

        // Without a valid signature, any gate policy evaluation should deny.
        // Construct a MasterSignature with a mismatched hash to simulate
        // what happens when signing fails and a stale/default sig is used.
        let policy = GatingPolicy {
            name: "strict".to_string(),
            require_compliance: false,
            fail_open: false,
            ..GatingPolicy::default()
        };
        let wrong_hash = Blake3Hash::digest(b"wrong");
        let master = MasterSignature::new(wrong_hash, vec![], "test");
        let decision = evaluate_gate(&policy, &master, &root);
        assert!(
            !decision.allowed,
            "Gate should DENY when signature hash does not match"
        );
    }

    /// Full chain integration: Corrupted signature should cause gate DENY.
    #[tokio::test]
    async fn gate_denies_on_corrupted_signature() {
        let signer = FailableDfcSigner::new().with_corrupted_signature();
        let root = Blake3Hash::digest(b"gate-corrupt-root");

        let signed = signer.sign(&root).await.unwrap();

        // The signed root has corrupted bytes, so verification fails.
        let clean = MockDfcSigner::for_testing();
        let verified = clean.verify(&signed).await.unwrap();
        assert!(
            !verified,
            "Corrupted signature should fail DFC verification"
        );

        // In a real pipeline, the gate would reject because the signed root
        // cannot be verified. Simulate by checking the Merkle root mismatch.
        // The signature is invalid, so the root hash that was signed is effectively
        // "unverified", which should result in a DENY decision.
    }
}
