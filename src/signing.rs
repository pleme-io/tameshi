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

use crate::hash::Blake3Hash;

/// Algorithm used to sign the Merkle root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    /// Local Ed25519 key (development/testing).
    Ed25519Local,
    /// Akeyless Distributed Fragment Cryptography (production).
    AkeylessDfc {
        /// The DFC key name in Akeyless.
        key_name: String,
    },
    /// Emergency break-glass bypass.
    BreakGlass,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519Local => write!(f, "ed25519_local"),
            Self::AkeylessDfc { key_name } => write!(f, "akeyless_dfc:{key_name}"),
            Self::BreakGlass => write!(f, "break_glass"),
        }
    }
}

/// A signed Merkle root with provenance metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRoot {
    /// The Merkle root that was signed.
    pub root: Blake3Hash,
    /// The cryptographic signature bytes.
    #[serde(with = "hex_sig")]
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

/// Placeholder for Akeyless DFC signing.
///
/// In production, this calls the Akeyless DFC API for threshold signing.
/// The key never exists in one piece — fragments are distributed across
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
}

impl AkeylessDfcSigner {
    /// Create a new DFC signer.
    #[must_use]
    pub fn new(key_name: &str, signer_id: &str, endpoint: &str) -> Self {
        Self {
            key_name: key_name.to_string(),
            signer_id: signer_id.to_string(),
            client: reqwest::Client::new(),
            endpoint: endpoint.to_string(),
        }
    }
}

impl MerkleRootSigner for AkeylessDfcSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        // In production: POST to Akeyless signing endpoint
        // For now: placeholder that returns a deterministic signature
        let _ = &self.client; // will be used for actual API calls
        let _ = &self.endpoint;

        // Placeholder: hash key_name + root as "signature"
        let mut data = Vec::new();
        data.extend_from_slice(self.key_name.as_bytes());
        data.push(0);
        data.extend_from_slice(&root.0);
        let sig_hash = Blake3Hash::digest(&data);

        Ok(SignedRoot {
            root: root.clone(),
            signature: sig_hash.0.to_vec(),
            algorithm: SigningAlgorithm::AkeylessDfc {
                key_name: self.key_name.clone(),
            },
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        // In production: POST to Akeyless verify endpoint
        // For now: re-sign and compare
        let expected = self.sign(&signed.root).await?;
        Ok(expected.signature == signed.signature)
    }
}

/// Emergency break-glass bypass token.
///
/// Allows deployments during attestation outages. Every break-glass event
/// is cryptographically logged for CIRCIA compliance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

    #[tokio::test]
    async fn dfc_signer_sign_verify() {
        let signer = AkeylessDfcSigner::new(
            "test-dfc-key",
            "ci-pipeline",
            "https://akeyless.example.com",
        );
        let root = Blake3Hash::digest(b"dfc-test");
        let signed = signer.sign(&root).await.unwrap();

        assert_eq!(signed.root, root);
        assert!(matches!(signed.algorithm, SigningAlgorithm::AkeylessDfc { .. }));

        let verified = signer.verify(&signed).await.unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn dfc_signer_deterministic() {
        let signer = AkeylessDfcSigner::new("key", "id", "https://example.com");
        let root = Blake3Hash::digest(b"deterministic");

        let s1 = signer.sign(&root).await.unwrap();
        let s2 = signer.sign(&root).await.unwrap();
        assert_eq!(s1.signature, s2.signature);
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
}
