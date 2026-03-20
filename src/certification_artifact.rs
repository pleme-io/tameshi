//! Recursive attestation Merkle assembler for per-binary certification artifacts.
//!
//! A certification artifact binds three sources of truth into a single
//! cryptographic commitment:
//!
//! - **Artifact provenance** (Nix derivation hash or OCI digest)
//! - **Compliance controls** (kensa assessment hash)
//! - **Infrastructure intent** (Pangea synthesis output hash)
//!
//! These three inputs compose into a 3-leaf Merkle tree with RFC 9162
//! domain separation. The composed root is the single hash that gates
//! binary execution in the eBPF sentinel.
//!
//! # Usage
//!
//! ```rust,no_run
//! use tameshi::certification_artifact::*;
//! use tameshi::hash::Blake3Hash;
//!
//! let artifact = compose_certification_artifact(
//!     "/usr/bin/myapp",
//!     Blake3Hash::digest(b"nix-closure"),
//!     Blake3Hash::digest(b"kensa-result"),
//!     Blake3Hash::digest(b"pangea-synthesis"),
//!     "production",
//! );
//!
//! assert!(verify_certification_artifact(&artifact));
//! ```

use chrono::{DateTime, Utc};
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::merkle::{Blake3Algorithm, domain_separated_leaf};

/// A cryptographic certification artifact binding three sources of truth:
/// artifact provenance (Nix/OCI), compliance controls (kensa), and
/// infrastructure intent (Pangea synthesis).
///
/// The three inputs compose into a 3-leaf Merkle tree with RFC 9162
/// domain separation. The composed root is the single hash that gates
/// binary execution in the eBPF sentinel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CertificationArtifact {
    /// Path to the binary this artifact certifies.
    pub binary_path: String,
    /// BLAKE3 hash of the artifact (Nix derivation, OCI digest).
    pub artifact_hash: Blake3Hash,
    /// BLAKE3 hash of the compliance control result (kensa assessment).
    pub control_hash: Blake3Hash,
    /// BLAKE3 hash of the infrastructure intent (Pangea synthesis output).
    pub intent_hash: Blake3Hash,
    /// 3-leaf Merkle root composing all three inputs.
    pub composed_root: Blake3Hash,
    /// Inclusion proof paths for each input leaf.
    pub proof_paths: ArtifactProofPaths,
    /// Deployment environment.
    pub environment: String,
    /// When this artifact was computed.
    pub computed_at: DateTime<Utc>,
}

/// Merkle inclusion proof paths for the three certification inputs.
/// Leaf indices are fixed: artifact=0, control=1, intent=2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactProofPaths {
    /// Proof path for the artifact leaf (index 0).
    pub artifact_proof: Vec<Blake3Hash>,
    /// Proof path for the control leaf (index 1).
    pub control_proof: Vec<Blake3Hash>,
    /// Proof path for the intent leaf (index 2).
    pub intent_proof: Vec<Blake3Hash>,
}

/// Compose a certification artifact from three inputs.
///
/// Creates a 3-leaf Merkle tree with domain-separated leaves:
/// - Leaf 0: artifact hash (Nix derivation / OCI digest)
/// - Leaf 1: control hash (kensa compliance result)
/// - Leaf 2: intent hash (Pangea synthesis output)
///
/// Returns the artifact with composed root and inclusion proofs.
#[must_use]
pub fn compose_certification_artifact(
    binary_path: &str,
    artifact_hash: Blake3Hash,
    control_hash: Blake3Hash,
    intent_hash: Blake3Hash,
    environment: &str,
) -> CertificationArtifact {
    let leaves = build_leaves(&artifact_hash, &control_hash, &intent_hash);
    let tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
    let root = Blake3Hash(tree.root().expect("3-leaf tree always has a root"));

    let proof_paths = extract_proof_paths(&tree);

    CertificationArtifact {
        binary_path: binary_path.to_string(),
        artifact_hash,
        control_hash,
        intent_hash,
        composed_root: root,
        proof_paths,
        environment: environment.to_string(),
        computed_at: Utc::now(),
    }
}

/// Verify a certification artifact's integrity.
///
/// Checks that all three proof paths are valid against the composed root
/// and that the root matches a recomputation from the three input hashes.
#[must_use]
pub fn verify_certification_artifact(artifact: &CertificationArtifact) -> bool {
    // Recompute the tree from the three input hashes
    let leaves = build_leaves(
        &artifact.artifact_hash,
        &artifact.control_hash,
        &artifact.intent_hash,
    );
    let tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
    let recomputed_root = Blake3Hash(tree.root().expect("3-leaf tree always has a root"));

    // Check root matches
    if recomputed_root != artifact.composed_root {
        return false;
    }

    // Verify each proof independently
    let total_leaves = 3;

    let artifact_ok = verify_single_proof(
        &artifact.proof_paths.artifact_proof,
        &artifact.composed_root,
        &artifact.artifact_hash,
        0,
        total_leaves,
    );

    let control_ok = verify_single_proof(
        &artifact.proof_paths.control_proof,
        &artifact.composed_root,
        &artifact.control_hash,
        1,
        total_leaves,
    );

    let intent_ok = verify_single_proof(
        &artifact.proof_paths.intent_proof,
        &artifact.composed_root,
        &artifact.intent_hash,
        2,
        total_leaves,
    );

    artifact_ok && control_ok && intent_ok
}

/// Build the three domain-separated leaves for the Merkle tree.
fn build_leaves(
    artifact_hash: &Blake3Hash,
    control_hash: &Blake3Hash,
    intent_hash: &Blake3Hash,
) -> Vec<[u8; 32]> {
    vec![
        domain_separated_leaf(&artifact_hash.0),
        domain_separated_leaf(&control_hash.0),
        domain_separated_leaf(&intent_hash.0),
    ]
}

/// Extract proof paths for all three leaf indices from the tree.
fn extract_proof_paths(tree: &MerkleTree<Blake3Algorithm>) -> ArtifactProofPaths {
    let extract = |index: usize| -> Vec<Blake3Hash> {
        let proof = tree.proof(&[index]);
        proof
            .proof_hashes()
            .iter()
            .map(|h| Blake3Hash(*h))
            .collect()
    };

    ArtifactProofPaths {
        artifact_proof: extract(0),
        control_proof: extract(1),
        intent_proof: extract(2),
    }
}

/// Verify a single Merkle inclusion proof.
fn verify_single_proof(
    proof_hashes: &[Blake3Hash],
    root: &Blake3Hash,
    leaf_hash: &Blake3Hash,
    index: usize,
    total: usize,
) -> bool {
    let raw_hashes: Vec<[u8; 32]> = proof_hashes.iter().map(|h| h.0).collect();
    let proof = rs_merkle::MerkleProof::<Blake3Algorithm>::new(raw_hashes);
    let ds_leaf = domain_separated_leaf(&leaf_hash.0);
    proof.verify(root.0, &[index], &[ds_leaf], total)
}

/// Fluent builder for `CertificationArtifact`.
pub struct CertificationArtifactBuilder {
    binary_path: Option<String>,
    artifact_hash: Option<Blake3Hash>,
    control_hash: Option<Blake3Hash>,
    intent_hash: Option<Blake3Hash>,
    environment: Option<String>,
}

impl Default for CertificationArtifactBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificationArtifactBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary_path: None,
            artifact_hash: None,
            control_hash: None,
            intent_hash: None,
            environment: None,
        }
    }

    /// Set the binary path.
    #[must_use]
    pub fn binary_path(mut self, path: &str) -> Self {
        self.binary_path = Some(path.to_string());
        self
    }

    /// Set the artifact hash (Nix derivation / OCI digest).
    #[must_use]
    pub fn artifact_hash(mut self, hash: Blake3Hash) -> Self {
        self.artifact_hash = Some(hash);
        self
    }

    /// Set the control hash (kensa compliance result).
    #[must_use]
    pub fn control_hash(mut self, hash: Blake3Hash) -> Self {
        self.control_hash = Some(hash);
        self
    }

    /// Set the intent hash (Pangea synthesis output).
    #[must_use]
    pub fn intent_hash(mut self, hash: Blake3Hash) -> Self {
        self.intent_hash = Some(hash);
        self
    }

    /// Set the deployment environment.
    #[must_use]
    pub fn environment(mut self, env: &str) -> Self {
        self.environment = Some(env.to_string());
        self
    }

    /// Build the certification artifact.
    ///
    /// # Errors
    ///
    /// Returns `TameshiError::InvalidInput` if any required field is missing.
    pub fn build(self) -> crate::error::Result<CertificationArtifact> {
        let binary_path = self.binary_path.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("binary_path is required".to_string())
        })?;
        let artifact_hash = self.artifact_hash.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("artifact_hash is required".to_string())
        })?;
        let control_hash = self.control_hash.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("control_hash is required".to_string())
        })?;
        let intent_hash = self.intent_hash.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("intent_hash is required".to_string())
        })?;
        let environment = self.environment.unwrap_or_else(|| "default".to_string());

        Ok(compose_certification_artifact(
            &binary_path,
            artifact_hash,
            control_hash,
            intent_hash,
            &environment,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hashes() -> (Blake3Hash, Blake3Hash, Blake3Hash) {
        (
            Blake3Hash::digest(b"nix-closure-hash"),
            Blake3Hash::digest(b"kensa-control-hash"),
            Blake3Hash::digest(b"pangea-intent-hash"),
        )
    }

    // ---- 1. Compose determinism (2 tests) ----

    #[test]
    fn compose_determinism_same_inputs_same_root() {
        let (a, c, i) = sample_hashes();
        let art1 = compose_certification_artifact("/bin/app", a.clone(), c.clone(), i.clone(), "prod");
        let art2 = compose_certification_artifact("/bin/app", a, c, i, "prod");
        assert_eq!(art1.composed_root, art2.composed_root);
    }

    #[test]
    fn compose_determinism_repeated_calls() {
        let (a, c, i) = sample_hashes();
        let roots: Vec<Blake3Hash> = (0..5)
            .map(|_| {
                compose_certification_artifact("/bin/app", a.clone(), c.clone(), i.clone(), "prod")
                    .composed_root
            })
            .collect();
        for root in &roots {
            assert_eq!(root, &roots[0]);
        }
    }

    // ---- 2. Proof path verification per leaf (3 tests) ----

    #[test]
    fn proof_verification_artifact_leaf() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a.clone(), c, i, "prod");
        assert!(verify_single_proof(
            &art.proof_paths.artifact_proof,
            &art.composed_root,
            &a,
            0,
            3,
        ));
    }

    #[test]
    fn proof_verification_control_leaf() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c.clone(), i, "prod");
        assert!(verify_single_proof(
            &art.proof_paths.control_proof,
            &art.composed_root,
            &c,
            1,
            3,
        ));
    }

    #[test]
    fn proof_verification_intent_leaf() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c, i.clone(), "prod");
        assert!(verify_single_proof(
            &art.proof_paths.intent_proof,
            &art.composed_root,
            &i,
            2,
            3,
        ));
    }

    // ---- 3. Invalid/tampered proof rejection (3 tests) ----

    #[test]
    fn tampered_artifact_hash_fails_verification() {
        let (a, c, i) = sample_hashes();
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        art.artifact_hash = Blake3Hash::digest(b"tampered");
        assert!(!verify_certification_artifact(&art));
    }

    #[test]
    fn tampered_control_hash_fails_verification() {
        let (a, c, i) = sample_hashes();
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        art.control_hash = Blake3Hash::digest(b"tampered");
        assert!(!verify_certification_artifact(&art));
    }

    #[test]
    fn tampered_intent_hash_fails_verification() {
        let (a, c, i) = sample_hashes();
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        art.intent_hash = Blake3Hash::digest(b"tampered");
        assert!(!verify_certification_artifact(&art));
    }

    // ---- 4. Builder error cases (3 tests) ----

    #[test]
    fn builder_missing_artifact_hash_errors() {
        let (_, c, i) = sample_hashes();
        let result = CertificationArtifactBuilder::new()
            .binary_path("/bin/app")
            .control_hash(c)
            .intent_hash(i)
            .environment("prod")
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("artifact_hash"));
    }

    #[test]
    fn builder_missing_control_hash_errors() {
        let (a, _, i) = sample_hashes();
        let result = CertificationArtifactBuilder::new()
            .binary_path("/bin/app")
            .artifact_hash(a)
            .intent_hash(i)
            .environment("prod")
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("control_hash"));
    }

    #[test]
    fn builder_missing_intent_hash_errors() {
        let (a, c, _) = sample_hashes();
        let result = CertificationArtifactBuilder::new()
            .binary_path("/bin/app")
            .artifact_hash(a)
            .control_hash(c)
            .environment("prod")
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("intent_hash"));
    }

    #[test]
    fn builder_missing_binary_path_errors() {
        let (a, c, i) = sample_hashes();
        let result = CertificationArtifactBuilder::new()
            .artifact_hash(a)
            .control_hash(c)
            .intent_hash(i)
            .environment("prod")
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("binary_path"));
    }

    // ---- 5. Builder happy path (2 tests) ----

    #[test]
    fn builder_happy_path_all_fields() {
        let (a, c, i) = sample_hashes();
        let art = CertificationArtifactBuilder::new()
            .binary_path("/bin/app")
            .artifact_hash(a.clone())
            .control_hash(c.clone())
            .intent_hash(i.clone())
            .environment("staging")
            .build()
            .unwrap();
        assert_eq!(art.binary_path, "/bin/app");
        assert_eq!(art.environment, "staging");
        assert!(verify_certification_artifact(&art));
    }

    #[test]
    fn builder_default_environment() {
        let (a, c, i) = sample_hashes();
        let art = CertificationArtifactBuilder::new()
            .binary_path("/bin/app")
            .artifact_hash(a)
            .control_hash(c)
            .intent_hash(i)
            .build()
            .unwrap();
        assert_eq!(art.environment, "default");
    }

    // ---- 6. Serde roundtrip CertificationArtifact (1 test) ----

    #[test]
    fn serde_roundtrip_certification_artifact() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        let json = serde_json::to_string(&art).unwrap();
        let deserialized: CertificationArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(art, deserialized);
    }

    // ---- 7. Serde roundtrip ArtifactProofPaths (1 test) ----

    #[test]
    fn serde_roundtrip_artifact_proof_paths() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        let json = serde_json::to_string(&art.proof_paths).unwrap();
        let deserialized: ArtifactProofPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(art.proof_paths, deserialized);
    }

    // ---- 8. MasterSignature integration (3 tests) ----

    #[test]
    fn master_signature_with_certification_artifacts() {
        use crate::merkle::compose_merkle;
        use crate::signature::{LayerSignature, LayerType};

        let layers = vec![
            LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
            LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
        ];
        let (a, c, i) = sample_hashes();
        let cert = compose_certification_artifact("/bin/app", a, c, i, "prod");

        let master = compose_merkle(&layers, "production")
            .with_certification_artifacts(vec![cert.clone()]);

        assert_eq!(master.certification_artifacts.len(), 1);
        assert_eq!(master.certification_artifacts[0], cert);
    }

    #[test]
    fn master_signature_serialize_with_artifacts() {
        use crate::merkle::compose_merkle;
        use crate::signature::{LayerSignature, LayerType, MasterSignature};

        let layers = vec![
            LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        ];
        let (a, c, i) = sample_hashes();
        let cert = compose_certification_artifact("/bin/app", a, c, i, "prod");

        let master = compose_merkle(&layers, "production")
            .with_certification_artifacts(vec![cert]);

        let json = serde_json::to_string(&master).unwrap();
        let deserialized: MasterSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(master.certification_artifacts.len(), deserialized.certification_artifacts.len());
        assert_eq!(
            master.certification_artifacts[0].composed_root,
            deserialized.certification_artifacts[0].composed_root
        );
    }

    #[test]
    fn master_signature_backward_compat_no_artifacts_field() {
        use crate::signature::MasterSignature;

        // JSON from an older version without certification_artifacts field
        let old_json = r#"{
            "untested": "0000000000000000000000000000000000000000000000000000000000000000",
            "layers": [],
            "computed_at": "2026-03-20T00:00:00Z",
            "environment": "test"
        }"#;
        let master: MasterSignature = serde_json::from_str(old_json).unwrap();
        assert!(master.certification_artifacts.is_empty());
    }

    // ---- 9. Different inputs produce different roots (3 collision tests) ----

    #[test]
    fn different_artifact_hash_different_root() {
        let (_, c, i) = sample_hashes();
        let art1 = compose_certification_artifact(
            "/bin/app",
            Blake3Hash::digest(b"artifact-1"),
            c.clone(),
            i.clone(),
            "prod",
        );
        let art2 = compose_certification_artifact(
            "/bin/app",
            Blake3Hash::digest(b"artifact-2"),
            c,
            i,
            "prod",
        );
        assert_ne!(art1.composed_root, art2.composed_root);
    }

    #[test]
    fn different_control_hash_different_root() {
        let (a, _, i) = sample_hashes();
        let art1 = compose_certification_artifact(
            "/bin/app",
            a.clone(),
            Blake3Hash::digest(b"control-1"),
            i.clone(),
            "prod",
        );
        let art2 = compose_certification_artifact(
            "/bin/app",
            a,
            Blake3Hash::digest(b"control-2"),
            i,
            "prod",
        );
        assert_ne!(art1.composed_root, art2.composed_root);
    }

    #[test]
    fn different_intent_hash_different_root() {
        let (a, c, _) = sample_hashes();
        let art1 = compose_certification_artifact(
            "/bin/app",
            a.clone(),
            c.clone(),
            Blake3Hash::digest(b"intent-1"),
            "prod",
        );
        let art2 = compose_certification_artifact(
            "/bin/app",
            a,
            c,
            Blake3Hash::digest(b"intent-2"),
            "prod",
        );
        assert_ne!(art1.composed_root, art2.composed_root);
    }

    // ---- 10. Empty string binary path allowed (1 test) ----

    #[test]
    fn empty_binary_path_allowed() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("", a, c, i, "prod");
        assert_eq!(art.binary_path, "");
        assert!(verify_certification_artifact(&art));
    }

    // ---- 11. Tampered leaf detection (2 tests) ----

    #[test]
    fn tampered_proof_path_fails_verification() {
        let (a, c, i) = sample_hashes();
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        // Corrupt one proof hash
        if let Some(first) = art.proof_paths.artifact_proof.first_mut() {
            *first = Blake3Hash::digest(b"corrupted-proof");
        }
        assert!(!verify_certification_artifact(&art));
    }

    #[test]
    fn tampered_root_fails_verification() {
        let (a, c, i) = sample_hashes();
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        art.composed_root = Blake3Hash::digest(b"wrong-root");
        assert!(!verify_certification_artifact(&art));
    }

    // ---- 12. Single vs multi artifact batches (2 tests) ----

    #[test]
    fn single_artifact_batch() {
        let (a, c, i) = sample_hashes();
        let arts = vec![compose_certification_artifact("/bin/app", a, c, i, "prod")];
        assert_eq!(arts.len(), 1);
        assert!(verify_certification_artifact(&arts[0]));
    }

    #[test]
    fn multi_artifact_batch_independent() {
        let arts: Vec<CertificationArtifact> = (0..10)
            .map(|idx| {
                let a = Blake3Hash::digest(format!("artifact-{idx}").as_bytes());
                let c = Blake3Hash::digest(format!("control-{idx}").as_bytes());
                let i = Blake3Hash::digest(format!("intent-{idx}").as_bytes());
                compose_certification_artifact(
                    &format!("/bin/app-{idx}"),
                    a,
                    c,
                    i,
                    "prod",
                )
            })
            .collect();
        assert_eq!(arts.len(), 10);
        for art in &arts {
            assert!(verify_certification_artifact(art));
        }
        // All roots should be distinct
        let roots: std::collections::HashSet<_> =
            arts.iter().map(|a| a.composed_root.to_hex()).collect();
        assert_eq!(roots.len(), 10);
    }

    // ---- 13. Backward compat: old MasterSignature JSON deserializes (2 tests) ----

    #[test]
    fn backward_compat_old_master_signature_no_artifacts() {
        use crate::signature::MasterSignature;

        let old_json = serde_json::json!({
            "untested": "a" .repeat(64),
            "layers": [],
            "computed_at": "2026-01-01T00:00:00Z",
            "environment": "legacy"
        });
        let master: MasterSignature = serde_json::from_value(old_json).unwrap();
        assert!(master.certification_artifacts.is_empty());
        assert_eq!(master.environment, "legacy");
    }

    #[test]
    fn backward_compat_old_master_with_empty_artifacts() {
        use crate::signature::MasterSignature;

        let old_json = serde_json::json!({
            "untested": "b".repeat(64),
            "layers": [],
            "computed_at": "2026-01-01T00:00:00Z",
            "environment": "staging",
            "certification_artifacts": []
        });
        let master: MasterSignature = serde_json::from_value(old_json).unwrap();
        assert!(master.certification_artifacts.is_empty());
    }

    // ---- 14. Idempotency property (1 test) ----

    #[test]
    fn idempotency_verify_after_compose() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        // Verify multiple times; all must succeed
        for _ in 0..10 {
            assert!(verify_certification_artifact(&art));
        }
    }

    // ---- 15. Large batch no-panic (1 test) ----

    #[test]
    fn large_batch_no_panic() {
        let arts: Vec<CertificationArtifact> = (0..500)
            .map(|idx| {
                compose_certification_artifact(
                    &format!("/bin/svc-{idx}"),
                    Blake3Hash::digest(format!("a-{idx}").as_bytes()),
                    Blake3Hash::digest(format!("c-{idx}").as_bytes()),
                    Blake3Hash::digest(format!("i-{idx}").as_bytes()),
                    "prod",
                )
            })
            .collect();
        assert_eq!(arts.len(), 500);
        // Spot-check a few
        for idx in [0, 1, 249, 499] {
            assert!(verify_certification_artifact(&arts[idx]));
        }
    }

    // ---- 16. Verify returns false on wrong root (1 test) ----

    #[test]
    fn verify_returns_false_on_wrong_root() {
        let (a, c, i) = sample_hashes();
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        // Set root to a valid but wrong hash
        art.composed_root = Blake3Hash::digest(b"completely-different-root");
        assert!(!verify_certification_artifact(&art));
    }

    // ---- 17. ArtifactProofPaths individual proof verification (3 tests) ----

    #[test]
    fn artifact_proof_path_verifies_independently() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a.clone(), c, i, "prod");
        assert!(verify_single_proof(
            &art.proof_paths.artifact_proof,
            &art.composed_root,
            &a,
            0,
            3,
        ));
    }

    #[test]
    fn control_proof_path_verifies_independently() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c.clone(), i, "prod");
        assert!(verify_single_proof(
            &art.proof_paths.control_proof,
            &art.composed_root,
            &c,
            1,
            3,
        ));
    }

    #[test]
    fn intent_proof_path_verifies_independently() {
        let (a, c, i) = sample_hashes();
        let art = compose_certification_artifact("/bin/app", a, c, i.clone(), "prod");
        assert!(verify_single_proof(
            &art.proof_paths.intent_proof,
            &art.composed_root,
            &i,
            2,
            3,
        ));
    }
}
