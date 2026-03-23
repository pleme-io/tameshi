//! SMT-backed certification for key-value attestation.
//!
//! Extends the certification pipeline with a Sparse Merkle Tree that
//! supports arbitrary key-value attestation and non-inclusion proofs.
//! This complements the standard 3-leaf balanced tree used in
//! CertificationArtifact.

use crate::hash::Blake3Hash;
use crate::sparse_merkle::{SmtProof, SparseMerkleTree};

/// An SMT-backed attestation store.
/// Maps binary paths (hashed) to their composed roots.
#[derive(Clone, Debug)]
pub struct SmtAttestationStore {
    tree: SparseMerkleTree,
}

/// Result of an SMT attestation query.
#[derive(Clone, Debug)]
pub struct SmtAttestationResult {
    /// The binary path that was queried.
    pub binary_path_hash: Blake3Hash,
    /// The composed root (None if not attested).
    pub composed_root: Option<Blake3Hash>,
    /// The SMT proof (inclusion or non-inclusion).
    pub proof: SmtProof,
    /// The global SMT root at query time.
    pub smt_root: Blake3Hash,
}

impl SmtAttestationStore {
    /// Create a new empty store with the given tree depth.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self {
            tree: SparseMerkleTree::new(depth),
        }
    }

    /// Attest a binary: insert its composed root into the SMT.
    pub fn attest(&mut self, binary_path: &str, composed_root: Blake3Hash) {
        let key = Blake3Hash::digest(binary_path.as_bytes());
        self.tree.insert(key, composed_root);
    }

    /// Revoke a binary's attestation.
    pub fn revoke(&mut self, binary_path: &str) -> Option<Blake3Hash> {
        let key = Blake3Hash::digest(binary_path.as_bytes());
        self.tree.remove(&key)
    }

    /// Query a binary's attestation status with proof.
    #[must_use]
    pub fn query(&self, binary_path: &str) -> SmtAttestationResult {
        let key = Blake3Hash::digest(binary_path.as_bytes());
        let composed_root = self.tree.get(&key).cloned();
        let proof = self.tree.prove(&key);
        let smt_root = self.tree.root();
        SmtAttestationResult {
            binary_path_hash: key,
            composed_root,
            proof,
            smt_root,
        }
    }

    /// Verify an attestation result against a known root.
    #[must_use]
    pub fn verify(result: &SmtAttestationResult, expected_root: &Blake3Hash) -> bool {
        SparseMerkleTree::verify_proof(&result.proof, expected_root, result.proof.siblings.len())
    }

    /// Get the current SMT root.
    #[must_use]
    pub fn root(&self) -> Blake3Hash {
        self.tree.root()
    }

    /// Number of attested binaries.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tree.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attest_and_query_inclusion() {
        let mut store = SmtAttestationStore::new(16);
        let composed_root = Blake3Hash::digest(b"composed-root-for-myapp");
        store.attest("/usr/bin/myapp", composed_root.clone());

        let result = store.query("/usr/bin/myapp");
        assert_eq!(result.composed_root, Some(composed_root));
        assert!(
            SmtAttestationStore::verify(&result, &result.smt_root),
            "inclusion proof must verify against the current SMT root"
        );
    }

    #[test]
    fn query_non_attested_non_inclusion() {
        let mut store = SmtAttestationStore::new(16);
        // Insert one binary so the tree is not empty.
        store.attest("/usr/bin/other", Blake3Hash::digest(b"other-root"));

        let result = store.query("/usr/bin/absent");
        assert!(
            result.composed_root.is_none(),
            "absent binary should have no composed root"
        );
        assert!(
            SmtAttestationStore::verify(&result, &result.smt_root),
            "non-inclusion proof must verify against the current SMT root"
        );
    }

    #[test]
    fn revoke_then_non_inclusion() {
        let mut store = SmtAttestationStore::new(16);
        let composed_root = Blake3Hash::digest(b"revocable-root");
        store.attest("/usr/bin/revocable", composed_root);

        // Verify it's attested first.
        let before = store.query("/usr/bin/revocable");
        assert!(before.composed_root.is_some());

        // Revoke.
        let removed = store.revoke("/usr/bin/revocable");
        assert!(removed.is_some());

        // Now query should return non-inclusion.
        let after = store.query("/usr/bin/revocable");
        assert!(
            after.composed_root.is_none(),
            "revoked binary should have no composed root"
        );
        assert!(
            SmtAttestationStore::verify(&after, &after.smt_root),
            "non-inclusion proof after revocation must verify"
        );
    }

    #[test]
    fn different_binaries_different_roots() {
        let mut store_a = SmtAttestationStore::new(16);
        let mut store_b = SmtAttestationStore::new(16);

        let root = Blake3Hash::digest(b"same-composed-root");
        store_a.attest("/usr/bin/alpha", root.clone());
        store_b.attest("/usr/bin/beta", root);

        assert_ne!(
            store_a.root(),
            store_b.root(),
            "attesting different binaries with same root must produce different SMT roots"
        );
    }

    #[test]
    fn smt_root_deterministic() {
        let mut store1 = SmtAttestationStore::new(16);
        let mut store2 = SmtAttestationStore::new(16);

        let root_a = Blake3Hash::digest(b"root-a");
        let root_b = Blake3Hash::digest(b"root-b");

        store1.attest("/usr/bin/app1", root_a.clone());
        store1.attest("/usr/bin/app2", root_b.clone());

        store2.attest("/usr/bin/app1", root_a);
        store2.attest("/usr/bin/app2", root_b);

        assert_eq!(
            store1.root(),
            store2.root(),
            "same attestations must produce the same SMT root"
        );
    }

    #[test]
    fn verify_against_wrong_root_fails() {
        let mut store = SmtAttestationStore::new(16);
        store.attest("/usr/bin/myapp", Blake3Hash::digest(b"legit-root"));

        let result = store.query("/usr/bin/myapp");
        let wrong_root = Blake3Hash::digest(b"wrong-root");

        assert!(
            !SmtAttestationStore::verify(&result, &wrong_root),
            "proof must not verify against a different root"
        );
    }

    #[test]
    fn multiple_attestations() {
        let mut store = SmtAttestationStore::new(16);

        for i in 0..10 {
            let path = format!("/usr/bin/app{i}");
            let root = Blake3Hash::digest(format!("root-{i}").as_bytes());
            store.attest(&path, root);
        }

        assert_eq!(store.count(), 10);

        let smt_root = store.root();
        for i in 0..10 {
            let path = format!("/usr/bin/app{i}");
            let expected_root = Blake3Hash::digest(format!("root-{i}").as_bytes());
            let result = store.query(&path);
            assert_eq!(
                result.composed_root,
                Some(expected_root),
                "binary app{i} should have the correct composed root"
            );
            assert!(
                SmtAttestationStore::verify(&result, &smt_root),
                "inclusion proof for app{i} must verify"
            );
        }
    }

    #[test]
    fn revocation_proof_serves_as_evidence() {
        let mut store = SmtAttestationStore::new(16);
        store.attest("/usr/bin/compromised", Blake3Hash::digest(b"old-root"));

        // Revoke the compromised binary.
        store.revoke("/usr/bin/compromised");

        // Generate a non-inclusion proof as evidence of revocation.
        let evidence = store.query("/usr/bin/compromised");
        assert!(
            evidence.composed_root.is_none(),
            "revoked binary must not be attested"
        );

        let smt_root = store.root();
        assert!(
            SmtAttestationStore::verify(&evidence, &smt_root),
            "non-inclusion proof after revocation must verify as evidence"
        );
    }
}
