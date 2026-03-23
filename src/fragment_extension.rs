//! Fragment extension — binding the Merkle root as a DFC fragment.
//!
//! Makes the F* theorem from `fstar/Tameshi.FragmentedSovereignty.fst` executable
//! in Rust. The standard DFC reconstruction is `key = BLAKE3(F_a XOR F_b)`. The
//! extended reconstruction adds the composed Merkle root as a third fragment:
//!
//! ```text
//! key = BLAKE3(F_a XOR F_b XOR composed_root)
//! ```
//!
//! This binds the signing key to the specific attestation artifact. A key
//! reconstructed with a different root produces a different signature — even if
//! the DFC fragments are correct. No single entity holds enough information to
//! forge an attestation.
//!
//! # Security Properties (proved in F*)
//!
//! 1. **Root-binding** — different roots produce different keys
//!    (`lemma_root_binds_key`)
//! 2. **Split-knowledge** — different fragments still produce different keys
//!    (`lemma_fragments_still_independent`)
//! 3. **Tamper-detection** — wrong root fails verification
//!    (`lemma_wrong_root_fails_verify`)
//! 4. **Selective disclosure** — inclusion proofs are independent of signing
//!    (`lemma_selective_disclosure_composable`)

use crate::hash::Blake3Hash;

/// Trait for extended DFC signing operations.
///
/// Enables swapping the key reconstruction and signing strategy
/// for testing or alternative fragment schemes.
pub trait ExtendedSigner: Send + Sync {
    /// Reconstruct a signing key from fragments plus a Merkle root.
    fn reconstruct_key(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash) -> [u8; 32];
    /// Sign data using extended key reconstruction.
    fn sign(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash, data: &Blake3Hash) -> Vec<u8>;
    /// Verify a signature using extended key reconstruction.
    fn verify(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash, data: &Blake3Hash, signature: &[u8]) -> bool;
}

/// BLAKE3-based extended signer (default).
#[derive(Clone, Debug, Default)]
pub struct Blake3ExtendedSigner;

impl ExtendedSigner for Blake3ExtendedSigner {
    fn reconstruct_key(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash) -> [u8; 32] {
        reconstruct_key_extended(frag_a, frag_b, root)
    }

    fn sign(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash, data: &Blake3Hash) -> Vec<u8> {
        sign_extended(frag_a, frag_b, root, data)
    }

    fn verify(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash, data: &Blake3Hash, signature: &[u8]) -> bool {
        verify_extended(frag_a, frag_b, root, data, signature)
    }
}

/// Mock extended signer for testing.
/// Uses the same BLAKE3 implementation but provides a trait boundary
/// so consumers can inject alternatives.
#[derive(Clone, Debug, Default)]
pub struct MockExtendedSigner;

impl ExtendedSigner for MockExtendedSigner {
    fn reconstruct_key(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash) -> [u8; 32] {
        reconstruct_key_extended(frag_a, frag_b, root)
    }

    fn sign(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash, data: &Blake3Hash) -> Vec<u8> {
        sign_extended(frag_a, frag_b, root, data)
    }

    fn verify(&self, frag_a: &[u8; 32], frag_b: &[u8; 32], root: &Blake3Hash, data: &Blake3Hash, signature: &[u8]) -> bool {
        verify_extended(frag_a, frag_b, root, data, signature)
    }
}

/// Reconstruct a signing key from two DFC fragments plus the Merkle root.
///
/// This is the "extended" reconstruction that binds the key to the artifact.
/// Standard DFC: `key = BLAKE3(F_a XOR F_b)`.
/// Extended DFC: `key = BLAKE3(F_a XOR F_b XOR root)`.
///
/// # Arguments
///
/// * `frag_a` — First DFC key fragment (32 bytes).
/// * `frag_b` — Second DFC key fragment (32 bytes).
/// * `root` — Composed Merkle root from a [`CertificationArtifact`](crate::certification_artifact::CertificationArtifact).
///
/// # Returns
///
/// A 32-byte signing key derived from all three inputs.
#[inline]
#[must_use]
pub fn reconstruct_key_extended(
    frag_a: &[u8; 32],
    frag_b: &[u8; 32],
    root: &Blake3Hash,
) -> [u8; 32] {
    let mut xored = [0u8; 32];
    // Step 1: XOR frag_a and frag_b
    for i in 0..32 {
        xored[i] = frag_a[i] ^ frag_b[i];
    }
    // Step 2: XOR with the composed root
    for i in 0..32 {
        xored[i] ^= root.0[i];
    }
    // Step 3: BLAKE3 hash the final XOR result to derive the key
    *blake3::hash(&xored).as_bytes()
}

/// Sign data using the extended DFC scheme.
///
/// Reconstructs the signing key from both fragments and the Merkle root,
/// then produces a BLAKE3 keyed hash of the data.
///
/// # Arguments
///
/// * `frag_a` — First DFC key fragment (32 bytes).
/// * `frag_b` — Second DFC key fragment (32 bytes).
/// * `root` — Composed Merkle root binding the key to the attestation.
/// * `data` — The hash to sign (typically a [`Blake3Hash`] of the payload).
///
/// # Returns
///
/// Signature bytes (32 bytes as a `Vec<u8>`).
#[must_use]
pub fn sign_extended(
    frag_a: &[u8; 32],
    frag_b: &[u8; 32],
    root: &Blake3Hash,
    data: &Blake3Hash,
) -> Vec<u8> {
    let key = reconstruct_key_extended(frag_a, frag_b, root);
    blake3::keyed_hash(&key, &data.0).as_bytes().to_vec()
}

/// Verify a signature produced by [`sign_extended`].
///
/// Reconstructs the key from the same fragments and root, recomputes the
/// signature, and compares it to the provided signature bytes.
///
/// # Arguments
///
/// * `frag_a` — First DFC key fragment (32 bytes).
/// * `frag_b` — Second DFC key fragment (32 bytes).
/// * `root` — Composed Merkle root used during signing.
/// * `data` — The hash that was signed.
/// * `signature` — The signature bytes to verify.
///
/// # Returns
///
/// `true` if the signature matches, `false` otherwise.
#[must_use]
pub fn verify_extended(
    frag_a: &[u8; 32],
    frag_b: &[u8; 32],
    root: &Blake3Hash,
    data: &Blake3Hash,
    signature: &[u8],
) -> bool {
    let expected = sign_extended(frag_a, frag_b, root, data);
    expected == signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::{compose_certification_artifact, verify_certification_artifact};

    /// Helper: generate distinct 32-byte fragments from a seed.
    fn make_fragment(seed: u8) -> [u8; 32] {
        let mut frag = [0u8; 32];
        for (i, byte) in frag.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        frag
    }

    /// Witnesses F* `lemma_root_binds_key`:
    /// Different roots produce different extended keys.
    #[test]
    fn witness_root_binds_key() {
        let frag_a = make_fragment(0x10);
        let frag_b = make_fragment(0x20);
        let root1 = Blake3Hash::digest(b"root-one");
        let root2 = Blake3Hash::digest(b"root-two");

        let key1 = reconstruct_key_extended(&frag_a, &frag_b, &root1);
        let key2 = reconstruct_key_extended(&frag_a, &frag_b, &root2);

        assert_ne!(key1, key2, "different roots must produce different keys");
    }

    /// Witnesses F* `lemma_fragments_still_independent`:
    /// Different frag_a with same frag_b and root produce different keys.
    #[test]
    fn witness_fragments_still_independent() {
        let frag_a1 = make_fragment(0x10);
        let frag_a2 = make_fragment(0x30);
        let frag_b = make_fragment(0x20);
        let root = Blake3Hash::digest(b"shared-root");

        let key1 = reconstruct_key_extended(&frag_a1, &frag_b, &root);
        let key2 = reconstruct_key_extended(&frag_a2, &frag_b, &root);

        assert_ne!(
            key1, key2,
            "different frag_a must produce different keys (split-knowledge preserved)"
        );
    }

    /// Witnesses F* `lemma_wrong_root_fails_verify`:
    /// Sign with root1, verify with root2 fails.
    #[test]
    fn witness_wrong_root_fails_verify() {
        let frag_a = make_fragment(0x10);
        let frag_b = make_fragment(0x20);
        let root_correct = Blake3Hash::digest(b"correct-root");
        let root_tampered = Blake3Hash::digest(b"tampered-root");
        let data = Blake3Hash::digest(b"payload-data");

        let signature = sign_extended(&frag_a, &frag_b, &root_correct, &data);
        let valid = verify_extended(&frag_a, &frag_b, &root_tampered, &data, &signature);

        assert!(
            !valid,
            "verification must fail when root differs from signing root"
        );
    }

    /// Witnesses F* `lemma_selective_disclosure_composable`:
    /// Compose an artifact, use its root for signing, verify the artifact
    /// independently of the signing scheme.
    #[test]
    fn witness_selective_disclosure_composable() {
        let artifact_hash = Blake3Hash::digest(b"nix-closure-hash");
        let control_hash = Blake3Hash::digest(b"kensa-assessment");
        let intent_hash = Blake3Hash::digest(b"pangea-synthesis");

        let artifact = compose_certification_artifact(
            "/usr/bin/myapp",
            artifact_hash,
            control_hash,
            intent_hash,
            "production",
        );

        // The artifact's composed_root is used as the DFC fragment extension
        let frag_a = make_fragment(0x10);
        let frag_b = make_fragment(0x20);
        let data = Blake3Hash::digest(b"deploy-manifest");

        let signature = sign_extended(&frag_a, &frag_b, &artifact.composed_root, &data);
        let valid = verify_extended(&frag_a, &frag_b, &artifact.composed_root, &data, &signature);

        assert!(valid, "signature must verify with the artifact root");

        // The artifact can be independently verified — selective disclosure
        // operates independently of the signing key derivation
        assert!(
            verify_certification_artifact(&artifact),
            "artifact verification must work independently of DFC signing"
        );
    }

    /// Witnesses correct roundtrip: sign and verify with same fragments and root.
    #[test]
    fn witness_correct_roundtrip() {
        let frag_a = make_fragment(0xAA);
        let frag_b = make_fragment(0xBB);
        let root = Blake3Hash::digest(b"roundtrip-root");
        let data = Blake3Hash::digest(b"roundtrip-data");

        let signature = sign_extended(&frag_a, &frag_b, &root, &data);
        let valid = verify_extended(&frag_a, &frag_b, &root, &data, &signature);

        assert!(valid, "sign then verify with identical inputs must succeed");
    }

    /// Witnesses wrong fragment_a failure: sign with frag_a1, verify with frag_a2.
    #[test]
    fn witness_wrong_fragment_a_fails() {
        let frag_a1 = make_fragment(0x10);
        let frag_a2 = make_fragment(0x30);
        let frag_b = make_fragment(0x20);
        let root = Blake3Hash::digest(b"fragment-test-root");
        let data = Blake3Hash::digest(b"fragment-test-data");

        let signature = sign_extended(&frag_a1, &frag_b, &root, &data);
        let valid = verify_extended(&frag_a2, &frag_b, &root, &data, &signature);

        assert!(
            !valid,
            "verification must fail when frag_a differs from signing frag_a"
        );
    }

    /// Witnesses determinism: same inputs always produce same signature.
    #[test]
    fn witness_deterministic() {
        let frag_a = make_fragment(0x42);
        let frag_b = make_fragment(0x84);
        let root = Blake3Hash::digest(b"determinism-root");
        let data = Blake3Hash::digest(b"determinism-data");

        let sig1 = sign_extended(&frag_a, &frag_b, &root, &data);
        let sig2 = sign_extended(&frag_a, &frag_b, &root, &data);

        assert_eq!(sig1, sig2, "identical inputs must produce identical signatures");
    }

    #[test]
    fn trait_object_dispatch_extended_signer() {
        let signer: Box<dyn ExtendedSigner> = Box::new(Blake3ExtendedSigner);
        let frag_a = [1u8; 32];
        let frag_b = [2u8; 32];
        let root = Blake3Hash::digest(b"trait-root");
        let data = Blake3Hash::digest(b"trait-data");
        let sig = signer.sign(&frag_a, &frag_b, &root, &data);
        assert!(signer.verify(&frag_a, &frag_b, &root, &data, &sig));
    }

    #[test]
    fn mock_extended_signer_roundtrip() {
        let signer = MockExtendedSigner;
        let frag_a = [0xAA; 32];
        let frag_b = [0xBB; 32];
        let root = Blake3Hash::digest(b"mock-root");
        let data = Blake3Hash::digest(b"mock-data");
        let sig = signer.sign(&frag_a, &frag_b, &root, &data);
        assert!(signer.verify(&frag_a, &frag_b, &root, &data, &sig));
    }
}
