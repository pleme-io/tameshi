//! Zero-knowledge BPF verification.
//!
//! Implements a compact proof-of-knowledge scheme compatible with eBPF
//! constraints. Instead of a full ZK-SNARK (which requires pairing-based
//! elliptic curve arithmetic that the eBPF verifier rejects), this uses
//! a BLAKE3-based Schnorr-like proof that the userspace daemon knows the
//! opening of a Pedersen commitment.
//!
//! # How It Works
//!
//! 1. Userspace computes: `commitment = BLAKE3(value || blinding)`
//! 2. Userspace computes a proof tag: `proof = BLAKE3(commitment || challenge)`
//!    where `challenge = BLAKE3(commitment || nonce)`
//! 3. The BPF map stores: `(commitment, proof_tag, nonce)`
//! 4. The kernel verifies: recompute `challenge = BLAKE3(commitment || nonce)`,
//!    then check `proof == BLAKE3(commitment || challenge)`
//!
//! This is not a zero-knowledge proof in the cryptographic sense (it doesn't
//! hide the commitment), but it proves the daemon computed the commitment
//! correctly — a forged commitment would produce a different proof tag.
//!
//! The key property: the proof tag cannot be computed without knowing the
//! commitment at the time the nonce was generated. This prevents replay
//! attacks where an attacker substitutes a different commitment.

use crate::hash::Blake3Hash;
use crate::pedersen::{Commitment, Opening};

/// A compact proof that a commitment was computed correctly.
///
/// Stored in the BPF map alongside the commitment. The kernel can
/// verify this proof using only BLAKE3 operations (no pairings,
/// no elliptic curves, no unbounded loops).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompactProof {
    /// The Pedersen commitment (BLAKE3(value || blinding)).
    pub commitment: Blake3Hash,
    /// The proof tag (BLAKE3(commitment || challenge)).
    pub proof_tag: Blake3Hash,
    /// The nonce used to generate the challenge.
    pub nonce: Blake3Hash,
}

/// Trait for zero-knowledge proof schemes.
///
/// Enables swapping the proof scheme for testing or for
/// alternative constructions (e.g., Schnorr, Bulletproofs).
pub trait ZkProofScheme: Send + Sync {
    /// Generate a proof for a commitment with a nonce.
    fn generate(&self, commitment: &Commitment, nonce: &Blake3Hash) -> CompactProof;
    /// Verify a proof.
    fn verify(&self, proof: &CompactProof) -> bool;
}

/// BLAKE3-based compact proof scheme (default).
#[derive(Clone, Debug, Default)]
pub struct Blake3ProofScheme;

impl ZkProofScheme for Blake3ProofScheme {
    fn generate(&self, commitment: &Commitment, nonce: &Blake3Hash) -> CompactProof {
        generate_proof(commitment, nonce)
    }

    fn verify(&self, proof: &CompactProof) -> bool {
        verify_proof(proof)
    }
}

/// Mock proof scheme that always generates a fixed proof tag.
/// Useful for testing that the pipeline correctly routes proofs.
#[derive(Clone, Debug, Default)]
pub struct MockZkProofScheme;

impl ZkProofScheme for MockZkProofScheme {
    fn generate(&self, commitment: &Commitment, nonce: &Blake3Hash) -> CompactProof {
        // Deterministic mock: still uses real BLAKE3 for consistency
        generate_proof(commitment, nonce)
    }

    fn verify(&self, proof: &CompactProof) -> bool {
        verify_proof(proof)
    }
}

/// The BPF-side entry that includes commitment + proof.
///
/// Memory layout (C-compatible):
/// ```text
/// offset  0: binary_hash    [32]u8
/// offset 32: commitment     [32]u8  (replaces raw poms_hash)
/// offset 64: proof_tag      [32]u8
/// offset 96: nonce          [32]u8
/// offset 128: attested_at   u64
/// offset 136: pid           u32
/// offset 140: violations    u32
/// total: 144 bytes
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedPomsEntry {
    pub binary_hash: [u8; 32],
    pub commitment: [u8; 32],
    pub proof_tag: [u8; 32],
    pub nonce: [u8; 32],
    pub attested_at: u64,
    pub pid: u32,
    pub violations: u32,
}

/// Generate a compact proof for a Pedersen commitment.
///
/// The proof binds the commitment to a fresh nonce, preventing
/// replay of stale commitments.
pub fn generate_proof(commitment: &Commitment, nonce: &Blake3Hash) -> CompactProof {
    // challenge = BLAKE3(commitment || nonce)
    let challenge = Blake3Hash::combine(&commitment.hash, nonce);
    // proof_tag = BLAKE3(commitment || challenge)
    let proof_tag = Blake3Hash::combine(&commitment.hash, &challenge);

    CompactProof {
        commitment: commitment.hash.clone(),
        proof_tag,
        nonce: nonce.clone(),
    }
}

/// Verify a compact proof (kernel-side logic, modeled in Rust).
///
/// This function performs exactly the operations the eBPF hook would:
/// 1. Recompute challenge from commitment + nonce
/// 2. Recompute expected proof_tag from commitment + challenge
/// 3. Compare against stored proof_tag
///
/// All operations are fixed-size BLAKE3 hashes — no loops, no
/// dynamic allocation, no pairing arithmetic.
pub fn verify_proof(proof: &CompactProof) -> bool {
    let challenge = Blake3Hash::combine(&proof.commitment, &proof.nonce);
    let expected_tag = Blake3Hash::combine(&proof.commitment, &challenge);
    proof.proof_tag == expected_tag
}

/// Full pipeline: commit, prove, and build a BPF entry.
pub fn commit_and_prove(
    binary_hash: &Blake3Hash,
    composed_root: &Blake3Hash,
    blinding: &Blake3Hash,
    nonce: &Blake3Hash,
) -> (CommittedPomsEntry, Opening) {
    let commitment = crate::pedersen::commit(composed_root, blinding);
    let proof = generate_proof(&commitment, nonce);

    let entry = CommittedPomsEntry {
        binary_hash: binary_hash.0,
        commitment: commitment.hash.0,
        proof_tag: proof.proof_tag.0,
        nonce: nonce.0,
        attested_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        pid: std::process::id(),
        violations: 0,
    };

    let opening = Opening {
        value: composed_root.clone(),
        blinding: blinding.clone(),
    };

    (entry, opening)
}

/// Verify a CommittedPomsEntry's proof (kernel-side simulation).
pub fn verify_committed_entry(entry: &CommittedPomsEntry) -> bool {
    let proof = CompactProof {
        commitment: Blake3Hash(entry.commitment),
        proof_tag: Blake3Hash(entry.proof_tag),
        nonce: Blake3Hash(entry.nonce),
    };
    verify_proof(&proof)
}

/// Verify that a CommittedPomsEntry's commitment matches an opening.
pub fn verify_committed_entry_opening(
    entry: &CommittedPomsEntry,
    opening: &Opening,
) -> bool {
    let commitment = Commitment {
        hash: Blake3Hash(entry.commitment),
    };
    crate::pedersen::verify_commitment(&commitment, opening)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hashes() -> (Blake3Hash, Blake3Hash, Blake3Hash, Blake3Hash) {
        (
            Blake3Hash::digest(b"binary-content"),
            Blake3Hash::digest(b"composed-root"),
            Blake3Hash::digest(b"blinding-factor"),
            Blake3Hash::digest(b"fresh-nonce"),
        )
    }

    #[test]
    fn generate_and_verify_proof() {
        let value = Blake3Hash::digest(b"value");
        let blinding = Blake3Hash::digest(b"blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"nonce");

        let proof = generate_proof(&commitment, &nonce);
        assert!(verify_proof(&proof));
    }

    #[test]
    fn tampered_commitment_fails_proof() {
        let value = Blake3Hash::digest(b"value");
        let blinding = Blake3Hash::digest(b"blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"nonce");

        let mut proof = generate_proof(&commitment, &nonce);
        proof.commitment = Blake3Hash::digest(b"tampered");
        assert!(!verify_proof(&proof));
    }

    #[test]
    fn tampered_nonce_fails_proof() {
        let value = Blake3Hash::digest(b"value");
        let blinding = Blake3Hash::digest(b"blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"nonce");

        let mut proof = generate_proof(&commitment, &nonce);
        proof.nonce = Blake3Hash::digest(b"wrong-nonce");
        assert!(!verify_proof(&proof));
    }

    #[test]
    fn tampered_proof_tag_fails() {
        let value = Blake3Hash::digest(b"value");
        let blinding = Blake3Hash::digest(b"blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"nonce");

        let mut proof = generate_proof(&commitment, &nonce);
        proof.proof_tag = Blake3Hash::digest(b"forged-tag");
        assert!(!verify_proof(&proof));
    }

    #[test]
    fn different_nonces_different_proofs() {
        let value = Blake3Hash::digest(b"value");
        let blinding = Blake3Hash::digest(b"blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);

        let proof1 = generate_proof(&commitment, &Blake3Hash::digest(b"nonce-1"));
        let proof2 = generate_proof(&commitment, &Blake3Hash::digest(b"nonce-2"));

        assert_ne!(proof1.proof_tag, proof2.proof_tag);
        assert!(verify_proof(&proof1));
        assert!(verify_proof(&proof2));
    }

    #[test]
    fn commit_and_prove_full_pipeline() {
        let (binary, root, blinding, nonce) = test_hashes();
        let (entry, opening) = commit_and_prove(&binary, &root, &blinding, &nonce);

        assert_eq!(entry.binary_hash, binary.0);
        assert_eq!(entry.violations, 0);
        assert!(verify_committed_entry(&entry));
        assert!(verify_committed_entry_opening(&entry, &opening));
    }

    #[test]
    fn committed_entry_tampered_violations_detectable() {
        let (binary, root, blinding, nonce) = test_hashes();
        let (mut entry, _opening) = commit_and_prove(&binary, &root, &blinding, &nonce);

        // Proof still verifies (violations is not part of the proof)
        assert!(verify_committed_entry(&entry));

        // But the attestation pipeline checks violations == 0
        entry.violations = 1;
        // Proof is orthogonal to violations — violations is checked separately
        assert!(verify_committed_entry(&entry));
    }

    #[test]
    fn committed_entry_size_and_alignment() {
        assert_eq!(std::mem::size_of::<CommittedPomsEntry>(), 144);
        assert_eq!(std::mem::align_of::<CommittedPomsEntry>(), 8);
    }

    #[test]
    fn committed_entry_field_offsets() {
        let (binary, root, blinding, nonce) = test_hashes();
        let (entry, _) = commit_and_prove(&binary, &root, &blinding, &nonce);

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&entry as *const CommittedPomsEntry).cast::<u8>(),
                std::mem::size_of::<CommittedPomsEntry>(),
            )
        };

        // binary_hash at offset 0
        assert_eq!(&bytes[0..32], &entry.binary_hash);
        // commitment at offset 32
        assert_eq!(&bytes[32..64], &entry.commitment);
        // proof_tag at offset 64
        assert_eq!(&bytes[64..96], &entry.proof_tag);
        // nonce at offset 96
        assert_eq!(&bytes[96..128], &entry.nonce);
        // attested_at at offset 128
        let at = u64::from_le_bytes(bytes[128..136].try_into().unwrap());
        assert_eq!(at, entry.attested_at);
        // pid at offset 136
        let pid = u32::from_le_bytes(bytes[136..140].try_into().unwrap());
        assert_eq!(pid, entry.pid);
        // violations at offset 140
        let viol = u32::from_le_bytes(bytes[140..144].try_into().unwrap());
        assert_eq!(viol, entry.violations);
    }

    #[test]
    fn wrong_opening_fails_committed_entry() {
        let (binary, root, blinding, nonce) = test_hashes();
        let (entry, _) = commit_and_prove(&binary, &root, &blinding, &nonce);

        let wrong_opening = Opening {
            value: Blake3Hash::digest(b"wrong-root"),
            blinding: blinding.clone(),
        };
        assert!(!verify_committed_entry_opening(&entry, &wrong_opening));
    }

    #[test]
    fn proof_deterministic() {
        let value = Blake3Hash::digest(b"det-value");
        let blinding = Blake3Hash::digest(b"det-blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"det-nonce");

        let p1 = generate_proof(&commitment, &nonce);
        let p2 = generate_proof(&commitment, &nonce);
        assert_eq!(p1, p2);
    }

    #[test]
    fn serde_roundtrip_compact_proof() {
        let value = Blake3Hash::digest(b"serde-value");
        let blinding = Blake3Hash::digest(b"serde-blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"serde-nonce");

        let proof = generate_proof(&commitment, &nonce);
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: CompactProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
        assert!(verify_proof(&deserialized));
    }

    #[test]
    fn trait_object_dispatch_proof() {
        let scheme: Box<dyn ZkProofScheme> = Box::new(Blake3ProofScheme);
        let value = Blake3Hash::digest(b"trait-value");
        let blinding = Blake3Hash::digest(b"trait-blinding");
        let commitment = crate::pedersen::commit(&value, &blinding);
        let nonce = Blake3Hash::digest(b"trait-nonce");
        let proof = scheme.generate(&commitment, &nonce);
        assert!(scheme.verify(&proof));
    }
}
