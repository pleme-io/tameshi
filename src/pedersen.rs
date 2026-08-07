//! Pedersen-style commitments using BLAKE3.
//!
//! A commitment C = BLAKE3(value || blinding_factor) hides the value
//! while binding the committer: opening requires revealing both the
//! value and the blinding factor.

use crate::hash::Blake3Hash;

/// A Pedersen-style commitment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Commitment {
    pub hash: Blake3Hash,
}

/// An opening for a commitment (the value + blinding factor).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Opening {
    pub value: Blake3Hash,
    pub blinding: Blake3Hash,
}

/// Trait for commitment schemes.
///
/// Enables swapping the commitment algorithm for testing or
/// for alternative schemes (e.g., Pedersen over elliptic curves).
pub trait CommitmentScheme: Send + Sync {
    /// Create a commitment to a value with a blinding factor.
    fn commit(&self, value: &Blake3Hash, blinding: &Blake3Hash) -> Commitment;
    /// Verify that an opening matches a commitment.
    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool;
}

/// BLAKE3-based commitment scheme (default).
#[derive(Clone, Debug, Default)]
pub struct Blake3Commitment;

impl CommitmentScheme for Blake3Commitment {
    fn commit(&self, value: &Blake3Hash, blinding: &Blake3Hash) -> Commitment {
        let hash = Blake3Hash::combine(value, blinding);
        Commitment { hash }
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        let recomputed = Blake3Hash::combine(&opening.value, &opening.blinding);
        commitment.hash == recomputed
    }
}

/// Mock commitment scheme for testing.
///
/// Returns a deterministic commitment based on XOR of value and blinding,
/// making test assertions predictable.
#[derive(Clone, Debug, Default)]
pub struct MockCommitmentScheme;

impl CommitmentScheme for MockCommitmentScheme {
    fn commit(&self, value: &Blake3Hash, blinding: &Blake3Hash) -> Commitment {
        // Deterministic: just combine (same as real, but the trait boundary
        // allows injecting alternative schemes)
        let hash = Blake3Hash::combine(value, blinding);
        Commitment { hash }
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        self.commit(&opening.value, &opening.blinding).hash == commitment.hash
    }
}

/// Create a commitment to a value with a random blinding factor.
///
/// Delegates to [`Blake3Commitment`]. For custom schemes, use the
/// [`CommitmentScheme`] trait directly.
pub fn commit(value: &Blake3Hash, blinding: &Blake3Hash) -> Commitment {
    Blake3Commitment.commit(value, blinding)
}

/// Verify that an opening matches a commitment.
///
/// Delegates to [`Blake3Commitment`]. For custom schemes, use the
/// [`CommitmentScheme`] trait directly.
pub fn verify_commitment(commitment: &Commitment, opening: &Opening) -> bool {
    Blake3Commitment.verify(commitment, opening)
}

/// Create a commitment to a composed root for BPF map storage.
/// The blinding factor ensures the raw root is not exposed.
pub fn commit_for_bpf(composed_root: &Blake3Hash, blinding: &Blake3Hash) -> Commitment {
    commit(composed_root, blinding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_verify_roundtrip() {
        let value = Blake3Hash::digest(b"my-secret-value");
        let blinding = Blake3Hash::digest(b"random-blinding-factor");
        let commitment = commit(&value, &blinding);
        let opening = Opening {
            value: value.clone(),
            blinding: blinding.clone(),
        };
        assert!(verify_commitment(&commitment, &opening));
    }

    #[test]
    fn wrong_value_fails() {
        let value = Blake3Hash::digest(b"my-secret-value");
        let blinding = Blake3Hash::digest(b"random-blinding-factor");
        let commitment = commit(&value, &blinding);
        let wrong_opening = Opening {
            value: Blake3Hash::digest(b"wrong-value"),
            blinding: blinding.clone(),
        };
        assert!(!verify_commitment(&commitment, &wrong_opening));
    }

    #[test]
    fn wrong_blinding_fails() {
        let value = Blake3Hash::digest(b"my-secret-value");
        let blinding = Blake3Hash::digest(b"random-blinding-factor");
        let commitment = commit(&value, &blinding);
        let wrong_opening = Opening {
            value: value.clone(),
            blinding: Blake3Hash::digest(b"wrong-blinding"),
        };
        assert!(!verify_commitment(&commitment, &wrong_opening));
    }

    #[test]
    fn commitment_hides_value() {
        let value = Blake3Hash::digest(b"same-value");
        let blinding_1 = Blake3Hash::digest(b"blinding-one");
        let blinding_2 = Blake3Hash::digest(b"blinding-two");
        let c1 = commit(&value, &blinding_1);
        let c2 = commit(&value, &blinding_2);
        assert_ne!(
            c1, c2,
            "same value with different blindings must produce different commitments"
        );
    }

    #[test]
    fn commitment_binds_value() {
        let value_1 = Blake3Hash::digest(b"value-one");
        let value_2 = Blake3Hash::digest(b"value-two");
        let blinding = Blake3Hash::digest(b"same-blinding");
        let c1 = commit(&value_1, &blinding);
        let c2 = commit(&value_2, &blinding);
        assert_ne!(
            c1, c2,
            "different values with same blinding must produce different commitments"
        );
    }

    #[test]
    fn bpf_commitment_roundtrip() {
        let composed_root = Blake3Hash::digest(b"composed-root-data");
        let blinding = Blake3Hash::digest(b"bpf-blinding");
        let commitment = commit_for_bpf(&composed_root, &blinding);
        let opening = Opening {
            value: composed_root,
            blinding,
        };
        assert!(verify_commitment(&commitment, &opening));
    }

    #[test]
    fn serde_roundtrip() {
        let value = Blake3Hash::digest(b"serde-test-value");
        let blinding = Blake3Hash::digest(b"serde-test-blinding");
        let commitment = commit(&value, &blinding);
        let json = serde_json::to_string(&commitment).unwrap();
        let deserialized: Commitment = serde_json::from_str(&json).unwrap();
        assert_eq!(commitment, deserialized);
    }

    #[test]
    fn mock_commitment_scheme_roundtrip() {
        let scheme = MockCommitmentScheme;
        let value = Blake3Hash::digest(b"mock-test");
        let blinding = Blake3Hash::digest(b"mock-blinding");
        let commitment = scheme.commit(&value, &blinding);
        let opening = Opening { value, blinding };
        assert!(scheme.verify(&commitment, &opening));
    }

    #[test]
    fn trait_object_dispatch() {
        let scheme: Box<dyn CommitmentScheme> = Box::new(Blake3Commitment);
        let value = Blake3Hash::digest(b"dyn-test");
        let blinding = Blake3Hash::digest(b"dyn-blinding");
        let commitment = scheme.commit(&value, &blinding);
        let opening = Opening { value, blinding };
        assert!(scheme.verify(&commitment, &opening));
    }

    #[test]
    fn opening_serde_roundtrip() {
        let opening = Opening {
            value: Blake3Hash::digest(b"open-value"),
            blinding: Blake3Hash::digest(b"open-blinding"),
        };
        let json = serde_json::to_string(&opening).unwrap();
        let deserialized: Opening = serde_json::from_str(&json).unwrap();
        assert_eq!(opening.value, deserialized.value);
        assert_eq!(opening.blinding, deserialized.blinding);
    }

    #[test]
    fn commitment_deterministic() {
        let value = Blake3Hash::digest(b"deterministic-test");
        let blinding = Blake3Hash::digest(b"fixed-blinding");
        let c1 = commit(&value, &blinding);
        let c2 = commit(&value, &blinding);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_clone() {
        let value = Blake3Hash::digest(b"clone-test");
        let blinding = Blake3Hash::digest(b"clone-blinding");
        let commitment = commit(&value, &blinding);
        let cloned = commitment.clone();
        assert_eq!(commitment, cloned);
    }

    #[test]
    fn commit_for_bpf_same_as_commit() {
        let root = Blake3Hash::digest(b"composed-root");
        let blinding = Blake3Hash::digest(b"bpf-blinding");
        let c1 = commit(&root, &blinding);
        let c2 = commit_for_bpf(&root, &blinding);
        assert_eq!(c1, c2);
    }

    #[test]
    fn both_wrong_value_and_blinding_fails() {
        let value = Blake3Hash::digest(b"real-value");
        let blinding = Blake3Hash::digest(b"real-blinding");
        let commitment = commit(&value, &blinding);
        let wrong_opening = Opening {
            value: Blake3Hash::digest(b"wrong-value"),
            blinding: Blake3Hash::digest(b"wrong-blinding"),
        };
        assert!(!verify_commitment(&commitment, &wrong_opening));
    }
}
