//! Shamir-split Merkle root for threshold attestation.
//!
//! Splits a CertificationArtifact's composed root into k-of-n shares
//! using Shamir Secret Sharing. Reconstruction requires k shares,
//! ensuring no single entity can forge an attestation.

use crate::hash::Blake3Hash;
use crate::shamir_dfc::{reconstruct, split, split_deterministic, Share};

/// A Shamir-split attestation root.
#[derive(Clone, Debug)]
pub struct SplitRoot {
    /// The shares of the composed root.
    pub shares: Vec<Share>,
    /// The threshold (minimum shares needed).
    pub threshold: u8,
    /// Total number of shares.
    pub total: u8,
}

/// Split a composed root into k-of-n shares.
#[must_use]
pub fn split_root(composed_root: &Blake3Hash, k: u8, n: u8) -> SplitRoot {
    let shares = split(&composed_root.0, k, n);
    SplitRoot {
        shares,
        threshold: k,
        total: n,
    }
}

/// Split with deterministic randomness (for testing).
#[must_use]
pub fn split_root_deterministic(
    composed_root: &Blake3Hash,
    k: u8,
    n: u8,
    random_bytes: &[u8],
) -> SplitRoot {
    let shares = split_deterministic(&composed_root.0, k, n, random_bytes);
    SplitRoot {
        shares,
        threshold: k,
        total: n,
    }
}

/// Reconstruct the composed root from k or more shares.
#[must_use]
pub fn reconstruct_root(shares: &[Share]) -> Blake3Hash {
    let bytes = reconstruct(shares);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    Blake3Hash(arr)
}

/// Verify that a set of shares reconstructs to the expected root.
#[must_use]
pub fn verify_shares(shares: &[Share], expected_root: &Blake3Hash) -> bool {
    reconstruct_root(shares) == *expected_root
}

/// Distribute shares to named custodians.
#[must_use]
pub fn distribute_shares(split: &SplitRoot, custodian_names: &[&str]) -> Vec<(String, Share)> {
    split
        .shares
        .iter()
        .zip(custodian_names.iter().cycle())
        .map(|(share, name)| (name.to_string(), share.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reconstruct_root() {
        let composed_root = Blake3Hash::digest(b"composed-root-to-split");
        let sr = split_root(&composed_root, 2, 3);
        assert_eq!(sr.shares.len(), 3);
        assert_eq!(sr.threshold, 2);
        assert_eq!(sr.total, 3);

        // Any 2 of 3 shares should reconstruct the original root.
        let r01 = reconstruct_root(&[sr.shares[0].clone(), sr.shares[1].clone()]);
        let r02 = reconstruct_root(&[sr.shares[0].clone(), sr.shares[2].clone()]);
        let r12 = reconstruct_root(&[sr.shares[1].clone(), sr.shares[2].clone()]);

        assert_eq!(r01, composed_root);
        assert_eq!(r02, composed_root);
        assert_eq!(r12, composed_root);
    }

    #[test]
    fn below_threshold_wrong_root() {
        let composed_root = Blake3Hash::digest(b"threshold-test-root");
        let sr = split_root(&composed_root, 2, 3);

        // Reconstructing from only 1 share (below k=2) should give a wrong root.
        let wrong = reconstruct_root(&[sr.shares[0].clone()]);
        assert_ne!(
            wrong, composed_root,
            "below-threshold reconstruction must not produce the correct root"
        );
    }

    #[test]
    fn deterministic_split() {
        let composed_root = Blake3Hash::digest(b"deterministic-root");
        let random = vec![0x42; 32]; // (k-1)*32 = 1*32 = 32 bytes

        let sr1 = split_root_deterministic(&composed_root, 2, 3, &random);
        let sr2 = split_root_deterministic(&composed_root, 2, 3, &random);

        assert_eq!(
            sr1.shares, sr2.shares,
            "same root + same randomness must produce same shares"
        );
    }

    #[test]
    fn different_roots_different_shares() {
        let root_a = Blake3Hash::digest(b"root-alpha");
        let root_b = Blake3Hash::digest(b"root-beta");
        let random = vec![0x55; 32];

        let sr_a = split_root_deterministic(&root_a, 2, 3, &random);
        let sr_b = split_root_deterministic(&root_b, 2, 3, &random);

        assert_ne!(
            sr_a.shares[0].y, sr_b.shares[0].y,
            "different roots must produce different share values"
        );
    }

    #[test]
    fn distribute_names_shares() {
        let composed_root = Blake3Hash::digest(b"distribute-root");
        let sr = split_root(&composed_root, 2, 3);

        let custodians = ["alice", "bob", "charlie"];
        let distributed = distribute_shares(&sr, &custodians);

        assert_eq!(distributed.len(), 3);
        assert_eq!(distributed[0].0, "alice");
        assert_eq!(distributed[1].0, "bob");
        assert_eq!(distributed[2].0, "charlie");

        // Each distributed share should match the original share.
        for (i, (_, share)) in distributed.iter().enumerate() {
            assert_eq!(share, &sr.shares[i]);
        }
    }

    #[test]
    fn verify_shares_correct() {
        let composed_root = Blake3Hash::digest(b"verify-correct-root");
        let sr = split_root(&composed_root, 2, 3);

        // Any 2 shares should verify correctly.
        assert!(
            verify_shares(
                &[sr.shares[0].clone(), sr.shares[1].clone()],
                &composed_root
            ),
            "correct shares must verify"
        );
        assert!(
            verify_shares(
                &[sr.shares[1].clone(), sr.shares[2].clone()],
                &composed_root
            ),
            "correct shares must verify"
        );
    }

    #[test]
    fn verify_shares_wrong() {
        let composed_root = Blake3Hash::digest(b"verify-wrong-root");
        let sr = split_root(&composed_root, 2, 3);

        // Only 1 share (below threshold) should NOT verify.
        assert!(
            !verify_shares(&[sr.shares[0].clone()], &composed_root),
            "insufficient shares must not verify"
        );
    }

    #[test]
    fn split_3_of_5_any_subset() {
        let composed_root = Blake3Hash::digest(b"3-of-5-root");
        let sr = split_root(&composed_root, 3, 5);
        assert_eq!(sr.shares.len(), 5);
        assert_eq!(sr.threshold, 3);
        assert_eq!(sr.total, 5);

        // Enumerate all C(5,3) = 10 subsets of 3 shares and verify each reconstructs.
        let indices: Vec<[usize; 3]> = vec![
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
            [1, 2, 3],
            [1, 2, 4],
            [1, 3, 4],
            [2, 3, 4],
        ];

        for combo in &indices {
            let subset: Vec<Share> = combo.iter().map(|&i| sr.shares[i].clone()).collect();
            let reconstructed = reconstruct_root(&subset);
            assert_eq!(
                reconstructed, composed_root,
                "shares [{}, {}, {}] must reconstruct the correct root",
                combo[0], combo[1], combo[2]
            );
        }
    }
}
