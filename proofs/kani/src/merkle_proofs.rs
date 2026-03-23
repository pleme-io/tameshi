//! Merkle tree property proofs.
//!
//! Verifies tamper detection, canonical ordering, and domain separation
//! using a miniature 4-leaf binary Merkle tree.

use crate::Hash;

/// A 4-leaf balanced binary Merkle tree.
///
/// ```text
///        root
///       /    \
///     n01    n23
///    / \    / \
///   l0 l1 l2 l3
/// ```
#[cfg_attr(not(kani), allow(dead_code))]
struct MiniMerkle {
    leaves: [Hash; 4],
}

#[cfg_attr(not(kani), allow(dead_code))]
impl MiniMerkle {
    /// Compute the Merkle root from 4 leaves.
    fn root(&self) -> Hash {
        let l0 = crate::domain_leaf(&self.leaves[0]);
        let l1 = crate::domain_leaf(&self.leaves[1]);
        let l2 = crate::domain_leaf(&self.leaves[2]);
        let l3 = crate::domain_leaf(&self.leaves[3]);
        let n01 = crate::domain_internal(&l0, &l1);
        let n23 = crate::domain_internal(&l2, &l3);
        crate::domain_internal(&n01, &n23)
    }

    /// Compute the Merkle root from leaves sorted lexicographically.
    fn canonical_root(&self) -> Hash {
        let mut sorted = self.leaves;
        // Simple insertion sort for 4 elements (no std in kani)
        for i in 1..4 {
            let mut j = i;
            while j > 0 && sorted[j] < sorted[j - 1] {
                sorted.swap(j, j - 1);
                j -= 1;
            }
        }
        let tree = MiniMerkle { leaves: sorted };
        tree.root()
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Tampering with any single leaf changes the Merkle root.
    ///
    /// This is the core tamper-detection property. For any 4-leaf tree,
    /// modifying any one leaf to a different value MUST produce a different root.
    /// Kani symbolically picks which leaf to tamper and what to change it to.
    #[kani::proof]
    fn merkle_tamper_4_leaf() {
        let leaves: [Hash; 4] = kani::any();
        let tree = MiniMerkle { leaves };
        let original_root = tree.root();

        let tamper_idx: usize = kani::any();
        kani::assume(tamper_idx < 4);
        let tamper_value: Hash = kani::any();
        kani::assume(tamper_value != leaves[tamper_idx]);

        let mut tampered_leaves = leaves;
        tampered_leaves[tamper_idx] = tamper_value;
        let tampered = MiniMerkle {
            leaves: tampered_leaves,
        };
        assert_ne!(
            original_root,
            tampered.root(),
            "tampering with any leaf must change the root"
        );
    }

    /// Two permutations of the same leaf set produce the same canonical root.
    ///
    /// When leaves are sorted before tree construction, insertion order
    /// does not affect the root. This is essential for set-membership proofs
    /// where the order of attestation layers should not matter.
    #[kani::proof]
    fn canonical_sort() {
        let leaves: [Hash; 4] = kani::any();

        let tree1 = MiniMerkle { leaves };
        let root1 = tree1.canonical_root();

        // Swap first two leaves to create a different ordering
        let mut swapped = leaves;
        swapped.swap(0, 1);
        let tree2 = MiniMerkle { leaves: swapped };
        let root2 = tree2.canonical_root();

        assert_eq!(
            root1, root2,
            "canonical sort must produce same root regardless of input order"
        );
    }

    /// Leaf domain and internal domain never collide: `domain_leaf(x) != domain_internal(x, x)`.
    ///
    /// Domain separation prevents second-preimage attacks where an attacker
    /// crafts a leaf that hashes identically to an internal node. The distinct
    /// prefix bytes (0x00 for leaf, 0x01 for internal) guarantee disjointness.
    #[kani::proof]
    fn domain_disjoint() {
        let x: Hash = kani::any();
        let leaf_hash = crate::domain_leaf(&x);
        let internal_hash = crate::domain_internal(&x, &x);
        assert_ne!(
            leaf_hash, internal_hash,
            "leaf and internal domains must be disjoint"
        );
    }
}
