//! Sparse Merkle Tree for key-value attestation.
//!
//! A 256-level binary tree where keys are 32-byte BLAKE3 hashes and values
//! are 32-byte hashes. Supports inclusion proofs (prove a key exists with
//! a given value) and non-inclusion proofs (prove a key does NOT exist).
//!
//! This complements the balanced Merkle tree in `merkle.rs`:
//! - Balanced tree: fixed set of layers, sorted, composed into root
//! - Sparse tree: dynamic key-value store, arbitrary insertions, non-inclusion proofs

use crate::hash::Blake3Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default hash for empty nodes at each level.
/// `empty_hash(0)` = `BLAKE3("smt:empty:leaf")`
/// `empty_hash(n)` = `BLAKE3(empty_hash(n-1) || empty_hash(n-1))`
fn empty_hash(level: usize) -> Blake3Hash {
    static EMPTY_LEAF: std::sync::LazyLock<Blake3Hash> =
        std::sync::LazyLock::new(|| Blake3Hash::digest(b"smt:empty:leaf"));

    if level == 0 {
        return EMPTY_LEAF.clone();
    }

    let child = empty_hash(level - 1);
    Blake3Hash::combine(&child, &child)
}

/// Trait for Merkle tree operations.
///
/// Abstracts the tree implementation so consumers can inject
/// mocks or alternative implementations (e.g., persistent SMT,
/// in-memory balanced tree).
pub trait MerkleTreeOps: Send + Sync {
    /// Insert a key-value pair. Returns the old value if key existed.
    fn insert(&mut self, key: Blake3Hash, value: Blake3Hash) -> Option<Blake3Hash>;
    /// Remove a key. Returns the old value if key existed.
    fn remove(&mut self, key: &Blake3Hash) -> Option<Blake3Hash>;
    /// Get the value for a key.
    fn get(&self, key: &Blake3Hash) -> Option<&Blake3Hash>;
    /// Compute the root hash.
    fn root(&self) -> Blake3Hash;
    /// Generate a proof for a key (inclusion or non-inclusion).
    fn prove(&self, key: &Blake3Hash) -> SmtProof;
    /// Number of entries.
    fn len(&self) -> usize;
    /// Whether empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A Sparse Merkle Tree with 256-bit key space.
///
/// Keys and values are both 32-byte BLAKE3 hashes. The tree is stored
/// as a flat `HashMap` of non-empty leaves. The root is recomputed on demand.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleTree {
    leaves: HashMap<Blake3Hash, Blake3Hash>, // key -> value
    depth: usize, // tree depth (number of bits used from key), max 256
}

/// A proof of inclusion or non-inclusion in the SMT.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtProof {
    /// Sibling hashes along the path from leaf to root.
    pub siblings: Vec<Blake3Hash>,
    /// The key being proved.
    pub key: Blake3Hash,
    /// The value at this key (None for non-inclusion proof).
    pub value: Option<Blake3Hash>,
}

impl SparseMerkleTree {
    /// Create a new empty SMT with the given depth.
    /// Depth determines how many bits of the key are used.
    /// For practical use, 16-32 is sufficient (2^16 to 2^32 entries).
    ///
    /// # Panics
    ///
    /// Panics if `depth` is 0 or greater than 256.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 256, "depth must be 1..=256");
        Self {
            leaves: HashMap::new(),
            depth,
        }
    }

    /// Insert a key-value pair. Returns the old value if the key existed.
    pub fn insert(&mut self, key: Blake3Hash, value: Blake3Hash) -> Option<Blake3Hash> {
        self.leaves.insert(key, value)
    }

    /// Remove a key. Returns the old value if the key existed.
    pub fn remove(&mut self, key: &Blake3Hash) -> Option<Blake3Hash> {
        self.leaves.remove(key)
    }

    /// Get the value for a key, if it exists.
    #[must_use]
    pub fn get(&self, key: &Blake3Hash) -> Option<&Blake3Hash> {
        self.leaves.get(key)
    }

    /// Number of non-empty leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The configured depth of this tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Compute the root hash of the tree.
    ///
    /// For an empty tree, returns the empty hash at the tree depth.
    /// For non-empty trees, rebuilds the relevant paths.
    #[must_use]
    pub fn root(&self) -> Blake3Hash {
        if self.leaves.is_empty() {
            return empty_hash(self.depth);
        }

        // Build a map of leaf-level hashes keyed by their bit-path.
        let mut level_nodes: HashMap<Vec<bool>, Blake3Hash> = HashMap::new();
        for (key, value) in &self.leaves {
            let path = key_to_path(key, self.depth);
            // Leaf hash = BLAKE3(key || value)
            let leaf_hash = Blake3Hash::combine(key, value);
            level_nodes.insert(path, leaf_hash);
        }

        // Build tree bottom-up, level by level.
        for level in (0..self.depth).rev() {
            let mut parent_nodes: HashMap<Vec<bool>, Blake3Hash> = HashMap::new();
            // Collect all unique parent paths at this level.
            let mut parent_paths: std::collections::HashSet<Vec<bool>> =
                std::collections::HashSet::new();
            for path in level_nodes.keys() {
                parent_paths.insert(path[..level].to_vec());
            }

            let empty_at_depth = empty_hash(self.depth - level - 1);

            for parent_path in parent_paths {
                let mut left_path = parent_path.clone();
                left_path.push(false);
                let mut right_path = parent_path.clone();
                right_path.push(true);

                let left = level_nodes
                    .get(&left_path)
                    .cloned()
                    .unwrap_or_else(|| empty_at_depth.clone());
                let right = level_nodes
                    .get(&right_path)
                    .cloned()
                    .unwrap_or_else(|| empty_at_depth.clone());

                parent_nodes.insert(parent_path, Blake3Hash::combine(&left, &right));
            }

            level_nodes = parent_nodes;
        }

        level_nodes
            .get(&vec![])
            .cloned()
            .unwrap_or_else(|| empty_hash(self.depth))
    }

    /// Generate a proof for a key (inclusion or non-inclusion).
    #[must_use]
    pub fn prove(&self, key: &Blake3Hash) -> SmtProof {
        let path = key_to_path(key, self.depth);
        let value = self.leaves.get(key).cloned();

        // Collect sibling hashes along the path.
        let mut siblings = Vec::with_capacity(self.depth);

        // Build leaf-level hashes.
        let mut level_nodes: HashMap<Vec<bool>, Blake3Hash> = HashMap::new();
        for (k, v) in &self.leaves {
            let p = key_to_path(k, self.depth);
            level_nodes.insert(p, Blake3Hash::combine(k, v));
        }

        for level in (0..self.depth).rev() {
            let bit = path[level];
            let mut sibling_path = path[..level].to_vec();
            sibling_path.push(!bit);

            // Find the sibling's hash (or empty hash if absent).
            let sibling_hash =
                self.subtree_hash(&level_nodes, &sibling_path, self.depth - level - 1);
            siblings.push(sibling_hash);

            // Move to parent level.
            let mut parent_nodes: HashMap<Vec<bool>, Blake3Hash> = HashMap::new();
            let mut parent_paths: std::collections::HashSet<Vec<bool>> =
                std::collections::HashSet::new();
            for p in level_nodes.keys() {
                parent_paths.insert(p[..level].to_vec());
            }
            let empty_at_depth = empty_hash(self.depth - level - 1);
            for pp in parent_paths {
                let mut lp = pp.clone();
                lp.push(false);
                let mut rp = pp.clone();
                rp.push(true);
                let l = level_nodes
                    .get(&lp)
                    .cloned()
                    .unwrap_or_else(|| empty_at_depth.clone());
                let r = level_nodes
                    .get(&rp)
                    .cloned()
                    .unwrap_or_else(|| empty_at_depth.clone());
                parent_nodes.insert(pp, Blake3Hash::combine(&l, &r));
            }
            level_nodes = parent_nodes;
        }

        SmtProof {
            siblings,
            key: key.clone(),
            value,
        }
    }

    /// Verify a proof against a known root.
    #[must_use]
    pub fn verify_proof(proof: &SmtProof, root: &Blake3Hash, depth: usize) -> bool {
        let path = key_to_path(&proof.key, depth);

        // Start from the leaf.
        let mut current = match &proof.value {
            Some(value) => Blake3Hash::combine(&proof.key, value), // inclusion
            None => empty_hash(0),                                 // non-inclusion: empty leaf
        };

        // Walk up using siblings.
        for (i, sibling) in proof.siblings.iter().enumerate() {
            let level = depth - 1 - i;
            let bit = path[level];
            current = if bit {
                Blake3Hash::combine(sibling, &current) // we're on the right
            } else {
                Blake3Hash::combine(&current, sibling) // we're on the left
            };
        }

        current == *root
    }

    fn subtree_hash(
        &self,
        level_nodes: &HashMap<Vec<bool>, Blake3Hash>,
        prefix: &[bool],
        remaining_depth: usize,
    ) -> Blake3Hash {
        if let Some(hash) = level_nodes.get(prefix) {
            return hash.clone();
        }
        if remaining_depth == 0 {
            return empty_hash(0);
        }
        // This subtree has no leaves -- return empty hash at this depth.
        empty_hash(remaining_depth)
    }
}

impl MerkleTreeOps for SparseMerkleTree {
    fn insert(&mut self, key: Blake3Hash, value: Blake3Hash) -> Option<Blake3Hash> {
        self.leaves.insert(key, value)
    }

    fn remove(&mut self, key: &Blake3Hash) -> Option<Blake3Hash> {
        self.leaves.remove(key)
    }

    fn get(&self, key: &Blake3Hash) -> Option<&Blake3Hash> {
        self.leaves.get(key)
    }

    fn root(&self) -> Blake3Hash {
        SparseMerkleTree::root(self)
    }

    fn prove(&self, key: &Blake3Hash) -> SmtProof {
        SparseMerkleTree::prove(self, key)
    }

    fn len(&self) -> usize {
        self.leaves.len()
    }
}

/// Mock Merkle tree for testing consumers that depend on `MerkleTreeOps`.
///
/// Stores entries in a HashMap and computes roots deterministically.
/// Does not build a real tree -- just hashes all values together.
#[derive(Debug, Default)]
pub struct MockMerkleTree {
    entries: HashMap<Blake3Hash, Blake3Hash>,
}

impl MockMerkleTree {
    /// Create a new empty mock tree.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl MerkleTreeOps for MockMerkleTree {
    fn insert(&mut self, key: Blake3Hash, value: Blake3Hash) -> Option<Blake3Hash> {
        self.entries.insert(key, value)
    }

    fn remove(&mut self, key: &Blake3Hash) -> Option<Blake3Hash> {
        self.entries.remove(key)
    }

    fn get(&self, key: &Blake3Hash) -> Option<&Blake3Hash> {
        self.entries.get(key)
    }

    fn root(&self) -> Blake3Hash {
        if self.entries.is_empty() {
            return Blake3Hash::digest(b"mock-empty-root");
        }
        let mut sorted: Vec<_> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        let mut data = Vec::new();
        for (k, v) in &sorted {
            data.extend_from_slice(&k.0);
            data.extend_from_slice(&v.0);
        }
        Blake3Hash::digest(&data)
    }

    fn prove(&self, key: &Blake3Hash) -> SmtProof {
        SmtProof {
            siblings: vec![],
            key: key.clone(),
            value: self.entries.get(key).cloned(),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Convert a key to a path of bits (MSB first).
fn key_to_path(key: &Blake3Hash, depth: usize) -> Vec<bool> {
    let mut path = Vec::with_capacity(depth);
    for i in 0..depth {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if byte_idx < 32 {
            path.push((key.0[byte_idx] >> bit_idx) & 1 == 1);
        } else {
            path.push(false);
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_deterministic() {
        let tree1 = SparseMerkleTree::new(8);
        let tree2 = SparseMerkleTree::new(8);
        assert_eq!(tree1.root(), tree2.root());

        // Calling root() multiple times gives the same result.
        let root_a = tree1.root();
        let root_b = tree1.root();
        assert_eq!(root_a, root_b);
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = SparseMerkleTree::new(8);
        let empty_root = tree.root();

        let key = Blake3Hash::digest(b"key1");
        let value = Blake3Hash::digest(b"value1");
        tree.insert(key, value);

        let new_root = tree.root();
        assert_ne!(empty_root, new_root, "inserting a value must change the root");
    }

    #[test]
    fn insert_same_key_updates() {
        let mut tree = SparseMerkleTree::new(8);

        let key = Blake3Hash::digest(b"key");
        let v1 = Blake3Hash::digest(b"value1");
        let v2 = Blake3Hash::digest(b"value2");

        tree.insert(key.clone(), v1);
        let root1 = tree.root();

        let old = tree.insert(key, v2);
        assert!(old.is_some(), "reinserting should return old value");
        let root2 = tree.root();
        assert_ne!(root1, root2, "updating value must change root");
    }

    #[test]
    fn remove_restores_empty() {
        let mut tree = SparseMerkleTree::new(8);
        let empty_root = tree.root();

        let key = Blake3Hash::digest(b"removable");
        let value = Blake3Hash::digest(b"temp");
        tree.insert(key.clone(), value);
        assert_ne!(tree.root(), empty_root);

        tree.remove(&key);
        assert_eq!(
            tree.root(),
            empty_root,
            "removing the only entry must restore empty root"
        );
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut tree = SparseMerkleTree::new(8);

        let key = Blake3Hash::digest(b"proven-key");
        let value = Blake3Hash::digest(b"proven-value");
        tree.insert(key.clone(), value.clone());

        let root = tree.root();
        let proof = tree.prove(&key);

        assert_eq!(proof.value, Some(value), "proof should contain the value");
        assert!(
            SparseMerkleTree::verify_proof(&proof, &root, tree.depth()),
            "inclusion proof must verify"
        );
    }

    #[test]
    fn non_inclusion_proof_verifies() {
        let mut tree = SparseMerkleTree::new(8);

        // Insert one key, then prove a different key is absent.
        let key_present = Blake3Hash::digest(b"present");
        let value = Blake3Hash::digest(b"exists");
        tree.insert(key_present, value);

        let key_absent = Blake3Hash::digest(b"absent");
        let root = tree.root();
        let proof = tree.prove(&key_absent);

        assert!(proof.value.is_none(), "absent key should have no value");
        assert!(
            SparseMerkleTree::verify_proof(&proof, &root, tree.depth()),
            "non-inclusion proof must verify"
        );
    }

    #[test]
    fn tampered_value_fails_proof() {
        let mut tree = SparseMerkleTree::new(8);

        let key = Blake3Hash::digest(b"tamper-key");
        let value = Blake3Hash::digest(b"real-value");
        tree.insert(key.clone(), value);

        let root = tree.root();
        let mut proof = tree.prove(&key);

        // Tamper with the value in the proof.
        proof.value = Some(Blake3Hash::digest(b"fake-value"));
        assert!(
            !SparseMerkleTree::verify_proof(&proof, &root, tree.depth()),
            "tampered proof must not verify"
        );
    }

    #[test]
    fn different_keys_different_roots() {
        let mut tree_a = SparseMerkleTree::new(8);
        let mut tree_b = SparseMerkleTree::new(8);

        let key_a = Blake3Hash::digest(b"key-a");
        let key_b = Blake3Hash::digest(b"key-b");
        let value = Blake3Hash::digest(b"same-value");

        tree_a.insert(key_a, value.clone());
        tree_b.insert(key_b, value);

        assert_ne!(
            tree_a.root(),
            tree_b.root(),
            "different keys with same value must produce different roots"
        );
    }

    #[test]
    fn order_independent() {
        let mut tree_ab = SparseMerkleTree::new(8);
        let mut tree_ba = SparseMerkleTree::new(8);

        let key_a = Blake3Hash::digest(b"order-a");
        let val_a = Blake3Hash::digest(b"val-a");
        let key_b = Blake3Hash::digest(b"order-b");
        let val_b = Blake3Hash::digest(b"val-b");

        // Insert A then B.
        tree_ab.insert(key_a.clone(), val_a.clone());
        tree_ab.insert(key_b.clone(), val_b.clone());

        // Insert B then A.
        tree_ba.insert(key_b, val_b);
        tree_ba.insert(key_a, val_a);

        assert_eq!(
            tree_ab.root(),
            tree_ba.root(),
            "insertion order must not affect the root"
        );
    }

    #[test]
    fn proof_for_wrong_root_fails() {
        let mut tree1 = SparseMerkleTree::new(8);
        let mut tree2 = SparseMerkleTree::new(8);

        let key = Blake3Hash::digest(b"shared-key");
        let val1 = Blake3Hash::digest(b"value-1");
        let val2 = Blake3Hash::digest(b"value-2");

        tree1.insert(key.clone(), val1);
        tree2.insert(key.clone(), val2);

        let proof1 = tree1.prove(&key);
        let root2 = tree2.root();

        assert!(
            !SparseMerkleTree::verify_proof(&proof1, &root2, tree1.depth()),
            "proof from tree1 must not verify against tree2's root"
        );
    }

    #[test]
    fn mock_tree_insert_and_root() {
        let mut mock = MockMerkleTree::new();
        let key = Blake3Hash::digest(b"key");
        let val = Blake3Hash::digest(b"val");
        mock.insert(key.clone(), val);
        assert_eq!(mock.len(), 1);
        assert!(mock.get(&key).is_some());
        let _ = mock.root(); // should not panic
    }

    #[test]
    fn trait_object_dispatch_smt() {
        let mut tree: Box<dyn MerkleTreeOps> = Box::new(SparseMerkleTree::new(8));
        let key = Blake3Hash::digest(b"trait-key");
        let val = Blake3Hash::digest(b"trait-val");
        tree.insert(key.clone(), val);
        assert_eq!(tree.len(), 1);
        let _ = tree.root();
    }
}
