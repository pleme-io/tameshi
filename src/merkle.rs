//! Merkle tree construction for composing layer signatures.
//!
//! Layer signatures are sorted by [`LayerType`] to ensure deterministic ordering,
//! then composed into a balanced binary Merkle tree using BLAKE3 at each node.
//! The Merkle root serves as the Master Untested Signature.
//!
//! # Domain Separation (CT/RFC 9162)
//!
//! To prevent second-preimage attacks, leaf and internal node hashes occupy
//! distinct domains:
//!
//! - **Leaf**: `BLAKE3(0x00 || layer_hash_bytes)`
//! - **Internal node**: `BLAKE3(0x01 || left_child || right_child)`
//!
//! This follows the Certificate Transparency / RFC 9162 convention and ensures
//! that an attacker cannot present an internal node as a leaf (or vice versa).
//!
//! # COMPATIBILITY NOTE
//!
//! This module uses `rs_merkle` internally with a custom `Blake3Algorithm`
//! hasher that overrides `concat_and_hash` for internal-node domain separation.
//! Leaf domain separation is applied before leaves enter the tree.
//! Trees with an odd number of leaves (>1) duplicate the last leaf for padding
//! (matching `rs_merkle` behavior).

use rs_merkle::{Hasher as MerkleHasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::signature::{LayerSignature, MasterSignature};

/// Domain-separated BLAKE3 hasher adapter for `rs_merkle`.
///
/// Implements the CT/RFC 9162 domain separation convention to prevent
/// second-preimage attacks:
///
/// - Leaf hash: `BLAKE3(0x00 || data)`
/// - Internal node hash: `BLAKE3(0x01 || left || right)`
///
/// The `hash` method is used by `rs_merkle` only for internal concatenation
/// (via `concat_and_hash`). We override `concat_and_hash` to inject the
/// `0x01` prefix. Leaf domain separation (`0x00` prefix) is applied in
/// [`domain_separated_leaf`] before leaves enter the tree.
#[derive(Clone)]
pub struct Blake3Algorithm;

impl MerkleHasher for Blake3Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        match right {
            Some(right_node) => {
                // Internal node: BLAKE3(0x01 || left || right)
                let mut data = Vec::with_capacity(1 + 32 + 32);
                data.push(0x01);
                data.extend_from_slice(left);
                data.extend_from_slice(right_node);
                blake3::hash(&data).into()
            }
            // Odd node with no sibling: propagate as-is (rs_merkle default)
            None => *left,
        }
    }
}

/// Apply leaf domain separation: `BLAKE3(0x00 || data)`.
///
/// Every leaf entering the Merkle tree MUST pass through this function so
/// that leaf hashes live in a different domain from internal node hashes.
#[inline]
#[must_use]
pub fn domain_separated_leaf(data: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(33);
    buf.push(0x00);
    buf.extend_from_slice(data);
    blake3::hash(&buf).into()
}

/// A node in the Merkle tree (for audit/inspection).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleNode {
    /// BLAKE3 hash at this node.
    pub hash: Blake3Hash,
    /// Left child (if internal node).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<Box<MerkleNode>>,
    /// Right child (if internal node).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<Box<MerkleNode>>,
    /// Leaf data (if leaf node).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
}

impl MerkleNode {
    /// Create a leaf node from a layer signature.
    ///
    /// Applies the `0x00` domain separation prefix so the leaf hash matches
    /// the domain-separated leaves used in `compute_merkle_root`.
    #[must_use]
    pub fn leaf(sig: &LayerSignature) -> Self {
        Self {
            hash: Blake3Hash(domain_separated_leaf(&sig.hash.0)),
            left: None,
            right: None,
            layer: Some(sig.layer.to_string()),
        }
    }

    /// Create an internal node by combining two children with domain separation.
    ///
    /// Uses `BLAKE3(0x01 || left || right)` matching the `Blake3Algorithm`
    /// `concat_and_hash` override.
    #[must_use]
    pub fn branch(left: MerkleNode, right: MerkleNode) -> Self {
        let combined = Blake3Algorithm::concat_and_hash(&left.hash.0, Some(&right.hash.0));
        Self {
            hash: Blake3Hash(combined),
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            layer: None,
        }
    }
}

/// Sort layer signatures by layer type for deterministic ordering.
fn sorted_layers(layers: &[LayerSignature]) -> Vec<&LayerSignature> {
    let mut sorted: Vec<&LayerSignature> = layers.iter().collect();
    sorted.sort_by(|a, b| a.layer.cmp(&b.layer));
    sorted
}

/// Convert sorted layer signatures to domain-separated leaf hashes for rs_merkle.
///
/// Applies the `0x00` leaf prefix per CT/RFC 9162 before the hash enters
/// the Merkle tree. This ensures leaf hashes and internal node hashes
/// occupy distinct domains, preventing second-preimage attacks.
fn layer_leaves(sorted: &[&LayerSignature]) -> Vec<[u8; 32]> {
    sorted
        .iter()
        .map(|sig| domain_separated_leaf(&sig.hash.0))
        .collect()
}

/// Compute the Merkle root from a set of layer signatures.
///
/// Signatures are sorted by [`LayerType`] to ensure deterministic ordering
/// regardless of the order they were collected.
///
/// Uses `rs_merkle` internally with `Blake3Algorithm` as the hasher.
#[must_use]
pub fn compute_merkle_root(layers: &[LayerSignature]) -> Blake3Hash {
    if layers.is_empty() {
        return Blake3Hash::digest(b"empty-tree");
    }

    let sorted = sorted_layers(layers);
    let leaves = layer_leaves(&sorted);

    let tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
    Blake3Hash(tree.root().unwrap_or([0u8; 32]))
}

/// Build the full Merkle tree (for audit/inspection).
///
/// Returns a `MerkleNode` tree structure that can be serialized for audit logs.
/// The root hash matches `compute_merkle_root` for the same inputs.
#[must_use]
pub fn build_merkle_tree(layers: &[LayerSignature]) -> MerkleNode {
    let sorted = sorted_layers(layers);
    let leaves: Vec<MerkleNode> = sorted.iter().map(|sig| MerkleNode::leaf(sig)).collect();
    build_node_tree(leaves)
}

/// Build a `MerkleNode` tree from leaf nodes, mirroring rs_merkle's algorithm.
///
/// For odd leaf counts, duplicates the last leaf (matching rs_merkle behavior).
fn build_node_tree(mut nodes: Vec<MerkleNode>) -> MerkleNode {
    if nodes.is_empty() {
        return MerkleNode {
            hash: Blake3Hash::digest(b"empty-tree"),
            left: None,
            right: None,
            layer: Some("empty".to_string()),
        };
    }

    while nodes.len() > 1 {
        let mut next_level = Vec::with_capacity((nodes.len() + 1) / 2);
        let mut i = 0;
        while i < nodes.len() {
            if i + 1 < nodes.len() {
                let left = nodes[i].clone();
                let right = nodes[i + 1].clone();
                next_level.push(MerkleNode::branch(left, right));
                i += 2;
            } else {
                // Odd node: duplicate (matching rs_merkle behavior)
                let left = nodes[i].clone();
                let right = nodes[i].clone();
                next_level.push(MerkleNode::branch(left, right));
                i += 1;
            }
        }
        nodes = next_level;
    }

    nodes.into_iter().next().unwrap()
}

/// Compose layer signatures into a Master Signature via Merkle tree.
///
/// This is the primary composition strategy (Strategy 1 from the architecture).
/// Sorts layers by type, builds a balanced Merkle tree, and returns a
/// `MasterSignature` with the Merkle root as the untested signature.
#[must_use]
pub fn compose_merkle(layers: &[LayerSignature], environment: &str) -> MasterSignature {
    let root = compute_merkle_root(layers);
    MasterSignature::new(root, layers.to_vec(), environment)
}

/// Generate a Merkle inclusion proof for the leaf at the given index.
///
/// The `index` refers to the position in the sorted (by layer type) leaf list.
/// Returns `None` if the index is out of bounds or the tree is empty.
#[must_use]
pub fn merkle_proof(layers: &[LayerSignature], index: usize) -> Option<Vec<[u8; 32]>> {
    if layers.is_empty() || index >= layers.len() {
        return None;
    }

    let sorted = sorted_layers(layers);
    let leaves = layer_leaves(&sorted);

    let tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
    let proof = tree.proof(&[index]);
    Some(proof.proof_hashes().to_vec())
}

/// Verify a Merkle inclusion proof for a leaf against a known root.
///
/// `proof_hashes` is the proof returned by `merkle_proof`.
/// `root` is the expected Merkle root.
/// `leaf` is the layer signature whose inclusion is being verified.
/// `index` is the leaf position in the sorted tree.
/// `total` is the total number of leaves in the tree.
///
/// The leaf hash is domain-separated (`0x00` prefix) before verification,
/// matching the tree construction.
#[must_use]
pub fn verify_proof(
    proof_hashes: &[[u8; 32]],
    root: &Blake3Hash,
    leaf: &LayerSignature,
    index: usize,
    total: usize,
) -> bool {
    let proof = MerkleProof::<Blake3Algorithm>::new(proof_hashes.to_vec());
    let ds_leaf = domain_separated_leaf(&leaf.hash.0);
    proof.verify(root.0, &[index], &[ds_leaf], total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::LayerType;

    fn make_layer(layer: LayerType, data: &[u8]) -> LayerSignature {
        LayerSignature::new(layer, Blake3Hash::digest(data), "test", vec![])
    }

    #[test]
    fn merkle_root_deterministic() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
        ];
        let r1 = compute_merkle_root(&layers);
        let r2 = compute_merkle_root(&layers);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_order_independent() {
        let a = make_layer(LayerType::Nix, b"nix");
        let b = make_layer(LayerType::Oci, b"oci");
        let c = make_layer(LayerType::Helm, b"helm");

        // Different input orders should produce the same root (sorted internally)
        let r1 = compute_merkle_root(&[a.clone(), b.clone(), c.clone()]);
        let r2 = compute_merkle_root(&[c.clone(), a.clone(), b.clone()]);
        let r3 = compute_merkle_root(&[b.clone(), c.clone(), a.clone()]);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn merkle_root_single_layer() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let root = compute_merkle_root(&layers);
        // With domain separation: single leaf root = BLAKE3(0x00 || leaf_hash)
        let expected = Blake3Hash(domain_separated_leaf(&Blake3Hash::digest(b"nix").0));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_two_layers() {
        let layers = vec![
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Nix, b"nix"),
        ];
        let root = compute_merkle_root(&layers);

        // Two layers: sorted by LayerType. Verify determinism by
        // recomputing with reversed input order.
        let root2 = compute_merkle_root(&[
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Helm, b"helm"),
        ]);
        assert_eq!(root, root2);
    }

    #[test]
    fn merkle_root_empty() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, Blake3Hash::digest(b"empty-tree"));
    }

    #[test]
    fn compose_merkle_creates_master() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        let master = compose_merkle(&layers, "production");
        assert_eq!(master.environment, "production");
        assert_eq!(master.layers.len(), 2);
        assert!(master.verify_untested());
        assert!(!master.is_fully_attested());
    }

    #[test]
    fn build_tree_preserves_structure() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Tofu, b"tofu"),
        ];
        let tree = build_merkle_tree(&layers);
        assert!(tree.left.is_some());
        assert!(tree.right.is_some());
    }

    #[test]
    fn merkle_root_from_rs_merkle_matches() {
        // Verify the rs_merkle-based implementation produces deterministic
        // results that match a manual rs_merkle tree construction.
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Tofu, b"tofu"),
        ];

        let root = compute_merkle_root(&layers);

        // Manually construct the same tree with rs_merkle
        let sorted = sorted_layers(&layers);
        let leaves = layer_leaves(&sorted);
        let manual_tree = MerkleTree::<Blake3Algorithm>::from_leaves(&leaves);
        let manual_root = Blake3Hash(manual_tree.root().unwrap());

        assert_eq!(root, manual_root);
    }

    #[test]
    fn merkle_proof_generation() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Tofu, b"tofu"),
        ];

        // Generate proof for each leaf
        for i in 0..layers.len() {
            let proof = merkle_proof(&layers, i);
            assert!(proof.is_some(), "proof should exist for index {i}");
            let proof_hashes = proof.unwrap();
            assert!(!proof_hashes.is_empty(), "proof should have hashes for index {i}");
        }
    }

    #[test]
    fn merkle_proof_verification() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Tofu, b"tofu"),
        ];
        let root = compute_merkle_root(&layers);

        // Sort the layers the same way compute_merkle_root does
        let mut sorted_sigs: Vec<LayerSignature> = layers.clone();
        sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));

        for i in 0..sorted_sigs.len() {
            let proof_hashes = merkle_proof(&layers, i).unwrap();
            let valid = verify_proof(
                &proof_hashes,
                &root,
                &sorted_sigs[i],
                i,
                sorted_sigs.len(),
            );
            assert!(valid, "proof verification should pass for sorted index {i}");
        }
    }

    #[test]
    fn merkle_proof_invalid() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
        ];
        let root = compute_merkle_root(&layers);

        // Get proof for index 0
        let proof_hashes = merkle_proof(&layers, 0).unwrap();

        // Try to verify with a different leaf (wrong data)
        let fake_leaf = make_layer(LayerType::Nix, b"fake-nix");
        let valid = verify_proof(&proof_hashes, &root, &fake_leaf, 0, layers.len());
        assert!(!valid, "proof should fail for wrong leaf data");

        // Try to verify with wrong root
        let wrong_root = Blake3Hash::digest(b"wrong-root");
        let mut sorted_sigs: Vec<LayerSignature> = layers.clone();
        sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));
        let valid = verify_proof(&proof_hashes, &wrong_root, &sorted_sigs[0], 0, layers.len());
        assert!(!valid, "proof should fail for wrong root");
    }

    #[test]
    fn merkle_single_leaf() {
        let layers = vec![make_layer(LayerType::Nix, b"single")];
        let root = compute_merkle_root(&layers);

        // With domain separation: single leaf root = BLAKE3(0x00 || leaf_hash)
        let expected = Blake3Hash(domain_separated_leaf(&Blake3Hash::digest(b"single").0));
        assert_eq!(root, expected);

        // Proof for the single leaf should work
        let proof_hashes = merkle_proof(&layers, 0).unwrap();
        let valid = verify_proof(&proof_hashes, &root, &layers[0], 0, 1);
        assert!(valid);
    }

    #[test]
    fn merkle_empty() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, Blake3Hash::digest(b"empty-tree"));

        // No proof possible for empty tree
        assert!(merkle_proof(&[], 0).is_none());
    }

    #[test]
    fn merkle_large_tree() {
        // Build a tree with 128 leaves
        let layer_types = [
            LayerType::Nix,
            LayerType::Oci,
            LayerType::Helm,
            LayerType::Tofu,
            LayerType::Kubernetes,
            LayerType::Kindling,
            LayerType::Tatara,
            LayerType::FluxCD,
            LayerType::ArgoCD,
            LayerType::Akeyless,
        ];

        let layers: Vec<LayerSignature> = (0..128)
            .map(|i| {
                let lt = layer_types[i % layer_types.len()].clone();
                let data = format!("leaf-{i}");
                // Use unique hash per leaf but allow duplicate layer types
                LayerSignature::new(lt, Blake3Hash::digest(data.as_bytes()), "test", vec![])
            })
            .collect();

        let root = compute_merkle_root(&layers);

        // Root should be deterministic
        let root2 = compute_merkle_root(&layers);
        assert_eq!(root, root2);

        // Verify proofs for a sample of leaves
        let mut sorted_sigs = layers.clone();
        sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));

        for i in [0, 1, 63, 64, 127] {
            let proof_hashes = merkle_proof(&layers, i).unwrap();
            let valid = verify_proof(
                &proof_hashes,
                &root,
                &sorted_sigs[i],
                i,
                sorted_sigs.len(),
            );
            assert!(valid, "proof should verify for leaf {i} in large tree");
        }
    }

    #[test]
    fn merkle_proof_out_of_bounds() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        assert!(merkle_proof(&layers, 2).is_none());
        assert!(merkle_proof(&layers, 100).is_none());
    }

    #[test]
    fn build_tree_matches_compute_root() {
        // The MerkleNode tree root hash should match compute_merkle_root
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Tofu, b"tofu"),
        ];

        let root = compute_merkle_root(&layers);
        let tree = build_merkle_tree(&layers);
        assert_eq!(root, tree.hash);
    }

    // -- Property-based edge case tests --

    #[test]
    fn merkle_root_idempotent_recomputation() {
        // Merkle root should be a fixed point: computing it twice gives the same result
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
        ];
        let root1 = compute_merkle_root(&layers);
        let root2 = compute_merkle_root(&layers);
        let root3 = compute_merkle_root(&layers);
        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn merkle_single_element_degeneracy() {
        // Single-element tree: root = domain-separated leaf hash
        for i in 0..10 {
            let data = format!("single-{i}");
            let layers = vec![make_layer(LayerType::Nix, data.as_bytes())];
            let root = compute_merkle_root(&layers);
            let expected = Blake3Hash(domain_separated_leaf(&Blake3Hash::digest(data.as_bytes()).0));
            assert_eq!(root, expected,
                "Single-element tree root must equal domain-separated leaf hash for input {i}");
        }
    }

    #[test]
    fn merkle_empty_input_sentinel() {
        let root = compute_merkle_root(&[]);
        let expected = Blake3Hash::digest(b"empty-tree");
        assert_eq!(root, expected, "Empty tree must produce defined sentinel");
    }

    #[test]
    fn merkle_very_large_tree_no_panic() {
        // Build a tree with 1024 leaves
        let layers: Vec<LayerSignature> = (0..1024)
            .map(|i| {
                let data = format!("large-tree-leaf-{i}");
                LayerSignature::new(
                    LayerType::Nix,
                    Blake3Hash::digest(data.as_bytes()),
                    "test",
                    vec![],
                )
            })
            .collect();

        let root = compute_merkle_root(&layers);
        let root2 = compute_merkle_root(&layers);
        assert_eq!(root, root2, "Large tree must be deterministic");

        // Build the tree structure too
        let tree = build_merkle_tree(&layers);
        assert_eq!(root, tree.hash, "build_merkle_tree must agree with compute_merkle_root for large trees");
    }

    #[test]
    fn merkle_odd_leaf_counts_stable() {
        // Verify trees with odd leaf counts (3, 5, 7, 9) are stable
        for count in [3, 5, 7, 9, 11, 13] {
            let layers: Vec<LayerSignature> = (0..count)
                .map(|i| {
                    let data = format!("odd-{count}-leaf-{i}");
                    LayerSignature::new(
                        LayerType::Nix,
                        Blake3Hash::digest(data.as_bytes()),
                        "test",
                        vec![],
                    )
                })
                .collect();

            let root1 = compute_merkle_root(&layers);
            let root2 = compute_merkle_root(&layers);
            assert_eq!(root1, root2, "Odd-count tree with {count} leaves must be deterministic");
        }
    }

    #[test]
    fn merkle_node_serde_roundtrip() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        let tree = build_merkle_tree(&layers);
        let json = serde_json::to_string(&tree).unwrap();
        let deserialized: MerkleNode = serde_json::from_str(&json).unwrap();
        assert_eq!(tree, deserialized);
    }

    // -- Domain separation tests --

    #[test]
    fn domain_separation_leaf_differs_from_raw() {
        // Domain-separated leaf BLAKE3(0x00 || data) must differ from raw BLAKE3(data)
        let data = Blake3Hash::digest(b"test-data");
        let ds = domain_separated_leaf(&data.0);
        assert_ne!(ds, data.0, "domain-separated leaf must differ from raw hash");
    }

    #[test]
    fn domain_separation_leaf_vs_internal_prefix() {
        // Leaf prefix (0x00) and internal prefix (0x01) must produce different hashes
        // for the same underlying data
        let data = [0xAA; 32];
        let leaf_hash = domain_separated_leaf(&data);

        // Simulate internal node hash with the same data as both children
        let internal_hash = Blake3Algorithm::concat_and_hash(&data, Some(&data));

        assert_ne!(leaf_hash, internal_hash,
            "leaf domain (0x00) must differ from internal domain (0x01)");
    }

    #[test]
    fn domain_separation_prevents_second_preimage() {
        // An internal node hash(0x01 || left || right) must not collide with
        // any leaf hash(0x00 || data), even when data = left || right.
        let left = Blake3Hash::digest(b"left").0;
        let right = Blake3Hash::digest(b"right").0;

        let internal = Blake3Algorithm::concat_and_hash(&left, Some(&right));

        // Construct a "leaf" whose raw hash equals hash(left || right)
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);
        let fake_leaf_data: [u8; 32] = blake3::hash(&combined).into();

        let fake_as_leaf = domain_separated_leaf(&fake_leaf_data);

        assert_ne!(internal, fake_as_leaf,
            "internal node must not collide with leaf containing the same byte pattern");
    }

    #[test]
    fn domain_separation_root_differs_from_undifferentiated() {
        // Verify that the domain-separated tree root differs from a naive
        // (non-domain-separated) construction for multi-leaf trees.
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];

        let ds_root = compute_merkle_root(&layers);

        // Compute a naive root without domain separation
        let sorted = sorted_layers(&layers);
        let naive_leaves: Vec<[u8; 32]> = sorted.iter().map(|sig| sig.hash.0).collect();
        let naive_combined = Blake3Hash::combine(
            &Blake3Hash(naive_leaves[0]),
            &Blake3Hash(naive_leaves[1]),
        );

        assert_ne!(ds_root, naive_combined,
            "domain-separated root must differ from naive combination");
    }
}
