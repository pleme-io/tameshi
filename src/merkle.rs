//! Merkle tree construction for composing layer signatures.
//!
//! Layer signatures are sorted by [`LayerType`] to ensure deterministic ordering,
//! then composed into a balanced binary Merkle tree using BLAKE3 at each node.
//! The Merkle root serves as the Master Untested Signature.

use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::signature::{LayerSignature, MasterSignature};

/// A node in the Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn leaf(sig: &LayerSignature) -> Self {
        Self {
            hash: sig.hash.clone(),
            left: None,
            right: None,
            layer: Some(sig.layer.to_string()),
        }
    }

    /// Create an internal node by combining two children.
    pub fn branch(left: MerkleNode, right: MerkleNode) -> Self {
        let hash = Blake3Hash::combine(&left.hash, &right.hash);
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            layer: None,
        }
    }
}

/// Build a balanced Merkle tree from leaf nodes.
///
/// If the number of nodes is odd, the last node is promoted as-is.
fn build_tree(mut nodes: Vec<MerkleNode>) -> MerkleNode {
    if nodes.is_empty() {
        return MerkleNode {
            hash: Blake3Hash::digest(b"empty"),
            left: None,
            right: None,
            layer: Some("empty".to_string()),
        };
    }

    while nodes.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < nodes.len() {
            if i + 1 < nodes.len() {
                let left = nodes[i].clone();
                let right = nodes[i + 1].clone();
                next_level.push(MerkleNode::branch(left, right));
                i += 2;
            } else {
                // Odd node out — promote to next level
                next_level.push(nodes[i].clone());
                i += 1;
            }
        }
        nodes = next_level;
    }

    nodes.into_iter().next().unwrap()
}

/// Compute the Merkle root from a set of layer signatures.
///
/// Signatures are sorted by [`LayerType`] to ensure deterministic ordering
/// regardless of the order they were collected.
pub fn compute_merkle_root(layers: &[LayerSignature]) -> Blake3Hash {
    let mut sorted: Vec<&LayerSignature> = layers.iter().collect();
    sorted.sort_by(|a, b| a.layer.cmp(&b.layer));

    let leaves: Vec<MerkleNode> = sorted.iter().map(|sig| MerkleNode::leaf(sig)).collect();
    let root = build_tree(leaves);
    root.hash
}

/// Build the full Merkle tree (for audit/inspection).
pub fn build_merkle_tree(layers: &[LayerSignature]) -> MerkleNode {
    let mut sorted: Vec<&LayerSignature> = layers.iter().collect();
    sorted.sort_by(|a, b| a.layer.cmp(&b.layer));

    let leaves: Vec<MerkleNode> = sorted.iter().map(|sig| MerkleNode::leaf(sig)).collect();
    build_tree(leaves)
}

/// Compose layer signatures into a Master Signature via Merkle tree.
///
/// This is the primary composition strategy (Strategy 1 from the architecture).
/// Sorts layers by type, builds a balanced Merkle tree, and returns a
/// `MasterSignature` with the Merkle root as the untested signature.
pub fn compose_merkle(layers: &[LayerSignature], environment: &str) -> MasterSignature {
    let root = compute_merkle_root(layers);
    MasterSignature::new(root, layers.to_vec(), environment)
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

        // Different input orders should produce the same root
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
        assert_eq!(root, Blake3Hash::digest(b"nix"));
    }

    #[test]
    fn merkle_root_two_layers() {
        let layers = vec![
            make_layer(LayerType::Helm, b"helm"),
            make_layer(LayerType::Nix, b"nix"),
        ];
        let root = compute_merkle_root(&layers);

        // Two layers: sorted by LayerType. With two leaves the tree is just
        // combine(first_sorted, second_sorted). Verify determinism by
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
        assert_eq!(root, Blake3Hash::digest(b"empty"));
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
}
