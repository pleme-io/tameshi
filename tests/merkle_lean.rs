use tameshi::hash::Blake3Hash;
use tameshi::merkle::{compute_leaf_root, leaf_inclusion_proof, verify_leaf_inclusion};
use tameshi::sparse_merkle::SparseMerkleTree;

fn leaf(byte: u8) -> Blake3Hash {
    Blake3Hash::digest(&[byte])
}

fn domain(prefix: u8, parts: &[&[u8; 32]]) -> [u8; 32] {
    let mut buf = vec![prefix];
    for part in parts {
        buf.extend_from_slice(*part);
    }
    blake3::hash(&buf).into()
}

#[test]
fn a_two_leaf_root_is_the_rfc_9162_composition() {
    let (a, b) = (leaf(1), leaf(2));
    let expected = domain(0x01, &[&domain(0x00, &[&a.0]), &domain(0x00, &[&b.0])]);
    assert_eq!(compute_leaf_root(&[a, b]).0, expected);
}

#[test]
fn an_empty_list_has_the_sentinel_root() {
    assert_eq!(compute_leaf_root(&[]), Blake3Hash::digest(b"empty-tree"));
}

#[test]
fn every_leaf_of_every_size_proves_and_no_other_leaf_does() {
    for size in 1..=9u8 {
        let leaves: Vec<Blake3Hash> = (0..size).map(leaf).collect();
        let root = compute_leaf_root(&leaves);
        let total = leaves.len();
        for (index, item) in leaves.iter().enumerate() {
            let path = leaf_inclusion_proof(&leaves, index).expect("in bounds");
            assert!(verify_leaf_inclusion(&path, &root, item, index, total));
            assert!(!verify_leaf_inclusion(&path, &root, &leaf(200), index, total));
        }
        assert!(leaf_inclusion_proof(&leaves, total).is_none());
    }
}

#[test]
fn a_sparse_tree_proves_presence_and_absence_against_one_root() {
    let mut tree = SparseMerkleTree::new(16);
    tree.insert(leaf(1), leaf(11));
    tree.insert(leaf(2), leaf(22));
    let root = tree.root();
    let present = tree.prove(&leaf(1));
    assert_eq!(present.value, Some(leaf(11)));
    assert!(SparseMerkleTree::verify_proof(&present, &root, 16));
    let absent = tree.prove(&leaf(3));
    assert_eq!(absent.value, None);
    assert!(SparseMerkleTree::verify_proof(&absent, &root, 16));
    tree.insert(leaf(2), leaf(23));
    assert!(!SparseMerkleTree::verify_proof(&present, &tree.root(), 16));
}
