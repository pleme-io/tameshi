//! Node-salted attestation pipeline.
//!
//! Combines the certification artifact with node-specific salt
//! and optional Pedersen blinding before pushing to the BPF map.

use crate::bpf_loader::BpfMapOps;
use crate::hash::Blake3Hash;
use crate::node_salt::{NodeSalt, salted_root};
use crate::pedersen::{Commitment, Opening, commit_for_bpf};

/// Attest a binary with node-specific salting.
/// The salted root binds the attestation to this specific node.
pub fn attest_binary_salted(
    maps: &dyn BpfMapOps,
    binary_hash: &Blake3Hash,
    _poms_hash: &Blake3Hash,
    composed_root: &Blake3Hash,
    salt: &dyn NodeSalt,
) -> Result<(), String> {
    let sr = salted_root(composed_root, &salt.salt());
    maps.push_poms_to_kernel(&binary_hash.0, &sr.0, 0)
}

/// Attest a binary with Pedersen commitment (hiding the root).
pub fn attest_binary_committed(
    maps: &dyn BpfMapOps,
    binary_hash: &Blake3Hash,
    composed_root: &Blake3Hash,
    blinding: &Blake3Hash,
) -> Result<(Commitment, Opening), String> {
    let commitment = commit_for_bpf(composed_root, blinding);
    maps.push_poms_to_kernel(&binary_hash.0, &commitment.hash.0, 0)?;
    let opening = Opening {
        value: composed_root.clone(),
        blinding: blinding.clone(),
    };
    Ok((commitment, opening))
}

/// Attest with both salting AND commitment.
pub fn attest_binary_salted_committed(
    maps: &dyn BpfMapOps,
    binary_hash: &Blake3Hash,
    composed_root: &Blake3Hash,
    salt: &dyn NodeSalt,
    blinding: &Blake3Hash,
) -> Result<(Commitment, Opening), String> {
    let sr = salted_root(composed_root, &salt.salt());
    let commitment = commit_for_bpf(&sr, blinding);
    maps.push_poms_to_kernel(&binary_hash.0, &commitment.hash.0, 0)?;
    let opening = Opening {
        value: sr,
        blinding: blinding.clone(),
    };
    Ok((commitment, opening))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_loader::MockBpfMaps;
    use crate::node_salt::MockTpmSalt;
    use crate::pedersen::verify_commitment;

    #[test]
    fn salted_attest_succeeds() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"binary-content");
        let poms = Blake3Hash::digest(b"poms-data");
        let root = Blake3Hash::digest(b"composed-root");
        let salt = MockTpmSalt::from_node_name("test");

        attest_binary_salted(&maps, &binary, &poms, &root, &salt).unwrap();
        assert!(maps.lookup_poms(&binary.0).is_some());
    }

    #[test]
    fn salted_attest_different_salt() {
        let maps_a = MockBpfMaps::new();
        let maps_b = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"binary-content");
        let poms = Blake3Hash::digest(b"poms-data");
        let root = Blake3Hash::digest(b"composed-root");
        let salt_a = MockTpmSalt::from_node_name("node-a");
        let salt_b = MockTpmSalt::from_node_name("node-b");

        attest_binary_salted(&maps_a, &binary, &poms, &root, &salt_a).unwrap();
        attest_binary_salted(&maps_b, &binary, &poms, &root, &salt_b).unwrap();

        let entry_a = maps_a.lookup_poms(&binary.0).unwrap();
        let entry_b = maps_b.lookup_poms(&binary.0).unwrap();
        assert_ne!(entry_a.poms_hash, entry_b.poms_hash, "different salts must produce different map entries");
    }

    #[test]
    fn committed_attest_succeeds() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"binary-content");
        let root = Blake3Hash::digest(b"composed-root");
        let blinding = Blake3Hash::digest(b"blinding-factor");

        let (_commitment, _opening) =
            attest_binary_committed(&maps, &binary, &root, &blinding).unwrap();
        assert!(maps.lookup_poms(&binary.0).is_some());
    }

    #[test]
    fn committed_attest_opening_verifies() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"binary-content");
        let root = Blake3Hash::digest(b"composed-root");
        let blinding = Blake3Hash::digest(b"blinding-factor");

        let (commitment, opening) =
            attest_binary_committed(&maps, &binary, &root, &blinding).unwrap();
        assert!(verify_commitment(&commitment, &opening));
    }

    #[test]
    fn salted_committed_attest() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"binary-content");
        let root = Blake3Hash::digest(b"composed-root");
        let salt = MockTpmSalt::from_node_name("test");
        let blinding = Blake3Hash::digest(b"blinding-factor");

        let (_commitment, _opening) =
            attest_binary_salted_committed(&maps, &binary, &root, &salt, &blinding).unwrap();
        assert!(maps.lookup_poms(&binary.0).is_some());
    }

    #[test]
    fn salted_committed_opening_verifies() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"binary-content");
        let root = Blake3Hash::digest(b"composed-root");
        let salt = MockTpmSalt::from_node_name("test");
        let blinding = Blake3Hash::digest(b"blinding-factor");

        let (commitment, opening) =
            attest_binary_salted_committed(&maps, &binary, &root, &salt, &blinding).unwrap();
        assert!(verify_commitment(&commitment, &opening));
    }
}
