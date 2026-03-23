//! Artifact composition property proofs.
//!
//! Models tameshi's artifact attestation as a 3-leaf Merkle tree:
//! source hash, build hash, and config hash compose into an artifact root.
//! Verifies consistency and tamper detection.

use crate::Hash;

/// A 3-leaf artifact attestation.
///
/// In tameshi, an artifact is composed from multiple attestation layers.
/// This model uses 3 leaves representing source, build, and config hashes.
///
/// ```text
///      artifact_root
///       /          \
///   n_source_build  leaf_config
///    /         \
/// leaf_source  leaf_build
/// ```
struct Artifact {
    source: Hash,
    build: Hash,
    config: Hash,
}

impl Artifact {
    /// Compute the artifact root from its 3 component hashes.
    fn root(&self) -> Hash {
        let l_source = crate::domain_leaf(&self.source);
        let l_build = crate::domain_leaf(&self.build);
        let l_config = crate::domain_leaf(&self.config);

        let n_sb = crate::domain_internal(&l_source, &l_build);
        crate::domain_internal(&n_sb, &l_config)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Computing the artifact root twice from the same inputs yields identical results.
    ///
    /// This verifies that artifact composition is a pure function: given the same
    /// source, build, and config hashes, the artifact root is always the same.
    /// This is the foundation of reproducible attestation.
    #[kani::proof]
    fn compose_verify_roundtrip() {
        let source: Hash = kani::any();
        let build: Hash = kani::any();
        let config: Hash = kani::any();

        let artifact = Artifact {
            source,
            build,
            config,
        };

        let root1 = artifact.root();
        let root2 = artifact.root();

        assert_eq!(
            root1, root2,
            "artifact composition must be deterministic"
        );
    }

    /// Tampering with any of the 3 artifact components changes the root.
    ///
    /// Kani symbolically chooses which component (source, build, or config)
    /// to tamper with and what value to change it to. The root must differ.
    #[kani::proof]
    fn tamper_any_leaf() {
        let source: Hash = kani::any();
        let build: Hash = kani::any();
        let config: Hash = kani::any();

        let original = Artifact {
            source,
            build,
            config,
        };
        let original_root = original.root();

        let which: u8 = kani::any();
        kani::assume(which < 3);
        let tamper_value: Hash = kani::any();

        let tampered = match which {
            0 => {
                kani::assume(tamper_value != source);
                Artifact {
                    source: tamper_value,
                    build,
                    config,
                }
            }
            1 => {
                kani::assume(tamper_value != build);
                Artifact {
                    source,
                    build: tamper_value,
                    config,
                }
            }
            _ => {
                kani::assume(tamper_value != config);
                Artifact {
                    source,
                    build,
                    config: tamper_value,
                }
            }
        };

        assert_ne!(
            original_root,
            tampered.root(),
            "tampering with any artifact component must change the root"
        );
    }
}
