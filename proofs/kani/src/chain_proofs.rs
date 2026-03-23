//! Attestation chain property proofs.
//!
//! Models tameshi's hash chain as a sequence of entries where each entry
//! contains a content hash and a back-pointer (prev_hash) to the previous
//! entry's computed hash. Verifies linkage invariants and tamper detection.

use crate::Hash;

/// A single entry in the attestation chain.
#[derive(Clone, Copy)]
struct ChainEntry {
    /// Hash of the content this entry attests.
    content: Hash,
    /// Hash of the previous entry (ZERO_HASH for the genesis entry).
    prev_hash: Hash,
}

impl ChainEntry {
    /// Compute this entry's hash: `combine(prev_hash, content)`.
    fn entry_hash(&self) -> Hash {
        crate::combine(&self.prev_hash, &self.content)
    }
}

/// Build a 4-entry chain from content hashes.
///
/// Returns the chain entries with correctly linked prev_hash pointers.
fn build_chain(contents: &[Hash; 4]) -> [ChainEntry; 4] {
    let e0 = ChainEntry {
        content: contents[0],
        prev_hash: crate::ZERO_HASH,
    };
    let e1 = ChainEntry {
        content: contents[1],
        prev_hash: e0.entry_hash(),
    };
    let e2 = ChainEntry {
        content: contents[2],
        prev_hash: e1.entry_hash(),
    };
    let e3 = ChainEntry {
        content: contents[3],
        prev_hash: e2.entry_hash(),
    };
    [e0, e1, e2, e3]
}

/// Verify chain linkage: each entry's prev_hash equals the previous entry's hash.
fn verify_linkage(chain: &[ChainEntry; 4]) -> bool {
    chain[0].prev_hash == crate::ZERO_HASH
        && chain[1].prev_hash == chain[0].entry_hash()
        && chain[2].prev_hash == chain[1].entry_hash()
        && chain[3].prev_hash == chain[2].entry_hash()
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// A correctly built chain always passes linkage verification.
    ///
    /// For any 4 content hashes, `build_chain` produces entries with valid
    /// back-pointers. This verifies the chain construction invariant that
    /// tameshi relies on for append-only attestation logs.
    #[kani::proof]
    fn chain_linkage_invariant() {
        let contents: [Hash; 4] = kani::any();
        let chain = build_chain(&contents);

        assert!(
            verify_linkage(&chain),
            "correctly built chain must pass linkage verification"
        );
    }

    /// Tampering with any entry's content breaks the linkage of subsequent entries.
    ///
    /// If an attacker modifies the content of entry i (where i < 3), then
    /// entry i's hash changes, which invalidates entry i+1's prev_hash.
    /// This is the core tamper-detection property of hash chains.
    #[kani::proof]
    fn chain_tamper_detection() {
        let contents: [Hash; 4] = kani::any();
        let chain = build_chain(&contents);

        // Pick an entry to tamper (0..2, since entry 3 has no successor to break)
        let tamper_idx: usize = kani::any();
        kani::assume(tamper_idx < 3);

        let tamper_content: Hash = kani::any();
        kani::assume(tamper_content != contents[tamper_idx]);

        // Tamper the content but leave the rest of the chain unchanged
        let mut tampered = chain;
        tampered[tamper_idx].content = tamper_content;

        // The tampered entry's hash differs from what the next entry expects
        let tampered_hash = tampered[tamper_idx].entry_hash();
        let expected_prev = tampered[tamper_idx + 1].prev_hash;

        assert_ne!(
            tampered_hash, expected_prev,
            "tampering with entry content must break chain linkage"
        );
    }
}
