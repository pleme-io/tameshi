//! Hash primitive property proofs.
//!
//! Verifies fundamental properties of the abstract hash model:
//! determinism and non-commutativity of combination.

#[cfg(kani)]
mod proofs {
    use crate::Hash;

    /// For any 4-byte input, hashing the same data twice yields identical results.
    ///
    /// This is the most fundamental property: a hash function MUST be deterministic.
    /// Kani exhaustively checks all 2^32 possible 4-byte inputs.
    #[kani::proof]
    fn hash_determinism() {
        let data: [u8; 4] = kani::any();
        let h1 = crate::abstract_hash(&data);
        let h2 = crate::abstract_hash(&data);
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    /// For distinct inputs a and b, combine(a,b) != combine(b,a).
    ///
    /// Non-commutativity is essential for Merkle tree correctness: swapping
    /// children of an internal node MUST produce a different hash, otherwise
    /// tree structure is not authenticated.
    ///
    /// This holds because combine prepends 0x02 and concatenates in order:
    /// `hash(0x02 || a || b)` vs `hash(0x02 || b || a)` see different inputs.
    #[kani::proof]
    fn combine_non_commutative() {
        let a: Hash = kani::any();
        let b: Hash = kani::any();
        kani::assume(a != b);
        let ab = crate::combine(&a, &b);
        let ba = crate::combine(&b, &a);
        assert_ne!(ab, ba, "combine must be non-commutative for distinct inputs");
    }
}
