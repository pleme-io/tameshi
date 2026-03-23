//! Split-knowledge signing property proofs.
//!
//! Tameshi uses XOR-based secret splitting for split-knowledge signing:
//! a secret key is split into fragments, and recombined via XOR.
//! These proofs verify the algebraic properties that make this secure.

#[cfg(kani)]
mod proofs {
    use crate::Hash;

    /// XOR is a bijection: `xor(xor(a, b), b) == a` for all a, b.
    ///
    /// This is the recoverability property: given one fragment and the XOR
    /// combination, the other fragment can always be recovered. This is
    /// essential for split-knowledge key management — both fragments are
    /// needed, and either can reconstruct the secret given the other.
    #[kani::proof]
    fn xor_bijection() {
        let a: Hash = kani::any();
        let b: Hash = kani::any();

        let combined = crate::xor(&a, &b);
        let recovered = crate::xor(&combined, &b);

        assert_eq!(
            a, recovered,
            "XOR must be a bijection: xor(xor(a, b), b) == a"
        );
    }

    /// Different fragments produce different signing keys.
    ///
    /// If fragment a1 != a2, then `hash(xor(a1, b)) != hash(xor(a2, b))`.
    /// This ensures that each unique split produces a unique derived key,
    /// preventing two different key holders from accidentally generating
    /// the same signing capability.
    #[kani::proof]
    fn split_knowledge_key_changes() {
        let a1: Hash = kani::any();
        let a2: Hash = kani::any();
        let b: Hash = kani::any();
        kani::assume(a1 != a2);

        let key1 = crate::abstract_hash(&crate::xor(&a1, &b));
        let key2 = crate::abstract_hash(&crate::xor(&a2, &b));

        assert_ne!(
            key1, key2,
            "different fragments must produce different signing keys"
        );
    }
}
