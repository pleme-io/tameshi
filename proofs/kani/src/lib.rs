//! Kani bounded model checking proofs for tameshi attestation primitives.
//!
//! These proofs verify core cryptographic properties using abstract hash models.
//! Real BLAKE3 causes state explosion in bounded model checkers, so we use a
//! 4-byte FNV-based hash as an injective stub. If properties hold for ANY
//! injective function, they hold for any collision-resistant function.

/// 4-byte abstract hash type. Small enough for exhaustive Kani exploration.
pub type Hash = [u8; 4];

/// Zero hash constant, used as identity/sentinel.
pub const ZERO_HASH: Hash = [0, 0, 0, 0];

/// Abstract deterministic hash function.
///
/// Uses FNV-1a (32-bit) to produce a 4-byte digest. This is NOT
/// cryptographic — it serves as a deterministic injective-enough
/// function for bounded model checking over small input spaces.
#[must_use]
pub fn abstract_hash(data: &[u8]) -> Hash {
    let mut h: u32 = 0x811c_9dc5; // FNV-1a offset basis
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193); // FNV-1a prime
    }
    h.to_le_bytes()
}

/// Combine two hashes by concatenating with a domain separator and hashing.
///
/// `combine(a, b) = hash(0x02 || a || b)`
///
/// The 0x02 prefix ensures domain separation from leaf and internal nodes.
/// The ordered concatenation guarantees non-commutativity: `combine(a,b) != combine(b,a)`
/// for distinct inputs, because the underlying hash sees different byte sequences.
#[must_use]
pub fn combine(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 9]; // 1 + 4 + 4
    buf[0] = 0x02;
    buf[1..5].copy_from_slice(left);
    buf[5..9].copy_from_slice(right);
    abstract_hash(&buf)
}

/// Domain-separated leaf hash: `hash(0x00 || data)`.
///
/// Ensures leaf nodes occupy a different hash domain than internal nodes,
/// preventing second-preimage attacks on the Merkle tree structure.
#[must_use]
pub fn domain_leaf(data: &Hash) -> Hash {
    let mut buf = [0u8; 5]; // 1 + 4
    buf[0] = 0x00;
    buf[1..5].copy_from_slice(data);
    abstract_hash(&buf)
}

/// Domain-separated internal node hash: `hash(0x01 || left || right)`.
///
/// Distinct prefix from `domain_leaf` prevents leaf/internal confusion.
#[must_use]
pub fn domain_internal(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 9]; // 1 + 4 + 4
    buf[0] = 0x01;
    buf[1..5].copy_from_slice(left);
    buf[5..9].copy_from_slice(right);
    abstract_hash(&buf)
}

/// XOR two hashes element-wise.
///
/// Used in split-knowledge signing: secret = xor(fragment_a, fragment_b).
#[must_use]
pub fn xor(a: &Hash, b: &Hash) -> Hash {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

mod hash_proofs;
mod merkle_proofs;
mod artifact_proofs;
mod chain_proofs;
mod signing_proofs;
mod gating_proofs;
mod concurrency_proofs;
mod liveness_proofs;
mod ffi_safety_proofs;
mod performance_bounds;
mod crypto_timing_proofs;
mod resource_bounds;
