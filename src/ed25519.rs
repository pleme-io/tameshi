//! The one Ed25519 verification every tameshi signature path shares:
//! `crate::signing` and `crate::threshold` alike.

/// Verify an Ed25519 signature over `data` with a 32-byte public key.
/// Returns `false` on any malformed input — never panics, never errors.
///
/// Uses `verify_strict`: it rejects small-order / torsion-component public keys
/// and non-canonical signatures. In a swarm of mutually-untrusting peers that
/// hardening (against signature malleability and key-substitution) is the point.
pub(crate) fn verify_ed25519(data: &[u8], signature: &[u8], verifying_key: &[u8; 32]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(verifying_key) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(data, &sig).is_ok()
}
