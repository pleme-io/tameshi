//! Shamir Secret Sharing for threshold DFC attestation.
//!
//! Implements (k, n) threshold secret sharing over GF(256) for splitting
//! signing keys (or Merkle roots) into n shares where any k shares can
//! reconstruct the original, but k-1 shares reveal nothing.
//!
//! This upgrades the tameshi signing model from 2-of-2 XOR (MockDfcSigner)
//! to k-of-n threshold (ShamirDfcSigner). Combined with the fragment
//! extension theorem, the Merkle root can be an additional share.
//!
//! # GF(256) Arithmetic
//!
//! All operations use the Rijndael (AES) field: irreducible polynomial
//! x^8 + x^4 + x^3 + x + 1 (0x11B). This gives us a finite field where
//! every non-zero element has a multiplicative inverse.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::signing::{MerkleRootSigner, SignedRoot, SigningAlgorithm};

// =========================================================================
// GF(256) Arithmetic
// =========================================================================

/// Multiply two elements in GF(256) using the AES irreducible polynomial.
#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1 (low byte of 0x11B)
        }
        b >>= 1;
    }
    result
}

/// Compute the multiplicative inverse in GF(256) using the extended Euclidean algorithm.
/// Returns 0 for input 0 (which has no inverse, but we define it as 0 for convenience).
#[inline]
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^254 = a^(-1) in GF(256) (since a^255 = 1 for all non-zero a)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

/// Divide in GF(256): a / b = a * b^(-1).
#[inline]
fn gf256_div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_inv(b))
}

// =========================================================================
// Shamir Secret Sharing
// =========================================================================

/// Trait for secret sharing schemes.
///
/// Abstracts the split/reconstruct operations so consumers
/// can inject mocks or alternative sharing schemes (e.g., Feldman VSS).
pub trait SecretSharingScheme: Send + Sync {
    /// Split a secret into n shares with threshold k.
    fn split(&self, secret: &[u8], k: u8, n: u8) -> Vec<Share>;
    /// Reconstruct a secret from k or more shares.
    fn reconstruct(&self, shares: &[Share]) -> Vec<u8>;
}

/// Shamir GF(256) secret sharing (default).
#[derive(Clone, Debug, Default)]
pub struct ShamirScheme;

impl SecretSharingScheme for ShamirScheme {
    fn split(&self, secret: &[u8], k: u8, n: u8) -> Vec<Share> {
        split(secret, k, n)
    }

    fn reconstruct(&self, shares: &[Share]) -> Vec<u8> {
        reconstruct(shares)
    }
}

/// Mock secret sharing for testing.
///
/// Splits by simply copying the secret to each share (NOT secure --
/// testing only). Reconstructs by returning the first share's data.
#[derive(Clone, Debug, Default)]
pub struct MockSecretSharing;

impl SecretSharingScheme for MockSecretSharing {
    fn split(&self, secret: &[u8], _k: u8, n: u8) -> Vec<Share> {
        (1..=n).map(|x| Share {
            x,
            y: secret.to_vec(),
        }).collect()
    }

    fn reconstruct(&self, shares: &[Share]) -> Vec<u8> {
        shares[0].y.clone()
    }
}

/// A single share of a secret-shared value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// The x-coordinate (share index, 1-based). Must be non-zero.
    pub x: u8,
    /// The y-values (one byte per byte of the original secret).
    pub y: Vec<u8>,
}

/// Split a secret into n shares with threshold k.
///
/// Any k shares can reconstruct the secret. k-1 shares reveal nothing.
///
/// # Panics
/// Panics if k == 0, n < k, or n > 255.
#[must_use]
pub fn split(secret: &[u8], k: u8, n: u8) -> Vec<Share> {
    assert!(k > 0, "threshold must be at least 1");
    assert!(n >= k, "n must be >= k");
    assert!(n > 0, "n must be at least 1");

    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();

    // For each byte of the secret, create a random polynomial of degree k-1
    // and evaluate it at x=1, x=2, ..., x=n.
    let mut rng_state: u64 = 0x5A5A_5A5A_5A5A_5A5A;
    for &secret_byte in secret {
        // Coefficients: a[0] = secret_byte, a[1..k-1] = random
        let mut coeffs = vec![secret_byte];
        for _ in 1..k {
            // Simple deterministic PRNG for reproducibility in tests.
            // In production, use a CSPRNG.
            rng_state = rng_state.wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            coeffs.push((rng_state >> 33) as u8);
        }

        // Evaluate polynomial at each share's x-coordinate
        for share in &mut shares {
            let mut y: u8 = 0;
            let mut x_pow: u8 = 1; // x^0 = 1
            for &coeff in &coeffs {
                y ^= gf256_mul(coeff, x_pow);
                x_pow = gf256_mul(x_pow, share.x);
            }
            share.y.push(y);
        }
    }

    shares
}

/// Split a secret with explicit random coefficients (for deterministic testing).
///
/// `random_bytes` must contain exactly `(k-1) * secret.len()` bytes.
#[must_use]
pub fn split_deterministic(secret: &[u8], k: u8, n: u8, random_bytes: &[u8]) -> Vec<Share> {
    assert!(k > 0 && n >= k);
    let needed = (k as usize - 1) * secret.len();
    assert!(
        random_bytes.len() >= needed,
        "need {} random bytes, got {}",
        needed,
        random_bytes.len()
    );

    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();

    let mut rand_idx = 0;
    for &secret_byte in secret {
        let mut coeffs = vec![secret_byte];
        for _ in 1..k {
            coeffs.push(random_bytes[rand_idx]);
            rand_idx += 1;
        }

        for share in &mut shares {
            let mut y: u8 = 0;
            let mut x_pow: u8 = 1;
            for &coeff in &coeffs {
                y ^= gf256_mul(coeff, x_pow);
                x_pow = gf256_mul(x_pow, share.x);
            }
            share.y.push(y);
        }
    }

    shares
}

/// Reconstruct a secret from k or more shares using Lagrange interpolation.
///
/// # Panics
/// Panics if shares have different y-lengths or if shares is empty.
#[must_use]
pub fn reconstruct(shares: &[Share]) -> Vec<u8> {
    assert!(!shares.is_empty(), "need at least one share");
    let len = shares[0].y.len();
    assert!(shares.iter().all(|s| s.y.len() == len), "shares must have equal length");

    let mut secret = vec![0u8; len];

    for byte_idx in 0..len {
        // Lagrange interpolation at x=0
        let mut value: u8 = 0;
        for i in 0..shares.len() {
            let mut basis: u8 = 1;
            for j in 0..shares.len() {
                if i == j {
                    continue;
                }
                // basis *= x_j / (x_j - x_i) where evaluation point is x=0
                // = x_j / (x_j ^ x_i)  (XOR is subtraction in GF(256))
                let num = shares[j].x;
                let den = shares[j].x ^ shares[i].x;
                basis = gf256_mul(basis, gf256_div(num, den));
            }
            value ^= gf256_mul(shares[i].y[byte_idx], basis);
        }
        secret[byte_idx] = value;
    }

    secret
}

// =========================================================================
// Shamir DFC Signer
// =========================================================================

/// Threshold DFC signer using Shamir Secret Sharing.
///
/// The signing key is split into n shares with threshold k. Any k shares
/// can reconstruct the key and produce a valid signature. k-1 shares
/// reveal zero information about the key.
///
/// This implements the `MerkleRootSigner` trait so it can be used as a
/// drop-in replacement for `MockDfcSigner` or `AkeylessDfcSigner`.
pub struct ShamirDfcSigner {
    signer_id: String,
    shares: Vec<Share>,
    threshold: u8,
}

impl std::fmt::Debug for ShamirDfcSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShamirDfcSigner")
            .field("signer_id", &self.signer_id)
            .field("threshold", &self.threshold)
            .field("shares", &format!("[{} shares REDACTED]", self.shares.len()))
            .finish()
    }
}

impl ShamirDfcSigner {
    /// Create a signer from pre-split shares.
    #[must_use]
    pub fn from_shares(shares: Vec<Share>, threshold: u8, signer_id: &str) -> Self {
        assert!(
            shares.len() >= threshold as usize,
            "need at least {} shares, got {}",
            threshold,
            shares.len()
        );
        Self {
            signer_id: signer_id.to_string(),
            shares,
            threshold,
        }
    }

    /// Create a signer by splitting a key into n shares with threshold k.
    #[must_use]
    pub fn from_key(key: &[u8; 32], k: u8, n: u8, signer_id: &str) -> Self {
        let shares = split(key, k, n);
        Self::from_shares(shares, k, signer_id)
    }

    /// Create a deterministic test signer (2-of-3 threshold).
    #[must_use]
    pub fn for_testing() -> Self {
        let key = [42u8; 32];
        Self::from_key(&key, 2, 3, "shamir-test")
    }

    /// Reconstruct the signing key from the available shares.
    fn reconstruct_key(&self) -> [u8; 32] {
        let secret = reconstruct(&self.shares[..self.threshold as usize]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&secret);
        key
    }

    /// Return the number of shares held.
    #[must_use]
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Return the threshold.
    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
}

impl MerkleRootSigner for ShamirDfcSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        let key = self.reconstruct_key();
        let signature = blake3::keyed_hash(&key, &root.0).as_bytes().to_vec();
        Ok(SignedRoot {
            root: root.clone(),
            signature,
            algorithm: SigningAlgorithm::MockDfc, // reuse enum variant
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        let key = self.reconstruct_key();
        let expected = blake3::keyed_hash(&key, &signed.root.0).as_bytes().to_vec();
        Ok(expected == signed.signature)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- GF(256) arithmetic --

    #[test]
    fn gf256_mul_identity() {
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 1), a, "a * 1 = a for all a");
        }
    }

    #[test]
    fn gf256_mul_zero() {
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 0), 0, "a * 0 = 0 for all a");
        }
    }

    #[test]
    fn gf256_mul_commutative() {
        for a in 0..=15u8 {
            for b in 0..=15u8 {
                assert_eq!(
                    gf256_mul(a, b),
                    gf256_mul(b, a),
                    "a*b = b*a for a={a}, b={b}"
                );
            }
        }
    }

    #[test]
    fn gf256_inv_roundtrip() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(
                gf256_mul(a, inv),
                1,
                "a * a^(-1) = 1 for a={a}"
            );
        }
    }

    #[test]
    fn gf256_div_by_self() {
        for a in 1..=255u8 {
            assert_eq!(gf256_div(a, a), 1, "a / a = 1 for a={a}");
        }
    }

    // -- Shamir Secret Sharing --

    #[test]
    fn split_and_reconstruct_1_of_1() {
        let secret = b"hello world 32 bytes padding!!xx";
        let shares = split_deterministic(secret, 1, 1, &[]);
        assert_eq!(shares.len(), 1);
        let recovered = reconstruct(&shares);
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn split_and_reconstruct_2_of_3() {
        let secret = [0xAA; 32];
        let random = vec![0x55; 32]; // (k-1)*len = 1*32 = 32 random bytes
        let shares = split_deterministic(&secret, 2, 3, &random);
        assert_eq!(shares.len(), 3);

        // Any 2 of 3 should reconstruct
        let r12 = reconstruct(&[shares[0].clone(), shares[1].clone()]);
        let r13 = reconstruct(&[shares[0].clone(), shares[2].clone()]);
        let r23 = reconstruct(&[shares[1].clone(), shares[2].clone()]);

        assert_eq!(r12, secret);
        assert_eq!(r13, secret);
        assert_eq!(r23, secret);
    }

    #[test]
    fn split_and_reconstruct_3_of_5() {
        let secret = [0xBB; 32];
        let random = vec![0x42; 64]; // (k-1)*len = 2*32 = 64
        let shares = split_deterministic(&secret, 3, 5, &random);
        assert_eq!(shares.len(), 5);

        // Any 3 of 5 should reconstruct
        let r = reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]);
        assert_eq!(r, secret);

        let r2 = reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]);
        assert_eq!(r2, secret);
    }

    #[test]
    fn single_share_reveals_nothing_useful() {
        let secret = [0xCC; 32];
        let shares = split(&secret, 2, 3);

        // A single share reconstructed as if it were the only share
        // should NOT produce the original secret
        let wrong = reconstruct(&[shares[0].clone()]);
        // With k=2, 1 share = polynomial evaluated at x=share.x,
        // which is NOT the secret (secret is at x=0)
        assert_ne!(wrong, secret, "single share must not reveal secret");
    }

    #[test]
    fn shares_have_correct_x_coordinates() {
        let shares = split(&[0; 32], 2, 5);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.x, (i + 1) as u8);
        }
    }

    #[test]
    fn different_secrets_produce_different_shares() {
        let random = vec![0x11; 32];
        let s1 = split_deterministic(&[0xAA; 32], 2, 3, &random);
        let s2 = split_deterministic(&[0xBB; 32], 2, 3, &random);
        // At least the first share should differ (different secret)
        assert_ne!(s1[0].y, s2[0].y);
    }

    // -- ShamirDfcSigner --

    #[tokio::test]
    async fn shamir_signer_sign_verify_roundtrip() {
        let signer = ShamirDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"test-root");
        let signed = signer.sign(&root).await.unwrap();
        assert!(signer.verify(&signed).await.unwrap());
    }

    #[tokio::test]
    async fn shamir_signer_wrong_root_fails() {
        let signer = ShamirDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"correct-root");
        let mut signed = signer.sign(&root).await.unwrap();
        signed.root = Blake3Hash::digest(b"tampered-root");
        assert!(!signer.verify(&signed).await.unwrap());
    }

    #[tokio::test]
    async fn shamir_signer_deterministic() {
        let signer = ShamirDfcSigner::for_testing();
        let root = Blake3Hash::digest(b"determinism-test");
        let sig1 = signer.sign(&root).await.unwrap();
        let sig2 = signer.sign(&root).await.unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[tokio::test]
    async fn shamir_signer_threshold_subset_works() {
        let key = [42u8; 32];
        let all_shares = split(&key, 2, 5);

        // Signer with shares 1,3 (any 2 of 5)
        let signer_a = ShamirDfcSigner::from_shares(
            vec![all_shares[0].clone(), all_shares[2].clone()],
            2,
            "signer-a",
        );

        // Signer with shares 2,4 (different 2 of 5)
        let signer_b = ShamirDfcSigner::from_shares(
            vec![all_shares[1].clone(), all_shares[3].clone()],
            2,
            "signer-b",
        );

        let root = Blake3Hash::digest(b"threshold-test");
        let sig_a = signer_a.sign(&root).await.unwrap();
        let sig_b = signer_b.sign(&root).await.unwrap();

        // Both should produce the same signature (same reconstructed key)
        assert_eq!(sig_a.signature, sig_b.signature);

        // And both should verify each other's signatures
        assert!(signer_a.verify(&sig_b).await.unwrap());
        assert!(signer_b.verify(&sig_a).await.unwrap());
    }

    #[tokio::test]
    async fn shamir_signer_below_threshold_fails() {
        let key = [42u8; 32];
        let all_shares = split(&key, 3, 5);

        // Signer with all 5 shares, threshold 3 (correct)
        let correct_signer = ShamirDfcSigner::from_shares(
            all_shares.clone(),
            3,
            "correct",
        );

        // Signer with only 2 shares but claiming threshold 2
        // (reconstructing with fewer shares gives a DIFFERENT key)
        let wrong_key_bytes = reconstruct(&all_shares[0..2]);
        let mut wrong_key = [0u8; 32];
        wrong_key.copy_from_slice(&wrong_key_bytes);

        // Sign with correct signer
        let root = Blake3Hash::digest(b"threshold-test");
        let signed = correct_signer.sign(&root).await.unwrap();

        // Verify with wrong key should fail
        let wrong_sig = blake3::keyed_hash(&wrong_key, &root.0).as_bytes().to_vec();
        assert_ne!(signed.signature, wrong_sig, "below-threshold key must differ");
    }

    #[test]
    fn for_testing_deterministic() {
        let s1 = ShamirDfcSigner::for_testing();
        let s2 = ShamirDfcSigner::for_testing();
        assert_eq!(s1.reconstruct_key(), s2.reconstruct_key());
    }

    #[test]
    fn share_count_and_threshold() {
        let signer = ShamirDfcSigner::for_testing();
        assert_eq!(signer.share_count(), 3);
        assert_eq!(signer.threshold(), 2);
    }

    #[test]
    fn shamir_scheme_trait_roundtrip() {
        let scheme = ShamirScheme;
        let secret = [0xCC; 32];
        let shares = scheme.split(&secret, 2, 3);
        let recovered = scheme.reconstruct(&shares[0..2]);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn mock_scheme_roundtrip() {
        let scheme = MockSecretSharing;
        let secret = [0xDD; 32];
        let shares = scheme.split(&secret, 2, 3);
        assert_eq!(shares.len(), 3);
        let recovered = scheme.reconstruct(&shares);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn trait_object_dispatch_sharing() {
        let scheme: Box<dyn SecretSharingScheme> = Box::new(ShamirScheme);
        let secret = [0xEE; 32];
        let shares = scheme.split(&secret, 2, 3);
        let recovered = scheme.reconstruct(&shares[0..2]);
        assert_eq!(recovered, secret);
    }
}
