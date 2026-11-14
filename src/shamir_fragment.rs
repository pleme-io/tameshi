//! Shamir Secret Sharing for threshold Fragment attestation.
//!
//! Implements (k, n) threshold secret sharing over GF(256) for splitting
//! signing keys (or Merkle roots) into n shares where any k shares can
//! reconstruct the original, but k-1 shares reveal nothing.
//!
//! This upgrades the tameshi signing model from 2-of-2 XOR (MockFragmentSigner)
//! to k-of-n threshold (ShamirFragmentSigner). Combined with the fragment
//! extension theorem, the Merkle root can be an additional share.
//!
//! # Reconstructs the key
//!
//! [`ShamirFragmentSigner`] interpolates the whole signing key in memory on every
//! sign and every verify. The shares are k-of-n at rest only. For a key that
//! must never exist as one value in any memory, use
//! [`ThresholdSigner`](crate::threshold::signing::ThresholdSigner): FROST
//! signs with the shares and adds signature shares, never key shares.
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

type Field = vsss_rs::Gf256;

#[inline]
fn gf256_mul(a: u8, b: u8) -> u8 {
    (Field::from(a) * Field::from(b)).0
}

#[inline]
fn gf256_inv(a: u8) -> u8 {
    ff::Field::invert(&Field::from(a))
        .unwrap_or(<Field as ff::Field>::ZERO)
        .0
}

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
        (1..=n)
            .map(|x| Share {
                x,
                y: secret.to_vec(),
            })
            .collect()
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
/// The polynomial coefficients come from the operating system CSPRNG.
///
/// # Panics
/// Panics if k == 0, n < k, or the operating system CSPRNG fails.
#[must_use]
pub fn split(secret: &[u8], k: u8, n: u8) -> Vec<Share> {
    assert!(k > 0, "threshold must be at least 1");
    assert!(n >= k, "n must be >= k");
    let mut coefficients =
        zeroize::Zeroizing::new(vec![0u8; (usize::from(k) - 1) * secret.len()]);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut coefficients);
    split_with_coefficients(secret, k, n, &coefficients)
}

/// Split a secret with caller-supplied random coefficients.
///
/// `random_bytes` holds the `(k-1) * secret.len()` coefficients, in order.
/// The shares are only as secret as these bytes: they must come from a
/// CSPRNG. Use this function for reproducible tests, or when the caller
/// derives the coefficients from its own secret key. [`split`] draws them
/// from the operating system.
///
/// # Panics
/// Panics if k == 0, n < k, or `random_bytes` is shorter than needed.
#[must_use]
pub fn split_deterministic(secret: &[u8], k: u8, n: u8, random_bytes: &[u8]) -> Vec<Share> {
    assert!(k > 0 && n >= k);
    let needed = (usize::from(k) - 1) * secret.len();
    assert!(
        random_bytes.len() >= needed,
        "need {} random bytes, got {}",
        needed,
        random_bytes.len()
    );
    split_with_coefficients(secret, k, n, &random_bytes[..needed])
}

fn split_with_coefficients(secret: &[u8], k: u8, n: u8, coefficients: &[u8]) -> Vec<Share> {
    let degree = usize::from(k) - 1;
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();
    for (index, &secret_byte) in secret.iter().enumerate() {
        let higher = &coefficients[index * degree..(index + 1) * degree];
        for share in &mut shares {
            let x = Field::from(share.x);
            let mut y = Field::from(secret_byte);
            let mut x_pow = x;
            for &coefficient in higher {
                y += Field::from(coefficient) * x_pow;
                x_pow *= x;
            }
            share.y.push(y.0);
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
    assert!(
        shares.iter().all(|s| s.y.len() == len),
        "shares must have equal length"
    );

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
// Shamir Fragment Signer
// =========================================================================

/// Threshold Fragment signer using Shamir Secret Sharing.
///
/// The signing key is split into n shares with threshold k. Any k shares
/// can reconstruct the key and produce a valid signature. k-1 shares
/// reveal zero information about the key.
///
/// # Reconstructs the key
///
/// `sign` and `verify` interpolate the whole 32-byte key from `k` shares in
/// this process's memory, then MAC with BLAKE3 (tagged
/// [`SigningAlgorithm::MockFragment`]). It is kept, and nothing selects it by
/// default. [`ThresholdSigner`](crate::threshold::signing::ThresholdSigner)
/// is the signer that never assembles the key, and the default for new
/// fragments.
///
/// This implements the `MerkleRootSigner` trait so it can be used as a
/// drop-in replacement for `MockFragmentSigner` or `RemoteFragmentSigner`.
pub struct ShamirFragmentSigner {
    signer_id: String,
    shares: Vec<Share>,
    threshold: u8,
}

impl std::fmt::Debug for ShamirFragmentSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShamirFragmentSigner")
            .field("signer_id", &self.signer_id)
            .field("threshold", &self.threshold)
            .field(
                "shares",
                &format!("[{} shares REDACTED]", self.shares.len()),
            )
            .finish()
    }
}

impl ShamirFragmentSigner {
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

    /// Reconstruct the whole signing key from the available shares, in memory.
    fn reconstruct_key(&self) -> [u8; 32] {
        let recovered = reconstruct(&self.shares[..self.threshold as usize]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&recovered);
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

impl MerkleRootSigner for ShamirFragmentSigner {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        let key = self.reconstruct_key();
        let signature = blake3::keyed_hash(&key, &root.0).as_bytes().to_vec();
        Ok(SignedRoot {
            root: root.clone(),
            signature,
            algorithm: SigningAlgorithm::MockFragment, // reuse enum variant
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    async fn verify(&self, signed: &SignedRoot) -> crate::error::Result<bool> {
        let key = self.reconstruct_key();
        Ok(crate::hash::keyed_mac_matches(
            &key,
            &signed.root.0,
            &signed.signature,
        ))
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
            assert_eq!(gf256_mul(a, inv), 1, "a * a^(-1) = 1 for a={a}");
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

    // -- ShamirFragmentSigner --

    #[tokio::test]
    async fn shamir_signer_sign_verify_roundtrip() {
        let signer = ShamirFragmentSigner::for_testing();
        let root = Blake3Hash::digest(b"test-root");
        let signed = signer.sign(&root).await.unwrap();
        assert!(signer.verify(&signed).await.unwrap());
    }

    #[tokio::test]
    async fn shamir_signer_wrong_root_fails() {
        let signer = ShamirFragmentSigner::for_testing();
        let root = Blake3Hash::digest(b"correct-root");
        let mut signed = signer.sign(&root).await.unwrap();
        signed.root = Blake3Hash::digest(b"tampered-root");
        assert!(!signer.verify(&signed).await.unwrap());
    }

    #[tokio::test]
    async fn shamir_signer_deterministic() {
        let signer = ShamirFragmentSigner::for_testing();
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
        let signer_a = ShamirFragmentSigner::from_shares(
            vec![all_shares[0].clone(), all_shares[2].clone()],
            2,
            "signer-a",
        );

        // Signer with shares 2,4 (different 2 of 5)
        let signer_b = ShamirFragmentSigner::from_shares(
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
        let correct_signer = ShamirFragmentSigner::from_shares(all_shares.clone(), 3, "correct");

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
        assert_ne!(
            signed.signature, wrong_sig,
            "below-threshold key must differ"
        );
    }

    #[test]
    fn for_testing_deterministic() {
        let s1 = ShamirFragmentSigner::for_testing();
        let s2 = ShamirFragmentSigner::for_testing();
        assert_eq!(s1.reconstruct_key(), s2.reconstruct_key());
    }

    #[test]
    fn share_count_and_threshold() {
        let signer = ShamirFragmentSigner::for_testing();
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

    const SAMPLES: u32 = 25_600;
    const CHI_SQUARE_LIMIT: f64 = 400.0;

    fn chi_square(counts: &[u32; 256]) -> f64 {
        let expected = f64::from(SAMPLES) / 256.0;
        counts
            .iter()
            .map(|&count| {
                let delta = f64::from(count) - expected;
                delta * delta / expected
            })
            .sum()
    }

    #[test]
    fn field_arithmetic_is_the_branch_free_vsss_gf256() {
        assert_eq!(std::any::type_name::<Field>(), "vsss_rs::gf256::Gf256");
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf256_mul(a, b), (vsss_rs::Gf256(a) * vsss_rs::Gf256(b)).0);
            }
            let expected = Option::<vsss_rs::Gf256>::from(ff::Field::invert(&vsss_rs::Gf256(a)))
                .map_or(0, |inverse| inverse.0);
            assert_eq!(gf256_inv(a), expected);
        }
    }

    #[test]
    fn two_splits_of_one_secret_draw_fresh_coefficients() {
        let secret = [0x5A; 32];
        let first = split(&secret, 3, 5);
        let second = split(&secret, 3, 5);
        assert_ne!(first, second);
        assert_eq!(reconstruct(&first[..3]), secret);
        assert_eq!(reconstruct(&second[2..]), secret);
    }

    #[test]
    fn one_share_below_threshold_is_uniform_for_every_secret() {
        for secret in [0x00u8, 0x01, 0x80, 0xFF] {
            let mut counts = [0u32; 256];
            for _ in 0..SAMPLES {
                let shares = split(&[secret], 2, 3);
                counts[usize::from(shares[1].y[0])] += 1;
            }
            let statistic = chi_square(&counts);
            assert!(
                statistic < CHI_SQUARE_LIMIT,
                "secret {secret:#04x}: chi-square {statistic}"
            );
        }
    }

    #[test]
    fn two_shares_below_threshold_are_jointly_uniform_for_every_secret() {
        for secret in [0x00u8, 0x01, 0x80, 0xFF] {
            let mut counts = [0u32; 256];
            for _ in 0..SAMPLES {
                let shares = split(&[secret], 3, 5);
                let bin = (shares[0].y[0] & 0xF0) | (shares[3].y[0] >> 4);
                counts[usize::from(bin)] += 1;
            }
            let statistic = chi_square(&counts);
            assert!(
                statistic < CHI_SQUARE_LIMIT,
                "secret {secret:#04x}: chi-square {statistic}"
            );
        }
    }
}
