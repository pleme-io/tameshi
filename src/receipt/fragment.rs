//! The signed attestation fragment: a receipt's leaves, their Merkle root
//! and an Ed25519 [`SignedRoot`] over that root.

use serde::{Deserialize, Serialize};

use super::{B3, ControlLeaf, Receipt, schema_tag};
use crate::canonicalize::canonical_json_bytes;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::merkle::compute_leaf_root;
use crate::signing::{LocalSigner, MerkleRootSigner, SignedRoot, verify_signed_root};

schema_tag!(FragmentSchema, "tameshi-fragment.v1");

/// Where the signing key came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyMode {
    /// The public test key ([`LocalSigner::for_testing`]): integrity only, no
    /// authenticity. The mode a sandboxed build uses, since no secret enters it.
    Test,
    /// A seed read at run time from a file outside the nix store.
    SeedFile,
}

/// A receipt's signed attestation fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationFragment {
    /// Always `tameshi-fragment.v1`.
    pub schema: FragmentSchema,
    /// The digest of the receipt this fragment attests.
    pub receipt_digest: B3,
    /// The receipt's leaves, in control order.
    pub leaves: Vec<ControlLeaf>,
    /// The Merkle root over those leaves.
    pub root: B3,
    /// The signature over `root`.
    pub signed_root: SignedRoot,
    /// The Ed25519 verifying key, 64 lowercase hex digits.
    pub verifying_key: String,
    /// Where the key came from.
    pub key_mode: KeyMode,
}

impl AttestationFragment {
    /// Parse a fragment strictly.
    ///
    /// # Errors
    ///
    /// Refuses unknown fields, a wrong schema and malformed hashes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| TameshiError::InvalidInput(format!("fragment refused: {e}")))
    }

    /// Canonical JSON bytes.
    ///
    /// # Panics
    ///
    /// Never: a fragment always serializes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(self).expect("a fragment always serializes")
    }
}

/// Sign a receipt's leaf root.
///
/// `signed_at` is `SOURCE_DATE_EPOCH` when that is set, so a sandboxed build
/// writes the same fragment every time; the signature covers only the root.
///
/// # Panics
///
/// Never: local Ed25519 signing has no failure path.
#[must_use]
pub fn sign_fragment(
    receipt: &Receipt,
    signer: &LocalSigner,
    key_mode: KeyMode,
) -> AttestationFragment {
    let leaves = receipt.leaves();
    let root = leaf_root(&leaves);
    let mut signed_root =
        futures::executor::block_on(signer.sign(&root)).expect("local Ed25519 signing cannot fail");
    if let Some(at) = source_date_epoch() {
        signed_root.signed_at = at;
    }
    AttestationFragment {
        schema: FragmentSchema,
        receipt_digest: B3(receipt.digest()),
        leaves,
        root: B3(root),
        signed_root,
        verifying_key: const_hex::encode(signer.verifying_key()),
        key_mode,
    }
}

/// The verdict of checking a fragment against its receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FragmentVerdict {
    /// The fragment names this receipt's digest.
    pub digest_matches: bool,
    /// The fragment's leaves are the receipt's leaves.
    pub leaves_match: bool,
    /// The root is the Merkle root of those leaves and is the signed root.
    pub root_matches: bool,
    /// The signature verifies under the fragment's verifying key.
    pub signature_valid: bool,
    /// The verifying key is the trusted key, when one was given.
    pub key_trusted: Option<bool>,
}

impl FragmentVerdict {
    /// Every check held.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.digest_matches
            && self.leaves_match
            && self.root_matches
            && self.signature_valid
            && self.key_trusted != Some(false)
    }
}

/// Check a fragment against the receipt it claims to attest.
#[must_use]
pub fn verify_fragment(
    fragment: &AttestationFragment,
    receipt: &Receipt,
    trusted_key: Option<&[u8; 32]>,
) -> FragmentVerdict {
    let leaves = receipt.leaves();
    let root = leaf_root(&leaves);
    let key = parse_key(&fragment.verifying_key);
    FragmentVerdict {
        digest_matches: fragment.receipt_digest.0 == receipt.digest(),
        leaves_match: fragment.leaves == leaves,
        root_matches: fragment.root.0 == root && fragment.signed_root.root == root,
        signature_valid: key.is_some_and(|k| verify_signed_root(&fragment.signed_root, &k)),
        key_trusted: trusted_key.map(|t| key.as_ref() == Some(t)),
    }
}

/// Parse a 64-hex-digit Ed25519 key or seed.
///
/// # Errors
///
/// Refuses anything but 32 bytes of hex.
pub fn parse_key_hex(text: &str) -> Result<[u8; 32]> {
    parse_key(text.trim())
        .ok_or_else(|| TameshiError::InvalidInput("a key is 64 hex digits (32 bytes)".to_string()))
}

fn parse_key(text: &str) -> Option<[u8; 32]> {
    let bytes = const_hex::decode(text).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn leaf_root(leaves: &[ControlLeaf]) -> Blake3Hash {
    let hashes: Vec<Blake3Hash> = leaves.iter().map(|l| l.leaf.0.clone()).collect();
    compute_leaf_root(&hashes)
}

fn source_date_epoch() -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()?
        .parse::<i64>()
        .ok()?;
    chrono::DateTime::from_timestamp(secs, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::tests::{sample, sample_parts};

    #[test]
    fn a_signed_fragment_verifies_against_its_receipt() {
        let receipt = sample();
        let signer = LocalSigner::for_testing();
        let fragment = sign_fragment(&receipt, &signer, KeyMode::Test);
        let verdict = verify_fragment(&fragment, &receipt, Some(&signer.verifying_key()));
        assert!(verdict.ok(), "{verdict:?}");
        let parsed = AttestationFragment::parse(&fragment.canonical_bytes()).unwrap();
        assert_eq!(parsed, fragment);
    }

    #[test]
    fn a_fragment_does_not_verify_a_different_receipt() {
        let signer = LocalSigner::for_testing();
        let fragment = sign_fragment(&sample(), &signer, KeyMode::Test);
        let mut parts = sample_parts();
        parts.assertions.passed = 9;
        let other = Receipt::new(parts).unwrap();
        let verdict = verify_fragment(&fragment, &other, None);
        assert!(!verdict.digest_matches && !verdict.leaves_match && !verdict.ok());
    }

    #[test]
    fn an_untrusted_key_fails_when_a_trusted_key_is_given() {
        let receipt = sample();
        let fragment = sign_fragment(
            &receipt,
            &LocalSigner::from_seed([7; 32], "x"),
            KeyMode::SeedFile,
        );
        let trusted = LocalSigner::for_testing().verifying_key();
        let verdict = verify_fragment(&fragment, &receipt, Some(&trusted));
        assert!(verdict.signature_valid);
        assert_eq!(verdict.key_trusted, Some(false));
        assert!(!verdict.ok());
    }

    #[test]
    fn a_forged_signature_fails() {
        let receipt = sample();
        let mut fragment = sign_fragment(&receipt, &LocalSigner::for_testing(), KeyMode::Test);
        fragment.signed_root.signature[0] ^= 1;
        assert!(!verify_fragment(&fragment, &receipt, None).signature_valid);
    }
}
