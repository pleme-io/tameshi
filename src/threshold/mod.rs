//! Threshold Ed25519 signing that never assembles the signing key.
//!
//! FROST(Ed25519, SHA-512) from RFC 9591, through the Zcash Foundation
//! `frost-ed25519` crate, behind tameshi's own types. A group of `n`
//! participants holds one key share each. Any `k` of them sign together in
//! two rounds, and the coordinator adds their signature shares into one
//! ordinary RFC 8032 Ed25519 signature under the group's 32-byte verifying
//! key. [`verify_signed_root`](crate::signing::verify_signed_root),
//! [`verify_fragment`](crate::receipt::fragment::verify_fragment) and any
//! Ed25519 verifier accept it unchanged.
//!
//! The group secret is never one scalar in any memory:
//!
//! - [`keygen::dkg`] generates the shares so that no participant ever holds
//!   the secret. Each one samples its own polynomial and keeps the sum of what
//!   it receives.
//! - Signing adds signature shares, never key shares. The second round
//!   consumes the nonces, so a commitment signs once.
//! - This module names frost items only from per-file allowlists, and no
//!   allowlist holds an item that interpolates, splits or holds a whole key.
//!   The `audit` tests read this module's source to keep it so.
//!
//! [`keygen::trusted_dealer`] is the test path: its dealer samples the
//! secret before it splits it.
//!
//! The protocol, with the type each step sends:
//!
//! 1. each signer calls [`signing::commit`] and sends its [`signing::Commitment`];
//! 2. the coordinator builds a [`signing::SigningRequest`] from at least `k`
//!    commitments, and refuses fewer;
//! 3. each signer answers with a [`signing::SignatureShare`] from [`signing::sign`];
//! 4. the coordinator calls [`signing::aggregate`], which refuses a forged
//!    share and names its participant.
//!
//! [`signing::ThresholdSigner`] runs the rounds over any
//! [`signing::SigningParty`] and is a [`MerkleRootSigner`](crate::signing::MerkleRootSigner).
//! A [`signing::LocalParty`] holds its share in this process: k local parties
//! in one process never compute the secret, but one memory then holds k
//! shares. To keep every share on its own machine, implement
//! [`signing::SigningParty`] over a transport that carries the round messages,
//! which all serialize.

pub mod keygen;
pub mod signing;

#[cfg(test)]
mod audit;
#[cfg(test)]
mod tests;

use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Why a threshold operation was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThresholdError {
    /// A group needs `2 <= k <= n`.
    #[error("a threshold group needs 2 <= k <= n, got {min_signers}-of-{max_signers}")]
    InvalidParams {
        /// The requested `k`.
        min_signers: u16,
        /// The requested `n`.
        max_signers: u16,
    },
    /// Participant indices start at 1.
    #[error("a participant index is 1 or more, got {0}")]
    InvalidParticipant(u16),
    /// Fewer than `k` signers took part.
    #[error("{have} signers cannot sign for a group that needs {need}")]
    BelowThreshold {
        /// How many signers took part.
        have: usize,
        /// The group's `k`.
        need: u16,
    },
    /// A participant appears twice in one round.
    #[error("participant {0} appears twice")]
    DuplicateParticipant(ParticipantId),
    /// A participant is not a member of the group.
    #[error("participant {0} is not in the group")]
    UnknownParticipant(ParticipantId),
    /// Signature shares that do not verify under their participants' shares.
    #[error("signature shares from participants {culprits:?} do not verify")]
    InvalidShares {
        /// The participants whose shares failed.
        culprits: Vec<ParticipantId>,
    },
    /// The aggregate is not a valid Ed25519 signature under the group key.
    #[error("the aggregate is not a valid signature under the group key")]
    InvalidSignature,
    /// A party was asked to sign without a commitment outstanding.
    #[error("participant {0} holds no commitment to sign with")]
    NoPendingCommitment(ParticipantId),
    /// A request does not match the commitment the party made.
    #[error("participant {0} committed to a different signing session")]
    SessionMismatch(ParticipantId),
    /// A key share belongs to a different group key.
    #[error("participant {0} holds a share of a different group")]
    GroupMismatch(ParticipantId),
    /// Key generation refused a package.
    #[error("key generation refused participants {culprits:?}: {reason}")]
    KeyGeneration {
        /// The participants whose packages failed, when frost can name them.
        culprits: Vec<ParticipantId>,
        /// What frost reported.
        reason: String,
    },
    /// Any other refusal from the protocol.
    #[error("the threshold protocol refused: {0}")]
    Protocol(String),
}

/// A participant's index in a group: 1 to `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct ParticipantId(u16);

impl ParticipantId {
    /// The participant with this index.
    ///
    /// # Errors
    ///
    /// Refuses 0.
    pub fn new(index: u16) -> Result<Self, ThresholdError> {
        if index == 0 {
            Err(ThresholdError::InvalidParticipant(index))
        } else {
            Ok(Self(index))
        }
    }

    /// The index.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }

    fn identifier(self) -> frost::Identifier {
        frost::Identifier::try_from(self.0).expect("a non-zero index is a frost identifier")
    }

    fn from_identifier(identifier: &frost::Identifier) -> Result<Self, ThresholdError> {
        let bytes = identifier.serialize();
        let index = match bytes.as_slice() {
            [low, high, rest @ ..] if rest.iter().all(|b| *b == 0) => {
                u16::from_le_bytes([*low, *high])
            }
            _ => 0,
        };
        let participant = Self::new(index)?;
        if participant.identifier() == *identifier {
            Ok(participant)
        } else {
            Err(ThresholdError::InvalidParticipant(index))
        }
    }
}

impl TryFrom<u16> for ParticipantId {
    type Error = ThresholdError;

    fn try_from(index: u16) -> Result<Self, ThresholdError> {
        Self::new(index)
    }
}

impl From<ParticipantId> for u16 {
    fn from(participant: ParticipantId) -> u16 {
        participant.0
    }
}

impl std::fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A `k`-of-`n` threshold: any `k` of the `n` participants sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawParams", into = "RawParams")]
pub struct ThresholdParams {
    min_signers: u16,
    max_signers: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParams {
    min_signers: u16,
    max_signers: u16,
}

impl TryFrom<RawParams> for ThresholdParams {
    type Error = ThresholdError;

    fn try_from(raw: RawParams) -> Result<Self, ThresholdError> {
        Self::new(raw.min_signers, raw.max_signers)
    }
}

impl From<ThresholdParams> for RawParams {
    fn from(params: ThresholdParams) -> RawParams {
        RawParams {
            min_signers: params.min_signers,
            max_signers: params.max_signers,
        }
    }
}

impl ThresholdParams {
    /// A `min_signers`-of-`max_signers` threshold.
    ///
    /// # Errors
    ///
    /// Refuses anything but `2 <= min_signers <= max_signers`: a 1-of-n group
    /// gives every participant the whole key.
    pub fn new(min_signers: u16, max_signers: u16) -> Result<Self, ThresholdError> {
        if min_signers < 2 || min_signers > max_signers {
            return Err(ThresholdError::InvalidParams {
                min_signers,
                max_signers,
            });
        }
        Ok(Self {
            min_signers,
            max_signers,
        })
    }

    /// `k`: how many participants must sign.
    #[must_use]
    pub fn min_signers(self) -> u16 {
        self.min_signers
    }

    /// `n`: how many participants hold a share.
    #[must_use]
    pub fn max_signers(self) -> u16 {
        self.max_signers
    }

    /// Every participant, 1 to `n`.
    pub fn participants(self) -> impl Iterator<Item = ParticipantId> {
        (1..=self.max_signers).map(ParticipantId)
    }

    fn admits(self, participant: ParticipantId) -> Result<(), ThresholdError> {
        if participant.0 <= self.max_signers {
            Ok(())
        } else {
            Err(ThresholdError::UnknownParticipant(participant))
        }
    }
}

/// One participant's secret share of a group key.
///
/// The share alone signs nothing: [`signing::sign`] makes a signature share,
/// and `k` of those make a signature.
pub struct KeyShare {
    participant: ParticipantId,
    package: frost::keys::KeyPackage,
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("participant", &self.participant)
            .field("min_signers", self.package.min_signers())
            .field("share", &"REDACTED")
            .finish()
    }
}

impl KeyShare {
    fn new(package: frost::keys::KeyPackage) -> Result<Self, ThresholdError> {
        Ok(Self {
            participant: ParticipantId::from_identifier(package.identifier())?,
            package,
        })
    }

    /// The participant holding this share.
    #[must_use]
    pub fn participant(&self) -> ParticipantId {
        self.participant
    }

    /// The group's `k`.
    #[must_use]
    pub fn min_signers(&self) -> u16 {
        *self.package.min_signers()
    }

    /// The group's 32-byte Ed25519 verifying key.
    #[must_use]
    pub fn group_key(&self) -> [u8; 32] {
        key_bytes(self.package.verifying_key())
    }

    /// The share as bytes, for the participant's own storage.
    ///
    /// # Errors
    ///
    /// Refuses when frost cannot encode the share.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, ThresholdError> {
        self.package
            .serialize()
            .map(Zeroizing::new)
            .map_err(refused)
    }

    /// A share read back from [`KeyShare::to_bytes`].
    ///
    /// # Errors
    ///
    /// Refuses bytes that are not a share.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        Self::new(frost::keys::KeyPackage::deserialize(bytes).map_err(refused)?)
    }

    fn package(&self) -> &frost::keys::KeyPackage {
        &self.package
    }
}

/// A group's public key material: the verifying key and each participant's
/// verifying share. It holds no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKey {
    params: ThresholdParams,
    package: frost::keys::PublicKeyPackage,
}

impl GroupKey {
    fn new(package: frost::keys::PublicKeyPackage) -> Result<Self, ThresholdError> {
        let min_signers = package.min_signers().ok_or_else(|| {
            ThresholdError::Protocol("the group key names no threshold".to_string())
        })?;
        let max_signers = u16::try_from(package.verifying_shares().len())
            .map_err(|_| ThresholdError::Protocol("more than 65535 participants".to_string()))?;
        let params = ThresholdParams::new(min_signers, max_signers)?;
        for identifier in package.verifying_shares().keys() {
            params.admits(ParticipantId::from_identifier(identifier)?)?;
        }
        Ok(Self { params, package })
    }

    /// The group's threshold.
    #[must_use]
    pub fn params(&self) -> ThresholdParams {
        self.params
    }

    /// The group's 32-byte Ed25519 verifying key: what verifiers trust.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        key_bytes(self.package.verifying_key())
    }

    /// Whether this participant is a member.
    #[must_use]
    pub fn has(&self, participant: ParticipantId) -> bool {
        self.package
            .verifying_shares()
            .contains_key(&participant.identifier())
    }

    /// The group as bytes.
    ///
    /// # Errors
    ///
    /// Refuses when frost cannot encode the group.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        self.package.serialize().map_err(refused)
    }

    /// A group read back from [`GroupKey::to_bytes`].
    ///
    /// # Errors
    ///
    /// Refuses bytes that are not a group key, and a group with no threshold.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        Self::new(frost::keys::PublicKeyPackage::deserialize(bytes).map_err(refused)?)
    }

    fn package(&self) -> &frost::keys::PublicKeyPackage {
        &self.package
    }
}

fn key_bytes(key: &frost::VerifyingKey) -> [u8; 32] {
    let bytes = key.serialize().expect("a verifying key always encodes");
    <[u8; 32]>::try_from(bytes.as_slice()).expect("an Ed25519 verifying key is 32 bytes")
}

fn refused(error: frost::Error) -> ThresholdError {
    let culprits: Vec<ParticipantId> = error
        .culprits()
        .iter()
        .filter_map(|identifier| ParticipantId::from_identifier(identifier).ok())
        .collect();
    match error {
        frost::Error::InvalidSignatureShare { .. } => ThresholdError::InvalidShares { culprits },
        frost::Error::InvalidSignature => ThresholdError::InvalidSignature,
        keygen @ (frost::Error::InvalidProofOfKnowledge { .. }
        | frost::Error::InvalidSecretShare { .. }) => ThresholdError::KeyGeneration {
            culprits,
            reason: keygen.to_string(),
        },
        other => ThresholdError::Protocol(other.to_string()),
    }
}

struct Xof(blake3::OutputReader);

impl Xof {
    fn public(context: &str, input: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(input);
        Self(hasher.finalize_xof())
    }
}

impl rand_core::RngCore for Xof {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Xof {}
