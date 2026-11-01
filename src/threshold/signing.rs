//! The two-round threshold signing protocol. The parties and the signer that
//! run it over [`MerkleRootSigner`](crate::signing::MerkleRootSigner) need the
//! `full` feature.

use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519 as frost;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

#[cfg(feature = "full")]
pub use super::party::{LocalParty, SigningParty, ThresholdSigner};
use super::{GroupKey, KeyShare, ParticipantId, ThresholdError, refused};
use crate::ed25519::verify_ed25519;

/// A signer's secret nonces for one signing session.
///
/// [`sign`] takes them by value, so a commitment signs exactly once.
pub struct Nonces {
    participant: ParticipantId,
    message: [u8; 32],
    pair: frost::round1::SigningNonces,
}

impl std::fmt::Debug for Nonces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nonces")
            .field("participant", &self.participant)
            .field("message", &const_hex::encode(self.message))
            .field("pair", &"REDACTED")
            .finish()
    }
}

fn digest(message: &[u8]) -> [u8; 32] {
    *blake3::hash(message).as_bytes()
}

/// Round 1, signer to coordinator: the public commitments to a signer's nonces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// The signer.
    pub participant: ParticipantId,
    commitments: frost::round1::SigningCommitments,
}

impl Commitment {
    /// The commitment as frost's bytes, without its signer.
    ///
    /// # Errors
    ///
    /// Refuses when frost cannot encode the commitment.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        self.commitments.serialize().map_err(refused)
    }

    /// The commitment `participant` made, read back from [`Commitment::to_bytes`].
    ///
    /// # Errors
    ///
    /// Refuses bytes that are not a commitment.
    pub fn from_bytes(participant: ParticipantId, bytes: &[u8]) -> Result<Self, ThresholdError> {
        Ok(Self {
            participant,
            commitments: frost::round1::SigningCommitments::deserialize(bytes).map_err(refused)?,
        })
    }
}

/// Coordinator to signers: the message and the commitments of every signer
/// in this session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    package: frost::SigningPackage,
}

impl SigningRequest {
    /// The request for `message` from these commitments.
    ///
    /// # Errors
    ///
    /// Refuses fewer than the group's `k` commitments, a duplicate signer and
    /// a signer outside the group.
    pub fn new(
        group: &GroupKey,
        message: &[u8],
        commitments: Vec<Commitment>,
    ) -> Result<Self, ThresholdError> {
        let by_signer = by_signer(commitments, |participant| {
            if group.has(participant) {
                Ok(())
            } else {
                Err(ThresholdError::UnknownParticipant(participant))
            }
        })?;
        at_least(by_signer.len(), group.params().min_signers())?;
        Ok(Self {
            package: frost::SigningPackage::new(by_signer, message),
        })
    }

    /// The request for `message` from these commitments, as a party that
    /// holds no [`GroupKey`] builds it. [`sign`] still refuses fewer than its
    /// share's `k`, and [`aggregate`] fewer than the group's.
    ///
    /// # Errors
    ///
    /// Refuses a duplicate signer.
    pub fn from_commitments(
        message: &[u8],
        commitments: Vec<Commitment>,
    ) -> Result<Self, ThresholdError> {
        Ok(Self {
            package: frost::SigningPackage::new(by_signer(commitments, |_| Ok(()))?, message),
        })
    }

    /// The message to sign.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.package.message()
    }

    /// The signers of this session.
    ///
    /// # Errors
    ///
    /// Refuses a request naming a participant outside `1..=65535`.
    pub fn signers(&self) -> Result<Vec<ParticipantId>, ThresholdError> {
        self.package
            .signing_commitments()
            .keys()
            .map(ParticipantId::from_identifier)
            .collect()
    }
}

fn by_signer(
    commitments: Vec<Commitment>,
    admit: impl Fn(ParticipantId) -> Result<(), ThresholdError>,
) -> Result<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>, ThresholdError> {
    let mut by_signer = BTreeMap::new();
    for commitment in commitments {
        admit(commitment.participant)?;
        if by_signer
            .insert(commitment.participant.identifier(), commitment.commitments)
            .is_some()
        {
            return Err(ThresholdError::DuplicateParticipant(commitment.participant));
        }
    }
    Ok(by_signer)
}

/// Round 2, signer to coordinator: one signer's share of the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureShare {
    /// The signer.
    pub participant: ParticipantId,
    share: frost::round2::SignatureShare,
}

impl SignatureShare {
    /// The share as frost's bytes, without its signer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.share.serialize()
    }

    /// The share `participant` signed, read back from [`SignatureShare::to_bytes`].
    ///
    /// # Errors
    ///
    /// Refuses bytes that are not a signature share.
    pub fn from_bytes(participant: ParticipantId, bytes: &[u8]) -> Result<Self, ThresholdError> {
        Ok(Self {
            participant,
            share: frost::round2::SignatureShare::deserialize(bytes).map_err(refused)?,
        })
    }
}

/// An aggregated threshold signature: 64 bytes, RFC 8032 Ed25519.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ThresholdSignature([u8; 64]);

impl ThresholdSignature {
    /// The 64 signature bytes, `R || s`.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl std::fmt::Debug for ThresholdSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ThresholdSignature({})", const_hex::encode(self.0))
    }
}

/// Round 1: make fresh nonces from the operating system's randomness and
/// their public commitment, for signing `message`.
#[cfg(feature = "os-rng")]
#[must_use]
pub fn commit(share: &KeyShare, message: &[u8]) -> (Nonces, Commitment) {
    commit_with_rng(share, message, &mut rand_core::OsRng)
}

/// Round 1: make nonces from `rng` and their public commitment, for signing
/// `message`.
///
/// Two commitments whose nonces repeat give away the share: `rng` must never
/// yield the same stream for two sessions of one share that sign different
/// messages.
#[must_use]
pub fn commit_with_rng(
    share: &KeyShare,
    message: &[u8],
    rng: &mut impl CryptoRngCore,
) -> (Nonces, Commitment) {
    let (nonces, commitments) = frost::round1::commit(share.package().signing_share(), rng);
    (
        Nonces {
            participant: share.participant(),
            message: digest(message),
            pair: nonces,
        },
        Commitment {
            participant: share.participant(),
            commitments,
        },
    )
}

/// Round 2: sign the request with one share, consuming the nonces.
///
/// # Errors
///
/// Refuses nonces made by another participant or for another message, a
/// request with fewer than `k` signers, and a request that does not carry
/// this signer's commitment.
pub fn sign(
    request: &SigningRequest,
    nonces: Nonces,
    share: &KeyShare,
) -> Result<SignatureShare, ThresholdError> {
    let Nonces {
        participant: committed,
        message,
        pair,
    } = nonces;
    let participant = share.participant();
    if committed != participant || message != digest(request.message()) {
        return Err(ThresholdError::SessionMismatch(participant));
    }
    at_least(
        request.package.signing_commitments().len(),
        share.min_signers(),
    )?;
    let signature_share = frost::round2::sign(&request.package, &pair, share.package()).map_err(
        |error| match error {
            frost::Error::MissingCommitment | frost::Error::IncorrectCommitment => {
                ThresholdError::SessionMismatch(participant)
            }
            other => refused(other),
        },
    )?;
    Ok(SignatureShare {
        participant,
        share: signature_share,
    })
}

/// Aggregate the signature shares into one Ed25519 signature under the
/// group key, and verify it.
///
/// # Errors
///
/// Refuses fewer than `k` shares, a duplicate share, a share from a signer
/// outside the request, and shares that do not verify, naming their signers.
pub fn aggregate(
    group: &GroupKey,
    request: &SigningRequest,
    shares: &[SignatureShare],
) -> Result<ThresholdSignature, ThresholdError> {
    at_least(shares.len(), group.params().min_signers())?;
    let signers: BTreeSet<ParticipantId> = request.signers()?.into_iter().collect();
    let mut by_signer = BTreeMap::new();
    for share in shares {
        if !signers.contains(&share.participant) {
            return Err(ThresholdError::UnknownParticipant(share.participant));
        }
        if by_signer
            .insert(share.participant.identifier(), share.share)
            .is_some()
        {
            return Err(ThresholdError::DuplicateParticipant(share.participant));
        }
    }
    let signature =
        frost::aggregate(&request.package, &by_signer, group.package()).map_err(refused)?;
    let bytes = signature.serialize().map_err(refused)?;
    let bytes = <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| ThresholdError::Protocol("an Ed25519 signature is 64 bytes".to_string()))?;
    if verify_ed25519(request.message(), &bytes, &group.verifying_key()) {
        Ok(ThresholdSignature(bytes))
    } else {
        Err(ThresholdError::InvalidSignature)
    }
}

pub(super) fn at_least(have: usize, need: u16) -> Result<(), ThresholdError> {
    if have < usize::from(need) {
        Err(ThresholdError::BelowThreshold { have, need })
    } else {
        Ok(())
    }
}
