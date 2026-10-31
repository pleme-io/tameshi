//! The two-round threshold signing protocol and the signer that runs it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use chrono::Utc;
use frost_ed25519 as frost;
use futures::future::join_all;
use serde::{Deserialize, Serialize};

use super::{GroupKey, KeyShare, ParticipantId, ThresholdError, Xof, keygen, refused};
use crate::hash::Blake3Hash;
use crate::signing::{
    Ed25519Signer, MerkleRootSigner, SignedRoot, SigningAlgorithm, verify_ed25519,
    verify_signed_root,
};

const PUBLIC_TEST_NONCE_CONTEXT: &str = "tameshi threshold public test nonce v1";

/// A signer's secret nonces for one signing session.
///
/// [`sign`] takes them by value, so a commitment signs exactly once.
pub struct Nonces {
    participant: ParticipantId,
    message: Blake3Hash,
    pair: frost::round1::SigningNonces,
}

impl std::fmt::Debug for Nonces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nonces")
            .field("participant", &self.participant)
            .field("message", &self.message)
            .field("pair", &"REDACTED")
            .finish()
    }
}

/// Round 1, signer to coordinator: the public commitments to a signer's nonces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// The signer.
    pub participant: ParticipantId,
    commitments: frost::round1::SigningCommitments,
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
        let mut by_signer = BTreeMap::new();
        for commitment in commitments {
            if !group.has(commitment.participant) {
                return Err(ThresholdError::UnknownParticipant(commitment.participant));
            }
            if by_signer
                .insert(commitment.participant.identifier(), commitment.commitments)
                .is_some()
            {
                return Err(ThresholdError::DuplicateParticipant(commitment.participant));
            }
        }
        at_least(by_signer.len(), group.params().min_signers())?;
        Ok(Self {
            package: frost::SigningPackage::new(by_signer, message),
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

/// Round 2, signer to coordinator: one signer's share of the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureShare {
    /// The signer.
    pub participant: ParticipantId,
    share: frost::round2::SignatureShare,
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
#[must_use]
pub fn commit(share: &KeyShare, message: &[u8]) -> (Nonces, Commitment) {
    commit_with(share, message, &mut rand_core::OsRng)
}

fn commit_with<R: rand_core::RngCore + rand_core::CryptoRng>(
    share: &KeyShare,
    message: &[u8],
    rng: &mut R,
) -> (Nonces, Commitment) {
    let (nonces, commitments) = frost::round1::commit(share.package().signing_share(), rng);
    (
        Nonces {
            participant: share.participant(),
            message: Blake3Hash::digest(message),
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
    if committed != participant || message != Blake3Hash::digest(request.message()) {
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

fn at_least(have: usize, need: u16) -> Result<(), ThresholdError> {
    if have < usize::from(need) {
        Err(ThresholdError::BelowThreshold { have, need })
    } else {
        Ok(())
    }
}

/// One participant in a signing session, as the coordinator sees it.
///
/// [`LocalParty`] holds its share in this process. An implementation over a
/// network sends the message and [`SigningRequest`] and returns what the
/// remote participant answers.
pub trait SigningParty: Send + Sync {
    /// The participant this party signs as.
    fn participant(&self) -> ParticipantId;

    /// Round 1: commit to fresh nonces for signing `message`.
    fn commit(
        &self,
        message: &[u8],
    ) -> impl std::future::Future<Output = Result<Commitment, ThresholdError>> + Send;

    /// Round 2: sign the request with the nonces of the last commitment.
    fn sign(
        &self,
        request: &SigningRequest,
    ) -> impl std::future::Future<Output = Result<SignatureShare, ThresholdError>> + Send;
}

enum NonceSource {
    Os,
    PublicTest,
}

/// A participant whose share lives in this process.
///
/// It keeps the nonces of its last commitment and gives them up to the next
/// [`SigningParty::sign`]; a second sign without a new commitment is refused.
pub struct LocalParty {
    share: KeyShare,
    pending: Mutex<Option<Nonces>>,
    source: NonceSource,
}

impl std::fmt::Debug for LocalParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalParty")
            .field("share", &self.share)
            .finish_non_exhaustive()
    }
}

impl LocalParty {
    /// A party for this share, with nonces from the operating system.
    #[must_use]
    pub fn new(share: KeyShare) -> Self {
        Self {
            share,
            pending: Mutex::new(None),
            source: NonceSource::Os,
        }
    }

    fn public_test(share: KeyShare) -> Self {
        Self {
            share,
            pending: Mutex::new(None),
            source: NonceSource::PublicTest,
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Option<Nonces>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SigningParty for LocalParty {
    fn participant(&self) -> ParticipantId {
        self.share.participant()
    }

    fn commit(
        &self,
        message: &[u8],
    ) -> impl std::future::Future<Output = Result<Commitment, ThresholdError>> + Send {
        let (nonces, commitment) = match self.source {
            NonceSource::Os => commit(&self.share, message),
            NonceSource::PublicTest => {
                let mut input = self.share.participant().get().to_be_bytes().to_vec();
                input.extend_from_slice(message);
                let mut rng = Xof::public(PUBLIC_TEST_NONCE_CONTEXT, &input);
                commit_with(&self.share, message, &mut rng)
            }
        };
        *self.pending() = Some(nonces);
        std::future::ready(Ok(commitment))
    }

    fn sign(
        &self,
        request: &SigningRequest,
    ) -> impl std::future::Future<Output = Result<SignatureShare, ThresholdError>> + Send {
        let pending = self.pending().take();
        std::future::ready(
            pending
                .ok_or(ThresholdError::NoPendingCommitment(self.participant()))
                .and_then(|nonces| sign(request, nonces, &self.share)),
        )
    }
}

/// A [`MerkleRootSigner`] whose key is a `k`-of-`n` threshold group.
///
/// Signing asks every party to commit, builds the request from those that
/// did, collects their signature shares and aggregates them. The result is a
/// [`SignedRoot`] with [`SigningAlgorithm::FrostEd25519`] whose signature is
/// ordinary Ed25519 under [`GroupKey::verifying_key`].
pub struct ThresholdSigner<P = LocalParty> {
    group: GroupKey,
    parties: Vec<P>,
    signer_id: String,
}

impl<P: std::fmt::Debug> std::fmt::Debug for ThresholdSigner<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdSigner")
            .field("params", &self.group.params())
            .field(
                "verifying_key",
                &const_hex::encode(self.group.verifying_key()),
            )
            .field("parties", &self.parties)
            .field("signer_id", &self.signer_id)
            .finish()
    }
}

impl<P: SigningParty> ThresholdSigner<P> {
    /// A signer for this group over these parties.
    ///
    /// # Errors
    ///
    /// Refuses fewer than `k` parties, a duplicate party and a party outside
    /// the group.
    pub fn new(group: GroupKey, parties: Vec<P>, signer_id: &str) -> Result<Self, ThresholdError> {
        let mut seen = BTreeSet::new();
        for party in &parties {
            let participant = party.participant();
            if !group.has(participant) {
                return Err(ThresholdError::UnknownParticipant(participant));
            }
            if !seen.insert(participant) {
                return Err(ThresholdError::DuplicateParticipant(participant));
            }
        }
        at_least(parties.len(), group.params().min_signers())?;
        Ok(Self {
            group,
            parties,
            signer_id: signer_id.to_string(),
        })
    }

    /// The group this signer signs for.
    #[must_use]
    pub fn group(&self) -> &GroupKey {
        &self.group
    }

    /// Run both rounds over `message` and aggregate.
    ///
    /// # Errors
    ///
    /// Refuses when fewer than `k` parties commit, when a committed party
    /// refuses to sign, and when a share does not verify.
    pub async fn sign_message(&self, message: &[u8]) -> Result<ThresholdSignature, ThresholdError> {
        let commitments: Vec<Commitment> =
            join_all(self.parties.iter().map(|party| party.commit(message)))
                .await
                .into_iter()
                .filter_map(Result::ok)
                .collect();
        let request = SigningRequest::new(&self.group, message, commitments)?;
        let signers: BTreeSet<ParticipantId> = request.signers()?.into_iter().collect();
        let shares = join_all(
            self.parties
                .iter()
                .filter(|party| signers.contains(&party.participant()))
                .map(|party| party.sign(&request)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, ThresholdError>>()?;
        aggregate(&self.group, &request, &shares)
    }
}

impl ThresholdSigner<LocalParty> {
    /// A signer over local shares of `group`.
    ///
    /// # Errors
    ///
    /// Refuses a share of another group, and everything [`ThresholdSigner::new`] refuses.
    pub fn from_shares(
        group: GroupKey,
        shares: Vec<KeyShare>,
        signer_id: &str,
    ) -> Result<Self, ThresholdError> {
        if let Some(stranger) = shares
            .iter()
            .find(|share| share.group_key() != group.verifying_key())
        {
            return Err(ThresholdError::GroupMismatch(stranger.participant()));
        }
        Self::new(
            group,
            shares.into_iter().map(LocalParty::new).collect(),
            signer_id,
        )
    }

    /// The public 2-of-3 test group, every share public: integrity only, the
    /// threshold counterpart of [`LocalSigner::for_testing`](crate::signing::LocalSigner::for_testing).
    ///
    /// Its nonces derive from the message, so the same root signs to the same
    /// signature and a sandboxed build stays reproducible. That is safe only
    /// because these shares are public; [`LocalParty::new`] always takes
    /// nonces from the operating system.
    ///
    /// # Panics
    ///
    /// Never: the group is dealt from fixed parameters and holds every share.
    #[must_use]
    pub fn public_test() -> Self {
        let (shares, group) = keygen::public_test_group();
        Self::new(
            group,
            shares.into_iter().map(LocalParty::public_test).collect(),
            "threshold-test-signer",
        )
        .expect("the public test group holds every share")
    }
}

impl<P: SigningParty> MerkleRootSigner for ThresholdSigner<P> {
    async fn sign(&self, root: &Blake3Hash) -> crate::error::Result<SignedRoot> {
        let signature = self.sign_message(&root.0).await?;
        let params = self.group.params();
        Ok(SignedRoot {
            root: root.clone(),
            signature: signature.to_bytes().to_vec(),
            algorithm: SigningAlgorithm::FrostEd25519 {
                min_signers: params.min_signers(),
                max_signers: params.max_signers(),
            },
            signer_id: self.signer_id.clone(),
            signed_at: Utc::now(),
        })
    }

    fn verify(
        &self,
        signed: &SignedRoot,
    ) -> impl std::future::Future<Output = crate::error::Result<bool>> + Send {
        std::future::ready(Ok(verify_signed_root(signed, &self.group.verifying_key())))
    }
}

impl<P: SigningParty> Ed25519Signer for ThresholdSigner<P> {
    fn verifying_key(&self) -> [u8; 32] {
        self.group.verifying_key()
    }
}
