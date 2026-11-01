//! The parties of a signing session and the signer that runs the protocol
//! over them as a [`MerkleRootSigner`].

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

use chrono::Utc;
use futures::future::join_all;

use super::signing::{
    Commitment, Nonces, SignatureShare, SigningRequest, ThresholdSignature, aggregate, at_least,
    commit, commit_with_rng, sign,
};
use super::{GroupKey, KeyShare, ParticipantId, ThresholdError, Xof, keygen};
use crate::hash::Blake3Hash;
use crate::signing::{
    Ed25519Signer, MerkleRootSigner, SignedRoot, SigningAlgorithm, verify_signed_root,
};

const PUBLIC_TEST_NONCE_CONTEXT: &str = "tameshi threshold public test nonce v1";

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
                commit_with_rng(&self.share, message, &mut rng)
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
