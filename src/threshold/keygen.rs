//! Key generation for a threshold group.
//!
//! [`dkg`] is the production path: no participant, and no dealer, ever holds
//! the group secret. [`trusted_dealer`] is the test path.

use frost_ed25519 as frost;

use super::{GroupKey, KeyShare, ThresholdError, ThresholdParams, Xof, refused};

pub mod dkg {
    //! Distributed key generation: the Pedersen DKG with proofs of knowledge
    //! from the FROST paper (Komlo and Goldberg, 2020), as `frost-ed25519`
    //! implements it. RFC 9591 leaves key generation out of scope; its
    //! appendix C describes only the trusted dealer.
    //!
    //! Three steps per participant:
    //!
    //! 1. [`start`]: broadcast the [`Round1Package`] to every participant.
    //! 2. [`exchange`] with every participant's [`Round1Package`]: send each
    //!    [`Round2Package`] privately to the participant it names in `to`.
    //! 3. [`finish`] with the round 1 packages and the round 2 packages
    //!    addressed to you: keep the [`KeyShare`], publish the [`GroupKey`].
    //!
    //! Each participant's share is the sum of what every participant's
    //! polynomial gives at its index. The group secret is the sum of every
    //! participant's polynomial constant, and no step computes it.

    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize};

    use super::frost;
    use crate::threshold::{
        GroupKey, KeyShare, ParticipantId, ThresholdError, ThresholdParams, refused,
    };

    /// The secret state a participant keeps between [`start`] and [`exchange`].
    pub struct Round1Secret {
        participant: ParticipantId,
        params: ThresholdParams,
        package: frost::keys::dkg::round1::SecretPackage,
    }

    impl std::fmt::Debug for Round1Secret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Round1Secret")
                .field("participant", &self.participant)
                .field("params", &self.params)
                .field("package", &"REDACTED")
                .finish()
        }
    }

    /// The public package a participant broadcasts after [`start`]: its
    /// polynomial commitment and proof of knowledge.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Round1Package {
        /// The participant that sent it.
        pub from: ParticipantId,
        package: frost::keys::dkg::round1::Package,
    }

    /// The secret state a participant keeps between [`exchange`] and [`finish`].
    pub struct Round2Secret {
        participant: ParticipantId,
        params: ThresholdParams,
        package: frost::keys::dkg::round2::SecretPackage,
    }

    impl std::fmt::Debug for Round2Secret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Round2Secret")
                .field("participant", &self.participant)
                .field("params", &self.params)
                .field("package", &"REDACTED")
                .finish()
        }
    }

    /// A private package from one participant to another after [`exchange`]:
    /// the sender's polynomial at the recipient's index. Send it over an
    /// authenticated, confidential channel.
    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Round2Package {
        /// The participant that sent it.
        pub from: ParticipantId,
        /// The participant it is for.
        pub to: ParticipantId,
        package: frost::keys::dkg::round2::Package,
    }

    impl std::fmt::Debug for Round2Package {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Round2Package")
                .field("from", &self.from)
                .field("to", &self.to)
                .field("package", &"REDACTED")
                .finish()
        }
    }

    /// Step 1: sample this participant's polynomial.
    ///
    /// # Errors
    ///
    /// Refuses a participant outside `1..=n`.
    pub fn start(
        participant: ParticipantId,
        params: ThresholdParams,
    ) -> Result<(Round1Secret, Round1Package), ThresholdError> {
        params.admits(participant)?;
        let (secret, package) = frost::keys::dkg::part1(
            participant.identifier(),
            params.max_signers(),
            params.min_signers(),
            rand_core::OsRng,
        )
        .map_err(refused)?;
        Ok((
            Round1Secret {
                participant,
                params,
                package: secret,
            },
            Round1Package {
                from: participant,
                package,
            },
        ))
    }

    /// Step 2: check every other participant's proof and make their private
    /// packages. `received` may include this participant's own package.
    ///
    /// # Errors
    ///
    /// Refuses a duplicate or unknown sender, a missing participant and a
    /// failed proof of knowledge, naming the culprit.
    pub fn exchange(
        secret: Round1Secret,
        received: &[Round1Package],
    ) -> Result<(Round2Secret, Vec<Round2Package>), ThresholdError> {
        let Round1Secret {
            participant,
            params,
            package,
        } = secret;
        let others = round1_from_others(participant, params, received)?;
        let (next, outgoing) = frost::keys::dkg::part2(package, &others).map_err(refused)?;
        let packages = outgoing
            .into_iter()
            .map(|(identifier, package)| {
                Ok(Round2Package {
                    from: participant,
                    to: ParticipantId::from_identifier(&identifier)?,
                    package,
                })
            })
            .collect::<Result<Vec<_>, ThresholdError>>()?;
        Ok((
            Round2Secret {
                participant,
                params,
                package: next,
            },
            packages,
        ))
    }

    /// Step 3: check the private packages against the broadcast commitments
    /// and keep this participant's share. Packages addressed to another
    /// participant are ignored.
    ///
    /// # Errors
    ///
    /// Refuses a duplicate, unknown or missing sender and a package that does
    /// not match its sender's commitment, naming the culprit.
    pub fn finish(
        secret: &Round2Secret,
        round1: &[Round1Package],
        round2: &[Round2Package],
    ) -> Result<(KeyShare, GroupKey), ThresholdError> {
        let others = round1_from_others(secret.participant, secret.params, round1)?;
        let mut mine = BTreeMap::new();
        for package in round2.iter().filter(|p| p.to == secret.participant) {
            secret.params.admits(package.from)?;
            if mine
                .insert(package.from.identifier(), package.package.clone())
                .is_some()
            {
                return Err(ThresholdError::DuplicateParticipant(package.from));
            }
        }
        let (share, group) =
            frost::keys::dkg::part3(&secret.package, &others, &mine).map_err(refused)?;
        Ok((KeyShare::new(share)?, GroupKey::new(group)?))
    }

    fn round1_from_others(
        me: ParticipantId,
        params: ThresholdParams,
        received: &[Round1Package],
    ) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>, ThresholdError>
    {
        let mut others = BTreeMap::new();
        for package in received.iter().filter(|p| p.from != me) {
            params.admits(package.from)?;
            if others
                .insert(package.from.identifier(), package.package.clone())
                .is_some()
            {
                return Err(ThresholdError::DuplicateParticipant(package.from));
            }
        }
        Ok(others)
    }
}

/// Generate a group with a trusted dealer: the test path.
///
/// The dealer samples the group secret and splits it, so the secret exists in
/// this process while it runs. Use [`dkg`] for a key that must never exist
/// in one piece.
///
/// # Errors
///
/// Refuses when frost refuses the parameters.
pub fn trusted_dealer(
    params: ThresholdParams,
) -> Result<(Vec<KeyShare>, GroupKey), ThresholdError> {
    dealt(params, rand_core::OsRng)
}

pub(crate) const PUBLIC_TEST_GROUP_CONTEXT: &str = "tameshi threshold public test group v1";

/// The public 2-of-3 test group: dealt from a public seed, so every share is
/// public and the group key proves integrity only, like
/// [`LocalSigner::for_testing`](crate::signing::LocalSigner::for_testing).
pub(crate) fn public_test_group() -> (Vec<KeyShare>, GroupKey) {
    let params = ThresholdParams::new(2, 3).expect("2-of-3 is a threshold");
    dealt(params, Xof::public(PUBLIC_TEST_GROUP_CONTEXT, b""))
        .expect("the public test group deals from fixed parameters")
}

fn dealt<R: rand_core::RngCore + rand_core::CryptoRng>(
    params: ThresholdParams,
    rng: R,
) -> Result<(Vec<KeyShare>, GroupKey), ThresholdError> {
    let (secret_shares, group) = frost::keys::generate_with_dealer(
        params.max_signers(),
        params.min_signers(),
        frost::keys::IdentifierList::Default,
        rng,
    )
    .map_err(refused)?;
    let shares = secret_shares
        .into_values()
        .map(|secret_share| {
            KeyShare::new(frost::keys::KeyPackage::try_from(secret_share).map_err(refused)?)
        })
        .collect::<Result<Vec<_>, ThresholdError>>()?;
    Ok((shares, GroupKey::new(group)?))
}
