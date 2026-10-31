use std::collections::BTreeMap;

use frost_ed25519 as frost;

use super::keygen::{dkg, trusted_dealer};
use super::signing::{
    Commitment, LocalParty, SignatureShare, SigningParty, SigningRequest, ThresholdSigner,
    aggregate, commit, sign,
};
use super::{GroupKey, KeyShare, ParticipantId, ThresholdError, ThresholdParams, refused};
use crate::hash::Blake3Hash;
use crate::receipt::fragment::{KeyMode, sign_fragment_with, verify_fragment};
use crate::signing::{
    Ed25519Signer, LocalSigner, MerkleRootSigner, SigningAlgorithm, verify_signed_root,
};

fn params(k: u16, n: u16) -> ThresholdParams {
    ThresholdParams::new(k, n).unwrap()
}

fn id(index: u16) -> ParticipantId {
    ParticipantId::new(index).unwrap()
}

fn run_dkg(params: ThresholdParams) -> (Vec<KeyShare>, GroupKey) {
    let (secrets, round1): (Vec<_>, Vec<_>) = params
        .participants()
        .map(|p| dkg::start(p, params).unwrap())
        .unzip();
    let (secrets, round2): (Vec<_>, Vec<_>) = secrets
        .into_iter()
        .map(|s| dkg::exchange(s, &round1).unwrap())
        .unzip();
    let round2: Vec<_> = round2.into_iter().flatten().collect();
    let outcomes: Vec<(KeyShare, GroupKey)> = secrets
        .iter()
        .map(|s| dkg::finish(s, &round1, &round2).unwrap())
        .collect();
    let group = outcomes[0].1.clone();
    assert!(outcomes.iter().all(|(_, g)| *g == group));
    (
        outcomes.into_iter().map(|(share, _)| share).collect(),
        group,
    )
}

fn copy(share: &KeyShare) -> KeyShare {
    KeyShare::from_bytes(&share.to_bytes().unwrap()).unwrap()
}

fn subset(shares: &[KeyShare], indices: &[u16]) -> Vec<KeyShare> {
    shares
        .iter()
        .filter(|s| indices.contains(&s.participant().get()))
        .map(copy)
        .collect()
}

fn dalek_verifies(message: &[u8], signature: &[u8], key: &[u8; 32]) -> bool {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(signature).unwrap();
    key.verify_strict(message, &signature).is_ok()
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    futures::executor::block_on(future)
}

#[test]
fn dkg_shares_sign_without_any_party_holding_the_group_secret() {
    let (shares, group) = run_dkg(params(2, 3));
    let root = Blake3Hash::digest(b"dkg root");
    for pair in [[1, 2], [1, 3], [2, 3]] {
        let signer =
            ThresholdSigner::from_shares(group.clone(), subset(&shares, &pair), "dkg").unwrap();
        let attested = block_on(signer.sign(&root)).unwrap();
        assert_eq!(
            attested.algorithm,
            SigningAlgorithm::FrostEd25519 {
                min_signers: 2,
                max_signers: 3
            }
        );
        assert!(
            dalek_verifies(&root.0, &attested.signature, &group.verifying_key()),
            "signers {pair:?}: ed25519-dalek verify_strict accepts the aggregate"
        );
        assert!(verify_signed_root(&attested, &group.verifying_key()));
        assert!(block_on(signer.verify(&attested)).unwrap());
    }
}

#[test]
fn the_aggregate_verifies_through_verify_fragment() {
    let (shares, group) = run_dkg(params(3, 5));
    let signer =
        ThresholdSigner::from_shares(group.clone(), subset(&shares, &[1, 3, 5]), "fragment")
            .unwrap();
    let receipt = crate::receipt::tests::sample();
    let fragment = sign_fragment_with(&receipt, &signer, KeyMode::ThresholdShares).unwrap();
    assert_eq!(
        fragment.verifying_key,
        const_hex::encode(group.verifying_key())
    );
    let verdict = verify_fragment(&fragment, &receipt, Some(&group.verifying_key()));
    assert!(verdict.ok(), "{verdict:?}");
    let mut forged = fragment.clone();
    forged.signed_root.signature[0] ^= 1;
    assert!(!verify_fragment(&forged, &receipt, None).signature_valid);
}

#[test]
fn k_minus_one_signers_are_refused_at_every_layer() {
    let (shares, group) = run_dkg(params(3, 5));
    let too_few = subset(&shares, &[2, 4]);

    assert_eq!(
        ThresholdSigner::from_shares(group.clone(), subset(&shares, &[2, 4]), "k-1").unwrap_err(),
        ThresholdError::BelowThreshold { have: 2, need: 3 }
    );

    let message = b"k-1";
    let (nonces, commitments): (Vec<_>, Vec<_>) =
        too_few.iter().map(|s| commit(s, message)).unzip();
    assert_eq!(
        SigningRequest::new(&group, message, commitments.clone()).unwrap_err(),
        ThresholdError::BelowThreshold { have: 2, need: 3 }
    );

    let third = commit(&shares[0], message).1;
    let honest = SigningRequest::new(&group, message, [commitments, vec![third]].concat()).unwrap();
    let mut forged_request = serde_json::to_value(&honest).unwrap();
    let signing_commitments = forged_request["package"]["signing_commitments"]
        .as_object_mut()
        .unwrap();
    let first = signing_commitments.keys().next().unwrap().clone();
    signing_commitments.remove(&first);
    let forged_request: SigningRequest = serde_json::from_value(forged_request).unwrap();
    assert_eq!(forged_request.signers().unwrap(), vec![id(2), id(4)]);
    for (nonce, share) in nonces.into_iter().zip(&too_few) {
        assert_eq!(
            sign(&forged_request, nonce, share).unwrap_err(),
            ThresholdError::BelowThreshold { have: 2, need: 3 }
        );
    }

    let lowered: Vec<frost::keys::KeyPackage> = too_few
        .iter()
        .map(|s| {
            frost::keys::KeyPackage::new(
                *s.package.identifier(),
                *s.package.signing_share(),
                *s.package.verifying_share(),
                *s.package.verifying_key(),
                2,
            )
        })
        .collect();
    let unbounded = frost::keys::PublicKeyPackage::new(
        group.package.verifying_shares().clone(),
        *group.package.verifying_key(),
        None,
    );
    let mut nonces = BTreeMap::new();
    let mut signing_commitments = BTreeMap::new();
    for package in &lowered {
        let (n, c) = frost::round1::commit(package.signing_share(), &mut rand_core::OsRng);
        nonces.insert(*package.identifier(), n);
        signing_commitments.insert(*package.identifier(), c);
    }
    let package = frost::SigningPackage::new(signing_commitments, message);
    let signature_shares: BTreeMap<_, _> = lowered
        .iter()
        .map(|p| {
            (
                *p.identifier(),
                frost::round2::sign(&package, &nonces[p.identifier()], p).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        frost::aggregate(&package, &signature_shares, &unbounded).map_err(refused),
        Err(ThresholdError::InvalidSignature),
        "with every count check removed, k-1 honest shares still make no valid signature"
    );
}

#[test]
fn a_forged_share_fails_aggregation_and_names_its_signer() {
    let (shares, group) = run_dkg(params(2, 3));
    let (impostors, _) = run_dkg(params(2, 3));
    let message = b"forgery";

    let (n1, c1) = commit(&shares[0], message);
    let (n2, c2) = commit(&impostors[1], message);
    let request = SigningRequest::new(&group, message, vec![c1, c2]).unwrap();
    let honest = sign(&request, n1, &shares[0]).unwrap();
    let impostor = sign(&request, n2, &impostors[1]).unwrap();
    assert_eq!(
        aggregate(&group, &request, &[honest.clone(), impostor]).unwrap_err(),
        ThresholdError::InvalidShares {
            culprits: vec![id(2)]
        }
    );

    let (n1, c1) = commit(&shares[0], message);
    let (n2, c2) = commit(&shares[1], message);
    let request = SigningRequest::new(&group, message, vec![c1, c2]).unwrap();
    let first = sign(&request, n1, &shares[0]).unwrap();
    let second = sign(&request, n2, &shares[1]).unwrap();
    let mut tampered = serde_json::to_value(&second).unwrap();
    let hex = tampered["share"]["share"].as_str().unwrap().to_string();
    let mut bytes = const_hex::decode(&hex).unwrap();
    bytes[0] ^= 1;
    tampered["share"]["share"] = serde_json::Value::String(const_hex::encode(bytes));
    let tampered: SignatureShare = serde_json::from_value(tampered).unwrap();
    assert_eq!(
        aggregate(&group, &request, &[first.clone(), tampered]).unwrap_err(),
        ThresholdError::InvalidShares {
            culprits: vec![id(2)]
        }
    );
    let signature = aggregate(&group, &request, &[first, second]).unwrap();
    assert!(dalek_verifies(
        message,
        &signature.to_bytes(),
        &group.verifying_key()
    ));
}

#[test]
fn nonces_sign_once_and_only_the_committed_message() {
    let (shares, group) = run_dkg(params(2, 2));
    let parties: Vec<LocalParty> = shares.into_iter().map(LocalParty::new).collect();
    let commitments: Vec<Commitment> = parties
        .iter()
        .map(|p| block_on(p.commit(b"once")).unwrap())
        .collect();
    let request = SigningRequest::new(&group, b"once", commitments).unwrap();
    block_on(parties[0].sign(&request)).unwrap();
    assert_eq!(
        block_on(parties[0].sign(&request)).unwrap_err(),
        ThresholdError::NoPendingCommitment(id(1))
    );

    let commitments: Vec<Commitment> = parties
        .iter()
        .map(|p| block_on(p.commit(b"committed")).unwrap())
        .collect();
    let other = SigningRequest::new(&group, b"other message", commitments).unwrap();
    assert_eq!(
        block_on(parties[1].sign(&other)).unwrap_err(),
        ThresholdError::SessionMismatch(id(2))
    );
}

#[test]
fn the_round_messages_cross_a_wire_as_json() {
    let (shares, group) = run_dkg(params(2, 3));
    let group = GroupKey::from_bytes(&group.to_bytes().unwrap()).unwrap();
    let message = b"over the wire";
    let signers = subset(&shares, &[1, 3]);
    let (nonces, commitments): (Vec<_>, Vec<_>) =
        signers.iter().map(|s| commit(s, message)).unzip();
    let commitments: Vec<Commitment> = commitments
        .iter()
        .map(|c| serde_json::from_str(&serde_json::to_string(c).unwrap()).unwrap())
        .collect();
    let request = SigningRequest::new(&group, message, commitments).unwrap();
    let request: SigningRequest =
        serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
    let answers: Vec<SignatureShare> = nonces
        .into_iter()
        .zip(&signers)
        .map(|(n, s)| sign(&request, n, s).unwrap())
        .map(|share| serde_json::from_str(&serde_json::to_string(&share).unwrap()).unwrap())
        .collect();
    let signature = aggregate(&group, &request, &answers).unwrap();
    assert!(dalek_verifies(
        message,
        &signature.to_bytes(),
        &group.verifying_key()
    ));
}

#[test]
fn the_dealer_test_path_signs_three_of_five() {
    let (shares, group) = trusted_dealer(params(3, 5)).unwrap();
    let signer =
        ThresholdSigner::from_shares(group.clone(), subset(&shares, &[2, 3, 5]), "dealer").unwrap();
    let root = Blake3Hash::digest(b"dealer");
    let attested = block_on(signer.sign(&root)).unwrap();
    assert!(dalek_verifies(
        &root.0,
        &attested.signature,
        &group.verifying_key()
    ));
}

#[test]
fn the_public_test_group_is_fixed_and_signs_deterministically() {
    let a = ThresholdSigner::public_test();
    let b = ThresholdSigner::public_test();
    assert_eq!(a.verifying_key(), b.verifying_key());
    assert_ne!(
        a.verifying_key(),
        LocalSigner::for_testing().verifying_key()
    );
    let root = Blake3Hash::digest(b"reproducible");
    let first = block_on(a.sign(&root)).unwrap();
    let second = block_on(b.sign(&root)).unwrap();
    assert_eq!(first.signature, second.signature);
    assert!(verify_signed_root(&first, &a.verifying_key()));
}

#[test]
fn dkg_refuses_a_round2_package_that_does_not_match_its_commitment() {
    let p = params(2, 3);
    let (secrets, round1): (Vec<_>, Vec<_>) =
        p.participants().map(|i| dkg::start(i, p).unwrap()).unzip();
    let (secrets, round2): (Vec<_>, Vec<_>) = secrets
        .into_iter()
        .map(|s| dkg::exchange(s, &round1).unwrap())
        .unzip();
    let mut round2: Vec<_> = round2.into_iter().flatten().collect();

    let (other_secrets, other_round1): (Vec<_>, Vec<_>) =
        p.participants().map(|i| dkg::start(i, p).unwrap()).unzip();
    let (_, other_round2): (Vec<_>, Vec<_>) = other_secrets
        .into_iter()
        .map(|s| dkg::exchange(s, &other_round1).unwrap())
        .unzip();
    let forged = other_round2
        .into_iter()
        .flatten()
        .find(|pkg| pkg.from == id(1) && pkg.to == id(2))
        .unwrap();
    round2.retain(|pkg| !(pkg.from == id(1) && pkg.to == id(2)));
    round2.push(forged);

    match dkg::finish(&secrets[1], &round1, &round2).unwrap_err() {
        ThresholdError::KeyGeneration { culprits, .. } => assert_eq!(culprits, vec![id(1)]),
        other => panic!("expected a key generation refusal, got {other:?}"),
    }
}

#[test]
fn a_share_of_another_group_is_refused() {
    let (shares, group) = run_dkg(params(2, 3));
    let (strangers, _) = run_dkg(params(2, 3));
    let mut mixed = subset(&shares, &[1]);
    mixed.push(copy(&strangers[1]));
    assert_eq!(
        ThresholdSigner::from_shares(group, mixed, "mixed").unwrap_err(),
        ThresholdError::GroupMismatch(id(2))
    );
}

#[test]
fn params_and_participants_refuse_what_is_not_a_threshold() {
    for (k, n) in [(1, 3), (4, 3), (0, 0), (1, 1)] {
        assert_eq!(
            ThresholdParams::new(k, n).unwrap_err(),
            ThresholdError::InvalidParams {
                min_signers: k,
                max_signers: n
            }
        );
    }
    assert_eq!(
        ParticipantId::new(0).unwrap_err(),
        ThresholdError::InvalidParticipant(0)
    );
    assert!(
        serde_json::from_str::<ThresholdParams>(r#"{"min_signers":1,"max_signers":3}"#).is_err()
    );
    assert!(serde_json::from_str::<ParticipantId>("0").is_err());
    assert_eq!(
        dkg::start(id(4), params(2, 3)).unwrap_err(),
        ThresholdError::UnknownParticipant(id(4))
    );
}

#[test]
fn a_share_survives_storage_and_never_prints_its_secret() {
    let (shares, group) = run_dkg(params(2, 3));
    let bytes = shares[0].to_bytes().unwrap();
    let back = KeyShare::from_bytes(&bytes).unwrap();
    assert_eq!(back.participant(), id(1));
    assert_eq!(back.min_signers(), 2);
    assert_eq!(back.group_key(), group.verifying_key());
    let printed = format!("{:?}", shares[0]);
    assert!(printed.contains("REDACTED"));
    let secret_hex = const_hex::encode(shares[0].package.signing_share().serialize());
    assert!(!printed.contains(&secret_hex));
    assert!(KeyShare::from_bytes(b"not a share").is_err());
}
