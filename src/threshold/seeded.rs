use super::keygen::{dkg, trusted_dealer_with_rng};
use super::signing::{
    Commitment, SignatureShare, SigningRequest, aggregate, commit_with_rng, sign,
};
use super::{GroupKey, KeyShare, ParticipantId, ThresholdError, ThresholdParams, Xof};

const SEED_CONTEXT: &str = "tameshi threshold seeded test v1";

fn rng(seed: &str) -> Xof {
    Xof::public(SEED_CONTEXT, seed.as_bytes())
}

fn params(k: u16, n: u16) -> ThresholdParams {
    ThresholdParams::new(k, n).unwrap()
}

fn id(index: u16) -> ParticipantId {
    ParticipantId::new(index).unwrap()
}

fn dealt(seed: &str) -> (Vec<KeyShare>, GroupKey) {
    trusted_dealer_with_rng(params(2, 3), &mut rng(seed)).unwrap()
}

fn share_bytes(shares: &[KeyShare]) -> Vec<Vec<u8>> {
    shares
        .iter()
        .map(|share| share.to_bytes().unwrap().to_vec())
        .collect()
}

fn dalek_verifies(message: &[u8], signature: &[u8; 64], key: &[u8; 32]) -> bool {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).unwrap();
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

fn signed(
    shares: &[KeyShare],
    group: &GroupKey,
    picks: &[usize],
    message: &[u8],
    seed: &str,
) -> [u8; 64] {
    let mut stream = rng(seed);
    let (nonces, commitments): (Vec<_>, Vec<_>) = picks
        .iter()
        .map(|&i| commit_with_rng(&shares[i], message, &mut stream))
        .unzip();
    let request = SigningRequest::new(group, message, commitments).unwrap();
    let parts: Vec<SignatureShare> = picks
        .iter()
        .zip(nonces)
        .map(|(&i, nonces)| sign(&request, nonces, &shares[i]).unwrap())
        .collect();
    aggregate(group, &request, &parts).unwrap().to_bytes()
}

#[test]
fn a_seeded_dealer_deals_the_same_shares_twice_and_another_seed_does_not() {
    let (first, first_group) = dealt("one");
    let (again, again_group) = dealt("one");
    let (other, other_group) = dealt("two");
    assert_eq!(share_bytes(&first), share_bytes(&again));
    assert_eq!(first_group, again_group);
    assert_ne!(share_bytes(&first), share_bytes(&other));
    assert_ne!(first_group.verifying_key(), other_group.verifying_key());
    assert_eq!(
        first
            .iter()
            .map(|share| share.participant().get())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[test]
fn seeded_nonces_sign_the_same_signature_twice_and_it_verifies_as_ed25519() {
    let (shares, group) = dealt("sign");
    let first = signed(&shares, &group, &[0, 2], b"m", "nonces");
    let again = signed(&shares, &group, &[0, 2], b"m", "nonces");
    let other = signed(&shares, &group, &[0, 2], b"m", "other nonces");
    assert_eq!(first, again);
    assert_ne!(first, other);
    for signature in [first, other] {
        assert!(dalek_verifies(b"m", &signature, &group.verifying_key()));
        assert!(!dalek_verifies(b"n", &signature, &group.verifying_key()));
    }
}

#[test]
fn a_seeded_dkg_starts_the_same_way_twice_and_makes_one_group_any_two_sign_for() {
    let p = params(2, 3);
    let start = |seed: &str| -> (Vec<dkg::Round1Secret>, Vec<dkg::Round1Package>) {
        let mut stream = rng(seed);
        p.participants()
            .map(|i| dkg::start_with_rng(i, p, &mut stream).unwrap())
            .unzip()
    };
    let (secrets, round1) = start("dkg");
    assert_eq!(round1, start("dkg").1);
    assert_ne!(round1, start("other dkg").1);
    assert!(
        secrets
            .iter()
            .zip(p.participants())
            .all(|(secret, i)| { secret.participant() == i && secret.params() == p })
    );
    let (secrets, round2): (Vec<_>, Vec<_>) = secrets
        .into_iter()
        .map(|secret| dkg::exchange(secret, &round1).unwrap())
        .unzip();
    assert!(
        secrets
            .iter()
            .zip(p.participants())
            .all(|(secret, i)| { secret.participant() == i && secret.params() == p })
    );
    let round2: Vec<_> = round2.into_iter().flatten().collect();
    assert_eq!(round2.len(), 6);
    let done: Vec<(KeyShare, GroupKey)> = secrets
        .iter()
        .map(|secret| dkg::finish(secret, &round1, &round2).unwrap())
        .collect();
    let group = done[0].1.clone();
    assert!(done.iter().all(|(_, g)| *g == group));
    let shares: Vec<KeyShare> = done.into_iter().map(|(share, _)| share).collect();
    let signature = signed(&shares, &group, &[1, 2], b"dkg", "dkg nonces");
    assert!(dalek_verifies(b"dkg", &signature, &group.verifying_key()));
}

#[test]
fn every_round_message_survives_frost_bytes_and_garbage_is_refused() {
    let (shares, group) = dealt("bytes");
    let mut stream = rng("bytes nonces");
    let (n1, c1) = commit_with_rng(&shares[0], b"m", &mut stream);
    let (n2, c2) = commit_with_rng(&shares[1], b"m", &mut stream);
    let carried: Vec<Commitment> = [&c1, &c2]
        .into_iter()
        .map(|c| Commitment::from_bytes(c.participant, &c.to_bytes().unwrap()).unwrap())
        .collect();
    assert_eq!(carried, vec![c1, c2]);
    let request = SigningRequest::from_commitments(b"m", carried).unwrap();
    let parts: Vec<SignatureShare> = [(n1, &shares[0]), (n2, &shares[1])]
        .into_iter()
        .map(|(nonces, share)| sign(&request, nonces, share).unwrap())
        .map(|part| SignatureShare::from_bytes(part.participant, &part.to_bytes()).unwrap())
        .collect();
    let signature = aggregate(&group, &request, &parts).unwrap().to_bytes();
    assert!(dalek_verifies(b"m", &signature, &group.verifying_key()));

    let p = params(2, 3);
    let mut stream = rng("bytes dkg");
    let (starts, round1): (Vec<_>, Vec<_>) = p
        .participants()
        .map(|i| dkg::start_with_rng(i, p, &mut stream).unwrap())
        .unzip();
    for package in &round1 {
        let carried =
            dkg::Round1Package::from_bytes(package.from, &package.to_bytes().unwrap()).unwrap();
        assert_eq!(&carried, package);
    }
    let first = starts.into_iter().next().unwrap();
    let (_, sends) = dkg::exchange(first, &round1).unwrap();
    assert_eq!(sends.len(), 2);
    for send in &sends {
        let carried =
            dkg::Round2Package::from_bytes(send.from, send.to, &send.to_bytes().unwrap()).unwrap();
        assert_eq!(&carried, send);
    }

    let garbage = [0x00, 0xff];
    assert!(matches!(
        Commitment::from_bytes(id(1), &garbage),
        Err(ThresholdError::Protocol(_))
    ));
    assert!(matches!(
        SignatureShare::from_bytes(id(1), &garbage),
        Err(ThresholdError::Protocol(_))
    ));
    assert!(matches!(
        dkg::Round1Package::from_bytes(id(1), &garbage),
        Err(ThresholdError::Protocol(_))
    ));
    assert!(matches!(
        dkg::Round2Package::from_bytes(id(1), id(2), &garbage),
        Err(ThresholdError::Protocol(_))
    ));
}

#[test]
fn a_request_built_without_the_group_refuses_a_duplicate_and_signs_only_at_k() {
    let (shares, group) = dealt("request");
    let mut stream = rng("request nonces");
    let (nonces, commitment) = commit_with_rng(&shares[0], b"m", &mut stream);
    assert_eq!(
        SigningRequest::from_commitments(b"m", vec![commitment.clone(), commitment.clone()])
            .unwrap_err(),
        ThresholdError::DuplicateParticipant(id(1))
    );
    let alone = SigningRequest::from_commitments(b"m", vec![commitment.clone()]).unwrap();
    assert_eq!(
        sign(&alone, nonces, &shares[0]).unwrap_err(),
        ThresholdError::BelowThreshold { have: 1, need: 2 }
    );
    assert_eq!(
        SigningRequest::new(&group, b"m", vec![commitment]).unwrap_err(),
        ThresholdError::BelowThreshold { have: 1, need: 2 }
    );
}
