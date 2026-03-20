#![allow(clippy::pedantic)]

use proptest::prelude::*;
use tameshi::changeset::{Operation, ResourceId, certify_changeset, verify_changeset};
use tameshi::gating::{GatingPolicy, evaluate_gate};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::{compose_merkle, compute_merkle_root, merkle_proof, verify_proof};
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};

fn arb_layer_type() -> impl Strategy<Value = LayerType> {
    prop_oneof![
        Just(LayerType::Nix),
        Just(LayerType::Oci),
        Just(LayerType::Helm),
        Just(LayerType::Tofu),
        Just(LayerType::Kubernetes),
        Just(LayerType::Kindling),
        Just(LayerType::Tatara),
        Just(LayerType::FluxCD),
        Just(LayerType::ArgoCD),
        Just(LayerType::Akeyless),
        Just(LayerType::AkeylessTarget),
    ]
}

fn arb_layer_sig() -> impl Strategy<Value = LayerSignature> {
    (
        arb_layer_type(),
        prop::collection::vec(any::<u8>(), 1..256),
    )
        .prop_map(|(lt, data)| {
            LayerSignature::new(lt, Blake3Hash::digest(&data), "proptest", vec![])
        })
}

proptest! {
    // Hash determinism
    #[test]
    fn hash_determinism(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let h1 = Blake3Hash::digest(&data);
        let h2 = Blake3Hash::digest(&data);
        prop_assert_eq!(h1, h2);
    }

    // Hash sensitivity
    #[test]
    fn hash_sensitivity(
        a in prop::collection::vec(any::<u8>(), 1..256),
        b in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(a != b);
        let ha = Blake3Hash::digest(&a);
        let hb = Blake3Hash::digest(&b);
        prop_assert_ne!(ha, hb);
    }

    // Hash combine non-commutativity
    #[test]
    fn hash_combine_non_commutative(
        a in prop::collection::vec(any::<u8>(), 1..64),
        b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(a != b);
        let ha = Blake3Hash::digest(&a);
        let hb = Blake3Hash::digest(&b);
        let ab = Blake3Hash::combine(&ha, &hb);
        let ba = Blake3Hash::combine(&hb, &ha);
        prop_assert_ne!(ab, ba);
    }

    // Hex encoding roundtrip
    #[test]
    fn hex_roundtrip(data in prop::collection::vec(any::<u8>(), 1..256)) {
        let h = Blake3Hash::digest(&data);
        let hex = h.to_hex();
        let h2 = Blake3Hash::from_hex(&hex).unwrap();
        prop_assert_eq!(h, h2);
    }

    // Prefixed encoding roundtrip
    #[test]
    fn prefixed_roundtrip(data in prop::collection::vec(any::<u8>(), 1..256)) {
        let h = Blake3Hash::digest(&data);
        let prefixed = h.to_prefixed();
        let h2 = Blake3Hash::from_prefixed(&prefixed).unwrap();
        prop_assert_eq!(h, h2);
    }

    // Merkle root order independence (requires unique layer types for stable sort)
    #[test]
    fn merkle_order_independence(
        count in 2..11usize,
        data_seed in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 11..12),
    ) {
        let all_types = [
            LayerType::Nix,
            LayerType::Oci,
            LayerType::Helm,
            LayerType::Tofu,
            LayerType::Kubernetes,
            LayerType::Kindling,
            LayerType::Tatara,
            LayerType::FluxCD,
            LayerType::ArgoCD,
            LayerType::Akeyless,
            LayerType::AkeylessTarget,
        ];
        let layers: Vec<LayerSignature> = all_types[..count]
            .iter()
            .enumerate()
            .map(|(i, lt)| {
                let d = &data_seed[0][..std::cmp::min(data_seed[0].len(), i + 1)];
                LayerSignature::new(lt.clone(), Blake3Hash::digest(d), "proptest", vec![])
            })
            .collect();
        let root1 = compute_merkle_root(&layers);
        let mut shuffled = layers.clone();
        shuffled.reverse();
        let root2 = compute_merkle_root(&shuffled);
        prop_assert_eq!(root1, root2);
    }

    // Merkle tamper detection
    #[test]
    fn merkle_tamper_detection(
        layers in prop::collection::vec(arb_layer_sig(), 2..10),
        idx in any::<prop::sample::Index>(),
    ) {
        let root = compute_merkle_root(&layers);
        let mut tampered = layers.clone();
        let i = idx.index(tampered.len());
        tampered[i] = LayerSignature::new(
            tampered[i].layer.clone(),
            Blake3Hash::digest(b"tampered-content"),
            "tampered",
            vec![],
        );
        let tampered_root = compute_merkle_root(&tampered);
        prop_assert_ne!(root, tampered_root);
    }

    // Merkle proof validity
    #[test]
    fn merkle_proof_validity(layers in prop::collection::vec(arb_layer_sig(), 2..20)) {
        let root = compute_merkle_root(&layers);
        let mut sorted = layers.clone();
        sorted.sort_by(|a, b| a.layer.cmp(&b.layer));
        for i in 0..sorted.len() {
            if let Some(proof_hashes) = merkle_proof(&layers, i) {
                let valid = verify_proof(&proof_hashes, &root, &sorted[i], i, sorted.len());
                prop_assert!(valid, "Proof should verify for index {}", i);
            }
        }
    }

    // Master signature untested roundtrip
    #[test]
    fn master_untested_roundtrip(layers in prop::collection::vec(arb_layer_sig(), 1..10)) {
        let master = compose_merkle(&layers, "proptest");
        prop_assert!(master.verify_untested());
    }

    // Two-phase consistency
    #[test]
    fn two_phase_consistency(
        layers in prop::collection::vec(arb_layer_sig(), 1..10),
        compliance_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let compliance = Blake3Hash::digest(&compliance_data);
        let master = compose_merkle(&layers, "proptest").with_compliance(compliance);
        prop_assert!(master.verify_untested());
        prop_assert!(master.verify_secure());
        prop_assert!(master.is_fully_attested());
    }

    // Gating transitivity (matching sig => allow)
    #[test]
    fn gating_transitivity(layers in prop::collection::vec(arb_layer_sig(), 1..5)) {
        let compliance = Blake3Hash::digest(b"compliance");
        let master = compose_merkle(&layers, "proptest").with_compliance(compliance);
        let expected = master.gating_signature().clone();
        let policy = GatingPolicy {
            require_compliance: true,
            max_signature_age_secs: None,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        prop_assert!(decision.allowed);
    }

    // Layer type display/parse roundtrip
    #[test]
    fn layer_type_roundtrip(lt in arb_layer_type()) {
        let s = lt.to_string();
        let parsed: LayerType = s.parse().unwrap();
        prop_assert_eq!(lt, parsed);
    }

    // Serde roundtrip for MasterSignature
    #[test]
    fn master_sig_serde_roundtrip(layers in prop::collection::vec(arb_layer_sig(), 1..5)) {
        let master = compose_merkle(&layers, "proptest");
        let json = serde_json::to_string(&master).unwrap();
        let deserialized: MasterSignature = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(master.untested, deserialized.untested);
        prop_assert_eq!(master.environment, deserialized.environment);
    }

    // Changeset certify/verify roundtrip
    #[test]
    fn changeset_roundtrip(content in prop::collection::vec(any::<u8>(), 1..256)) {
        let resource = ResourceId {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
        };
        let before = Blake3Hash::digest(b"before");
        let after = Blake3Hash::digest(b"after");
        let env_sig = Blake3Hash::digest(b"env");
        let compliance = Blake3Hash::digest(b"compliance");
        let certified = certify_changeset(
            Operation::Update,
            resource,
            &content,
            Some(&before),
            Some(&after),
            &env_sig,
            Some(&compliance),
            "tester",
        );
        prop_assert!(verify_changeset(&certified));
    }

    // Changeset tamper detection
    #[test]
    fn changeset_tamper_detection(content in prop::collection::vec(any::<u8>(), 1..256)) {
        let resource = ResourceId {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
        };
        let before = Blake3Hash::digest(b"before");
        let after = Blake3Hash::digest(b"after");
        let env_sig = Blake3Hash::digest(b"env");
        let compliance = Blake3Hash::digest(b"compliance");
        let mut certified = certify_changeset(
            Operation::Update,
            resource,
            &content,
            Some(&before),
            Some(&after),
            &env_sig,
            Some(&compliance),
            "tester",
        );
        // Tamper with the changeset hash
        certified.changeset_hash = Blake3Hash::digest(b"tampered");
        prop_assert!(!verify_changeset(&certified));
    }

    // =========================================================================
    // Pillar 1: CertificationArtifact proptest properties
    // =========================================================================

    // Random inputs always produce valid artifacts that verify
    #[test]
    fn certification_artifact_compose_verify_roundtrip(
        a_data in prop::collection::vec(any::<u8>(), 1..256),
        c_data in prop::collection::vec(any::<u8>(), 1..256),
        i_data in prop::collection::vec(any::<u8>(), 1..256),
        path in "[a-z/]{1,100}",
        env in "[a-z]{1,20}",
    ) {
        use tameshi::certification_artifact::{compose_certification_artifact, verify_certification_artifact};

        let a = Blake3Hash::digest(&a_data);
        let c = Blake3Hash::digest(&c_data);
        let i = Blake3Hash::digest(&i_data);
        let art = compose_certification_artifact(&path, a, c, i, &env);
        prop_assert!(verify_certification_artifact(&art), "Random artifact should verify");
    }

    // Different artifact inputs always produce different roots
    #[test]
    fn certification_artifact_collision_resistance(
        a1_data in prop::collection::vec(any::<u8>(), 1..256),
        a2_data in prop::collection::vec(any::<u8>(), 1..256),
        shared_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        use tameshi::certification_artifact::compose_certification_artifact;

        prop_assume!(a1_data != a2_data);
        let c = Blake3Hash::digest(&shared_data);
        let i = Blake3Hash::digest(&shared_data);
        let art1 = compose_certification_artifact("/bin/app", Blake3Hash::digest(&a1_data), c.clone(), i.clone(), "prod");
        let art2 = compose_certification_artifact("/bin/app", Blake3Hash::digest(&a2_data), c, i, "prod");
        prop_assert_ne!(art1.composed_root, art2.composed_root);
    }

    // Tampered artifact never verifies
    #[test]
    fn certification_artifact_tamper_detection(
        a_data in prop::collection::vec(any::<u8>(), 1..256),
        c_data in prop::collection::vec(any::<u8>(), 1..256),
        i_data in prop::collection::vec(any::<u8>(), 1..256),
        tamper_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        use tameshi::certification_artifact::{compose_certification_artifact, verify_certification_artifact};

        prop_assume!(a_data != tamper_data);
        let a = Blake3Hash::digest(&a_data);
        let c = Blake3Hash::digest(&c_data);
        let i = Blake3Hash::digest(&i_data);
        let mut art = compose_certification_artifact("/bin/app", a, c, i, "prod");
        // Tamper with artifact hash
        art.artifact_hash = Blake3Hash::digest(&tamper_data);
        prop_assert!(!verify_certification_artifact(&art), "Tampered artifact should not verify");
    }

    // Serde roundtrip preserves certification artifact integrity
    #[test]
    fn certification_artifact_serde_roundtrip(
        a_data in prop::collection::vec(any::<u8>(), 1..256),
        c_data in prop::collection::vec(any::<u8>(), 1..256),
        i_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        use tameshi::certification_artifact::{CertificationArtifact, compose_certification_artifact, verify_certification_artifact};

        let art = compose_certification_artifact(
            "/bin/app",
            Blake3Hash::digest(&a_data),
            Blake3Hash::digest(&c_data),
            Blake3Hash::digest(&i_data),
            "prod",
        );
        let json = serde_json::to_string(&art).unwrap();
        let deserialized: CertificationArtifact = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&art, &deserialized);
        prop_assert!(verify_certification_artifact(&deserialized));
    }
}
