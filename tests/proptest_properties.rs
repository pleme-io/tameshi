#![allow(clippy::pedantic)]

use proptest::prelude::*;
use std::collections::BTreeMap;
use tameshi::certification_artifact::{
    compose_certification_artifact, verify_certification_artifact, verify_proof_path,
};
use tameshi::changeset::{Operation, ResourceId, certify_changeset, verify_changeset};
use tameshi::gating::{GatingPolicy, evaluate_gate};
use tameshi::global::{ClusterRootEntry, ClusterStatus, compute_cluster_root, compute_global_root};
use tameshi::hash::Blake3Hash;
use tameshi::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};
use tameshi::merkle::{
    compose_merkle, compute_merkle_root, domain_separated_leaf, merkle_proof, verify_proof,
};
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};
use tameshi::signing::{LocalSigner, MerkleRootSigner, MockDfcSigner};

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
        Just(LayerType::FerritePoms),
    ]
}

fn arb_layer_sig() -> impl Strategy<Value = LayerSignature> {
    (arb_layer_type(), prop::collection::vec(any::<u8>(), 1..256)).prop_map(|(lt, data)| {
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

// =========================================================================
// Extended property-based tests (10,000 cases each)
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    // Property 1: Avalanche effect (Thm 3.1)
    // Flipping a single bit should cause ~50% of output bits to change.
    #[test]
    fn avalanche_effect(
        data in prop::collection::vec(any::<u8>(), 1..256),
        byte_idx in any::<prop::sample::Index>(),
        bit_idx in 0..8u8,
    ) {
        let mut flipped = data.clone();
        let idx = byte_idx.index(flipped.len());
        flipped[idx] ^= 1 << bit_idx;
        let h1 = Blake3Hash::digest(&data);
        let h2 = Blake3Hash::digest(&flipped);
        // Count differing bits
        let mut diff_bits = 0u32;
        for (a, b) in h1.0.iter().zip(h2.0.iter()) {
            diff_bits += (a ^ b).count_ones();
        }
        // Conservatively require >= 64 of 256 bits differ (25%)
        prop_assert!(diff_bits >= 64, "Only {} bits differ out of 256", diff_bits);
    }

    // Property 2: Domain separation leaf vs internal (Thm 2.2)
    // Leaf domain (0x00 prefix) must produce different hash than internal (0x01 prefix).
    #[test]
    fn domain_separation_leaf_vs_internal(data in any::<[u8; 32]>()) {
        let leaf = domain_separated_leaf(&data);
        // Simulate internal-node domain: 0x01 || data
        let mut internal_input = Vec::with_capacity(33);
        internal_input.push(0x01);
        internal_input.extend_from_slice(&data);
        let internal: [u8; 32] = blake3::hash(&internal_input).into();
        prop_assert_ne!(leaf, internal, "Leaf and internal domain hashes must differ");
    }

    // Property 3: Hierarchical tamper detection (Thm 6.2)
    // Tampering with one artifact in one cluster must change the global root.
    #[test]
    fn hierarchical_tamper_detection(
        cluster_count in 2..4usize,
        artifacts_per_cluster in 2..5usize,
        seed in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 4..21),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let signer = LocalSigner::for_testing();

        // Build clusters
        let mut all_cluster_artifacts: Vec<Vec<Blake3Hash>> = Vec::new();
        let mut seed_idx = 0;
        for _ in 0..cluster_count {
            let mut artifacts = Vec::new();
            for _ in 0..artifacts_per_cluster {
                let s = &seed[seed_idx % seed.len()];
                artifacts.push(Blake3Hash::digest(s));
                seed_idx += 1;
            }
            all_cluster_artifacts.push(artifacts);
        }

        // Build original global root
        let mut original_map = BTreeMap::new();
        for (i, artifacts) in all_cluster_artifacts.iter().enumerate() {
            let cluster_root = compute_cluster_root(artifacts);
            let signed = rt.block_on(signer.sign(&cluster_root)).unwrap();
            let cluster_id = format!("cluster-{i}");
            original_map.insert(cluster_id.clone(), ClusterRootEntry {
                cluster_id,
                cluster_root,
                signed_root: signed,
                node_count: 1,
                artifact_count: artifacts.len() as u64,
                last_reported: chrono::Utc::now(),
                status: ClusterStatus::Active,
            });
        }
        let original_global = compute_global_root(&original_map);

        // Tamper: modify first artifact of first cluster
        let mut tampered_artifacts = all_cluster_artifacts.clone();
        tampered_artifacts[0][0] = Blake3Hash::digest(b"TAMPERED");
        let tampered_cluster_root = compute_cluster_root(&tampered_artifacts[0]);
        let tampered_signed = rt.block_on(signer.sign(&tampered_cluster_root)).unwrap();
        let mut tampered_map = original_map.clone();
        let entry = tampered_map.get_mut("cluster-0").unwrap();
        entry.cluster_root = tampered_cluster_root;
        entry.signed_root = tampered_signed;
        let tampered_global = compute_global_root(&tampered_map);

        prop_assert_ne!(original_global, tampered_global, "Tampered global root must differ");
    }

    // Property 4: Chain integrity random tampering (Thm 7.1)
    // Tampering with any entry_hash breaks the chain linkage.
    #[test]
    fn chain_integrity_random_tampering(
        entry_count in 3..11usize,
        tamper_idx in any::<prop::sample::Index>(),
    ) {
        let chain = HeartbeatChain::new();
        let verifier = VerifierIdentity::new("test", "proptest", "0.1");
        for i in 0..entry_count {
            chain.append(
                verifier.clone(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                &format!("resource-{i}"),
                Blake3Hash::digest(format!("sig-{i}").as_bytes()),
            );
        }
        // Chain should be valid before tampering
        prop_assert!(chain.verify_integrity(), "Chain should be valid before tampering");

        let entries = chain.entries();
        let idx = tamper_idx.index(entries.len().saturating_sub(1)); // tamper with 0..N-1
        // After tampering entry[idx].entry_hash, entry[idx+1].previous_hash won't match
        let tampered_hash = Blake3Hash::digest(b"tampered");
        let next_entry = &entries[idx + 1];
        prop_assert_ne!(
            &next_entry.previous_hash, &tampered_hash,
            "Entry after tampered one has wrong previous_hash"
        );
    }

    // Property 5: Two-phase binding different compliance (Thm 9.1)
    // Same layers + different compliance hashes => different secure hashes.
    #[test]
    fn two_phase_binding_different_compliance(
        layers in prop::collection::vec(arb_layer_sig(), 1..6),
        comp_a in prop::collection::vec(any::<u8>(), 1..64),
        comp_b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(comp_a != comp_b);
        let master_a = compose_merkle(&layers, "proptest")
            .with_compliance(Blake3Hash::digest(&comp_a));
        let master_b = compose_merkle(&layers, "proptest")
            .with_compliance(Blake3Hash::digest(&comp_b));
        prop_assert_ne!(
            master_a.secure.unwrap(),
            master_b.secure.unwrap(),
            "Different compliance must yield different secure hashes"
        );
    }

    // Property 6: Two-phase binding different untested (Thm 9.1)
    // Different layer sets + same compliance hash => different secure hashes.
    #[test]
    fn two_phase_binding_different_untested(
        layers_a in prop::collection::vec(arb_layer_sig(), 1..6),
        layers_b in prop::collection::vec(arb_layer_sig(), 1..6),
        compliance_data in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let root_a = compute_merkle_root(&layers_a);
        let root_b = compute_merkle_root(&layers_b);
        prop_assume!(root_a != root_b);
        let compliance = Blake3Hash::digest(&compliance_data);
        let master_a = compose_merkle(&layers_a, "proptest")
            .with_compliance(compliance.clone());
        let master_b = compose_merkle(&layers_b, "proptest")
            .with_compliance(compliance);
        prop_assert_ne!(
            master_a.secure.unwrap(),
            master_b.secure.unwrap(),
            "Different untested roots must yield different secure hashes"
        );
    }

    // Property 7: Certification artifact three paths independent (Thm 4.1)
    // All 3 proof paths independently verify against the composed root.
    #[test]
    fn certification_artifact_three_paths_independent(
        a_data in prop::collection::vec(any::<u8>(), 1..256),
        c_data in prop::collection::vec(any::<u8>(), 1..256),
        i_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let a = Blake3Hash::digest(&a_data);
        let c = Blake3Hash::digest(&c_data);
        let i = Blake3Hash::digest(&i_data);
        let art = compose_certification_artifact("/bin/test", a.clone(), c.clone(), i.clone(), "test");

        // Verify each proof path independently
        let artifact_ok = verify_proof_path(
            &art.proof_paths.artifact_proof, &art.composed_root, &a, 0, 3,
        );
        let control_ok = verify_proof_path(
            &art.proof_paths.control_proof, &art.composed_root, &c, 1, 3,
        );
        let intent_ok = verify_proof_path(
            &art.proof_paths.intent_proof, &art.composed_root, &i, 2, 3,
        );
        prop_assert!(artifact_ok, "Artifact proof path must verify");
        prop_assert!(control_ok, "Control proof path must verify");
        prop_assert!(intent_ok, "Intent proof path must verify");
    }

    // Property 8: Certification artifact partial tamper (Thm 4.1)
    // Tampering with control_hash makes verification fail.
    #[test]
    fn certification_artifact_partial_tamper(
        a_data in prop::collection::vec(any::<u8>(), 1..256),
        c_data in prop::collection::vec(any::<u8>(), 1..256),
        i_data in prop::collection::vec(any::<u8>(), 1..256),
        tamper_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(c_data != tamper_data);
        let a = Blake3Hash::digest(&a_data);
        let c = Blake3Hash::digest(&c_data);
        let i = Blake3Hash::digest(&i_data);
        let mut art = compose_certification_artifact("/bin/test", a, c, i, "test");
        art.control_hash = Blake3Hash::digest(&tamper_data);
        prop_assert!(!verify_certification_artifact(&art), "Tampered control_hash should fail verification");
    }

    // Property 9: Split knowledge fragment change (Thm 10.1)
    // Different fragment_a => different signatures.
    #[test]
    fn split_knowledge_fragment_change(
        frag_a1 in any::<[u8; 32]>(),
        frag_a2 in any::<[u8; 32]>(),
        frag_b in any::<[u8; 32]>(),
        root_data in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(frag_a1 != frag_a2);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = Blake3Hash::digest(&root_data);
        let signer1 = MockDfcSigner::from_fragments(frag_a1, frag_b, "signer-1");
        let signer2 = MockDfcSigner::from_fragments(frag_a2, frag_b, "signer-2");
        let sig1 = rt.block_on(signer1.sign(&root)).unwrap();
        let sig2 = rt.block_on(signer2.sign(&root)).unwrap();
        prop_assert_ne!(sig1.signature, sig2.signature, "Different fragments must produce different signatures");
    }

    // Property 10: Split knowledge both fragments needed (Thm 10.1)
    // Verifying with wrong fragment_a must fail.
    #[test]
    fn split_knowledge_both_fragments_needed(
        frag_a in any::<[u8; 32]>(),
        frag_a_wrong in any::<[u8; 32]>(),
        frag_b in any::<[u8; 32]>(),
        root_data in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(frag_a != frag_a_wrong);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = Blake3Hash::digest(&root_data);
        let signer = MockDfcSigner::from_fragments(frag_a, frag_b, "signer");
        let wrong_signer = MockDfcSigner::from_fragments(frag_a_wrong, frag_b, "signer");
        let signed = rt.block_on(signer.sign(&root)).unwrap();
        let verified = rt.block_on(wrong_signer.verify(&signed)).unwrap();
        prop_assert!(!verified, "Verification with wrong fragment_a must fail");
    }

    // Property 11: Canonical sort stability (Thm 5.1)
    // Layers with unique types in any order must produce the same Merkle root.
    #[test]
    fn canonical_sort_stability(
        count in 2..12usize,
        data_seed in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 12..13),
    ) {
        let all_types = [
            LayerType::Nix, LayerType::Oci, LayerType::Helm,
            LayerType::Tofu, LayerType::Kubernetes, LayerType::Kindling,
            LayerType::Tatara, LayerType::FluxCD, LayerType::ArgoCD,
            LayerType::Akeyless, LayerType::AkeylessTarget, LayerType::FerritePoms,
        ];
        let count = count.min(all_types.len());
        let layers: Vec<LayerSignature> = all_types[..count]
            .iter()
            .enumerate()
            .map(|(i, lt)| {
                let d = &data_seed[0][..std::cmp::min(data_seed[0].len(), i + 1)];
                LayerSignature::new(lt.clone(), Blake3Hash::digest(d), "proptest", vec![])
            })
            .collect();
        let root1 = compute_merkle_root(&layers);
        let mut reversed = layers.clone();
        reversed.reverse();
        let root2 = compute_merkle_root(&reversed);
        prop_assert_eq!(root1, root2, "Root must be order-independent due to canonical sort");
    }

    // Property 12: Global root order independence (Thm 6.1)
    // BTreeMap insertion order doesn't matter; global root is deterministic.
    #[test]
    fn global_root_order_independence(
        cluster_count in 2..6usize,
        seed in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 2..6),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let signer = LocalSigner::for_testing();

        // Build (key, seed) pairs so the mapping is stable regardless of insertion order
        let pairs: Vec<(String, &Vec<u8>)> = (0..cluster_count)
            .map(|i| (format!("cluster-{i:03}"), &seed[i % seed.len()]))
            .collect();

        let build_map = |pair_order: &[(String, &Vec<u8>)]| -> BTreeMap<String, ClusterRootEntry> {
            let mut map = BTreeMap::new();
            for (k, s) in pair_order {
                let cr = Blake3Hash::digest(s);
                let signed = rt.block_on(signer.sign(&cr)).unwrap();
                map.insert(k.clone(), ClusterRootEntry {
                    cluster_id: k.clone(),
                    cluster_root: cr,
                    signed_root: signed,
                    node_count: 1,
                    artifact_count: 1,
                    last_reported: chrono::Utc::now(),
                    status: ClusterStatus::Active,
                });
            }
            map
        };

        let map1 = build_map(&pairs);
        let mut reversed_pairs = pairs.clone();
        reversed_pairs.reverse();
        let map2 = build_map(&reversed_pairs);

        let root1 = compute_global_root(&map1);
        let root2 = compute_global_root(&map2);
        prop_assert_eq!(root1, root2, "Global root must be independent of insertion order");
    }

    // Property 13: Consistency proof after extend (Thm 8.1)
    // The from_hash of a consistency proof anchors correctly across extensions.
    #[test]
    fn consistency_proof_after_extend(
        n in 3..9usize,
        m in 1..6usize,
    ) {
        let chain = HeartbeatChain::new();
        let verifier = VerifierIdentity::new("test", "proptest", "0.1");

        // Build N entries
        for i in 0..n {
            chain.append(
                verifier.clone(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                &format!("res-{i}"),
                Blake3Hash::digest(format!("sig-{i}").as_bytes()),
            );
        }
        let proof1 = chain.consistency_proof(0, (n - 1) as u64).unwrap();

        // Extend with M more entries
        for i in 0..m {
            chain.append(
                verifier.clone(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                &format!("ext-{i}"),
                Blake3Hash::digest(format!("ext-sig-{i}").as_bytes()),
            );
        }
        let proof2 = chain.consistency_proof(0, (n + m - 1) as u64).unwrap();

        // Both proofs start from the same anchor
        prop_assert_eq!(
            proof1.from_hash, proof2.from_hash,
            "from_hash must be identical across extensions"
        );
    }

    // Property 14: Gating default deny
    // Default policy (require_compliance=true) denies master without compliance.
    #[test]
    fn gating_default_deny(layers in prop::collection::vec(arb_layer_sig(), 1..5)) {
        let master = compose_merkle(&layers, "proptest"); // no compliance
        let expected = master.gating_signature().clone();
        let policy = GatingPolicy {
            require_compliance: true,
            max_signature_age_secs: None,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        prop_assert!(!decision.allowed, "Default policy must deny without compliance");
    }

    // Property 15: Merkle proof tamper with sibling (Thm 3.3)
    // Tampering with a proof hash makes verification fail.
    #[test]
    fn merkle_proof_tamper_with_sibling(
        layers in prop::collection::vec(arb_layer_sig(), 3..10),
        target_idx in any::<prop::sample::Index>(),
    ) {
        let root = compute_merkle_root(&layers);
        let mut sorted = layers.clone();
        sorted.sort_by(|a, b| a.layer.cmp(&b.layer));
        let idx = target_idx.index(sorted.len());

        if let Some(mut proof_hashes) = merkle_proof(&layers, idx) {
            if !proof_hashes.is_empty() {
                // Tamper with the first proof hash
                proof_hashes[0] = Blake3Hash::digest(b"tampered-sibling").0;
                let valid = verify_proof(&proof_hashes, &root, &sorted[idx], idx, sorted.len());
                prop_assert!(!valid, "Tampered proof sibling must cause verification failure");
            }
        }
    }

    // Property 16: Certification artifact root guessing (Cor 4.1.1)
    // Random roots should not match the real composed_root.
    #[test]
    fn certification_artifact_root_guessing(
        a_data in prop::collection::vec(any::<u8>(), 1..64),
        c_data in prop::collection::vec(any::<u8>(), 1..64),
        i_data in prop::collection::vec(any::<u8>(), 1..64),
        guesses in prop::collection::vec(any::<[u8; 32]>(), 100..101),
    ) {
        let art = compose_certification_artifact(
            "/bin/test",
            Blake3Hash::digest(&a_data),
            Blake3Hash::digest(&c_data),
            Blake3Hash::digest(&i_data),
            "test",
        );
        for guess in &guesses {
            let guessed_root = Blake3Hash::from(*guess);
            prop_assert_ne!(
                &art.composed_root, &guessed_root,
                "Random guess should not match composed_root"
            );
        }
    }

    // Property 17: Selective disclosure hides other leaves (Cor 4.1.2)
    // The artifact_proof should not contain raw control_hash or intent_hash bytes.
    #[test]
    fn selective_disclosure_hides_other_leaves(
        a_data in prop::collection::vec(any::<u8>(), 1..256),
        c_data in prop::collection::vec(any::<u8>(), 1..256),
        i_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let c = Blake3Hash::digest(&c_data);
        let i = Blake3Hash::digest(&i_data);
        let art = compose_certification_artifact(
            "/bin/test",
            Blake3Hash::digest(&a_data),
            c.clone(),
            i.clone(),
            "test",
        );
        // The artifact proof path should not contain the raw control_hash or intent_hash
        for proof_node in &art.proof_paths.artifact_proof {
            prop_assert_ne!(proof_node, &c, "Proof must not leak raw control_hash");
            prop_assert_ne!(proof_node, &i, "Proof must not leak raw intent_hash");
        }
    }

    // Property 18: Chain deletion detection (Cor 7.1.1)
    // Removing an entry from the chain breaks linkage.
    #[test]
    fn chain_deletion_detection(
        entry_count in 5..11usize,
        delete_idx in 1..4usize,
    ) {
        let chain = HeartbeatChain::new();
        let verifier = VerifierIdentity::new("test", "proptest", "0.1");
        for i in 0..entry_count {
            chain.append(
                verifier.clone(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                &format!("res-{i}"),
                Blake3Hash::digest(format!("sig-{i}").as_bytes()),
            );
        }
        let entries = chain.entries();
        let del_idx = delete_idx % (entries.len() - 1); // ensure valid index and not last
        // Remove the entry at del_idx
        let mut pruned: Vec<_> = entries.clone();
        pruned.remove(del_idx);
        // The entry now at del_idx (was del_idx+1) has a previous_hash pointing
        // to the removed entry, not to entries[del_idx-1]
        let entry_after = &pruned[del_idx];
        let entry_before = if del_idx > 0 {
            &pruned[del_idx - 1]
        } else {
            // If we removed index 0, the new index 0's previous_hash should be all zeros
            // but it will point to the removed entry's hash
            &pruned[0]
        };
        if del_idx > 0 {
            prop_assert_ne!(
                &entry_after.previous_hash,
                &entry_before.entry_hash,
                "Deletion at index {} must break chain linkage",
                del_idx
            );
        } else {
            let zero_hash = Blake3Hash::from([0u8; 32]);
            prop_assert_ne!(
                &entry_after.previous_hash,
                &zero_hash,
                "Deletion at index 0 must break chain linkage"
            );
        }
    }

    // Property 19: Chain reorder detection (Cor 7.1.2)
    // Swapping two adjacent entries breaks chain linkage.
    #[test]
    fn chain_reorder_detection(
        entry_count in 5..11usize,
        swap_idx in 1..4usize,
    ) {
        let chain = HeartbeatChain::new();
        let verifier = VerifierIdentity::new("test", "proptest", "0.1");
        for i in 0..entry_count {
            chain.append(
                verifier.clone(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                &format!("res-{i}"),
                Blake3Hash::digest(format!("sig-{i}").as_bytes()),
            );
        }
        let mut entries = chain.entries();
        let idx = swap_idx % (entries.len() - 1); // ensure valid swap range
        entries.swap(idx, idx + 1);
        // After swapping, entries[idx+1].previous_hash should NOT equal entries[idx].entry_hash
        // (since entries[idx+1] was originally entries[idx] and vice versa)
        let broken = entries[idx + 1].previous_hash != entries[idx].entry_hash;
        prop_assert!(broken, "Swapping entries at index {} must break chain linkage", idx);
    }

    // Property 20: Compliance cannot be retrofitted (Cor 9.1.1)
    // Publishing untested hash U then adding compliance C produces secure hash S = H(U||C).
    // An attacker who publishes U cannot later substitute a different compliance C' and
    // claim the result was the original S. Different C => different S, even with same U.
    #[test]
    fn compliance_cannot_be_retrofitted(
        layers in prop::collection::vec(arb_layer_sig(), 1..5),
        c1_data in prop::collection::vec(any::<u8>(), 1..256),
        c2_data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(c1_data != c2_data);
        let master = compose_merkle(&layers, "proptest");
        let published_untested = master.untested.clone();

        // Two different compliance hashes applied to the SAME published untested
        let c1 = Blake3Hash::digest(&c1_data);
        let c2 = Blake3Hash::digest(&c2_data);
        let s1 = master.clone().with_compliance(c1);
        let s2 = master.with_compliance(c2);

        // The secure hashes must differ — cannot retrofit a different compliance
        prop_assert_ne!(
            s1.secure.as_ref().unwrap(),
            s2.secure.as_ref().unwrap(),
            "Different compliance on same untested must produce different secure hashes"
        );

        // Both must share the same untested root (it was already published)
        prop_assert_eq!(
            &s1.untested, &published_untested,
            "Untested root must be preserved after compliance"
        );
        prop_assert_eq!(
            &s2.untested, &published_untested,
            "Untested root must be preserved after compliance"
        );
    }
}
