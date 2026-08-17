//! End-to-end attestation chain tests.
//!
//! Exercises the FULL attestation pipeline:
//!   Collectors -> LayerSignatures -> Merkle Tree -> Master Signature
//!                                                       +
//!                                             Compliance Hash
//!                                                       =
//!                                             Secure Master Signature
//!                                                       +
//!                                             Product Certification

use chrono::Utc;

use tameshi::certification::{
    BuildAttestation, ChartAttestation, DependencyHash, DeploymentAttestation, ImageAttestation,
    ProductCertification, SourceAttestation, relaxed_staging_policy, strict_production_policy,
};
use tameshi::collectors::akeyless::AkeylessCollector;
use tameshi::collectors::mock::MockCollector;
use tameshi::collectors::traits::LayerCollector;
use tameshi::compliance::akeyless::{
    AkeylessAuthMethod, AkeylessSecretAccess, AkeylessSecretAttestation, AkeylessSecretType,
    compute_akeyless_hash,
};
use tameshi::compliance::cve::{
    ScanTarget, ScanTargetType, VulnSummary, VulnerabilityScan, VulnerabilityScanner,
};
use tameshi::compliance::dimensions::{
    AttestationBuilder, ComplianceAttestation, ComplianceDimension, DimensionType,
};
use tameshi::compliance::sbom::{
    SbomAttestation, SbomFormat, SbomGenerator, SbomSubject, SbomSubjectType,
};
use tameshi::compliance::slsa::{
    ArtifactType, BuildType, ProvenanceSubject, SlsaLevel, SlsaProvenance,
};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::{
    compose_merkle, compute_merkle_root, domain_separated_leaf, merkle_proof, verify_proof,
};
use tameshi::signature::{InputHash, LayerSignature, LayerType};
use tameshi::verify::verify_master;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_source() -> SourceAttestation {
    SourceAttestation {
        repository: "github.com/pleme-io/myapp".to_string(),
        commit: "abc123def456".to_string(),
        git_ref: "refs/heads/main".to_string(),
        commit_signed: true,
        tree_hash: Blake3Hash::digest(b"git-tree-content"),
        flake_lock_hash: Blake3Hash::digest(b"flake-lock-content"),
        flake_input_count: 8,
        all_inputs_pinned: true,
    }
}

fn make_build(service: &str) -> BuildAttestation {
    BuildAttestation {
        service: service.to_string(),
        derivation: format!("/nix/store/xxxxx-myapp-{service}.drv"),
        closure_hash: Blake3Hash::digest(format!("closure-{service}").as_bytes()),
        slsa_level: SlsaLevel::L3,
        reproducible: true,
        hermetic: true,
        sbom_hash: Blake3Hash::digest(format!("sbom-{service}").as_bytes()),
        vuln_scan_hash: Blake3Hash::digest(format!("vulns-{service}").as_bytes()),
        cve_count: 1,
        critical_high_cves: 0,
        builder: "nix-build@forge.pleme.io".to_string(),
        built_at: Utc::now(),
    }
}

fn make_image(service: &str) -> ImageAttestation {
    ImageAttestation {
        image_ref: format!("ghcr.io/pleme-io/myapp-{service}"),
        tag: format!("amd64-abc123"),
        architecture: "amd64".to_string(),
        manifest_hash: Blake3Hash::digest(format!("manifest-{service}").as_bytes()),
        cosign_verified: true,
        signer_identity: Some("github-actions[bot]".to_string()),
        vuln_scan_hash: Blake3Hash::digest(b"trivy-image-scan"),
        vuln_count: 2,
        critical_high_vulns: 0,
        sbom_hash: Blake3Hash::digest(b"image-sbom"),
        layer_type: LayerType::Oci,
    }
}

fn make_chart(name: &str) -> ChartAttestation {
    ChartAttestation {
        chart_name: name.to_string(),
        chart_version: "0.2.0".to_string(),
        chart_hash: Blake3Hash::digest(format!("chart-{name}").as_bytes()),
        provenance_verified: true,
        dependency_hashes: vec![DependencyHash {
            name: "pleme-lib".to_string(),
            version: "0.3.1".to_string(),
            hash: Blake3Hash::digest(b"pleme-lib-chart"),
        }],
        linter_passed: true,
        policy_passed: true,
        registry_ref: format!("oci://ghcr.io/pleme-io/charts/{name}"),
    }
}

fn make_deployment() -> DeploymentAttestation {
    DeploymentAttestation {
        namespace: "myapp-staging".to_string(),
        kustomization: "myapp-staging".to_string(),
        source_commit: "abc123def456".to_string(),
        source_verified: true,
        manifest_hash: Blake3Hash::digest(b"rendered-k8s-manifests"),
        all_releases_signed: true,
        cis_k8s_pass_rate: 0.93,
        network_policies_verified: true,
        running_pods: 6,
        all_healthy: true,
    }
}

fn make_compliance() -> ComplianceAttestation {
    ComplianceAttestation {
        environment: "staging".to_string(),
        artifact: "myapp".to_string(),
        dimensions: vec![
            ComplianceDimension {
                dimension_type: DimensionType::NistAssessment,
                hash: Blake3Hash::digest(b"nist-assessment"),
                passed: true,
                summary: "All controls satisfied".to_string(),
                assessed_at: Utc::now(),
                required: true,
            },
            ComplianceDimension {
                dimension_type: DimensionType::VulnerabilityScan,
                hash: Blake3Hash::digest(b"vuln-scan"),
                passed: true,
                summary: "0 critical, 0 high".to_string(),
                assessed_at: Utc::now(),
                required: true,
            },
        ],
        compliance_hash: Blake3Hash::digest(b"compliance-all-passed"),
        computed_at: Utc::now(),
        policy_name: "default".to_string(),
        all_passed: true,
    }
}

fn sample_akeyless_attestation() -> AkeylessSecretAttestation {
    AkeylessSecretAttestation {
        gateway_url: "https://gw.akeyless.example.com".to_string(),
        auth_method: AkeylessAuthMethod::K8s,
        secrets_accessed: vec![
            AkeylessSecretAccess {
                path: "/production/db-password".to_string(),
                secret_type: AkeylessSecretType::DynamicDatabase,
                value_hash: Blake3Hash::digest(b"secret-db-password-value"),
                accessed_at: Utc::now(),
                version: Some(3),
            },
            AkeylessSecretAccess {
                path: "/production/api-key".to_string(),
                secret_type: AkeylessSecretType::Static,
                value_hash: Blake3Hash::digest(b"secret-api-key-value"),
                accessed_at: Utc::now(),
                version: Some(1),
            },
        ],
        gateway_certificate_hash: Blake3Hash::digest(b"gateway-tls-cert"),
        session_hash: Blake3Hash::digest(b"auth-session-token"),
    }
}

fn make_vuln_scan() -> VulnerabilityScan {
    VulnerabilityScan {
        scanner: VulnerabilityScanner::Trivy,
        scanner_hash: Blake3Hash::digest(b"trivy"),
        db_version: "2026-03-18".to_string(),
        db_hash: Blake3Hash::digest(b"nvd"),
        target: ScanTarget {
            target_type: ScanTargetType::OciImage,
            identifier: "ghcr.io/pleme-io/myapp:latest".to_string(),
        },
        target_hash: Blake3Hash::digest(b"img"),
        vulnerabilities: vec![],
        summary: VulnSummary::default(),
        scanned_at: Utc::now(),
    }
}

fn make_sbom() -> SbomAttestation {
    SbomAttestation {
        format: SbomFormat::CycloneDx,
        generator: SbomGenerator::Syft,
        generator_hash: Blake3Hash::digest(b"syft"),
        sbom_hash: Blake3Hash::digest(b"sbom"),
        subject: SbomSubject {
            subject_type: SbomSubjectType::OciImage,
            identifier: "ghcr.io/pleme-io/myapp".to_string(),
            artifact_hash: Blake3Hash::digest(b"img"),
        },
        component_count: 42,
        dependency_count: 20,
        licenses: vec![],
        generated_at: Utc::now(),
        ntia_compliant: true,
    }
}

fn make_provenance() -> SlsaProvenance {
    SlsaProvenance {
        level: SlsaLevel::L3,
        build_type: BuildType::NixBuild,
        builder_id: "nix-build@forge.pleme.io".to_string(),
        source_repo: "github.com/pleme-io/myapp".to_string(),
        source_commit: "abc123def456".to_string(),
        source_ref: "main".to_string(),
        build_config: "flake.nix".to_string(),
        materials: vec![],
        subject: ProvenanceSubject {
            name: "myapp".to_string(),
            digest: Blake3Hash::digest(b"output"),
            artifact_type: ArtifactType::OciImage,
        },
        reproducible: true,
        hermetic: true,
        built_at: Utc::now(),
        triggered_by: "ci".to_string(),
        two_person_reviewed: false,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Full attestation chain end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_attestation_chain() {
    // 1. Source attestation — mock git commit hash
    let source_hash = Blake3Hash::digest(b"abc123def456-tree-content");
    assert_ne!(source_hash, Blake3Hash::digest(b""));

    // 2. Build attestation — mock Nix derivation closure hash
    let build_hash = Blake3Hash::digest(b"/nix/store/xxxxxxxxx-myapp-backend.drv-closure");
    assert_ne!(build_hash, Blake3Hash::digest(b""));

    // 3. Layer collection — use MockCollector for multiple layers
    let nix_collector = MockCollector::new(LayerType::Nix);
    let oci_collector = MockCollector::new(LayerType::Oci);
    let helm_collector = MockCollector::new(LayerType::Helm);
    let k8s_collector = MockCollector::new(LayerType::Kubernetes);
    let akeyless_collector = AkeylessCollector::new(sample_akeyless_attestation());

    let nix_sig = nix_collector.collect().await.unwrap();
    let oci_sig = oci_collector.collect().await.unwrap();
    let helm_sig = helm_collector.collect().await.unwrap();
    let k8s_sig = k8s_collector.collect().await.unwrap();
    let akeyless_sig = akeyless_collector.collect().await.unwrap();

    let signatures = vec![
        nix_sig.clone(),
        oci_sig.clone(),
        helm_sig.clone(),
        k8s_sig.clone(),
        akeyless_sig.clone(),
    ];
    assert_eq!(signatures.len(), 5);

    // 4. Merkle composition — compute Merkle root from all layer signatures
    let root = compute_merkle_root(&signatures);
    assert_ne!(root, Blake3Hash::digest(b"empty-tree"));

    // 5. Build master signature (untested)
    let master = compose_merkle(&signatures, "production");
    assert!(master.verify_untested());
    assert!(!master.is_fully_attested());

    // 6. Build compliance attestation
    let scan = make_vuln_scan();
    let sbom = make_sbom();
    let prov = make_provenance();

    let compliance = AttestationBuilder::new("production", "myapp-backend", "default")
        .with_vuln_scan(&scan, true, true)
        .with_sbom(&sbom, true)
        .with_slsa(&prov, &SlsaLevel::L2, true)
        .build();

    assert!(compliance.all_passed);
    assert_eq!(compliance.dimensions.len(), 3);

    // 7. Add compliance to master for secure signature
    let secure_master = master.with_compliance(compliance.compliance_hash.clone());
    assert!(secure_master.is_fully_attested());
    assert!(secure_master.verify_untested());
    assert!(secure_master.verify_secure());

    // 8. Verify master signature against its own gating signature
    let expected = secure_master.gating_signature().clone();
    let result = verify_master(&secure_master, &expected);
    assert!(
        result.passed,
        "Full chain verification must pass: {}",
        result.description
    );

    // 9. Merkle proofs — verify inclusion proofs for each layer
    let mut sorted_sigs = signatures.clone();
    sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));

    for i in 0..sorted_sigs.len() {
        let proof_hashes =
            merkle_proof(&signatures, i).expect("proof should exist for every layer");
        let verified = verify_proof(&proof_hashes, &root, &sorted_sigs[i], i, sorted_sigs.len());
        assert!(
            verified,
            "Proof for layer {} (sorted index {i}) should verify",
            sorted_sigs[i].layer
        );
    }

    // 10. Akeyless in the chain — verify it's present and non-trivial
    assert_eq!(akeyless_sig.layer, LayerType::Akeyless);
    assert_ne!(akeyless_sig.hash, Blake3Hash::digest(b"empty"));
    assert_eq!(akeyless_sig.inputs.len(), 2);
    assert_eq!(akeyless_sig.inputs[0].name, "/production/db-password");
    assert_eq!(akeyless_sig.inputs[1].name, "/production/api-key");
}

// ---------------------------------------------------------------------------
// Test 2: Tamper detection changes Merkle root
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tamper_detection_changes_root() {
    let c1 = MockCollector::new(LayerType::Nix);
    let c2 = MockCollector::new(LayerType::Oci);

    let sig1 = c1.collect().await.unwrap();
    let sig2 = c2.collect().await.unwrap();

    let root1 = compute_merkle_root(&[sig1.clone(), sig2.clone()]);

    // Tamper: create a signature with a different hash for the Nix layer
    let tampered_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"TAMPERED-nix-data"),
        "tampered-source",
        vec![],
    );

    let root2 = compute_merkle_root(&[tampered_sig, sig2]);

    // Roots MUST differ when any input is modified
    assert_ne!(root1, root2, "Tampered input must change Merkle root");
}

// ---------------------------------------------------------------------------
// Test 3: Tamper detection invalidates master signature verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tamper_detection_invalidates_verification() {
    let nix = MockCollector::new(LayerType::Nix);
    let oci = MockCollector::new(LayerType::Oci);

    let sig_nix = nix.collect().await.unwrap();
    let sig_oci = oci.collect().await.unwrap();

    let master = compose_merkle(&[sig_nix, sig_oci], "prod");
    let original_gating = master.gating_signature().clone();

    // Now verify with a wrong expected hash (simulating tampered record)
    let wrong_hash = Blake3Hash::digest(b"someone-changed-the-manifest");
    let result = verify_master(&master, &wrong_hash);
    assert!(
        !result.passed,
        "Tampered expected hash must fail verification"
    );

    // Original should still pass
    let result_ok = verify_master(&master, &original_gating);
    assert!(result_ok.passed, "Original hash must still verify");
}

// ---------------------------------------------------------------------------
// Test 4: Akeyless secrets in the attestation chain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn akeyless_secrets_in_attestation_chain() {
    let attestation1 = sample_akeyless_attestation();
    let collector1 = AkeylessCollector::new(attestation1);
    let sig1 = collector1.collect().await.unwrap();

    assert_eq!(collector1.layer_type(), LayerType::Akeyless);
    assert_ne!(sig1.hash, Blake3Hash::digest(b"empty"));

    // Build a second attestation with different secrets
    let attestation2 = AkeylessSecretAttestation {
        gateway_url: "https://gw.akeyless.example.com".to_string(),
        auth_method: AkeylessAuthMethod::K8s,
        secrets_accessed: vec![AkeylessSecretAccess {
            path: "/staging/different-secret".to_string(),
            secret_type: AkeylessSecretType::Static,
            value_hash: Blake3Hash::digest(b"completely-different-secret"),
            accessed_at: Utc::now(),
            version: Some(1),
        }],
        gateway_certificate_hash: Blake3Hash::digest(b"gateway-tls-cert"),
        session_hash: Blake3Hash::digest(b"auth-session-token"),
    };
    let collector2 = AkeylessCollector::new(attestation2);
    let sig2 = collector2.collect().await.unwrap();

    // Different secrets = different hash
    assert_ne!(
        sig1.hash, sig2.hash,
        "Different secrets must produce different hashes"
    );

    // Both are Akeyless layers
    assert_eq!(sig1.layer, LayerType::Akeyless);
    assert_eq!(sig2.layer, LayerType::Akeyless);
}

// ---------------------------------------------------------------------------
// Test 5: Compliance dimensions compose correctly
// ---------------------------------------------------------------------------

#[test]
fn compliance_dimensions_compose_correctly() {
    let scan = make_vuln_scan();
    let sbom = make_sbom();
    let prov = make_provenance();

    // Build with all dimensions
    let attestation = AttestationBuilder::new("production", "myapp", "default")
        .with_vuln_scan(&scan, true, true)
        .with_sbom(&sbom, true)
        .with_slsa(&prov, &SlsaLevel::L2, true)
        .build();

    assert_eq!(attestation.dimensions.len(), 3);
    assert!(attestation.all_passed);
    assert_eq!(attestation.environment, "production");
    assert_eq!(attestation.artifact, "myapp");

    // Verify the compliance hash is deterministic
    let attestation2 = AttestationBuilder::new("production", "myapp", "default")
        .with_vuln_scan(&scan, true, true)
        .with_sbom(&sbom, true)
        .with_slsa(&prov, &SlsaLevel::L2, true)
        .build();

    assert_eq!(attestation.compliance_hash, attestation2.compliance_hash);

    // Required-failed dimension should make all_passed false
    let failed_attestation = AttestationBuilder::new("production", "myapp", "strict")
        .with_vuln_scan(&scan, false, true) // passed=false, required=true
        .with_sbom(&sbom, true)
        .build();

    assert!(!failed_attestation.all_passed);

    // Optional failure should NOT block
    let optional_fail = AttestationBuilder::new("production", "myapp", "lenient")
        .with_vuln_scan(&scan, true, true) // passed, required
        .with_vuln_scan(&scan, false, false) // failed, optional
        .build();

    assert!(optional_fail.all_passed);
}

// ---------------------------------------------------------------------------
// Test 6: Certification pipeline produces deterministic hashes
// ---------------------------------------------------------------------------

#[test]
fn certification_pipeline_deterministic() {
    let cert1 = ProductCertification::builder("myapp", "staging", "plo")
        .with_policy(relaxed_staging_policy())
        .with_source(make_source())
        .with_build(make_build("backend"))
        .with_image(make_image("backend"))
        .with_chart(make_chart("myapp-backend"))
        .with_deployment(make_deployment())
        .with_compliance(make_compliance())
        .certify()
        .unwrap();

    let cert2 = ProductCertification::builder("myapp", "staging", "plo")
        .with_policy(relaxed_staging_policy())
        .with_source(make_source())
        .with_build(make_build("backend"))
        .with_image(make_image("backend"))
        .with_chart(make_chart("myapp-backend"))
        .with_deployment(make_deployment())
        .with_compliance(make_compliance())
        .certify()
        .unwrap();

    assert_eq!(
        cert1.certification_hash, cert2.certification_hash,
        "Same inputs must produce same certification hash"
    );

    assert!(cert1.is_certified());
    assert!(cert2.is_certified());
}

// ---------------------------------------------------------------------------
// Test 7: Verification catches mismatches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verification_catches_mismatches() {
    // Build a master signature from layers
    let nix = MockCollector::new(LayerType::Nix);
    let oci = MockCollector::new(LayerType::Oci);
    let helm = MockCollector::new(LayerType::Helm);

    let sigs: Vec<LayerSignature> = vec![
        nix.collect().await.unwrap(),
        oci.collect().await.unwrap(),
        helm.collect().await.unwrap(),
    ];

    let compliance_hash = Blake3Hash::digest(b"compliance-passed");
    let master = compose_merkle(&sigs, "staging").with_compliance(compliance_hash);
    let correct_gating = master.gating_signature().clone();

    // Correct gating signature passes
    let pass_result = verify_master(&master, &correct_gating);
    assert!(pass_result.passed, "Correct gating signature must pass");

    // Wrong gating signature fails
    let wrong_result = verify_master(&master, &Blake3Hash::digest(b"wrong"));
    assert!(!wrong_result.passed, "Wrong gating signature must fail");

    // Verify prefixed roundtrip works
    let prefixed = master.gating_signature_prefixed();
    assert!(prefixed.starts_with("blake3:"));
    let roundtrip = tameshi::verify::verify_prefixed(&master, &prefixed);
    assert!(roundtrip.is_ok(), "Prefixed roundtrip must work");
}

// ---------------------------------------------------------------------------
// Test 8: Empty and edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_and_edge_cases() {
    // Empty layer list
    let empty_root = compute_merkle_root(&[]);
    assert_eq!(empty_root, Blake3Hash::digest(b"empty-tree"));

    // Proof for empty tree
    assert!(merkle_proof(&[], 0).is_none());

    // Single layer
    let single_layer = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"single"),
        "test",
        vec![],
    );
    let single_root = compute_merkle_root(&[single_layer.clone()]);
    // With domain separation: single leaf root = BLAKE3(0x00 || leaf_hash)
    let expected = Blake3Hash(domain_separated_leaf(&Blake3Hash::digest(b"single").0));
    assert_eq!(single_root, expected);

    // Single layer Merkle proof
    let single_proof = merkle_proof(&[single_layer.clone()], 0).unwrap();
    let verified = verify_proof(&single_proof, &single_root, &single_layer, 0, 1);
    assert!(verified, "Single layer proof must verify");

    // Out of bounds proof
    assert!(merkle_proof(&[single_layer], 1).is_none());

    // Master with no compliance is not fully attested
    let master = compose_merkle(
        &[LayerSignature::new(
            LayerType::Nix,
            Blake3Hash::digest(b"x"),
            "t",
            vec![],
        )],
        "test",
    );
    assert!(!master.is_fully_attested());
    assert!(master.verify_untested());
    // Gating signature falls back to untested
    assert_eq!(master.gating_signature(), &master.untested);
}

// ---------------------------------------------------------------------------
// Test 9: Merkle proof verification for all layers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn merkle_proofs_verify_all_layers() {
    // Use all available layer types
    let layer_types = vec![
        LayerType::Nix,
        LayerType::Oci,
        LayerType::Helm,
        LayerType::Kubernetes,
        LayerType::Tofu,
        LayerType::Akeyless,
        LayerType::FluxCD,
    ];

    let signatures: Vec<LayerSignature> = layer_types
        .iter()
        .map(|lt| {
            LayerSignature::new(
                lt.clone(),
                Blake3Hash::digest(format!("data-for-{lt}").as_bytes()),
                "e2e-test",
                vec![InputHash {
                    name: format!("{lt}-input"),
                    hash: Blake3Hash::digest(format!("input-{lt}").as_bytes()),
                    size_bytes: Some(4096),
                }],
            )
        })
        .collect();

    let root = compute_merkle_root(&signatures);

    // Sort signatures the same way Merkle tree does
    let mut sorted_sigs = signatures.clone();
    sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));

    for i in 0..sorted_sigs.len() {
        let proof_hashes = merkle_proof(&signatures, i).expect("proof must exist");
        let verified = verify_proof(&proof_hashes, &root, &sorted_sigs[i], i, sorted_sigs.len());
        assert!(
            verified,
            "Merkle proof for layer {} at sorted index {i} must verify",
            sorted_sigs[i].layer
        );
    }

    // Invalid proof: wrong leaf data should not verify
    let fake_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"fake-data"),
        "fake",
        vec![],
    );
    let proof_0 = merkle_proof(&signatures, 0).unwrap();
    let invalid = verify_proof(&proof_0, &root, &fake_sig, 0, sorted_sigs.len());
    assert!(!invalid, "Wrong leaf data must not verify");
}

// ---------------------------------------------------------------------------
// Test 10: Akeyless hash determinism and sensitivity
// ---------------------------------------------------------------------------

#[test]
fn akeyless_hash_determinism_and_sensitivity() {
    let attestation = sample_akeyless_attestation();

    // Deterministic
    let h1 = compute_akeyless_hash(&attestation);
    let h2 = compute_akeyless_hash(&attestation);
    assert_eq!(h1, h2, "Same attestation must produce same hash");

    // Sensitive to gateway URL change
    let mut modified = attestation.clone();
    modified.gateway_url = "https://other-gw.akeyless.example.com".to_string();
    assert_ne!(
        compute_akeyless_hash(&attestation),
        compute_akeyless_hash(&modified),
        "Different gateway URL must change hash"
    );

    // Sensitive to secret path change
    let mut modified2 = attestation.clone();
    modified2.secrets_accessed[0].path = "/staging/other-secret".to_string();
    assert_ne!(
        compute_akeyless_hash(&attestation),
        compute_akeyless_hash(&modified2),
        "Different secret path must change hash"
    );

    // Sensitive to auth method change
    let mut modified3 = attestation.clone();
    modified3.auth_method = AkeylessAuthMethod::ApiKey;
    assert_ne!(
        compute_akeyless_hash(&attestation),
        compute_akeyless_hash(&modified3),
        "Different auth method must change hash"
    );

    // Sensitive to secret value change (only hash stored)
    let mut modified4 = attestation.clone();
    modified4.secrets_accessed[0].value_hash = Blake3Hash::digest(b"rotated-secret-value");
    assert_ne!(
        compute_akeyless_hash(&attestation),
        compute_akeyless_hash(&modified4),
        "Different secret value hash must change hash"
    );
}

// ---------------------------------------------------------------------------
// Test 11: Full certification with strict policy fails on violations
// ---------------------------------------------------------------------------

#[test]
fn strict_policy_catches_violations() {
    // Unsigned image should fail strict policy
    let mut image = make_image("backend");
    image.cosign_verified = false;

    let cert = ProductCertification::builder("myapp", "production", "plo")
        .with_policy(strict_production_policy())
        .with_source(make_source())
        .with_build(make_build("backend"))
        .with_image(image)
        .with_chart(make_chart("myapp-backend"))
        .with_deployment(make_deployment())
        .with_compliance(make_compliance())
        .certify()
        .unwrap();

    assert!(
        !cert.is_certified(),
        "Unsigned image must fail strict policy"
    );

    // High CVE count should fail
    let mut build = make_build("backend");
    build.critical_high_cves = 5;

    let cert2 = ProductCertification::builder("myapp", "production", "plo")
        .with_policy(strict_production_policy())
        .with_source(make_source())
        .with_build(build)
        .with_image(make_image("backend"))
        .with_chart(make_chart("myapp-backend"))
        .with_deployment(make_deployment())
        .with_compliance(make_compliance())
        .certify()
        .unwrap();

    assert!(
        !cert2.is_certified(),
        "High CVE count must fail strict policy"
    );
}

// ---------------------------------------------------------------------------
// Test 12: Merkle root order independence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn merkle_root_order_independence() {
    let nix = MockCollector::new(LayerType::Nix);
    let oci = MockCollector::new(LayerType::Oci);
    let helm = MockCollector::new(LayerType::Helm);
    let k8s = MockCollector::new(LayerType::Kubernetes);

    let sig_nix = nix.collect().await.unwrap();
    let sig_oci = oci.collect().await.unwrap();
    let sig_helm = helm.collect().await.unwrap();
    let sig_k8s = k8s.collect().await.unwrap();

    // Different orderings should produce the same root
    let root_a = compute_merkle_root(&[
        sig_nix.clone(),
        sig_oci.clone(),
        sig_helm.clone(),
        sig_k8s.clone(),
    ]);
    let root_b = compute_merkle_root(&[
        sig_k8s.clone(),
        sig_helm.clone(),
        sig_oci.clone(),
        sig_nix.clone(),
    ]);
    let root_c = compute_merkle_root(&[
        sig_helm.clone(),
        sig_nix.clone(),
        sig_k8s.clone(),
        sig_oci.clone(),
    ]);

    assert_eq!(
        root_a, root_b,
        "Different layer ordering must produce same root"
    );
    assert_eq!(
        root_b, root_c,
        "Different layer ordering must produce same root"
    );
}

// ---------------------------------------------------------------------------
// Test 13: Secure signature composition
// ---------------------------------------------------------------------------

#[test]
fn secure_signature_composition() {
    let layers = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
    ];

    let untested_master = compose_merkle(&layers, "prod");
    let untested_root = untested_master.untested.clone();

    // Add compliance
    let compliance_hash = Blake3Hash::digest(b"compliance-data");
    let secure_master = untested_master.with_compliance(compliance_hash.clone());

    // Secure signature = BLAKE3(untested || compliance)
    let expected_secure = Blake3Hash::combine(&untested_root, &compliance_hash);
    assert_eq!(
        secure_master.secure.as_ref().unwrap(),
        &expected_secure,
        "Secure = BLAKE3(untested || compliance)"
    );

    // Gating should return secure when available
    assert_eq!(secure_master.gating_signature(), &expected_secure);
    assert!(secure_master.verify_secure());
    assert!(secure_master.verify_untested());
}

// ---------------------------------------------------------------------------
// Test 14: Hackathon demo — full multi-service attestation pipeline
// ---------------------------------------------------------------------------

/// Exercises the FULL hackathon demo flow end-to-end:
///   Source -> Build -> Image -> Chart -> K8s -> Akeyless -> Merkle Tree
///   -> Compliance -> Secure Signature -> Certification -> Verification
///   -> Tamper Detection -> Gate Decision -> Merkle Inclusion Proofs
///
/// All mocked — no real K8s, Nix, or Akeyless needed.
#[tokio::test]
async fn hackathon_demo_full_pipeline() {
    // === Step 1: Source Attestation ===
    let source = SourceAttestation {
        repository: "github.com/pleme-io/my-service".to_string(),
        commit: "abc123def456".to_string(),
        git_ref: "refs/heads/main".to_string(),
        commit_signed: true,
        tree_hash: Blake3Hash::digest(b"git-tree-content"),
        flake_lock_hash: Blake3Hash::digest(b"flake-lock-content"),
        flake_input_count: 5,
        all_inputs_pinned: true,
    };
    assert!(source.commit_signed, "Source commit must be signed");
    assert!(source.all_inputs_pinned, "All flake inputs must be pinned");

    // === Step 2: Build Attestation (inshou would do this) ===
    let nix_collector = MockCollector::new(LayerType::Nix);
    let nix_sig = nix_collector.collect().await.unwrap();
    assert_eq!(nix_sig.layer, LayerType::Nix);

    // === Step 3: Image Attestation ===
    let oci_collector = MockCollector::new(LayerType::Oci);
    let oci_sig = oci_collector.collect().await.unwrap();
    assert_eq!(oci_sig.layer, LayerType::Oci);

    // === Step 4: Helm Attestation ===
    let helm_collector = MockCollector::new(LayerType::Helm);
    let helm_sig = helm_collector.collect().await.unwrap();
    assert_eq!(helm_sig.layer, LayerType::Helm);

    // === Step 5: Kubernetes Attestation ===
    let k8s_collector = MockCollector::new(LayerType::Kubernetes);
    let k8s_sig = k8s_collector.collect().await.unwrap();
    assert_eq!(k8s_sig.layer, LayerType::Kubernetes);

    // === Step 6: Akeyless Secret Attestation ===
    let akeyless_attestation = AkeylessSecretAttestation {
        gateway_url: "https://gw.akeyless.example.com".to_string(),
        auth_method: AkeylessAuthMethod::K8s,
        secrets_accessed: vec![
            AkeylessSecretAccess {
                path: "/production/db-password".to_string(),
                secret_type: AkeylessSecretType::DynamicDatabase,
                value_hash: Blake3Hash::digest(b"real-db-password"),
                accessed_at: Utc::now(),
                version: Some(3),
            },
            AkeylessSecretAccess {
                path: "/production/api-key".to_string(),
                secret_type: AkeylessSecretType::Static,
                value_hash: Blake3Hash::digest(b"real-api-key"),
                accessed_at: Utc::now(),
                version: Some(1),
            },
        ],
        gateway_certificate_hash: Blake3Hash::digest(b"gw-cert"),
        session_hash: Blake3Hash::digest(b"session"),
    };
    let akeyless_collector = AkeylessCollector::new(akeyless_attestation.clone());
    let akeyless_sig = akeyless_collector.collect().await.unwrap();
    assert_eq!(akeyless_sig.layer, LayerType::Akeyless);
    assert_eq!(akeyless_sig.inputs.len(), 2);
    assert_eq!(akeyless_sig.inputs[0].name, "/production/db-password");
    assert_eq!(akeyless_sig.inputs[1].name, "/production/api-key");

    // === Step 7: Compose Merkle Tree ===
    let all_sigs = vec![
        nix_sig.clone(),
        oci_sig.clone(),
        helm_sig.clone(),
        k8s_sig.clone(),
        akeyless_sig.clone(),
    ];
    assert_eq!(all_sigs.len(), 5, "Must have all 5 layers");

    let merkle_root = compute_merkle_root(&all_sigs);

    // Verify Merkle root is deterministic
    let merkle_root2 = compute_merkle_root(&all_sigs);
    assert_eq!(
        merkle_root, merkle_root2,
        "Merkle root must be deterministic"
    );

    // Build untested master signature
    let master = compose_merkle(&all_sigs, "production");
    assert!(master.verify_untested(), "Untested Merkle root must verify");
    assert!(
        !master.is_fully_attested(),
        "Without compliance, must not be fully attested"
    );

    // === Step 8: Compliance Check (kensa would do this) ===
    let scan = make_vuln_scan();
    let sbom = make_sbom();
    let prov = make_provenance();

    let compliance = AttestationBuilder::new("production", "my-service", "strict-production")
        .with_vuln_scan(&scan, true, true)
        .with_sbom(&sbom, true)
        .with_slsa(&prov, &SlsaLevel::L2, true)
        .build();

    assert!(compliance.all_passed, "All compliance dimensions must pass");
    assert_eq!(compliance.dimensions.len(), 3, "3 compliance dimensions");
    let compliance_hash = compliance.compliance_hash.clone();

    // Add compliance to master for secure signature (two-phase)
    let master_with_compliance = master.with_compliance(compliance_hash.clone());
    assert!(
        master_with_compliance.is_fully_attested(),
        "Must be fully attested after compliance"
    );
    assert!(
        master_with_compliance.verify_untested(),
        "Untested must still verify"
    );
    assert!(master_with_compliance.verify_secure(), "Secure must verify");

    // Verify two-phase signature composition
    assert!(
        master_with_compliance.compliance.is_some(),
        "Compliance hash must be present"
    );
    assert!(
        master_with_compliance.secure.is_some(),
        "Secure signature must be present"
    );
    let secure = master_with_compliance.secure.as_ref().unwrap();
    let expected_secure = Blake3Hash::combine(
        &master_with_compliance.untested,
        master_with_compliance.compliance.as_ref().unwrap(),
    );
    assert_eq!(
        secure, &expected_secure,
        "secure = BLAKE3(untested || compliance)"
    );

    // === Step 9: Product Certification ===
    let build = BuildAttestation {
        service: "my-service".to_string(),
        derivation: "/nix/store/xxxxx-my-service.drv".to_string(),
        closure_hash: Blake3Hash::digest(b"closure-my-service"),
        slsa_level: SlsaLevel::L3,
        reproducible: true,
        hermetic: true,
        sbom_hash: Blake3Hash::digest(b"sbom-my-service"),
        vuln_scan_hash: Blake3Hash::digest(b"vulns-my-service"),
        cve_count: 1,
        critical_high_cves: 0,
        builder: "nix-build@forge.pleme.io".to_string(),
        built_at: Utc::now(),
    };
    let image = ImageAttestation {
        image_ref: "ghcr.io/pleme-io/my-service".to_string(),
        tag: "amd64-abc123".to_string(),
        architecture: "amd64".to_string(),
        manifest_hash: Blake3Hash::digest(b"manifest-my-service"),
        cosign_verified: true,
        signer_identity: Some("github-actions[bot]".to_string()),
        vuln_scan_hash: Blake3Hash::digest(b"trivy-image-scan"),
        vuln_count: 2,
        critical_high_vulns: 0,
        sbom_hash: Blake3Hash::digest(b"image-sbom"),
        layer_type: LayerType::Oci,
    };
    let chart = ChartAttestation {
        chart_name: "my-service".to_string(),
        chart_version: "0.2.0".to_string(),
        chart_hash: Blake3Hash::digest(b"chart-my-service"),
        provenance_verified: true,
        dependency_hashes: vec![DependencyHash {
            name: "pleme-lib".to_string(),
            version: "0.3.1".to_string(),
            hash: Blake3Hash::digest(b"pleme-lib-chart"),
        }],
        linter_passed: true,
        policy_passed: true,
        registry_ref: "oci://ghcr.io/pleme-io/charts/my-service".to_string(),
    };
    let deployment = DeploymentAttestation {
        namespace: "my-service-production".to_string(),
        kustomization: "my-service-production".to_string(),
        source_commit: "abc123def456".to_string(),
        source_verified: true,
        manifest_hash: Blake3Hash::digest(b"rendered-k8s-manifests"),
        all_releases_signed: true,
        cis_k8s_pass_rate: 0.95,
        network_policies_verified: true,
        running_pods: 6,
        all_healthy: true,
    };

    let cert = ProductCertification::builder("my-service", "production", "plo")
        .with_policy(strict_production_policy())
        .with_source(source)
        .with_build(build)
        .with_image(image)
        .with_chart(chart)
        .with_deployment(deployment)
        .with_compliance(compliance.clone())
        .certify()
        .unwrap();

    assert!(
        cert.is_certified(),
        "Full pipeline certification must pass with strict policy"
    );
    assert_eq!(cert.product, "my-service");
    assert_eq!(cert.environment, "production");
    assert_eq!(cert.cluster, "plo");
    // 1 source + 1 build + 1 image + 1 chart + 1 deployment + 1 compliance = 6
    assert_eq!(cert.stage_results.len(), 6);
    for sr in &cert.stage_results {
        assert!(
            sr.passed,
            "Stage {:?} must pass: violations = {:?}",
            sr.stage, sr.violations
        );
    }

    // === Step 10: Verification (sekiban would do this) ===
    let gating_sig = master_with_compliance.gating_signature().clone();
    let verify_result = verify_master(&master_with_compliance, &gating_sig);
    assert!(
        verify_result.passed,
        "Verification must pass for untampered data: {}",
        verify_result.description
    );

    // Verify prefixed roundtrip
    let prefixed = master_with_compliance.gating_signature_prefixed();
    assert!(
        prefixed.starts_with("blake3:"),
        "Prefixed must start with blake3:"
    );
    let roundtrip = tameshi::verify::verify_prefixed(&master_with_compliance, &prefixed);
    assert!(
        roundtrip.is_ok(),
        "Prefixed verification roundtrip must work"
    );

    // === Step 11: Tamper Detection ===
    // Change one secret value and verify the hash changes at every level
    let mut tampered_attestation = akeyless_attestation;
    tampered_attestation.secrets_accessed[0].value_hash = Blake3Hash::digest(b"TAMPERED-password");
    let tampered_collector = AkeylessCollector::new(tampered_attestation);
    let tampered_sig = tampered_collector.collect().await.unwrap();

    // Tampered Akeyless signature must differ from original
    assert_ne!(
        akeyless_sig.hash, tampered_sig.hash,
        "Tampered secret MUST change the layer hash"
    );

    // Tampered Merkle root must differ
    let tampered_sigs = vec![
        nix_sig.clone(),
        oci_sig.clone(),
        helm_sig.clone(),
        k8s_sig.clone(),
        tampered_sig,
    ];
    let tampered_root = compute_merkle_root(&tampered_sigs);
    assert_ne!(
        merkle_root, tampered_root,
        "Tampered secret MUST change the Merkle root"
    );

    // Tampered master verification must fail against original gating signature
    let tampered_master =
        compose_merkle(&tampered_sigs, "production").with_compliance(compliance_hash.clone());
    let tampered_verify = verify_master(&tampered_master, &gating_sig);
    assert!(
        !tampered_verify.passed,
        "Tampered master must FAIL verification against original gating signature"
    );

    // === Step 12: Gate Decision ===
    let gate_policy = tameshi::gating::GatingPolicy {
        name: "production-gate".to_string(),
        required_layers: vec!["nix".to_string(), "oci".to_string(), "akeyless".to_string()],
        require_compliance: true,
        max_signature_age_secs: Some(3600),
        fail_open: false,
        require_certification_artifacts: false,
    };
    let decision =
        tameshi::gating::evaluate_gate(&gate_policy, &master_with_compliance, &gating_sig);
    assert!(
        decision.allowed,
        "Gate should allow valid certification: {}",
        decision.reason
    );

    // Gate must deny tampered master
    let tampered_decision = tameshi::gating::evaluate_gate(
        &gate_policy,
        &tampered_master,
        &gating_sig, // use original expected signature
    );
    assert!(
        !tampered_decision.allowed,
        "Gate must DENY tampered master signature"
    );

    // Gate must deny when compliance is missing
    let no_compliance_master = compose_merkle(&all_sigs, "production");
    let no_compliance_gating = no_compliance_master.gating_signature().clone();
    let no_compliance_decision =
        tameshi::gating::evaluate_gate(&gate_policy, &no_compliance_master, &no_compliance_gating);
    assert!(
        !no_compliance_decision.allowed,
        "Gate must DENY when compliance is required but missing"
    );

    // Gate must deny when required layer is missing
    let missing_layer_policy = tameshi::gating::GatingPolicy {
        name: "strict-gate".to_string(),
        required_layers: vec!["fluxcd".to_string()], // not in our layers
        require_compliance: false,
        max_signature_age_secs: None,
        fail_open: false,
        require_certification_artifacts: false,
    };
    let missing_decision =
        tameshi::gating::evaluate_gate(&missing_layer_policy, &master_with_compliance, &gating_sig);
    assert!(
        !missing_decision.allowed,
        "Gate must DENY when required layer is missing"
    );

    // === Step 13: Merkle Inclusion Proofs ===
    let mut sorted_sigs = all_sigs.clone();
    sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));

    for i in 0..sorted_sigs.len() {
        let proof = merkle_proof(&all_sigs, i).expect("Proof should exist");
        let verified = verify_proof(&proof, &merkle_root, &sorted_sigs[i], i, sorted_sigs.len());
        assert!(
            verified,
            "Proof for layer {} at index {} must verify",
            sorted_sigs[i].layer, i
        );
    }

    // Invalid proof: wrong leaf should NOT verify
    let fake_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"fake-data"),
        "fake",
        vec![],
    );
    let proof_0 = merkle_proof(&all_sigs, 0).unwrap();
    let invalid_proof = verify_proof(&proof_0, &merkle_root, &fake_sig, 0, sorted_sigs.len());
    assert!(!invalid_proof, "Wrong leaf data must NOT verify");

    // === Step 14: Certification determinism ===
    // Rebuild the exact same compliance and certification to verify determinism.
    let compliance_for_cert2 =
        AttestationBuilder::new("production", "my-service", "strict-production")
            .with_vuln_scan(&scan, true, true)
            .with_sbom(&sbom, true)
            .with_slsa(&prov, &SlsaLevel::L2, true)
            .build();

    let cert2 = ProductCertification::builder("my-service", "production", "plo")
        .with_policy(strict_production_policy())
        .with_source(SourceAttestation {
            repository: "github.com/pleme-io/my-service".to_string(),
            commit: "abc123def456".to_string(),
            git_ref: "refs/heads/main".to_string(),
            commit_signed: true,
            tree_hash: Blake3Hash::digest(b"git-tree-content"),
            flake_lock_hash: Blake3Hash::digest(b"flake-lock-content"),
            flake_input_count: 5,
            all_inputs_pinned: true,
        })
        .with_build(BuildAttestation {
            service: "my-service".to_string(),
            derivation: "/nix/store/xxxxx-my-service.drv".to_string(),
            closure_hash: Blake3Hash::digest(b"closure-my-service"),
            slsa_level: SlsaLevel::L3,
            reproducible: true,
            hermetic: true,
            sbom_hash: Blake3Hash::digest(b"sbom-my-service"),
            vuln_scan_hash: Blake3Hash::digest(b"vulns-my-service"),
            cve_count: 1,
            critical_high_cves: 0,
            builder: "nix-build@forge.pleme.io".to_string(),
            built_at: Utc::now(),
        })
        .with_image(ImageAttestation {
            image_ref: "ghcr.io/pleme-io/my-service".to_string(),
            tag: "amd64-abc123".to_string(),
            architecture: "amd64".to_string(),
            manifest_hash: Blake3Hash::digest(b"manifest-my-service"),
            cosign_verified: true,
            signer_identity: Some("github-actions[bot]".to_string()),
            vuln_scan_hash: Blake3Hash::digest(b"trivy-image-scan"),
            vuln_count: 2,
            critical_high_vulns: 0,
            sbom_hash: Blake3Hash::digest(b"image-sbom"),
            layer_type: LayerType::Oci,
        })
        .with_chart(ChartAttestation {
            chart_name: "my-service".to_string(),
            chart_version: "0.2.0".to_string(),
            chart_hash: Blake3Hash::digest(b"chart-my-service"),
            provenance_verified: true,
            dependency_hashes: vec![DependencyHash {
                name: "pleme-lib".to_string(),
                version: "0.3.1".to_string(),
                hash: Blake3Hash::digest(b"pleme-lib-chart"),
            }],
            linter_passed: true,
            policy_passed: true,
            registry_ref: "oci://ghcr.io/pleme-io/charts/my-service".to_string(),
        })
        .with_deployment(DeploymentAttestation {
            namespace: "my-service-production".to_string(),
            kustomization: "my-service-production".to_string(),
            source_commit: "abc123def456".to_string(),
            source_verified: true,
            manifest_hash: Blake3Hash::digest(b"rendered-k8s-manifests"),
            all_releases_signed: true,
            cis_k8s_pass_rate: 0.95,
            network_policies_verified: true,
            running_pods: 6,
            all_healthy: true,
        })
        .with_compliance(compliance_for_cert2)
        .certify()
        .unwrap();

    assert_eq!(
        cert.certification_hash, cert2.certification_hash,
        "Same inputs must produce same certification hash"
    );

    // === Summary ===
    println!("=== HACKATHON DEMO PIPELINE COMPLETE ===");
    println!("Layers: {}", all_sigs.len());
    println!("Merkle root: {}", merkle_root.to_prefixed());
    println!("Compliance hash: {}", compliance_hash.to_prefixed());
    println!("Secure signature: {}", secure.to_prefixed());
    println!("Gate decision: ALLOWED");
    println!("Akeyless secrets attested: {}", akeyless_sig.inputs.len());
    println!("Tamper detection: WORKING");
    println!(
        "Certification: CERTIFIED (product={}, env={}, cluster={})",
        cert.product, cert.environment, cert.cluster
    );
    println!(
        "Merkle proofs verified: {}/{}",
        sorted_sigs.len(),
        sorted_sigs.len()
    );
    println!(
        "Stage results: {}/{} passed",
        cert.stage_results.iter().filter(|s| s.passed).count(),
        cert.stage_results.len()
    );
}

// ===========================================================================
// Akeyless Target Attestation E2E Tests
// ===========================================================================

use tameshi::akeyless_client::MockAkeylessClient;
use tameshi::collectors::akeyless_target::AkeylessTargetCollector;
use tameshi::compliance::akeyless_target::{
    AkeylessTargetAttestation, AkeylessTargetType, ProducerAssociation, compute_multi_target_hash,
    compute_target_attestation_hash,
};

fn make_target_attestation(
    name: &str,
    target_type: AkeylessTargetType,
) -> AkeylessTargetAttestation {
    AkeylessTargetAttestation {
        target_name: name.to_string(),
        target_type,
        target_config_hash: Blake3Hash::digest(format!("config-{name}").as_bytes()),
        target_credential_hash: Blake3Hash::digest(format!("creds-{name}").as_bytes()),
        backend_endpoint_hash: Blake3Hash::digest(format!("endpoint-{name}").as_bytes()),
        backend_tls_cert_hash: Some(Blake3Hash::digest(format!("tls-{name}").as_bytes())),
        backend_tls_verified: true,
        associated_producers: vec![ProducerAssociation {
            producer_name: format!("/producers/{name}-dynamic"),
            producer_type: AkeylessSecretType::DynamicDatabase,
            user_ttl: "1h".to_string(),
            target_assoc_id: Some(format!("assoc-{name}")),
        }],
        attested_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn e2e_target_attestation_with_mock_client() {
    let target_att = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let client = MockAkeylessClient::new().with_target_attestations(vec![target_att.clone()]);
    let result = tameshi::akeyless_client::AkeylessClient::build_target_attestation(
        &client,
        &["/targets/prod/db".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].target_name, "/targets/prod/db");
    assert_eq!(result[0].target_type, AkeylessTargetType::Database);
}

#[test]
fn e2e_target_config_hash_sensitivity() {
    let att1 = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let mut att2 = att1.clone();
    att2.backend_endpoint_hash = Blake3Hash::digest(b"different-endpoint:5432");

    let h1 = compute_target_attestation_hash(&att1);
    let h2 = compute_target_attestation_hash(&att2);
    assert_ne!(h1, h2, "Changing endpoint must change the attestation hash");
}

#[test]
fn e2e_tls_cert_hash_rotation_detection() {
    let att1 = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let mut att2 = att1.clone();
    att2.backend_tls_cert_hash = Some(Blake3Hash::digest(b"rotated-tls-cert-2025"));

    let h1 = compute_target_attestation_hash(&att1);
    let h2 = compute_target_attestation_hash(&att2);
    assert_ne!(h1, h2, "TLS cert rotation must change the attestation hash");
}

#[test]
fn e2e_producer_association_tracking() {
    let mut att = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let h_before = compute_target_attestation_hash(&att);

    att.associated_producers.push(ProducerAssociation {
        producer_name: "/producers/db-readonly".to_string(),
        producer_type: AkeylessSecretType::DynamicDatabase,
        user_ttl: "30m".to_string(),
        target_assoc_id: None,
    });
    let h_after = compute_target_attestation_hash(&att);
    assert_ne!(
        h_before, h_after,
        "Adding a producer must change the attestation hash"
    );
}

#[test]
fn e2e_multi_target_composition_deterministic_order_independent() {
    let att_db = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let att_api = make_target_attestation("/targets/prod/api", AkeylessTargetType::Web);
    let att_ssh = make_target_attestation("/targets/prod/ssh", AkeylessTargetType::Ssh);

    let h_forward = compute_multi_target_hash(&[att_db.clone(), att_api.clone(), att_ssh.clone()]);
    let h_reverse = compute_multi_target_hash(&[att_ssh, att_api, att_db]);
    assert_eq!(
        h_forward, h_reverse,
        "Multi-target hash must be order-independent"
    );

    // Determinism: same input -> same output
    let att_db2 = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let att_api2 = make_target_attestation("/targets/prod/api", AkeylessTargetType::Web);
    let att_ssh2 = make_target_attestation("/targets/prod/ssh", AkeylessTargetType::Ssh);
    let h_again = compute_multi_target_hash(&[att_db2, att_api2, att_ssh2]);
    assert_eq!(
        h_forward, h_again,
        "Multi-target hash must be deterministic"
    );
}

#[tokio::test]
async fn e2e_target_layer_in_merkle_tree_with_inclusion_proofs() {
    let att_db = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let att_api = make_target_attestation("/targets/prod/api", AkeylessTargetType::Web);

    let target_collector = AkeylessTargetCollector::new(vec![att_db.clone(), att_api.clone()]);
    let target_sig = target_collector.collect().await.unwrap();
    assert_eq!(target_sig.layer, LayerType::AkeylessTarget);
    assert_eq!(target_sig.inputs.len(), 2);

    // Compose with other layers in a Merkle tree
    let nix_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix-closure"),
        "nix",
        vec![],
    );
    let oci_sig = LayerSignature::new(
        LayerType::Oci,
        Blake3Hash::digest(b"oci-manifest"),
        "oci",
        vec![],
    );
    let all_sigs = vec![nix_sig, oci_sig, target_sig.clone()];
    let root = compute_merkle_root(&all_sigs);

    // Verify inclusion proof for the target layer
    let mut sorted_sigs = all_sigs.clone();
    sorted_sigs.sort_by(|a, b| a.layer.cmp(&b.layer));
    let target_idx = sorted_sigs
        .iter()
        .position(|s| s.layer == LayerType::AkeylessTarget)
        .unwrap();
    let proof = merkle_proof(&all_sigs, target_idx).unwrap();
    let verified = verify_proof(
        &proof,
        &root,
        &sorted_sigs[target_idx],
        target_idx,
        sorted_sigs.len(),
    );
    assert!(verified, "Target layer inclusion proof must verify");
}

#[tokio::test]
async fn e2e_full_pipeline_source_build_image_chart_secrets_target_deploy_compliance() {
    // === Source ===
    let source = make_source();
    let source_hash = Blake3Hash::digest(
        format!("{}:{}:{}", source.repository, source.commit, source.git_ref).as_bytes(),
    );
    let nix_sig = LayerSignature::new(LayerType::Nix, source_hash, "source", vec![]);

    // === Build + Image ===
    let build = make_build("backend");
    let oci_sig = LayerSignature::new(
        LayerType::Oci,
        Blake3Hash::digest(format!("oci:{}", build.service).as_bytes()),
        "oci",
        vec![],
    );

    // === Chart ===
    let helm_sig = LayerSignature::new(
        LayerType::Helm,
        Blake3Hash::digest(b"chart-hash"),
        "helm",
        vec![],
    );

    // === Secrets (Akeyless) ===
    let akeyless_attestation = AkeylessSecretAttestation {
        gateway_url: "https://gw.akeyless.example.com".to_string(),
        auth_method: AkeylessAuthMethod::K8s,
        secrets_accessed: vec![AkeylessSecretAccess {
            path: "/production/db/password".to_string(),
            secret_type: AkeylessSecretType::Static,
            value_hash: Blake3Hash::digest(b"secret-value"),
            accessed_at: chrono::Utc::now(),
            version: Some(1),
        }],
        gateway_certificate_hash: Blake3Hash::digest(b"tls-cert"),
        session_hash: Blake3Hash::digest(b"session-data"),
    };
    let akeyless_collector = AkeylessCollector::new(akeyless_attestation);
    let akeyless_sig = akeyless_collector.collect().await.unwrap();

    // === Target ===
    let target_atts = vec![
        make_target_attestation("/targets/prod/db", AkeylessTargetType::Database),
        make_target_attestation("/targets/prod/api", AkeylessTargetType::Web),
    ];
    let target_collector = AkeylessTargetCollector::new(target_atts);
    let target_sig = target_collector.collect().await.unwrap();

    // === Deploy (K8s) ===
    let k8s_sig = LayerSignature::new(
        LayerType::Kubernetes,
        Blake3Hash::digest(b"k8s-manifests"),
        "kubernetes",
        vec![],
    );

    // === Compose Merkle tree ===
    let all_sigs = vec![
        nix_sig,
        oci_sig,
        helm_sig,
        akeyless_sig,
        target_sig.clone(),
        k8s_sig,
    ];
    let master = compose_merkle(&all_sigs, "production");
    assert!(master.verify_untested(), "Master signature must verify");

    // Verify target layer is in the tree
    assert!(
        master
            .layers
            .iter()
            .any(|l| l.layer == LayerType::AkeylessTarget),
        "AkeylessTarget layer must be in master"
    );

    // === Compliance ===
    let compliance = Blake3Hash::digest(b"all-compliance-passed");
    let secure_master = master.with_compliance(compliance);
    assert!(
        secure_master.verify_secure(),
        "Secure master must verify with compliance"
    );
    assert!(
        secure_master.is_fully_attested(),
        "Master must be fully attested"
    );
}

#[tokio::test]
async fn e2e_tamper_detection_target_endpoint_changes_master_signature() {
    let att_db = make_target_attestation("/targets/prod/db", AkeylessTargetType::Database);
    let target_collector = AkeylessTargetCollector::new(vec![att_db.clone()]);
    let original_sig = target_collector.collect().await.unwrap();

    let nix_sig = LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "nix", vec![]);

    let original_sigs = vec![nix_sig.clone(), original_sig];
    let original_master = compose_merkle(&original_sigs, "production");
    let original_root = original_master.untested.clone();

    // Tamper: change the backend endpoint
    let mut tampered_att = att_db;
    tampered_att.backend_endpoint_hash = Blake3Hash::digest(b"TAMPERED-endpoint:9999");
    let tampered_collector = AkeylessTargetCollector::new(vec![tampered_att]);
    let tampered_sig = tampered_collector.collect().await.unwrap();

    let tampered_sigs = vec![nix_sig, tampered_sig];
    let tampered_master = compose_merkle(&tampered_sigs, "production");

    assert_ne!(
        original_root, tampered_master.untested,
        "Tampered target endpoint MUST change the master signature"
    );

    // Verify that the original gating signature rejects the tampered master
    let compliance = Blake3Hash::digest(b"compliance");
    let original_with_compliance =
        compose_merkle(&original_sigs, "production").with_compliance(compliance.clone());
    let gating_sig = original_with_compliance.gating_signature().clone();

    let tampered_with_compliance =
        compose_merkle(&tampered_sigs, "production").with_compliance(compliance);
    let verify_result = tameshi::verify::verify_master(&tampered_with_compliance, &gating_sig);
    assert!(
        !verify_result.passed,
        "Tampered target must FAIL verification against original gating signature"
    );
}
