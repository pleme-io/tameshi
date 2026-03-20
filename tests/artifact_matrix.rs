//! Artifact matrix tests — every artifact type through the full attestation pipeline.
//!
//! Tests CertificationArtifact → Merkle → sign → verify → gate for all
//! artifact types, tampered variants, cross-variant checks, SDLC chains,
//! and composition variations.

use tameshi::certification_artifact::{
    compose_certification_artifact, verify_certification_artifact,
};
use tameshi::gating::{evaluate_gate, GatingPolicy};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};
use tameshi::signing::{MockDfcSigner, MerkleRootSigner};

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn make_layer(lt: LayerType, data: &[u8]) -> LayerSignature {
    LayerSignature::new(lt, Blake3Hash::digest(data), "test", vec![])
}

fn make_artifact(
    path: &str,
    artifact_data: &[u8],
    control_data: &[u8],
    intent_data: &[u8],
) -> tameshi::certification_artifact::CertificationArtifact {
    compose_certification_artifact(
        path,
        Blake3Hash::digest(artifact_data),
        Blake3Hash::digest(control_data),
        Blake3Hash::digest(intent_data),
        "production",
    )
}

fn make_signed_master_with_artifact(
    artifact: tameshi::certification_artifact::CertificationArtifact,
) -> MasterSignature {
    let layers = vec![
        make_layer(LayerType::Nix, b"nix-layer"),
        make_layer(LayerType::Oci, b"oci-layer"),
    ];
    compose_merkle(&layers, "production")
        .with_compliance(Blake3Hash::digest(b"compliance"))
        .with_certification_artifacts(vec![artifact])
}

fn gate_policy_with_artifacts() -> GatingPolicy {
    GatingPolicy {
        name: "artifact-gate".to_string(),
        required_layers: vec![],
        require_compliance: true,
        max_signature_age_secs: None,
        fail_open: false,
        require_certification_artifacts: true,
    }
}

fn tamper_hash(hash: &Blake3Hash) -> Blake3Hash {
    let mut bytes = hash.0;
    bytes[0] ^= 0xFF;
    Blake3Hash(bytes)
}

/// Full positive pipeline: create → verify → sign → gate
async fn positive_pipeline(
    artifact: tameshi::certification_artifact::CertificationArtifact,
) {
    // Step 1: Verify the artifact
    assert!(
        verify_certification_artifact(&artifact),
        "Artifact verification should pass"
    );

    // Step 2: Sign the composed root
    let signer = MockDfcSigner::for_testing();
    let signed = signer.sign(&artifact.composed_root).await.unwrap();
    assert!(signer.verify(&signed).await.unwrap());

    // Step 3: Build master with artifact and check gate
    let master = make_signed_master_with_artifact(artifact);
    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(decision.allowed, "Gate should allow: {}", decision.reason);
}

/// Full negative pipeline: create → tamper → verify fails → gate denies
fn negative_pipeline(
    artifact_data: &[u8],
    control_data: &[u8],
    intent_data: &[u8],
    tamper_which: &str,
) {
    let mut artifact = compose_certification_artifact(
        "/usr/bin/tampered",
        Blake3Hash::digest(artifact_data),
        Blake3Hash::digest(control_data),
        Blake3Hash::digest(intent_data),
        "production",
    );

    // Tamper
    match tamper_which {
        "artifact" => artifact.artifact_hash = tamper_hash(&artifact.artifact_hash),
        "control" => artifact.control_hash = tamper_hash(&artifact.control_hash),
        "intent" => artifact.intent_hash = tamper_hash(&artifact.intent_hash),
        _ => panic!("Unknown tamper target"),
    }

    // Verification should fail
    assert!(
        !verify_certification_artifact(&artifact),
        "Tampered artifact ({tamper_which}) should fail verification"
    );

    // Gate should deny
    let master = make_signed_master_with_artifact(artifact);
    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(!decision.allowed, "Gate should deny tampered artifact");
}

// ═══════════════════════════════════════════════════════════════════
// ARTIFACT SOURCE VARIATIONS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nix_closure_artifact() {
    let artifact = make_artifact(
        "/nix/store/hash-myapp",
        b"nix-closure-hash-full",
        b"kensa-assessment",
        b"pangea-synthesis-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn nix_single_path_artifact() {
    let artifact = make_artifact(
        "/nix/store/single-path",
        b"nix-single-drv-hash",
        b"kensa-controls",
        b"pangea-synth",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn nix_system_profile_artifact() {
    let artifact = make_artifact(
        "/nix/var/nix/profiles/system",
        b"system-profile-closure-hash",
        b"compliance-controls-hash",
        b"intent-from-pangea",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn oci_manifest_artifact() {
    let artifact = make_artifact(
        "ghcr.io/pleme-io/app@sha256:abc123",
        b"oci-manifest-digest",
        b"oci-security-controls",
        b"pangea-oci-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn oci_layer_hash_artifact() {
    let artifact = make_artifact(
        "ghcr.io/pleme-io/app:v1.0/layers/0",
        b"individual-layer-sha256",
        b"layer-security-scan",
        b"layer-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn helm_chart_dir_artifact() {
    let artifact = make_artifact(
        "charts/myapp",
        b"helm-chart-directory-hash",
        b"helm-security-controls",
        b"helm-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn helm_rendered_artifact() {
    let artifact = make_artifact(
        "charts/myapp/rendered",
        b"helm-template-output-hash",
        b"rendered-security-controls",
        b"rendered-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn pangea_synthesis_artifact() {
    let artifact = make_artifact(
        "pangea/akeyless-resources",
        b"terraform-json-synthesis",
        b"pangea-synthesis-controls",
        b"pangea-deterministic-output",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn rspec_result_artifact() {
    let rspec_json = serde_json::json!({
        "examples": [
            {"description": "test1", "status": "passed"},
            {"description": "test2", "status": "passed"}
        ],
        "summary": {"example_count": 2, "failure_count": 0}
    });
    let artifact = make_artifact(
        "specs/akeyless_spec.rb",
        b"rspec-binary-hash",
        rspec_json.to_string().as_bytes(),
        b"rspec-pangea-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn inspec_result_artifact() {
    let inspec_json = serde_json::json!({
        "controls": [
            {"id": "ctrl-1", "status": "passed"},
            {"id": "ctrl-2", "status": "passed"}
        ],
        "statistics": {"duration": 1.2}
    });
    let artifact = make_artifact(
        "profiles/akeyless",
        b"inspec-profile-hash",
        inspec_json.to_string().as_bytes(),
        b"inspec-pangea-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn git_tree_artifact() {
    let artifact = make_artifact(
        "git://pleme-io/myapp@main",
        b"git-tree-hash-abc123",
        b"sdlc-source-controls",
        b"git-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn ci_build_artifact() {
    let artifact = make_artifact(
        "ci/builds/12345",
        b"ci-build-output-hash",
        b"build-security-controls",
        b"ci-pangea-intent",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn iac_test_suite_artifact() {
    let suite_report = serde_json::json!({
        "suite_name": "akeyless-integration",
        "platform": "k3s",
        "phases": [
            {"phase": "Init", "success": true},
            {"phase": "Apply", "success": true},
            {"phase": "Verify", "success": true},
            {"phase": "Teardown", "success": true}
        ],
        "all_passed": true
    });
    let artifact = make_artifact(
        "iac-test/akeyless-suite",
        b"suite-binary-hash",
        suite_report.to_string().as_bytes(),
        b"iac-test-intent",
    );
    positive_pipeline(artifact).await;
}

// ═══════════════════════════════════════════════════════════════════
// WRAPPED/COMPOSITE VARIATIONS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn nix_wrapped_oci_artifact() {
    // Nix builds an OCI image — artifact_hash is the Nix derivation,
    // but the binary_path references the OCI image
    let nix_drv_hash = Blake3Hash::digest(b"nix-builds-oci");
    let oci_hash = Blake3Hash::digest(b"oci-output-of-nix");
    let combined = Blake3Hash::combine(&nix_drv_hash, &oci_hash);
    let artifact = compose_certification_artifact(
        "ghcr.io/pleme-io/nix-built-image:v1",
        combined,
        Blake3Hash::digest(b"wrapped-controls"),
        Blake3Hash::digest(b"wrapped-intent"),
        "production",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn helm_with_oci_refs_artifact() {
    let helm_hash = Blake3Hash::digest(b"helm-chart-contents");
    let oci_ref_hash = Blake3Hash::digest(b"oci-image-referenced");
    let combined = Blake3Hash::combine(&helm_hash, &oci_ref_hash);
    let artifact = compose_certification_artifact(
        "charts/myapp-with-oci",
        combined,
        Blake3Hash::digest(b"helm-oci-controls"),
        Blake3Hash::digest(b"helm-oci-intent"),
        "staging",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn pangea_through_nix_artifact() {
    let pangea_hash = Blake3Hash::digest(b"pangea-gem-derivation");
    let nix_hash = Blake3Hash::digest(b"nix-wraps-pangea");
    let combined = Blake3Hash::combine(&pangea_hash, &nix_hash);
    let artifact = compose_certification_artifact(
        "/nix/store/pangea-synth",
        combined,
        Blake3Hash::digest(b"pangea-nix-controls"),
        Blake3Hash::digest(b"pangea-nix-intent"),
        "production",
    );
    positive_pipeline(artifact).await;
}

#[tokio::test]
async fn inspec_transpiled_to_rspec() {
    let inspec_hash = Blake3Hash::digest(b"inspec-original");
    let rspec_hash = Blake3Hash::digest(b"rspec-transpiled");
    let combined = Blake3Hash::combine(&inspec_hash, &rspec_hash);
    let artifact = compose_certification_artifact(
        "specs/transpiled-inspec",
        combined,
        Blake3Hash::digest(b"transpiled-controls"),
        Blake3Hash::digest(b"transpiled-intent"),
        "test",
    );
    positive_pipeline(artifact).await;
}

// ═══════════════════════════════════════════════════════════════════
// NEGATIVE TESTS (tampered = DENY)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tampered_nix_closure_denied() {
    negative_pipeline(
        b"nix-closure-hash",
        b"controls",
        b"intent",
        "artifact",
    );
}

#[test]
fn tampered_oci_manifest_denied() {
    negative_pipeline(
        b"oci-manifest",
        b"controls",
        b"intent",
        "control",
    );
}

#[test]
fn tampered_helm_chart_denied() {
    negative_pipeline(
        b"helm-chart",
        b"helm-controls",
        b"helm-intent",
        "intent",
    );
}

#[test]
fn tampered_pangea_synthesis_denied() {
    negative_pipeline(
        b"pangea-synthesis",
        b"pangea-controls",
        b"pangea-intent",
        "artifact",
    );
}

#[test]
fn tampered_rspec_result_denied() {
    negative_pipeline(
        b"rspec-result",
        b"rspec-controls",
        b"rspec-intent",
        "control",
    );
}

#[test]
fn tampered_inspec_result_denied() {
    negative_pipeline(
        b"inspec-result",
        b"inspec-controls",
        b"inspec-intent",
        "intent",
    );
}

#[test]
fn tampered_git_tree_denied() {
    negative_pipeline(
        b"git-tree",
        b"git-controls",
        b"git-intent",
        "artifact",
    );
}

#[test]
fn tampered_iac_suite_denied() {
    negative_pipeline(
        b"iac-suite",
        b"iac-controls",
        b"iac-intent",
        "control",
    );
}

// ═══════════════════════════════════════════════════════════════════
// CROSS-VARIANT TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn nix_hash_differs_from_oci_hash() {
    // Same content bytes, different provenance context
    let content = b"same-binary-content";
    let nix_artifact = compose_certification_artifact(
        "/nix/store/myapp",
        Blake3Hash::digest(content),
        Blake3Hash::digest(b"nix-controls"),
        Blake3Hash::digest(b"nix-intent"),
        "prod",
    );
    let oci_artifact = compose_certification_artifact(
        "ghcr.io/pleme-io/myapp:v1",
        Blake3Hash::digest(content),
        Blake3Hash::digest(b"oci-controls"),
        Blake3Hash::digest(b"oci-intent"),
        "prod",
    );
    // Same artifact_hash but different control/intent → different composed_root
    assert_ne!(nix_artifact.composed_root, oci_artifact.composed_root);
}

#[test]
fn helm_dir_hash_differs_from_rendered() {
    let chart_dir = compose_certification_artifact(
        "charts/myapp",
        Blake3Hash::digest(b"chart-dir-files"),
        Blake3Hash::digest(b"controls"),
        Blake3Hash::digest(b"intent"),
        "prod",
    );
    let rendered = compose_certification_artifact(
        "charts/myapp/rendered",
        Blake3Hash::digest(b"rendered-yaml-output"),
        Blake3Hash::digest(b"controls"),
        Blake3Hash::digest(b"intent"),
        "prod",
    );
    assert_ne!(chart_dir.composed_root, rendered.composed_root);
}

#[test]
fn rspec_hash_differs_from_inspec_hash() {
    let rspec = compose_certification_artifact(
        "specs/controls",
        Blake3Hash::digest(b"binary"),
        Blake3Hash::digest(b"rspec-json-output"),
        Blake3Hash::digest(b"intent"),
        "prod",
    );
    let inspec = compose_certification_artifact(
        "profiles/controls",
        Blake3Hash::digest(b"binary"),
        Blake3Hash::digest(b"inspec-json-output"),
        Blake3Hash::digest(b"intent"),
        "prod",
    );
    assert_ne!(rspec.composed_root, inspec.composed_root);
}

#[test]
fn two_pangea_synths_different_resources_differ() {
    let synth_a = compose_certification_artifact(
        "pangea/resource-a",
        Blake3Hash::digest(b"artifact-a"),
        Blake3Hash::digest(b"controls-a"),
        Blake3Hash::digest(b"intent-a"),
        "prod",
    );
    let synth_b = compose_certification_artifact(
        "pangea/resource-b",
        Blake3Hash::digest(b"artifact-b"),
        Blake3Hash::digest(b"controls-b"),
        Blake3Hash::digest(b"intent-b"),
        "prod",
    );
    assert_ne!(synth_a.composed_root, synth_b.composed_root);
}

// ═══════════════════════════════════════════════════════════════════
// SDLC CHAIN VARIATIONS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sdlc_chain_all_nix_artifacts() {
    let artifacts: Vec<_> = (0..4)
        .map(|i| {
            make_artifact(
                &format!("/nix/store/phase-{i}"),
                format!("nix-phase-{i}").as_bytes(),
                format!("controls-{i}").as_bytes(),
                format!("intent-{i}").as_bytes(),
            )
        })
        .collect();

    for artifact in &artifacts {
        assert!(verify_certification_artifact(artifact));
    }

    let layers = vec![make_layer(LayerType::Nix, b"nix-sdlc")];
    let master = compose_merkle(&layers, "prod")
        .with_compliance(Blake3Hash::digest(b"compliance"))
        .with_certification_artifacts(artifacts);

    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(decision.allowed);
}

#[test]
fn sdlc_chain_mixed_artifacts() {
    let artifacts = vec![
        make_artifact("/nix/store/app", b"nix-build", b"nix-controls", b"nix-intent"),
        make_artifact("ghcr.io/app:v1", b"oci-image", b"oci-controls", b"oci-intent"),
        make_artifact("charts/app", b"helm-chart", b"helm-controls", b"helm-intent"),
        make_artifact("pangea/synth", b"pangea-tf", b"pangea-controls", b"pangea-intent"),
    ];

    for artifact in &artifacts {
        assert!(verify_certification_artifact(artifact));
    }

    let layers = vec![
        make_layer(LayerType::Nix, b"nix"),
        make_layer(LayerType::Oci, b"oci"),
        make_layer(LayerType::Helm, b"helm"),
    ];
    let master = compose_merkle(&layers, "prod")
        .with_compliance(Blake3Hash::digest(b"compliance"))
        .with_certification_artifacts(artifacts);

    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(decision.allowed);
}

#[test]
fn sdlc_chain_missing_container_build_incomplete() {
    // Master with no certification artifacts should be denied
    let layers = vec![make_layer(LayerType::Nix, b"nix")];
    let master = compose_merkle(&layers, "prod")
        .with_compliance(Blake3Hash::digest(b"compliance"));

    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(!decision.allowed);
    assert!(decision.reason.contains("none present"));
}

#[test]
fn sdlc_chain_all_passed_then_tampered() {
    let good_artifact = make_artifact("/app", b"good", b"controls", b"intent");
    assert!(verify_certification_artifact(&good_artifact));

    // Now tamper one
    let mut bad_artifact = make_artifact("/app2", b"bad", b"controls2", b"intent2");
    bad_artifact.artifact_hash = tamper_hash(&bad_artifact.artifact_hash);
    assert!(!verify_certification_artifact(&bad_artifact));

    // Master with one good and one tampered
    let layers = vec![make_layer(LayerType::Nix, b"nix")];
    let master = compose_merkle(&layers, "prod")
        .with_compliance(Blake3Hash::digest(b"compliance"))
        .with_certification_artifacts(vec![good_artifact, bad_artifact]);

    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(!decision.allowed, "Gate should deny when any artifact is tampered");
}

// ═══════════════════════════════════════════════════════════════════
// MERKLE TREE COMPOSITION VARIATIONS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn certification_artifact_all_three_different() {
    let artifact = compose_certification_artifact(
        "/usr/bin/test",
        Blake3Hash::digest(b"unique-artifact"),
        Blake3Hash::digest(b"unique-control"),
        Blake3Hash::digest(b"unique-intent"),
        "test",
    );
    assert!(verify_certification_artifact(&artifact));
    // All three leaf hashes should be different
    assert_ne!(artifact.artifact_hash, artifact.control_hash);
    assert_ne!(artifact.control_hash, artifact.intent_hash);
    assert_ne!(artifact.artifact_hash, artifact.intent_hash);
}

#[test]
fn certification_artifact_control_equals_intent() {
    // Same hash for control and intent leaves
    let same = Blake3Hash::digest(b"same-data-for-both");
    let artifact = compose_certification_artifact(
        "/usr/bin/test",
        Blake3Hash::digest(b"artifact"),
        same.clone(),
        same.clone(),
        "test",
    );
    assert!(verify_certification_artifact(&artifact));
    assert_eq!(artifact.control_hash, artifact.intent_hash);
}

#[test]
fn certification_artifact_all_zero_hashes() {
    let zero = Blake3Hash([0u8; 32]);
    let artifact = compose_certification_artifact(
        "/usr/bin/zero",
        zero.clone(),
        zero.clone(),
        zero.clone(),
        "test",
    );
    assert!(verify_certification_artifact(&artifact));
}

#[test]
fn certification_artifact_max_length_path() {
    let long_path = "/".to_owned() + &"a".repeat(4096);
    let artifact = compose_certification_artifact(
        &long_path,
        Blake3Hash::digest(b"artifact"),
        Blake3Hash::digest(b"control"),
        Blake3Hash::digest(b"intent"),
        "test",
    );
    assert!(verify_certification_artifact(&artifact));
    assert_eq!(artifact.binary_path.len(), 4097);
}

#[tokio::test]
async fn multiple_artifacts_on_master_signature() {
    let artifacts: Vec<_> = (0..5)
        .map(|i| {
            make_artifact(
                &format!("/usr/bin/app-{i}"),
                format!("artifact-{i}").as_bytes(),
                format!("control-{i}").as_bytes(),
                format!("intent-{i}").as_bytes(),
            )
        })
        .collect();

    // Verify each individually
    for artifact in &artifacts {
        assert!(verify_certification_artifact(artifact));
    }

    // Sign each composed root
    let signer = MockDfcSigner::for_testing();
    for artifact in &artifacts {
        let signed = signer.sign(&artifact.composed_root).await.unwrap();
        assert!(signer.verify(&signed).await.unwrap());
    }

    // Attach all 5 to a master and check gate
    let layers = vec![
        make_layer(LayerType::Nix, b"nix"),
        make_layer(LayerType::Oci, b"oci"),
        make_layer(LayerType::Helm, b"helm"),
    ];
    let master = compose_merkle(&layers, "production")
        .with_compliance(Blake3Hash::digest(b"full-compliance"))
        .with_certification_artifacts(artifacts);

    let policy = gate_policy_with_artifacts();
    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(decision.allowed, "Gate should allow with 5 valid artifacts");
}

// ═══════════════════════════════════════════════════════════════════
// PART 3: Plugin domain_hash → CertificationArtifact integration
// ═══════════════════════════════════════════════════════════════════

mod plugin_merkle_integration {
    use super::*;
    use std::sync::Arc;
    use tameshi::compliance::plugin::{CompliancePlugin, PluginConfig};
    use tameshi::compliance::plugins::kernel::KernelPlugin;
    use tameshi::compliance::plugins::kubernetes::KubernetesPlugin;
    use tameshi::compliance::plugins::nix_store::NixStorePlugin;
    use tameshi::compliance::plugins::oci::OciPlugin;
    use tameshi::traits::MockCommandRunner;

    fn mock_kernel_runner() -> Arc<MockCommandRunner> {
        let runner = MockCommandRunner::new();
        let sysctl = [
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
            ("kernel.yama.ptrace_scope", "1"),
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv4.conf.all.accept_source_route", "0"),
            ("net.ipv4.conf.all.log_martians", "1"),
            ("net.ipv4.conf.all.rp_filter", "1"),
            ("fs.protected_hardlinks", "1"),
            ("fs.protected_symlinks", "1"),
            ("vm.mmap_min_addr", "65536"),
        ]
        .iter()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect::<Vec<_>>()
        .join("\n");
        runner.add_response("sysctl", &["-a"], &sysctl);
        runner.add_response("getenforce", &[], "Enforcing\n");
        Arc::new(runner)
    }

    #[tokio::test]
    async fn kernel_domain_hash_feeds_certification_artifact() {
        let plugin = KernelPlugin::new(mock_kernel_runner());
        let config = PluginConfig::default();
        let controls = plugin.generate_controls(&config);
        let evaluation = plugin.evaluate(&controls, &config).await.unwrap();

        let artifact = compose_certification_artifact(
            "/usr/bin/myapp",
            Blake3Hash::digest(b"nix-closure"),
            evaluation.domain_hash.clone(),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );

        assert!(verify_certification_artifact(&artifact));
    }

    #[tokio::test]
    async fn nix_store_domain_hash_feeds_certification_artifact() {
        let runner = Arc::new(MockCommandRunner::new());
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{},"nixpkgs":{"locked":{"rev":"abc"}}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_error("vulnix", &["--system"], "not found");
        runner.add_response("nix-store", &["--gc", "--print-roots"], "/nix/var/nix/gcroots/auto/abc -> /nix/store/abc\n");
        runner.add_response("stat", &["-c", "%a", "/nix/store"], "1775\n");
        runner.add_response(
            "nix",
            &["show-config", "--json"],
            r#"{"sandbox":{"value":true},"trusted-users":{"value":"root"},"require-sigs":{"value":true},"trusted-public-keys":{"value":"cache.nixos.org-1:key1"},"allowed-users":{"value":"root"},"max-jobs":{"value":4},"experimental-features":{"value":"nix-command flakes"},"build-users-group":{"value":"nixbld"},"pure-eval":{"value":true}}"#,
        );

        let plugin = NixStorePlugin::new(runner);
        let config = PluginConfig::default();
        let controls = plugin.generate_controls(&config);
        let evaluation = plugin.evaluate(&controls, &config).await.unwrap();

        let artifact = compose_certification_artifact(
            "/usr/bin/nix-app",
            Blake3Hash::digest(b"nix-closure"),
            evaluation.domain_hash.clone(),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );

        assert!(verify_certification_artifact(&artifact));
    }

    #[tokio::test]
    async fn oci_domain_hash_feeds_certification_artifact() {
        let runner = Arc::new(MockCommandRunner::new());
        let img = "docker://test:v1.0";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            r#"{"config":{"User":"1000","Labels":{"cap-drop":"ALL","read-only":"true"},"Healthcheck":{"Test":["CMD","healthcheck"]},"WorkingDir":"/app","Entrypoint":["/app/start"],"ExposedPorts":{"8080/tcp":{}},"Env":["PATH=/usr/bin","HOME=/app"]}}"#,
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:abc123"},"layers":[]}"#,
        );

        let plugin = OciPlugin::new(runner, img);
        let config = PluginConfig::default();
        let controls = plugin.generate_controls(&config);
        let evaluation = plugin.evaluate(&controls, &config).await.unwrap();

        let artifact = compose_certification_artifact(
            "ghcr.io/pleme-io/app:v1.0",
            Blake3Hash::digest(b"oci-manifest"),
            evaluation.domain_hash.clone(),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );

        assert!(verify_certification_artifact(&artifact));
    }

    #[tokio::test]
    async fn kubernetes_domain_hash_feeds_certification_artifact() {
        let runner = Arc::new(MockCommandRunner::new());
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            r#"{"items":[{"metadata":{"name":"app-ns","labels":{"pod-security.kubernetes.io/enforce":"restricted"}}}]}"#,
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            r#"{"items":[{"metadata":{"name":"default-deny"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}]}"#,
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            r#"{"items":[{"metadata":{"name":"system:admin"},"roleRef":{"name":"cluster-admin"}}]}"#,
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            r#"{"items":[{"metadata":{"name":"test-pod"},"spec":{"automountServiceAccountToken":false,"serviceAccountName":"app-sa","containers":[{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":false},"livenessProbe":{"httpGet":{"path":"/health","port":8080}},"readinessProbe":{"httpGet":{"path":"/ready","port":8080}},"imagePullPolicy":"Always"}]}}]}"#,
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "json"],
            r#"{"items":[{"spec":{"containers":[{"command":["kube-apiserver","--encryption-provider-config=/etc/k8s/enc.yaml"]}]}}]}"#,
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterroles", "-o", "json"],
            r#"{"items":[{"metadata":{"name":"system:admin"},"rules":[{"verbs":["*"],"resources":["*"]}]}]}"#,
        );

        let plugin = KubernetesPlugin::new(runner);
        let config = PluginConfig::default();
        let controls = plugin.generate_controls(&config);
        let evaluation = plugin.evaluate(&controls, &config).await.unwrap();

        let artifact = compose_certification_artifact(
            "/usr/bin/k8s-app",
            Blake3Hash::digest(b"k8s-deployment"),
            evaluation.domain_hash.clone(),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );

        assert!(verify_certification_artifact(&artifact));
    }
}
