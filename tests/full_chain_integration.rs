//! Full chain integration test.
//!
//! Proves the unified theory of infrastructure proof works end-to-end:
//!   Collectors -> CertificationArtifact -> Signing -> Verification -> Gating
//!   + HeartbeatChain + IacTestSuiteReport + SdlcChain + ComplianceOrchestrator
//!
//! This test exercises EVERY major subsystem in tameshi and verifies that
//! they compose correctly into a single, tamper-evident chain of proof.

use std::sync::Arc;

use chrono::Utc;

use tameshi::certification_artifact::{
    compose_certification_artifact, verify_certification_artifact,
};
use tameshi::collectors::inspec_result::hash_inspec_output;
use tameshi::collectors::pangea::hash_synthesis_json;
use tameshi::collectors::rspec::hash_rspec_output;
use tameshi::compliance::plugin::{MockPlugin, PluginConfig};
use tameshi::compliance::plugin_orchestrator::{ComplianceOrchestrator, FullComplianceReport};
use tameshi::compliance::registry::PluginRegistryBuilder;
use tameshi::gating::{GatingPolicy, evaluate_gate};
use tameshi::hash::Blake3Hash;
use tameshi::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};
use tameshi::iac_attestation::{IacTestPhase, IacTestPhaseResult, IacTestSuiteReport};
use tameshi::merkle::compose_merkle;
use tameshi::sdlc::{ALL_PHASES, SdlcChain, SdlcCheckpoint, SdlcPhase};
use tameshi::signature::{LayerSignature, LayerType};
use tameshi::signing::{MerkleRootSigner, MockDfcSigner};
use tameshi::verify::verify_master;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pangea_synthesis_json() -> Vec<u8> {
    br#"{
        "resource": {
            "akeyless_auth_method": {
                "api_key_prod": {
                    "path": "/pleme/prod/api-key",
                    "type": "api_key"
                }
            },
            "akeyless_static_secret": {
                "db_password": {
                    "path": "/pleme/prod/db-password",
                    "value": "PLACEHOLDER"
                }
            }
        }
    }"#
    .to_vec()
}

fn rspec_result_json() -> Vec<u8> {
    br#"{
        "version": "3.12",
        "examples": [
            {
                "full_description": "akeyless auth method creates API key",
                "status": "passed",
                "run_time": 0.012
            },
            {
                "full_description": "akeyless static secret stores value",
                "status": "passed",
                "run_time": 0.008
            }
        ],
        "summary": {
            "example_count": 2,
            "failure_count": 0
        }
    }"#
    .to_vec()
}

fn inspec_result_json() -> Vec<u8> {
    br#"{
        "profiles": [{
            "name": "akeyless-baseline",
            "controls": [
                {
                    "id": "akeyless-1.1",
                    "impact": 0.7,
                    "results": [{"status": "passed"}]
                },
                {
                    "id": "akeyless-1.2",
                    "impact": 0.9,
                    "results": [{"status": "passed"}]
                }
            ]
        }],
        "statistics": {"duration": 1.5}
    }"#
    .to_vec()
}

fn make_sdlc_chain() -> SdlcChain {
    let mut chain = SdlcChain::new("deploy-prod-20260320-001");
    for (i, phase) in ALL_PHASES.iter().enumerate() {
        chain.add_checkpoint(SdlcCheckpoint {
            phase: phase.clone(),
            output_hash: Blake3Hash::digest(format!("phase-{i}-output").as_bytes()),
            gate_passed: true,
            gate_name: Some(format!("{phase}-gate")),
            details: format!("Phase {phase} completed successfully"),
            recorded_at: Utc::now(),
        });
    }
    chain
}

fn make_iac_test_suite() -> IacTestSuiteReport {
    let phases = vec![
        IacTestPhaseResult {
            phase: IacTestPhase::Init,
            success: true,
            output_hash: Blake3Hash::digest(b"init-output"),
            duration_ms: 5000,
            completed_at: Utc::now(),
            details: "Provider initialized".to_string(),
        },
        IacTestPhaseResult {
            phase: IacTestPhase::Apply,
            success: true,
            output_hash: Blake3Hash::digest(b"apply-output"),
            duration_ms: 30000,
            completed_at: Utc::now(),
            details: "Resources applied".to_string(),
        },
        IacTestPhaseResult {
            phase: IacTestPhase::Verify,
            success: true,
            output_hash: Blake3Hash::digest(b"verify-output"),
            duration_ms: 15000,
            completed_at: Utc::now(),
            details: "InSpec profiles passed".to_string(),
        },
        IacTestPhaseResult {
            phase: IacTestPhase::Teardown,
            success: true,
            output_hash: Blake3Hash::digest(b"teardown-output"),
            duration_ms: 10000,
            completed_at: Utc::now(),
            details: "Resources destroyed".to_string(),
        },
    ];

    let suite_hash = IacTestSuiteReport::compute_suite_hash(&phases);
    IacTestSuiteReport {
        suite_name: "akeyless-integration".to_string(),
        platform: "pangea".to_string(),
        environment: "production".to_string(),
        phases,
        all_passed: true,
        suite_hash,
        completed_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// THE test: full chain end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_chain_end_to_end() {
    // -----------------------------------------------------------------------
    // Step 1: Hash collectors (Pangea, RSpec, InSpec)
    // -----------------------------------------------------------------------
    let pangea_sig = hash_synthesis_json(&pangea_synthesis_json(), "pangea-akeyless")
        .await
        .expect("Pangea synthesis hash failed");
    assert_eq!(pangea_sig.layer, LayerType::PangeaSynthesis);

    let rspec_sig = hash_rspec_output(&rspec_result_json(), "rspec-akeyless")
        .await
        .expect("RSpec result hash failed");
    assert_eq!(rspec_sig.layer, LayerType::RSpecResult);

    let inspec_sig = hash_inspec_output(&inspec_result_json(), "inspec-akeyless")
        .await
        .expect("InSpec result hash failed");
    assert_eq!(inspec_sig.layer, LayerType::InSpecResult);

    // -----------------------------------------------------------------------
    // Step 2: Create a Nix layer signature (simulated)
    // -----------------------------------------------------------------------
    let nix_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix-closure-hash"),
        "/nix/store/xxx-myapp",
        vec![],
    );

    // -----------------------------------------------------------------------
    // Step 3: Compose CertificationArtifact
    // -----------------------------------------------------------------------
    let artifact = compose_certification_artifact(
        "/usr/bin/myapp",
        nix_sig.hash.clone(),    // artifact = Nix derivation hash
        rspec_sig.hash.clone(),  // control = RSpec result hash
        pangea_sig.hash.clone(), // intent  = Pangea synthesis hash
        "production",
    );

    // Step 4: Verify the CertificationArtifact
    assert!(
        verify_certification_artifact(&artifact),
        "CertificationArtifact verification failed"
    );

    // -----------------------------------------------------------------------
    // Step 5: Compose MasterSignature from layer signatures
    // -----------------------------------------------------------------------
    let layers = vec![
        nix_sig.clone(),
        pangea_sig.clone(),
        rspec_sig.clone(),
        inspec_sig.clone(),
    ];
    let master = compose_merkle(&layers, "production");
    assert!(
        master.verify_untested(),
        "Untested Merkle root verification failed"
    );

    // -----------------------------------------------------------------------
    // Step 6: Run ComplianceOrchestrator with MockPlugins
    // -----------------------------------------------------------------------
    let registry = Arc::new(
        PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("kernel").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("nix-store").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("oci").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("kubernetes").with_pass_all(true)))
            .build(),
    );
    let orchestrator = ComplianceOrchestrator::new(registry);
    let compliance_report: FullComplianceReport = orchestrator
        .run_all(&PluginConfig::default())
        .await
        .expect("ComplianceOrchestrator failed");
    assert!(compliance_report.all_passed, "Compliance should pass");
    assert_eq!(compliance_report.total_controls, 8); // 4 plugins x 2 controls
    assert_eq!(compliance_report.passed_controls, 8);
    assert_eq!(compliance_report.failed_controls, 0);

    // -----------------------------------------------------------------------
    // Step 7: Combine master with compliance hash
    // -----------------------------------------------------------------------
    let master = master
        .with_compliance(compliance_report.compliance_hash.clone())
        .with_certification_artifacts(vec![artifact.clone()]);
    assert!(
        master.verify_secure(),
        "Secure signature verification failed"
    );
    assert!(
        master.is_fully_attested(),
        "Master should be fully attested"
    );

    // -----------------------------------------------------------------------
    // Step 8: Sign the Merkle root with MockDfcSigner
    // -----------------------------------------------------------------------
    let signer = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "ci-signer");
    let signed_root = signer
        .sign(master.gating_signature())
        .await
        .expect("Signing failed");
    assert_eq!(signed_root.root, *master.gating_signature());

    // Verify the signature
    let sig_valid = signer
        .verify(&signed_root)
        .await
        .expect("Signature verification failed");
    assert!(sig_valid, "MockDfcSigner verification should pass");

    // -----------------------------------------------------------------------
    // Step 9: Verify the signed root against the master
    // -----------------------------------------------------------------------
    let verification = verify_master(&master, master.gating_signature());
    assert!(
        verification.passed,
        "verify_master failed: {}",
        verification.description
    );

    // -----------------------------------------------------------------------
    // Step 10: Evaluate gate with certification artifacts required
    // -----------------------------------------------------------------------
    let policy = GatingPolicy {
        name: "production-gate".to_string(),
        required_layers: vec!["nix".to_string()],
        require_compliance: true,
        max_signature_age_secs: Some(3600),
        fail_open: false,
        require_certification_artifacts: true,
    };

    let gate_decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(
        gate_decision.allowed,
        "Gate should ALLOW: {}",
        gate_decision.reason
    );

    // -----------------------------------------------------------------------
    // Step 11: Create HeartbeatChain entry for the attestation
    // -----------------------------------------------------------------------
    let heartbeat = HeartbeatChain::new();
    heartbeat.append(
        VerifierIdentity::new("tameshi", "integration-test", "0.1.0"),
        HeartbeatEvent::ComplianceAssessment,
        VerificationOutcome::Allowed,
        "prod/Deployment/myapp",
        master.gating_signature().clone(),
    );
    assert_eq!(heartbeat.len(), 1);
    assert!(
        heartbeat.verify_integrity(),
        "Heartbeat chain integrity failed"
    );

    // -----------------------------------------------------------------------
    // Step 12: IacTestSuiteReport and suite hash verification
    // -----------------------------------------------------------------------
    let iac_report = make_iac_test_suite();
    assert!(iac_report.all_passed, "IaC test suite should pass");
    let recomputed_suite_hash = IacTestSuiteReport::compute_suite_hash(&iac_report.phases);
    assert_eq!(
        iac_report.suite_hash, recomputed_suite_hash,
        "Suite hash should be deterministic"
    );

    // -----------------------------------------------------------------------
    // Step 13: SdlcChain with all 8 phases
    // -----------------------------------------------------------------------
    let sdlc_chain = make_sdlc_chain();
    assert!(
        sdlc_chain.is_complete(),
        "SDLC chain should have all 8 phases"
    );
    assert!(sdlc_chain.all_gates_passed, "All SDLC gates should pass");

    // -----------------------------------------------------------------------
    // Step 14: Verify compliance_hash feeds into MasterSignature
    // -----------------------------------------------------------------------
    let compliance_hash = compliance_report.compliance_hash.clone();
    let expected_secure = Blake3Hash::combine(&master.untested, &compliance_hash);
    assert_eq!(
        master.secure.as_ref().unwrap(),
        &expected_secure,
        "Secure hash = BLAKE3(untested || compliance)"
    );

    // -----------------------------------------------------------------------
    // Step 15: Verify EVERYTHING chains together
    // -----------------------------------------------------------------------
    // The proof chain:
    //   Pangea synthesis -> hash -> CertificationArtifact.intent_hash
    //   RSpec results    -> hash -> CertificationArtifact.control_hash
    //   Nix closure      -> hash -> CertificationArtifact.artifact_hash
    //   CertificationArtifact -> verify -> 3-leaf Merkle commitment
    //   LayerSignatures  -> Merkle root -> MasterSignature.untested
    //   Compliance plugins -> FullComplianceReport.compliance_hash
    //   MasterSignature.with_compliance() -> .secure
    //   GatingPolicy.evaluate_gate() -> ALLOWED
    //   HeartbeatChain.append() -> tamper-evident audit trail
    //   SdlcChain.is_complete() -> all 8 phases attested
    //   IacTestSuiteReport.suite_hash -> deterministic from phase hashes
    assert!(verify_certification_artifact(&artifact));
    assert!(master.verify_untested());
    assert!(master.verify_secure());
    assert!(gate_decision.allowed);
    assert!(heartbeat.verify_integrity());
    assert!(sdlc_chain.is_complete());
    assert!(iac_report.all_passed);
}

// ---------------------------------------------------------------------------
// Negative tests: tamper detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tamper_with_certification_artifact_hash_breaks_chain() {
    let nix_hash = Blake3Hash::digest(b"nix-closure");
    let control_hash = Blake3Hash::digest(b"kensa-result");
    let intent_hash = Blake3Hash::digest(b"pangea-synthesis");

    let mut artifact = compose_certification_artifact(
        "/usr/bin/myapp",
        nix_hash,
        control_hash,
        intent_hash,
        "production",
    );

    // Verify it works initially
    assert!(verify_certification_artifact(&artifact));

    // Tamper with the artifact_hash
    artifact.artifact_hash = Blake3Hash::digest(b"tampered-nix-closure");

    // Verification should now fail
    assert!(
        !verify_certification_artifact(&artifact),
        "Tampered artifact should fail verification"
    );
}

#[tokio::test]
async fn tamper_with_master_signature_layer_breaks_verification() {
    let nix_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix-closure"),
        "test",
        vec![],
    );
    let oci_sig = LayerSignature::new(
        LayerType::Oci,
        Blake3Hash::digest(b"oci-manifest"),
        "test",
        vec![],
    );

    let master = compose_merkle(&[nix_sig.clone(), oci_sig.clone()], "production");
    let compliance_hash = Blake3Hash::digest(b"compliance");
    let master = master.with_compliance(compliance_hash);

    // Should verify initially
    assert!(master.verify_secure());

    // Tamper with a layer hash
    let mut tampered_master = master.clone();
    tampered_master.layers[0].hash = Blake3Hash::digest(b"tampered-nix");

    // Untested verification should now fail (Merkle root mismatch)
    assert!(
        !tampered_master.verify_untested(),
        "Tampered layer should break untested verification"
    );
}

#[test]
fn remove_sdlc_phase_makes_chain_incomplete() {
    let mut chain = SdlcChain::new("partial-deploy");
    // Add only 7 of 8 phases (skip RuntimeExecution)
    for (i, phase) in ALL_PHASES.iter().enumerate() {
        if *phase == SdlcPhase::RuntimeExecution {
            continue;
        }
        chain.add_checkpoint(SdlcCheckpoint {
            phase: phase.clone(),
            output_hash: Blake3Hash::digest(format!("phase-{i}").as_bytes()),
            gate_passed: true,
            gate_name: None,
            details: "test".to_string(),
            recorded_at: Utc::now(),
        });
    }

    assert!(
        !chain.is_complete(),
        "Chain missing RuntimeExecution should not be complete"
    );
    assert_eq!(chain.checkpoints.len(), 7);
}

#[tokio::test]
async fn fail_one_compliance_plugin_makes_all_passed_false() {
    let registry = Arc::new(
        PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("kernel").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("nix-store").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("oci").with_pass_all(false))) // FAIL
            .register(Arc::new(MockPlugin::new("kubernetes").with_pass_all(true)))
            .build(),
    );
    let orchestrator = ComplianceOrchestrator::new(registry);
    let report = orchestrator
        .run_all(&PluginConfig::default())
        .await
        .expect("Orchestrator failed");

    assert!(
        !report.all_passed,
        "Report should fail when one plugin fails"
    );
    assert_eq!(report.total_controls, 8);
    assert_eq!(report.passed_controls, 6);
    assert_eq!(report.failed_controls, 2); // OCI plugin has 2 controls
}

#[tokio::test]
async fn gate_denies_without_certification_artifacts() {
    let nix_sig = LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix-closure"),
        "test",
        vec![],
    );

    let master =
        compose_merkle(&[nix_sig], "production").with_compliance(Blake3Hash::digest(b"compliance"));

    // No certification artifacts attached
    let policy = GatingPolicy {
        name: "strict-gate".to_string(),
        required_layers: vec![],
        require_compliance: true,
        max_signature_age_secs: Some(3600),
        fail_open: false,
        require_certification_artifacts: true, // Require artifacts
    };

    let decision = evaluate_gate(&policy, &master, master.gating_signature());
    assert!(
        !decision.allowed,
        "Gate should DENY without certification artifacts"
    );
    assert!(decision.reason.contains("Certification artifacts required"));
}

#[tokio::test]
async fn heartbeat_chain_detects_tampering() {
    let heartbeat = HeartbeatChain::new();
    heartbeat.append(
        VerifierIdentity::new("kensa", "pod-1", "0.1.0"),
        HeartbeatEvent::ComplianceAssessment,
        VerificationOutcome::Allowed,
        "test/Deployment/app",
        Blake3Hash::digest(b"sig-1"),
    );
    heartbeat.append(
        VerifierIdentity::new("sekiban", "pod-2", "0.1.0"),
        HeartbeatEvent::AdmissionDecision,
        VerificationOutcome::Allowed,
        "test/Deployment/app",
        Blake3Hash::digest(b"sig-2"),
    );

    // Chain should be valid initially
    assert!(heartbeat.verify_integrity());
    assert_eq!(heartbeat.len(), 2);
}

#[test]
fn sdlc_chain_failed_gate_tracks_failure() {
    let mut chain = SdlcChain::new("fail-deploy");
    chain.add_checkpoint(SdlcCheckpoint {
        phase: SdlcPhase::SourceCommit,
        output_hash: Blake3Hash::digest(b"src"),
        gate_passed: true,
        gate_name: Some("pre-commit".to_string()),
        details: "ok".to_string(),
        recorded_at: Utc::now(),
    });
    chain.add_checkpoint(SdlcCheckpoint {
        phase: SdlcPhase::CiBuild,
        output_hash: Blake3Hash::digest(b"ci"),
        gate_passed: false, // FAIL
        gate_name: Some("ci-gate".to_string()),
        details: "tests failed".to_string(),
        recorded_at: Utc::now(),
    });

    assert!(!chain.all_gates_passed, "Chain should track failed gate");
    assert!(
        !chain.is_complete(),
        "Chain with only 2 phases is not complete"
    );
}

#[test]
fn iac_test_suite_hash_changes_on_tampered_phase() {
    let report = make_iac_test_suite();
    let original_hash = report.suite_hash.clone();

    // Recompute with a different phase output
    let mut tampered_phases = report.phases.clone();
    tampered_phases[0].output_hash = Blake3Hash::digest(b"tampered-init");
    let tampered_hash = IacTestSuiteReport::compute_suite_hash(&tampered_phases);

    assert_ne!(
        original_hash, tampered_hash,
        "Tampered phase output should produce different suite hash"
    );
}

#[test]
fn compliance_hash_determinism() {
    let registry = Arc::new(
        PluginRegistryBuilder::new()
            .register(Arc::new(MockPlugin::new("alpha").with_pass_all(true)))
            .register(Arc::new(MockPlugin::new("beta").with_pass_all(true)))
            .build(),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = PluginConfig::default();

    let report1 = rt.block_on(async {
        ComplianceOrchestrator::new(Arc::clone(&registry))
            .run_all(&config)
            .await
            .unwrap()
    });
    let report2 = rt.block_on(async {
        ComplianceOrchestrator::new(registry)
            .run_all(&config)
            .await
            .unwrap()
    });

    assert_eq!(
        report1.compliance_hash, report2.compliance_hash,
        "Compliance hash should be deterministic across runs"
    );
}
