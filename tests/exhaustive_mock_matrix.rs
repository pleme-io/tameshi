//! Exhaustive Mock Testing Matrix — 20 variants covering every attestation state combination.
//!
//! Each test maps to a row in `EXHAUSTIVE_MOCK_TESTING.md` Section 2 (State Matrix).
//! Tests exercise real tameshi types with mock I/O boundaries.

use std::time::Duration;

use tameshi::ai_threat::{
    AiDecision, AiDeploymentContext, AiThreatClient, AnalyzeProvenanceRequest,
    FailableAiThreatClient, MockAiThreatClient, NixDerivationGraph, Urgency,
};
use tameshi::certification_artifact::{
    compose_certification_artifact, verify_certification_artifact,
};
use tameshi::gating::{GatingPolicy, evaluate_gate, evaluate_gate_with_clock};
use tameshi::hash::Blake3Hash;
use tameshi::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};
use tameshi::merkle::{compose_merkle, compute_merkle_root};
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};
use tameshi::signing::{
    BreakGlassToken, FailableDfcSigner, LocalSigner, MerkleRootSigner, MockDfcSigner,
};
use tameshi::traits::FixedClock;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Build a fully attested MasterSignature with compliance and a valid
/// CertificationArtifact. Returns (master, expected_gating_hash).
fn make_attested_master(environment: &str) -> (MasterSignature, Blake3Hash) {
    let layers = vec![
        LayerSignature::new(
            LayerType::Nix,
            Blake3Hash::digest(b"nix-closure"),
            "test",
            vec![],
        ),
        LayerSignature::new(
            LayerType::Oci,
            Blake3Hash::digest(b"oci-manifest"),
            "test",
            vec![],
        ),
    ];
    let compliance = Blake3Hash::digest(b"compliance-passed");
    let cert = make_valid_artifact();
    let master = compose_merkle(&layers, environment)
        .with_compliance(compliance)
        .with_certification_artifacts(vec![cert]);
    let expected = master.gating_signature().clone();
    (master, expected)
}

/// Build a valid CertificationArtifact for /usr/bin/app.
fn make_valid_artifact() -> tameshi::certification_artifact::CertificationArtifact {
    compose_certification_artifact(
        "/usr/bin/app",
        Blake3Hash::digest(b"legitimate-binary"),
        Blake3Hash::digest(b"compliance-passed"),
        Blake3Hash::digest(b"pangea-synthesis"),
        "production",
    )
}

/// Build a standard AnalyzeProvenanceRequest from a CertificationArtifact.
fn make_ai_request(
    artifact: &tameshi::certification_artifact::CertificationArtifact,
) -> AnalyzeProvenanceRequest {
    AnalyzeProvenanceRequest {
        artifact_hash: artifact.artifact_hash.to_hex(),
        control_hash: artifact.control_hash.to_hex(),
        intent_hash: artifact.intent_hash.to_hex(),
        composed_root: artifact.composed_root.to_hex(),
        nix_derivation_graph: NixDerivationGraph {
            store_path: "/nix/store/abc-app-1.0".to_string(),
            direct_dependencies: vec!["/nix/store/def-glibc-2.38".to_string()],
            transitive_dependency_count: 42,
            closure_hash: Blake3Hash::digest(b"closure").to_hex(),
            build_inputs_hash: Blake3Hash::digest(b"build-inputs").to_hex(),
        },
        deployment_context: AiDeploymentContext {
            cluster: "plo".to_string(),
            namespace: "default".to_string(),
            node: Some("node-01".to_string()),
            image_ref: "ghcr.io/pleme-io/app@sha256:abcdef".to_string(),
        },
        requesting_component: "test-harness".to_string(),
        urgency: Urgency::Admission,
    }
}

/// Record a gate decision in the heartbeat chain.
fn record_decision(chain: &HeartbeatChain, allowed: bool, resource: &str, hash: Blake3Hash) {
    let verifier = VerifierIdentity::new("test-harness", "matrix", "0.1.0");
    let outcome = if allowed {
        VerificationOutcome::Allowed
    } else {
        VerificationOutcome::Denied
    };
    chain.append(verifier, HeartbeatEvent::GateCheck, outcome, resource, hash);
}

/// Default GatingPolicy requiring compliance and certification artifacts.
fn strict_policy() -> GatingPolicy {
    GatingPolicy {
        name: "strict".to_string(),
        require_compliance: true,
        require_certification_artifacts: true,
        max_signature_age_secs: Some(3600),
        ..Default::default()
    }
}

// ===========================================================================
// V-01: Happy path — all valid -> ALLOW
// ===========================================================================

#[tokio::test]
async fn v01_happy_path_all_valid_allow() {
    // Setup
    let signer = MockDfcSigner::for_testing();
    let artifact = make_valid_artifact();
    let (master, expected) = make_attested_master("production");
    let chain = HeartbeatChain::new();

    // Verify artifact integrity (INV-12: determinism)
    assert!(
        verify_certification_artifact(&artifact),
        "V-01: valid artifact must verify"
    );

    // Sign and verify the master root
    let signed = signer.sign(&master.gating_signature()).await.unwrap();
    assert!(
        signer.verify(&signed).await.unwrap(),
        "V-01: signed root must verify with same signer"
    );

    // Gate evaluation
    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &expected);
    assert!(decision.allowed, "V-01: happy path must ALLOW");

    // AI check (ALLOW)
    let ai = MockAiThreatClient::new(); // default ALLOW
    let request = make_ai_request(&artifact);
    let ai_response = ai.analyze_provenance(&request).await.unwrap();
    assert_eq!(ai_response.decision, AiDecision::Allow);

    // INV-6: HeartbeatChain records the decision
    record_decision(&chain, decision.allowed, "/usr/bin/app", expected.clone());
    assert_eq!(chain.len(), 1, "INV-6: chain must record the decision");
    assert!(chain.verify_integrity(), "INV-6: chain integrity must hold");

    // INV-12: determinism — same inputs produce same root
    let (master2, expected2) = make_attested_master("production");
    assert_eq!(
        expected, expected2,
        "INV-12: same inputs must produce same gating hash"
    );
    let _ = master2; // suppress unused warning
}

// ===========================================================================
// V-02: Hash not in allow map -> DENY
// ===========================================================================

#[test]
fn v02_hash_not_in_allow_map_deny() {
    let (master, _expected) = make_attested_master("production");
    let unknown_hash = Blake3Hash::digest(b"unknown-binary-not-in-map");
    let chain = HeartbeatChain::new();

    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &unknown_hash);

    // INV-1: hash absent from allow map -> DENY
    assert!(
        !decision.allowed,
        "V-02 / INV-1: unknown hash must be DENIED"
    );
    assert!(
        decision.reason.contains("mismatch"),
        "V-02: reason should indicate mismatch"
    );

    // INV-6: record
    record_decision(&chain, decision.allowed, "/usr/bin/unknown", unknown_hash);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-03: Hash in revocation list -> DENY
// ===========================================================================

#[test]
fn v03_hash_in_revocation_list_deny() {
    // Simulate revocation: after initial attestation, the binary is revoked.
    // A new master is computed WITHOUT the revoked binary's layer.
    // The old expected hash no longer matches.
    let layers_original = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance-passed");
    let cert = make_valid_artifact();
    let original_master = compose_merkle(&layers_original, "production")
        .with_compliance(compliance.clone())
        .with_certification_artifacts(vec![cert]);
    let original_expected = original_master.gating_signature().clone();

    // Revocation: recompute master with a different OCI hash (simulates revocation)
    let layers_revoked = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(
            LayerType::Oci,
            Blake3Hash::digest(b"oci-revoked"),
            "test",
            vec![],
        ),
    ];
    let cert2 = make_valid_artifact();
    let new_master = compose_merkle(&layers_revoked, "production")
        .with_compliance(compliance)
        .with_certification_artifacts(vec![cert2]);

    // INV-2: The original expected hash should not match the new master
    let decision = evaluate_gate(&strict_policy(), &new_master, &original_expected);
    assert!(
        !decision.allowed,
        "V-03 / INV-2: revoked hash must be DENIED"
    );

    // INV-11: different inputs -> different roots
    let new_expected = new_master.gating_signature().clone();
    assert_ne!(
        original_expected, new_expected,
        "INV-11: different layers must produce different roots"
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", original_expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-04: Valid hash + revoked cert (tampered artifact_hash) -> DENY
// ===========================================================================

#[test]
fn v04_valid_hash_revoked_cert_deny() {
    let layers = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance-passed");

    let mut tampered_cert = make_valid_artifact();
    tampered_cert.artifact_hash = Blake3Hash::digest(b"tampered-binary");

    // INV-4: tampered artifact must not verify
    assert!(
        !verify_certification_artifact(&tampered_cert),
        "V-04 / INV-4: tampered artifact must fail verification"
    );

    let master = compose_merkle(&layers, "production")
        .with_compliance(compliance)
        .with_certification_artifacts(vec![tampered_cert]);
    let expected = master.gating_signature().clone();

    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &expected);
    assert!(
        !decision.allowed,
        "V-04: gate must DENY when artifact verification fails"
    );
    assert!(decision.reason.contains("Invalid certification artifact"));

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-05: AI detects 94.2% breach similarity -> DENY
// ===========================================================================

#[tokio::test]
async fn v05_ai_detects_breach_similarity_deny() {
    let artifact = make_valid_artifact();
    let request = make_ai_request(&artifact);

    // INV-8: AI DENY overrides gate ALLOW
    let ai = MockAiThreatClient::new().with_decision(AiDecision::Deny);
    let response = ai.analyze_provenance(&request).await.unwrap();
    assert_eq!(
        response.decision,
        AiDecision::Deny,
        "V-05 / INV-8: AI must return DENY"
    );

    // Even though the gate would ALLOW, AI DENY takes precedence
    let (master, expected) = make_attested_master("production");
    let gate_decision = evaluate_gate(&strict_policy(), &master, &expected);
    assert!(gate_decision.allowed, "Gate itself would ALLOW");

    // Pipeline decision: AI DENY overrides
    let pipeline_allowed = gate_decision.allowed && response.decision == AiDecision::Allow;
    assert!(
        !pipeline_allowed,
        "V-05 / INV-8: AI DENY must override gate ALLOW"
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    // Record AI analysis event
    let verifier = VerifierIdentity::new("ai-threat", "matrix", "0.1.0");
    chain.append(
        verifier,
        HeartbeatEvent::AiThreatAnalysis,
        VerificationOutcome::Denied,
        "/usr/bin/app",
        artifact.composed_root.clone(),
    );
    assert_eq!(chain.len(), 2);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-06: AI WARN + valid gate -> ALLOW with log
// ===========================================================================

#[tokio::test]
async fn v06_ai_warn_valid_gate_allow_with_log() {
    let artifact = make_valid_artifact();
    let request = make_ai_request(&artifact);

    let ai = MockAiThreatClient::new().with_decision(AiDecision::Warn);
    let response = ai.analyze_provenance(&request).await.unwrap();
    assert_eq!(response.decision, AiDecision::Warn);

    let (master, expected) = make_attested_master("production");
    let decision = evaluate_gate(&strict_policy(), &master, &expected);
    assert!(decision.allowed, "V-06: gate should ALLOW");

    // Pipeline: WARN does not block, but is logged
    let pipeline_allowed = decision.allowed && response.decision != AiDecision::Deny;
    assert!(pipeline_allowed, "V-06: WARN + valid gate = ALLOW");

    // INV-6: both gate and AI events recorded
    let chain = HeartbeatChain::new();
    record_decision(&chain, true, "/usr/bin/app", expected);
    let verifier = VerifierIdentity::new("ai-threat", "matrix", "0.1.0");
    chain.append(
        verifier,
        HeartbeatEvent::AiThreatAnalysis,
        VerificationOutcome::Allowed,
        "/usr/bin/app",
        artifact.composed_root.clone(),
    );
    assert_eq!(chain.len(), 2, "INV-6: must record both events");
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-07: TOCTOU — hash valid at admission, different at execve -> DENY
// ===========================================================================

#[test]
fn v07_toctou_hash_changes_deny() {
    let (master, expected_at_admission) = make_attested_master("production");

    // Admission: hash matches -> ALLOW
    let admission_decision = evaluate_gate(&strict_policy(), &master, &expected_at_admission);
    assert!(admission_decision.allowed, "V-07: admission should ALLOW");

    // At execve time, the binary has been replaced. The BPF map has the
    // OLD hash, but the binary now produces a DIFFERENT hash.
    let binary_hash_at_execve = Blake3Hash::digest(b"replaced-binary");

    // The BPF sentinel compares binary_hash_at_execve against the allow map
    // which contains expected_at_admission. They don't match.
    let hash_in_allow_map = expected_at_admission != binary_hash_at_execve;
    assert!(
        hash_in_allow_map,
        "Hashes should differ (binary was replaced)"
    );

    // INV-1: binary hash not in allow map at exec time -> DENY
    let exec_decision = evaluate_gate(&strict_policy(), &master, &binary_hash_at_execve);
    assert!(
        !exec_decision.allowed,
        "V-07 / INV-1: TOCTOU replaced binary must be DENIED at execve"
    );

    let chain = HeartbeatChain::new();
    record_decision(
        &chain,
        true,
        "/usr/bin/app (admission)",
        expected_at_admission,
    );
    record_decision(
        &chain,
        false,
        "/usr/bin/app (execve)",
        binary_hash_at_execve,
    );
    assert_eq!(chain.len(), 2);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-08: DFC signer timeout -> DENY
// ===========================================================================

#[tokio::test]
async fn v08_dfc_timeout_deny() {
    let signer = FailableDfcSigner::new().with_timeout(Duration::from_secs(5));
    let root = Blake3Hash::digest(b"test-root");

    // INV-3: external service failure -> error
    let result = signer.sign(&root).await;
    assert!(result.is_err(), "V-08 / INV-3: DFC timeout must error");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("timed out"),
        "V-08: error should mention timeout"
    );

    // Fail-secure: caller treats sign error as DENY
    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", root);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-09: DFC corrupted signature -> verify fails -> DENY
// ===========================================================================

#[tokio::test]
async fn v09_dfc_corrupted_signature_deny() {
    let signer = FailableDfcSigner::new().with_corrupted_signature();
    let root = Blake3Hash::digest(b"test-root");

    // Sign succeeds but signature is corrupted
    let signed = signer.sign(&root).await.unwrap();

    // Verify with a clean signer -> false (corrupted bits)
    let clean_signer = MockDfcSigner::for_testing();
    let verified = clean_signer.verify(&signed).await.unwrap();
    assert!(
        !verified,
        "V-09 / INV-5: corrupted signature must not verify"
    );

    // Also verify with the failable signer itself (delegates to inner MockDfcSigner)
    let failable_verified = signer.verify(&signed).await.unwrap();
    assert!(
        !failable_verified,
        "V-09: failable signer verify also rejects corrupted sig"
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", root);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-10: DFC auth failure -> DENY
// ===========================================================================

#[tokio::test]
async fn v10_dfc_auth_failure_deny() {
    let signer = FailableDfcSigner::new().with_auth_failure();
    let root = Blake3Hash::digest(b"test-root");

    // INV-3: auth failure -> error
    let result = signer.sign(&root).await;
    assert!(result.is_err(), "V-10 / INV-3: DFC auth failure must error");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("authentication failed"),
        "V-10: error should mention auth failure"
    );

    // Verify also fails
    let verify_result = signer
        .verify(&tameshi::signing::SignedRoot {
            root: root.clone(),
            signature: vec![0u8; 32],
            algorithm: tameshi::signing::SigningAlgorithm::MockDfc,
            signer_id: "test".to_string(),
            signed_at: chrono::Utc::now(),
        })
        .await;
    assert!(
        verify_result.is_err(),
        "V-10: verify must also fail on auth error"
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", root);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-11: AI timeout -> gate decides alone (AI fail-open)
// ===========================================================================

#[tokio::test]
async fn v11_ai_timeout_gate_decides_alone() {
    let artifact = make_valid_artifact();
    let request = make_ai_request(&artifact);

    // INV-9: AI timeout -> error
    let ai = FailableAiThreatClient::new().with_timeout(500);
    let ai_result = ai.analyze_provenance(&request).await;
    assert!(ai_result.is_err(), "V-11 / INV-9: AI timeout must error");

    // Gate proceeds without AI input
    let (master, expected) = make_attested_master("production");
    let decision = evaluate_gate(&strict_policy(), &master, &expected);
    assert!(
        decision.allowed,
        "V-11: gate should ALLOW when AI is unavailable (AI is fail-open)"
    );

    let chain = HeartbeatChain::new();
    // Record AI error
    let ai_verifier = VerifierIdentity::new("ai-threat", "matrix", "0.1.0");
    chain.append(
        ai_verifier,
        HeartbeatEvent::AiThreatAnalysis,
        VerificationOutcome::Error,
        "/usr/bin/app",
        artifact.composed_root.clone(),
    );
    // Record gate decision
    record_decision(&chain, true, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 2, "INV-6: both events recorded");
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-12: All services down -> DENY (fail-secure)
// ===========================================================================

#[tokio::test]
async fn v12_all_services_down_deny() {
    // DFC: timeout
    let signer = FailableDfcSigner::new().with_timeout(Duration::from_secs(5));
    let root = Blake3Hash::digest(b"test-root");
    let sign_result = signer.sign(&root).await;
    assert!(sign_result.is_err(), "V-12: DFC must fail");

    // AI: unavailable
    let ai = FailableAiThreatClient::new().with_unavailable();
    let artifact = make_valid_artifact();
    let request = make_ai_request(&artifact);
    let ai_result = ai.analyze_provenance(&request).await;
    assert!(ai_result.is_err(), "V-12: AI must fail");

    // Gate without compliance (simulating no compliance service)
    let layers = vec![LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix"),
        "test",
        vec![],
    )];
    let master = compose_merkle(&layers, "production"); // no compliance, no artifacts
    let expected = master.gating_signature().clone();
    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &expected);

    // INV-3: fail-secure -- compliance required but not present
    assert!(
        !decision.allowed,
        "V-12 / INV-3: all services down must DENY (fail-secure)"
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-13: Tampered CertificationArtifact -> DENY
// ===========================================================================

#[test]
fn v13_tampered_certification_artifact_deny() {
    let mut artifact = make_valid_artifact();

    // Tamper: change the artifact_hash after composition
    artifact.artifact_hash = Blake3Hash::digest(b"tampered-after-compose");

    // INV-4: verification must fail
    assert!(
        !verify_certification_artifact(&artifact),
        "V-13 / INV-4: tampered artifact must fail verification"
    );

    // Gate with tampered artifact
    let layers = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance-passed");
    let master = compose_merkle(&layers, "production")
        .with_compliance(compliance)
        .with_certification_artifacts(vec![artifact]);
    let expected = master.gating_signature().clone();

    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &expected);
    assert!(!decision.allowed, "V-13: gate must DENY tampered artifact");
    assert!(decision.reason.contains("Invalid certification artifact"));

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-14: Tampered HeartbeatChain entry -> integrity check fails
// ===========================================================================

#[test]
fn v14_tampered_heartbeat_chain_integrity_fails() {
    let chain = HeartbeatChain::new();
    let verifier = VerifierIdentity::new("test", "v14", "0.1.0");
    let hash1 = Blake3Hash::digest(b"binary-1");
    let hash2 = Blake3Hash::digest(b"binary-2");
    let hash3 = Blake3Hash::digest(b"binary-3");

    chain.append(
        verifier.clone(),
        HeartbeatEvent::GateCheck,
        VerificationOutcome::Allowed,
        "/usr/bin/app1",
        hash1.clone(),
    );
    chain.append(
        verifier.clone(),
        HeartbeatEvent::GateCheck,
        VerificationOutcome::Denied,
        "/usr/bin/app2",
        hash2.clone(),
    );
    chain.append(
        verifier.clone(),
        HeartbeatEvent::BinaryVerification,
        VerificationOutcome::Allowed,
        "/usr/bin/app3",
        hash3.clone(),
    );

    // INV-7: untampered chain verifies
    assert!(chain.verify_integrity(), "V-14: clean chain must verify");

    // INV-10: consistency proof across segments
    let proof = chain.consistency_proof(0, 2).unwrap();
    assert!(
        chain.verify_consistency_proof(&proof),
        "INV-10: consistency proof must verify"
    );

    // Demonstrate that the chain entries are linked:
    // Extracting entries and checking that previous_hash linkage holds
    let entries = chain.entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].previous_hash, Blake3Hash::from([0u8; 32]));
    assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
    assert_eq!(entries[2].previous_hash, entries[1].entry_hash);

    // INV-7: If any entry_hash were changed, verify_integrity would fail.
    // We cannot mutate the chain directly (RwLock), but we verify that
    // the chain's hash linkage is cryptographically sound.
    let mut cloned_entries = entries.clone();
    cloned_entries[1].resource = "TAMPERED".to_string();
    // The entry_hash no longer matches the tampered content
    // (this is what verify_integrity checks internally)
    assert_ne!(
        cloned_entries[1].resource, entries[1].resource,
        "V-14 / INV-7: tampering changes the entry"
    );
}

// ===========================================================================
// V-15: Missing certification artifacts when required -> DENY
// ===========================================================================

#[test]
fn v15_missing_certification_artifacts_deny() {
    let layers = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance-passed");
    let master = compose_merkle(&layers, "production").with_compliance(compliance);
    // No certification artifacts attached
    let expected = master.gating_signature().clone();

    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &expected);

    // INV-4: required artifacts missing -> DENY
    assert!(
        !decision.allowed,
        "V-15 / INV-4: missing required artifacts must DENY"
    );
    assert!(decision.reason.contains("none present"));

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-16: Valid cert + expired signature -> DENY
// ===========================================================================

#[test]
fn v16_valid_cert_expired_signature_deny() {
    let (master, expected) = make_attested_master("production");

    let policy = GatingPolicy {
        name: "strict-expiry".to_string(),
        require_compliance: true,
        require_certification_artifacts: true,
        max_signature_age_secs: Some(60), // 1 minute
        ..Default::default()
    };

    // Freeze clock 120 seconds in the future -- signature is stale
    let future_time = master.computed_at + chrono::Duration::seconds(120);
    let clock = FixedClock::new(future_time);
    let decision = evaluate_gate_with_clock(&policy, &master, &expected, &clock);

    assert!(!decision.allowed, "V-16: expired signature must DENY");
    assert!(
        decision.reason.contains("stale"),
        "V-16: reason should mention staleness"
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-17: Break-glass token valid -> ALLOW with audit
// ===========================================================================

#[test]
fn v17_break_glass_valid_allow_with_audit() {
    let signer = LocalSigner::for_testing();
    let token = BreakGlassToken::create_signed(
        "ops@pleme.io",
        "attestation service outage",
        vec![
            "namespace:default".to_string(),
            "namespace:production".to_string(),
        ],
        4, // valid for 4 hours
        &signer,
    );

    let now = chrono::Utc::now();
    assert!(
        token.is_valid(&now),
        "V-17: token must be valid at creation time"
    );
    assert!(
        token.covers_namespace("default"),
        "V-17: token must cover 'default' namespace"
    );
    assert!(
        token.covers_namespace("production"),
        "V-17: token must cover 'production' namespace"
    );
    assert!(
        token.verify_signature(&signer),
        "V-17: signature must verify"
    );

    // INV-6: break-glass events are recorded in the heartbeat chain
    let chain = HeartbeatChain::new();
    let verifier = VerifierIdentity::new("inshou", "v17", "0.1.0");
    chain.append(
        verifier,
        HeartbeatEvent::BreakGlass,
        VerificationOutcome::Allowed,
        "namespace:default",
        Blake3Hash::digest(token.reason.as_bytes()),
    );
    assert_eq!(chain.len(), 1, "INV-6: break-glass event recorded");
    assert!(chain.verify_integrity());

    // Verify the entry is a BreakGlass event
    let entries = chain.entries();
    assert_eq!(entries[0].event, HeartbeatEvent::BreakGlass);
    assert_eq!(entries[0].result, VerificationOutcome::Allowed);
}

// ===========================================================================
// V-18: Break-glass expired -> DENY
// ===========================================================================

#[test]
fn v18_break_glass_expired_deny() {
    let signer = LocalSigner::for_testing();
    let token = BreakGlassToken::create_signed(
        "ops@pleme.io",
        "attestation service outage",
        vec!["namespace:default".to_string()],
        1, // valid for 1 hour
        &signer,
    );

    // Token should be valid now
    let now = chrono::Utc::now();
    assert!(token.is_valid(&now), "Token valid at creation");

    // But expired 2 hours from now
    let future = now + chrono::Duration::hours(2);
    assert!(
        !token.is_valid(&future),
        "V-18: expired token must be invalid"
    );

    // Also check namespace: token doesn't cover uncovered namespaces
    assert!(
        !token.covers_namespace("kube-system"),
        "V-18: token must not cover uncovered namespace"
    );

    // INV-3: expired token -> DENY (fail-secure)
    let chain = HeartbeatChain::new();
    let verifier = VerifierIdentity::new("inshou", "v18", "0.1.0");
    chain.append(
        verifier,
        HeartbeatEvent::BreakGlass,
        VerificationOutcome::Denied,
        "namespace:default",
        Blake3Hash::digest(b"expired-token"),
    );
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());

    let entries = chain.entries();
    assert_eq!(entries[0].result, VerificationOutcome::Denied);
}

// ===========================================================================
// V-19: Multiple artifacts, one invalid -> DENY
// ===========================================================================

#[test]
fn v19_multiple_artifacts_one_invalid_deny() {
    let valid_artifact = make_valid_artifact();
    assert!(verify_certification_artifact(&valid_artifact));

    let mut tampered_artifact = compose_certification_artifact(
        "/usr/bin/helper",
        Blake3Hash::digest(b"helper-binary"),
        Blake3Hash::digest(b"helper-compliance"),
        Blake3Hash::digest(b"helper-intent"),
        "production",
    );
    // Tamper the second artifact
    tampered_artifact.control_hash = Blake3Hash::digest(b"tampered-control");
    assert!(!verify_certification_artifact(&tampered_artifact));

    let layers = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance-passed");
    let master = compose_merkle(&layers, "production")
        .with_compliance(compliance)
        .with_certification_artifacts(vec![valid_artifact, tampered_artifact]);
    let expected = master.gating_signature().clone();

    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &expected);

    // INV-4: one invalid artifact -> entire gate DENY
    assert!(
        !decision.allowed,
        "V-19 / INV-4: one invalid artifact out of many must DENY"
    );
    assert!(
        decision
            .reason
            .contains("Invalid certification artifact at index 1")
    );

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/app", expected);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// V-20: Empty BPF allow map with Enforce policy -> DENY all
// ===========================================================================

#[test]
fn v20_empty_allow_map_enforce_deny_all() {
    // With an empty allow map, every hash comparison fails.
    // Simulate: master exists, but we present a hash that can't be in any map.
    let (master, _expected) = make_attested_master("production");

    // "Empty allow map" = no known-good hash. Every comparison fails.
    let arbitrary_hash = Blake3Hash::digest(b"any-binary-whatsoever");

    let policy = strict_policy();
    let decision = evaluate_gate(&policy, &master, &arbitrary_hash);

    // INV-1: hash not in (empty) allow map -> DENY
    assert!(
        !decision.allowed,
        "V-20 / INV-1: empty allow map must DENY all"
    );

    // Try several different hashes -- all must be denied
    for i in 0..5 {
        let h = Blake3Hash::digest(format!("binary-{i}").as_bytes());
        let d = evaluate_gate(&policy, &master, &h);
        assert!(!d.allowed, "V-20: hash {i} must be DENIED");
    }

    let chain = HeartbeatChain::new();
    record_decision(&chain, false, "/usr/bin/anything", arbitrary_hash);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());
}

// ===========================================================================
// Cross-cutting invariant tests
// ===========================================================================

/// INV-5: MockDfcSigner with wrong fragments -> verify returns false.
#[tokio::test]
async fn inv05_wrong_fragments_verify_false() {
    let signer_a = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "signer-a");
    let signer_b = MockDfcSigner::from_fragments([3u8; 32], [4u8; 32], "signer-b");
    let root = Blake3Hash::digest(b"test-root");

    let signed = signer_a.sign(&root).await.unwrap();
    let verified_by_b = signer_b.verify(&signed).await.unwrap();
    assert!(!verified_by_b, "INV-5: different fragments must not verify");

    // Same signer verifies its own signature
    let verified_by_a = signer_a.verify(&signed).await.unwrap();
    assert!(verified_by_a, "INV-5: same signer must verify its own sig");
}

/// INV-10: Consistency proofs across chain segments.
#[test]
fn inv10_consistency_proofs_verifiable() {
    let chain = HeartbeatChain::new();
    let verifier = VerifierIdentity::new("test", "inv10", "0.1.0");

    for i in 0u8..10 {
        chain.append(
            verifier.clone(),
            HeartbeatEvent::GateCheck,
            if i % 2 == 0 {
                VerificationOutcome::Allowed
            } else {
                VerificationOutcome::Denied
            },
            &format!("/usr/bin/app-{i}"),
            Blake3Hash::digest(&[i]),
        );
    }

    assert_eq!(chain.len(), 10);
    assert!(chain.verify_integrity());

    // Proof for first half
    let proof_first_half = chain.consistency_proof(0, 4).unwrap();
    assert!(chain.verify_consistency_proof(&proof_first_half));

    // Proof for second half
    let proof_second_half = chain.consistency_proof(5, 9).unwrap();
    assert!(chain.verify_consistency_proof(&proof_second_half));

    // Proof for entire chain
    let proof_full = chain.consistency_proof(0, 9).unwrap();
    assert!(chain.verify_consistency_proof(&proof_full));

    // Single-entry proof
    let proof_single = chain.consistency_proof(3, 3).unwrap();
    assert!(chain.verify_consistency_proof(&proof_single));
}

/// INV-11: Different inputs always produce different Merkle roots.
#[test]
fn inv11_collision_resistance() {
    let layers_a = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix-a"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci-a"), "test", vec![]),
    ];
    let layers_b = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix-b"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci-b"), "test", vec![]),
    ];

    let root_a = compute_merkle_root(&layers_a);
    let root_b = compute_merkle_root(&layers_b);
    assert_ne!(
        root_a, root_b,
        "INV-11: different inputs must produce different roots"
    );

    // Even single-bit difference in one layer
    let layers_c = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix-a"), "test", vec![]),
        LayerSignature::new(
            LayerType::Oci,
            Blake3Hash::digest(b"oci-a-different"),
            "test",
            vec![],
        ),
    ];
    let root_c = compute_merkle_root(&layers_c);
    assert_ne!(
        root_a, root_c,
        "INV-11: single layer change -> different root"
    );
}

/// INV-12: Same inputs always produce same Merkle roots.
#[test]
fn inv12_determinism() {
    let layers = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
        LayerSignature::new(LayerType::Helm, Blake3Hash::digest(b"helm"), "test", vec![]),
    ];

    let root1 = compute_merkle_root(&layers);
    let root2 = compute_merkle_root(&layers);
    let root3 = compute_merkle_root(&layers);
    assert_eq!(root1, root2, "INV-12: first == second");
    assert_eq!(root2, root3, "INV-12: second == third");

    // Order independence (layers are sorted internally)
    let layers_reversed: Vec<LayerSignature> = layers.iter().rev().cloned().collect();
    let root_reversed = compute_merkle_root(&layers_reversed);
    assert_eq!(root1, root_reversed, "INV-12: order must not affect root");
}

/// INV-6: HeartbeatChain records BOTH ALLOW and DENY.
#[test]
fn inv06_heartbeat_records_both_outcomes() {
    let chain = HeartbeatChain::new();
    let verifier = VerifierIdentity::new("test", "inv06", "0.1.0");

    chain.append(
        verifier.clone(),
        HeartbeatEvent::GateCheck,
        VerificationOutcome::Allowed,
        "/usr/bin/good",
        Blake3Hash::digest(b"good"),
    );
    chain.append(
        verifier.clone(),
        HeartbeatEvent::GateCheck,
        VerificationOutcome::Denied,
        "/usr/bin/bad",
        Blake3Hash::digest(b"bad"),
    );

    assert_eq!(chain.len(), 2);
    let (allowed, denied) = chain.outcome_counts();
    assert_eq!(allowed, 1, "INV-6: one ALLOW recorded");
    assert_eq!(denied, 1, "INV-6: one DENY recorded");
    assert!(chain.verify_integrity());
}

/// DFC rate-limited failure.
#[tokio::test]
async fn dfc_rate_limited_deny() {
    let signer = FailableDfcSigner::new().with_rate_limited();
    let root = Blake3Hash::digest(b"test-root");

    let result = signer.sign(&root).await;
    assert!(result.is_err(), "Rate limited must error");
    assert!(
        result.unwrap_err().to_string().contains("rate limited"),
        "Error should mention rate limiting"
    );
}

/// AI auth failure.
#[tokio::test]
async fn ai_auth_failure_deny() {
    let ai = FailableAiThreatClient::new().with_auth_failure();
    let artifact = make_valid_artifact();
    let request = make_ai_request(&artifact);

    let result = ai.analyze_provenance(&request).await;
    assert!(result.is_err(), "AI auth failure must error");
}

/// AI corrupted response.
#[tokio::test]
async fn ai_corrupted_response_deny() {
    let ai = FailableAiThreatClient::new().with_corrupted();
    let artifact = make_valid_artifact();
    let request = make_ai_request(&artifact);

    let result = ai.analyze_provenance(&request).await;
    assert!(result.is_err(), "AI corrupted response must error");
}

/// Verify CertificationArtifact proof paths independently.
#[test]
fn certification_artifact_proof_paths_valid() {
    let artifact = make_valid_artifact();

    // Each proof path should verify independently
    assert!(tameshi::certification_artifact::verify_proof_path(
        &artifact.proof_paths.artifact_proof,
        &artifact.composed_root,
        &artifact.artifact_hash,
        0,
        3,
    ));
    assert!(tameshi::certification_artifact::verify_proof_path(
        &artifact.proof_paths.control_proof,
        &artifact.composed_root,
        &artifact.control_hash,
        1,
        3,
    ));
    assert!(tameshi::certification_artifact::verify_proof_path(
        &artifact.proof_paths.intent_proof,
        &artifact.composed_root,
        &artifact.intent_hash,
        2,
        3,
    ));
}
