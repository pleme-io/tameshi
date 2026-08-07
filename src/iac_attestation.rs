//! IaC test attestation types.
//!
//! Provides types for recording IaC test pipeline results into the
//! [`HeartbeatChain`](crate::heartbeat::HeartbeatChain) and computing
//! attestation hashes. The iac-test-runner consumes these types to
//! emit phase-level and suite-level attestation events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// Result of a single IaC test phase.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IacTestPhaseResult {
    /// Phase name (init, apply, verify, teardown).
    pub phase: IacTestPhase,
    /// Whether the phase succeeded.
    pub success: bool,
    /// BLAKE3 hash of the phase output/artifacts.
    pub output_hash: Blake3Hash,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// When the phase completed.
    pub completed_at: DateTime<Utc>,
    /// Human-readable details.
    pub details: String,
}

/// IaC test pipeline phases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IacTestPhase {
    /// Infrastructure initialization (provider setup, state init).
    Init,
    /// Infrastructure apply (create/update resources).
    Apply,
    /// Verification (InSpec profiles, compliance checks).
    Verify,
    /// Infrastructure teardown (destroy resources).
    Teardown,
}

impl std::fmt::Display for IacTestPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "init"),
            Self::Apply => write!(f, "apply"),
            Self::Verify => write!(f, "verify"),
            Self::Teardown => write!(f, "teardown"),
        }
    }
}

/// Complete IaC test suite report.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IacTestSuiteReport {
    /// Name of the test suite.
    pub suite_name: String,
    /// Platform used (terraform, pulumi, pangea, crossplane, ansible).
    pub platform: String,
    /// Environment tested.
    pub environment: String,
    /// Results per phase.
    pub phases: Vec<IacTestPhaseResult>,
    /// Whether all phases passed.
    pub all_passed: bool,
    /// Composite BLAKE3 hash of all phase hashes.
    pub suite_hash: Blake3Hash,
    /// When the suite completed.
    pub completed_at: DateTime<Utc>,
}

impl IacTestSuiteReport {
    /// Compute the composite suite hash from all phase hashes.
    #[must_use]
    pub fn compute_suite_hash(phases: &[IacTestPhaseResult]) -> Blake3Hash {
        let mut data = Vec::with_capacity(phases.len() * 32);
        for phase in phases {
            data.extend_from_slice(&phase.output_hash.0);
        }
        Blake3Hash::digest(&data)
    }

    /// Build a suite report from phase results.
    #[must_use]
    pub fn from_phases(
        suite_name: &str,
        platform: &str,
        environment: &str,
        phases: Vec<IacTestPhaseResult>,
    ) -> Self {
        let all_passed = phases.iter().all(|p| p.success);
        let suite_hash = Self::compute_suite_hash(&phases);
        Self {
            suite_name: suite_name.to_string(),
            platform: platform.to_string(),
            environment: environment.to_string(),
            phases,
            all_passed,
            suite_hash,
            completed_at: Utc::now(),
        }
    }

    /// Check if the verify phase passed (the compliance-critical phase).
    #[must_use]
    pub fn verify_passed(&self) -> bool {
        self.phases
            .iter()
            .any(|p| p.phase == IacTestPhase::Verify && p.success)
    }

    /// Get the verify phase result if present.
    #[must_use]
    pub fn verify_result(&self) -> Option<&IacTestPhaseResult> {
        self.phases.iter().find(|p| p.phase == IacTestPhase::Verify)
    }
}

/// Trait for emitting IaC test attestation events.
///
/// Implementations record test results into the
/// [`HeartbeatChain`](crate::heartbeat::HeartbeatChain) and optionally
/// emit to external stores (S3, etc.).
pub trait IacTestAttester: Send + Sync {
    /// Record a phase completion.
    fn attest_phase(&self, result: &IacTestPhaseResult) -> crate::error::Result<()>;

    /// Record a complete suite and return the suite hash.
    fn attest_suite(&self, report: &IacTestSuiteReport) -> crate::error::Result<Blake3Hash>;
}

/// Mock IaC test attester for testing.
pub struct MockIacTestAttester {
    phases: std::sync::Mutex<Vec<IacTestPhaseResult>>,
    suites: std::sync::Mutex<Vec<IacTestSuiteReport>>,
}

impl MockIacTestAttester {
    /// Create a new empty mock attester.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phases: std::sync::Mutex::new(Vec::new()),
            suites: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Return the number of recorded phase attestations.
    #[must_use]
    pub fn phase_count(&self) -> usize {
        self.phases.lock().expect("lock poisoned").len()
    }

    /// Return the number of recorded suite attestations.
    #[must_use]
    pub fn suite_count(&self) -> usize {
        self.suites.lock().expect("lock poisoned").len()
    }

    /// Return the last recorded suite report, if any.
    #[must_use]
    pub fn last_suite(&self) -> Option<IacTestSuiteReport> {
        self.suites.lock().expect("lock poisoned").last().cloned()
    }

    /// Return all recorded phase results.
    #[must_use]
    pub fn recorded_phases(&self) -> Vec<IacTestPhaseResult> {
        self.phases.lock().expect("lock poisoned").clone()
    }
}

impl Default for MockIacTestAttester {
    fn default() -> Self {
        Self::new()
    }
}

impl IacTestAttester for MockIacTestAttester {
    fn attest_phase(&self, result: &IacTestPhaseResult) -> crate::error::Result<()> {
        self.phases
            .lock()
            .expect("lock poisoned")
            .push(result.clone());
        Ok(())
    }

    fn attest_suite(&self, report: &IacTestSuiteReport) -> crate::error::Result<Blake3Hash> {
        let hash = report.suite_hash.clone();
        self.suites
            .lock()
            .expect("lock poisoned")
            .push(report.clone());
        Ok(hash)
    }
}

// =============================================================================
// Helper: build a test phase result with sensible defaults.
// =============================================================================

/// Build a phase result for testing.
#[cfg(test)]
fn make_phase(phase: IacTestPhase, success: bool, data: &[u8]) -> IacTestPhaseResult {
    IacTestPhaseResult {
        phase,
        success,
        output_hash: Blake3Hash::digest(data),
        duration_ms: 1234,
        completed_at: Utc::now(),
        details: format!("phase completed (success={success})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // 1-5: IacTestPhaseResult serde / variants / success-failure
    // =========================================================================

    #[test]
    fn phase_result_serde_roundtrip() {
        let result = make_phase(IacTestPhase::Init, true, b"init-output");
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: IacTestPhaseResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.phase, IacTestPhase::Init);
        assert!(deserialized.success);
        assert_eq!(deserialized.output_hash, result.output_hash);
    }

    #[test]
    fn phase_result_all_variants_serialize() {
        for phase in [
            IacTestPhase::Init,
            IacTestPhase::Apply,
            IacTestPhase::Verify,
            IacTestPhase::Teardown,
        ] {
            let result = make_phase(phase.clone(), true, b"data");
            let json = serde_json::to_string(&result).unwrap();
            let deserialized: IacTestPhaseResult = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.phase, phase);
        }
    }

    #[test]
    fn phase_result_success_flag() {
        let success = make_phase(IacTestPhase::Apply, true, b"ok");
        assert!(success.success);
    }

    #[test]
    fn phase_result_failure_flag() {
        let failure = make_phase(IacTestPhase::Verify, false, b"fail");
        assert!(!failure.success);
    }

    #[test]
    fn phase_result_output_hash_differs_by_data() {
        let r1 = make_phase(IacTestPhase::Init, true, b"data-a");
        let r2 = make_phase(IacTestPhase::Init, true, b"data-b");
        assert_ne!(r1.output_hash, r2.output_hash);
    }

    // =========================================================================
    // 6-10: IacTestSuiteReport::from_phases, all_passed
    // =========================================================================

    #[test]
    fn suite_report_from_phases_all_pass() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"init"),
            make_phase(IacTestPhase::Apply, true, b"apply"),
            make_phase(IacTestPhase::Verify, true, b"verify"),
            make_phase(IacTestPhase::Teardown, true, b"teardown"),
        ];
        let report = IacTestSuiteReport::from_phases("suite-1", "terraform", "staging", phases);
        assert!(report.all_passed);
        assert_eq!(report.suite_name, "suite-1");
        assert_eq!(report.platform, "terraform");
        assert_eq!(report.environment, "staging");
    }

    #[test]
    fn suite_report_from_phases_one_fails() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"init"),
            make_phase(IacTestPhase::Apply, false, b"apply-fail"),
            make_phase(IacTestPhase::Verify, true, b"verify"),
            make_phase(IacTestPhase::Teardown, true, b"teardown"),
        ];
        let report = IacTestSuiteReport::from_phases("suite-2", "pulumi", "prod", phases);
        assert!(!report.all_passed);
    }

    #[test]
    fn suite_report_all_fail() {
        let phases = vec![
            make_phase(IacTestPhase::Init, false, b"f1"),
            make_phase(IacTestPhase::Apply, false, b"f2"),
        ];
        let report = IacTestSuiteReport::from_phases("suite-3", "crossplane", "dev", phases);
        assert!(!report.all_passed);
    }

    #[test]
    fn suite_report_has_four_phases() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"a"),
            make_phase(IacTestPhase::Apply, true, b"b"),
            make_phase(IacTestPhase::Verify, true, b"c"),
            make_phase(IacTestPhase::Teardown, true, b"d"),
        ];
        let report = IacTestSuiteReport::from_phases("suite-4", "ansible", "qa", phases);
        assert_eq!(report.phases.len(), 4);
    }

    #[test]
    fn suite_report_serde_roundtrip() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"init"),
            make_phase(IacTestPhase::Verify, true, b"verify"),
        ];
        let report = IacTestSuiteReport::from_phases("serde-suite", "pangea", "staging", phases);
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: IacTestSuiteReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.suite_name, "serde-suite");
        assert_eq!(deserialized.suite_hash, report.suite_hash);
        assert!(deserialized.all_passed);
    }

    // =========================================================================
    // 11-15: compute_suite_hash determinism, different phases, empty
    // =========================================================================

    #[test]
    fn compute_suite_hash_deterministic() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"x"),
            make_phase(IacTestPhase::Apply, true, b"y"),
        ];
        let h1 = IacTestSuiteReport::compute_suite_hash(&phases);
        let h2 = IacTestSuiteReport::compute_suite_hash(&phases);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_suite_hash_different_phases_differ() {
        let phases_a = vec![
            make_phase(IacTestPhase::Init, true, b"aaa"),
            make_phase(IacTestPhase::Apply, true, b"bbb"),
        ];
        let phases_b = vec![
            make_phase(IacTestPhase::Init, true, b"ccc"),
            make_phase(IacTestPhase::Apply, true, b"ddd"),
        ];
        let h1 = IacTestSuiteReport::compute_suite_hash(&phases_a);
        let h2 = IacTestSuiteReport::compute_suite_hash(&phases_b);
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_suite_hash_empty_phases() {
        let h = IacTestSuiteReport::compute_suite_hash(&[]);
        // Hashing empty data should still produce a valid hash.
        assert_ne!(h, Blake3Hash([0u8; 32]));
    }

    #[test]
    fn compute_suite_hash_order_matters() {
        let p1 = make_phase(IacTestPhase::Init, true, b"first");
        let p2 = make_phase(IacTestPhase::Apply, true, b"second");
        let h_ab = IacTestSuiteReport::compute_suite_hash(&[p1.clone(), p2.clone()]);
        let h_ba = IacTestSuiteReport::compute_suite_hash(&[p2, p1]);
        assert_ne!(h_ab, h_ba, "phase order must affect suite hash");
    }

    #[test]
    fn compute_suite_hash_matches_from_phases() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"m1"),
            make_phase(IacTestPhase::Verify, true, b"m2"),
        ];
        let manual_hash = IacTestSuiteReport::compute_suite_hash(&phases);
        let report = IacTestSuiteReport::from_phases("match", "terraform", "prod", phases);
        assert_eq!(report.suite_hash, manual_hash);
    }

    // =========================================================================
    // 16-20: verify_passed, verify_result, no verify phase
    // =========================================================================

    #[test]
    fn verify_passed_when_verify_succeeds() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"i"),
            make_phase(IacTestPhase::Verify, true, b"v"),
        ];
        let report = IacTestSuiteReport::from_phases("vp", "terraform", "prod", phases);
        assert!(report.verify_passed());
    }

    #[test]
    fn verify_passed_when_verify_fails() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"i"),
            make_phase(IacTestPhase::Verify, false, b"v-fail"),
        ];
        let report = IacTestSuiteReport::from_phases("vf", "terraform", "prod", phases);
        assert!(!report.verify_passed());
    }

    #[test]
    fn verify_passed_when_no_verify_phase() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"i"),
            make_phase(IacTestPhase::Apply, true, b"a"),
        ];
        let report = IacTestSuiteReport::from_phases("nv", "pangea", "staging", phases);
        assert!(!report.verify_passed());
    }

    #[test]
    fn verify_result_present() {
        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"i"),
            make_phase(IacTestPhase::Verify, true, b"v"),
        ];
        let report = IacTestSuiteReport::from_phases("vr", "crossplane", "dev", phases);
        let result = report.verify_result();
        assert!(result.is_some());
        assert_eq!(result.unwrap().phase, IacTestPhase::Verify);
    }

    #[test]
    fn verify_result_absent() {
        let phases = vec![make_phase(IacTestPhase::Init, true, b"i")];
        let report = IacTestSuiteReport::from_phases("vra", "ansible", "dev", phases);
        assert!(report.verify_result().is_none());
    }

    // =========================================================================
    // 21-25: MockIacTestAttester
    // =========================================================================

    #[test]
    fn mock_attester_records_phases() {
        let attester = MockIacTestAttester::new();
        let phase = make_phase(IacTestPhase::Init, true, b"mock-init");
        attester.attest_phase(&phase).unwrap();
        assert_eq!(attester.phase_count(), 1);
    }

    #[test]
    fn mock_attester_records_suites() {
        let attester = MockIacTestAttester::new();
        let phases = vec![make_phase(IacTestPhase::Verify, true, b"s1")];
        let report = IacTestSuiteReport::from_phases("mock-suite", "terraform", "prod", phases);
        let hash = attester.attest_suite(&report).unwrap();
        assert_eq!(hash, report.suite_hash);
        assert_eq!(attester.suite_count(), 1);
    }

    #[test]
    fn mock_attester_counts() {
        let attester = MockIacTestAttester::new();
        assert_eq!(attester.phase_count(), 0);
        assert_eq!(attester.suite_count(), 0);
        attester
            .attest_phase(&make_phase(IacTestPhase::Apply, true, b"a"))
            .unwrap();
        attester
            .attest_phase(&make_phase(IacTestPhase::Teardown, true, b"t"))
            .unwrap();
        assert_eq!(attester.phase_count(), 2);
    }

    #[test]
    fn mock_attester_last_suite() {
        let attester = MockIacTestAttester::new();
        assert!(attester.last_suite().is_none());
        let r1 = IacTestSuiteReport::from_phases(
            "first",
            "terraform",
            "dev",
            vec![make_phase(IacTestPhase::Init, true, b"f1")],
        );
        let r2 = IacTestSuiteReport::from_phases(
            "second",
            "pulumi",
            "staging",
            vec![make_phase(IacTestPhase::Init, true, b"f2")],
        );
        attester.attest_suite(&r1).unwrap();
        attester.attest_suite(&r2).unwrap();
        let last = attester.last_suite().unwrap();
        assert_eq!(last.suite_name, "second");
    }

    #[test]
    fn mock_attester_default() {
        let attester = MockIacTestAttester::default();
        assert_eq!(attester.phase_count(), 0);
        assert_eq!(attester.suite_count(), 0);
    }

    // =========================================================================
    // 26-30: IacTestPhase serde, Display, PartialEq
    // =========================================================================

    #[test]
    fn iac_test_phase_serde_roundtrip() {
        for phase in [
            IacTestPhase::Init,
            IacTestPhase::Apply,
            IacTestPhase::Verify,
            IacTestPhase::Teardown,
        ] {
            let json = serde_json::to_string(&phase).unwrap();
            let deserialized: IacTestPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, phase);
        }
    }

    #[test]
    fn iac_test_phase_display() {
        assert_eq!(IacTestPhase::Init.to_string(), "init");
        assert_eq!(IacTestPhase::Apply.to_string(), "apply");
        assert_eq!(IacTestPhase::Verify.to_string(), "verify");
        assert_eq!(IacTestPhase::Teardown.to_string(), "teardown");
    }

    #[test]
    fn iac_test_phase_partial_eq() {
        assert_eq!(IacTestPhase::Init, IacTestPhase::Init);
        assert_ne!(IacTestPhase::Init, IacTestPhase::Apply);
        assert_ne!(IacTestPhase::Verify, IacTestPhase::Teardown);
    }

    #[test]
    fn iac_test_phase_serde_snake_case() {
        let json = serde_json::to_string(&IacTestPhase::Teardown).unwrap();
        assert_eq!(json, "\"teardown\"");
        let json = serde_json::to_string(&IacTestPhase::Verify).unwrap();
        assert_eq!(json, "\"verify\"");
    }

    #[test]
    fn iac_test_phase_clone() {
        let phase = IacTestPhase::Apply;
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    // =========================================================================
    // 31-35: Integration tests
    // =========================================================================

    #[test]
    fn suite_hash_as_certification_control_hash() {
        // The suite_hash can be fed into compose_certification_artifact
        // as the control_hash (kensa compliance input).
        use crate::certification_artifact::compose_certification_artifact;

        let phases = vec![
            make_phase(IacTestPhase::Init, true, b"ci-init"),
            make_phase(IacTestPhase::Apply, true, b"ci-apply"),
            make_phase(IacTestPhase::Verify, true, b"ci-verify"),
            make_phase(IacTestPhase::Teardown, true, b"ci-teardown"),
        ];
        let report = IacTestSuiteReport::from_phases("integration", "terraform", "prod", phases);

        let artifact = compose_certification_artifact(
            "/usr/bin/iac-test-runner",
            Blake3Hash::digest(b"nix-closure"),
            report.suite_hash.clone(), // suite hash as control_hash
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );

        assert!(crate::certification_artifact::verify_certification_artifact(&artifact));
        // The control_hash in the artifact should match the suite_hash.
        assert_eq!(artifact.control_hash, report.suite_hash);
    }

    #[test]
    fn heartbeat_event_iac_variants_display() {
        use crate::heartbeat::HeartbeatEvent;
        assert_eq!(HeartbeatEvent::IacTestInit.to_string(), "iac_test_init");
        assert_eq!(HeartbeatEvent::IacTestApply.to_string(), "iac_test_apply");
        assert_eq!(HeartbeatEvent::IacTestVerify.to_string(), "iac_test_verify");
        assert_eq!(
            HeartbeatEvent::IacTestTeardown.to_string(),
            "iac_test_teardown"
        );
        assert_eq!(
            HeartbeatEvent::IacTestSuiteComplete.to_string(),
            "iac_test_suite_complete"
        );
    }

    #[test]
    fn heartbeat_event_iac_variants_serde_roundtrip() {
        use crate::heartbeat::HeartbeatEvent;
        for event in [
            HeartbeatEvent::IacTestInit,
            HeartbeatEvent::IacTestApply,
            HeartbeatEvent::IacTestVerify,
            HeartbeatEvent::IacTestTeardown,
            HeartbeatEvent::IacTestSuiteComplete,
        ] {
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: HeartbeatEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, event);
        }
    }

    #[test]
    fn heartbeat_chain_accepts_iac_events() {
        use crate::heartbeat::{
            HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity,
        };

        let chain = HeartbeatChain::new();
        let verifier = VerifierIdentity::new("iac-test-runner", "runner-pod-1", "0.1.0");

        chain.append(
            verifier.clone(),
            HeartbeatEvent::IacTestInit,
            VerificationOutcome::Allowed,
            "test-suite/init",
            Blake3Hash::digest(b"init-sig"),
        );
        chain.append(
            verifier.clone(),
            HeartbeatEvent::IacTestApply,
            VerificationOutcome::Allowed,
            "test-suite/apply",
            Blake3Hash::digest(b"apply-sig"),
        );
        chain.append(
            verifier.clone(),
            HeartbeatEvent::IacTestVerify,
            VerificationOutcome::Allowed,
            "test-suite/verify",
            Blake3Hash::digest(b"verify-sig"),
        );
        chain.append(
            verifier.clone(),
            HeartbeatEvent::IacTestTeardown,
            VerificationOutcome::Allowed,
            "test-suite/teardown",
            Blake3Hash::digest(b"teardown-sig"),
        );
        chain.append(
            verifier,
            HeartbeatEvent::IacTestSuiteComplete,
            VerificationOutcome::Allowed,
            "test-suite/complete",
            Blake3Hash::digest(b"suite-sig"),
        );

        assert_eq!(chain.len(), 5);
        assert!(chain.verify_integrity());

        // Filter by event type
        let init_entries = chain.entries_by_event(&HeartbeatEvent::IacTestInit);
        assert_eq!(init_entries.len(), 1);
        let complete_entries = chain.entries_by_event(&HeartbeatEvent::IacTestSuiteComplete);
        assert_eq!(complete_entries.len(), 1);
    }

    #[test]
    fn mock_attester_recorded_phases_returns_all() {
        let attester = MockIacTestAttester::new();
        let p1 = make_phase(IacTestPhase::Init, true, b"r1");
        let p2 = make_phase(IacTestPhase::Apply, false, b"r2");
        attester.attest_phase(&p1).unwrap();
        attester.attest_phase(&p2).unwrap();
        let recorded = attester.recorded_phases();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].phase, IacTestPhase::Init);
        assert_eq!(recorded[1].phase, IacTestPhase::Apply);
        assert!(recorded[0].success);
        assert!(!recorded[1].success);
    }
}
