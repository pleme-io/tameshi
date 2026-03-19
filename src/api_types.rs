//! Shared API request/response types.
//!
//! Used by sekiban (K8s controller), kensa (compliance service), and inshou (Nix gate)
//! for inter-service communication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::signature::{LayerType, MasterSignature};

/// Request to compute a master signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeSignatureRequest {
    /// Which layers to collect and hash.
    pub layers: Vec<LayerType>,
    /// Environment identifier.
    pub environment: String,
    /// Whether to include compliance hash.
    pub include_compliance: bool,
}

/// Response from a signature computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeSignatureResponse {
    /// The computed master signature.
    pub signature: MasterSignature,
    /// Duration of computation in milliseconds.
    pub duration_ms: u64,
}

/// Request to verify a signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifySignatureRequest {
    /// Expected signature (prefixed, e.g., "blake3:abc123...").
    pub expected: String,
    /// Environment to verify.
    pub environment: String,
    /// Which layers to verify (empty = all).
    #[serde(default)]
    pub layers: Vec<LayerType>,
}

/// Response from a signature verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifySignatureResponse {
    /// Whether verification passed.
    pub verified: bool,
    /// Expected hash.
    pub expected: String,
    /// Actual hash.
    pub actual: String,
    /// Per-layer verification results.
    pub layer_results: Vec<LayerVerificationResult>,
    /// Human-readable description.
    pub description: String,
}

/// Per-layer verification result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerVerificationResult {
    /// Layer type.
    pub layer: LayerType,
    /// Whether this layer passed.
    pub verified: bool,
    /// Layer hash.
    pub hash: String,
}

/// Certification status for an environment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificationStatus {
    /// Environment identifier.
    pub environment: String,
    /// Current certification phase.
    pub phase: CertificationPhase,
    /// Master untested signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_signature: Option<String>,
    /// Compliance hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_signature: Option<String>,
    /// Final secure signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_signature: Option<String>,
    /// When last certified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_certified_at: Option<DateTime<Utc>>,
    /// Per-layer statuses.
    pub layers: Vec<LayerCertificationStatus>,
}

/// Certification phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificationPhase {
    /// Not yet assessed.
    Pending,
    /// All checks passed.
    Certified,
    /// Some checks degraded.
    Degraded,
    /// Certification failed.
    Failed,
}

/// Per-layer certification status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerCertificationStatus {
    /// Layer type.
    pub layer: LayerType,
    /// Layer hash.
    pub hash: String,
    /// Whether verified.
    pub verified: bool,
    /// When last verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,
}

/// Audit trail entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When this entry was recorded.
    pub timestamp: DateTime<Utc>,
    /// Environment.
    pub environment: String,
    /// Action that was performed.
    pub action: AuditAction,
    /// The signature at the time of the action.
    pub signature: String,
    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Audit actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Signature was computed.
    SignatureComputed,
    /// Signature was verified.
    SignatureVerified,
    /// Verification failed.
    VerificationFailed,
    /// Compliance test was run.
    ComplianceTestRun,
    /// Environment was certified.
    Certified,
    /// Environment certification degraded.
    Degraded,
    /// Provisioning was gated (allowed).
    GateAllowed,
    /// Provisioning was gated (denied).
    GateDenied,
}

impl std::fmt::Display for CertificationPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificationPhase::Pending => write!(f, "pending"),
            CertificationPhase::Certified => write!(f, "certified"),
            CertificationPhase::Degraded => write!(f, "degraded"),
            CertificationPhase::Failed => write!(f, "failed"),
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::SignatureComputed => write!(f, "signature_computed"),
            AuditAction::SignatureVerified => write!(f, "signature_verified"),
            AuditAction::VerificationFailed => write!(f, "verification_failed"),
            AuditAction::ComplianceTestRun => write!(f, "compliance_test_run"),
            AuditAction::Certified => write!(f, "certified"),
            AuditAction::Degraded => write!(f, "degraded"),
            AuditAction::GateAllowed => write!(f, "gate_allowed"),
            AuditAction::GateDenied => write!(f, "gate_denied"),
        }
    }
}

/// Gate decision — the result of a gating check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateDecision {
    /// Whether provisioning is allowed.
    pub allowed: bool,
    /// Reason for the decision.
    pub reason: String,
    /// The signature that was checked.
    pub signature: String,
    /// Expected signature.
    pub expected: String,
    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
    /// Which gate made the decision.
    pub gate: String,
}

impl GateDecision {
    /// Create an "allowed" gate decision.
    #[must_use]
    pub fn allow(signature: &Blake3Hash, expected: &Blake3Hash, gate: &str) -> Self {
        Self {
            allowed: true,
            reason: "Signature verified".to_string(),
            signature: signature.to_prefixed(),
            expected: expected.to_prefixed(),
            decided_at: Utc::now(),
            gate: gate.to_string(),
        }
    }

    /// Create a "denied" gate decision.
    #[must_use]
    pub fn deny(signature: &Blake3Hash, expected: &Blake3Hash, gate: &str, reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
            signature: signature.to_prefixed(),
            expected: expected.to_prefixed(),
            decided_at: Utc::now(),
            gate: gate.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_signature_request_serde_roundtrip() {
        let req = ComputeSignatureRequest {
            layers: vec![LayerType::Nix, LayerType::Oci],
            environment: "production".to_string(),
            include_compliance: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ComputeSignatureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.environment, "production");
        assert!(deserialized.include_compliance);
        assert_eq!(deserialized.layers.len(), 2);
    }

    #[test]
    fn verify_signature_request_serde_roundtrip() {
        let req = VerifySignatureRequest {
            expected: "blake3:abc123".to_string(),
            environment: "staging".to_string(),
            layers: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: VerifySignatureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expected, "blake3:abc123");
        assert_eq!(deserialized.environment, "staging");
    }

    #[test]
    fn certification_phase_serde_roundtrip() {
        for phase in &[
            CertificationPhase::Pending,
            CertificationPhase::Certified,
            CertificationPhase::Degraded,
            CertificationPhase::Failed,
        ] {
            let json = serde_json::to_string(phase).unwrap();
            let deserialized: CertificationPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, deserialized);
        }
    }

    #[test]
    fn certification_phase_display() {
        assert_eq!(CertificationPhase::Pending.to_string(), "pending");
        assert_eq!(CertificationPhase::Certified.to_string(), "certified");
        assert_eq!(CertificationPhase::Degraded.to_string(), "degraded");
        assert_eq!(CertificationPhase::Failed.to_string(), "failed");
    }

    #[test]
    fn audit_action_display() {
        assert_eq!(AuditAction::SignatureComputed.to_string(), "signature_computed");
        assert_eq!(AuditAction::GateDenied.to_string(), "gate_denied");
    }

    #[test]
    fn audit_action_serde_roundtrip() {
        for action in &[
            AuditAction::SignatureComputed,
            AuditAction::SignatureVerified,
            AuditAction::VerificationFailed,
            AuditAction::ComplianceTestRun,
            AuditAction::Certified,
            AuditAction::Degraded,
            AuditAction::GateAllowed,
            AuditAction::GateDenied,
        ] {
            let json = serde_json::to_string(action).unwrap();
            let deserialized: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, deserialized);
        }
    }

    #[test]
    fn gate_decision_allow_fields() {
        let sig = Blake3Hash::digest(b"sig");
        let expected = Blake3Hash::digest(b"sig");
        let decision = GateDecision::allow(&sig, &expected, "test-gate");
        assert!(decision.allowed);
        assert_eq!(decision.gate, "test-gate");
        assert_eq!(decision.reason, "Signature verified");
        assert!(decision.signature.starts_with("blake3:"));
    }

    #[test]
    fn gate_decision_deny_fields() {
        let sig = Blake3Hash::digest(b"wrong");
        let expected = Blake3Hash::digest(b"right");
        let decision = GateDecision::deny(&sig, &expected, "my-gate", "mismatch");
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "mismatch");
        assert_ne!(decision.signature, decision.expected);
    }

    #[test]
    fn gate_decision_serde_roundtrip() {
        let sig = Blake3Hash::digest(b"sig");
        let decision = GateDecision::allow(&sig, &sig, "gate");
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowed, decision.allowed);
        assert_eq!(deserialized.gate, decision.gate);
    }

    #[test]
    fn certification_status_serde_roundtrip() {
        let status = CertificationStatus {
            environment: "prod".to_string(),
            phase: CertificationPhase::Certified,
            master_signature: Some("blake3:abc".to_string()),
            compliance_signature: None,
            secure_signature: None,
            last_certified_at: Some(Utc::now()),
            layers: vec![LayerCertificationStatus {
                layer: LayerType::Nix,
                hash: "blake3:def".to_string(),
                verified: true,
                last_verified_at: Some(Utc::now()),
            }],
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: CertificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.environment, "prod");
        assert_eq!(deserialized.phase, CertificationPhase::Certified);
        assert_eq!(deserialized.layers.len(), 1);
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            environment: "staging".to_string(),
            action: AuditAction::SignatureComputed,
            signature: "blake3:xxx".to_string(),
            details: Some("computed successfully".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.environment, "staging");
        assert_eq!(deserialized.action, AuditAction::SignatureComputed);
    }

    #[test]
    fn layer_verification_result_serde_roundtrip() {
        let result = LayerVerificationResult {
            layer: LayerType::Helm,
            verified: true,
            hash: "blake3:abc".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: LayerVerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.layer, LayerType::Helm);
        assert!(deserialized.verified);
    }
}
