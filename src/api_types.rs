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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
