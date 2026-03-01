//! Comprehensive compliance reporting types.
//!
//! Provides full visibility into the compliance state of any environment,
//! layer, control, or timeframe. These types are served by sekiban (REST/GraphQL/gRPC)
//! and populated by kensa (compliance testing) + sekiban (continuous certification).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::signature::LayerType;

/// Complete environment compliance dashboard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvironmentReport {
    /// Environment name.
    pub environment: String,
    /// Overall compliance status.
    pub status: EnvironmentStatus,
    /// Current master signature.
    pub master_signature: SignatureReport,
    /// Per-layer status.
    pub layers: Vec<LayerReport>,
    /// Compliance testing summary.
    pub compliance: ComplianceSummary,
    /// Framework self-attestation.
    pub framework_attestation: FrameworkReport,
    /// Recent gate decisions.
    pub recent_gates: Vec<GateReport>,
    /// Recent alerts.
    pub recent_alerts: Vec<AlertReport>,
    /// Report generation metadata.
    pub generated_at: DateTime<Utc>,
    /// Time range covered.
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
}

/// High-level environment status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentStatus {
    /// All layers verified, compliance passed, signature current.
    Green,
    /// Minor issues (e.g., approaching stale, some warnings).
    Yellow,
    /// Major issues (compliance failures, signature mismatch).
    Red,
    /// Environment not yet assessed.
    Unknown,
}

impl std::fmt::Display for EnvironmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvironmentStatus::Green => write!(f, "green"),
            EnvironmentStatus::Yellow => write!(f, "yellow"),
            EnvironmentStatus::Red => write!(f, "red"),
            EnvironmentStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Signature status report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureReport {
    /// Current untested signature.
    pub untested: String,
    /// Current compliance hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    /// Current secure signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<String>,
    /// Is fully attested (has compliance)?
    pub fully_attested: bool,
    /// When computed.
    pub computed_at: DateTime<Utc>,
    /// Age in seconds.
    pub age_seconds: i64,
    /// Whether the signature is considered stale.
    pub stale: bool,
}

/// Per-layer compliance report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerReport {
    /// Layer type.
    pub layer: LayerType,
    /// Layer hash.
    pub hash: String,
    /// Whether verified against expected.
    pub verified: bool,
    /// Number of inputs that were hashed.
    pub input_count: usize,
    /// When last verified.
    pub last_verified_at: DateTime<Utc>,
    /// Source that was hashed.
    pub source: String,
}

/// Compliance testing summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Total controls assessed.
    pub total_controls: usize,
    /// Controls that passed.
    pub passed: usize,
    /// Controls that failed.
    pub failed: usize,
    /// Controls not assessed.
    pub skipped: usize,
    /// Pass percentage.
    pub pass_rate: f64,
    /// Compliance hash.
    pub compliance_hash: String,
    /// Framework used (e.g., "inspec", "kensa").
    pub framework: String,
    /// Baseline (e.g., "moderate").
    pub baseline: String,
    /// Failed control IDs.
    pub failed_controls: Vec<String>,
    /// When last assessed.
    pub last_assessed_at: DateTime<Utc>,
    /// NIST control family breakdown.
    pub family_breakdown: Vec<ControlFamilyReport>,
}

/// NIST control family breakdown.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlFamilyReport {
    /// Family ID (e.g., "AC", "SC").
    pub family: String,
    /// Family name.
    pub name: String,
    /// Controls assessed in this family.
    pub total: usize,
    /// Controls passed.
    pub passed: usize,
    /// Controls failed.
    pub failed: usize,
}

/// Framework self-attestation report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkReport {
    /// Whether all framework components are attested.
    pub attested: bool,
    /// Component attestation statuses.
    pub components: Vec<ComponentReport>,
    /// Composite framework hash.
    pub framework_hash: String,
    /// NIST controls satisfied by the framework.
    pub satisfied_controls: Vec<String>,
}

/// Per-component attestation report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentReport {
    /// Component name.
    pub name: String,
    /// Component version.
    pub version: String,
    /// Binary hash.
    pub hash: String,
    /// Whether hash matches expected.
    pub verified: bool,
}

/// Recent gate decision summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateReport {
    /// When the decision was made.
    pub timestamp: DateTime<Utc>,
    /// Whether allowed.
    pub allowed: bool,
    /// Gate name.
    pub gate: String,
    /// Resource affected.
    pub resource: String,
    /// Reason.
    pub reason: String,
}

/// Recent alert summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertReport {
    /// When the alert fired.
    pub timestamp: DateTime<Utc>,
    /// Severity.
    pub severity: String,
    /// Summary.
    pub summary: String,
    /// Whether acknowledged.
    pub acknowledged: bool,
}

/// Historical trend data point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrendDataPoint {
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Compliance pass rate (0.0 - 1.0).
    pub pass_rate: f64,
    /// Number of gate denials.
    pub gate_denials: u32,
    /// Number of alerts.
    pub alerts: u32,
    /// Whether environment was fully certified.
    pub certified: bool,
}

/// Compliance drift detection report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DriftReport {
    /// Whether drift was detected.
    pub drift_detected: bool,
    /// Layers with drift.
    pub drifted_layers: Vec<LayerDrift>,
    /// When baseline was established.
    pub baseline_established_at: DateTime<Utc>,
    /// When drift was detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift_detected_at: Option<DateTime<Utc>>,
}

/// Drift details for a single layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerDrift {
    /// Layer type.
    pub layer: LayerType,
    /// Expected hash (from baseline).
    pub expected_hash: String,
    /// Actual current hash.
    pub actual_hash: String,
    /// When drift was first detected.
    pub detected_at: DateTime<Utc>,
}

/// Request to generate a full environment report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportRequest {
    /// Environment to report on.
    pub environment: String,
    /// Time range start (defaults to 24h ago).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    /// Time range end (defaults to now).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    /// Include trend data.
    #[serde(default)]
    pub include_trends: bool,
    /// Include drift detection.
    #[serde(default)]
    pub include_drift: bool,
    /// Output format.
    #[serde(default)]
    pub format: ReportFormat,
}

/// Report output formats.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    #[default]
    Json,
    Oscal,
    Nist,
    Html,
    Csv,
}
