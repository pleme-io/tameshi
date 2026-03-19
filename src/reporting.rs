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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    #[default]
    Json,
    Oscal,
    Nist,
    Html,
    Csv,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Json => write!(f, "json"),
            ReportFormat::Oscal => write!(f, "oscal"),
            ReportFormat::Nist => write!(f, "nist"),
            ReportFormat::Html => write!(f, "html"),
            ReportFormat::Csv => write!(f, "csv"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_status_display() {
        assert_eq!(EnvironmentStatus::Green.to_string(), "green");
        assert_eq!(EnvironmentStatus::Yellow.to_string(), "yellow");
        assert_eq!(EnvironmentStatus::Red.to_string(), "red");
        assert_eq!(EnvironmentStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn environment_status_serde_roundtrip() {
        for status in &[
            EnvironmentStatus::Green,
            EnvironmentStatus::Yellow,
            EnvironmentStatus::Red,
            EnvironmentStatus::Unknown,
        ] {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: EnvironmentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, deserialized);
        }
    }

    #[test]
    fn report_format_display() {
        assert_eq!(ReportFormat::Json.to_string(), "json");
        assert_eq!(ReportFormat::Oscal.to_string(), "oscal");
        assert_eq!(ReportFormat::Csv.to_string(), "csv");
    }

    #[test]
    fn report_format_default_is_json() {
        let format = ReportFormat::default();
        assert_eq!(format, ReportFormat::Json);
    }

    #[test]
    fn report_format_serde_roundtrip() {
        for fmt in &[
            ReportFormat::Json,
            ReportFormat::Oscal,
            ReportFormat::Nist,
            ReportFormat::Html,
            ReportFormat::Csv,
        ] {
            let json = serde_json::to_string(fmt).unwrap();
            let deserialized: ReportFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(*fmt, deserialized);
        }
    }

    #[test]
    fn report_request_serde_roundtrip() {
        let req = ReportRequest {
            environment: "production".to_string(),
            from: None,
            to: None,
            include_trends: true,
            include_drift: false,
            format: ReportFormat::Oscal,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ReportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.environment, "production");
        assert!(deserialized.include_trends);
        assert!(!deserialized.include_drift);
        assert_eq!(deserialized.format, ReportFormat::Oscal);
    }

    #[test]
    fn report_request_defaults() {
        let json = r#"{"environment": "staging"}"#;
        let req: ReportRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.environment, "staging");
        assert!(!req.include_trends);
        assert!(!req.include_drift);
        assert_eq!(req.format, ReportFormat::Json);
    }

    #[test]
    fn signature_report_serde_roundtrip() {
        let report = SignatureReport {
            untested: "blake3:abc".to_string(),
            compliance: Some("blake3:def".to_string()),
            secure: Some("blake3:ghi".to_string()),
            fully_attested: true,
            computed_at: Utc::now(),
            age_seconds: 300,
            stale: false,
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: SignatureReport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.fully_attested);
        assert!(!deserialized.stale);
    }

    #[test]
    fn layer_report_serde_roundtrip() {
        let report = LayerReport {
            layer: LayerType::Nix,
            hash: "blake3:abc".to_string(),
            verified: true,
            input_count: 42,
            last_verified_at: Utc::now(),
            source: "/nix/store/xxx".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: LayerReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.layer, LayerType::Nix);
        assert!(deserialized.verified);
        assert_eq!(deserialized.input_count, 42);
    }

    #[test]
    fn compliance_summary_serde_roundtrip() {
        let summary = ComplianceSummary {
            total_controls: 100,
            passed: 95,
            failed: 3,
            skipped: 2,
            pass_rate: 0.95,
            compliance_hash: "blake3:xxx".to_string(),
            framework: "kensa".to_string(),
            baseline: "moderate".to_string(),
            failed_controls: vec!["AC-2".to_string(), "SC-7".to_string()],
            last_assessed_at: Utc::now(),
            family_breakdown: vec![ControlFamilyReport {
                family: "AC".to_string(),
                name: "Access Control".to_string(),
                total: 10,
                passed: 9,
                failed: 1,
            }],
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: ComplianceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_controls, 100);
        assert_eq!(deserialized.failed_controls.len(), 2);
    }

    #[test]
    fn drift_report_no_drift() {
        let report = DriftReport {
            drift_detected: false,
            drifted_layers: vec![],
            baseline_established_at: Utc::now(),
            drift_detected_at: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: DriftReport = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.drift_detected);
        assert!(deserialized.drifted_layers.is_empty());
    }

    #[test]
    fn drift_report_with_drift() {
        let report = DriftReport {
            drift_detected: true,
            drifted_layers: vec![LayerDrift {
                layer: LayerType::Oci,
                expected_hash: "blake3:aaa".to_string(),
                actual_hash: "blake3:bbb".to_string(),
                detected_at: Utc::now(),
            }],
            baseline_established_at: Utc::now(),
            drift_detected_at: Some(Utc::now()),
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: DriftReport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.drift_detected);
        assert_eq!(deserialized.drifted_layers.len(), 1);
    }

    #[test]
    fn trend_data_point_serde_roundtrip() {
        let point = TrendDataPoint {
            timestamp: Utc::now(),
            pass_rate: 0.95,
            gate_denials: 2,
            alerts: 1,
            certified: true,
        };
        let json = serde_json::to_string(&point).unwrap();
        let deserialized: TrendDataPoint = serde_json::from_str(&json).unwrap();
        assert!(deserialized.certified);
        assert_eq!(deserialized.gate_denials, 2);
    }
}
