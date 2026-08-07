//! Compliance plugin types and trait.
//!
//! Defines the [`CompliancePlugin`] trait that every compliance domain implements,
//! along with supporting types for controls, evaluations, and configuration.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// Severity level for a compliance control.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlSeverity {
    /// Informational only.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl schemars::JsonSchema for ControlSeverity {
    fn schema_name() -> String {
        "ControlSeverity".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(_gen)
    }
}

impl std::fmt::Display for ControlSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlSeverity::Info => write!(f, "info"),
            ControlSeverity::Low => write!(f, "low"),
            ControlSeverity::Medium => write!(f, "medium"),
            ControlSeverity::High => write!(f, "high"),
            ControlSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// A single compliance control definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceControl {
    /// Unique identifier for this control.
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// Detailed description of what this control checks.
    pub description: String,
    /// Severity if this control fails.
    pub severity: ControlSeverity,
    /// NIST 800-53 control identifiers this maps to.
    pub nist_control_ids: Vec<String>,
    /// Domain this control belongs to (e.g., "kernel", "nix-store").
    pub domain: String,
    /// Whether this control is required for overall pass.
    pub required: bool,
}

impl schemars::JsonSchema for ComplianceControl {
    fn schema_name() -> String {
        "ComplianceControl".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <BTreeMap<String, String> as schemars::JsonSchema>::json_schema(_gen)
    }
}

/// Result of evaluating a single compliance control.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControlEvaluation {
    /// The control that was evaluated.
    pub control: ComplianceControl,
    /// Whether the control passed.
    pub passed: bool,
    /// Human-readable message describing the result.
    pub message: String,
    /// Optional BLAKE3 hash of evidence gathered during evaluation.
    pub evidence_hash: Option<Blake3Hash>,
    /// When the evaluation was performed.
    pub evaluated_at: DateTime<Utc>,
    /// Evaluation duration in milliseconds.
    pub duration_ms: u64,
}

impl schemars::JsonSchema for ControlEvaluation {
    fn schema_name() -> String {
        "ControlEvaluation".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <BTreeMap<String, String> as schemars::JsonSchema>::json_schema(_gen)
    }
}

/// Result of evaluating all controls in a compliance domain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DomainEvaluation {
    /// Domain name (e.g., "kernel", "nix-store").
    pub domain: String,
    /// Individual control evaluations.
    pub evaluations: Vec<ControlEvaluation>,
    /// BLAKE3 hash of this domain's evaluation results.
    pub domain_hash: Blake3Hash,
    /// When the domain evaluation completed.
    pub completed_at: DateTime<Utc>,
    /// Total duration in milliseconds for all control evaluations.
    pub total_duration_ms: u64,
    /// Whether all required controls passed.
    pub all_required_passed: bool,
}

impl schemars::JsonSchema for DomainEvaluation {
    fn schema_name() -> String {
        "DomainEvaluation".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <BTreeMap<String, String> as schemars::JsonSchema>::json_schema(_gen)
    }
}

impl DomainEvaluation {
    /// Compute the domain hash from a set of control evaluations.
    #[must_use]
    pub fn compute_domain_hash(domain: &str, evaluations: &[ControlEvaluation]) -> Blake3Hash {
        let mut data = Vec::new();
        data.extend_from_slice(domain.as_bytes());
        for eval in evaluations {
            data.extend_from_slice(eval.control.id.as_bytes());
            data.push(u8::from(eval.passed));
            data.extend_from_slice(eval.message.as_bytes());
            if let Some(ref h) = eval.evidence_hash {
                data.extend_from_slice(&h.0);
            }
        }
        Blake3Hash::digest(&data)
    }
}

/// Configuration for compliance plugin evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Environment being evaluated (e.g., "production", "staging").
    pub environment: String,
    /// Baseline profile (e.g., "level1", "level2", "stig").
    pub baseline: String,
    /// Domain-specific settings.
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Whether to include advisory (non-required) controls.
    pub include_advisory: bool,
}

impl schemars::JsonSchema for PluginConfig {
    fn schema_name() -> String {
        "PluginConfig".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <BTreeMap<String, String> as schemars::JsonSchema>::json_schema(_gen)
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            environment: "production".to_string(),
            baseline: "level1".to_string(),
            settings: BTreeMap::new(),
            include_advisory: false,
        }
    }
}

/// Core trait for compliance domain plugins.
///
/// Every compliance domain (kernel hardening, Nix store, OCI, Kubernetes, etc.)
/// implements this trait. The [`super::plugin_orchestrator::ComplianceOrchestrator`]
/// discovers and invokes plugins via the [`super::registry::PluginRegistry`].
pub trait CompliancePlugin: Send + Sync {
    /// Domain name (e.g., "kernel", "nix-store", "oci", "kubernetes").
    fn domain(&self) -> &str;

    /// NIST 800-53 control families this plugin covers.
    fn nist_families(&self) -> Vec<String>;

    /// Generate the set of controls for this domain given the config.
    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl>;

    /// Evaluate the provided controls and return a domain evaluation.
    fn evaluate(
        &self,
        controls: &[ComplianceControl],
        config: &PluginConfig,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<DomainEvaluation>> + Send + '_>>;

    /// Whether this plugin can operate in the current environment.
    fn is_available(&self) -> bool;
}

/// Mock compliance plugin for testing the framework.
pub struct MockPlugin {
    domain_name: String,
    nist_families: Vec<String>,
    controls: Vec<ComplianceControl>,
    pass_all: bool,
    available: bool,
}

impl MockPlugin {
    /// Create a new mock plugin.
    #[must_use]
    pub fn new(domain: &str) -> Self {
        Self {
            domain_name: domain.to_string(),
            nist_families: vec!["AC".to_string(), "CM".to_string()],
            controls: Vec::new(),
            pass_all: true,
            available: true,
        }
    }

    /// Set NIST families.
    #[must_use]
    pub fn with_nist_families(mut self, families: Vec<String>) -> Self {
        self.nist_families = families;
        self
    }

    /// Set controls returned by `generate_controls`.
    #[must_use]
    pub fn with_controls(mut self, controls: Vec<ComplianceControl>) -> Self {
        self.controls = controls;
        self
    }

    /// Set whether all evaluations pass.
    #[must_use]
    pub fn with_pass_all(mut self, pass: bool) -> Self {
        self.pass_all = pass;
        self
    }

    /// Set availability.
    #[must_use]
    pub fn with_available(mut self, available: bool) -> Self {
        self.available = available;
        self
    }

    /// Create a simple test control.
    #[must_use]
    pub fn make_control(id: &str, domain: &str, required: bool) -> ComplianceControl {
        ComplianceControl {
            id: id.to_string(),
            title: format!("Test control {id}"),
            description: format!("Test control {id} for domain {domain}"),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["AC-1".to_string()],
            domain: domain.to_string(),
            required,
        }
    }
}

impl CompliancePlugin for MockPlugin {
    fn domain(&self) -> &str {
        &self.domain_name
    }

    fn nist_families(&self) -> Vec<String> {
        self.nist_families.clone()
    }

    fn generate_controls(&self, _config: &PluginConfig) -> Vec<ComplianceControl> {
        if self.controls.is_empty() {
            vec![
                MockPlugin::make_control(
                    &format!("{}-001", self.domain_name),
                    &self.domain_name,
                    true,
                ),
                MockPlugin::make_control(
                    &format!("{}-002", self.domain_name),
                    &self.domain_name,
                    false,
                ),
            ]
        } else {
            self.controls.clone()
        }
    }

    fn evaluate(
        &self,
        controls: &[ComplianceControl],
        _config: &PluginConfig,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<DomainEvaluation>> + Send + '_>> {
        let domain = self.domain_name.clone();
        let pass_all = self.pass_all;
        let controls = controls.to_vec();
        Box::pin(async move {
            let now = Utc::now();
            let evaluations: Vec<ControlEvaluation> = controls
                .iter()
                .map(|c| ControlEvaluation {
                    control: c.clone(),
                    passed: pass_all,
                    message: if pass_all {
                        format!("{}: passed", c.id)
                    } else {
                        format!("{}: failed", c.id)
                    },
                    evidence_hash: Some(Blake3Hash::digest(c.id.as_bytes())),
                    evaluated_at: now,
                    duration_ms: 1,
                })
                .collect();
            let domain_hash = DomainEvaluation::compute_domain_hash(&domain, &evaluations);
            let total_duration_ms = evaluations.iter().map(|e| e.duration_ms).sum();
            let all_required_passed = evaluations.iter().all(|e| !e.control.required || e.passed);
            Ok(DomainEvaluation {
                domain,
                evaluations,
                domain_hash,
                completed_at: now,
                total_duration_ms,
                all_required_passed,
            })
        })
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_severity_display() {
        assert_eq!(ControlSeverity::Info.to_string(), "info");
        assert_eq!(ControlSeverity::Low.to_string(), "low");
        assert_eq!(ControlSeverity::Medium.to_string(), "medium");
        assert_eq!(ControlSeverity::High.to_string(), "high");
        assert_eq!(ControlSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn control_severity_ordering() {
        assert!(ControlSeverity::Info < ControlSeverity::Low);
        assert!(ControlSeverity::Low < ControlSeverity::Medium);
        assert!(ControlSeverity::Medium < ControlSeverity::High);
        assert!(ControlSeverity::High < ControlSeverity::Critical);
    }

    #[test]
    fn control_severity_serde_roundtrip() {
        let sev = ControlSeverity::Critical;
        let json = serde_json::to_string(&sev).unwrap();
        let back: ControlSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }

    #[test]
    fn compliance_control_serde_roundtrip() {
        let control = ComplianceControl {
            id: "KERN-001".to_string(),
            title: "IP forwarding".to_string(),
            description: "Ensure IP forwarding is disabled".to_string(),
            severity: ControlSeverity::High,
            nist_control_ids: vec!["SC-7".to_string(), "CM-6".to_string()],
            domain: "kernel".to_string(),
            required: true,
        };
        let json = serde_json::to_string(&control).unwrap();
        let back: ComplianceControl = serde_json::from_str(&json).unwrap();
        assert_eq!(control, back);
    }

    #[test]
    fn control_evaluation_serde_roundtrip() {
        let eval = ControlEvaluation {
            control: MockPlugin::make_control("TEST-001", "test", true),
            passed: true,
            message: "Passed".to_string(),
            evidence_hash: Some(Blake3Hash::digest(b"evidence")),
            evaluated_at: Utc::now(),
            duration_ms: 42,
        };
        let json = serde_json::to_string(&eval).unwrap();
        let back: ControlEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(eval.control, back.control);
        assert_eq!(eval.passed, back.passed);
        assert_eq!(eval.message, back.message);
        assert_eq!(eval.evidence_hash, back.evidence_hash);
    }

    #[test]
    fn domain_evaluation_serde_roundtrip() {
        let evals = vec![ControlEvaluation {
            control: MockPlugin::make_control("TEST-001", "test", true),
            passed: true,
            message: "ok".to_string(),
            evidence_hash: None,
            evaluated_at: Utc::now(),
            duration_ms: 1,
        }];
        let domain_hash = DomainEvaluation::compute_domain_hash("test", &evals);
        let de = DomainEvaluation {
            domain: "test".to_string(),
            evaluations: evals,
            domain_hash,
            completed_at: Utc::now(),
            total_duration_ms: 1,
            all_required_passed: true,
        };
        let json = serde_json::to_string(&de).unwrap();
        let back: DomainEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(de.domain, back.domain);
        assert_eq!(de.domain_hash, back.domain_hash);
    }

    #[test]
    fn plugin_config_serde_roundtrip() {
        let mut settings = BTreeMap::new();
        settings.insert("key".to_string(), serde_json::json!("value"));
        let config = PluginConfig {
            environment: "staging".to_string(),
            baseline: "level2".to_string(),
            settings,
            include_advisory: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: PluginConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn plugin_config_default() {
        let config = PluginConfig::default();
        assert_eq!(config.environment, "production");
        assert_eq!(config.baseline, "level1");
        assert!(config.settings.is_empty());
        assert!(!config.include_advisory);
    }

    #[test]
    fn domain_evaluation_compute_hash_deterministic() {
        let evals = vec![
            ControlEvaluation {
                control: MockPlugin::make_control("T-001", "test", true),
                passed: true,
                message: "ok".to_string(),
                evidence_hash: None,
                evaluated_at: Utc::now(),
                duration_ms: 1,
            },
            ControlEvaluation {
                control: MockPlugin::make_control("T-002", "test", false),
                passed: false,
                message: "fail".to_string(),
                evidence_hash: Some(Blake3Hash::digest(b"ev")),
                evaluated_at: Utc::now(),
                duration_ms: 2,
            },
        ];
        let h1 = DomainEvaluation::compute_domain_hash("test", &evals);
        let h2 = DomainEvaluation::compute_domain_hash("test", &evals);
        assert_eq!(h1, h2);
    }

    #[test]
    fn domain_evaluation_hash_changes_with_domain() {
        let evals = vec![ControlEvaluation {
            control: MockPlugin::make_control("T-001", "test", true),
            passed: true,
            message: "ok".to_string(),
            evidence_hash: None,
            evaluated_at: Utc::now(),
            duration_ms: 1,
        }];
        let h1 = DomainEvaluation::compute_domain_hash("alpha", &evals);
        let h2 = DomainEvaluation::compute_domain_hash("beta", &evals);
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_evaluation_hash_changes_with_pass_status() {
        let pass_eval = vec![ControlEvaluation {
            control: MockPlugin::make_control("T-001", "test", true),
            passed: true,
            message: "ok".to_string(),
            evidence_hash: None,
            evaluated_at: Utc::now(),
            duration_ms: 1,
        }];
        let fail_eval = vec![ControlEvaluation {
            control: MockPlugin::make_control("T-001", "test", true),
            passed: false,
            message: "ok".to_string(),
            evidence_hash: None,
            evaluated_at: Utc::now(),
            duration_ms: 1,
        }];
        let h1 = DomainEvaluation::compute_domain_hash("test", &pass_eval);
        let h2 = DomainEvaluation::compute_domain_hash("test", &fail_eval);
        assert_ne!(h1, h2);
    }

    #[test]
    fn mock_plugin_domain() {
        let p = MockPlugin::new("test-domain");
        assert_eq!(p.domain(), "test-domain");
    }

    #[test]
    fn mock_plugin_nist_families() {
        let p =
            MockPlugin::new("test").with_nist_families(vec!["SC".to_string(), "SI".to_string()]);
        assert_eq!(p.nist_families(), vec!["SC", "SI"]);
    }

    #[test]
    fn mock_plugin_generates_default_controls() {
        let p = MockPlugin::new("mydom");
        let controls = p.generate_controls(&PluginConfig::default());
        assert_eq!(controls.len(), 2);
        assert_eq!(controls[0].id, "mydom-001");
        assert_eq!(controls[1].id, "mydom-002");
        assert!(controls[0].required);
        assert!(!controls[1].required);
    }

    #[test]
    fn mock_plugin_generates_custom_controls() {
        let custom = vec![MockPlugin::make_control("CUST-001", "custom", true)];
        let p = MockPlugin::new("custom").with_controls(custom.clone());
        let out = p.generate_controls(&PluginConfig::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "CUST-001");
    }

    #[tokio::test]
    async fn mock_plugin_evaluate_pass() {
        let p = MockPlugin::new("test").with_pass_all(true);
        let controls = p.generate_controls(&PluginConfig::default());
        let result = p
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();
        assert!(result.all_required_passed);
        assert_eq!(result.domain, "test");
        assert!(result.evaluations.iter().all(|e| e.passed));
    }

    #[tokio::test]
    async fn mock_plugin_evaluate_fail() {
        let p = MockPlugin::new("test").with_pass_all(false);
        let controls = p.generate_controls(&PluginConfig::default());
        let result = p
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();
        assert!(!result.all_required_passed);
        assert!(result.evaluations.iter().all(|e| !e.passed));
    }

    #[test]
    fn mock_plugin_availability() {
        let avail = MockPlugin::new("test").with_available(true);
        assert!(avail.is_available());
        let unavail = MockPlugin::new("test").with_available(false);
        assert!(!unavail.is_available());
    }

    #[tokio::test]
    async fn mock_plugin_domain_hash_is_set() {
        let p = MockPlugin::new("test");
        let controls = p.generate_controls(&PluginConfig::default());
        let result = p
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();
        // Hash should not be zero
        assert_ne!(result.domain_hash, Blake3Hash::digest(b""));
    }

    #[tokio::test]
    async fn mock_plugin_evidence_hashes_present() {
        let p = MockPlugin::new("test");
        let controls = p.generate_controls(&PluginConfig::default());
        let result = p
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();
        for eval in &result.evaluations {
            assert!(eval.evidence_hash.is_some());
        }
    }

    #[test]
    fn make_control_helper() {
        let c = MockPlugin::make_control("ID-1", "dom", true);
        assert_eq!(c.id, "ID-1");
        assert_eq!(c.domain, "dom");
        assert!(c.required);
        assert_eq!(c.severity, ControlSeverity::Medium);
    }

    #[test]
    fn all_severity_variants_serde() {
        for sev in &[
            ControlSeverity::Info,
            ControlSeverity::Low,
            ControlSeverity::Medium,
            ControlSeverity::High,
            ControlSeverity::Critical,
        ] {
            let json = serde_json::to_string(sev).unwrap();
            let back: ControlSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    #[test]
    fn empty_evaluations_hash() {
        let h = DomainEvaluation::compute_domain_hash("test", &[]);
        // Should hash just the domain name
        let expected = Blake3Hash::digest(b"test");
        assert_eq!(h, expected);
    }

    #[test]
    fn control_evaluation_without_evidence() {
        let eval = ControlEvaluation {
            control: MockPlugin::make_control("T-001", "test", true),
            passed: true,
            message: "ok".to_string(),
            evidence_hash: None,
            evaluated_at: Utc::now(),
            duration_ms: 0,
        };
        let json = serde_json::to_string(&eval).unwrap();
        let back: ControlEvaluation = serde_json::from_str(&json).unwrap();
        assert!(back.evidence_hash.is_none());
    }
}
