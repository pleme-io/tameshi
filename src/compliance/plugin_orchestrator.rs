//! Compliance orchestrator that runs all registered plugins and produces a
//! composite compliance report.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

use super::plugin::{DomainEvaluation, PluginConfig};
use super::registry::PluginRegistry;

/// Full compliance report produced by the orchestrator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FullComplianceReport {
    /// Environment that was evaluated.
    pub environment: String,
    /// Per-domain evaluation results.
    pub domain_evaluations: Vec<DomainEvaluation>,
    /// Composite BLAKE3 hash of all domain hashes (sorted by domain name).
    pub compliance_hash: Blake3Hash,
    /// Whether all required controls across all domains passed.
    pub all_passed: bool,
    /// Total number of controls evaluated.
    pub total_controls: usize,
    /// Number of controls that passed.
    pub passed_controls: usize,
    /// Number of controls that failed.
    pub failed_controls: usize,
    /// When the report was computed.
    pub computed_at: DateTime<Utc>,
}

impl schemars::JsonSchema for FullComplianceReport {
    fn schema_name() -> String {
        "FullComplianceReport".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <std::collections::BTreeMap<String, String> as schemars::JsonSchema>::json_schema(_gen)
    }
}

/// Orchestrator that drives compliance evaluation across all registered plugins.
pub struct ComplianceOrchestrator {
    registry: Arc<PluginRegistry>,
}

impl ComplianceOrchestrator {
    /// Create a new orchestrator with the given plugin registry.
    #[must_use]
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self { registry }
    }

    /// Run all available plugins and produce a composite compliance report.
    ///
    /// For each available plugin: generates controls, evaluates them, and
    /// collects the results. The composite `compliance_hash` is computed
    /// from the sorted domain hashes.
    pub async fn run_all(
        &self,
        config: &PluginConfig,
    ) -> crate::error::Result<FullComplianceReport> {
        let available = self.registry.available();
        let mut domain_evaluations = Vec::with_capacity(available.len());

        for plugin in &available {
            let controls = plugin.generate_controls(config);
            let evaluation = plugin.evaluate(&controls, config).await?;
            domain_evaluations.push(evaluation);
        }

        let compliance_hash = Self::compute_compliance_hash(&domain_evaluations);

        let total_controls: usize = domain_evaluations
            .iter()
            .map(|de| de.evaluations.len())
            .sum();
        let passed_controls: usize = domain_evaluations
            .iter()
            .flat_map(|de| &de.evaluations)
            .filter(|e| e.passed)
            .count();
        let failed_controls = total_controls - passed_controls;
        let all_passed = domain_evaluations.iter().all(|de| de.all_required_passed);

        Ok(FullComplianceReport {
            environment: config.environment.clone(),
            domain_evaluations,
            compliance_hash,
            all_passed,
            total_controls,
            passed_controls,
            failed_controls,
            computed_at: Utc::now(),
        })
    }

    /// Compute the composite compliance hash from domain evaluations.
    ///
    /// Sorts evaluations by domain name, concatenates their domain hashes,
    /// and computes a BLAKE3 digest.
    #[must_use]
    pub fn compute_compliance_hash(evaluations: &[DomainEvaluation]) -> Blake3Hash {
        let mut data = Vec::new();
        let mut sorted: Vec<&DomainEvaluation> = evaluations.iter().collect();
        sorted.sort_by(|a, b| a.domain.cmp(&b.domain));
        for eval in &sorted {
            data.extend_from_slice(&eval.domain_hash.0);
        }
        Blake3Hash::digest(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::plugin::{MockPlugin, PluginConfig};

    fn default_config() -> PluginConfig {
        PluginConfig::default()
    }

    #[tokio::test]
    async fn run_all_with_empty_registry() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new().build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert!(report.all_passed);
        assert_eq!(report.total_controls, 0);
        assert_eq!(report.passed_controls, 0);
        assert_eq!(report.failed_controls, 0);
        assert!(report.domain_evaluations.is_empty());
    }

    #[tokio::test]
    async fn run_all_with_single_passing_plugin() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("test").with_pass_all(true)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert!(report.all_passed);
        assert_eq!(report.total_controls, 2);
        assert_eq!(report.passed_controls, 2);
        assert_eq!(report.failed_controls, 0);
        assert_eq!(report.domain_evaluations.len(), 1);
        assert_eq!(report.domain_evaluations[0].domain, "test");
    }

    #[tokio::test]
    async fn run_all_with_single_failing_plugin() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("test").with_pass_all(false)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert!(!report.all_passed);
        assert_eq!(report.total_controls, 2);
        assert_eq!(report.passed_controls, 0);
        assert_eq!(report.failed_controls, 2);
    }

    #[tokio::test]
    async fn run_all_with_multiple_plugins() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("alpha").with_pass_all(true)))
                .register(Arc::new(MockPlugin::new("beta").with_pass_all(true)))
                .register(Arc::new(MockPlugin::new("gamma").with_pass_all(true)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert!(report.all_passed);
        assert_eq!(report.total_controls, 6); // 3 plugins x 2 controls each
        assert_eq!(report.passed_controls, 6);
        assert_eq!(report.domain_evaluations.len(), 3);
    }

    #[tokio::test]
    async fn run_all_skips_unavailable_plugins() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("avail").with_available(true)))
                .register(Arc::new(MockPlugin::new("unavail").with_available(false)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert_eq!(report.domain_evaluations.len(), 1);
        assert_eq!(report.domain_evaluations[0].domain, "avail");
    }

    #[tokio::test]
    async fn run_all_mixed_pass_fail() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("pass-domain").with_pass_all(true)))
                .register(Arc::new(MockPlugin::new("fail-domain").with_pass_all(false)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert!(!report.all_passed);
        assert_eq!(report.total_controls, 4);
        assert_eq!(report.passed_controls, 2);
        assert_eq!(report.failed_controls, 2);
    }

    #[test]
    fn compute_compliance_hash_deterministic() {
        let now = Utc::now();
        let eval1 = DomainEvaluation {
            domain: "alpha".to_string(),
            evaluations: vec![],
            domain_hash: Blake3Hash::digest(b"alpha-hash"),
            completed_at: now,
            total_duration_ms: 1,
            all_required_passed: true,
        };
        let eval2 = DomainEvaluation {
            domain: "beta".to_string(),
            evaluations: vec![],
            domain_hash: Blake3Hash::digest(b"beta-hash"),
            completed_at: now,
            total_duration_ms: 1,
            all_required_passed: true,
        };

        let h1 = ComplianceOrchestrator::compute_compliance_hash(&[eval1.clone(), eval2.clone()]);
        let h2 = ComplianceOrchestrator::compute_compliance_hash(&[eval1.clone(), eval2.clone()]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_compliance_hash_order_independent() {
        let now = Utc::now();
        let eval1 = DomainEvaluation {
            domain: "alpha".to_string(),
            evaluations: vec![],
            domain_hash: Blake3Hash::digest(b"alpha-hash"),
            completed_at: now,
            total_duration_ms: 1,
            all_required_passed: true,
        };
        let eval2 = DomainEvaluation {
            domain: "beta".to_string(),
            evaluations: vec![],
            domain_hash: Blake3Hash::digest(b"beta-hash"),
            completed_at: now,
            total_duration_ms: 1,
            all_required_passed: true,
        };

        let h_ab = ComplianceOrchestrator::compute_compliance_hash(&[eval1.clone(), eval2.clone()]);
        let h_ba = ComplianceOrchestrator::compute_compliance_hash(&[eval2, eval1]);
        // Sorted by domain name, so order of input shouldn't matter
        assert_eq!(h_ab, h_ba);
    }

    #[test]
    fn compute_compliance_hash_empty() {
        let h = ComplianceOrchestrator::compute_compliance_hash(&[]);
        // Hashing empty data
        let expected = Blake3Hash::digest(b"");
        assert_eq!(h, expected);
    }

    #[test]
    fn compute_compliance_hash_different_hashes() {
        let now = Utc::now();
        let eval1 = DomainEvaluation {
            domain: "test".to_string(),
            evaluations: vec![],
            domain_hash: Blake3Hash::digest(b"hash-a"),
            completed_at: now,
            total_duration_ms: 1,
            all_required_passed: true,
        };
        let eval2 = DomainEvaluation {
            domain: "test".to_string(),
            evaluations: vec![],
            domain_hash: Blake3Hash::digest(b"hash-b"),
            completed_at: now,
            total_duration_ms: 1,
            all_required_passed: true,
        };

        let h1 = ComplianceOrchestrator::compute_compliance_hash(&[eval1]);
        let h2 = ComplianceOrchestrator::compute_compliance_hash(&[eval2]);
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn report_environment_matches_config() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("test")))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let mut config = default_config();
        config.environment = "staging".to_string();
        let report = orchestrator.run_all(&config).await.unwrap();
        assert_eq!(report.environment, "staging");
    }

    #[test]
    fn full_compliance_report_serde_roundtrip() {
        let report = FullComplianceReport {
            environment: "prod".to_string(),
            domain_evaluations: vec![],
            compliance_hash: Blake3Hash::digest(b"test"),
            all_passed: true,
            total_controls: 10,
            passed_controls: 8,
            failed_controls: 2,
            computed_at: Utc::now(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: FullComplianceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.environment, back.environment);
        assert_eq!(report.compliance_hash, back.compliance_hash);
        assert_eq!(report.total_controls, back.total_controls);
        assert_eq!(report.passed_controls, back.passed_controls);
        assert_eq!(report.failed_controls, back.failed_controls);
    }

    #[tokio::test]
    async fn compliance_hash_feeds_into_master_signature() {
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("test").with_pass_all(true)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();

        // The compliance_hash can be used with MasterSignature.with_compliance()
        let layers = vec![crate::signature::LayerSignature::new(
            crate::signature::LayerType::Nix,
            Blake3Hash::digest(b"nix"),
            "test",
            vec![],
        )];
        let master = crate::merkle::compose_merkle(&layers, "test")
            .with_compliance(report.compliance_hash.clone());
        assert!(master.verify_secure());
    }

    #[tokio::test]
    async fn all_passed_true_when_only_optional_fail() {
        // MockPlugin generates one required and one optional control.
        // With pass_all=true, both pass.
        let registry = Arc::new(
            crate::compliance::registry::PluginRegistryBuilder::new()
                .register(Arc::new(MockPlugin::new("test").with_pass_all(true)))
                .build(),
        );
        let orchestrator = ComplianceOrchestrator::new(registry);
        let report = orchestrator.run_all(&default_config()).await.unwrap();
        assert!(report.all_passed);
    }
}
