//! Agent layer compliance plugin.
//!
//! Evaluates agent attestation layers (`AgentMcpServers`, `AgentDependencies`,
//! `AgentCertificates`) against compliance controls for system integrity,
//! continuous monitoring, and developer testing.
//!
//! Unlike kernel or OCI plugins, this plugin does not shell out to external
//! commands. Instead it reads presence/absence flags from
//! [`PluginConfig::settings`] to determine whether agent artefacts have been
//! attested upstream. This keeps the plugin pure and fully testable without
//! mocks.

use std::future::Future;
use std::pin::Pin;

use chrono::Utc;

use crate::compliance::plugin::{
    ComplianceControl, CompliancePlugin, ControlEvaluation, ControlSeverity, DomainEvaluation,
    PluginConfig,
};
use crate::hash::Blake3Hash;

const DOMAIN: &str = "agent-attestation";

/// Control definition tuple: (id, title, description, severity, required,
/// nist_control_ids, settings_key).
///
/// `settings_key` is the key looked up in [`PluginConfig::settings`]; when the
/// value is a JSON `true` the control passes.
type ControlDef = (
    &'static str,        // id
    &'static str,        // title
    &'static str,        // description
    ControlSeverity,     // severity
    bool,                // required
    &'static [&'static str], // nist_control_ids
    &'static str,        // settings_key
);

/// Required controls.
const REQUIRED_CONTROLS: &[ControlDef] = &[
    (
        "AGENT-CERT-1",
        "Agent certificates must be present",
        "The AgentCertificates layer must contain at least one certificate attestation",
        ControlSeverity::High,
        true,
        &["SI-7", "CA-7"],
        "agent_certificates_present",
    ),
    (
        "AGENT-CERT-2",
        "Agent certificate chain must be non-empty",
        "The certificate chain in the AgentCertificates layer must contain at least one entry to ensure provenance",
        ControlSeverity::Critical,
        true,
        &["SI-7", "SA-11"],
        "agent_certificate_chain_present",
    ),
    (
        "AGENT-DEP-1",
        "Agent SBOM must be present",
        "The AgentDependencies layer must include a software bill of materials attestation",
        ControlSeverity::High,
        true,
        &["SA-11", "SI-7"],
        "agent_dependencies_present",
    ),
    (
        "AGENT-DEP-2",
        "Agent lock file attestation required",
        "The AgentDependencies layer must attest the lock file hash for reproducible builds",
        ControlSeverity::Medium,
        true,
        &["CA-7", "SA-11"],
        "agent_lock_file_present",
    ),
    (
        "AGENT-MCP-1",
        "MCP server configurations must be attested",
        "The AgentMcpServers layer must include attestation of all MCP server configurations",
        ControlSeverity::High,
        true,
        &["SI-7", "CA-7"],
        "agent_mcp_servers_present",
    ),
    (
        "AGENT-MCP-2",
        "MCP server registry manifest required",
        "The AgentMcpServers layer must include an attested registry manifest listing all servers",
        ControlSeverity::Medium,
        true,
        &["CA-7", "SA-11"],
        "agent_mcp_registry_present",
    ),
];

/// Agent layer compliance plugin.
///
/// Evaluates agent attestation layers against compliance controls by checking
/// presence flags in [`PluginConfig::settings`].
pub struct AgentLayerPlugin;

impl AgentLayerPlugin {
    /// Create a new agent layer plugin.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for AgentLayerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

fn make_control(def: &ControlDef) -> ComplianceControl {
    let &(id, title, desc, ref severity, required, nist_ids, _settings_key) = def;
    ComplianceControl {
        id: id.to_string(),
        title: title.to_string(),
        description: desc.to_string(),
        severity: severity.clone(),
        nist_control_ids: nist_ids.iter().map(|s| (*s).to_string()).collect(),
        domain: DOMAIN.to_string(),
        required,
    }
}

/// Check whether a settings key is present and set to JSON `true`.
fn setting_is_true(config: &PluginConfig, key: &str) -> bool {
    config
        .settings
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

impl CompliancePlugin for AgentLayerPlugin {
    fn domain(&self) -> &str {
        DOMAIN
    }

    fn nist_families(&self) -> Vec<String> {
        vec![
            "SI-7".to_string(),  // System and Information Integrity — Software Integrity
            "CA-7".to_string(),  // Continuous Monitoring
            "SA-11".to_string(), // Developer Testing and Evaluation
        ]
    }

    fn generate_controls(&self, _config: &PluginConfig) -> Vec<ComplianceControl> {
        REQUIRED_CONTROLS.iter().map(make_control).collect()
    }

    fn evaluate(
        &self,
        controls: &[ComplianceControl],
        config: &PluginConfig,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<DomainEvaluation>> + Send + '_>> {
        let controls = controls.to_vec();
        let config = config.clone();
        Box::pin(async move {
            let now = Utc::now();
            let mut evaluations = Vec::with_capacity(controls.len());

            for control in &controls {
                let start = std::time::Instant::now();

                // Find the matching definition to retrieve the settings_key.
                let settings_key = REQUIRED_CONTROLS
                    .iter()
                    .find(|d| d.0 == control.id)
                    .map(|d| d.6);

                let (passed, message) = match settings_key {
                    Some(key) => {
                        let present = setting_is_true(&config, key);
                        if present {
                            (true, format!("{}: attestation present", control.id))
                        } else {
                            (
                                false,
                                format!(
                                    "{}: attestation missing (settings key '{}' not set to true)",
                                    control.id, key
                                ),
                            )
                        }
                    }
                    None => (false, format!("Unknown control: {}", control.id)),
                };

                let duration_ms = start.elapsed().as_millis() as u64;

                evaluations.push(ControlEvaluation {
                    control: control.clone(),
                    passed,
                    message: message.clone(),
                    evidence_hash: Some(Blake3Hash::digest(message.as_bytes())),
                    evaluated_at: now,
                    duration_ms,
                });
            }

            let domain_hash = DomainEvaluation::compute_domain_hash(DOMAIN, &evaluations);
            let total_duration_ms = evaluations.iter().map(|e| e.duration_ms).sum();
            let all_required_passed = evaluations
                .iter()
                .all(|e| !e.control.required || e.passed);

            Ok(DomainEvaluation {
                domain: DOMAIN.to_string(),
                evaluations,
                domain_hash,
                completed_at: Utc::now(),
                total_duration_ms,
                all_required_passed,
            })
        })
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn default_config() -> PluginConfig {
        PluginConfig::default()
    }

    fn all_present_config() -> PluginConfig {
        let mut settings = BTreeMap::new();
        settings.insert(
            "agent_certificates_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_certificate_chain_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_dependencies_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_lock_file_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_mcp_servers_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_mcp_registry_present".to_string(),
            serde_json::json!(true),
        );
        PluginConfig {
            settings,
            ..PluginConfig::default()
        }
    }

    // ── 1. Controls are not empty ──────────────────────────────────────

    #[test]
    fn controls_not_empty() {
        let plugin = AgentLayerPlugin::new();
        let controls = plugin.generate_controls(&default_config());
        assert!(!controls.is_empty());
        assert_eq!(controls.len(), 6);
    }

    // ── 2. Domain name is correct ──────────────────────────────────────

    #[test]
    fn domain_name_correct() {
        let plugin = AgentLayerPlugin::new();
        assert_eq!(plugin.domain(), "agent-attestation");
    }

    // ── 3. Control IDs are unique ──────────────────────────────────────

    #[test]
    fn control_ids_unique() {
        let plugin = AgentLayerPlugin::new();
        let controls = plugin.generate_controls(&default_config());
        let mut ids: Vec<&str> = controls.iter().map(|c| c.id.as_str()).collect();
        let original_len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "control IDs must be unique");
    }

    // ── 4. All settings present → all controls pass ────────────────────

    #[tokio::test]
    async fn evaluate_all_present_passes() {
        let plugin = AgentLayerPlugin::new();
        let config = all_present_config();
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        assert!(result.all_required_passed);
        assert_eq!(result.domain, "agent-attestation");
        for eval in &result.evaluations {
            assert!(eval.passed, "control {} should pass", eval.control.id);
        }
    }

    // ── 5. Missing certificates → cert controls fail ───────────────────

    #[tokio::test]
    async fn evaluate_missing_certificates_fails() {
        let plugin = AgentLayerPlugin::new();
        // Omit certificate keys
        let mut settings = BTreeMap::new();
        settings.insert(
            "agent_dependencies_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_lock_file_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_mcp_servers_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_mcp_registry_present".to_string(),
            serde_json::json!(true),
        );
        let config = PluginConfig {
            settings,
            ..PluginConfig::default()
        };

        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        assert!(!result.all_required_passed);

        let cert_evals: Vec<_> = result
            .evaluations
            .iter()
            .filter(|e| e.control.id.starts_with("AGENT-CERT"))
            .collect();
        assert!(cert_evals.iter().all(|e| !e.passed));

        // Non-cert controls should still pass.
        let non_cert: Vec<_> = result
            .evaluations
            .iter()
            .filter(|e| !e.control.id.starts_with("AGENT-CERT"))
            .collect();
        assert!(non_cert.iter().all(|e| e.passed));
    }

    // ── 6. Missing dependencies → dep controls fail ────────────────────

    #[tokio::test]
    async fn evaluate_missing_dependencies_fails() {
        let plugin = AgentLayerPlugin::new();
        // Omit dependency keys
        let mut settings = BTreeMap::new();
        settings.insert(
            "agent_certificates_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_certificate_chain_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_mcp_servers_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_mcp_registry_present".to_string(),
            serde_json::json!(true),
        );
        let config = PluginConfig {
            settings,
            ..PluginConfig::default()
        };

        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        assert!(!result.all_required_passed);

        let dep_evals: Vec<_> = result
            .evaluations
            .iter()
            .filter(|e| e.control.id.starts_with("AGENT-DEP"))
            .collect();
        assert!(dep_evals.iter().all(|e| !e.passed));

        // Non-dep controls should still pass.
        let non_dep: Vec<_> = result
            .evaluations
            .iter()
            .filter(|e| !e.control.id.starts_with("AGENT-DEP"))
            .collect();
        assert!(non_dep.iter().all(|e| e.passed));
    }

    // ── 7. Serde roundtrip on controls ─────────────────────────────────

    #[test]
    fn controls_serde_roundtrip() {
        let plugin = AgentLayerPlugin::new();
        let controls = plugin.generate_controls(&default_config());
        let json = serde_json::to_string(&controls).unwrap();
        let back: Vec<ComplianceControl> = serde_json::from_str(&json).unwrap();
        assert_eq!(controls, back);
    }

    // ── 8. NIST families correct ───────────────────────────────────────

    #[test]
    fn nist_families_correct() {
        let plugin = AgentLayerPlugin::new();
        let families = plugin.nist_families();
        assert!(families.contains(&"SI-7".to_string()));
        assert!(families.contains(&"CA-7".to_string()));
        assert!(families.contains(&"SA-11".to_string()));
    }

    // ── 9. Plugin is always available ──────────────────────────────────

    #[test]
    fn plugin_always_available() {
        let plugin = AgentLayerPlugin::new();
        assert!(plugin.is_available());
    }

    // ── 10. Default constructor via Default trait ───────────────────────

    #[test]
    fn default_trait_works() {
        let plugin = AgentLayerPlugin::default();
        assert_eq!(plugin.domain(), "agent-attestation");
    }

    // ── 11. Empty settings → all fail ──────────────────────────────────

    #[tokio::test]
    async fn evaluate_empty_settings_all_fail() {
        let plugin = AgentLayerPlugin::new();
        let config = default_config();
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        assert!(!result.all_required_passed);
        for eval in &result.evaluations {
            assert!(!eval.passed, "control {} should fail", eval.control.id);
        }
    }

    // ── 12. Evidence hashes are present ────────────────────────────────

    #[tokio::test]
    async fn evidence_hashes_present() {
        let plugin = AgentLayerPlugin::new();
        let config = all_present_config();
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        for eval in &result.evaluations {
            assert!(
                eval.evidence_hash.is_some(),
                "evidence hash missing for {}",
                eval.control.id
            );
        }
    }

    // ── 13. Domain hash is deterministic ───────────────────────────────

    #[tokio::test]
    async fn domain_hash_deterministic() {
        let plugin = AgentLayerPlugin::new();
        let config = all_present_config();
        let controls = plugin.generate_controls(&config);

        let r1 = plugin.evaluate(&controls, &config).await.unwrap();
        let r2 = plugin.evaluate(&controls, &config).await.unwrap();

        assert_eq!(r1.domain_hash, r2.domain_hash);
    }

    // ── 14. All controls belong to the correct domain ──────────────────

    #[test]
    fn all_controls_belong_to_domain() {
        let plugin = AgentLayerPlugin::new();
        let controls = plugin.generate_controls(&default_config());
        for control in &controls {
            assert_eq!(
                control.domain, "agent-attestation",
                "control {} has wrong domain",
                control.id
            );
        }
    }

    // ── 15. Missing MCP → MCP controls fail ────────────────────────────

    #[tokio::test]
    async fn evaluate_missing_mcp_fails() {
        let plugin = AgentLayerPlugin::new();
        // Omit MCP keys
        let mut settings = BTreeMap::new();
        settings.insert(
            "agent_certificates_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_certificate_chain_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_dependencies_present".to_string(),
            serde_json::json!(true),
        );
        settings.insert(
            "agent_lock_file_present".to_string(),
            serde_json::json!(true),
        );
        let config = PluginConfig {
            settings,
            ..PluginConfig::default()
        };

        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        assert!(!result.all_required_passed);

        let mcp_evals: Vec<_> = result
            .evaluations
            .iter()
            .filter(|e| e.control.id.starts_with("AGENT-MCP"))
            .collect();
        assert!(mcp_evals.iter().all(|e| !e.passed));

        // Non-MCP controls should still pass.
        let non_mcp: Vec<_> = result
            .evaluations
            .iter()
            .filter(|e| !e.control.id.starts_with("AGENT-MCP"))
            .collect();
        assert!(non_mcp.iter().all(|e| e.passed));
    }
}
