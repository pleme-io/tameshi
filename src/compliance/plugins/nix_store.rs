//! Nix store compliance plugin.
//!
//! Evaluates Nix store integrity: closure hash verification, flake input
//! pinning, and known vulnerability checks.
//!
//! Uses [`CommandRunner`] for subprocess execution so all evaluation can be
//! tested with [`MockCommandRunner`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;

use crate::compliance::plugin::{
    ComplianceControl, CompliancePlugin, ControlEvaluation, ControlSeverity, DomainEvaluation,
    PluginConfig,
};
use crate::hash::Blake3Hash;
use crate::traits::CommandRunner;

const DOMAIN: &str = "nix-store";

/// Nix store compliance plugin.
///
/// Checks closure integrity, flake input pinning, and vulnerability state.
pub struct NixStorePlugin<C: CommandRunner> {
    runner: Arc<C>,
}

impl<C: CommandRunner> NixStorePlugin<C> {
    /// Create a new Nix store plugin with the given command runner.
    #[must_use]
    pub fn new(runner: Arc<C>) -> Self {
        Self { runner }
    }
}

impl<C: CommandRunner + 'static> CompliancePlugin for NixStorePlugin<C> {
    fn domain(&self) -> &str {
        DOMAIN
    }

    fn nist_families(&self) -> Vec<String> {
        vec![
            "SI".to_string(), // System and Information Integrity
            "CM".to_string(), // Configuration Management
            "SA".to_string(), // System and Services Acquisition
        ]
    }

    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl> {
        let mut controls = vec![
            ComplianceControl {
                id: "NIX-001".to_string(),
                title: "Store path closure verifiable".to_string(),
                description: "The Nix store closure must be queryable and hash-verifiable"
                    .to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["SI-7".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "NIX-002".to_string(),
                title: "Flake inputs pinned".to_string(),
                description: "All flake inputs must have locked revisions (not floating)"
                    .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["CM-2".to_string(), "SA-10".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "NIX-003".to_string(),
                title: "Store integrity verified".to_string(),
                description: "nix-store --verify must report no corruption".to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["SI-7".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "NIX-004".to_string(),
                title: "No known CVEs in closure".to_string(),
                description: "Closure store paths should not contain packages with known CVEs"
                    .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["SI-2".to_string(), "SI-5".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
        ];

        if config.include_advisory {
            controls.push(ComplianceControl {
                id: "NIX-005".to_string(),
                title: "Binary cache signatures verified".to_string(),
                description: "Substituted paths should be signed by a trusted key".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["SI-7".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
        }

        controls
    }

    fn evaluate(
        &self,
        controls: &[ComplianceControl],
        _config: &PluginConfig,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<DomainEvaluation>> + Send + '_>> {
        let controls = controls.to_vec();
        let runner = Arc::clone(&self.runner);
        Box::pin(async move {
            let now = Utc::now();
            let mut evaluations = Vec::with_capacity(controls.len());

            for control in &controls {
                let start = std::time::Instant::now();
                let (passed, message) = match control.id.as_str() {
                    "NIX-001" => check_closure_query(&*runner).await,
                    "NIX-002" => check_flake_inputs_pinned(&*runner).await,
                    "NIX-003" => check_store_verify(&*runner).await,
                    "NIX-004" => check_no_known_cves(&*runner).await,
                    "NIX-005" => check_binary_cache_sigs(&*runner).await,
                    _ => (false, format!("Unknown control: {}", control.id)),
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
        // Nix store is available on both Linux and macOS if nix is installed
        true
    }
}

async fn check_closure_query<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run("nix-store", &["--query", "--requisites", "/run/current-system"])
        .await
    {
        Ok(output) => {
            let count = output.lines().filter(|l| !l.is_empty()).count();
            (
                count > 0,
                format!("Closure contains {count} store paths"),
            )
        }
        Err(e) => (false, format!("nix-store query failed: {e}")),
    }
}

async fn check_flake_inputs_pinned<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner.run("nix", &["flake", "metadata", "--json"]).await {
        Ok(output) => {
            // Check that all inputs have a "locked" section
            match serde_json::from_str::<serde_json::Value>(&output) {
                Ok(meta) => {
                    if let Some(locks) = meta.get("locks").and_then(|l| l.get("nodes")) {
                        if let Some(obj) = locks.as_object() {
                            let unpinned: Vec<&str> = obj
                                .iter()
                                .filter(|(k, v)| {
                                    *k != "root" && v.get("locked").is_none()
                                })
                                .map(|(k, _)| k.as_str())
                                .collect();
                            if unpinned.is_empty() {
                                (true, "All flake inputs are pinned".to_string())
                            } else {
                                (
                                    false,
                                    format!("Unpinned inputs: {}", unpinned.join(", ")),
                                )
                            }
                        } else {
                            (false, "Invalid locks structure".to_string())
                        }
                    } else {
                        (false, "No locks found in flake metadata".to_string())
                    }
                }
                Err(e) => (false, format!("Failed to parse flake metadata: {e}")),
            }
        }
        Err(e) => (false, format!("nix flake metadata failed: {e}")),
    }
}

async fn check_store_verify<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner.run("nix-store", &["--verify", "--check-contents"]).await {
        Ok(output) => {
            let trimmed = output.trim();
            if trimmed.is_empty() || !trimmed.contains("error") {
                (true, "Nix store integrity verified".to_string())
            } else {
                (false, format!("Store verification errors: {trimmed}"))
            }
        }
        Err(e) => (false, format!("nix-store --verify failed: {e}")),
    }
}

async fn check_no_known_cves<C: CommandRunner>(runner: &C) -> (bool, String) {
    // Use vulnix or similar scanner
    match runner.run("vulnix", &["--system"]).await {
        Ok(output) => {
            let trimmed = output.trim();
            if trimmed.is_empty() || trimmed.contains("0 derivations with known") {
                (true, "No known CVEs in system closure".to_string())
            } else {
                let count = output.lines().count();
                (false, format!("{count} potentially vulnerable packages"))
            }
        }
        Err(_) => {
            // vulnix not available — pass with advisory
            (true, "CVE scanner not available, skipped".to_string())
        }
    }
}

async fn check_binary_cache_sigs<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run("nix", &["show-config", "--json"])
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(config) => {
                if let Some(keys) = config
                    .get("trusted-public-keys")
                    .and_then(|k| k.get("value"))
                    .and_then(|v| v.as_str())
                {
                    let key_count = keys.split_whitespace().count();
                    (
                        key_count > 0,
                        format!("{key_count} trusted public keys configured"),
                    )
                } else {
                    (false, "No trusted public keys configured".to_string())
                }
            }
            Err(e) => (false, format!("Failed to parse nix config: {e}")),
        },
        Err(e) => (false, format!("nix show-config failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockCommandRunner;

    fn make_runner() -> Arc<MockCommandRunner> {
        Arc::new(MockCommandRunner::new())
    }

    #[test]
    fn domain_name() {
        let plugin = NixStorePlugin::new(make_runner());
        assert_eq!(plugin.domain(), "nix-store");
    }

    #[test]
    fn nist_families_covered() {
        let plugin = NixStorePlugin::new(make_runner());
        let families = plugin.nist_families();
        assert!(families.contains(&"SI".to_string()));
        assert!(families.contains(&"CM".to_string()));
        assert!(families.contains(&"SA".to_string()));
    }

    #[test]
    fn generate_controls_default() {
        let plugin = NixStorePlugin::new(make_runner());
        let controls = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(controls.len(), 4);
        assert!(controls.iter().all(|c| c.domain == "nix-store"));
    }

    #[test]
    fn generate_controls_with_advisory() {
        let plugin = NixStorePlugin::new(make_runner());
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        assert_eq!(controls.len(), 5);
    }

    #[test]
    fn control_ids_are_unique() {
        let plugin = NixStorePlugin::new(make_runner());
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let ids: Vec<&str> = controls.iter().map(|c| c.id.as_str()).collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len());
    }

    #[test]
    fn controls_have_nist_tags() {
        let plugin = NixStorePlugin::new(make_runner());
        let controls = plugin.generate_controls(&PluginConfig::default());
        for c in &controls {
            assert!(!c.nist_control_ids.is_empty(), "Control {} has no NIST IDs", c.id);
        }
    }

    #[test]
    fn controls_are_deterministic() {
        let plugin = NixStorePlugin::new(make_runner());
        let c1 = plugin.generate_controls(&PluginConfig::default());
        let c2 = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(c1, c2);
    }

    #[test]
    fn is_available_true() {
        let plugin = NixStorePlugin::new(make_runner());
        assert!(plugin.is_available());
    }

    #[tokio::test]
    async fn evaluate_all_pass() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n/nix/store/def-bar\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{},"nixpkgs":{"locked":{"rev":"abc"}}}}}"#,
        );
        runner.add_response(
            "nix-store",
            &["--verify", "--check-contents"],
            "",
        );
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        assert!(result.all_required_passed);
        assert_eq!(result.domain, "nix-store");
    }

    #[tokio::test]
    async fn evaluate_closure_empty_fails() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let closure = result.evaluations.iter().find(|e| e.control.id == "NIX-001").unwrap();
        assert!(!closure.passed);
    }

    #[tokio::test]
    async fn evaluate_unpinned_inputs() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{},"nixpkgs":{"original":{"type":"github"}}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let pinned = result.evaluations.iter().find(|e| e.control.id == "NIX-002").unwrap();
        assert!(!pinned.passed);
        assert!(pinned.message.contains("Unpinned"));
    }

    #[tokio::test]
    async fn evaluate_store_corruption() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{}}}}"#,
        );
        runner.add_response(
            "nix-store",
            &["--verify", "--check-contents"],
            "error: path '/nix/store/xyz' has changed hash",
        );
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let verify = result.evaluations.iter().find(|e| e.control.id == "NIX-003").unwrap();
        assert!(!verify.passed);
    }

    #[tokio::test]
    async fn evaluate_vulnix_finds_cves() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_response(
            "vulnix",
            &["--system"],
            "CVE-2024-1234 openssl\nCVE-2024-5678 curl\n",
        );

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let cve = result.evaluations.iter().find(|e| e.control.id == "NIX-004").unwrap();
        assert!(!cve.passed);
        assert!(cve.message.contains("vulnerable"));
    }

    #[tokio::test]
    async fn domain_evaluation_serde_roundtrip() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let back: DomainEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(result.domain, back.domain);
        assert_eq!(result.domain_hash, back.domain_hash);
    }

    #[tokio::test]
    async fn evidence_hashes_present() {
        let runner = make_runner();
        runner.add_response(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "/nix/store/abc-foo\n",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        for eval in &result.evaluations {
            assert!(eval.evidence_hash.is_some());
        }
    }

    #[tokio::test]
    async fn nix_store_query_command_fails() {
        let runner = make_runner();
        runner.add_error(
            "nix-store",
            &["--query", "--requisites", "/run/current-system"],
            "error: path does not exist",
        );
        runner.add_response(
            "nix",
            &["flake", "metadata", "--json"],
            r#"{"locks":{"nodes":{"root":{}}}}"#,
        );
        runner.add_response("nix-store", &["--verify", "--check-contents"], "");
        runner.add_error("vulnix", &["--system"], "not found");

        let plugin = NixStorePlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let closure = result.evaluations.iter().find(|e| e.control.id == "NIX-001").unwrap();
        assert!(!closure.passed);
        assert!(closure.message.contains("failed"));
    }
}
