//! Kernel hardening compliance plugin.
//!
//! Evaluates Linux kernel security controls: sysctl parameters, loaded kernel
//! modules, and mandatory access control (SELinux/AppArmor) enforcement.
//!
//! Uses [`CommandRunner`] for subprocess execution so all evaluation can be
//! tested with [`MockCommandRunner`] — no real Linux kernel needed.

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

const DOMAIN: &str = "kernel";

/// Kernel hardening compliance plugin.
///
/// Checks sysctl parameters, kernel module loading, and MAC enforcement.
pub struct KernelPlugin<C: CommandRunner> {
    runner: Arc<C>,
}

impl<C: CommandRunner> KernelPlugin<C> {
    /// Create a new kernel plugin with the given command runner.
    #[must_use]
    pub fn new(runner: Arc<C>) -> Self {
        Self { runner }
    }
}

impl<C: CommandRunner + 'static> CompliancePlugin for KernelPlugin<C> {
    fn domain(&self) -> &str {
        DOMAIN
    }

    fn nist_families(&self) -> Vec<String> {
        vec![
            "SC".to_string(), // System and Communications Protection
            "CM".to_string(), // Configuration Management
            "SI".to_string(), // System and Information Integrity
        ]
    }

    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl> {
        let mut controls = vec![
            ComplianceControl {
                id: "KERN-001".to_string(),
                title: "IP forwarding disabled".to_string(),
                description: "net.ipv4.ip_forward must be 0 to prevent packet forwarding"
                    .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["SC-7".to_string(), "CM-6".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "KERN-002".to_string(),
                title: "ASLR fully enabled".to_string(),
                description: "kernel.randomize_va_space must be 2 for full ASLR".to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["SI-16".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "KERN-003".to_string(),
                title: "SYN cookies enabled".to_string(),
                description: "net.ipv4.tcp_syncookies must be 1 to mitigate SYN floods"
                    .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["SC-5".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "KERN-004".to_string(),
                title: "Core dumps restricted".to_string(),
                description: "fs.suid_dumpable must be 0 to prevent SUID core dumps".to_string(),
                severity: ControlSeverity::Medium,
                nist_control_ids: vec!["CM-6".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "KERN-005".to_string(),
                title: "MAC enforcement active".to_string(),
                description:
                    "SELinux or AppArmor must be in enforcing mode for mandatory access control"
                        .to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["AC-3".to_string(), "SC-3".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
        ];

        if config.include_advisory {
            controls.push(ComplianceControl {
                id: "KERN-006".to_string(),
                title: "Kernel module loading restricted".to_string(),
                description: "kernel.modules_disabled should be 1 on hardened systems".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["CM-7".to_string()],
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

            // Fetch sysctl output once
            let sysctl_output = runner.run("sysctl", &["-a"]).await;

            for control in &controls {
                let start = std::time::Instant::now();
                let (passed, message) = match control.id.as_str() {
                    "KERN-001" => check_sysctl(&sysctl_output, "net.ipv4.ip_forward", "0"),
                    "KERN-002" => {
                        check_sysctl(&sysctl_output, "kernel.randomize_va_space", "2")
                    }
                    "KERN-003" => {
                        check_sysctl(&sysctl_output, "net.ipv4.tcp_syncookies", "1")
                    }
                    "KERN-004" => check_sysctl(&sysctl_output, "fs.suid_dumpable", "0"),
                    "KERN-005" => check_mac_enforcement(&*runner).await,
                    "KERN-006" => {
                        check_sysctl(&sysctl_output, "kernel.modules_disabled", "1")
                    }
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
        cfg!(target_os = "linux")
    }
}

fn check_sysctl(
    output: &crate::error::Result<String>,
    key: &str,
    expected: &str,
) -> (bool, String) {
    match output {
        Ok(text) => {
            for line in text.lines() {
                // sysctl -a output: "key = value"
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim();
                    if k == key {
                        let passed = v == expected;
                        return (
                            passed,
                            format!("{key} = {v} (expected {expected})"),
                        );
                    }
                }
            }
            (false, format!("{key}: not found in sysctl output"))
        }
        Err(e) => (false, format!("sysctl failed: {e}")),
    }
}

async fn check_mac_enforcement<C: CommandRunner>(runner: &C) -> (bool, String) {
    // Try SELinux first
    match runner.run("getenforce", &[]).await {
        Ok(output) => {
            let mode = output.trim();
            let passed = mode == "Enforcing";
            return (passed, format!("SELinux: {mode}"));
        }
        Err(_) => {}
    }
    // Try AppArmor
    match runner.run("aa-status", &["--enabled"]).await {
        Ok(_) => (true, "AppArmor: enabled".to_string()),
        Err(_) => (false, "No MAC enforcement detected (SELinux/AppArmor)".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockCommandRunner;

    fn make_sysctl_output(params: &[(&str, &str)]) -> String {
        params
            .iter()
            .map(|(k, v)| format!("{k} = {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn make_runner_with_sysctl(params: &[(&str, &str)]) -> Arc<MockCommandRunner> {
        let runner = MockCommandRunner::new();
        runner.add_response("sysctl", &["-a"], &make_sysctl_output(params));
        Arc::new(runner)
    }

    #[test]
    fn domain_name() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        assert_eq!(plugin.domain(), "kernel");
    }

    #[test]
    fn nist_families_covered() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let families = plugin.nist_families();
        assert!(families.contains(&"SC".to_string()));
        assert!(families.contains(&"CM".to_string()));
        assert!(families.contains(&"SI".to_string()));
    }

    #[test]
    fn generate_controls_default() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(controls.len(), 5);
        assert!(controls.iter().all(|c| c.domain == "kernel"));
    }

    #[test]
    fn generate_controls_with_advisory() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        assert_eq!(controls.len(), 6);
        assert!(!controls.last().unwrap().required);
    }

    #[test]
    fn control_ids_are_unique() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
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
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        for c in &controls {
            assert!(!c.nist_control_ids.is_empty(), "Control {} has no NIST IDs", c.id);
        }
    }

    #[test]
    fn controls_are_deterministic() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let c1 = plugin.generate_controls(&PluginConfig::default());
        let c2 = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(c1, c2);
    }

    #[tokio::test]
    async fn evaluate_all_pass() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        // Add SELinux enforcing
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        assert!(result.all_required_passed);
        assert_eq!(result.domain, "kernel");
        assert_eq!(result.evaluations.len(), 5);
        for eval in &result.evaluations {
            assert!(eval.passed, "Control {} should pass: {}", eval.control.id, eval.message);
        }
    }

    #[tokio::test]
    async fn evaluate_ip_forward_enabled_fails() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "1"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        assert!(!result.all_required_passed);
        let ip_fwd = result.evaluations.iter().find(|e| e.control.id == "KERN-001").unwrap();
        assert!(!ip_fwd.passed);
        assert!(ip_fwd.message.contains("1"));
    }

    #[tokio::test]
    async fn evaluate_sysctl_not_found() {
        let runner = make_runner_with_sysctl(&[
            // Missing net.ipv4.ip_forward
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let ip_fwd = result.evaluations.iter().find(|e| e.control.id == "KERN-001").unwrap();
        assert!(!ip_fwd.passed);
        assert!(ip_fwd.message.contains("not found"));
    }

    #[tokio::test]
    async fn evaluate_sysctl_command_fails() {
        let runner = Arc::new(MockCommandRunner::new());
        runner.add_error("sysctl", &["-a"], "permission denied");
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        // Sysctl controls should all fail
        for eval in result.evaluations.iter().filter(|e| e.control.id != "KERN-005") {
            assert!(!eval.passed, "{} should fail when sysctl fails", eval.control.id);
        }
    }

    #[tokio::test]
    async fn evaluate_mac_selinux_permissive() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_response("getenforce", &[], "Permissive\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let mac = result.evaluations.iter().find(|e| e.control.id == "KERN-005").unwrap();
        assert!(!mac.passed);
        assert!(mac.message.contains("Permissive"));
    }

    #[tokio::test]
    async fn evaluate_mac_apparmor_fallback() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_error("getenforce", &[], "not found");
        runner.add_response("aa-status", &["--enabled"], "Yes\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let mac = result.evaluations.iter().find(|e| e.control.id == "KERN-005").unwrap();
        assert!(mac.passed);
        assert!(mac.message.contains("AppArmor"));
    }

    #[tokio::test]
    async fn evaluate_no_mac() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_error("getenforce", &[], "not found");
        runner.add_error("aa-status", &["--enabled"], "not found");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let mac = result.evaluations.iter().find(|e| e.control.id == "KERN-005").unwrap();
        assert!(!mac.passed);
    }

    #[test]
    fn is_available_matches_platform() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        // On macOS, should be false; on Linux, should be true
        assert_eq!(plugin.is_available(), cfg!(target_os = "linux"));
    }

    #[tokio::test]
    async fn domain_evaluation_serde_roundtrip() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let back: DomainEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(result.domain, back.domain);
        assert_eq!(result.domain_hash, back.domain_hash);
        assert_eq!(result.evaluations.len(), back.evaluations.len());
    }

    #[tokio::test]
    async fn evidence_hashes_present() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
        ]);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        for eval in &result.evaluations {
            assert!(eval.evidence_hash.is_some());
        }
    }

    #[tokio::test]
    async fn advisory_control_evaluation() {
        let runner = make_runner_with_sysctl(&[
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
            ("kernel.modules_disabled", "0"), // Not restricted
        ]);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        // Advisory control fails but all_required_passed is still true
        let advisory = result.evaluations.iter().find(|e| e.control.id == "KERN-006").unwrap();
        assert!(!advisory.passed);
        assert!(result.all_required_passed);
    }
}
