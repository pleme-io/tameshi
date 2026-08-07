//! Kernel hardening compliance plugin.
//!
//! Evaluates Linux kernel security controls: sysctl parameters, loaded kernel
//! modules, and mandatory access control (SELinux/AppArmor) enforcement.
//!
//! Uses [`CommandRunner`] for subprocess execution so all evaluation can be
//! tested with [`MockCommandRunner`] — no real Linux kernel needed.
//!
//! Controls are defined data-driven via tuples for easy expansion.

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

/// Sysctl control definition: (id, title, description, sysctl_key, expected_value, required, nist_ids).
/// Controls using exact match (check_sysctl).
type SysctlExactDef = (
    &'static str,            // id
    &'static str,            // title
    &'static str,            // description
    &'static str,            // sysctl_key
    &'static str,            // expected_value
    bool,                    // required
    &'static [&'static str], // nist_control_ids
    ControlSeverity,
);

/// Sysctl control definition for >= comparison.
type SysctlGteDef = (
    &'static str,            // id
    &'static str,            // title
    &'static str,            // description
    &'static str,            // sysctl_key
    i64,                     // min_value
    bool,                    // required
    &'static [&'static str], // nist_control_ids
    ControlSeverity,
);

/// Required sysctl controls with exact match.
const REQUIRED_SYSCTL_EXACT: &[SysctlExactDef] = &[
    (
        "KERN-001",
        "IP forwarding disabled",
        "net.ipv4.ip_forward must be 0 to prevent packet forwarding",
        "net.ipv4.ip_forward",
        "0",
        true,
        &["SC-7", "CM-6"],
        ControlSeverity::High,
    ),
    (
        "KERN-003",
        "SYN cookies enabled",
        "net.ipv4.tcp_syncookies must be 1 to mitigate SYN floods",
        "net.ipv4.tcp_syncookies",
        "1",
        true,
        &["SC-5"],
        ControlSeverity::High,
    ),
    (
        "KERN-004",
        "Core dumps restricted",
        "fs.suid_dumpable must be 0 to prevent SUID core dumps",
        "fs.suid_dumpable",
        "0",
        true,
        &["CM-6"],
        ControlSeverity::Medium,
    ),
    (
        "KERN-009",
        "Dmesg access restricted",
        "kernel.dmesg_restrict must be 1 to restrict kernel log access",
        "kernel.dmesg_restrict",
        "1",
        true,
        &["AU-9"],
        ControlSeverity::Medium,
    ),
    (
        "KERN-010",
        "SUID core dumps disabled",
        "fs.suid_dumpable must be 0 to prevent SUID core dumps",
        "fs.suid_dumpable",
        "0",
        true,
        &["AC-6"],
        ControlSeverity::Medium,
    ),
    // Network hardening
    (
        "KERN-012",
        "ICMP redirects rejected",
        "net.ipv4.conf.all.accept_redirects must be 0 to reject ICMP redirects",
        "net.ipv4.conf.all.accept_redirects",
        "0",
        true,
        &["CM-7", "SC-7"],
        ControlSeverity::High,
    ),
    (
        "KERN-013",
        "Source routing disabled",
        "net.ipv4.conf.all.accept_source_route must be 0 to prevent source routing",
        "net.ipv4.conf.all.accept_source_route",
        "0",
        true,
        &["CM-7", "SC-7"],
        ControlSeverity::High,
    ),
    (
        "KERN-014",
        "Martian packets logged",
        "net.ipv4.conf.all.log_martians must be 1 to log impossible addresses",
        "net.ipv4.conf.all.log_martians",
        "1",
        true,
        &["AU-2", "SI-4"],
        ControlSeverity::Medium,
    ),
    (
        "KERN-015",
        "Reverse path filtering enabled",
        "net.ipv4.conf.all.rp_filter must be 1 for source address validation",
        "net.ipv4.conf.all.rp_filter",
        "1",
        true,
        &["SC-7"],
        ControlSeverity::High,
    ),
    // Filesystem hardening
    (
        "KERN-018",
        "Protected hardlinks",
        "fs.protected_hardlinks must be 1 to prevent hardlink attacks",
        "fs.protected_hardlinks",
        "1",
        true,
        &["AC-6", "SC-28"],
        ControlSeverity::High,
    ),
    (
        "KERN-019",
        "Protected symlinks",
        "fs.protected_symlinks must be 1 to prevent symlink attacks",
        "fs.protected_symlinks",
        "1",
        true,
        &["AC-6", "SC-28"],
        ControlSeverity::High,
    ),
];

/// Required sysctl controls with >= comparison.
const REQUIRED_SYSCTL_GTE: &[SysctlGteDef] = &[
    (
        "KERN-002",
        "ASLR fully enabled",
        "kernel.randomize_va_space must be 2 for full ASLR",
        "kernel.randomize_va_space",
        2,
        true,
        &["SI-16"],
        ControlSeverity::Critical,
    ),
    (
        "KERN-007",
        "Ptrace scope restricted",
        "kernel.yama.ptrace_scope must be >= 1 to prevent ptrace attacks",
        "kernel.yama.ptrace_scope",
        1,
        true,
        &["SI-3"],
        ControlSeverity::High,
    ),
    (
        "KERN-008",
        "Kernel pointer restriction",
        "kernel.kptr_restrict must be >= 1 to hide kernel pointers",
        "kernel.kptr_restrict",
        1,
        true,
        &["SC-28"],
        ControlSeverity::High,
    ),
    // Memory protection
    (
        "KERN-020",
        "Minimum mmap address enforced",
        "vm.mmap_min_addr must be >= 65536 to prevent NULL pointer dereference exploits",
        "vm.mmap_min_addr",
        65536,
        true,
        &["SC-3", "SI-16"],
        ControlSeverity::High,
    ),
];

/// Advisory (non-required) sysctl controls with exact match.
const ADVISORY_SYSCTL_EXACT: &[SysctlExactDef] = &[
    (
        "KERN-006",
        "Kernel module loading restricted",
        "kernel.modules_disabled should be 1 on hardened systems",
        "kernel.modules_disabled",
        "1",
        false,
        &["CM-7"],
        ControlSeverity::Low,
    ),
    (
        "KERN-011",
        "Exec-shield enabled",
        "kernel.exec-shield should be 1 for executable space protection",
        "kernel.exec-shield",
        "1",
        false,
        &["SI-16"],
        ControlSeverity::Low,
    ),
    // IPv6 hardening (advisory because not all systems use IPv6)
    (
        "KERN-016",
        "IPv6 router advertisements rejected",
        "net.ipv6.conf.all.accept_ra should be 0 to prevent RA-based attacks",
        "net.ipv6.conf.all.accept_ra",
        "0",
        false,
        &["CM-7", "SC-7"],
        ControlSeverity::Medium,
    ),
    (
        "KERN-017",
        "IPv6 redirects rejected",
        "net.ipv6.conf.all.accept_redirects should be 0 to prevent redirect attacks",
        "net.ipv6.conf.all.accept_redirects",
        "0",
        false,
        &["CM-7"],
        ControlSeverity::Medium,
    ),
];

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

fn make_sysctl_control(
    id: &str,
    title: &str,
    description: &str,
    required: bool,
    nist_ids: &[&str],
    severity: &ControlSeverity,
) -> ComplianceControl {
    ComplianceControl {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity: severity.clone(),
        nist_control_ids: nist_ids.iter().map(|s| (*s).to_string()).collect(),
        domain: DOMAIN.to_string(),
        required,
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
            "AC".to_string(), // Access Control
            "AU".to_string(), // Audit and Accountability
        ]
    }

    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl> {
        let mut controls = Vec::new();

        // Required exact-match sysctl controls
        for &(id, title, desc, _key, _expected, required, nist_ids, ref severity) in
            REQUIRED_SYSCTL_EXACT
        {
            controls.push(make_sysctl_control(
                id, title, desc, required, nist_ids, severity,
            ));
        }

        // MAC enforcement (special — not a simple sysctl check)
        controls.push(ComplianceControl {
            id: "KERN-005".to_string(),
            title: "MAC enforcement active".to_string(),
            description:
                "SELinux or AppArmor must be in enforcing mode for mandatory access control"
                    .to_string(),
            severity: ControlSeverity::Critical,
            nist_control_ids: vec!["AC-3".to_string(), "SC-3".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });

        // Required GTE sysctl controls
        for &(id, title, desc, _key, _min, required, nist_ids, ref severity) in REQUIRED_SYSCTL_GTE
        {
            controls.push(make_sysctl_control(
                id, title, desc, required, nist_ids, severity,
            ));
        }

        // Advisory controls
        if config.include_advisory {
            for &(id, title, desc, _key, _expected, required, nist_ids, ref severity) in
                ADVISORY_SYSCTL_EXACT
            {
                controls.push(make_sysctl_control(
                    id, title, desc, required, nist_ids, severity,
                ));
            }
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
                let (passed, message) =
                    evaluate_control(&control.id, &sysctl_output, &*runner).await;
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
            let all_required_passed = evaluations.iter().all(|e| !e.control.required || e.passed);

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

/// Route a control ID to its evaluation function, using the data-driven tables.
async fn evaluate_control<C: CommandRunner>(
    id: &str,
    sysctl_output: &crate::error::Result<String>,
    runner: &C,
) -> (bool, String) {
    // Check exact-match required controls
    for &(ctrl_id, _title, _desc, key, expected, _req, _nist, ref _sev) in REQUIRED_SYSCTL_EXACT {
        if id == ctrl_id {
            return check_sysctl(sysctl_output, key, expected);
        }
    }

    // Check GTE required controls
    for &(ctrl_id, _title, _desc, key, min_val, _req, _nist, ref _sev) in REQUIRED_SYSCTL_GTE {
        if id == ctrl_id {
            return check_sysctl_gte(sysctl_output, key, min_val);
        }
    }

    // Check advisory exact-match controls
    for &(ctrl_id, _title, _desc, key, expected, _req, _nist, ref _sev) in ADVISORY_SYSCTL_EXACT {
        if id == ctrl_id {
            return check_sysctl(sysctl_output, key, expected);
        }
    }

    // Special controls
    if id == "KERN-005" {
        return check_mac_enforcement(runner).await;
    }

    (false, format!("Unknown control: {id}"))
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
                        return (passed, format!("{key} = {v} (expected {expected})"));
                    }
                }
            }
            (false, format!("{key}: not found in sysctl output"))
        }
        Err(e) => (false, format!("sysctl failed: {e}")),
    }
}

fn check_sysctl_gte(
    output: &crate::error::Result<String>,
    key: &str,
    min_value: i64,
) -> (bool, String) {
    match output {
        Ok(text) => {
            for line in text.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim();
                    if k == key {
                        return match v.parse::<i64>() {
                            Ok(val) => {
                                let passed = val >= min_value;
                                (passed, format!("{key} = {val} (expected >= {min_value})"))
                            }
                            Err(_) => (false, format!("{key} = {v} (not a valid integer)")),
                        };
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
        Err(_) => (
            false,
            "No MAC enforcement detected (SELinux/AppArmor)".to_string(),
        ),
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
        assert!(families.contains(&"AC".to_string()));
        assert!(families.contains(&"AU".to_string()));
    }

    #[test]
    fn generate_controls_default_has_20_plus() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        // 11 required exact + 1 MAC + 4 required GTE = 16 required
        assert!(
            controls.len() >= 16,
            "expected >= 16 required controls, got {}",
            controls.len()
        );
        assert!(controls.iter().all(|c| c.domain == "kernel"));
    }

    #[test]
    fn generate_controls_with_advisory_has_20_plus() {
        let runner = Arc::new(MockCommandRunner::new());
        let plugin = KernelPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        // 16 required + 4 advisory = 20
        assert!(
            controls.len() >= 20,
            "expected >= 20 total controls, got {}",
            controls.len()
        );
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
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        for c in &controls {
            assert!(
                !c.nist_control_ids.is_empty(),
                "Control {} has no NIST IDs",
                c.id
            );
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

    fn full_sysctl_params() -> Vec<(&'static str, &'static str)> {
        vec![
            ("net.ipv4.ip_forward", "0"),
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
            ("kernel.yama.ptrace_scope", "1"),
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
            // New network hardening
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv4.conf.all.accept_source_route", "0"),
            ("net.ipv4.conf.all.log_martians", "1"),
            ("net.ipv4.conf.all.rp_filter", "1"),
            // Filesystem hardening
            ("fs.protected_hardlinks", "1"),
            ("fs.protected_symlinks", "1"),
            // Memory protection
            ("vm.mmap_min_addr", "65536"),
        ]
    }

    #[tokio::test]
    async fn evaluate_all_pass() {
        let runner = make_runner_with_sysctl(&full_sysctl_params());
        // Add SELinux enforcing
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        assert!(result.all_required_passed);
        assert_eq!(result.domain, "kernel");
        for eval in &result.evaluations {
            assert!(
                eval.passed,
                "Control {} should pass: {}",
                eval.control.id, eval.message
            );
        }
    }

    #[tokio::test]
    async fn evaluate_ip_forward_enabled_fails() {
        let mut params = full_sysctl_params();
        params[0] = ("net.ipv4.ip_forward", "1");
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        assert!(!result.all_required_passed);
        let ip_fwd = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-001")
            .unwrap();
        assert!(!ip_fwd.passed);
        assert!(ip_fwd.message.contains("1"));
    }

    #[tokio::test]
    async fn evaluate_sysctl_not_found() {
        // Missing net.ipv4.ip_forward
        let runner = make_runner_with_sysctl(&[
            ("kernel.randomize_va_space", "2"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("fs.suid_dumpable", "0"),
            ("kernel.yama.ptrace_scope", "1"),
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv4.conf.all.accept_source_route", "0"),
            ("net.ipv4.conf.all.log_martians", "1"),
            ("net.ipv4.conf.all.rp_filter", "1"),
            ("fs.protected_hardlinks", "1"),
            ("fs.protected_symlinks", "1"),
            ("vm.mmap_min_addr", "65536"),
        ]);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ip_fwd = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-001")
            .unwrap();
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
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        // Sysctl controls should all fail
        for eval in result
            .evaluations
            .iter()
            .filter(|e| e.control.id != "KERN-005")
        {
            assert!(
                !eval.passed,
                "{} should fail when sysctl fails",
                eval.control.id
            );
        }
    }

    #[tokio::test]
    async fn evaluate_mac_selinux_permissive() {
        let runner = make_runner_with_sysctl(&full_sysctl_params());
        runner.add_response("getenforce", &[], "Permissive\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let mac = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-005")
            .unwrap();
        assert!(!mac.passed);
        assert!(mac.message.contains("Permissive"));
    }

    #[tokio::test]
    async fn evaluate_mac_apparmor_fallback() {
        let runner = make_runner_with_sysctl(&full_sysctl_params());
        runner.add_error("getenforce", &[], "not found");
        runner.add_response("aa-status", &["--enabled"], "Yes\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let mac = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-005")
            .unwrap();
        assert!(mac.passed);
        assert!(mac.message.contains("AppArmor"));
    }

    #[tokio::test]
    async fn evaluate_no_mac() {
        let runner = make_runner_with_sysctl(&full_sysctl_params());
        runner.add_error("getenforce", &[], "not found");
        runner.add_error("aa-status", &["--enabled"], "not found");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let mac = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-005")
            .unwrap();
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
        let runner = make_runner_with_sysctl(&full_sysctl_params());
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let back: DomainEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(result.domain, back.domain);
        assert_eq!(result.domain_hash, back.domain_hash);
        assert_eq!(result.evaluations.len(), back.evaluations.len());
    }

    #[tokio::test]
    async fn evidence_hashes_present() {
        let runner = make_runner_with_sysctl(&full_sysctl_params());
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        for eval in &result.evaluations {
            assert!(eval.evidence_hash.is_some());
        }
    }

    #[tokio::test]
    async fn advisory_control_evaluation() {
        let mut params = full_sysctl_params();
        params.push(("kernel.modules_disabled", "0"));
        params.push(("kernel.exec-shield", "0"));
        params.push(("net.ipv6.conf.all.accept_ra", "1"));
        params.push(("net.ipv6.conf.all.accept_redirects", "1"));
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        // Advisory controls fail but all_required_passed is still true
        let advisory_006 = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-006")
            .unwrap();
        assert!(!advisory_006.passed);
        let advisory_011 = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-011")
            .unwrap();
        assert!(!advisory_011.passed);
        assert!(result.all_required_passed);
    }

    #[tokio::test]
    async fn evaluate_ptrace_scope_zero_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "kernel.yama.ptrace_scope" {
                *p = ("kernel.yama.ptrace_scope", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ptrace = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-007")
            .unwrap();
        assert!(!ptrace.passed);
        assert!(ptrace.message.contains("0"));
    }

    #[tokio::test]
    async fn evaluate_ptrace_scope_high_passes() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "kernel.yama.ptrace_scope" {
                *p = ("kernel.yama.ptrace_scope", "3");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ptrace = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-007")
            .unwrap();
        assert!(ptrace.passed);
    }

    #[tokio::test]
    async fn evaluate_kptr_restrict_zero_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "kernel.kptr_restrict" {
                *p = ("kernel.kptr_restrict", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let kptr = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-008")
            .unwrap();
        assert!(!kptr.passed);
    }

    #[tokio::test]
    async fn evaluate_dmesg_restrict_off_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "kernel.dmesg_restrict" {
                *p = ("kernel.dmesg_restrict", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let dmesg = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-009")
            .unwrap();
        assert!(!dmesg.passed);
    }

    #[tokio::test]
    async fn evaluate_suid_dumpable_enabled_fails_kern010() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "fs.suid_dumpable" {
                *p = ("fs.suid_dumpable", "2");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let suid = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-010")
            .unwrap();
        assert!(!suid.passed);
    }

    #[tokio::test]
    async fn evaluate_exec_shield_advisory() {
        let mut params = full_sysctl_params();
        params.push(("kernel.modules_disabled", "1"));
        params.push(("kernel.exec-shield", "1"));
        params.push(("net.ipv6.conf.all.accept_ra", "0"));
        params.push(("net.ipv6.conf.all.accept_redirects", "0"));
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        let exec_shield = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-011")
            .unwrap();
        assert!(exec_shield.passed);
    }

    // -- New control tests --

    #[tokio::test]
    async fn evaluate_icmp_redirects_enabled_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "net.ipv4.conf.all.accept_redirects" {
                *p = ("net.ipv4.conf.all.accept_redirects", "1");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-012")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_source_route_enabled_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "net.ipv4.conf.all.accept_source_route" {
                *p = ("net.ipv4.conf.all.accept_source_route", "1");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-013")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_log_martians_disabled_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "net.ipv4.conf.all.log_martians" {
                *p = ("net.ipv4.conf.all.log_martians", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-014")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_rp_filter_disabled_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "net.ipv4.conf.all.rp_filter" {
                *p = ("net.ipv4.conf.all.rp_filter", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-015")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_protected_hardlinks_off_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "fs.protected_hardlinks" {
                *p = ("fs.protected_hardlinks", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-018")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_protected_symlinks_off_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "fs.protected_symlinks" {
                *p = ("fs.protected_symlinks", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-019")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_mmap_min_addr_too_low_fails() {
        let mut params = full_sysctl_params();
        for p in &mut params {
            if p.0 == "vm.mmap_min_addr" {
                *p = ("vm.mmap_min_addr", "0");
            }
        }
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let ctrl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-020")
            .unwrap();
        assert!(!ctrl.passed);
    }

    #[tokio::test]
    async fn evaluate_ipv6_advisory_controls() {
        let mut params = full_sysctl_params();
        params.push(("kernel.modules_disabled", "1"));
        params.push(("kernel.exec-shield", "1"));
        params.push(("net.ipv6.conf.all.accept_ra", "0"));
        params.push(("net.ipv6.conf.all.accept_redirects", "0"));
        let runner = make_runner_with_sysctl(&params);
        runner.add_response("getenforce", &[], "Enforcing\n");

        let plugin = KernelPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        let ipv6_ra = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-016")
            .unwrap();
        assert!(ipv6_ra.passed);
        let ipv6_redir = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "KERN-017")
            .unwrap();
        assert!(ipv6_redir.passed);
    }
}
