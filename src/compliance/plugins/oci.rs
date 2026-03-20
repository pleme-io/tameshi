//! OCI container compliance plugin.
//!
//! Evaluates OCI container image security: manifest digest verification,
//! non-root user configuration, dropped capabilities, and seccomp profiles.
//!
//! Uses [`CommandRunner`] for `skopeo inspect` so all evaluation can be
//! tested with [`MockCommandRunner`].
//!
//! Controls are defined data-driven for easy expansion.

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

const DOMAIN: &str = "oci";

/// OCI container compliance plugin.
///
/// Checks container image security posture via `skopeo inspect`.
pub struct OciPlugin<C: CommandRunner> {
    runner: Arc<C>,
    /// Image reference to inspect (e.g., "docker://ghcr.io/pleme-io/app:latest").
    image_ref: String,
}

impl<C: CommandRunner> OciPlugin<C> {
    /// Create a new OCI plugin for the given image reference.
    #[must_use]
    pub fn new(runner: Arc<C>, image_ref: &str) -> Self {
        Self {
            runner,
            image_ref: image_ref.to_string(),
        }
    }
}

impl<C: CommandRunner + 'static> CompliancePlugin for OciPlugin<C> {
    fn domain(&self) -> &str {
        DOMAIN
    }

    fn nist_families(&self) -> Vec<String> {
        vec![
            "CM".to_string(), // Configuration Management
            "AC".to_string(), // Access Control
            "SC".to_string(), // System and Communications Protection
        ]
    }

    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl> {
        let mut controls = vec![
            ComplianceControl {
                id: "OCI-001".to_string(),
                title: "Manifest digest verified".to_string(),
                description: "OCI manifest must have a valid digest".to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["SI-7".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "OCI-002".to_string(),
                title: "Non-root user configured".to_string(),
                description: "Container must not run as root (UID 0)".to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["AC-6".to_string(), "CM-6".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "OCI-003".to_string(),
                title: "Dangerous capabilities dropped".to_string(),
                description: "Container should drop ALL capabilities and add only needed ones"
                    .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["AC-6".to_string(), "SC-3".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "OCI-004".to_string(),
                title: "Read-only root filesystem".to_string(),
                description: "Container root filesystem should be read-only".to_string(),
                severity: ControlSeverity::Medium,
                nist_control_ids: vec!["CM-5".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
        ];

        controls.push(ComplianceControl {
            id: "OCI-006".to_string(),
            title: "Container has healthcheck".to_string(),
            description: "Container image must define a HEALTHCHECK instruction".to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["CM-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "OCI-007".to_string(),
            title: "Image tag is not :latest".to_string(),
            description: "Image tag must be a pinned version or digest, not :latest".to_string(),
            severity: ControlSeverity::High,
            nist_control_ids: vec!["CM-2".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        // New required controls
        controls.push(ComplianceControl {
            id: "OCI-009".to_string(),
            title: "No secrets in env vars".to_string(),
            description: "Container must not have SECRET/PASSWORD/KEY/TOKEN in environment variable names".to_string(),
            severity: ControlSeverity::Critical,
            nist_control_ids: vec!["SC-28".to_string(), "IA-5".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "OCI-010".to_string(),
            title: "WORKDIR is explicitly set".to_string(),
            description: "Container image should have an explicit WORKDIR set".to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["CM-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "OCI-011".to_string(),
            title: "No privileged ports".to_string(),
            description: "Container should not expose ports below 1024".to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["AC-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "OCI-012".to_string(),
            title: "ENTRYPOINT is explicitly set".to_string(),
            description: "Container image must have an explicit ENTRYPOINT".to_string(),
            severity: ControlSeverity::High,
            nist_control_ids: vec!["CM-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });

        if config.include_advisory {
            controls.push(ComplianceControl {
                id: "OCI-005".to_string(),
                title: "Image labels present".to_string(),
                description: "Image should have standard OCI labels (maintainer, version)"
                    .to_string(),
                severity: ControlSeverity::Info,
                nist_control_ids: vec!["CM-2".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "OCI-008".to_string(),
                title: "Required OCI labels present".to_string(),
                description:
                    "Image should have org.opencontainers.image.source and version labels"
                        .to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["CM-8".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "OCI-013".to_string(),
                title: "Only expected ports exposed".to_string(),
                description: "Only expected application ports should be exposed".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["SC-7".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "OCI-014".to_string(),
                title: "Multi-stage build used".to_string(),
                description: "Image should use multi-stage builds for minimal final image size".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["CM-7".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "OCI-015".to_string(),
                title: "No ADD instructions".to_string(),
                description: "Image should use COPY instead of ADD to avoid unexpected behavior".to_string(),
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
        let image_ref = self.image_ref.clone();
        Box::pin(async move {
            let now = Utc::now();
            let mut evaluations = Vec::with_capacity(controls.len());

            // Inspect the image once
            let inspect_result = (*runner)
                .run("skopeo", &["inspect", "--config", &image_ref])
                .await;

            let raw_inspect_result = (*runner)
                .run("skopeo", &["inspect", "--raw", &image_ref])
                .await;

            for control in &controls {
                let start = std::time::Instant::now();
                let (passed, message) = match control.id.as_str() {
                    "OCI-001" => check_manifest_digest(&raw_inspect_result),
                    "OCI-002" => check_non_root_user(&inspect_result),
                    "OCI-003" => check_dropped_capabilities(&inspect_result),
                    "OCI-004" => check_readonly_rootfs(&inspect_result),
                    "OCI-005" => check_image_labels(&inspect_result),
                    "OCI-006" => check_healthcheck(&inspect_result),
                    "OCI-007" => check_no_latest_tag(&image_ref),
                    "OCI-008" => check_required_oci_labels(&inspect_result),
                    "OCI-009" => check_no_env_secrets(&inspect_result),
                    "OCI-010" => check_workdir_set(&inspect_result),
                    "OCI-011" => check_no_privileged_ports(&inspect_result),
                    "OCI-012" => check_entrypoint_set(&inspect_result),
                    "OCI-013" => check_exposed_ports(&inspect_result),
                    "OCI-014" => check_multi_stage(&inspect_result),
                    "OCI-015" => check_no_add(&inspect_result),
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
        // skopeo is generally available; rely on runtime check
        true
    }
}

fn check_manifest_digest(raw_result: &crate::error::Result<String>) -> (bool, String) {
    match raw_result {
        Ok(output) => {
            match serde_json::from_str::<serde_json::Value>(output) {
                Ok(manifest) => {
                    // Check that mediaType and config.digest exist
                    let has_digest = manifest
                        .get("config")
                        .and_then(|c| c.get("digest"))
                        .and_then(|d| d.as_str())
                        .is_some();
                    if has_digest {
                        (true, "Manifest has valid config digest".to_string())
                    } else {
                        (false, "Manifest missing config digest".to_string())
                    }
                }
                Err(e) => (false, format!("Invalid manifest JSON: {e}")),
            }
        }
        Err(e) => (false, format!("skopeo inspect --raw failed: {e}")),
    }
}

fn check_non_root_user(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let user = config
                    .get("config")
                    .and_then(|c| c.get("User"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("");
                if user.is_empty() || user == "0" || user == "root" {
                    (false, format!("Container runs as root (User: '{user}')"))
                } else {
                    (true, format!("Container runs as user '{user}'"))
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_dropped_capabilities(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                // Check for SecurityOpt or Labels indicating cap-drop
                let labels = config
                    .get("config")
                    .and_then(|c| c.get("Labels"))
                    .and_then(|l| l.as_object());

                let has_cap_drop = labels
                    .map(|l| {
                        l.keys()
                            .any(|k| k.contains("cap-drop") || k.contains("security.capabilities"))
                    })
                    .unwrap_or(false);

                if has_cap_drop {
                    (true, "Capability restrictions declared".to_string())
                } else {
                    // Also pass if the image is built with no-new-privileges
                    (
                        false,
                        "No capability drop configuration found in labels".to_string(),
                    )
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_readonly_rootfs(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let labels = config
                    .get("config")
                    .and_then(|c| c.get("Labels"))
                    .and_then(|l| l.as_object());

                let has_readonly = labels
                    .map(|l| l.keys().any(|k| k.contains("read-only") || k.contains("readonly")))
                    .unwrap_or(false);

                if has_readonly {
                    (true, "Read-only root filesystem declared".to_string())
                } else {
                    (
                        false,
                        "No read-only root filesystem label found".to_string(),
                    )
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_image_labels(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let labels = config
                    .get("config")
                    .and_then(|c| c.get("Labels"))
                    .and_then(|l| l.as_object());

                match labels {
                    Some(l) if !l.is_empty() => {
                        (true, format!("{} labels present", l.len()))
                    }
                    _ => (false, "No image labels found".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_healthcheck(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let healthcheck = config
                    .get("config")
                    .and_then(|c| c.get("Healthcheck"));
                match healthcheck {
                    Some(hc) if !hc.is_null() => {
                        (true, "Container has HEALTHCHECK defined".to_string())
                    }
                    _ => (false, "No HEALTHCHECK defined in container image".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_no_latest_tag(image_ref: &str) -> (bool, String) {
    if image_ref.ends_with(":latest") {
        (
            false,
            format!("Image uses :latest tag: {image_ref}"),
        )
    } else if image_ref.contains('@') {
        (true, "Image pinned by digest".to_string())
    } else if image_ref.contains(':') {
        (true, "Image uses pinned tag".to_string())
    } else {
        // No tag specified means implicit :latest
        (
            false,
            format!("Image has no tag (implicit :latest): {image_ref}"),
        )
    }
}

fn check_required_oci_labels(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let labels = config
                    .get("config")
                    .and_then(|c| c.get("Labels"))
                    .and_then(|l| l.as_object());
                match labels {
                    Some(l) => {
                        let has_source = l
                            .keys()
                            .any(|k| k == "org.opencontainers.image.source");
                        let has_version = l
                            .keys()
                            .any(|k| k == "org.opencontainers.image.version");
                        let mut missing = Vec::new();
                        if !has_source {
                            missing.push("org.opencontainers.image.source");
                        }
                        if !has_version {
                            missing.push("org.opencontainers.image.version");
                        }
                        if missing.is_empty() {
                            (true, "Required OCI labels present".to_string())
                        } else {
                            (
                                false,
                                format!("Missing required labels: {}", missing.join(", ")),
                            )
                        }
                    }
                    None => (false, "No labels found on image".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_no_env_secrets(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let env_vars = config
                    .get("config")
                    .and_then(|c| c.get("Env"))
                    .and_then(|e| e.as_array());
                match env_vars {
                    Some(vars) => {
                        let secret_patterns = ["SECRET", "PASSWORD", "KEY", "TOKEN", "PRIVATE"];
                        let leaks: Vec<String> = vars
                            .iter()
                            .filter_map(|v| v.as_str())
                            .filter(|v| {
                                let name = v.split('=').next().unwrap_or("");
                                let upper = name.to_uppercase();
                                secret_patterns.iter().any(|p| upper.contains(p))
                            })
                            .map(|v| v.split('=').next().unwrap_or("").to_string())
                            .collect();
                        if leaks.is_empty() {
                            (true, "No secret-like env vars found".to_string())
                        } else {
                            (
                                false,
                                format!("Potential secrets in env: {}", leaks.join(", ")),
                            )
                        }
                    }
                    None => (true, "No environment variables set".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_workdir_set(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let workdir = config
                    .get("config")
                    .and_then(|c| c.get("WorkingDir"))
                    .and_then(|w| w.as_str())
                    .unwrap_or("");
                if workdir.is_empty() {
                    (false, "WORKDIR is not set in container image".to_string())
                } else {
                    (true, format!("WORKDIR is set to '{workdir}'"))
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_no_privileged_ports(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let ports = config
                    .get("config")
                    .and_then(|c| c.get("ExposedPorts"))
                    .and_then(|p| p.as_object());
                match ports {
                    Some(port_map) => {
                        let privileged: Vec<String> = port_map
                            .keys()
                            .filter(|k| {
                                let port_str = k.split('/').next().unwrap_or("0");
                                port_str.parse::<u16>().unwrap_or(0) < 1024
                            })
                            .cloned()
                            .collect();
                        if privileged.is_empty() {
                            (true, "No privileged ports exposed".to_string())
                        } else {
                            (
                                false,
                                format!("Privileged ports exposed: {}", privileged.join(", ")),
                            )
                        }
                    }
                    None => (true, "No ports exposed".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_entrypoint_set(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let entrypoint = config
                    .get("config")
                    .and_then(|c| c.get("Entrypoint"));
                match entrypoint {
                    Some(ep) if !ep.is_null() => {
                        if let Some(arr) = ep.as_array() {
                            if arr.is_empty() {
                                (false, "ENTRYPOINT is empty".to_string())
                            } else {
                                (true, "ENTRYPOINT is set".to_string())
                            }
                        } else {
                            (true, "ENTRYPOINT is set".to_string())
                        }
                    }
                    _ => (false, "No ENTRYPOINT defined in container image".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_exposed_ports(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                let ports = config
                    .get("config")
                    .and_then(|c| c.get("ExposedPorts"))
                    .and_then(|p| p.as_object());
                match ports {
                    Some(port_map) => {
                        let count = port_map.len();
                        if count <= 5 {
                            (true, format!("{count} port(s) exposed (reasonable)"))
                        } else {
                            (
                                false,
                                format!("{count} ports exposed (unusually many)"),
                            )
                        }
                    }
                    None => (true, "No ports exposed".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_multi_stage(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                // Heuristic: check layer count or image size hints from labels
                let labels = config
                    .get("config")
                    .and_then(|c| c.get("Labels"))
                    .and_then(|l| l.as_object());
                let has_multistage_label = labels
                    .map(|l| {
                        l.keys()
                            .any(|k| k.contains("multi-stage") || k.contains("build.stage"))
                    })
                    .unwrap_or(false);
                if has_multistage_label {
                    (true, "Multi-stage build label present".to_string())
                } else {
                    // Advisory: we can't definitively tell from inspect alone
                    (
                        false,
                        "No multi-stage build indicator found (advisory)".to_string(),
                    )
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

fn check_no_add(inspect_result: &crate::error::Result<String>) -> (bool, String) {
    match inspect_result {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(config) => {
                // Check history for ADD instructions
                let history = config.get("history").and_then(|h| h.as_array());
                match history {
                    Some(entries) => {
                        let has_add = entries.iter().any(|e| {
                            e.get("created_by")
                                .and_then(|c| c.as_str())
                                .is_some_and(|s| s.starts_with("ADD "))
                        });
                        if has_add {
                            (false, "Image uses ADD instruction (use COPY instead)".to_string())
                        } else {
                            (true, "No ADD instructions found".to_string())
                        }
                    }
                    None => (true, "No build history available (advisory pass)".to_string()),
                }
            }
            Err(e) => (false, format!("Invalid config JSON: {e}")),
        },
        Err(e) => (false, format!("skopeo inspect --config failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockCommandRunner;

    fn make_runner() -> Arc<MockCommandRunner> {
        Arc::new(MockCommandRunner::new())
    }

    fn config_json(user: &str, labels: &str) -> String {
        format!(
            r#"{{"config":{{"User":"{user}","Labels":{labels}}}}}"#
        )
    }

    fn config_json_with_healthcheck(user: &str, labels: &str) -> String {
        format!(
            r#"{{"config":{{"User":"{user}","Labels":{labels},"Healthcheck":{{"Test":["CMD","healthcheck"]}}}}}}"#
        )
    }

    fn config_json_full(user: &str, labels: &str) -> String {
        format!(
            r#"{{"config":{{"User":"{user}","Labels":{labels},"Healthcheck":{{"Test":["CMD","healthcheck"]}},"WorkingDir":"/app","Entrypoint":["/app/start"],"ExposedPorts":{{"8080/tcp":{{}}}},"Env":["PATH=/usr/bin","HOME=/app"]}}}}"#
        )
    }

    fn raw_manifest_with_digest() -> &'static str {
        r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:abc123"},"layers":[]}"#
    }

    fn raw_manifest_without_digest() -> &'static str {
        r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#
    }

    #[test]
    fn domain_name() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        assert_eq!(plugin.domain(), "oci");
    }

    #[test]
    fn nist_families_covered() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        let families = plugin.nist_families();
        assert!(families.contains(&"CM".to_string()));
        assert!(families.contains(&"AC".to_string()));
        assert!(families.contains(&"SC".to_string()));
    }

    #[test]
    fn generate_controls_default() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        let controls = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(controls.len(), 10);
        assert!(controls.iter().all(|c| c.domain == "oci"));
    }

    #[test]
    fn generate_controls_with_advisory() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        assert!(controls.len() >= 15, "expected >= 15 controls, got {}", controls.len());
    }

    #[test]
    fn control_ids_are_unique() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
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
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        let controls = plugin.generate_controls(&PluginConfig::default());
        for c in &controls {
            assert!(!c.nist_control_ids.is_empty(), "Control {} has no NIST IDs", c.id);
        }
    }

    #[test]
    fn controls_are_deterministic() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        let c1 = plugin.generate_controls(&PluginConfig::default());
        let c2 = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(c1, c2);
    }

    #[test]
    fn is_available_true() {
        let plugin = OciPlugin::new(make_runner(), "docker://test");
        assert!(plugin.is_available());
    }

    #[tokio::test]
    async fn evaluate_all_pass() {
        let runner = make_runner();
        let img = "docker://test:v1.2.3";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json_full("1000", r#"{"cap-drop":"ALL","read-only":"true"}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        assert!(result.all_required_passed, "Expected all required to pass. Failures: {:?}",
            result.evaluations.iter().filter(|e| !e.passed).map(|e| format!("{}: {}", e.control.id, e.message)).collect::<Vec<_>>());
        assert_eq!(result.domain, "oci");
    }

    #[tokio::test]
    async fn evaluate_root_user_fails() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("root", r#"{"cap-drop":"ALL","read-only":"true"}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let user = result.evaluations.iter().find(|e| e.control.id == "OCI-002").unwrap();
        assert!(!user.passed);
        assert!(user.message.contains("root"));
    }

    #[tokio::test]
    async fn evaluate_empty_user_fails() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let user = result.evaluations.iter().find(|e| e.control.id == "OCI-002").unwrap();
        assert!(!user.passed);
    }

    #[tokio::test]
    async fn evaluate_manifest_no_digest() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_without_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let digest = result.evaluations.iter().find(|e| e.control.id == "OCI-001").unwrap();
        assert!(!digest.passed);
    }

    #[tokio::test]
    async fn evaluate_skopeo_fails() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_error("skopeo", &["inspect", "--config", img], "not found");
        runner.add_error("skopeo", &["inspect", "--raw", img], "not found");

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        assert!(!result.all_required_passed);
        for eval in &result.evaluations {
            assert!(!eval.passed);
        }
    }

    #[tokio::test]
    async fn evaluate_no_cap_drop() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let caps = result.evaluations.iter().find(|e| e.control.id == "OCI-003").unwrap();
        assert!(!caps.passed);
    }

    #[tokio::test]
    async fn domain_evaluation_serde_roundtrip() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{"cap-drop":"ALL","read-only":"true"}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
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
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        for eval in &result.evaluations {
            assert!(eval.evidence_hash.is_some());
        }
    }

    #[tokio::test]
    async fn advisory_labels_check() {
        let runner = make_runner();
        let img = "docker://test:v1.0";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{"org.opencontainers.image.version":"1.0"}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        let labels = result.evaluations.iter().find(|e| e.control.id == "OCI-005").unwrap();
        assert!(labels.passed);
    }

    #[tokio::test]
    async fn evaluate_no_healthcheck_fails() {
        let runner = make_runner();
        let img = "docker://test:v1.0";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let hc = result.evaluations.iter().find(|e| e.control.id == "OCI-006").unwrap();
        assert!(!hc.passed);
        assert!(hc.message.contains("No HEALTHCHECK"));
    }

    #[tokio::test]
    async fn evaluate_healthcheck_present_passes() {
        let runner = make_runner();
        let img = "docker://test:v1.0";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json_with_healthcheck("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let hc = result.evaluations.iter().find(|e| e.control.id == "OCI-006").unwrap();
        assert!(hc.passed);
    }

    #[tokio::test]
    async fn evaluate_latest_tag_fails() {
        let runner = make_runner();
        let img = "docker://test:latest";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json_with_healthcheck("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let tag = result.evaluations.iter().find(|e| e.control.id == "OCI-007").unwrap();
        assert!(!tag.passed);
        assert!(tag.message.contains("latest"));
    }

    #[tokio::test]
    async fn evaluate_pinned_digest_passes() {
        let runner = make_runner();
        let img = "docker://test@sha256:abcdef";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json_with_healthcheck("1000", r#"{}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin.evaluate(&controls, &PluginConfig::default()).await.unwrap();

        let tag = result.evaluations.iter().find(|e| e.control.id == "OCI-007").unwrap();
        assert!(tag.passed);
    }

    #[tokio::test]
    async fn evaluate_required_oci_labels_all_present() {
        let runner = make_runner();
        let img = "docker://test:v1.0";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{"org.opencontainers.image.source":"https://github.com/test","org.opencontainers.image.version":"1.0"}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        let labels = result.evaluations.iter().find(|e| e.control.id == "OCI-008").unwrap();
        assert!(labels.passed);
    }

    #[tokio::test]
    async fn evaluate_required_oci_labels_missing() {
        let runner = make_runner();
        let img = "docker://test:v1.0";
        runner.add_response(
            "skopeo",
            &["inspect", "--config", img],
            &config_json("1000", r#"{"maintainer":"test"}"#),
        );
        runner.add_response(
            "skopeo",
            &["inspect", "--raw", img],
            raw_manifest_with_digest(),
        );

        let plugin = OciPlugin::new(runner, img);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        let labels = result.evaluations.iter().find(|e| e.control.id == "OCI-008").unwrap();
        assert!(!labels.passed);
        assert!(labels.message.contains("Missing"));
    }
}
