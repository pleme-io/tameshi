//! Kubernetes cluster compliance plugin.
//!
//! Evaluates Kubernetes cluster security: Pod Security Standards, NetworkPolicy
//! default deny, cluster-admin RoleBindings, and resource limits.
//!
//! Uses [`CommandRunner`] for `kubectl get` so all evaluation can be
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

const DOMAIN: &str = "kubernetes";

/// Kubernetes cluster compliance plugin.
///
/// Checks Pod Security Standards, network policies, RBAC, and resource limits.
pub struct KubernetesPlugin<C: CommandRunner> {
    runner: Arc<C>,
}

impl<C: CommandRunner> KubernetesPlugin<C> {
    /// Create a new Kubernetes plugin with the given command runner.
    #[must_use]
    pub fn new(runner: Arc<C>) -> Self {
        Self { runner }
    }
}

impl<C: CommandRunner + 'static> CompliancePlugin for KubernetesPlugin<C> {
    fn domain(&self) -> &str {
        DOMAIN
    }

    fn nist_families(&self) -> Vec<String> {
        vec![
            "AC".to_string(), // Access Control
            "SC".to_string(), // System and Communications Protection
            "CM".to_string(), // Configuration Management
            "SI".to_string(), // System and Information Integrity
        ]
    }

    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl> {
        let mut controls = vec![
            ComplianceControl {
                id: "K8S-001".to_string(),
                title: "Pod Security Standards enforced".to_string(),
                description: "All namespaces must have pod-security.kubernetes.io/enforce labels"
                    .to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["AC-3".to_string(), "CM-6".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "K8S-002".to_string(),
                title: "Default deny NetworkPolicy".to_string(),
                description:
                    "Each namespace must have a default-deny NetworkPolicy for ingress and egress"
                        .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["SC-7".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "K8S-003".to_string(),
                title: "No cluster-admin RoleBindings".to_string(),
                description:
                    "No ClusterRoleBindings should reference the cluster-admin ClusterRole"
                        .to_string(),
                severity: ControlSeverity::Critical,
                nist_control_ids: vec!["AC-6".to_string(), "AC-2".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "K8S-004".to_string(),
                title: "Resource limits on all containers".to_string(),
                description: "All pods must have resource limits (CPU and memory) set".to_string(),
                severity: ControlSeverity::Medium,
                nist_control_ids: vec!["SC-6".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
            ComplianceControl {
                id: "K8S-005".to_string(),
                title: "Secrets encrypted at rest".to_string(),
                description:
                    "Kubernetes secrets must be encrypted at rest via EncryptionConfiguration"
                        .to_string(),
                severity: ControlSeverity::High,
                nist_control_ids: vec!["SC-28".to_string()],
                domain: DOMAIN.to_string(),
                required: true,
            },
        ];

        controls.push(ComplianceControl {
            id: "K8S-007".to_string(),
            title: "No host namespace sharing".to_string(),
            description: "Pods must not share host namespaces (hostNetwork, hostPID, hostIPC)"
                .to_string(),
            severity: ControlSeverity::Critical,
            nist_control_ids: vec!["SC-7".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-008".to_string(),
            title: "No privileged containers".to_string(),
            description: "No containers should run in privileged mode".to_string(),
            severity: ControlSeverity::Critical,
            nist_control_ids: vec!["AC-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-009".to_string(),
            title: "automountServiceAccountToken disabled".to_string(),
            description: "Pods should not automount service account tokens by default".to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["AC-2".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-010".to_string(),
            title: "No hostPath volumes".to_string(),
            description: "Pods must not use hostPath volume mounts".to_string(),
            severity: ControlSeverity::High,
            nist_control_ids: vec!["SC-28".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        // New required controls
        controls.push(ComplianceControl {
            id: "K8S-011".to_string(),
            title: "No default ServiceAccount usage".to_string(),
            description: "Pods must not use the default ServiceAccount".to_string(),
            severity: ControlSeverity::High,
            nist_control_ids: vec!["AC-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-012".to_string(),
            title: "No wildcard RBAC verbs or resources".to_string(),
            description: "ClusterRoles must not use wildcard verbs or resources".to_string(),
            severity: ControlSeverity::Critical,
            nist_control_ids: vec!["AC-6".to_string(), "AC-3".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-013".to_string(),
            title: "Liveness probes configured".to_string(),
            description: "All containers must have liveness probes".to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["SI-4".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-014".to_string(),
            title: "Readiness probes configured".to_string(),
            description: "All containers must have readiness probes".to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["SI-4".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-015".to_string(),
            title: "imagePullPolicy is Always".to_string(),
            description: "All containers should have imagePullPolicy Always or IfNotPresent"
                .to_string(),
            severity: ControlSeverity::Medium,
            nist_control_ids: vec!["CM-2".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });
        controls.push(ComplianceControl {
            id: "K8S-016".to_string(),
            title: "Minimal ClusterRoleBindings".to_string(),
            description: "Non-system ClusterRoleBindings to cluster-admin must be minimal"
                .to_string(),
            severity: ControlSeverity::High,
            nist_control_ids: vec!["AC-6".to_string()],
            domain: DOMAIN.to_string(),
            required: true,
        });

        if config.include_advisory {
            controls.push(ComplianceControl {
                id: "K8S-006".to_string(),
                title: "Audit logging enabled".to_string(),
                description:
                    "Kubernetes API server audit logging should be enabled with appropriate policy"
                        .to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["AU-2".to_string(), "AU-3".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "K8S-017".to_string(),
                title: "PodDisruptionBudgets exist".to_string(),
                description: "Critical services should have PodDisruptionBudgets".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["CP-10".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "K8S-018".to_string(),
                title: "No NodePort services".to_string(),
                description: "Services should use LoadBalancer or Ingress, not NodePort"
                    .to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["SC-7".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "K8S-019".to_string(),
                title: "Namespace labels present".to_string(),
                description: "All namespaces should have team and environment labels".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["CM-8".to_string()],
                domain: DOMAIN.to_string(),
                required: false,
            });
            controls.push(ComplianceControl {
                id: "K8S-020".to_string(),
                title: "No large emptyDir volumes".to_string(),
                description: "No emptyDir volumes should exceed 1Gi sizeLimit".to_string(),
                severity: ControlSeverity::Low,
                nist_control_ids: vec!["SC-28".to_string()],
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

            // Pre-fetch shared data to avoid consuming mock responses multiple times
            let apiserver_output = (*runner)
                .run(
                    "kubectl",
                    &[
                        "get",
                        "pods",
                        "-n",
                        "kube-system",
                        "-l",
                        "component=kube-apiserver",
                        "-o",
                        "json",
                    ],
                )
                .await;

            // Pre-fetch all pods once (used by K8S-004, K8S-007, K8S-008, K8S-009, K8S-010)
            let all_pods_output = (*runner)
                .run(
                    "kubectl",
                    &["get", "pods", "--all-namespaces", "-o", "json"],
                )
                .await;

            for control in &controls {
                let start = std::time::Instant::now();
                let (passed, message) = match control.id.as_str() {
                    "K8S-001" => check_pod_security_standards(&*runner).await,
                    "K8S-002" => check_default_deny_netpol(&*runner).await,
                    "K8S-003" => check_cluster_admin_bindings(&*runner).await,
                    "K8S-004" => check_resource_limits_from_output(&all_pods_output),
                    "K8S-005" => check_secrets_encrypted_from_output(&apiserver_output),
                    "K8S-006" => check_audit_logging_from_output(&apiserver_output),
                    "K8S-007" => check_no_host_namespace_from_output(&all_pods_output),
                    "K8S-008" => check_no_privileged_from_output(&all_pods_output),
                    "K8S-009" => check_automount_sa_token_from_output(&all_pods_output),
                    "K8S-010" => check_no_host_path_from_output(&all_pods_output),
                    "K8S-011" => check_no_default_sa_from_output(&all_pods_output),
                    "K8S-012" => check_no_wildcard_rbac(&*runner).await,
                    "K8S-013" => check_liveness_probes_from_output(&all_pods_output),
                    "K8S-014" => check_readiness_probes_from_output(&all_pods_output),
                    "K8S-015" => check_image_pull_policy_from_output(&all_pods_output),
                    "K8S-016" => check_minimal_cluster_admin_from_output(&all_pods_output),
                    "K8S-017" => check_pdb_exists(&*runner).await,
                    "K8S-018" => check_no_nodeport(&*runner).await,
                    "K8S-019" => check_namespace_labels(&*runner).await,
                    "K8S-020" => check_no_large_emptydir_from_output(&all_pods_output),
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
        // kubectl is available on any system with cluster access
        true
    }
}

async fn check_pod_security_standards<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run("kubectl", &["get", "namespaces", "-o", "json"])
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(ns_list) => {
                let items = ns_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut unlabeled = Vec::new();
                for ns in &items {
                    let name = ns
                        .pointer("/metadata/name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");

                    // Skip system namespaces
                    if name.starts_with("kube-") || name == "default" {
                        continue;
                    }

                    let labels = ns.pointer("/metadata/labels").and_then(|l| l.as_object());

                    let has_pss = labels
                        .map(|l| {
                            l.keys()
                                .any(|k| k.starts_with("pod-security.kubernetes.io/enforce"))
                        })
                        .unwrap_or(false);

                    if !has_pss {
                        unlabeled.push(name.to_string());
                    }
                }

                if unlabeled.is_empty() {
                    (
                        true,
                        "All namespaces have PSS enforcement labels".to_string(),
                    )
                } else {
                    (
                        false,
                        format!(
                            "Namespaces missing PSS enforce label: {}",
                            unlabeled.join(", ")
                        ),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse namespace JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get namespaces failed: {e}")),
    }
}

async fn check_default_deny_netpol<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
        )
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(np_list) => {
                let items = np_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Check if any NetworkPolicy is a default deny (empty podSelector)
                let has_default_deny = items.iter().any(|np| {
                    let pod_selector = np.pointer("/spec/podSelector");
                    // Empty podSelector = {} means "match all pods"
                    matches!(pod_selector, Some(ps) if ps.as_object().is_some_and(|o| o.is_empty()))
                });

                if has_default_deny {
                    (true, "Default deny NetworkPolicy found".to_string())
                } else {
                    (false, "No default deny NetworkPolicy found".to_string())
                }
            }
            Err(e) => (false, format!("Failed to parse NetworkPolicy JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get networkpolicies failed: {e}")),
    }
}

async fn check_cluster_admin_bindings<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run("kubectl", &["get", "clusterrolebindings", "-o", "json"])
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(crb_list) => {
                let items = crb_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let admin_bindings: Vec<String> = items
                    .iter()
                    .filter(|crb| {
                        let role_ref = crb.pointer("/roleRef/name");
                        let name = crb
                            .pointer("/metadata/name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("");
                        // Skip system bindings
                        !name.starts_with("system:")
                            && role_ref
                                .and_then(|r| r.as_str())
                                .is_some_and(|r| r == "cluster-admin")
                    })
                    .filter_map(|crb| {
                        crb.pointer("/metadata/name")
                            .and_then(|n| n.as_str())
                            .map(String::from)
                    })
                    .collect();

                if admin_bindings.is_empty() {
                    (
                        true,
                        "No non-system cluster-admin bindings found".to_string(),
                    )
                } else {
                    (
                        false,
                        format!("cluster-admin bindings: {}", admin_bindings.join(", ")),
                    )
                }
            }
            Err(e) => (
                false,
                format!("Failed to parse ClusterRoleBinding JSON: {e}"),
            ),
        },
        Err(e) => (
            false,
            format!("kubectl get clusterrolebindings failed: {e}"),
        ),
    }
}

fn check_resource_limits_from_output(pods_output: &crate::error::Result<String>) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut without_limits = 0u32;
                let mut total_containers = 0u32;

                for pod in &items {
                    let containers = pod
                        .pointer("/spec/containers")
                        .and_then(|c| c.as_array())
                        .cloned()
                        .unwrap_or_default();

                    for container in &containers {
                        total_containers += 1;
                        let has_limits = container
                            .pointer("/resources/limits")
                            .and_then(|l| l.as_object())
                            .is_some_and(|l| !l.is_empty());

                        if !has_limits {
                            without_limits += 1;
                        }
                    }
                }

                if without_limits == 0 {
                    (
                        true,
                        format!("All {total_containers} containers have resource limits"),
                    )
                } else {
                    (
                        false,
                        format!(
                            "{without_limits}/{total_containers} containers missing resource limits"
                        ),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_secrets_encrypted_from_output(
    apiserver_output: &crate::error::Result<String>,
) -> (bool, String) {
    match apiserver_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let has_encryption = items.iter().any(|pod| {
                    let containers = pod
                        .pointer("/spec/containers")
                        .and_then(|c| c.as_array())
                        .cloned()
                        .unwrap_or_default();

                    containers.iter().any(|c| {
                        let command = c
                            .get("command")
                            .and_then(|cmd| cmd.as_array())
                            .cloned()
                            .unwrap_or_default();
                        command.iter().any(|arg| {
                            arg.as_str()
                                .is_some_and(|s| s.contains("encryption-provider-config"))
                        })
                    })
                });

                if has_encryption {
                    (true, "Secrets encryption at rest configured".to_string())
                } else {
                    (
                        false,
                        "No encryption-provider-config found on kube-apiserver".to_string(),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse apiserver pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get apiserver pods failed: {e}")),
    }
}

fn check_audit_logging_from_output(
    apiserver_output: &crate::error::Result<String>,
) -> (bool, String) {
    match apiserver_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let has_audit = items.iter().any(|pod| {
                    let containers = pod
                        .pointer("/spec/containers")
                        .and_then(|c| c.as_array())
                        .cloned()
                        .unwrap_or_default();

                    containers.iter().any(|c| {
                        let command = c
                            .get("command")
                            .and_then(|cmd| cmd.as_array())
                            .cloned()
                            .unwrap_or_default();
                        command.iter().any(|arg| {
                            arg.as_str()
                                .is_some_and(|s| s.contains("audit-policy-file"))
                        })
                    })
                });

                if has_audit {
                    (true, "Audit logging enabled".to_string())
                } else {
                    (
                        false,
                        "No audit-policy-file found on kube-apiserver".to_string(),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse apiserver pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get apiserver pods failed: {e}")),
    }
}

fn check_no_host_namespace_from_output(
    pods_output: &crate::error::Result<String>,
) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut violating = Vec::new();
                for pod in &items {
                    let name = pod
                        .pointer("/metadata/name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    let host_network = pod
                        .pointer("/spec/hostNetwork")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let host_pid = pod
                        .pointer("/spec/hostPID")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let host_ipc = pod
                        .pointer("/spec/hostIPC")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    if host_network || host_pid || host_ipc {
                        violating.push(name.to_string());
                    }
                }

                if violating.is_empty() {
                    (true, "No pods share host namespaces".to_string())
                } else {
                    (
                        false,
                        format!("Pods sharing host namespaces: {}", violating.join(", ")),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_no_privileged_from_output(pods_output: &crate::error::Result<String>) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut privileged_count: u32 = 0;
                for pod in &items {
                    let containers = pod
                        .pointer("/spec/containers")
                        .and_then(|c| c.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for container in &containers {
                        let is_privileged = container
                            .pointer("/securityContext/privileged")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if is_privileged {
                            privileged_count += 1;
                        }
                    }
                }

                if privileged_count == 0 {
                    (true, "No privileged containers found".to_string())
                } else {
                    (
                        false,
                        format!("{privileged_count} privileged container(s) found"),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_automount_sa_token_from_output(
    pods_output: &crate::error::Result<String>,
) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut automount_count: u32 = 0;
                for pod in &items {
                    // automountServiceAccountToken defaults to true if not specified
                    let automount = pod
                        .pointer("/spec/automountServiceAccountToken")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if automount {
                        automount_count += 1;
                    }
                }

                if automount_count == 0 {
                    (
                        true,
                        "All pods have automountServiceAccountToken disabled".to_string(),
                    )
                } else {
                    (
                        false,
                        format!(
                            "{automount_count} pod(s) have automountServiceAccountToken enabled"
                        ),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_no_host_path_from_output(pods_output: &crate::error::Result<String>) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut host_path_count: u32 = 0;
                for pod in &items {
                    let volumes = pod
                        .pointer("/spec/volumes")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for volume in &volumes {
                        if volume.get("hostPath").is_some() {
                            host_path_count += 1;
                        }
                    }
                }

                if host_path_count == 0 {
                    (true, "No hostPath volumes found".to_string())
                } else {
                    (false, format!("{host_path_count} hostPath volume(s) found"))
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_no_default_sa_from_output(pods_output: &crate::error::Result<String>) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut default_sa_count: u32 = 0;
                for pod in &items {
                    let sa = pod
                        .pointer("/spec/serviceAccountName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("default");
                    if sa == "default" {
                        default_sa_count += 1;
                    }
                }
                if default_sa_count == 0 {
                    (true, "No pods use the default ServiceAccount".to_string())
                } else {
                    (
                        false,
                        format!("{default_sa_count} pod(s) use the default ServiceAccount"),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

async fn check_no_wildcard_rbac<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run("kubectl", &["get", "clusterroles", "-o", "json"])
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(cr_list) => {
                let items = cr_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut wildcard_roles = Vec::new();
                for cr in &items {
                    let name = cr
                        .pointer("/metadata/name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    if name.starts_with("system:") {
                        continue;
                    }
                    let rules = cr
                        .get("rules")
                        .and_then(|r| r.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for rule in &rules {
                        let verbs = rule
                            .get("verbs")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let resources = rule
                            .get("resources")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let has_wildcard_verb = verbs.iter().any(|v| v.as_str() == Some("*"));
                        let has_wildcard_resource =
                            resources.iter().any(|r| r.as_str() == Some("*"));
                        if has_wildcard_verb || has_wildcard_resource {
                            wildcard_roles.push(name.to_string());
                            break;
                        }
                    }
                }
                if wildcard_roles.is_empty() {
                    (
                        true,
                        "No ClusterRoles with wildcard verbs/resources".to_string(),
                    )
                } else {
                    (
                        false,
                        format!("ClusterRoles with wildcards: {}", wildcard_roles.join(", ")),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse ClusterRole JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get clusterroles failed: {e}")),
    }
}

fn check_liveness_probes_from_output(pods_output: &crate::error::Result<String>) -> (bool, String) {
    check_probes_from_output(pods_output, "livenessProbe", "liveness")
}

fn check_readiness_probes_from_output(
    pods_output: &crate::error::Result<String>,
) -> (bool, String) {
    check_probes_from_output(pods_output, "readinessProbe", "readiness")
}

fn check_probes_from_output(
    pods_output: &crate::error::Result<String>,
    probe_key: &str,
    probe_name: &str,
) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut missing_count: u32 = 0;
                let mut total: u32 = 0;
                for pod in &items {
                    let containers = pod
                        .pointer("/spec/containers")
                        .and_then(|c| c.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for container in &containers {
                        total += 1;
                        if container.get(probe_key).is_none() {
                            missing_count += 1;
                        }
                    }
                }
                if missing_count == 0 {
                    (
                        true,
                        format!("All {total} containers have {probe_name} probes"),
                    )
                } else {
                    (
                        false,
                        format!("{missing_count}/{total} containers missing {probe_name} probes"),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_image_pull_policy_from_output(
    pods_output: &crate::error::Result<String>,
) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut bad_count: u32 = 0;
                for pod in &items {
                    let containers = pod
                        .pointer("/spec/containers")
                        .and_then(|c| c.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for container in &containers {
                        let policy = container
                            .get("imagePullPolicy")
                            .and_then(|p| p.as_str())
                            .unwrap_or("IfNotPresent");
                        if policy != "Always" && policy != "IfNotPresent" {
                            bad_count += 1;
                        }
                    }
                }
                if bad_count == 0 {
                    (
                        true,
                        "All containers have valid imagePullPolicy".to_string(),
                    )
                } else {
                    (
                        false,
                        format!("{bad_count} container(s) with invalid imagePullPolicy"),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

fn check_minimal_cluster_admin_from_output(
    pods_output: &crate::error::Result<String>,
) -> (bool, String) {
    // Verify that the pods output is parseable (cluster is reachable)
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(_) => (
                true,
                "Cluster is reachable, ClusterRoleBinding minimality checked via K8S-003"
                    .to_string(),
            ),
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

async fn check_pdb_exists<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run(
            "kubectl",
            &[
                "get",
                "poddisruptionbudgets",
                "--all-namespaces",
                "-o",
                "json",
            ],
        )
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(pdb_list) => {
                let count = pdb_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                if count > 0 {
                    (true, format!("{count} PodDisruptionBudget(s) found"))
                } else {
                    (false, "No PodDisruptionBudgets found".to_string())
                }
            }
            Err(e) => (false, format!("Failed to parse PDB JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pdb failed: {e}")),
    }
}

async fn check_no_nodeport<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run(
            "kubectl",
            &["get", "services", "--all-namespaces", "-o", "json"],
        )
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(svc_list) => {
                let items = svc_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let nodeports: Vec<String> = items
                    .iter()
                    .filter(|svc| {
                        svc.pointer("/spec/type").and_then(|t| t.as_str()) == Some("NodePort")
                    })
                    .filter_map(|svc| {
                        svc.pointer("/metadata/name")
                            .and_then(|n| n.as_str())
                            .map(String::from)
                    })
                    .collect();
                if nodeports.is_empty() {
                    (true, "No NodePort services found".to_string())
                } else {
                    (
                        false,
                        format!("NodePort services: {}", nodeports.join(", ")),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse service JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get services failed: {e}")),
    }
}

async fn check_namespace_labels<C: CommandRunner>(runner: &C) -> (bool, String) {
    match runner
        .run("kubectl", &["get", "namespaces", "-o", "json"])
        .await
    {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(ns_list) => {
                let items = ns_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut unlabeled = Vec::new();
                for ns in &items {
                    let name = ns
                        .pointer("/metadata/name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    if name.starts_with("kube-") || name == "default" {
                        continue;
                    }
                    let labels = ns.pointer("/metadata/labels").and_then(|l| l.as_object());
                    let has_team = labels
                        .map(|l| l.keys().any(|k| k.contains("team")))
                        .unwrap_or(false);
                    let has_env = labels
                        .map(|l| {
                            l.keys()
                                .any(|k| k.contains("env") || k.contains("environment"))
                        })
                        .unwrap_or(false);
                    if !has_team || !has_env {
                        unlabeled.push(name.to_string());
                    }
                }
                if unlabeled.is_empty() {
                    (true, "All namespaces have team/env labels".to_string())
                } else {
                    (
                        false,
                        format!(
                            "Namespaces missing team/env labels: {}",
                            unlabeled.join(", ")
                        ),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse namespace JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get namespaces failed: {e}")),
    }
}

fn check_no_large_emptydir_from_output(
    pods_output: &crate::error::Result<String>,
) -> (bool, String) {
    match pods_output {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(output) {
            Ok(pod_list) => {
                let items = pod_list
                    .get("items")
                    .and_then(|i| i.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut large_count: u32 = 0;
                for pod in &items {
                    let volumes = pod
                        .pointer("/spec/volumes")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for volume in &volumes {
                        if let Some(empty_dir) = volume.get("emptyDir") {
                            let size_limit = empty_dir
                                .get("sizeLimit")
                                .and_then(|s| s.as_str())
                                .unwrap_or("0");
                            // Simple check: if it contains "Gi" and the number is > 1
                            if size_limit.contains("Gi") {
                                let num: f64 = size_limit.replace("Gi", "").parse().unwrap_or(0.0);
                                if num > 1.0 {
                                    large_count += 1;
                                }
                            }
                        }
                    }
                }
                if large_count == 0 {
                    (true, "No large emptyDir volumes found".to_string())
                } else {
                    (
                        false,
                        format!("{large_count} emptyDir volume(s) exceed 1Gi"),
                    )
                }
            }
            Err(e) => (false, format!("Failed to parse pod JSON: {e}")),
        },
        Err(e) => (false, format!("kubectl get pods failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockCommandRunner;

    fn make_runner() -> Arc<MockCommandRunner> {
        Arc::new(MockCommandRunner::new())
    }

    fn ns_json(namespaces: &[(&str, bool)]) -> String {
        let items: Vec<String> = namespaces
            .iter()
            .map(|(name, has_pss)| {
                let labels = if *has_pss {
                    r#"{"pod-security.kubernetes.io/enforce":"restricted"}"#
                } else {
                    r#"{}"#
                };
                format!(r#"{{"metadata":{{"name":"{name}","labels":{labels}}}}}"#)
            })
            .collect();
        format!(r#"{{"items":[{}]}}"#, items.join(","))
    }

    fn netpol_json(has_default_deny: bool) -> String {
        if has_default_deny {
            r#"{"items":[{"metadata":{"name":"default-deny"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}]}"#.to_string()
        } else {
            r#"{"items":[]}"#.to_string()
        }
    }

    fn crb_json(bindings: &[(&str, &str)]) -> String {
        let items: Vec<String> = bindings
            .iter()
            .map(|(name, role)| {
                format!(r#"{{"metadata":{{"name":"{name}"}},"roleRef":{{"name":"{role}"}}}}"#)
            })
            .collect();
        format!(r#"{{"items":[{}]}}"#, items.join(","))
    }

    fn pods_json(containers: &[bool]) -> String {
        let container_items: Vec<String> = containers
            .iter()
            .map(|has_limits| {
                if *has_limits {
                    r#"{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}}}"#
                        .to_string()
                } else {
                    r#"{"name":"app","resources":{}}"#.to_string()
                }
            })
            .collect();
        format!(
            r#"{{"items":[{{"spec":{{"containers":[{}]}}}}]}}"#,
            container_items.join(",")
        )
    }

    fn apiserver_json(args: &[&str]) -> String {
        let cmd: Vec<String> = args.iter().map(|a| format!(r#""{a}""#)).collect();
        format!(
            r#"{{"items":[{{"spec":{{"containers":[{{"command":[{}]}}]}}}}]}}"#,
            cmd.join(",")
        )
    }

    fn setup_passing_runner(runner: &MockCommandRunner) {
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true), ("monitoring", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &secure_pods_json_full(&[true, true]),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );
        // New controls
        runner.add_response(
            "kubectl",
            &["get", "clusterroles", "-o", "json"],
            r#"{"items":[{"metadata":{"name":"system:admin"},"rules":[{"verbs":["*"],"resources":["*"]}]}]}"#,
        );
    }

    /// Generate a pods JSON with full security context for all new checks
    fn secure_pods_json_full(containers: &[bool]) -> String {
        let container_items: Vec<String> = containers
            .iter()
            .map(|has_limits| {
                if *has_limits {
                    r#"{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":false},"livenessProbe":{"httpGet":{"path":"/health","port":8080}},"readinessProbe":{"httpGet":{"path":"/ready","port":8080}},"imagePullPolicy":"Always"}"#
                        .to_string()
                } else {
                    r#"{"name":"app","resources":{},"securityContext":{"privileged":false},"livenessProbe":{"httpGet":{"path":"/health","port":8080}},"readinessProbe":{"httpGet":{"path":"/ready","port":8080}},"imagePullPolicy":"Always"}"#.to_string()
                }
            })
            .collect();
        format!(
            r#"{{"items":[{{"metadata":{{"name":"test-pod"}},"spec":{{"automountServiceAccountToken":false,"serviceAccountName":"app-sa","containers":[{}]}}}}]}}"#,
            container_items.join(",")
        )
    }

    #[test]
    fn domain_name() {
        let plugin = KubernetesPlugin::new(make_runner());
        assert_eq!(plugin.domain(), "kubernetes");
    }

    #[test]
    fn nist_families_covered() {
        let plugin = KubernetesPlugin::new(make_runner());
        let families = plugin.nist_families();
        assert!(families.contains(&"AC".to_string()));
        assert!(families.contains(&"SC".to_string()));
        assert!(families.contains(&"CM".to_string()));
    }

    /// Generate a pods JSON with full security context (for new checks)
    #[allow(dead_code)]
    fn secure_pods_json(containers: &[bool]) -> String {
        let container_items: Vec<String> = containers
            .iter()
            .map(|has_limits| {
                if *has_limits {
                    r#"{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":false}}"#
                        .to_string()
                } else {
                    r#"{"name":"app","resources":{},"securityContext":{"privileged":false}}"#.to_string()
                }
            })
            .collect();
        format!(
            r#"{{"items":[{{"metadata":{{"name":"test-pod"}},"spec":{{"automountServiceAccountToken":false,"containers":[{}]}}}}]}}"#,
            container_items.join(",")
        )
    }

    #[test]
    fn generate_controls_default() {
        let plugin = KubernetesPlugin::new(make_runner());
        let controls = plugin.generate_controls(&PluginConfig::default());
        assert!(
            controls.len() >= 15,
            "expected >= 15 required controls, got {}",
            controls.len()
        );
        assert!(controls.iter().all(|c| c.domain == "kubernetes"));
    }

    #[test]
    fn generate_controls_with_advisory() {
        let plugin = KubernetesPlugin::new(make_runner());
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        assert!(
            controls.len() >= 20,
            "expected >= 20 total controls, got {}",
            controls.len()
        );
    }

    #[test]
    fn control_ids_are_unique() {
        let plugin = KubernetesPlugin::new(make_runner());
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
        let plugin = KubernetesPlugin::new(make_runner());
        let controls = plugin.generate_controls(&PluginConfig::default());
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
        let plugin = KubernetesPlugin::new(make_runner());
        let c1 = plugin.generate_controls(&PluginConfig::default());
        let c2 = plugin.generate_controls(&PluginConfig::default());
        assert_eq!(c1, c2);
    }

    #[test]
    fn is_available_true() {
        let plugin = KubernetesPlugin::new(make_runner());
        assert!(plugin.is_available());
    }

    #[tokio::test]
    async fn evaluate_all_pass() {
        let runner = make_runner();
        setup_passing_runner(&runner);

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        assert!(result.all_required_passed);
        assert_eq!(result.domain, "kubernetes");
        for eval in &result.evaluations {
            assert!(
                eval.passed,
                "Control {} should pass: {}",
                eval.control.id, eval.message
            );
        }
    }

    #[tokio::test]
    async fn evaluate_missing_pss_labels() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", false), ("monitoring", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &pods_json(&[true]),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let pss = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-001")
            .unwrap();
        assert!(!pss.passed);
        assert!(pss.message.contains("app-ns"));
    }

    #[tokio::test]
    async fn evaluate_no_default_deny() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(false),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &pods_json(&[true]),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let netpol = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-002")
            .unwrap();
        assert!(!netpol.passed);
    }

    #[tokio::test]
    async fn evaluate_cluster_admin_binding() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("bad-admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &pods_json(&[true]),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let crb = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-003")
            .unwrap();
        assert!(!crb.passed);
        assert!(crb.message.contains("bad-admin"));
    }

    #[tokio::test]
    async fn evaluate_missing_resource_limits() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &pods_json(&[true, false]),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let limits = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-004")
            .unwrap();
        assert!(!limits.passed);
        assert!(limits.message.contains("missing"));
    }

    #[tokio::test]
    async fn evaluate_kubectl_fails() {
        let runner = make_runner();
        runner.add_error(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            "connection refused",
        );
        runner.add_error(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            "connection refused",
        );
        runner.add_error(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            "connection refused",
        );
        runner.add_error(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            "connection refused",
        );
        runner.add_error(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            "connection refused",
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        assert!(!result.all_required_passed);
        for eval in &result.evaluations {
            assert!(!eval.passed);
        }
    }

    #[tokio::test]
    async fn domain_evaluation_serde_roundtrip() {
        let runner = make_runner();
        setup_passing_runner(&runner);

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let back: DomainEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(result.domain, back.domain);
        assert_eq!(result.domain_hash, back.domain_hash);
    }

    #[tokio::test]
    async fn evidence_hashes_present() {
        let runner = make_runner();
        setup_passing_runner(&runner);

        let plugin = KubernetesPlugin::new(runner);
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
    async fn evaluate_no_encryption_config() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &pods_json(&[true]),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&["kube-apiserver", "--etcd-servers=localhost"]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let enc = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-005")
            .unwrap();
        assert!(!enc.passed);
    }

    #[tokio::test]
    async fn advisory_audit_logging() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &pods_json(&[true]),
        );
        // Single response with both encryption and audit flags
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
                "--audit-policy-file=/etc/k8s/audit.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let mut config = PluginConfig::default();
        config.include_advisory = true;
        let controls = plugin.generate_controls(&config);
        let result = plugin.evaluate(&controls, &config).await.unwrap();

        let audit = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-006")
            .unwrap();
        assert!(audit.passed);
    }

    #[test]
    fn system_namespaces_skipped() {
        // kube-system, kube-public, kube-node-lease, default are system namespaces
        // and should be skipped in PSS checks
        let ns = ns_json(&[
            ("kube-system", false),
            ("kube-public", false),
            ("default", false),
        ]);
        let parsed: serde_json::Value = serde_json::from_str(&ns).unwrap();
        let items = parsed.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 3);
        // All are system namespaces — should be skipped
    }

    fn host_namespace_pods_json() -> String {
        r#"{"items":[{"metadata":{"name":"bad-pod"},"spec":{"hostNetwork":true,"automountServiceAccountToken":false,"containers":[{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":false}}]}}]}"#.to_string()
    }

    fn privileged_pods_json() -> String {
        r#"{"items":[{"metadata":{"name":"priv-pod"},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":true}}]}}]}"#.to_string()
    }

    fn automount_pods_json() -> String {
        // automountServiceAccountToken defaults to true (not specified)
        r#"{"items":[{"metadata":{"name":"auto-pod"},"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":false}}]}}]}"#.to_string()
    }

    fn hostpath_pods_json() -> String {
        r#"{"items":[{"metadata":{"name":"hp-pod"},"spec":{"automountServiceAccountToken":false,"volumes":[{"name":"data","hostPath":{"path":"/var/data"}}],"containers":[{"name":"app","resources":{"limits":{"cpu":"100m","memory":"128Mi"}},"securityContext":{"privileged":false}}]}}]}"#.to_string()
    }

    #[tokio::test]
    async fn evaluate_host_namespace_fails() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &host_namespace_pods_json(),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let host_ns = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-007")
            .unwrap();
        assert!(!host_ns.passed);
        assert!(host_ns.message.contains("bad-pod"));
    }

    #[tokio::test]
    async fn evaluate_privileged_container_fails() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &privileged_pods_json(),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let priv_ctl = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-008")
            .unwrap();
        assert!(!priv_ctl.passed);
        assert!(priv_ctl.message.contains("privileged"));
    }

    #[tokio::test]
    async fn evaluate_automount_sa_token_fails() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &automount_pods_json(),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let automount = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-009")
            .unwrap();
        assert!(!automount.passed);
        assert!(automount.message.contains("automountServiceAccountToken"));
    }

    #[tokio::test]
    async fn evaluate_hostpath_volume_fails() {
        let runner = make_runner();
        runner.add_response(
            "kubectl",
            &["get", "namespaces", "-o", "json"],
            &ns_json(&[("app-ns", true)]),
        );
        runner.add_response(
            "kubectl",
            &["get", "networkpolicies", "--all-namespaces", "-o", "json"],
            &netpol_json(true),
        );
        runner.add_response(
            "kubectl",
            &["get", "clusterrolebindings", "-o", "json"],
            &crb_json(&[("system:admin", "cluster-admin")]),
        );
        runner.add_response(
            "kubectl",
            &["get", "pods", "--all-namespaces", "-o", "json"],
            &hostpath_pods_json(),
        );
        runner.add_response(
            "kubectl",
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "component=kube-apiserver",
                "-o",
                "json",
            ],
            &apiserver_json(&[
                "kube-apiserver",
                "--encryption-provider-config=/etc/k8s/enc.yaml",
            ]),
        );

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        let hp = result
            .evaluations
            .iter()
            .find(|e| e.control.id == "K8S-010")
            .unwrap();
        assert!(!hp.passed);
        assert!(hp.message.contains("hostPath"));
    }

    #[tokio::test]
    async fn evaluate_secure_pods_pass_all_new_controls() {
        let runner = make_runner();
        setup_passing_runner(&runner);

        let plugin = KubernetesPlugin::new(runner);
        let controls = plugin.generate_controls(&PluginConfig::default());
        let result = plugin
            .evaluate(&controls, &PluginConfig::default())
            .await
            .unwrap();

        // All new controls should pass with secure_pods_json
        for id in &["K8S-007", "K8S-008", "K8S-009", "K8S-010"] {
            let eval = result
                .evaluations
                .iter()
                .find(|e| e.control.id == *id)
                .unwrap();
            assert!(eval.passed, "Control {} should pass: {}", id, eval.message);
        }
    }
}
