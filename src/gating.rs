//! Universal gating primitives for all provisioning layers.
//!
//! Every provisioning system (Nix, Kubernetes, FluxCD, ArgoCD, Tatara, Kindling)
//! must verify a master secure signature before allowing changes. This module
//! provides the shared gating logic that each system's gate implementation uses.
//!
//! ## Gating Points
//!
//! | System | Gate Type | Implementation |
//! |--------|-----------|---------------|
//! | Nix | Pre-activation script | inshou (activation gate) |
//! | Kubernetes | Admission webhook | sekiban (ValidatingAdmissionWebhook) |
//! | FluxCD | Annotation check | sekiban (Kustomization/HelmRelease gate) |
//! | ArgoCD | Sync hook | sekiban (pre-sync gate) |
//! | Tatara | Job submission gate | tameshi (signature check in job spec) |
//! | Kindling | Identity verification | tameshi (identity document gate) |
//! | Helm | Chart verification | inshou/sekiban (provenance check) |
//! | OpenTofu | Pre-apply check | inshou (state verification) |

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::api_types::GateDecision;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::MasterSignature;

/// A gating policy that defines what must be verified before provisioning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatingPolicy {
    /// Policy name.
    pub name: String,
    /// Which layers must be present in the master signature.
    pub required_layers: Vec<String>,
    /// Whether compliance hash is required (not just untested).
    pub require_compliance: bool,
    /// Maximum age of the signature before it's considered stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_signature_age_secs: Option<u64>,
    /// Whether to allow if the gate endpoint is unreachable.
    pub fail_open: bool,
}

impl Default for GatingPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            required_layers: vec![],
            require_compliance: true,
            fail_open: false, // Fail closed by default
            max_signature_age_secs: Some(3600), // 1 hour
        }
    }
}

/// Evaluate a gating decision against a master signature and expected hash.
pub fn evaluate_gate(
    policy: &GatingPolicy,
    master: &MasterSignature,
    expected: &Blake3Hash,
) -> GateDecision {
    // Check if compliance is required and present
    if policy.require_compliance && !master.is_fully_attested() {
        return GateDecision::deny(
            master.gating_signature(),
            expected,
            &policy.name,
            "Compliance hash required but not present in master signature",
        );
    }

    // Check signature age if configured
    if let Some(max_age) = policy.max_signature_age_secs {
        let age = Utc::now()
            .signed_duration_since(master.computed_at)
            .num_seconds();
        if age > max_age as i64 {
            return GateDecision::deny(
                master.gating_signature(),
                expected,
                &policy.name,
                &format!(
                    "Signature is stale: {}s old (max {}s)",
                    age, max_age
                ),
            );
        }
    }

    // Check required layers
    for required_layer in &policy.required_layers {
        let found = master.layers.iter().any(|l| l.layer.to_string() == *required_layer);
        if !found {
            return GateDecision::deny(
                master.gating_signature(),
                expected,
                &policy.name,
                &format!("Required layer '{}' not in master signature", required_layer),
            );
        }
    }

    // Verify the signature
    let gating_sig = master.gating_signature();
    if *gating_sig != *expected {
        return GateDecision::deny(
            gating_sig,
            expected,
            &policy.name,
            "Signature mismatch",
        );
    }

    // Verify internal consistency
    if !master.verify_untested() {
        return GateDecision::deny(
            gating_sig,
            expected,
            &policy.name,
            "Merkle root recomputation failed — signature integrity compromised",
        );
    }

    if master.is_fully_attested() && !master.verify_secure() {
        return GateDecision::deny(
            gating_sig,
            expected,
            &policy.name,
            "Secure signature recomputation failed — compliance chain broken",
        );
    }

    GateDecision::allow(gating_sig, expected, &policy.name)
}

/// Fetch the expected signature from a remote endpoint.
pub async fn fetch_expected_signature(endpoint: &str, environment: &str) -> Result<Blake3Hash> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/gates/{}/verify", endpoint, environment);

    let resp = client.get(&url).send().await.map_err(|e| {
        TameshiError::CollectorError {
            layer: "gate".to_string(),
            message: format!("failed to fetch signature from {}: {}", url, e),
        }
    })?;

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        TameshiError::CollectorError {
            layer: "gate".to_string(),
            message: format!("failed to parse gate response: {}", e),
        }
    })?;

    let sig_str = body
        .get("expected_signature")
        .and_then(|s| s.as_str())
        .ok_or_else(|| TameshiError::CollectorError {
            layer: "gate".to_string(),
            message: "gate response missing expected_signature field".to_string(),
        })?;

    Blake3Hash::from_prefixed(sig_str).map_err(|e| {
        TameshiError::InvalidInput(format!("invalid signature format: {}", e))
    })
}

/// Tatara-specific gating: verify a job submission has a valid signature.
pub fn gate_tatara_job(
    job_spec: &serde_json::Value,
    expected_signature: &Blake3Hash,
) -> GateDecision {
    // Extract signature from job spec metadata
    let sig_str = job_spec
        .get("metadata")
        .and_then(|m| m.get("signature"))
        .and_then(|s| s.as_str());

    match sig_str {
        None => GateDecision::deny(
            &Blake3Hash::digest(b"missing"),
            expected_signature,
            "tatara-job-gate",
            "Job spec missing required signature in metadata.signature",
        ),
        Some(sig) => match Blake3Hash::from_prefixed(sig) {
            Ok(job_sig) => {
                if job_sig == *expected_signature {
                    GateDecision::allow(&job_sig, expected_signature, "tatara-job-gate")
                } else {
                    GateDecision::deny(
                        &job_sig,
                        expected_signature,
                        "tatara-job-gate",
                        "Job signature does not match expected environment signature",
                    )
                }
            }
            Err(_) => GateDecision::deny(
                &Blake3Hash::digest(sig.as_bytes()),
                expected_signature,
                "tatara-job-gate",
                "Invalid signature format in job spec",
            ),
        },
    }
}

/// FluxCD gating: verify a Kustomization/HelmRelease annotation.
pub fn gate_fluxcd_resource(
    annotations: &std::collections::HashMap<String, String>,
    expected_signature: &Blake3Hash,
) -> GateDecision {
    let sig_str = annotations.get("sekiban.pleme.io/signature");

    match sig_str {
        None => GateDecision::deny(
            &Blake3Hash::digest(b"missing"),
            expected_signature,
            "fluxcd-gate",
            "Resource missing sekiban.pleme.io/signature annotation",
        ),
        Some(sig) => match Blake3Hash::from_prefixed(sig) {
            Ok(resource_sig) => {
                if resource_sig == *expected_signature {
                    GateDecision::allow(&resource_sig, expected_signature, "fluxcd-gate")
                } else {
                    GateDecision::deny(
                        &resource_sig,
                        expected_signature,
                        "fluxcd-gate",
                        "Annotation signature does not match expected",
                    )
                }
            }
            Err(_) => GateDecision::deny(
                &Blake3Hash::digest(sig.as_bytes()),
                expected_signature,
                "fluxcd-gate",
                "Invalid signature format in annotation",
            ),
        },
    }
}

/// ArgoCD gating: verify sync operation has valid signature.
pub fn gate_argocd_sync(
    app_annotations: &std::collections::HashMap<String, String>,
    expected_signature: &Blake3Hash,
) -> GateDecision {
    // ArgoCD uses the same annotation pattern
    gate_fluxcd_resource(app_annotations, expected_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::signature::{LayerSignature, LayerType};

    fn make_master(environment: &str) -> (MasterSignature, Blake3Hash) {
        let layers = vec![
            LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
            LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
        ];
        let compliance = Blake3Hash::digest(b"compliance-passed");
        let master = merkle::compose_merkle(&layers, environment).with_compliance(compliance);
        let expected = master.gating_signature().clone();
        (master, expected)
    }

    #[test]
    fn gate_allows_valid_signature() {
        let (master, expected) = make_master("test");
        let policy = GatingPolicy::default();
        let decision = evaluate_gate(&policy, &master, &expected);
        assert!(decision.allowed);
    }

    #[test]
    fn gate_denies_wrong_signature() {
        let (master, _) = make_master("test");
        let wrong = Blake3Hash::digest(b"wrong");
        let policy = GatingPolicy::default();
        let decision = evaluate_gate(&policy, &master, &wrong);
        assert!(!decision.allowed);
    }

    #[test]
    fn gate_denies_missing_compliance() {
        let layers = vec![
            LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
        ];
        let master = merkle::compose_merkle(&layers, "test");
        let expected = master.gating_signature().clone();
        let policy = GatingPolicy {
            require_compliance: true,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("Compliance hash required"));
    }

    #[test]
    fn tatara_job_gate_valid() {
        let expected = Blake3Hash::digest(b"env-sig");
        let job = serde_json::json!({
            "metadata": {
                "signature": expected.to_prefixed()
            }
        });
        let decision = gate_tatara_job(&job, &expected);
        assert!(decision.allowed);
    }

    #[test]
    fn tatara_job_gate_missing_sig() {
        let expected = Blake3Hash::digest(b"env-sig");
        let job = serde_json::json!({"metadata": {}});
        let decision = gate_tatara_job(&job, &expected);
        assert!(!decision.allowed);
    }

    #[test]
    fn fluxcd_gate_valid_annotation() {
        let expected = Blake3Hash::digest(b"sig");
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            "sekiban.pleme.io/signature".to_string(),
            expected.to_prefixed(),
        );
        let decision = gate_fluxcd_resource(&annotations, &expected);
        assert!(decision.allowed);
    }

    #[test]
    fn fluxcd_gate_missing_annotation() {
        let expected = Blake3Hash::digest(b"sig");
        let annotations = std::collections::HashMap::new();
        let decision = gate_fluxcd_resource(&annotations, &expected);
        assert!(!decision.allowed);
    }
}
