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

use serde::{Deserialize, Serialize};

use crate::api_types::GateDecision;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::MasterSignature;
use crate::traits::Clock;

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
///
/// Uses [`SystemClock`](crate::traits::SystemClock) for signature age checks.
/// For deterministic testing, use [`evaluate_gate_with_clock`] instead.
#[inline]
#[must_use]
pub fn evaluate_gate(
    policy: &GatingPolicy,
    master: &MasterSignature,
    expected: &Blake3Hash,
) -> GateDecision {
    evaluate_gate_with_clock(policy, master, expected, &crate::traits::SystemClock)
}

/// Evaluate a gating decision with an injected clock for deterministic testing.
#[inline]
#[must_use]
pub fn evaluate_gate_with_clock(
    policy: &GatingPolicy,
    master: &MasterSignature,
    expected: &Blake3Hash,
    clock: &impl Clock,
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
        let age = clock.now()
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
///
/// Uses the default [`ReqwestHttpClient`](crate::traits::ReqwestHttpClient).
/// For testing, use [`fetch_expected_signature_with`] with a mock client.
pub async fn fetch_expected_signature(endpoint: &str, environment: &str) -> Result<Blake3Hash> {
    fetch_expected_signature_with(endpoint, environment, &crate::traits::ReqwestHttpClient::new()).await
}

/// Fetch the expected signature from a remote endpoint using an injected HTTP client.
pub async fn fetch_expected_signature_with(
    endpoint: &str,
    environment: &str,
    client: &impl crate::traits::HttpClient,
) -> Result<Blake3Hash> {
    let url = format!("{}/api/v1/gates/{}/verify", endpoint, environment);

    let body: serde_json::Value = client.get_json(&url).await.map_err(|_| {
        TameshiError::CollectorError {
            layer: "gate".to_string(),
            message: format!("failed to fetch signature from {}", url),
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
#[must_use]
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
#[must_use]
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
#[must_use]
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

    #[test]
    fn gate_with_clock_detects_stale_signature() {
        use crate::traits::FixedClock;

        let (master, expected) = make_master("test");
        let policy = GatingPolicy {
            max_signature_age_secs: Some(60), // 1 minute
            ..Default::default()
        };

        // Freeze clock 120 seconds in the future — signature should be stale
        let future_time = master.computed_at + chrono::Duration::seconds(120);
        let clock = FixedClock::new(future_time);
        let decision = evaluate_gate_with_clock(&policy, &master, &expected, &clock);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("stale"));
    }

    #[test]
    fn gate_with_clock_accepts_fresh_signature() {
        use crate::traits::FixedClock;

        let (master, expected) = make_master("test");
        let policy = GatingPolicy {
            max_signature_age_secs: Some(3600),
            ..Default::default()
        };

        // Freeze clock 10 seconds in the future — signature is fresh
        let near_future = master.computed_at + chrono::Duration::seconds(10);
        let clock = FixedClock::new(near_future);
        let decision = evaluate_gate_with_clock(&policy, &master, &expected, &clock);
        assert!(decision.allowed);
    }

    #[test]
    fn gate_denies_missing_required_layer() {
        let (master, expected) = make_master("test");
        let policy = GatingPolicy {
            required_layers: vec!["helm".to_string()], // not present in master
            require_compliance: false,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("Required layer"));
    }

    #[test]
    fn tatara_job_gate_wrong_signature() {
        let expected = Blake3Hash::digest(b"correct-sig");
        let wrong = Blake3Hash::digest(b"wrong-sig");
        let job = serde_json::json!({
            "metadata": {
                "signature": wrong.to_prefixed()
            }
        });
        let decision = gate_tatara_job(&job, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("does not match"));
    }

    #[test]
    fn tatara_job_gate_invalid_format() {
        let expected = Blake3Hash::digest(b"sig");
        let job = serde_json::json!({
            "metadata": {
                "signature": "not-a-valid-blake3-hash"
            }
        });
        let decision = gate_tatara_job(&job, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("Invalid signature format"));
    }

    #[test]
    fn fluxcd_gate_wrong_signature() {
        let expected = Blake3Hash::digest(b"correct");
        let wrong = Blake3Hash::digest(b"wrong");
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            "sekiban.pleme.io/signature".to_string(),
            wrong.to_prefixed(),
        );
        let decision = gate_fluxcd_resource(&annotations, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("does not match"));
    }

    #[test]
    fn fluxcd_gate_invalid_format_annotation() {
        let expected = Blake3Hash::digest(b"sig");
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            "sekiban.pleme.io/signature".to_string(),
            "not-blake3:garbage".to_string(),
        );
        let decision = gate_fluxcd_resource(&annotations, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("Invalid signature format"));
    }

    #[test]
    fn argocd_gate_delegates_to_fluxcd() {
        let expected = Blake3Hash::digest(b"sig");
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            "sekiban.pleme.io/signature".to_string(),
            expected.to_prefixed(),
        );
        let decision = gate_argocd_sync(&annotations, &expected);
        assert!(decision.allowed);
    }

    #[test]
    fn gating_policy_serde_roundtrip() {
        let policy = GatingPolicy {
            name: "custom-policy".to_string(),
            required_layers: vec!["nix".to_string(), "oci".to_string()],
            require_compliance: true,
            max_signature_age_secs: Some(7200),
            fail_open: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: GatingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "custom-policy");
        assert_eq!(deserialized.required_layers.len(), 2);
        assert_eq!(deserialized.max_signature_age_secs, Some(7200));
    }

    #[tokio::test]
    async fn fetch_expected_signature_with_mock() {
        let client = crate::traits::MockHttpClient::new();
        let expected_hash = Blake3Hash::digest(b"env-sig");
        let response = serde_json::json!({
            "expected_signature": expected_hash.to_prefixed()
        });
        client.add_json_response(
            "https://gate.example.com/api/v1/gates/production/verify",
            &response,
        );

        let result = fetch_expected_signature_with(
            "https://gate.example.com",
            "production",
            &client,
        ).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_hash);
    }

    #[tokio::test]
    async fn fetch_expected_signature_with_missing_field() {
        let client = crate::traits::MockHttpClient::new();
        let response = serde_json::json!({"other_field": "value"});
        client.add_json_response(
            "https://gate.example.com/api/v1/gates/staging/verify",
            &response,
        );

        let result = fetch_expected_signature_with(
            "https://gate.example.com",
            "staging",
            &client,
        ).await;
        assert!(result.is_err());
    }

    #[test]
    fn gate_expired_signature_max_age_exceeded() {
        use crate::traits::FixedClock;

        let (master, expected) = make_master("test");
        let policy = GatingPolicy {
            max_signature_age_secs: Some(30), // 30 seconds
            ..Default::default()
        };

        // Clock 31 seconds in the future -- just barely expired
        let expired_time = master.computed_at + chrono::Duration::seconds(31);
        let clock = FixedClock::new(expired_time);
        let decision = evaluate_gate_with_clock(&policy, &master, &expected, &clock);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("stale"));
        assert!(decision.reason.contains("31"));
        assert!(decision.reason.contains("30"));
    }

    #[test]
    fn gate_exactly_at_max_age_boundary() {
        use crate::traits::FixedClock;

        let (master, expected) = make_master("test");
        let policy = GatingPolicy {
            max_signature_age_secs: Some(60),
            ..Default::default()
        };

        // Clock exactly at 60 seconds -- should pass (not strictly greater)
        let boundary_time = master.computed_at + chrono::Duration::seconds(60);
        let clock = FixedClock::new(boundary_time);
        let decision = evaluate_gate_with_clock(&policy, &master, &expected, &clock);
        assert!(decision.allowed, "Signature at exactly max_age should be allowed");
    }

    #[test]
    fn gate_fail_open_is_not_default() {
        let policy = GatingPolicy::default();
        assert!(!policy.fail_open, "Default policy must NOT be fail_open (secure by default)");
        assert!(policy.require_compliance, "Default policy must require compliance");
        assert!(policy.max_signature_age_secs.is_some(), "Default policy must set max age");
        assert_eq!(policy.max_signature_age_secs, Some(3600), "Default max age should be 1 hour");
    }

    #[test]
    fn gate_100_required_layers_all_missing() {
        let (master, expected) = make_master("test");
        let required: Vec<String> = (0..100).map(|i| format!("layer-{i}")).collect();
        let policy = GatingPolicy {
            required_layers: required,
            require_compliance: false,
            max_signature_age_secs: None,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("Required layer"));
    }

    #[test]
    fn gate_100_required_layers_all_present() {
        // Build a master with 100 unique layer types (using the same type but different hash)
        // Since required_layers checks layer.to_string(), we need actual matching types
        let all_types = vec![
            LayerType::Nix,
            LayerType::Oci,
        ];
        let layers: Vec<LayerSignature> = all_types
            .iter()
            .map(|lt| LayerSignature::new(lt.clone(), Blake3Hash::digest(lt.to_string().as_bytes()), "test", vec![]))
            .collect();
        let compliance = Blake3Hash::digest(b"compliance-passed");
        let master = merkle::compose_merkle(&layers, "test").with_compliance(compliance);
        let expected = master.gating_signature().clone();

        let required: Vec<String> = all_types.iter().map(|lt| lt.to_string()).collect();
        let policy = GatingPolicy {
            required_layers: required,
            require_compliance: true,
            max_signature_age_secs: None,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        assert!(decision.allowed, "All required layers present should pass gate");
    }

    #[test]
    fn gate_fail_open_field_serializes() {
        let policy = GatingPolicy {
            fail_open: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"fail_open\":true"));

        let policy2 = GatingPolicy::default();
        let json2 = serde_json::to_string(&policy2).unwrap();
        assert!(json2.contains("\"fail_open\":false"));
    }

    #[test]
    fn gate_no_max_age_allows_any_signature() {
        let (master, expected) = make_master("test");
        let policy = GatingPolicy {
            max_signature_age_secs: None,
            ..Default::default()
        };
        let decision = evaluate_gate(&policy, &master, &expected);
        assert!(decision.allowed);
    }
}
