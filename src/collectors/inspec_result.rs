//! InSpec JSON result collector.
//!
//! Hashes InSpec JSON reporter output for attestation. InSpec produces
//! deterministic JSON with control results, profiles, and statistics.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

/// Hash InSpec JSON output from bytes.
///
/// Extracts per-control results as [`InputHash`] entries. Uses the control ID
/// as the input name for traceability.
pub async fn hash_inspec_output(json_bytes: &[u8], source: &str) -> Result<LayerSignature> {
    let value: serde_json::Value =
        serde_json::from_slice(json_bytes).map_err(|e| TameshiError::CollectorError {
            layer: "inspec_result".to_string(),
            message: format!("invalid InSpec JSON: {e}"),
        })?;

    let mut inputs = Vec::new();

    // InSpec JSON structure: { "profiles": [{ "controls": [{ "id": ..., "results": [...] }] }] }
    if let Some(profiles) = value.get("profiles").and_then(|p| p.as_array()) {
        for profile in profiles {
            let profile_name = profile
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            if let Some(controls) = profile.get("controls").and_then(|c| c.as_array()) {
                for control in controls {
                    let control_id = control
                        .get("id")
                        .and_then(|i| i.as_str())
                        .unwrap_or("unknown");
                    let impact = control
                        .get("impact")
                        .and_then(|i| i.as_f64())
                        .unwrap_or(0.0);
                    let control_json = serde_json::to_vec(control).unwrap_or_default();
                    inputs.push(InputHash {
                        name: format!("{profile_name}/{control_id} [impact={impact:.1}]"),
                        hash: Blake3Hash::digest(&control_json),
                        size_bytes: Some(control_json.len() as u64),
                    });
                }
            }
        }
    }

    let composite = Blake3Hash::digest(json_bytes);
    Ok(LayerSignature::new(
        LayerType::InSpecResult,
        composite,
        source,
        inputs,
    ))
}

/// Hash InSpec JSON output from a file.
pub async fn hash_inspec_file(path: &str) -> Result<LayerSignature> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "inspec_result".to_string(),
            message: format!("failed to read {path}: {e}"),
        })?;
    hash_inspec_output(&bytes, path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;

    fn inspec_json(profiles: &[(&str, &[(&str, f64)])]) -> Vec<u8> {
        let profiles_json: Vec<String> = profiles
            .iter()
            .map(|(name, controls)| {
                let controls_json: Vec<String> = controls
                    .iter()
                    .map(|(id, impact)| {
                        format!(
                            r#"{{"id":"{}","impact":{},"title":"Control {}","results":[{{"status":"passed"}}]}}"#,
                            id, impact, id
                        )
                    })
                    .collect();
                format!(
                    r#"{{"name":"{}","controls":[{}]}}"#,
                    name,
                    controls_json.join(",")
                )
            })
            .collect();
        format!(
            r#"{{"profiles":[{}],"statistics":{{"duration":0.5}}}}"#,
            profiles_json.join(",")
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn hash_inspec_output_standard_json() {
        let json = inspec_json(&[("my-profile", &[("ctrl-001", 0.7), ("ctrl-002", 1.0)])]);
        let sig = hash_inspec_output(&json, "inspec-output.json")
            .await
            .unwrap();
        assert_eq!(sig.layer, LayerType::InSpecResult);
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.metadata.source, "inspec-output.json");
    }

    #[tokio::test]
    async fn hash_inspec_output_extracts_per_control_with_id() {
        let json = inspec_json(&[("profile-a", &[("sshd-01", 0.7), ("sshd-02", 1.0)])]);
        let sig = hash_inspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 2);
        assert!(sig.inputs[0].name.contains("profile-a/sshd-01"));
        assert!(sig.inputs[1].name.contains("profile-a/sshd-02"));
    }

    #[tokio::test]
    async fn hash_inspec_output_multiple_profiles() {
        let json = inspec_json(&[
            ("profile-a", &[("ctrl-a1", 0.5)]),
            ("profile-b", &[("ctrl-b1", 1.0), ("ctrl-b2", 0.3)]),
        ]);
        let sig = hash_inspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 3);
        assert!(sig.inputs[0].name.contains("profile-a/ctrl-a1"));
        assert!(sig.inputs[1].name.contains("profile-b/ctrl-b1"));
        assert!(sig.inputs[2].name.contains("profile-b/ctrl-b2"));
    }

    #[tokio::test]
    async fn hash_inspec_output_impact_scores_in_names() {
        let json = inspec_json(&[("profile", &[("ctrl-high", 1.0), ("ctrl-low", 0.3)])]);
        let sig = hash_inspec_output(&json, "test").await.unwrap();
        assert!(sig.inputs[0].name.contains("[impact=1.0]"));
        assert!(sig.inputs[1].name.contains("[impact=0.3]"));
    }

    #[tokio::test]
    async fn hash_inspec_output_determinism() {
        let json = inspec_json(&[("profile", &[("ctrl-001", 0.7)])]);
        let sig1 = hash_inspec_output(&json, "test").await.unwrap();
        let sig2 = hash_inspec_output(&json, "test").await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
        assert_eq!(sig1.inputs.len(), sig2.inputs.len());
        for (a, b) in sig1.inputs.iter().zip(sig2.inputs.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.name, b.name);
        }
    }

    #[tokio::test]
    async fn hash_inspec_output_empty_controls() {
        let json = br#"{"profiles":[{"name":"empty","controls":[]}]}"#;
        let sig = hash_inspec_output(json, "empty").await.unwrap();
        assert_eq!(sig.layer, LayerType::InSpecResult);
        assert!(sig.inputs.is_empty());
    }

    #[tokio::test]
    async fn hash_inspec_output_invalid_json_returns_error() {
        let result = hash_inspec_output(b"not valid json{{{", "bad").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid InSpec JSON"));
    }

    #[tokio::test]
    async fn hash_inspec_file_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inspec_output.json");
        let json = inspec_json(&[("file-profile", &[("file-ctrl", 0.5)])]);
        tokio::fs::write(&path, &json).await.unwrap();

        let sig = hash_inspec_file(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::InSpecResult);
        assert_eq!(sig.inputs.len(), 1);
        assert!(sig.inputs[0].name.contains("file-profile/file-ctrl"));
    }

    #[tokio::test]
    async fn hash_inspec_file_nonexistent_returns_error() {
        let result = hash_inspec_file("/nonexistent/inspec_output.json").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read"));
    }

    #[tokio::test]
    async fn integration_hash_to_certification_artifact() {
        let json = inspec_json(&[("integration", &[("int-ctrl", 0.7)])]);
        let sig = hash_inspec_output(&json, "test").await.unwrap();

        // Use inspec result hash as the control_hash in a certification artifact
        let artifact = compose_certification_artifact(
            "/usr/bin/app",
            Blake3Hash::digest(b"nix-closure"),
            sig.hash.clone(),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );
        assert_eq!(artifact.control_hash, sig.hash);
        assert!(!artifact.composed_root.to_hex().is_empty());
    }

    #[tokio::test]
    async fn hash_inspec_output_no_profiles_key() {
        let json = br#"{"statistics":{"duration":0.1}}"#;
        let sig = hash_inspec_output(json, "test").await.unwrap();
        assert!(sig.inputs.is_empty());
        assert_eq!(sig.layer, LayerType::InSpecResult);
    }

    #[tokio::test]
    async fn hash_inspec_output_missing_control_id_uses_unknown() {
        let json = br#"{"profiles":[{"name":"p","controls":[{"impact":0.5,"results":[]}]}]}"#;
        let sig = hash_inspec_output(json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        assert!(sig.inputs[0].name.contains("p/unknown"));
    }

    #[tokio::test]
    async fn hash_inspec_output_missing_impact_uses_zero() {
        let json = br#"{"profiles":[{"name":"p","controls":[{"id":"ctrl-1","results":[]}]}]}"#;
        let sig = hash_inspec_output(json, "test").await.unwrap();
        assert!(sig.inputs[0].name.contains("[impact=0.0]"));
    }

    #[tokio::test]
    async fn hash_inspec_output_different_content_different_hash() {
        let json1 = inspec_json(&[("profile", &[("ctrl-a", 0.7)])]);
        let json2 = inspec_json(&[("profile", &[("ctrl-b", 1.0)])]);
        let sig1 = hash_inspec_output(&json1, "test").await.unwrap();
        let sig2 = hash_inspec_output(&json2, "test").await.unwrap();
        assert_ne!(sig1.hash, sig2.hash);
    }

    #[tokio::test]
    async fn hash_inspec_output_layer_type_string() {
        let json = inspec_json(&[("p", &[("c", 0.5)])]);
        let sig = hash_inspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.layer.to_string(), "inspec_result");
    }
}
