//! RSpec JSON result collector.
//!
//! Hashes RSpec JSON formatter output for attestation. The JSON format is
//! standard RSpec: `{"version":"...", "examples":[...], "summary":{...}}`.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

/// Hash RSpec JSON output from bytes.
///
/// Extracts per-example results as [`InputHash`] entries and computes a
/// composite hash over the full report bytes.
pub async fn hash_rspec_output(json_bytes: &[u8], source: &str) -> Result<LayerSignature> {
    let value: serde_json::Value = serde_json::from_slice(json_bytes).map_err(|e| {
        TameshiError::CollectorError {
            layer: "rspec_result".to_string(),
            message: format!("invalid RSpec JSON: {e}"),
        }
    })?;

    let mut inputs = Vec::new();

    // Extract per-example results
    if let Some(examples) = value.get("examples").and_then(|e| e.as_array()) {
        for (i, example) in examples.iter().enumerate() {
            let fallback = format!("example_{i}");
            let desc = example
                .get("full_description")
                .and_then(|d| d.as_str())
                .unwrap_or(&fallback);
            let status = example
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");
            let example_json = serde_json::to_vec(example).unwrap_or_default();
            inputs.push(InputHash {
                name: format!("{desc} [{status}]"),
                hash: Blake3Hash::digest(&example_json),
                size_bytes: Some(example_json.len() as u64),
            });
        }
    }

    // Composite hash of full report
    let composite = Blake3Hash::digest(json_bytes);

    Ok(LayerSignature::new(
        LayerType::RSpecResult,
        composite,
        source,
        inputs,
    ))
}

/// Hash RSpec JSON output from a file.
pub async fn hash_rspec_file(path: &str) -> Result<LayerSignature> {
    let bytes = tokio::fs::read(path).await.map_err(|e| {
        TameshiError::CollectorError {
            layer: "rspec_result".to_string(),
            message: format!("failed to read {path}: {e}"),
        }
    })?;
    hash_rspec_output(&bytes, path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;

    fn rspec_json(examples: &[(&str, &str)]) -> Vec<u8> {
        let examples_json: Vec<String> = examples
            .iter()
            .map(|(desc, status)| {
                format!(
                    r#"{{"full_description":"{}","status":"{}","run_time":0.001}}"#,
                    desc, status
                )
            })
            .collect();
        format!(
            r#"{{"version":"3.12","examples":[{}],"summary":{{"example_count":{},"failure_count":0}}}}"#,
            examples_json.join(","),
            examples.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn hash_rspec_output_standard_json() {
        let json = rspec_json(&[
            ("validates input", "passed"),
            ("rejects bad data", "passed"),
        ]);
        let sig = hash_rspec_output(&json, "rspec-output.json").await.unwrap();
        assert_eq!(sig.layer, LayerType::RSpecResult);
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.metadata.source, "rspec-output.json");
    }

    #[tokio::test]
    async fn hash_rspec_output_extracts_per_example_input_hash() {
        let json = rspec_json(&[
            ("first example", "passed"),
            ("second example", "failed"),
            ("third example", "pending"),
        ]);
        let sig = hash_rspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 3);
        assert!(sig.inputs[0].name.contains("first example"));
        assert!(sig.inputs[0].name.contains("[passed]"));
        assert!(sig.inputs[1].name.contains("second example"));
        assert!(sig.inputs[1].name.contains("[failed]"));
        assert!(sig.inputs[2].name.contains("third example"));
        assert!(sig.inputs[2].name.contains("[pending]"));
    }

    #[tokio::test]
    async fn hash_rspec_output_with_passed_failed_pending() {
        let json = rspec_json(&[
            ("passing test", "passed"),
            ("failing test", "failed"),
            ("pending test", "pending"),
        ]);
        let sig = hash_rspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 3);
        // Each input should have a non-zero size
        for input in &sig.inputs {
            assert!(input.size_bytes.unwrap() > 0);
        }
    }

    #[tokio::test]
    async fn hash_rspec_output_determinism() {
        let json = rspec_json(&[("determinism test", "passed")]);
        let sig1 = hash_rspec_output(&json, "test").await.unwrap();
        let sig2 = hash_rspec_output(&json, "test").await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
        assert_eq!(sig1.inputs.len(), sig2.inputs.len());
        for (a, b) in sig1.inputs.iter().zip(sig2.inputs.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.name, b.name);
        }
    }

    #[tokio::test]
    async fn hash_rspec_output_empty_examples() {
        let json = br#"{"version":"3.12","examples":[],"summary":{"example_count":0}}"#;
        let sig = hash_rspec_output(json, "empty").await.unwrap();
        assert_eq!(sig.layer, LayerType::RSpecResult);
        assert!(sig.inputs.is_empty());
        // Composite hash should still be computed from full bytes
        assert_ne!(sig.hash, Blake3Hash::digest(b""));
    }

    #[tokio::test]
    async fn hash_rspec_output_invalid_json_returns_error() {
        let result = hash_rspec_output(b"not valid json{{{", "bad").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid RSpec JSON"));
    }

    #[tokio::test]
    async fn hash_rspec_file_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rspec_output.json");
        let json = rspec_json(&[("file test", "passed")]);
        tokio::fs::write(&path, &json).await.unwrap();

        let sig = hash_rspec_file(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::RSpecResult);
        assert_eq!(sig.inputs.len(), 1);
        assert!(sig.inputs[0].name.contains("file test"));
    }

    #[tokio::test]
    async fn hash_rspec_file_nonexistent_returns_error() {
        let result = hash_rspec_file("/nonexistent/rspec_output.json").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read"));
    }

    #[tokio::test]
    async fn layer_signature_has_correct_layer_type() {
        let json = rspec_json(&[("type check", "passed")]);
        let sig = hash_rspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.layer, LayerType::RSpecResult);
        assert_eq!(sig.layer.to_string(), "rspec_result");
    }

    #[tokio::test]
    async fn integration_hash_to_certification_artifact() {
        let json = rspec_json(&[("integration test", "passed")]);
        let sig = hash_rspec_output(&json, "test").await.unwrap();

        // Use rspec hash as the control_hash in a certification artifact
        let artifact = compose_certification_artifact(
            "/usr/bin/app",
            Blake3Hash::digest(b"nix-closure"),
            sig.hash.clone(),
            Blake3Hash::digest(b"pangea-synthesis"),
            "staging",
        );
        assert_eq!(artifact.control_hash, sig.hash);
        assert!(!artifact.composed_root.to_hex().is_empty());
    }

    #[tokio::test]
    async fn hash_rspec_output_missing_full_description_uses_fallback() {
        let json = br#"{"version":"3.12","examples":[{"status":"passed","run_time":0.01}]}"#;
        let sig = hash_rspec_output(json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        assert!(sig.inputs[0].name.contains("example_0"));
    }

    #[tokio::test]
    async fn hash_rspec_output_missing_status_uses_unknown() {
        let json = br#"{"version":"3.12","examples":[{"full_description":"some test"}]}"#;
        let sig = hash_rspec_output(json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        assert!(sig.inputs[0].name.contains("[unknown]"));
    }

    #[tokio::test]
    async fn hash_rspec_output_no_examples_key() {
        let json = br#"{"version":"3.12","summary":{"example_count":0}}"#;
        let sig = hash_rspec_output(json, "test").await.unwrap();
        assert!(sig.inputs.is_empty());
        assert_eq!(sig.layer, LayerType::RSpecResult);
    }

    #[tokio::test]
    async fn hash_rspec_output_many_examples() {
        let examples: Vec<(&str, &str)> = (0..50)
            .map(|_| ("test example", "passed"))
            .collect();
        let json = rspec_json(&examples);
        let sig = hash_rspec_output(&json, "test").await.unwrap();
        assert_eq!(sig.inputs.len(), 50);
    }

    #[tokio::test]
    async fn hash_rspec_output_different_content_different_hash() {
        let json1 = rspec_json(&[("test A", "passed")]);
        let json2 = rspec_json(&[("test B", "failed")]);
        let sig1 = hash_rspec_output(&json1, "test").await.unwrap();
        let sig2 = hash_rspec_output(&json2, "test").await.unwrap();
        assert_ne!(sig1.hash, sig2.hash);
    }
}
