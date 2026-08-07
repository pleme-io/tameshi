//! Pangea synthesis output collector.
//!
//! Hashes deterministic Terraform JSON produced by Pangea's Ruby synthesizer.
//! The synthesis output is canonical by construction (Pangea sorts keys),
//! making it suitable for attestation without additional canonicalization.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};
use crate::traits::CommandRunner;

use super::traits::LayerCollector;

/// Hash Pangea synthesis JSON output from bytes.
///
/// Parses the JSON, extracts individual resource blocks as [`InputHash`] entries,
/// and computes the composite BLAKE3 hash. The JSON is re-serialized with
/// sorted keys for deterministic hashing.
pub async fn hash_synthesis_json(json_bytes: &[u8], source: &str) -> Result<LayerSignature> {
    let value: serde_json::Value =
        serde_json::from_slice(json_bytes).map_err(|e| TameshiError::CollectorError {
            layer: "pangea_synthesis".to_string(),
            message: format!("invalid JSON: {e}"),
        })?;

    let mut inputs = Vec::new();

    // Extract resource blocks from Terraform JSON structure.
    // Terraform JSON: { "resource": { "type": { "name": { ... } } } }
    if let Some(resources) = value.get("resource").and_then(|r| r.as_object()) {
        let mut resource_types: Vec<_> = resources.keys().collect();
        resource_types.sort();

        for resource_type in resource_types {
            if let Some(instances) = resources[resource_type].as_object() {
                let mut instance_names: Vec<_> = instances.keys().collect();
                instance_names.sort();

                for instance_name in instance_names {
                    let block_json =
                        serde_json::to_vec(&instances[instance_name]).unwrap_or_default();
                    inputs.push(InputHash {
                        name: format!("{resource_type}.{instance_name}"),
                        hash: Blake3Hash::digest(&block_json),
                        size_bytes: Some(block_json.len() as u64),
                    });
                }
            }
        }
    }

    // Also hash data sources.
    if let Some(data) = value.get("data").and_then(|d| d.as_object()) {
        let mut data_types: Vec<_> = data.keys().collect();
        data_types.sort();

        for data_type in data_types {
            if let Some(instances) = data[data_type].as_object() {
                let mut names: Vec<_> = instances.keys().collect();
                names.sort();
                for name in names {
                    let block_json = serde_json::to_vec(&instances[name]).unwrap_or_default();
                    inputs.push(InputHash {
                        name: format!("data.{data_type}.{name}"),
                        hash: Blake3Hash::digest(&block_json),
                        size_bytes: Some(block_json.len() as u64),
                    });
                }
            }
        }
    }

    // Composite hash of ALL canonical JSON bytes.
    let canonical = serde_json::to_vec(&value).map_err(|e| TameshiError::CollectorError {
        layer: "pangea_synthesis".to_string(),
        message: format!("JSON canonicalization failed: {e}"),
    })?;
    let composite = Blake3Hash::digest(&canonical);

    Ok(LayerSignature::new(
        LayerType::PangeaSynthesis,
        composite,
        source,
        inputs,
    ))
}

/// Hash Pangea synthesis JSON from a file path.
pub async fn hash_synthesis_file(path: &str) -> Result<LayerSignature> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "pangea_synthesis".to_string(),
            message: format!("failed to read {path}: {e}"),
        })?;
    hash_synthesis_json(&bytes, path).await
}

/// Pangea synthesis collector parameterized over a [`CommandRunner`].
///
/// Runs the Pangea synthesis command, reads the output file, and hashes the
/// resulting deterministic Terraform JSON.
pub struct PangeaSynthesisCollector<C: CommandRunner> {
    /// Directory containing the Pangea project.
    working_dir: String,
    /// Path to the synthesis output JSON file.
    output_file: String,
    /// Command runner for executing the synthesis command.
    command_runner: C,
}

impl<C: CommandRunner> PangeaSynthesisCollector<C> {
    /// Create a new Pangea synthesis collector.
    #[must_use]
    pub fn new(working_dir: &str, output_file: &str, command_runner: C) -> Self {
        Self {
            working_dir: working_dir.to_string(),
            output_file: output_file.to_string(),
            command_runner,
        }
    }
}

impl<C: CommandRunner> LayerCollector for PangeaSynthesisCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        // Run Pangea synthesis.
        self.command_runner
            .run_in_dir(
                "bundle",
                &[
                    "exec",
                    "ruby",
                    "-e",
                    "require 'pangea'; puts Pangea::Synthesizer.new.synthesis.to_json",
                ],
                &self.working_dir,
            )
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "pangea_synthesis".to_string(),
                message: format!("synthesis command failed: {e}"),
            })?;

        // Hash the output.
        hash_synthesis_file(&self.output_file).await
    }

    fn layer_type(&self) -> LayerType {
        LayerType::PangeaSynthesis
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;
    use crate::traits::MockCommandRunner;

    // -----------------------------------------------------------------------
    // 1. hash_synthesis_json with empty JSON object (valid but no resources)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_empty_object() {
        let json = b"{}";
        let sig = hash_synthesis_json(json, "empty.json").await.unwrap();
        assert_eq!(sig.layer, LayerType::PangeaSynthesis);
        assert!(sig.inputs.is_empty());
        assert_eq!(sig.metadata.source, "empty.json");
    }

    // -----------------------------------------------------------------------
    // 2. hash_synthesis_json with one resource type, one instance
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_one_resource() {
        let json = br#"{
            "resource": {
                "akeyless_auth_method": {
                    "my_auth": {"name": "/my-auth", "type": "api_key"}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "single.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "akeyless_auth_method.my_auth");
        assert!(sig.inputs[0].size_bytes.is_some());
    }

    // -----------------------------------------------------------------------
    // 3. hash_synthesis_json with multiple resource types (sorted ordering)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_multiple_types_sorted() {
        let json = br#"{
            "resource": {
                "akeyless_target": {
                    "t1": {"name": "target-1"}
                },
                "akeyless_auth_method": {
                    "a1": {"name": "auth-1"}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "multi.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 2);
        // Should be sorted by resource type: akeyless_auth_method before akeyless_target
        assert_eq!(sig.inputs[0].name, "akeyless_auth_method.a1");
        assert_eq!(sig.inputs[1].name, "akeyless_target.t1");
    }

    // -----------------------------------------------------------------------
    // 4. hash_synthesis_json with data sources included
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_with_data_sources() {
        let json = br#"{
            "resource": {
                "akeyless_auth_method": {
                    "a1": {"name": "auth-1"}
                }
            },
            "data": {
                "akeyless_secret": {
                    "s1": {"path": "/secret"}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "data.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "akeyless_auth_method.a1");
        assert_eq!(sig.inputs[1].name, "data.akeyless_secret.s1");
    }

    // -----------------------------------------------------------------------
    // 5. hash_synthesis_json determinism (same input -> same hash)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_determinism() {
        let json = br#"{"resource":{"t":{"a":{"x":1}}}}"#;
        let sig1 = hash_synthesis_json(json, "det.json").await.unwrap();
        let sig2 = hash_synthesis_json(json, "det.json").await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
        assert_eq!(sig1.inputs.len(), sig2.inputs.len());
        for (a, b) in sig1.inputs.iter().zip(sig2.inputs.iter()) {
            assert_eq!(a.hash, b.hash);
        }
    }

    // -----------------------------------------------------------------------
    // 6. hash_synthesis_json different inputs -> different hashes
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_different_inputs_different_hashes() {
        let json_a = br#"{"resource":{"t":{"a":{"x":1}}}}"#;
        let json_b = br#"{"resource":{"t":{"a":{"x":2}}}}"#;
        let sig_a = hash_synthesis_json(json_a, "a.json").await.unwrap();
        let sig_b = hash_synthesis_json(json_b, "b.json").await.unwrap();
        assert_ne!(sig_a.hash, sig_b.hash);
    }

    // -----------------------------------------------------------------------
    // 7. hash_synthesis_json canonical: reordered keys produce same hash
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_canonical_key_order() {
        // serde_json::Value sorts keys on re-serialization
        let json_a = br#"{"resource":{"t":{"a":{"x":1,"y":2}}}}"#;
        let json_b = br#"{"resource":{"t":{"a":{"y":2,"x":1}}}}"#;
        let sig_a = hash_synthesis_json(json_a, "a.json").await.unwrap();
        let sig_b = hash_synthesis_json(json_b, "b.json").await.unwrap();
        assert_eq!(sig_a.hash, sig_b.hash);
    }

    // -----------------------------------------------------------------------
    // 8. hash_synthesis_json extracts individual InputHash per resource
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_individual_input_hashes() {
        let json = br#"{
            "resource": {
                "type_a": {
                    "inst1": {"k": "v1"},
                    "inst2": {"k": "v2"}
                },
                "type_b": {
                    "inst3": {"k": "v3"}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "inputs.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 3);
        assert_eq!(sig.inputs[0].name, "type_a.inst1");
        assert_eq!(sig.inputs[1].name, "type_a.inst2");
        assert_eq!(sig.inputs[2].name, "type_b.inst3");
        // Each input should have a unique hash
        assert_ne!(sig.inputs[0].hash, sig.inputs[1].hash);
        assert_ne!(sig.inputs[1].hash, sig.inputs[2].hash);
    }

    // -----------------------------------------------------------------------
    // 9. hash_synthesis_json with nested resource attributes
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_nested_attributes() {
        let json = br#"{
            "resource": {
                "aws_instance": {
                    "web": {
                        "ami": "ami-12345",
                        "tags": {"Name": "web-server", "Env": "prod"},
                        "network": {"vpc_id": "vpc-abc", "subnets": ["a","b"]}
                    }
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "nested.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "aws_instance.web");
        assert!(sig.inputs[0].size_bytes.unwrap() > 0);
    }

    // -----------------------------------------------------------------------
    // 10. hash_synthesis_json with invalid JSON returns error
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_invalid_json_error() {
        let result = hash_synthesis_json(b"not json at all", "bad.json").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("pangea_synthesis"));
    }

    // -----------------------------------------------------------------------
    // 11. hash_synthesis_file reads file (tempfile test)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_file_reads_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("synthesis.tf.json");
        let json = br#"{"resource":{"t":{"a":{"k":"v"}}}}"#;
        tokio::fs::write(&file_path, json).await.unwrap();

        let sig = hash_synthesis_file(file_path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(sig.layer, LayerType::PangeaSynthesis);
        assert_eq!(sig.inputs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 12. PangeaSynthesisCollector layer_type returns PangeaSynthesis
    // -----------------------------------------------------------------------
    #[test]
    fn collector_layer_type() {
        let runner = MockCommandRunner::new();
        let collector = PangeaSynthesisCollector::new("/tmp/project", "/tmp/output.json", runner);
        assert_eq!(collector.layer_type(), LayerType::PangeaSynthesis);
    }

    // -----------------------------------------------------------------------
    // 13. LayerType::PangeaSynthesis display is "pangea_synthesis"
    // -----------------------------------------------------------------------
    #[test]
    fn pangea_synthesis_display() {
        assert_eq!(LayerType::PangeaSynthesis.to_string(), "pangea_synthesis");
    }

    // -----------------------------------------------------------------------
    // 14. LayerType::PangeaSynthesis from_str roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn pangea_synthesis_from_str_roundtrip() {
        let display = LayerType::PangeaSynthesis.to_string();
        let parsed: LayerType = display.parse().unwrap();
        assert_eq!(parsed, LayerType::PangeaSynthesis);
        // Also test alias
        let alias: LayerType = "pangea".parse().unwrap();
        assert_eq!(alias, LayerType::PangeaSynthesis);
    }

    // -----------------------------------------------------------------------
    // 15. LayerType::RSpecResult display/from_str roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn rspec_result_display_from_str_roundtrip() {
        let display = LayerType::RSpecResult.to_string();
        assert_eq!(display, "rspec_result");
        let parsed: LayerType = display.parse().unwrap();
        assert_eq!(parsed, LayerType::RSpecResult);
        // Also test aliases
        let alias: LayerType = "rspec".parse().unwrap();
        assert_eq!(alias, LayerType::RSpecResult);
    }

    // -----------------------------------------------------------------------
    // 16. LayerType::InSpecResult display/from_str roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn inspec_result_display_from_str_roundtrip() {
        let display = LayerType::InSpecResult.to_string();
        assert_eq!(display, "inspec_result");
        let parsed: LayerType = display.parse().unwrap();
        assert_eq!(parsed, LayerType::InSpecResult);
    }

    // -----------------------------------------------------------------------
    // 17. LayerType all_variants count includes new 3
    // -----------------------------------------------------------------------
    #[test]
    fn layer_type_all_variants_count() {
        let all = vec![
            LayerType::Nix,
            LayerType::Oci,
            LayerType::Helm,
            LayerType::Tofu,
            LayerType::Kubernetes,
            LayerType::Kindling,
            LayerType::Tatara,
            LayerType::FluxCD,
            LayerType::ArgoCD,
            LayerType::Akeyless,
            LayerType::AkeylessTarget,
            LayerType::PangeaSynthesis,
            LayerType::RSpecResult,
            LayerType::InSpecResult,
            LayerType::FerritePoms,
        ];
        assert_eq!(all.len(), 15);
        // Verify all are distinct
        let mut deduped = all.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 15);
    }

    // -----------------------------------------------------------------------
    // 18. PangeaSynthesis LayerSignature serde roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn pangea_synthesis_layer_signature_serde_roundtrip() {
        let sig = LayerSignature::new(
            LayerType::PangeaSynthesis,
            Blake3Hash::digest(b"pangea-data"),
            "synthesis.tf.json",
            vec![InputHash {
                name: "akeyless_auth_method.my_auth".to_string(),
                hash: Blake3Hash::digest(b"auth-block"),
                size_bytes: Some(42),
            }],
        );
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("pangea_synthesis"));
        let deserialized: LayerSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.layer, LayerType::PangeaSynthesis);
        assert_eq!(deserialized.hash, sig.hash);
        assert_eq!(deserialized.inputs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 19. hash_synthesis_json with Akeyless-style resources (real-world)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_akeyless_real_world() {
        let json = br#"{
            "resource": {
                "akeyless_auth_method": {
                    "api_key": {
                        "name": "/pleme/auth/api-key",
                        "type": "api_key",
                        "bound_ips": ["10.0.0.0/8"]
                    },
                    "saml": {
                        "name": "/pleme/auth/saml",
                        "type": "saml2",
                        "idp_metadata_url": "https://idp.example.com/metadata"
                    }
                },
                "akeyless_target": {
                    "aws_prod": {
                        "name": "/pleme/targets/aws-prod",
                        "type": "aws",
                        "region": "us-east-1"
                    }
                },
                "akeyless_dynamic_secret": {
                    "db_creds": {
                        "name": "/pleme/dynamic/db-creds",
                        "target_name": "/pleme/targets/aws-prod"
                    }
                }
            },
            "data": {
                "akeyless_secret": {
                    "master_key": {
                        "path": "/pleme/secrets/master-key"
                    }
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "akeyless.tf.json").await.unwrap();
        // 2 auth methods + 1 target + 1 dynamic secret + 1 data source = 5
        assert_eq!(sig.inputs.len(), 5);
        // Verify sorted ordering
        assert!(sig.inputs[0].name.starts_with("akeyless_auth_method"));
        assert!(sig.inputs[2].name.starts_with("akeyless_dynamic_secret"));
        assert!(sig.inputs[3].name.starts_with("akeyless_target"));
        assert!(sig.inputs[4].name.starts_with("data.akeyless_secret"));
    }

    // -----------------------------------------------------------------------
    // 20. Integration: hash pangea synthesis -> compose_certification_artifact
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_as_intent_hash_for_certification() {
        let json = br#"{"resource":{"t":{"a":{"k":"v"}}}}"#;
        let sig = hash_synthesis_json(json, "intent.json").await.unwrap();

        let artifact = compose_certification_artifact(
            "/usr/bin/myapp",
            Blake3Hash::digest(b"nix-closure"),
            Blake3Hash::digest(b"kensa-result"),
            sig.hash.clone(), // Use pangea synthesis hash as intent_hash
            "production",
        );

        assert!(!artifact.composed_root.to_hex().is_empty());
        assert_eq!(artifact.intent_hash, sig.hash);
        assert_eq!(artifact.environment, "production");
    }

    // -----------------------------------------------------------------------
    // 21. Edge case: very large JSON (many resources)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_large_resource_count() {
        let mut resources = serde_json::Map::new();
        for i in 0..100 {
            let mut instances = serde_json::Map::new();
            instances.insert(
                format!("inst_{i}"),
                serde_json::json!({"id": i, "name": format!("resource-{i}")}),
            );
            resources.insert(format!("type_{i:03}"), serde_json::Value::Object(instances));
        }
        let value = serde_json::json!({"resource": resources});
        let bytes = serde_json::to_vec(&value).unwrap();
        let sig = hash_synthesis_json(&bytes, "large.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 100);
        // Verify deterministic ordering (type_000 before type_001, etc.)
        assert!(sig.inputs[0].name.starts_with("type_000"));
        assert!(sig.inputs[99].name.starts_with("type_099"));
    }

    // -----------------------------------------------------------------------
    // 22. Edge case: empty resource block
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_empty_resource_block() {
        let json = br#"{"resource":{}}"#;
        let sig = hash_synthesis_json(json, "empty-res.json").await.unwrap();
        assert!(sig.inputs.is_empty());
        assert_eq!(sig.layer, LayerType::PangeaSynthesis);
    }

    // -----------------------------------------------------------------------
    // 23. Edge case: null values in resource attributes
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_null_values() {
        let json = br#"{
            "resource": {
                "t": {
                    "a": {"name": null, "count": null}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "nulls.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "t.a");
    }

    // -----------------------------------------------------------------------
    // 24. Edge case: unicode keys in resources
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_unicode_keys() {
        let json = serde_json::json!({
            "resource": {
                "\u{65e5}\u{672c}\u{8a9e}": {
                    "\u{30ea}\u{30bd}\u{30fc}\u{30b9}": {"value": 42}
                }
            }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let sig = hash_synthesis_json(&bytes, "unicode.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
        // The hash should be deterministic for unicode
        let sig2 = hash_synthesis_json(&bytes, "unicode.json").await.unwrap();
        assert_eq!(sig.hash, sig2.hash);
    }

    // -----------------------------------------------------------------------
    // 25. Edge case: resource type with empty instances object
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_empty_instances() {
        let json = br#"{
            "resource": {
                "type_a": {},
                "type_b": {
                    "inst1": {"k": "v"}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "empty-inst.json").await.unwrap();
        // type_a has no instances, so only type_b.inst1
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "type_b.inst1");
    }

    // -----------------------------------------------------------------------
    // hash_synthesis_file with nonexistent file returns error
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_file_nonexistent() {
        let result = hash_synthesis_file("/nonexistent/path/synthesis.json").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("pangea_synthesis"));
    }

    // -----------------------------------------------------------------------
    // Data sources only (no resources)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn hash_synthesis_json_data_only() {
        let json = br#"{
            "data": {
                "akeyless_secret": {
                    "s1": {"path": "/a"},
                    "s2": {"path": "/b"}
                }
            }
        }"#;
        let sig = hash_synthesis_json(json, "data-only.json").await.unwrap();
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "data.akeyless_secret.s1");
        assert_eq!(sig.inputs[1].name, "data.akeyless_secret.s2");
    }
}
