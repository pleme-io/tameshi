//! Kubernetes manifest collector.
//!
//! Computes BLAKE3 hashes of Kubernetes manifest sets. This covers
//! both static manifests (from git) and live cluster state, enabling
//! drift detection between desired and actual state.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// Hash a directory of Kubernetes manifests.
///
/// Reads all YAML/JSON files in the directory (recursively), sorts by path,
/// and computes a composite hash.
pub async fn hash_manifest_dir(dir_path: &str) -> Result<LayerSignature> {
    let mut inputs = Vec::new();
    collect_manifests(dir_path, &mut inputs).await?;
    inputs.sort_by(|a, b| a.name.cmp(&b.name));

    let composite = compute_composite(&inputs);

    debug!(
        dir = dir_path,
        manifests = inputs.len(),
        "Hashed Kubernetes manifest directory"
    );

    Ok(LayerSignature::new(
        LayerType::Kubernetes,
        composite,
        dir_path,
        inputs,
    ))
}

/// Hash the live state of a Kubernetes namespace.
///
/// Runs `kubectl get` for key resource types, canonicalizes the output,
/// and hashes it. This captures what's actually running vs what's declared.
pub async fn hash_namespace_state(namespace: &str) -> Result<LayerSignature> {
    let resource_types = [
        "deployments",
        "statefulsets",
        "daemonsets",
        "services",
        "configmaps",
        "secrets",
        "ingresses",
        "networkpolicies",
    ];

    let mut inputs = Vec::new();

    for resource_type in &resource_types {
        let output = Command::new("kubectl")
            .args([
                "get",
                resource_type,
                "-n",
                namespace,
                "-o",
                "json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if output.status.success() {
            // Canonicalize: parse JSON, strip volatile fields, re-serialize
            if let Ok(mut resources) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                strip_volatile_fields(&mut resources);
                let canonical = serde_json::to_vec(&resources)?;
                inputs.push(InputHash {
                    name: format!("{}/{}", namespace, resource_type),
                    hash: Blake3Hash::digest(&canonical),
                    size_bytes: Some(canonical.len() as u64),
                });
            }
        }
    }

    let composite = compute_composite(&inputs);

    debug!(
        namespace = namespace,
        resource_types = inputs.len(),
        "Hashed Kubernetes namespace state"
    );

    Ok(LayerSignature::new(
        LayerType::Kubernetes,
        composite,
        &format!("namespace:{}", namespace),
        inputs,
    ))
}

/// Hash a Kustomize build output.
///
/// Runs `kustomize build <dir>` and hashes the rendered manifests.
pub async fn hash_kustomize_build(dir_path: &str) -> Result<LayerSignature> {
    let output = Command::new("kustomize")
        .args(["build", dir_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("kustomize build {}", dir_path),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let hash = Blake3Hash::digest(&output.stdout);
    let inputs = vec![InputHash {
        name: "kustomize-build".to_string(),
        hash: hash.clone(),
        size_bytes: Some(output.stdout.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Kubernetes,
        hash,
        dir_path,
        inputs,
    ))
}

/// Recursively collect and hash YAML/JSON manifest files.
async fn collect_manifests(dir: &str, inputs: &mut Vec<InputHash>) -> Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.is_dir() {
            if let Some(s) = path.to_str() {
                Box::pin(collect_manifests(s, inputs)).await?;
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "yaml" | "yml" | "json") {
                if let Ok(data) = tokio::fs::read(&path).await {
                    inputs.push(InputHash {
                        name: path.to_string_lossy().to_string(),
                        hash: Blake3Hash::digest(&data),
                        size_bytes: Some(data.len() as u64),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Strip volatile fields that change between reads (resourceVersion, uid,
/// creationTimestamp, managedFields, etc.) for deterministic hashing.
pub fn strip_volatile_fields(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        // Strip from metadata
        if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            metadata.remove("resourceVersion");
            metadata.remove("uid");
            metadata.remove("creationTimestamp");
            metadata.remove("managedFields");
            metadata.remove("selfLink");
            metadata.remove("generation");
        }

        // Strip status entirely (volatile by nature)
        obj.remove("status");

        // Recurse into items array (for list responses)
        if let Some(items) = obj.get_mut("items").and_then(|i| i.as_array_mut()) {
            for item in items {
                strip_volatile_fields(item);
            }
        }
    }
}

#[inline]
fn compute_composite(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-kubernetes-manifests");
    }
    let mut data = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}

/// Source for Kubernetes manifest collection.
#[derive(Clone, Debug)]
pub enum KubernetesSource {
    /// Hash a directory of static manifests.
    ManifestDir(String),
    /// Hash the live state of a namespace.
    NamespaceState(String),
    /// Hash a kustomize build output.
    KustomizeBuild(String),
}

/// Kubernetes manifest collector.
///
/// Wraps the standalone functions in a [`LayerCollector`] implementation.
pub struct KubernetesCollector {
    /// Source to collect from.
    pub source: KubernetesSource,
}

impl KubernetesCollector {
    /// Create a collector for a manifest directory.
    #[must_use]
    pub fn from_dir(dir_path: &str) -> Self {
        Self {
            source: KubernetesSource::ManifestDir(dir_path.to_string()),
        }
    }

    /// Create a collector for a live namespace.
    #[must_use]
    pub fn from_namespace(namespace: &str) -> Self {
        Self {
            source: KubernetesSource::NamespaceState(namespace.to_string()),
        }
    }

    /// Create a collector for a kustomize build.
    #[must_use]
    pub fn from_kustomize(dir_path: &str) -> Self {
        Self {
            source: KubernetesSource::KustomizeBuild(dir_path.to_string()),
        }
    }
}

impl LayerCollector for KubernetesCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            KubernetesSource::ManifestDir(path) => hash_manifest_dir(path).await,
            KubernetesSource::NamespaceState(ns) => hash_namespace_state(ns).await,
            KubernetesSource::KustomizeBuild(path) => hash_kustomize_build(path).await,
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Kubernetes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_volatile_fields_removes_metadata() {
        let mut value = serde_json::json!({
            "metadata": {
                "name": "my-deploy",
                "namespace": "default",
                "resourceVersion": "12345",
                "uid": "abc-def",
                "creationTimestamp": "2024-01-01T00:00:00Z",
                "managedFields": [{"manager": "kubectl"}],
                "selfLink": "/apis/apps/v1/deployments/my-deploy",
                "generation": 5,
                "labels": {"app": "test"}
            },
            "spec": {"replicas": 3},
            "status": {"readyReplicas": 3}
        });

        strip_volatile_fields(&mut value);

        let metadata = value.get("metadata").unwrap();
        assert!(metadata.get("name").is_some(), "name should be preserved");
        assert!(metadata.get("namespace").is_some(), "namespace should be preserved");
        assert!(metadata.get("labels").is_some(), "labels should be preserved");
        assert!(metadata.get("resourceVersion").is_none(), "resourceVersion should be stripped");
        assert!(metadata.get("uid").is_none(), "uid should be stripped");
        assert!(metadata.get("creationTimestamp").is_none(), "creationTimestamp should be stripped");
        assert!(metadata.get("managedFields").is_none(), "managedFields should be stripped");
        assert!(metadata.get("selfLink").is_none(), "selfLink should be stripped");
        assert!(metadata.get("generation").is_none(), "generation should be stripped");
        assert!(value.get("status").is_none(), "status should be stripped");
    }

    #[test]
    fn strip_volatile_fields_recurses_into_items() {
        let mut value = serde_json::json!({
            "kind": "DeploymentList",
            "items": [
                {
                    "metadata": {
                        "name": "deploy-1",
                        "resourceVersion": "111",
                        "uid": "uid-1"
                    },
                    "status": {"readyReplicas": 1}
                },
                {
                    "metadata": {
                        "name": "deploy-2",
                        "resourceVersion": "222",
                        "uid": "uid-2"
                    },
                    "status": {"readyReplicas": 2}
                }
            ]
        });

        strip_volatile_fields(&mut value);

        let items = value.get("items").unwrap().as_array().unwrap();
        for item in items {
            let md = item.get("metadata").unwrap();
            assert!(md.get("name").is_some());
            assert!(md.get("resourceVersion").is_none());
            assert!(md.get("uid").is_none());
            assert!(item.get("status").is_none());
        }
    }

    #[test]
    fn strip_volatile_fields_handles_no_metadata() {
        let mut value = serde_json::json!({"spec": {"replicas": 3}});
        strip_volatile_fields(&mut value);
        assert!(value.get("spec").is_some());
    }

    #[test]
    fn strip_volatile_fields_handles_non_object() {
        let mut value = serde_json::json!("just a string");
        strip_volatile_fields(&mut value);
        assert_eq!(value, serde_json::json!("just a string"));
    }

    #[test]
    fn compute_composite_empty_inputs() {
        let result = compute_composite(&[]);
        let expected = Blake3Hash::digest(b"empty-kubernetes-manifests");
        assert_eq!(result, expected);
    }

    #[test]
    fn compute_composite_single_input() {
        let hash = Blake3Hash::digest(b"manifest-content");
        let inputs = vec![InputHash {
            name: "deployment.yaml".to_string(),
            hash: hash.clone(),
            size_bytes: Some(100),
        }];
        let result = compute_composite(&inputs);
        assert_eq!(result, Blake3Hash::digest(&hash.0));
    }

    #[test]
    fn compute_composite_deterministic() {
        let inputs = vec![
            InputHash {
                name: "a.yaml".to_string(),
                hash: Blake3Hash::digest(b"content-a"),
                size_bytes: None,
            },
            InputHash {
                name: "b.yaml".to_string(),
                hash: Blake3Hash::digest(b"content-b"),
                size_bytes: None,
            },
        ];
        let result1 = compute_composite(&inputs);
        let result2 = compute_composite(&inputs);
        assert_eq!(result1, result2);
    }

    #[test]
    fn compute_composite_order_sensitive() {
        let hash_a = Blake3Hash::digest(b"content-a");
        let hash_b = Blake3Hash::digest(b"content-b");
        let inputs_ab = vec![
            InputHash { name: "a".to_string(), hash: hash_a.clone(), size_bytes: None },
            InputHash { name: "b".to_string(), hash: hash_b.clone(), size_bytes: None },
        ];
        let inputs_ba = vec![
            InputHash { name: "b".to_string(), hash: hash_b, size_bytes: None },
            InputHash { name: "a".to_string(), hash: hash_a, size_bytes: None },
        ];
        assert_ne!(
            compute_composite(&inputs_ab),
            compute_composite(&inputs_ba),
            "different ordering must produce different composite hashes"
        );
    }

    #[tokio::test]
    async fn hash_manifest_dir_with_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deploy.yaml"), b"apiVersion: apps/v1\nkind: Deployment\n").unwrap();
        std::fs::write(dir.path().join("svc.json"), b"{\"kind\":\"Service\"}").unwrap();
        std::fs::write(dir.path().join("readme.txt"), b"not a manifest").unwrap();

        let sig = hash_manifest_dir(dir.path().to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::Kubernetes);
        assert_eq!(sig.inputs.len(), 2, "only yaml and json files should be collected");
    }

    #[tokio::test]
    async fn hash_manifest_dir_empty() {
        let dir = tempfile::tempdir().unwrap();
        let sig = hash_manifest_dir(dir.path().to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::Kubernetes);
        assert_eq!(sig.inputs.len(), 0);
        let expected_empty = Blake3Hash::digest(b"empty-kubernetes-manifests");
        assert_eq!(sig.hash, expected_empty);
    }

    #[tokio::test]
    async fn hash_manifest_dir_nested() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("nested.yaml"), b"apiVersion: v1\nkind: ConfigMap\n").unwrap();

        let sig = hash_manifest_dir(dir.path().to_str().unwrap()).await.unwrap();
        assert_eq!(sig.inputs.len(), 1, "nested manifests should be collected recursively");
    }

    #[tokio::test]
    async fn hash_manifest_dir_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), b"kind: A\n").unwrap();
        std::fs::write(dir.path().join("b.yaml"), b"kind: B\n").unwrap();

        let sig1 = hash_manifest_dir(dir.path().to_str().unwrap()).await.unwrap();
        let sig2 = hash_manifest_dir(dir.path().to_str().unwrap()).await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[tokio::test]
    async fn hash_manifest_dir_nonexistent() {
        let result = hash_manifest_dir("/nonexistent/path/to/manifests").await;
        assert!(result.is_err());
    }

    #[test]
    fn kubernetes_collector_layer_type() {
        let c = KubernetesCollector::from_dir("/tmp");
        assert_eq!(c.layer_type(), LayerType::Kubernetes);
    }

    #[test]
    fn kubernetes_source_variants() {
        let c1 = KubernetesCollector::from_dir("/path");
        assert!(matches!(c1.source, KubernetesSource::ManifestDir(_)));
        let c2 = KubernetesCollector::from_namespace("default");
        assert!(matches!(c2.source, KubernetesSource::NamespaceState(_)));
        let c3 = KubernetesCollector::from_kustomize("/overlay");
        assert!(matches!(c3.source, KubernetesSource::KustomizeBuild(_)));
    }
}
