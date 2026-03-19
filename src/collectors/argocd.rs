//! ArgoCD application state collector.
//!
//! Computes BLAKE3 hashes of ArgoCD Application CRDs in a namespace.
//! This captures the sync status, health status, and source configuration
//! of ArgoCD-managed applications, enabling drift detection.

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// ArgoCD CRD resource types to collect.
const ARGOCD_RESOURCE_TYPES: [&str; 2] = [
    "applications.argoproj.io",
    "applicationsets.argoproj.io",
];

/// Collects ArgoCD application state as a layer signature.
///
/// Queries Application and ApplicationSet CRDs in a namespace,
/// strips volatile fields, and produces a deterministic hash of the state.
pub struct ArgoCDCollector {
    /// Namespace to query for ArgoCD resources.
    pub namespace: String,
}

impl ArgoCDCollector {
    /// Create a new ArgoCD collector for the given namespace.
    #[must_use]
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }
}

impl LayerCollector for ArgoCDCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let mut inputs = Vec::new();

        for resource_type in &ARGOCD_RESOURCE_TYPES {
            let output = Command::new("kubectl")
                .args(["get", resource_type, "-n", &self.namespace, "-o", "json"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await?;

            if output.status.success() {
                if let Ok(mut resources) =
                    serde_json::from_slice::<serde_json::Value>(&output.stdout)
                {
                    strip_argocd_volatile_fields(&mut resources);
                    let canonical = serde_json::to_vec(&resources)?;
                    inputs.push(InputHash {
                        name: format!("{}/{}", self.namespace, resource_type),
                        hash: Blake3Hash::digest(&canonical),
                        size_bytes: Some(canonical.len() as u64),
                    });
                }
            }
        }

        let composite = compute_composite(&inputs);

        debug!(
            namespace = self.namespace.as_str(),
            resource_types = inputs.len(),
            "Hashed ArgoCD application state"
        );

        Ok(LayerSignature::new(
            LayerType::ArgoCD,
            composite,
            &format!("argocd:{}", self.namespace),
            inputs,
        ))
    }

    fn layer_type(&self) -> LayerType {
        LayerType::ArgoCD
    }
}

/// Strip volatile fields from ArgoCD resources for deterministic hashing.
///
/// Removes metadata fields that change between reads (resourceVersion, uid,
/// creationTimestamp, managedFields, generation) and status (volatile by nature --
/// contains sync status, health, reconciledAt, etc.).
pub fn strip_argocd_volatile_fields(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        // Strip volatile metadata fields
        if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            metadata.remove("resourceVersion");
            metadata.remove("uid");
            metadata.remove("creationTimestamp");
            metadata.remove("managedFields");
            metadata.remove("selfLink");
            metadata.remove("generation");
        }

        // Strip status entirely (volatile by nature -- contains sync/health/reconciledAt)
        obj.remove("status");

        // Strip operation state (transient operation info)
        obj.remove("operation");

        // Recurse into items array (for list responses)
        if let Some(items) = obj.get_mut("items").and_then(|i| i.as_array_mut()) {
            for item in items {
                strip_argocd_volatile_fields(item);
            }
        }
    }
}

#[inline]
fn compute_composite(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-argocd-resources");
    }
    let mut data = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_volatile_fields_removes_metadata() {
        let mut resource = serde_json::json!({
            "metadata": {
                "name": "my-app",
                "namespace": "argocd",
                "resourceVersion": "12345",
                "uid": "abc-def",
                "creationTimestamp": "2026-01-01T00:00:00Z",
                "managedFields": [{"manager": "argocd"}],
                "generation": 5
            },
            "spec": {
                "source": {
                    "repoURL": "https://github.com/org/repo",
                    "targetRevision": "main",
                    "path": "k8s/overlays/prod"
                },
                "destination": {
                    "server": "https://kubernetes.default.svc",
                    "namespace": "default"
                }
            },
            "status": {
                "sync": {"status": "Synced"},
                "health": {"status": "Healthy"},
                "reconciledAt": "2026-03-19T10:00:00Z"
            },
            "operation": {
                "sync": {"revision": "abc123"}
            }
        });

        strip_argocd_volatile_fields(&mut resource);

        let obj = resource.as_object().unwrap();
        let metadata = obj["metadata"].as_object().unwrap();
        assert!(metadata.contains_key("name"));
        assert!(metadata.contains_key("namespace"));
        assert!(!metadata.contains_key("resourceVersion"));
        assert!(!metadata.contains_key("uid"));
        assert!(!metadata.contains_key("creationTimestamp"));
        assert!(!metadata.contains_key("managedFields"));
        assert!(!metadata.contains_key("generation"));
        assert!(!obj.contains_key("status"));
        assert!(!obj.contains_key("operation"));
        assert!(obj.contains_key("spec"));
    }

    #[test]
    fn strip_volatile_fields_recurses_into_items() {
        let mut list = serde_json::json!({
            "items": [
                {
                    "metadata": {"name": "app-a", "resourceVersion": "1"},
                    "status": {"sync": {"status": "Synced"}}
                },
                {
                    "metadata": {"name": "app-b", "uid": "xyz"},
                    "status": {"health": {"status": "Degraded"}},
                    "operation": {"sync": {}}
                }
            ]
        });

        strip_argocd_volatile_fields(&mut list);

        let items = list["items"].as_array().unwrap();
        for item in items {
            let obj = item.as_object().unwrap();
            let metadata = obj["metadata"].as_object().unwrap();
            assert!(!metadata.contains_key("resourceVersion"));
            assert!(!metadata.contains_key("uid"));
            assert!(!obj.contains_key("status"));
            assert!(!obj.contains_key("operation"));
        }
    }

    #[test]
    fn compute_composite_empty() {
        let hash = compute_composite(&[]);
        assert_eq!(hash, Blake3Hash::digest(b"empty-argocd-resources"));
    }

    #[test]
    fn compute_composite_deterministic() {
        let inputs = vec![
            InputHash {
                name: "a".to_string(),
                hash: Blake3Hash::digest(b"a"),
                size_bytes: None,
            },
            InputHash {
                name: "b".to_string(),
                hash: Blake3Hash::digest(b"b"),
                size_bytes: None,
            },
        ];
        let h1 = compute_composite(&inputs);
        let h2 = compute_composite(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn argocd_collector_layer_type() {
        let collector = ArgoCDCollector::new("argocd");
        assert_eq!(collector.layer_type(), LayerType::ArgoCD);
    }
}
