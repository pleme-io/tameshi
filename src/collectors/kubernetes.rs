//! Kubernetes manifest collector.
//!
//! Computes BLAKE3 hashes of Kubernetes manifest sets. This covers
//! both static manifests (from git) and live cluster state, enabling
//! drift detection between desired and actual state.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

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
fn strip_volatile_fields(value: &mut serde_json::Value) {
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

fn compute_composite(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-kubernetes-manifests");
    }
    let mut data = Vec::new();
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}
