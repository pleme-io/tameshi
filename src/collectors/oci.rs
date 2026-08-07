//! OCI image manifest collector.
//!
//! Computes BLAKE3 hashes of OCI image manifests by querying the registry
//! (via `skopeo inspect --raw` or the registry HTTP API).

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// Hash an OCI image by its manifest.
///
/// Uses `skopeo inspect --raw` to get the image manifest, then hashes it.
/// The manifest includes references to all layer digests, so this is a
/// complete content-addressable hash of the image.
pub async fn hash_manifest(image_ref: &str) -> Result<LayerSignature> {
    let docker_ref = if image_ref.starts_with("docker://") {
        image_ref.to_string()
    } else {
        format!("docker://{}", image_ref)
    };

    let output = Command::new("skopeo")
        .args(["inspect", "--raw", &docker_ref])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("skopeo inspect --raw {}", docker_ref),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let manifest_hash = Blake3Hash::digest(&output.stdout);

    // Parse manifest to extract layer digests as inputs
    let inputs = parse_manifest_layers(&output.stdout, image_ref)?;

    debug!(
        image = image_ref,
        layers = inputs.len(),
        "Hashed OCI manifest"
    );

    Ok(LayerSignature::new(
        LayerType::Oci,
        manifest_hash,
        image_ref,
        inputs,
    ))
}

/// Hash multiple OCI images and compose their signatures.
///
/// Returns a single LayerSignature whose hash is the BLAKE3 of all
/// individual manifest hashes concatenated in sorted order.
pub async fn hash_images(image_refs: &[&str]) -> Result<LayerSignature> {
    let mut sigs = Vec::new();
    for image_ref in image_refs {
        sigs.push(hash_manifest(image_ref).await?);
    }

    sigs.sort_by(|a, b| a.metadata.source.cmp(&b.metadata.source));

    let mut inputs: Vec<InputHash> = Vec::new();
    let mut composite_data = Vec::new();
    for sig in &sigs {
        composite_data.extend_from_slice(&sig.hash.0);
        inputs.push(InputHash {
            name: sig.metadata.source.clone(),
            hash: sig.hash.clone(),
            size_bytes: None,
        });
    }

    let composite = Blake3Hash::digest(&composite_data);
    Ok(LayerSignature::new(
        LayerType::Oci,
        composite,
        "multi-image",
        inputs,
    ))
}

/// Parse OCI manifest JSON to extract layer digest references.
pub fn parse_manifest_layers(manifest_bytes: &[u8], source: &str) -> Result<Vec<InputHash>> {
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest_bytes).map_err(|e| TameshiError::CollectorError {
            layer: "oci".to_string(),
            message: format!("failed to parse manifest for {}: {}", source, e),
        })?;

    let mut inputs = Vec::new();

    // Handle OCI image manifest (schemaVersion 2)
    if let Some(layers) = manifest.get("layers").and_then(|l| l.as_array()) {
        for (i, layer) in layers.iter().enumerate() {
            if let Some(digest) = layer.get("digest").and_then(|d| d.as_str()) {
                let size = layer.get("size").and_then(|s| s.as_u64());
                inputs.push(InputHash {
                    name: format!("layer-{}-{}", i, digest),
                    hash: Blake3Hash::digest(digest.as_bytes()),
                    size_bytes: size,
                });
            }
        }
    }

    // Handle config digest
    if let Some(config) = manifest.get("config") {
        if let Some(digest) = config.get("digest").and_then(|d| d.as_str()) {
            inputs.push(InputHash {
                name: format!("config-{}", digest),
                hash: Blake3Hash::digest(digest.as_bytes()),
                size_bytes: config.get("size").and_then(|s| s.as_u64()),
            });
        }
    }

    // Handle manifest list / index
    if let Some(manifests) = manifest.get("manifests").and_then(|m| m.as_array()) {
        for (i, m) in manifests.iter().enumerate() {
            if let Some(digest) = m.get("digest").and_then(|d| d.as_str()) {
                let platform = m
                    .get("platform")
                    .map(|p| {
                        format!(
                            "{}/{}",
                            p.get("os").and_then(|o| o.as_str()).unwrap_or("unknown"),
                            p.get("architecture")
                                .and_then(|a| a.as_str())
                                .unwrap_or("unknown")
                        )
                    })
                    .unwrap_or_else(|| format!("manifest-{}", i));
                inputs.push(InputHash {
                    name: format!("{}-{}", platform, digest),
                    hash: Blake3Hash::digest(digest.as_bytes()),
                    size_bytes: m.get("size").and_then(|s| s.as_u64()),
                });
            }
        }
    }

    Ok(inputs)
}

/// OCI image manifest collector.
///
/// Wraps the standalone functions in a [`LayerCollector`] implementation.
pub struct OciCollector {
    /// OCI image reference (e.g., `ghcr.io/pleme-io/app:latest`).
    pub image_ref: String,
}

impl OciCollector {
    /// Create a collector for a specific image reference.
    #[must_use]
    pub fn new(image_ref: &str) -> Self {
        Self {
            image_ref: image_ref.to_string(),
        }
    }
}

impl LayerCollector for OciCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        hash_manifest(&self.image_ref).await
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Oci
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest_layers_oci_image() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "digest": "sha256:config123",
                "size": 1234
            },
            "layers": [
                {"digest": "sha256:layer1abc", "size": 10000},
                {"digest": "sha256:layer2def", "size": 20000}
            ]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs = parse_manifest_layers(&bytes, "test-image:latest").unwrap();
        assert_eq!(inputs.len(), 3, "2 layers + 1 config");
        assert!(inputs[0].name.starts_with("layer-0-"));
        assert!(inputs[1].name.starts_with("layer-1-"));
        assert!(inputs[2].name.starts_with("config-"));
        assert_eq!(inputs[0].size_bytes, Some(10000));
        assert_eq!(inputs[1].size_bytes, Some(20000));
        assert_eq!(inputs[2].size_bytes, Some(1234));
    }

    #[test]
    fn parse_manifest_layers_manifest_list() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {
                    "digest": "sha256:amd64abc",
                    "size": 5000,
                    "platform": {"os": "linux", "architecture": "amd64"}
                },
                {
                    "digest": "sha256:arm64def",
                    "size": 6000,
                    "platform": {"os": "linux", "architecture": "arm64"}
                }
            ]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs = parse_manifest_layers(&bytes, "multi-arch:v1").unwrap();
        assert_eq!(inputs.len(), 2);
        assert!(inputs[0].name.contains("linux/amd64"));
        assert!(inputs[1].name.contains("linux/arm64"));
        assert_eq!(inputs[0].size_bytes, Some(5000));
    }

    #[test]
    fn parse_manifest_layers_empty_manifest() {
        let manifest = serde_json::json!({"schemaVersion": 2});
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs = parse_manifest_layers(&bytes, "empty:v1").unwrap();
        assert!(inputs.is_empty());
    }

    #[test]
    fn parse_manifest_layers_invalid_json() {
        let result = parse_manifest_layers(b"not json", "bad:v1");
        assert!(result.is_err());
    }

    #[test]
    fn parse_manifest_layers_missing_digest() {
        let manifest = serde_json::json!({
            "layers": [
                {"size": 10000},
                {"digest": "sha256:valid", "size": 20000}
            ]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs = parse_manifest_layers(&bytes, "partial:v1").unwrap();
        assert_eq!(inputs.len(), 1, "layer without digest should be skipped");
    }

    #[test]
    fn parse_manifest_layers_missing_platform() {
        let manifest = serde_json::json!({
            "manifests": [
                {"digest": "sha256:noplatform", "size": 1000}
            ]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs = parse_manifest_layers(&bytes, "noplatform:v1").unwrap();
        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].name.starts_with("manifest-0"));
    }

    #[test]
    fn parse_manifest_layers_config_without_size() {
        let manifest = serde_json::json!({
            "config": {"digest": "sha256:configonly"}
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs = parse_manifest_layers(&bytes, "configonly:v1").unwrap();
        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].name.starts_with("config-"));
        assert_eq!(inputs[0].size_bytes, None);
    }

    #[test]
    fn parse_manifest_layers_deterministic_hash() {
        let manifest = serde_json::json!({
            "layers": [{"digest": "sha256:abc123", "size": 100}]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let inputs1 = parse_manifest_layers(&bytes, "det:v1").unwrap();
        let inputs2 = parse_manifest_layers(&bytes, "det:v1").unwrap();
        assert_eq!(
            inputs1[0].hash, inputs2[0].hash,
            "same digest must produce same hash"
        );
    }

    #[test]
    fn oci_collector_layer_type() {
        let collector = OciCollector::new("test:latest");
        assert_eq!(collector.layer_type(), LayerType::Oci);
    }

    #[test]
    fn oci_collector_stores_image_ref() {
        let collector = OciCollector::new("ghcr.io/org/app:v1.0");
        assert_eq!(collector.image_ref, "ghcr.io/org/app:v1.0");
    }
}
