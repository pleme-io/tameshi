//! OCI image manifest collector.
//!
//! Computes BLAKE3 hashes of OCI image manifests by querying the registry
//! (via `skopeo inspect --raw` or the registry HTTP API).

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

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
fn parse_manifest_layers(manifest_bytes: &[u8], source: &str) -> Result<Vec<InputHash>> {
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
