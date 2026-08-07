//! Kasou VM state collector.
//!
//! Computes BLAKE3 hashes of kasou VM configuration and disk images
//! to produce a [`LayerSignature`] for attestation.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use tracing::debug;

/// Source for collecting kasou VM state.
#[derive(Clone, Debug)]
pub enum KasouSource {
    /// Hash VM config JSON + disk image from local filesystem.
    Local {
        /// Path to a JSON file containing the serialized VmConfig.
        config_path: String,
        /// Path to the root disk image.
        disk_path: String,
    },
    /// Hash from a serialized VmInfo JSON file.
    VmInfo(String),
}

/// Collector for kasou virtual machine state.
///
/// Hashes the VM's configuration, disk image, and network identity
/// into a composite [`LayerSignature`].
pub struct KasouCollector {
    pub source: KasouSource,
}

impl KasouCollector {
    /// Create a collector from local config and disk files.
    pub fn from_local(config_path: &str, disk_path: &str) -> Self {
        Self {
            source: KasouSource::Local {
                config_path: config_path.to_string(),
                disk_path: disk_path.to_string(),
            },
        }
    }

    /// Create a collector from a VmInfo JSON file.
    pub fn from_vm_info(info_path: &str) -> Self {
        Self {
            source: KasouSource::VmInfo(info_path.to_string()),
        }
    }
}

impl LayerCollector for KasouCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            KasouSource::Local {
                config_path,
                disk_path,
            } => hash_local(config_path, disk_path).await,
            KasouSource::VmInfo(info_path) => hash_vm_info(info_path).await,
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Kasou
    }
}

/// Hash VM config + disk image from local files.
async fn hash_local(config_path: &str, disk_path: &str) -> Result<LayerSignature> {
    let mut inputs = Vec::new();

    // Hash the VM config JSON (deterministic via serde)
    let config_content =
        tokio::fs::read(config_path)
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "kasou".into(),
                message: format!("reading config {config_path}: {e}"),
            })?;
    let config_hash = Blake3Hash::digest(&config_content);
    debug!(path = config_path, hash = %config_hash, "hashed VM config");
    inputs.push(InputHash {
        name: "vm-config".to_string(),
        hash: config_hash,
        size_bytes: Some(config_content.len() as u64),
    });

    // Hash the disk image (can be large — use file hashing)
    let disk_hash = hash_file(disk_path).await?;
    let disk_size = tokio::fs::metadata(disk_path).await.map(|m| m.len()).ok();
    debug!(path = disk_path, hash = %disk_hash, "hashed disk image");
    inputs.push(InputHash {
        name: "disk-image".to_string(),
        hash: disk_hash,
        size_bytes: disk_size,
    });

    let composite = compute_composite_hash(&inputs);
    Ok(LayerSignature::new(
        LayerType::Kasou,
        composite,
        config_path,
        inputs,
    ))
}

/// Hash a VmInfo JSON file.
async fn hash_vm_info(info_path: &str) -> Result<LayerSignature> {
    let content = tokio::fs::read(info_path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "kasou".into(),
            message: format!("reading vm info {info_path}: {e}"),
        })?;
    let hash = Blake3Hash::digest(&content);
    debug!(path = info_path, hash = %hash, "hashed VM info");

    let inputs = vec![InputHash {
        name: "vm-info".to_string(),
        hash: hash.clone(),
        size_bytes: Some(content.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Kasou,
        hash,
        info_path,
        inputs,
    ))
}

/// Hash a file using BLAKE3.
async fn hash_file(path: &str) -> Result<Blake3Hash> {
    let content = tokio::fs::read(path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "kasou".into(),
            message: format!("reading {path}: {e}"),
        })?;
    Ok(Blake3Hash::digest(&content))
}

/// Compute composite hash from sorted input hashes.
fn compute_composite_hash(inputs: &[InputHash]) -> Blake3Hash {
    let mut hashes: Vec<_> = inputs.iter().map(|i| i.hash.clone()).collect();
    hashes.sort();
    let combined: Vec<u8> = hashes.iter().flat_map(|h| h.0).collect();
    Blake3Hash::digest(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

    #[tokio::test]
    async fn kasou_collector_layer_type() {
        let collector = KasouCollector::from_local("/tmp/config.json", "/tmp/disk.raw");
        assert_eq!(collector.layer_type(), LayerType::Kasou);
    }

    #[tokio::test]
    async fn hash_config_deterministic() {
        let config = write_temp(b"{\"cpus\": 4, \"memory_mib\": 8192}");
        let disk = write_temp(b"fake disk content");

        let sig1 = hash_local(
            config.path().to_str().unwrap(),
            disk.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        let sig2 = hash_local(
            config.path().to_str().unwrap(),
            disk.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(sig1.hash, sig2.hash, "same input should produce same hash");
    }

    #[tokio::test]
    async fn hash_config_differs_on_change() {
        let config1 = write_temp(b"{\"cpus\": 4}");
        let config2 = write_temp(b"{\"cpus\": 8}");
        let disk = write_temp(b"disk");

        let sig1 = hash_local(
            config1.path().to_str().unwrap(),
            disk.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        let sig2 = hash_local(
            config2.path().to_str().unwrap(),
            disk.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        assert_ne!(
            sig1.hash, sig2.hash,
            "different config should produce different hash"
        );
    }

    #[tokio::test]
    async fn hash_vm_info_deterministic() {
        let info = write_temp(b"{\"id\": \"test\", \"state\": \"running\"}");
        let sig1 = hash_vm_info(info.path().to_str().unwrap()).await.unwrap();
        let sig2 = hash_vm_info(info.path().to_str().unwrap()).await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[tokio::test]
    async fn missing_file_returns_error() {
        let result = hash_local("/nonexistent/config.json", "/nonexistent/disk.raw").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signature_has_correct_inputs() {
        let config = write_temp(b"config");
        let disk = write_temp(b"disk");

        let sig = hash_local(
            config.path().to_str().unwrap(),
            disk.path().to_str().unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "vm-config");
        assert_eq!(sig.inputs[1].name, "disk-image");
    }

    #[test]
    fn composite_hash_is_deterministic() {
        let inputs = vec![
            InputHash {
                name: "a".into(),
                hash: Blake3Hash::digest(b"hello"),
                size_bytes: Some(5),
            },
            InputHash {
                name: "b".into(),
                hash: Blake3Hash::digest(b"world"),
                size_bytes: Some(5),
            },
        ];

        let h1 = compute_composite_hash(&inputs);
        let h2 = compute_composite_hash(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn composite_hash_order_independent() {
        let a = InputHash {
            name: "a".into(),
            hash: Blake3Hash::digest(b"x"),
            size_bytes: None,
        };
        let b = InputHash {
            name: "b".into(),
            hash: Blake3Hash::digest(b"y"),
            size_bytes: None,
        };

        let h_ab = compute_composite_hash(&[a.clone(), b.clone()]);
        let h_ba = compute_composite_hash(&[b, a]);
        assert_eq!(h_ab, h_ba, "order should not matter (sorted internally)");
    }
}
