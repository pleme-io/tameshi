//! Agent binary/container collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's binary or container image
//! by hashing the binary content. Follows the OCI collector pattern for
//! subprocess-based hashing and the Ferrite pattern for struct composition.

use std::path::Path;

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};
use crate::traits::FileSystem;

use super::traits::LayerCollector;

/// Configuration for agent binary collection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentBinaryConfig {
    /// Path to the agent binary or container image tar.
    pub binary_path: String,
    /// Optional version string for metadata.
    pub version: Option<String>,
    /// Optional container image reference (e.g., `ghcr.io/org/agent:v1`).
    pub image_ref: Option<String>,
}

/// Collector that produces a [`LayerSignature`] from an AI agent binary.
#[derive(Debug)]
pub struct AgentBinaryCollector<F: FileSystem = crate::traits::MockFileSystem> {
    config: AgentBinaryConfig,
    fs: F,
}

impl<F: FileSystem> AgentBinaryCollector<F> {
    /// Create a new agent binary collector.
    #[must_use]
    pub fn new(config: AgentBinaryConfig, fs: F) -> Self {
        Self { config, fs }
    }
}

impl<F: FileSystem + Send + Sync> LayerCollector for AgentBinaryCollector<F> {
    async fn collect(&self) -> Result<LayerSignature> {
        let path = Path::new(&self.config.binary_path);
        let content = self.fs.read_file(path).await.map_err(|e| {
            crate::error::TameshiError::InvalidInput(format!(
                "failed to read agent binary at '{}': {e}",
                self.config.binary_path
            ))
        })?;

        let binary_hash = Blake3Hash::digest(&content);

        let mut inputs = vec![InputHash {
            name: "binary_hash".into(),
            hash: binary_hash,
            size_bytes: Some(content.len() as u64),
        }];

        if let Some(ref version) = self.config.version {
            inputs.push(InputHash {
                name: "version".into(),
                hash: Blake3Hash::digest(version.as_bytes()),
                size_bytes: None,
            });
        }

        if let Some(ref image_ref) = self.config.image_ref {
            inputs.push(InputHash {
                name: "image_ref".into(),
                hash: Blake3Hash::digest(image_ref.as_bytes()),
                size_bytes: None,
            });
        }

        // Compute composite hash from sorted inputs
        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher_data = Vec::with_capacity(sorted.len() * 32);
        for input in &sorted {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let composite = Blake3Hash::digest(&hasher_data);

        Ok(LayerSignature {
            layer: LayerType::AgentBinary,
            hash: composite,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.config.binary_path.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::AgentBinary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockFileSystem;

    fn make_config() -> AgentBinaryConfig {
        AgentBinaryConfig {
            binary_path: "/opt/openclaw/bin/agent".into(),
            version: Some("1.0.0".into()),
            image_ref: Some("ghcr.io/org/openclaw:v1.0.0".into()),
        }
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let fs = MockFileSystem::new();
        fs.add_file("/opt/openclaw/bin/agent", b"agent-binary-content");
        let collector = AgentBinaryCollector::new(make_config(), fs);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentBinary);
        assert_eq!(sig.inputs.len(), 3);
        assert!(sig.inputs.iter().any(|i| i.name == "binary_hash"));
        assert!(sig.inputs.iter().any(|i| i.name == "version"));
        assert!(sig.inputs.iter().any(|i| i.name == "image_ref"));
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let fs1 = MockFileSystem::new();
        fs1.add_file("/opt/openclaw/bin/agent", b"agent-binary-content");
        let fs2 = MockFileSystem::new();
        fs2.add_file("/opt/openclaw/bin/agent", b"agent-binary-content");
        let config = make_config();
        let c1 = AgentBinaryCollector::new(config.clone(), fs1);
        let c2 = AgentBinaryCollector::new(config, fs2);
        let s1 = c1.collect().await.unwrap();
        let s2 = c2.collect().await.unwrap();
        assert_eq!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_without_optional_fields() {
        let fs = MockFileSystem::new();
        fs.add_file("/opt/openclaw/bin/agent", b"content");
        let config = AgentBinaryConfig {
            binary_path: "/opt/openclaw/bin/agent".into(),
            version: None,
            image_ref: None,
        };
        let collector = AgentBinaryCollector::new(config, fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
    }

    #[tokio::test]
    async fn collect_missing_binary_errors() {
        let fs = MockFileSystem::new();
        let collector = AgentBinaryCollector::new(make_config(), fs);
        assert!(collector.collect().await.is_err());
    }

    #[test]
    fn layer_type_is_agent_binary() {
        let fs = MockFileSystem::new();
        let collector = AgentBinaryCollector::new(make_config(), fs);
        assert_eq!(collector.layer_type(), LayerType::AgentBinary);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = make_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AgentBinaryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.binary_path, config.binary_path);
    }
}
