//! Agent configuration collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's configuration with
//! secret values stripped before hashing. Follows the Kindling collector
//! pattern for JSON canonical hashing.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};
use crate::traits::FileSystem;

use super::traits::LayerCollector;

/// Configuration for agent config collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigCollectorConfig {
    /// Path to the agent configuration file.
    pub config_path: String,
    /// Keys to strip before hashing (contain secrets).
    #[serde(default)]
    pub secret_keys: Vec<String>,
    /// Agent name for metadata.
    pub agent_name: String,
}

/// Collector that produces a [`LayerSignature`] from agent configuration.
#[derive(Debug)]
pub struct AgentConfigCollector<F: FileSystem = crate::traits::MockFileSystem> {
    config: AgentConfigCollectorConfig,
    fs: F,
}

impl<F: FileSystem> AgentConfigCollector<F> {
    /// Create a new agent config collector.
    #[must_use]
    pub fn new(config: AgentConfigCollectorConfig, fs: F) -> Self {
        Self { config, fs }
    }
}

/// Strip secret keys from a JSON value (replace with "[REDACTED]").
fn strip_secrets(value: &mut serde_json::Value, secret_keys: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if secret_keys.iter().any(|s| key.contains(s.as_str())) {
                    *val = serde_json::Value::String("[REDACTED]".into());
                } else {
                    strip_secrets(val, secret_keys);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_secrets(item, secret_keys);
            }
        }
        _ => {}
    }
}

impl<F: FileSystem + Send + Sync> LayerCollector for AgentConfigCollector<F> {
    async fn collect(&self) -> Result<LayerSignature> {
        let path = Path::new(&self.config.config_path);
        let content = self.fs.read_file(path).await.map_err(|e| {
            crate::error::TameshiError::InvalidInput(format!(
                "failed to read agent config at '{}': {e}",
                self.config.config_path
            ))
        })?;

        // Parse as JSON, strip secrets, re-serialize canonically
        let mut json_value: serde_json::Value =
            serde_json::from_slice(&content).map_err(|e| {
                crate::error::TameshiError::InvalidInput(format!("invalid agent config JSON: {e}"))
            })?;

        strip_secrets(&mut json_value, &self.config.secret_keys);

        let canonical = serde_json::to_string(&json_value).unwrap_or_default();
        let config_hash = Blake3Hash::digest(canonical.as_bytes());

        let inputs = vec![
            InputHash {
                name: "config_hash".into(),
                hash: config_hash,
                size_bytes: Some(canonical.len() as u64),
            },
            InputHash {
                name: "agent_name".into(),
                hash: Blake3Hash::digest(self.config.agent_name.as_bytes()),
                size_bytes: None,
            },
        ];

        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher_data = Vec::with_capacity(sorted.len() * 32);
        for input in &sorted {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let composite = Blake3Hash::digest(&hasher_data);

        Ok(LayerSignature {
            layer: LayerType::AgentConfig,
            hash: composite,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.config.config_path.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::AgentConfig
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockFileSystem;

    fn make_config() -> AgentConfigCollectorConfig {
        AgentConfigCollectorConfig {
            config_path: "/opt/openclaw/config.json".into(),
            secret_keys: vec!["api_key".into(), "token".into()],
            agent_name: "openclaw".into(),
        }
    }

    fn make_fs() -> MockFileSystem {
        let fs = MockFileSystem::new();
        fs.add_file(
            "/opt/openclaw/config.json",
            br#"{"model":"gpt-4","api_key":"sk-secret","settings":{"max_tokens":1000}}"#,
        );
        fs
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = AgentConfigCollector::new(make_config(), make_fs());
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentConfig);
        assert_eq!(sig.inputs.len(), 2);
    }

    #[tokio::test]
    async fn collect_strips_secrets() {
        let collector = AgentConfigCollector::new(make_config(), make_fs());
        let sig = collector.collect().await.unwrap();

        // Changing the secret shouldn't change the hash (since it's stripped)
        let fs2 = MockFileSystem::new();
        fs2.add_file(
            "/opt/openclaw/config.json",
            br#"{"model":"gpt-4","api_key":"sk-different-secret","settings":{"max_tokens":1000}}"#,
        );
        let collector2 = AgentConfigCollector::new(make_config(), fs2);
        let sig2 = collector2.collect().await.unwrap();

        assert_eq!(
            sig.hash, sig2.hash,
            "hash should be stable when only secrets change"
        );
    }

    #[tokio::test]
    async fn collect_hash_changes_on_config_change() {
        let collector = AgentConfigCollector::new(make_config(), make_fs());
        let sig1 = collector.collect().await.unwrap();

        let fs2 = MockFileSystem::new();
        fs2.add_file(
            "/opt/openclaw/config.json",
            br#"{"model":"claude-4","api_key":"sk-secret","settings":{"max_tokens":2000}}"#,
        );
        let collector2 = AgentConfigCollector::new(make_config(), fs2);
        let sig2 = collector2.collect().await.unwrap();

        assert_ne!(
            sig1.hash, sig2.hash,
            "hash should change when config changes"
        );
    }

    #[tokio::test]
    async fn collect_missing_config_errors() {
        let fs = MockFileSystem::new();
        let collector = AgentConfigCollector::new(make_config(), fs);
        assert!(collector.collect().await.is_err());
    }

    #[test]
    fn layer_type_is_agent_config() {
        let fs = MockFileSystem::new();
        let collector = AgentConfigCollector::new(make_config(), fs);
        assert_eq!(collector.layer_type(), LayerType::AgentConfig);
    }

    #[test]
    fn strip_secrets_replaces_keys() {
        let mut val = serde_json::json!({
            "api_key": "secret",
            "nested": {"token": "also-secret", "safe": "ok"}
        });
        strip_secrets(&mut val, &["api_key".into(), "token".into()]);
        assert_eq!(val["api_key"], "[REDACTED]");
        assert_eq!(val["nested"]["token"], "[REDACTED]");
        assert_eq!(val["nested"]["safe"], "ok");
    }
}
