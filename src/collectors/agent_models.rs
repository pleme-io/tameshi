//! Agent models collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's authorized model provider
//! configuration. Follows the Ferrite collector pattern for struct-based
//! attestation.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// An authorized model provider for the agent.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelProvider {
    /// Provider name (e.g., "anthropic", "openai", "local").
    pub provider: String,
    /// Model identifier (e.g., "claude-opus-4-6", "gpt-4o").
    pub model_id: String,
    /// Whether this provider is currently active.
    pub active: bool,
    /// Maximum tokens per request.
    pub max_tokens: Option<u32>,
    /// Rate limit (requests per minute).
    pub rate_limit_rpm: Option<u32>,
}

/// Configuration for agent models collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModelsConfig {
    /// List of authorized model providers.
    pub authorized_models: Vec<ModelProvider>,
    /// Agent name for metadata.
    pub agent_name: String,
}

/// Collector that produces a [`LayerSignature`] from authorized model providers.
#[derive(Debug)]
pub struct AgentModelsCollector {
    config: AgentModelsConfig,
}

impl AgentModelsCollector {
    #[must_use]
    pub fn new(config: AgentModelsConfig) -> Self {
        Self { config }
    }
}

impl LayerCollector for AgentModelsCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let mut inputs = Vec::new();

        for model in &self.config.authorized_models {
            let canonical = serde_json::to_string(model).unwrap_or_default();
            inputs.push(InputHash {
                name: format!("model:{}:{}", model.provider, model.model_id),
                hash: Blake3Hash::digest(canonical.as_bytes()),
                size_bytes: None,
            });
        }

        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher_data = Vec::with_capacity(sorted.len() * 32);
        for input in &sorted {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let composite = if hasher_data.is_empty() {
            Blake3Hash::digest(b"no-authorized-models")
        } else {
            Blake3Hash::digest(&hasher_data)
        };

        Ok(LayerSignature {
            layer: LayerType::AgentModels,
            hash: composite,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.config.agent_name.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::AgentModels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> AgentModelsConfig {
        AgentModelsConfig {
            authorized_models: vec![
                ModelProvider {
                    provider: "anthropic".into(),
                    model_id: "claude-opus-4-6".into(),
                    active: true,
                    max_tokens: Some(4096),
                    rate_limit_rpm: Some(60),
                },
                ModelProvider {
                    provider: "openai".into(),
                    model_id: "gpt-4o".into(),
                    active: false,
                    max_tokens: Some(8192),
                    rate_limit_rpm: Some(30),
                },
            ],
            agent_name: "openclaw".into(),
        }
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = AgentModelsCollector::new(make_config());
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentModels);
        assert_eq!(sig.inputs.len(), 2);
        assert!(
            sig.inputs
                .iter()
                .any(|i| i.name == "model:anthropic:claude-opus-4-6")
        );
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let c1 = AgentModelsCollector::new(make_config());
        let c2 = AgentModelsCollector::new(make_config());
        let s1 = c1.collect().await.unwrap();
        let s2 = c2.collect().await.unwrap();
        assert_eq!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_hash_changes_on_model_change() {
        let c1 = AgentModelsCollector::new(make_config());
        let s1 = c1.collect().await.unwrap();

        let mut config2 = make_config();
        config2.authorized_models[0].model_id = "claude-sonnet-4-6".into();
        let c2 = AgentModelsCollector::new(config2);
        let s2 = c2.collect().await.unwrap();

        assert_ne!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_empty_models() {
        let config = AgentModelsConfig {
            authorized_models: vec![],
            agent_name: "test".into(),
        };
        let collector = AgentModelsCollector::new(config);
        let sig = collector.collect().await.unwrap();
        assert!(sig.inputs.is_empty());
    }

    #[test]
    fn layer_type_is_agent_models() {
        let collector = AgentModelsCollector::new(make_config());
        assert_eq!(collector.layer_type(), LayerType::AgentModels);
    }

    #[test]
    fn model_provider_serde_roundtrip() {
        let model = ModelProvider {
            provider: "anthropic".into(),
            model_id: "claude-opus-4-6".into(),
            active: true,
            max_tokens: Some(4096),
            rate_limit_rpm: None,
        };
        let json = serde_json::to_string(&model).unwrap();
        let parsed: ModelProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider, "anthropic");
        assert_eq!(parsed.model_id, "claude-opus-4-6");
    }
}
