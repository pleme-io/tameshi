//! Agent guardrails collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's guardrail policies and
//! rules. Follows the Helm collector pattern for directory-based traversal.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};
use crate::traits::FileSystem;

use super::traits::LayerCollector;

/// Configuration for agent guardrails collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentGuardrailsConfig {
    /// Directory containing guardrail policy files.
    pub guardrails_dir: String,
    /// Optional path to a compiled ruleset file.
    pub ruleset_path: Option<String>,
}

/// Collector that produces a [`LayerSignature`] from agent guardrail policies.
#[derive(Debug)]
pub struct AgentGuardrailsCollector<F: FileSystem = crate::traits::MockFileSystem> {
    config: AgentGuardrailsConfig,
    fs: F,
}

impl<F: FileSystem> AgentGuardrailsCollector<F> {
    #[must_use]
    pub fn new(config: AgentGuardrailsConfig, fs: F) -> Self {
        Self { config, fs }
    }
}

impl<F: FileSystem + Send + Sync> LayerCollector for AgentGuardrailsCollector<F> {
    async fn collect(&self) -> Result<LayerSignature> {
        let mut inputs = Vec::new();

        // Hash compiled ruleset if present
        if let Some(ref ruleset_path) = self.config.ruleset_path {
            let rpath = Path::new(ruleset_path);
            if let Ok(content) = self.fs.read_file(rpath).await {
                inputs.push(InputHash {
                    name: "ruleset".into(),
                    hash: Blake3Hash::digest(&content),
                    size_bytes: Some(content.len() as u64),
                });
            }
        }

        // Hash all policy files in the guardrails directory
        let dir_path = Path::new(&self.config.guardrails_dir);
        let entries = self.fs.read_dir(dir_path).await.map_err(|e| {
            crate::error::TameshiError::InvalidInput(format!(
                "failed to list guardrails directory '{}': {e}",
                self.config.guardrails_dir
            ))
        })?;

        let mut sorted_entries = entries;
        sorted_entries.sort();

        for entry in &sorted_entries {
            let name = entry
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if let Ok(content) = self.fs.read_file(entry).await {
                inputs.push(InputHash {
                    name: format!("policy:{name}"),
                    hash: Blake3Hash::digest(&content),
                    size_bytes: Some(content.len() as u64),
                });
            }
        }

        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher_data = Vec::with_capacity(sorted.len() * 32);
        for input in &sorted {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let composite = if hasher_data.is_empty() {
            Blake3Hash::digest(b"empty-guardrails")
        } else {
            Blake3Hash::digest(&hasher_data)
        };

        Ok(LayerSignature {
            layer: LayerType::AgentGuardrails,
            hash: composite,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.config.guardrails_dir.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::AgentGuardrails
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockFileSystem;
    use std::path::PathBuf;

    fn make_config() -> AgentGuardrailsConfig {
        AgentGuardrailsConfig {
            guardrails_dir: "/opt/openclaw/guardrails".into(),
            ruleset_path: Some("/opt/openclaw/guardrails/rules.bin".into()),
        }
    }

    fn make_fs() -> MockFileSystem {
        let fs = MockFileSystem::new();
        fs.add_dir(
            "/opt/openclaw/guardrails",
            vec![
                PathBuf::from("/opt/openclaw/guardrails/rules.bin"),
                PathBuf::from("/opt/openclaw/guardrails/prompt_injection.yaml"),
                PathBuf::from("/opt/openclaw/guardrails/escalation.yaml"),
            ],
        );
        fs.add_file("/opt/openclaw/guardrails/rules.bin", b"compiled-rules");
        fs.add_file(
            "/opt/openclaw/guardrails/prompt_injection.yaml",
            b"deny: prompt_injection",
        );
        fs.add_file(
            "/opt/openclaw/guardrails/escalation.yaml",
            b"deny: privilege_escalation",
        );
        fs
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = AgentGuardrailsCollector::new(make_config(), make_fs());
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentGuardrails);
        assert!(sig.inputs.len() >= 3);
        assert!(sig.inputs.iter().any(|i| i.name == "ruleset"));
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let c1 = AgentGuardrailsCollector::new(make_config(), make_fs());
        let c2 = AgentGuardrailsCollector::new(make_config(), make_fs());
        let s1 = c1.collect().await.unwrap();
        let s2 = c2.collect().await.unwrap();
        assert_eq!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_without_ruleset() {
        let fs = MockFileSystem::new();
        fs.add_dir(
            "/opt/openclaw/guardrails",
            vec![PathBuf::from("/opt/openclaw/guardrails/policy.yaml")],
        );
        fs.add_file("/opt/openclaw/guardrails/policy.yaml", b"policy");
        let config = AgentGuardrailsConfig {
            guardrails_dir: "/opt/openclaw/guardrails".into(),
            ruleset_path: None,
        };
        let collector = AgentGuardrailsCollector::new(config, fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.inputs.len(), 1);
    }

    #[test]
    fn layer_type_is_agent_guardrails() {
        let fs = MockFileSystem::new();
        let collector = AgentGuardrailsCollector::new(make_config(), fs);
        assert_eq!(collector.layer_type(), LayerType::AgentGuardrails);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = make_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AgentGuardrailsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.guardrails_dir, config.guardrails_dir);
    }
}
