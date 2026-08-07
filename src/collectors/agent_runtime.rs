//! Agent runtime collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's runtime behavior policies
//! (rate limits, sandboxing, resource constraints). Follows the Ferrite
//! collector pattern for struct-based attestation.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Runtime behavior policy for the agent.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimePolicy {
    /// Maximum concurrent skill executions.
    pub max_concurrent_skills: u32,
    /// Whether shell access is allowed.
    pub allow_shell: bool,
    /// Whether network access is allowed.
    pub allow_network: bool,
    /// Whether filesystem write access is allowed.
    pub allow_filesystem_write: bool,
    /// Maximum memory per skill execution (bytes).
    pub max_memory_bytes: Option<u64>,
    /// Maximum execution time per skill (seconds).
    pub max_execution_secs: Option<u64>,
    /// Whether the agent can generate new skills.
    pub allow_skill_generation: bool,
    /// Whether generated skills require attestation before activation.
    pub require_generated_skill_attestation: bool,
    /// Sandboxing mode for skill execution.
    pub sandbox_mode: SandboxMode,
    /// Human oversight requirements.
    pub human_oversight: HumanOversight,
}

/// Sandboxing mode for skill execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// No sandboxing (dangerous).
    None,
    /// Process-level isolation.
    Process,
    /// Container-level isolation.
    Container,
    /// VM-level isolation.
    Vm,
}

/// Human oversight configuration.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HumanOversight {
    /// Whether human approval is required for destructive actions.
    pub require_approval_for_destructive: bool,
    /// Whether human approval is required for new skill activation.
    pub require_approval_for_skills: bool,
    /// Timeout for human approval requests (seconds).
    pub approval_timeout_secs: Option<u64>,
    /// Fallback action when approval times out.
    pub timeout_action: TimeoutAction,
}

/// Action when human oversight approval times out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutAction {
    /// Deny the action.
    Deny,
    /// Allow the action.
    Allow,
    /// Quarantine for later review.
    Quarantine,
}

/// Configuration for agent runtime collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuntimeConfig {
    /// Runtime policy definition.
    pub policy: RuntimePolicy,
    /// Agent name for metadata.
    pub agent_name: String,
}

/// Collector that produces a [`LayerSignature`] from runtime policies.
#[derive(Debug)]
pub struct AgentRuntimeCollector {
    config: AgentRuntimeConfig,
}

impl AgentRuntimeCollector {
    #[must_use]
    pub fn new(config: AgentRuntimeConfig) -> Self {
        Self { config }
    }
}

impl LayerCollector for AgentRuntimeCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let policy_canonical = serde_json::to_string(&self.config.policy).unwrap_or_default();
        let policy_hash = Blake3Hash::digest(policy_canonical.as_bytes());

        let oversight_canonical =
            serde_json::to_string(&self.config.policy.human_oversight).unwrap_or_default();
        let oversight_hash = Blake3Hash::digest(oversight_canonical.as_bytes());

        let sandbox_str =
            serde_json::to_string(&self.config.policy.sandbox_mode).unwrap_or_default();
        let sandbox_hash = Blake3Hash::digest(sandbox_str.as_bytes());

        let inputs = vec![
            InputHash {
                name: "policy_hash".into(),
                hash: policy_hash,
                size_bytes: Some(policy_canonical.len() as u64),
            },
            InputHash {
                name: "oversight_hash".into(),
                hash: oversight_hash,
                size_bytes: None,
            },
            InputHash {
                name: "sandbox_mode".into(),
                hash: sandbox_hash,
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
            layer: LayerType::AgentRuntime,
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
        LayerType::AgentRuntime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy() -> RuntimePolicy {
        RuntimePolicy {
            max_concurrent_skills: 5,
            allow_shell: false,
            allow_network: true,
            allow_filesystem_write: false,
            max_memory_bytes: Some(512 * 1024 * 1024),
            max_execution_secs: Some(300),
            allow_skill_generation: true,
            require_generated_skill_attestation: true,
            sandbox_mode: SandboxMode::Container,
            human_oversight: HumanOversight {
                require_approval_for_destructive: true,
                require_approval_for_skills: true,
                approval_timeout_secs: Some(300),
                timeout_action: TimeoutAction::Deny,
            },
        }
    }

    fn make_config() -> AgentRuntimeConfig {
        AgentRuntimeConfig {
            policy: make_policy(),
            agent_name: "openclaw".into(),
        }
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = AgentRuntimeCollector::new(make_config());
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentRuntime);
        assert_eq!(sig.inputs.len(), 3);
        assert!(sig.inputs.iter().any(|i| i.name == "policy_hash"));
        assert!(sig.inputs.iter().any(|i| i.name == "oversight_hash"));
        assert!(sig.inputs.iter().any(|i| i.name == "sandbox_mode"));
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let c1 = AgentRuntimeCollector::new(make_config());
        let c2 = AgentRuntimeCollector::new(make_config());
        let s1 = c1.collect().await.unwrap();
        let s2 = c2.collect().await.unwrap();
        assert_eq!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_hash_changes_on_policy_change() {
        let c1 = AgentRuntimeCollector::new(make_config());
        let s1 = c1.collect().await.unwrap();

        let mut config2 = make_config();
        config2.policy.allow_shell = true;
        let c2 = AgentRuntimeCollector::new(config2);
        let s2 = c2.collect().await.unwrap();

        assert_ne!(s1.hash, s2.hash);
    }

    #[test]
    fn layer_type_is_agent_runtime() {
        let collector = AgentRuntimeCollector::new(make_config());
        assert_eq!(collector.layer_type(), LayerType::AgentRuntime);
    }

    #[test]
    fn sandbox_mode_serde_roundtrip() {
        for mode in &[
            SandboxMode::None,
            SandboxMode::Process,
            SandboxMode::Container,
            SandboxMode::Vm,
        ] {
            let json = serde_json::to_string(mode).unwrap();
            let parsed: SandboxMode = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, mode);
        }
    }

    #[test]
    fn runtime_policy_serde_roundtrip() {
        let policy = make_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: RuntimePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_concurrent_skills, 5);
        assert!(!parsed.allow_shell);
        assert!(parsed.require_generated_skill_attestation);
    }
}
