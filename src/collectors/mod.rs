//! Infrastructure layer collectors.
//!
//! Each collector knows how to compute a [`LayerSignature`] for its respective
//! infrastructure layer. Collectors shell out to native tools (nix-store, skopeo,
//! helm, tofu) or query APIs to gather the data needed for hashing.
//!
//! All collectors implement the [`LayerCollector`] trait, which provides a
//! uniform interface for collecting layer signatures.

pub mod agent_binary;
pub mod agent_certificates;
pub mod agent_config;
pub mod agent_dependencies;
pub mod agent_guardrails;
pub mod agent_mcp_servers;
pub mod agent_models;
pub mod agent_runtime;
pub mod agent_skills;
pub mod akeyless;
pub mod akeyless_target;
pub mod argocd;
pub mod ferrite;
pub mod fluxcd;
pub mod generic;
pub mod helm;
pub mod inspec_result;
pub mod kasou;
pub mod kindling;
pub mod kubernetes;
pub mod mock;
pub mod nix;
pub mod oci;
pub mod pangea;
pub mod rspec;
pub mod tatara;
pub mod tofu;
pub mod traits;

pub use agent_binary::AgentBinaryCollector;
pub use agent_certificates::AgentCertificatesCollector;
pub use agent_config::AgentConfigCollector;
pub use agent_dependencies::AgentDependenciesCollector;
pub use agent_guardrails::AgentGuardrailsCollector;
pub use agent_mcp_servers::AgentMcpServersCollector;
pub use agent_models::AgentModelsCollector;
pub use agent_runtime::AgentRuntimeCollector;
pub use agent_skills::AgentSkillsCollector;
pub use ferrite::FerriteCollector;
pub use mock::MockCollector;
pub use traits::LayerCollector;
