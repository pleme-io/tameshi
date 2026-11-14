//! Tameshi (試し) - Deterministic integrity attestation library
//!
//! Provides cryptographic hash computation, Merkle tree composition, and signature
//! verification for infrastructure layers. Every provisioning layer (Nix stores,
//! OCI images, Helm charts, OpenTofu state, Kubernetes manifests, Kindling identity,
//! Tatara allocations) produces a layer signature. These compose into a master
//! signature that gates provisioning at every level.
//!
//! # Architecture
//!
//! ```text
//! Collectors → LayerSignatures → Merkle Tree → Master Untested Signature
//!                                                        +
//!                                              Compliance Hash
//!                                                        =
//!                                              Master Secure Signature
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! # #[cfg(feature = "full")]
//! use tameshi::{collectors, merkle, signature::MasterSignature};
//!
//! # #[cfg(feature = "full")]
//! # async fn example() -> Result<(), tameshi::error::TameshiError> {
//! // Collect layer signatures
//! let nix_sig = collectors::nix::hash_closure("/nix/store/...").await?;
//! let oci_sig = collectors::oci::hash_manifest("ghcr.io/pleme-io/app:latest").await?;
//!
//! // Compose into master signature
//! let master = merkle::compose_merkle(&[nix_sig, oci_sig], "production");
//!
//! // Verify
//! assert!(master.verify_untested());
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `full` (default): every module and the `tameshi` binary.
//! - `os-rng`: the threshold entry points that draw from the operating
//!   system: `threshold::keygen::trusted_dealer`, `threshold::keygen::dkg::start`
//!   and `threshold::signing::commit`.
//! - `threshold`: the `threshold` module alone, with randomness from the
//!   caller. `default-features = false, features = ["threshold"]` links no
//!   `tokio`, `reqwest`, `object_store`, `axum` or `ring`, and no entropy
//!   source.
//! - `content-address`: the `content_address` module alone, BLAKE3 over one
//!   canonical JSON; it links `serde_json` and nothing heavier.
//! - `merkle`: the `hash`, `merkle` and `sparse_merkle` modules alone:
//!   `Blake3Hash`, the domain-separated leaf root with its inclusion proofs,
//!   and the sparse Merkle tree. It links `blake3`, `rs_merkle`, `serde` and
//!   `const-hex`.

macro_rules! full {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "full")]
            $item
        )*
    };
}

full! {
    pub mod ai_threat;
    pub mod secrets_client;
    pub mod alerts;
    pub mod api_types;
    pub mod audit;
    pub mod bpf_loader;
    pub mod cache;
    pub mod canonicalize;
    pub mod certification;
    pub mod certification_artifact;
    pub mod changeset;
    pub mod ci;
    pub mod collectors;
    pub mod compliance;
    pub mod compliance_api;
    pub mod compliance_heartbeat;
    pub mod config;
    pub mod encrypted_chain;
    pub mod ephemeral_attestation;
    pub mod error;
    pub mod forensics;
    pub mod fragment_collector;
    pub mod fragment_extension;
    pub mod gating;
    pub mod global;
    pub mod heartbeat;
    pub mod iac_attestation;
    pub mod node_salt;
    pub mod pedersen;
    pub mod receipt;
    pub mod reporting;
    pub mod salted_attestation;
    pub mod sdlc;
    pub mod selftest;
    pub mod shamir_fragment;
    pub mod shamir_root;
    pub mod signature;
    pub mod signing;
    pub mod smt_certification;
    pub mod testing;
    pub mod traits;
    pub mod verify;
    pub mod zk_bpf;
}

#[cfg(feature = "content-address")]
pub mod content_address;
#[cfg(any(feature = "full", feature = "merkle"))]
pub mod hash;
#[cfg(any(feature = "full", feature = "merkle"))]
pub mod merkle;
#[cfg(any(feature = "full", feature = "merkle"))]
pub mod sparse_merkle;
#[cfg(any(feature = "full", feature = "threshold"))]
mod ed25519;
#[cfg(feature = "threshold")]
pub mod threshold;

/// Prelude module for convenient wildcard imports.
///
/// ```rust
/// use tameshi::prelude::*;
/// ```
#[cfg(feature = "full")]
pub mod prelude {
    pub use crate::ai_threat::{
        AiAnalysisSummary, AiDecision, AiDeploymentContext, AiFailMode, AiThreatClient,
        AiThreatError, AnalysisFeedback, AnalyzeProvenanceRequest, AnalyzeProvenanceResponse,
        DemoAiThreatClient, FailableAiThreatClient, FeedbackLabel, HttpAiThreatClient,
        MockAiThreatClient, ModelHealthStatus, RecommendedAction, Urgency,
    };
    pub use crate::secrets_client::{
        SecretsManagerClient, SecretsManagerError, SecretsManagerConfig, DynamicSecretInfo, HttpSecretsManagerClient,
        ItemAssociation, MockSecretsManagerClient, TargetInfo, TlsConfig, build_tls_client,
    };
    pub use crate::canonicalize::{
        CanonicalMode, Canonicalizer, JsonCanonicalizer, RawCanonicalizer, YamlCanonicalizer,
        canonical_hash, canonicalizer_for,
    };
    pub use crate::certification_artifact::{
        ArtifactProofPaths, CertificationArtifact, CertificationArtifactBuilder,
        compose_certification_artifact, verify_certification_artifact,
    };
    pub use crate::collectors::MockCollector;
    pub use crate::collectors::agent_binary::{AgentBinaryCollector, AgentBinaryConfig};
    pub use crate::collectors::agent_certificates::{
        AgentCertificatesCollector, AgentCertificatesConfig, CertificateEntry, CertificateUsage,
    };
    pub use crate::collectors::agent_config::{AgentConfigCollector, AgentConfigCollectorConfig};
    pub use crate::collectors::agent_dependencies::{
        AgentDependenciesCollector, AgentDependenciesConfig, DependencyEntry, SbomFormat,
    };
    pub use crate::collectors::agent_guardrails::{
        AgentGuardrailsCollector, AgentGuardrailsConfig,
    };
    pub use crate::collectors::agent_mcp_servers::{
        AgentMcpServersCollector, AgentMcpServersConfig, McpServerAttestation, McpTransport,
    };
    pub use crate::collectors::agent_models::{
        AgentModelsCollector, AgentModelsConfig, ModelProvider,
    };
    pub use crate::collectors::agent_runtime::{
        AgentRuntimeCollector, AgentRuntimeConfig, HumanOversight, RuntimePolicy, SandboxMode,
        TimeoutAction,
    };
    pub use crate::collectors::agent_skills::{
        AgentSkillsCollector, AgentSkillsConfig, SkillAttestation, SkillComplianceStatus,
        SkillDefinition, SkillSource, attest_skill,
    };
    pub use crate::collectors::secrets_manager::LiveSecretsManagerCollector;
    pub use crate::collectors::secret_target::{
        SecretTargetCollector, LiveSecretTargetCollector,
    };
    pub use crate::collectors::pangea::{
        PangeaSynthesisCollector, hash_synthesis_file, hash_synthesis_json,
    };
    pub use crate::collectors::traits::LayerCollector;
    pub use crate::compliance::secret_target::{
        SecretTargetAttestation, SecretTargetType, ProducerAssociation,
        compute_multi_target_hash, compute_target_attestation_hash,
    };
    pub use crate::compliance::plugin::{
        ComplianceControl, CompliancePlugin, ControlEvaluation, ControlSeverity, DomainEvaluation,
        MockPlugin, PluginConfig,
    };
    pub use crate::compliance::plugin_orchestrator::{
        ComplianceOrchestrator, FullComplianceReport,
    };
    pub use crate::compliance::registry::{PluginRegistry, PluginRegistryBuilder};
    pub use crate::compliance_api::{
        CertificationQueryStatus, CheckDefinition, ComplianceDistance, ComplianceQuery,
        ComplianceState, ComplianceStatus, DynamicComplianceCheck, FrameworkState,
    };
    pub use crate::config::ConfigLoader;
    pub use crate::forensics::bluecrash::{BlueCrash, IR_CONTROLS, IncidentBlastRadius};
    pub use crate::forensics::evidence::{
        Evidence, EvidenceLedger, InclusionProof, LeafKind, LeafStatus, LedgerLeaf,
    };
    pub use crate::forensics::index::LedgerIndex;
    pub use crate::forensics::ledger::{InMemoryLedgerStore, MerkleLedger, MerkleLedgerStore};
    pub use crate::forensics::query::{blast_radius, compute_evidence_hash, provenance, timeline};
    pub use crate::forensics::types::{
        ActiveArtifact, AffectedNodeDetail, BlastRadiusReport, CoResidentArtifact,
        DeploymentContext, LedgerEntryRef, MerkleLedgerEntry, ProvenanceSnapshot, RevokeRequest,
        RevokeResult, TimeRange, TimelineEvent,
    };
    pub use crate::fragment_extension::reconstruct_key_extended;
    pub use crate::global::{
        ArtifactDelta, ArtifactLocation, ClusterBlastRadius, ClusterRootEntry, ClusterRootReport,
        ClusterStatus, GlobalBlastRadiusReport, GlobalStateClient, GlobalStateRoot,
        MockGlobalStateClient, NodeBlastRadius, compute_cluster_root, compute_global_root,
    };
    pub use crate::hash::{AttestationHasher, Blake3Hash, Blake3Hasher, Sha256Hash, Sha256Hasher};
    pub use crate::iac_attestation::{
        IacTestAttester, IacTestPhase, IacTestPhaseResult, IacTestSuiteReport, MockIacTestAttester,
    };
    pub use crate::merkle::{
        compose_merkle, compute_leaf_root, compute_merkle_root, domain_separated_leaf,
        leaf_inclusion_proof, verify_leaf_inclusion,
    };
    pub use crate::receipt::fragment::{
        AttestationFragment, FragmentSettings, KeyMode, sign_fragment, sign_fragment_with,
        sign_test_fragment, verify_fragment,
    };
    pub use crate::receipt::{ControlId, ControlLeaf, Receipt, ReceiptParts, tuple_leaf};
    pub use crate::sdlc::{SdlcChain, SdlcCheckpoint, SdlcPhase};
    pub use crate::selftest::{
        attest_framework, compute_framework_hash, framework_attestation_hash,
    };
    pub use crate::signature::{InputHash, LayerSignature, LayerType, MasterSignature};
    pub use crate::sparse_merkle::{SmtProof, SparseMerkleTree};
    pub use crate::threshold::signing::{LocalParty, SigningParty, ThresholdSigner};
    pub use crate::threshold::{
        GroupKey, KeyShare, ParticipantId, ThresholdError, ThresholdParams,
    };
    pub use crate::traits::{
        Clock, CommandRunner, DefaultGatingEngine, DefaultVerifier, FileSystem, FixedClock,
        GatingEngine, HttpClient, MemStore, MetricsRecorder, MockCommandRunner, MockFileSystem,
        MockGatingEngine, MockHttpClient, MockVerifier, NoopMetrics, ReqwestHttpClient,
        SignatureVerifier, Store, SystemClock, SystemCommandRunner,
    };
    pub use crate::verify::{VerificationResult, verify_master};
}
