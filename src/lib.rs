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
//! use tameshi::{collectors, merkle, signature::MasterSignature};
//!
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

pub mod ai_threat;
pub mod akeyless_client;
pub mod alerts;
pub mod audit;
pub mod bpf_loader;
pub mod api_types;
pub mod cache;
pub mod canonicalize;
pub mod certification;
pub mod certification_artifact;
pub mod changeset;
pub mod ci;
pub mod collectors;
pub mod compliance;
pub mod compliance_api;
pub mod config;
pub mod encrypted_chain;
pub mod error;
pub mod forensics;
pub mod fragment_extension;
pub mod gating;
pub mod global;
pub mod hash;
pub mod heartbeat;
pub mod iac_attestation;
pub mod merkle;
pub mod node_salt;
pub mod pedersen;
pub mod reporting;
pub mod salted_attestation;
pub mod sdlc;
pub mod selftest;
pub mod shamir_dfc;
pub mod shamir_root;
pub mod signature;
pub mod signing;
pub mod smt_certification;
pub mod sparse_merkle;
pub mod testing;
pub mod traits;
pub mod zk_bpf;
pub mod verify;

/// Prelude module for convenient wildcard imports.
///
/// ```rust
/// use tameshi::prelude::*;
/// ```
pub mod prelude {
    pub use crate::ai_threat::{
        AiAnalysisSummary, AiDecision, AiDeploymentContext, AiFailMode, AiThreatClient,
        AiThreatError, AnalysisFeedback, AnalyzeProvenanceRequest, AnalyzeProvenanceResponse,
        DemoAiThreatClient, FailableAiThreatClient, FeedbackLabel, HttpAiThreatClient,
        MockAiThreatClient, ModelHealthStatus, RecommendedAction, Urgency,
    };
    pub use crate::certification_artifact::{
        ArtifactProofPaths, CertificationArtifact, CertificationArtifactBuilder,
        compose_certification_artifact, verify_certification_artifact,
    };
    pub use crate::canonicalize::{
        CanonicalMode, Canonicalizer, JsonCanonicalizer, RawCanonicalizer, YamlCanonicalizer,
        canonical_hash, canonicalizer_for,
    };
    pub use crate::akeyless_client::{
        AkeylessClient, AkeylessClientError, AkeylessConfig, DynamicSecretInfo,
        HttpAkeylessClient, ItemAssociation, MockAkeylessClient, TargetInfo, TlsConfig,
        build_tls_client,
    };
    pub use crate::collectors::akeyless::LiveAkeylessCollector;
    pub use crate::collectors::akeyless_target::{
        AkeylessTargetCollector, LiveAkeylessTargetCollector,
    };
    pub use crate::collectors::pangea::{
        PangeaSynthesisCollector, hash_synthesis_file, hash_synthesis_json,
    };
    pub use crate::collectors::traits::LayerCollector;
    pub use crate::collectors::MockCollector;
    pub use crate::compliance::akeyless_target::{
        AkeylessTargetAttestation, AkeylessTargetType, ProducerAssociation,
        compute_multi_target_hash, compute_target_attestation_hash,
    };
    pub use crate::compliance_api::{
        CertificationQueryStatus, CheckDefinition, ComplianceDistance, ComplianceQuery,
        ComplianceState, ComplianceStatus, DynamicComplianceCheck, FrameworkState,
    };
    pub use crate::config::ConfigLoader;
    pub use crate::fragment_extension::reconstruct_key_extended;
    pub use crate::hash::{AttestationHasher, Blake3Hash, Blake3Hasher, Sha256Hash, Sha256Hasher};
    pub use crate::merkle::{compose_merkle, compute_merkle_root, domain_separated_leaf};
    pub use crate::signature::{InputHash, LayerSignature, LayerType, MasterSignature};
    pub use crate::sparse_merkle::{SmtProof, SparseMerkleTree};
    pub use crate::traits::{
        Clock, CommandRunner, DefaultGatingEngine, DefaultVerifier, FileSystem, FixedClock,
        GatingEngine, HttpClient, MemStore, MetricsRecorder, MockCommandRunner, MockFileSystem,
        MockGatingEngine, MockHttpClient, MockVerifier, NoopMetrics, ReqwestHttpClient,
        SignatureVerifier, Store, SystemClock, SystemCommandRunner,
    };
    pub use crate::selftest::{
        attest_framework, compute_framework_hash, framework_attestation_hash,
    };
    pub use crate::verify::{verify_master, VerificationResult};
    pub use crate::iac_attestation::{
        IacTestAttester, IacTestPhase, IacTestPhaseResult, IacTestSuiteReport,
        MockIacTestAttester,
    };
    pub use crate::compliance::plugin::{
        ComplianceControl, CompliancePlugin, ControlEvaluation, ControlSeverity,
        DomainEvaluation, MockPlugin, PluginConfig,
    };
    pub use crate::compliance::registry::{PluginRegistry, PluginRegistryBuilder};
    pub use crate::compliance::plugin_orchestrator::{ComplianceOrchestrator, FullComplianceReport};
    pub use crate::sdlc::{SdlcPhase, SdlcCheckpoint, SdlcChain};
    pub use crate::forensics::ledger::{
        InMemoryLedgerStore, MerkleLedger, MerkleLedgerStore,
    };
    pub use crate::forensics::index::LedgerIndex;
    pub use crate::forensics::query::{blast_radius, compute_evidence_hash, provenance, timeline};
    pub use crate::forensics::types::{
        ActiveArtifact, AffectedNodeDetail, BlastRadiusReport, CoResidentArtifact,
        DeploymentContext, LedgerEntryRef, MerkleLedgerEntry, ProvenanceSnapshot, RevokeRequest,
        RevokeResult, TimeRange, TimelineEvent,
    };
    pub use crate::global::{
        ArtifactDelta, ArtifactLocation, ClusterBlastRadius, ClusterRootEntry,
        ClusterRootReport, ClusterStatus, GlobalBlastRadiusReport, GlobalStateClient,
        GlobalStateRoot, MockGlobalStateClient, NodeBlastRadius, compute_cluster_root,
        compute_global_root,
    };
}
