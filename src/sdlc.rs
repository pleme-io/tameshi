//! Software Delivery Lifecycle (SDLC) attestation integration points.
//!
//! Provides hash computation for every phase of the build-deploy pipeline,
//! enabling tameshi gates at each transition point. Each SDLC phase produces
//! a [`Blake3Hash`] that feeds into an [`SdlcChain`], which composes all
//! checkpoints into a single chain hash suitable for Merkle tree integration
//! via [`LayerSignature`].
//!
//! # Phases
//!
//! The eight SDLC phases mirror the complete delivery pipeline:
//!
//! ```text
//! SourceCommit → CiBuild → NixEvaluation → ContainerBuild
//!     → HelmPackage → GitOpsSync → K8sAdmission → RuntimeExecution
//! ```
//!
//! # Usage
//!
//! ```rust
//! use tameshi::sdlc::{SdlcChain, SdlcCheckpoint, SdlcPhase, hash_git_tree};
//! use tameshi::hash::Blake3Hash;
//! use chrono::Utc;
//!
//! let mut chain = SdlcChain::new("deploy-20260320-001");
//! chain.add_checkpoint(SdlcCheckpoint {
//!     phase: SdlcPhase::SourceCommit,
//!     output_hash: hash_git_tree("abc123def456"),
//!     gate_passed: true,
//!     gate_name: Some("pre-commit".to_string()),
//!     details: "Git tree hash attested".to_string(),
//!     recorded_at: Utc::now(),
//! });
//! assert!(chain.has_phase(&SdlcPhase::SourceCommit));
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

/// SDLC phases that produce attestation hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SdlcPhase {
    /// Source code commit (git tree hash -> BLAKE3).
    SourceCommit,
    /// CI build (build output hash).
    CiBuild,
    /// Nix evaluation (derivation hash).
    NixEvaluation,
    /// Container image build (OCI manifest digest).
    ContainerBuild,
    /// Helm chart package (chart archive hash).
    HelmPackage,
    /// GitOps sync (rendered manifest hash).
    GitOpsSync,
    /// K8s admission (sekiban gate decision).
    K8sAdmission,
    /// Runtime execution (kanshi eBPF verification).
    RuntimeExecution,
}

impl std::fmt::Display for SdlcPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceCommit => write!(f, "source_commit"),
            Self::CiBuild => write!(f, "ci_build"),
            Self::NixEvaluation => write!(f, "nix_evaluation"),
            Self::ContainerBuild => write!(f, "container_build"),
            Self::HelmPackage => write!(f, "helm_package"),
            Self::GitOpsSync => write!(f, "gitops_sync"),
            Self::K8sAdmission => write!(f, "k8s_admission"),
            Self::RuntimeExecution => write!(f, "runtime_execution"),
        }
    }
}

/// All SDLC phases in pipeline order.
pub const ALL_PHASES: [SdlcPhase; 8] = [
    SdlcPhase::SourceCommit,
    SdlcPhase::CiBuild,
    SdlcPhase::NixEvaluation,
    SdlcPhase::ContainerBuild,
    SdlcPhase::HelmPackage,
    SdlcPhase::GitOpsSync,
    SdlcPhase::K8sAdmission,
    SdlcPhase::RuntimeExecution,
];

/// An attestation checkpoint at an SDLC phase.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SdlcCheckpoint {
    /// Which SDLC phase this checkpoint represents.
    pub phase: SdlcPhase,
    /// BLAKE3 hash of the phase output.
    pub output_hash: Blake3Hash,
    /// Whether this phase passed its gate.
    pub gate_passed: bool,
    /// The gate that was evaluated (if any).
    pub gate_name: Option<String>,
    /// Human-readable details.
    pub details: String,
    /// When this checkpoint was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// Complete SDLC attestation chain for a deployment.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SdlcChain {
    /// Deployment identifier.
    pub deployment_id: String,
    /// All checkpoints in order.
    pub checkpoints: Vec<SdlcCheckpoint>,
    /// Composite hash of all checkpoint hashes.
    pub chain_hash: Blake3Hash,
    /// Whether all gates passed.
    pub all_gates_passed: bool,
}

impl SdlcChain {
    /// Create a new empty chain.
    #[must_use]
    pub fn new(deployment_id: &str) -> Self {
        Self {
            deployment_id: deployment_id.to_string(),
            checkpoints: Vec::new(),
            chain_hash: Blake3Hash::from([0u8; 32]),
            all_gates_passed: true,
        }
    }

    /// Add a checkpoint and recompute the chain hash.
    pub fn add_checkpoint(&mut self, checkpoint: SdlcCheckpoint) {
        if !checkpoint.gate_passed {
            self.all_gates_passed = false;
        }
        self.checkpoints.push(checkpoint);
        self.recompute_hash();
    }

    /// Recompute the chain hash from all checkpoints.
    fn recompute_hash(&mut self) {
        let mut data = Vec::with_capacity(self.checkpoints.len() * 32);
        for cp in &self.checkpoints {
            data.extend_from_slice(&cp.output_hash.0);
        }
        self.chain_hash = Blake3Hash::digest(&data);
    }

    /// Check if a specific phase has been attested.
    #[must_use]
    pub fn has_phase(&self, phase: &SdlcPhase) -> bool {
        self.checkpoints.iter().any(|cp| &cp.phase == phase)
    }

    /// Get the checkpoint for a specific phase.
    #[must_use]
    pub fn get_phase(&self, phase: &SdlcPhase) -> Option<&SdlcCheckpoint> {
        self.checkpoints.iter().find(|cp| &cp.phase == phase)
    }

    /// Verify the chain is complete (all 8 phases present).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        ALL_PHASES.iter().all(|phase| self.has_phase(phase))
    }

    /// Convert the chain hash to a [`LayerSignature`] for Merkle tree integration.
    #[must_use]
    pub fn to_layer_signature(&self) -> LayerSignature {
        let inputs: Vec<InputHash> = self
            .checkpoints
            .iter()
            .map(|cp| InputHash {
                name: cp.phase.to_string(),
                hash: cp.output_hash.clone(),
                size_bytes: None,
            })
            .collect();

        LayerSignature::new(
            LayerType::FluxCD, // Reuse FluxCD as the deployment layer type
            self.chain_hash.clone(),
            &self.deployment_id,
            inputs,
        )
    }
}

/// Hash a git tree for source commit attestation.
#[must_use]
pub fn hash_git_tree(tree_hash: &str) -> Blake3Hash {
    Blake3Hash::digest(tree_hash.as_bytes())
}

/// Hash CI build output for build attestation.
#[must_use]
pub fn hash_build_output(output_bytes: &[u8]) -> Blake3Hash {
    Blake3Hash::digest(output_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper --

    fn make_checkpoint(phase: SdlcPhase, data: &[u8], passed: bool) -> SdlcCheckpoint {
        SdlcCheckpoint {
            phase,
            output_hash: Blake3Hash::digest(data),
            gate_passed: passed,
            gate_name: Some(format!("{}-gate", std::any::type_name::<SdlcPhase>())),
            details: "test checkpoint".to_string(),
            recorded_at: Utc::now(),
        }
    }

    fn make_full_chain() -> SdlcChain {
        let mut chain = SdlcChain::new("full-deploy");
        for (i, phase) in ALL_PHASES.iter().enumerate() {
            chain.add_checkpoint(make_checkpoint(
                phase.clone(),
                format!("phase-{i}").as_bytes(),
                true,
            ));
        }
        chain
    }

    // -- 1-5: SdlcPhase serde, Display, all variants --

    #[test]
    fn sdlc_phase_serde_roundtrip_all_variants() {
        for phase in &ALL_PHASES {
            let json = serde_json::to_string(phase).unwrap();
            let deserialized: SdlcPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, &deserialized);
        }
    }

    #[test]
    fn sdlc_phase_display_all_variants() {
        let displays: Vec<String> = ALL_PHASES.iter().map(|p| p.to_string()).collect();
        assert_eq!(
            displays,
            vec![
                "source_commit",
                "ci_build",
                "nix_evaluation",
                "container_build",
                "helm_package",
                "gitops_sync",
                "k8s_admission",
                "runtime_execution",
            ]
        );
    }

    #[test]
    fn sdlc_phase_count_is_eight() {
        assert_eq!(ALL_PHASES.len(), 8);
    }

    #[test]
    fn sdlc_phase_equality() {
        assert_eq!(SdlcPhase::SourceCommit, SdlcPhase::SourceCommit);
        assert_ne!(SdlcPhase::SourceCommit, SdlcPhase::CiBuild);
    }

    #[test]
    fn sdlc_phase_clone() {
        let phase = SdlcPhase::NixEvaluation;
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    // -- 6-10: SdlcCheckpoint creation, gate logic, serde --

    #[test]
    fn checkpoint_creation_gate_passed() {
        let cp = make_checkpoint(SdlcPhase::SourceCommit, b"src", true);
        assert!(cp.gate_passed);
        assert_eq!(cp.phase, SdlcPhase::SourceCommit);
        assert!(cp.gate_name.is_some());
    }

    #[test]
    fn checkpoint_creation_gate_failed() {
        let cp = make_checkpoint(SdlcPhase::CiBuild, b"ci-fail", false);
        assert!(!cp.gate_passed);
        assert_eq!(cp.phase, SdlcPhase::CiBuild);
    }

    #[test]
    fn checkpoint_serde_roundtrip() {
        let cp = make_checkpoint(SdlcPhase::HelmPackage, b"helm", true);
        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: SdlcCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp.phase, deserialized.phase);
        assert_eq!(cp.output_hash, deserialized.output_hash);
        assert_eq!(cp.gate_passed, deserialized.gate_passed);
    }

    #[test]
    fn checkpoint_with_no_gate_name() {
        let cp = SdlcCheckpoint {
            phase: SdlcPhase::GitOpsSync,
            output_hash: Blake3Hash::digest(b"gitops"),
            gate_passed: true,
            gate_name: None,
            details: "no gate".to_string(),
            recorded_at: Utc::now(),
        };
        assert!(cp.gate_name.is_none());
        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: SdlcCheckpoint = serde_json::from_str(&json).unwrap();
        assert!(deserialized.gate_name.is_none());
    }

    #[test]
    fn checkpoint_output_hash_is_deterministic() {
        let cp1 = make_checkpoint(SdlcPhase::ContainerBuild, b"image-data", true);
        let cp2 = make_checkpoint(SdlcPhase::ContainerBuild, b"image-data", true);
        assert_eq!(cp1.output_hash, cp2.output_hash);
    }

    // -- 11-15: SdlcChain::new, add_checkpoint, chain_hash determinism --

    #[test]
    fn chain_new_is_empty() {
        let chain = SdlcChain::new("test-deploy");
        assert_eq!(chain.deployment_id, "test-deploy");
        assert!(chain.checkpoints.is_empty());
        assert!(chain.all_gates_passed);
        assert_eq!(chain.chain_hash, Blake3Hash::from([0u8; 32]));
    }

    #[test]
    fn chain_add_single_checkpoint() {
        let mut chain = SdlcChain::new("deploy-1");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::SourceCommit, b"src", true));
        assert_eq!(chain.checkpoints.len(), 1);
        assert_ne!(chain.chain_hash, Blake3Hash::from([0u8; 32]));
    }

    #[test]
    fn chain_hash_determinism() {
        let mut chain1 = SdlcChain::new("deploy-det");
        let mut chain2 = SdlcChain::new("deploy-det");

        let data = b"deterministic-data";
        chain1.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, data, true));
        chain2.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, data, true));

        assert_eq!(chain1.chain_hash, chain2.chain_hash);
    }

    #[test]
    fn chain_hash_changes_with_different_data() {
        let mut chain1 = SdlcChain::new("d1");
        let mut chain2 = SdlcChain::new("d2");

        chain1.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"data-a", true));
        chain2.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"data-b", true));

        assert_ne!(chain1.chain_hash, chain2.chain_hash);
    }

    #[test]
    fn chain_serde_roundtrip() {
        let mut chain = SdlcChain::new("serde-deploy");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::SourceCommit, b"src", true));
        chain.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"ci", true));

        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: SdlcChain = serde_json::from_str(&json).unwrap();
        assert_eq!(chain.deployment_id, deserialized.deployment_id);
        assert_eq!(chain.chain_hash, deserialized.chain_hash);
        assert_eq!(chain.checkpoints.len(), deserialized.checkpoints.len());
        assert_eq!(chain.all_gates_passed, deserialized.all_gates_passed);
    }

    // -- 16-20: has_phase, get_phase, is_complete --

    #[test]
    fn chain_has_phase_present() {
        let mut chain = SdlcChain::new("hp");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::K8sAdmission, b"k8s", true));
        assert!(chain.has_phase(&SdlcPhase::K8sAdmission));
    }

    #[test]
    fn chain_has_phase_absent() {
        let chain = SdlcChain::new("hp-absent");
        assert!(!chain.has_phase(&SdlcPhase::RuntimeExecution));
    }

    #[test]
    fn chain_get_phase_returns_checkpoint() {
        let mut chain = SdlcChain::new("gp");
        let hash = Blake3Hash::digest(b"nix-eval");
        chain.add_checkpoint(SdlcCheckpoint {
            phase: SdlcPhase::NixEvaluation,
            output_hash: hash.clone(),
            gate_passed: true,
            gate_name: Some("nix-gate".to_string()),
            details: "nix evaluation passed".to_string(),
            recorded_at: Utc::now(),
        });
        let cp = chain.get_phase(&SdlcPhase::NixEvaluation).unwrap();
        assert_eq!(cp.output_hash, hash);
    }

    #[test]
    fn chain_get_phase_returns_none_when_absent() {
        let chain = SdlcChain::new("gp-none");
        assert!(chain.get_phase(&SdlcPhase::HelmPackage).is_none());
    }

    #[test]
    fn chain_is_complete_when_all_present() {
        let chain = make_full_chain();
        assert!(chain.is_complete());
    }

    // -- 21-25: all_gates_passed, to_layer_signature --

    #[test]
    fn chain_is_not_complete_when_partial() {
        let mut chain = SdlcChain::new("partial");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::SourceCommit, b"src", true));
        chain.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"ci", true));
        assert!(!chain.is_complete());
    }

    #[test]
    fn chain_all_gates_passed_when_all_pass() {
        let chain = make_full_chain();
        assert!(chain.all_gates_passed);
    }

    #[test]
    fn chain_all_gates_passed_false_when_one_fails() {
        let mut chain = SdlcChain::new("one-fail");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::SourceCommit, b"src", true));
        chain.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"ci", false));
        assert!(!chain.all_gates_passed);
    }

    #[test]
    fn chain_to_layer_signature_type() {
        let chain = make_full_chain();
        let sig = chain.to_layer_signature();
        assert_eq!(sig.layer, LayerType::FluxCD);
        assert_eq!(sig.hash, chain.chain_hash);
    }

    #[test]
    fn chain_to_layer_signature_inputs() {
        let chain = make_full_chain();
        let sig = chain.to_layer_signature();
        assert_eq!(sig.inputs.len(), 8);
        assert_eq!(sig.inputs[0].name, "source_commit");
        assert_eq!(sig.inputs[7].name, "runtime_execution");
    }

    // -- 26-30: hash_git_tree, hash_build_output, chain_hash dynamics --

    #[test]
    fn hash_git_tree_deterministic() {
        let h1 = hash_git_tree("abc123");
        let h2 = hash_git_tree("abc123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_git_tree_different_inputs_differ() {
        let h1 = hash_git_tree("abc123");
        let h2 = hash_git_tree("def456");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_build_output_deterministic() {
        let h1 = hash_build_output(b"binary-content");
        let h2 = hash_build_output(b"binary-content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_build_output_different_inputs_differ() {
        let h1 = hash_build_output(b"v1");
        let h2 = hash_build_output(b"v2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_hash_changes_on_checkpoint_added() {
        let mut chain = SdlcChain::new("dynamic");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::SourceCommit, b"src", true));
        let hash_after_one = chain.chain_hash.clone();

        chain.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"ci", true));
        let hash_after_two = chain.chain_hash.clone();

        assert_ne!(hash_after_one, hash_after_two);
    }

    // -- 31+: Integration with CertificationArtifact --

    #[test]
    fn chain_hash_feeds_certification_artifact() {
        use crate::certification_artifact::compose_certification_artifact;

        let chain = make_full_chain();
        let artifact = compose_certification_artifact(
            "/usr/bin/myapp",
            chain.chain_hash.clone(),
            Blake3Hash::digest(b"kensa-compliance"),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        );
        // The chain hash should be the artifact_hash input
        assert_eq!(artifact.artifact_hash, chain.chain_hash);
        // The composed root should be a valid 3-leaf Merkle commitment
        assert!(crate::certification_artifact::verify_certification_artifact(&artifact));
    }

    #[test]
    fn chain_layer_signature_source_is_deployment_id() {
        let chain = make_full_chain();
        let sig = chain.to_layer_signature();
        assert_eq!(sig.metadata.source, "full-deploy");
    }

    #[test]
    fn chain_multiple_failed_gates_tracks_all() {
        let mut chain = SdlcChain::new("multi-fail");
        chain.add_checkpoint(make_checkpoint(SdlcPhase::SourceCommit, b"s", false));
        chain.add_checkpoint(make_checkpoint(SdlcPhase::CiBuild, b"c", false));
        chain.add_checkpoint(make_checkpoint(SdlcPhase::NixEvaluation, b"n", true));
        assert!(!chain.all_gates_passed);
        // Verify individual gate statuses are accessible
        assert!(
            !chain
                .get_phase(&SdlcPhase::SourceCommit)
                .unwrap()
                .gate_passed
        );
        assert!(!chain.get_phase(&SdlcPhase::CiBuild).unwrap().gate_passed);
        assert!(
            chain
                .get_phase(&SdlcPhase::NixEvaluation)
                .unwrap()
                .gate_passed
        );
    }

    #[test]
    fn empty_chain_is_not_complete() {
        let chain = SdlcChain::new("empty");
        assert!(!chain.is_complete());
    }

    #[test]
    fn sdlc_phase_json_schema() {
        // Verify schemars derives work (compile-time check + runtime schema)
        let schema = schemars::schema_for!(SdlcPhase);
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("source_commit"));
    }

    #[test]
    fn sdlc_chain_json_schema() {
        let schema = schemars::schema_for!(SdlcChain);
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("deployment_id"));
        assert!(json.contains("chain_hash"));
    }
}
