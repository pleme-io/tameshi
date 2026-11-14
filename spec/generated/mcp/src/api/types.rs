use serde::{Deserialize, Serialize};

/// Running counts of admission decisions made by this gate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionDecisionCounts {
    /// Number of requests allowed through the gate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<i64>,
    /// Number of requests denied by the gate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<i64>,
}

/// A node where the compromised hash was active during the queried window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedNode {
    /// Cluster name (e.g. plo, zek)
    pub cluster: String,
    /// Total number of verification events involving this hash on this node
    pub execution_count: i64,
    /// Earliest execution of the compromised hash on this node
    pub first_execution: String,
    /// Most recent execution of the compromised hash on this node
    pub last_execution: String,
    /// Namespaces containing pods that ran the compromised hash
    pub namespaces: Vec<String>,
    /// Node name
    pub node: String,
    /// Pod names that ran the compromised hash
    pub pods: Vec<String>,
}

/// Result of a single certification pipeline stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageStatus {
    /// BLAKE3 hash of the stage attestation data
    pub hash: String,
    /// Whether the stage passed
    pub passed: bool,
    /// Stage name (e.g. source, build, image, chart, deployment)
    pub stage: String,
    /// Policy violations found in this stage
    pub violations: Vec<String>,
}

/// Result of the certification pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifyResponse {
    /// Deterministic BLAKE3 hash of the entire certification
    pub certification_hash: String,
    /// Whether the product passed certification
    pub certified: bool,
    /// BLAKE3 hash of the compliance dimension
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_hash: Option<String>,
    /// Result for each pipeline stage
    pub stages: Vec<StageStatus>,
    /// List of policy violations found
    pub violations: Vec<String>,
}

/// API response wrapping a certification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponseCertifyResponse {
    pub data: CertifyResponse,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// NIST compliance baseline level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceBaseline {
    Low,
    Moderate,
    High,
}

impl std::fmt::Display for ComplianceBaseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Moderate => write!(f, "moderate"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Latest compliance hash information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashResponse {
    pub baseline: ComplianceBaseline,
    /// BLAKE3 hash of the most recent compliance assessment
    pub compliance_hash: String,
    /// When the hash was computed
    pub computed_at: String,
    /// Environment of the assessment
    pub environment: String,
}

/// API response wrapping a compliance hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponseHashResponse {
    pub data: HashResponse,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Abbreviated view of a compliance result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSummary {
    /// Whether all controls are satisfied
    pub all_satisfied: bool,
    pub baseline: ComplianceBaseline,
    /// BLAKE3 hash of the assessment result
    pub compliance_hash: String,
    /// Environment that was assessed
    pub environment: String,
    /// Unique identifier for this compliance result
    pub id: String,
    /// Number of unsatisfied controls
    pub not_satisfied: i64,
    /// When the assessment was performed
    pub performed_at: String,
    /// Number of satisfied controls
    pub satisfied: i64,
    /// Total number of controls assessed
    pub total_controls: i64,
}

/// API response wrapping a list of compliance result summaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponseResultSummaryList {
    /// List of compliance result summaries
    pub data: Vec<ResultSummary>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Response from triggering a compliance assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    /// Human-readable message about the run
    pub message: String,
    /// Status of the run (e.g. started, completed)
    pub status: String,
}

/// API response wrapping a compliance run result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponseRunResponse {
    pub data: RunResponse,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// BLAKE3 hash in prefixed hex format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake3Hash {
}

/// Location of an artifact in the global fleet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLocation {
    /// Path to the binary on disk
    pub binary_path: String,
    /// Cluster where the artifact resides
    pub cluster_id: String,
    pub composed_root: Blake3Hash,
    /// Kubernetes namespace
    pub namespace: String,
    /// Node within the cluster
    pub node: String,
    /// Pod name
    pub pod: String,
}

/// Delta of artifacts since last report (bandwidth optimization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDelta {
    /// Artifacts added since last report
    pub added: Vec<ArtifactLocation>,
    /// Composed root hashes of artifacts removed since last report
    pub removed: Vec<Blake3Hash>,
}

/// Type of audit action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    SignatureComputed,
    SignatureVerified,
    VerificationFailed,
    ComplianceTestRun,
    Certified,
    Degraded,
    GateAllowed,
    GateDenied,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureComputed => write!(f, "SignatureComputed"),
            Self::SignatureVerified => write!(f, "SignatureVerified"),
            Self::VerificationFailed => write!(f, "VerificationFailed"),
            Self::ComplianceTestRun => write!(f, "ComplianceTestRun"),
            Self::Certified => write!(f, "Certified"),
            Self::Degraded => write!(f, "Degraded"),
            Self::GateAllowed => write!(f, "GateAllowed"),
            Self::GateDenied => write!(f, "GateDenied"),
        }
    }
}

/// Single entry in the audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action: AuditAction,
    /// Whether the operation was allowed (for admission events)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    /// Human-readable details about the event
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Kubernetes resource involved (e.g. apps/v1/Deployment/my-app)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Signature associated with this audit event
    pub signature: String,
    /// When the audit event occurred
    pub timestamp: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// An artifact that shared the same Merkle root as the compromised hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoResidentArtifact {
    pub artifact_hash: Blake3Hash,
    /// Nix store path or binary path of the co-resident artifact
    pub binary_path: String,
    pub composed_root: Blake3Hash,
    pub control_hash: Blake3Hash,
    pub intent_hash: Blake3Hash,
}

/// Inclusion proof for the compromised hash in its Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the compromised hash leaf in the Merkle tree
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<i64>,
    /// BLAKE3 intermediate hashes forming the inclusion proof
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_nodes: Option<Vec<Blake3Hash>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Earliest timestamp the hash was observed in the ledger
    pub first_seen: String,
    /// Most recent timestamp the hash was observed in the ledger
    pub last_seen: String,
}

/// Blast radius report for a compromised BLAKE3 hash. Enumerates every node,
pod, namespace, and time window where the hash appeared in any
CertificationArtifact, plus co-resident artifacts sharing the same Merkle root.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusResponse {
    /// List of nodes where the compromised hash was active
    pub affected_nodes: Vec<AffectedNode>,
    /// Whether the ledger hash chain is intact for the queried range
    pub chain_integrity: bool,
    /// Other artifacts that shared the same Merkle root as the compromised hash
    pub co_resident_artifacts: Vec<CoResidentArtifact>,
    pub evidence_hash: Blake3Hash,
    /// Inclusion proof for the compromised hash in its Merkle tree
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<MerkleProof>,
    pub query_hash: Blake3Hash,
    pub time_range: TimeRange,
    /// Total number of affected nodes
    pub total_affected: i64,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// SLSA (Supply-chain Levels for Software Artifacts) level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SlsaLevel {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L0 => write!(f, "L0"),
            Self::L1 => write!(f, "L1"),
            Self::L2 => write!(f, "L2"),
            Self::L3 => write!(f, "L3"),
            Self::L4 => write!(f, "L4"),
        }
    }
}

/// Attestation of a build artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildAttestation {
    /// Builder identity (e.g. nix, bazel)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder: Option<String>,
    /// Timestamp when the build completed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at: Option<String>,
    /// BLAKE3 hash of the Nix closure
    pub closure_hash: String,
    /// Number of critical and high severity CVEs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_high_cves: Option<i64>,
    /// Total number of CVEs found
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_count: Option<i64>,
    /// Nix store derivation path
    pub derivation: String,
    /// Whether the build is hermetic (no network access)
    pub hermetic: bool,
    /// Whether the build is reproducible
    pub reproducible: bool,
    /// BLAKE3 hash of the software bill of materials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_hash: Option<String>,
    /// Name of the service that was built
    pub service: String,
    pub slsa_level: SlsaLevel,
    /// BLAKE3 hash of vulnerability scan results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_scan_hash: Option<String>,
}

/// Current phase of a certification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertPhase {
    Pending,
    Certified,
    Degraded,
    Failed,
}

impl std::fmt::Display for CertPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Certified => write!(f, "Certified"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Desired state of a Certification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationSpec {
    /// Number of days to retain audit trail entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_retention_days: Option<i64>,
    /// Target environment name
    pub environment: String,
    /// Names of SignatureGate resources to include
    pub gates: Vec<String>,
}

/// Current phase of a signature gate
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatePhase {
    Pending,
    Verified,
    Failed,
    Stale,
}

impl std::fmt::Display for GatePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Verified => write!(f, "Verified"),
            Self::Failed => write!(f, "Failed"),
            Self::Stale => write!(f, "Stale"),
        }
    }
}

/// Reference to a gate's status within a certification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateStatusRef {
    /// Timestamp of the last status check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<String>,
    /// Name of the referenced SignatureGate
    pub name: String,
    pub phase: GatePhase,
    /// Whether the gate is currently verified
    pub verified: bool,
}

/// Observed state of a Certification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationStatus {
    /// Ordered audit trail for this certification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_trail: Option<Vec<AuditEntry>>,
    /// BLAKE3 hash of the compliance assessment result
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_signature: Option<String>,
    /// Status of each gate included in this certification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_statuses: Option<Vec<GateStatusRef>>,
    /// Timestamp of the last successful certification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_certified_at: Option<String>,
    /// Composite master signature across all gates
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_signature: Option<String>,
    pub phase: CertPhase,
    /// BLAKE3 hash combining master and compliance signatures
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_signature: Option<String>,
}

/// Full Certification resource with spec and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certification {
    /// Name of the Certification resource
    pub name: String,
    /// Kubernetes namespace
    pub namespace: String,
    pub spec: CertificationSpec,
    pub status: CertificationStatus,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Policy defining certification requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationPolicy {
    /// Maximum allowed critical+high CVEs across all builds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_critical_high_cves: Option<i64>,
    /// Minimum CIS Kubernetes benchmark pass rate (0.0 to 1.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cis_pass_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_slsa_level: Option<SlsaLevel>,
    /// Policy name
    pub name: String,
    /// Require Helm chart provenance verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_chart_provenance: Option<bool>,
    /// Require compliance assessment to pass
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_compliance: Option<bool>,
    /// Require all container images to have cosign signatures
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_image_signatures: Option<bool>,
    /// Require NetworkPolicy resources for all namespaces
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_network_policies: Option<bool>,
    /// Require all Nix flake inputs to be pinned
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_pinned_inputs: Option<bool>,
    /// Require builds to be reproducible
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_reproducible: Option<bool>,
    /// Require all commits to be GPG/SSH signed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_signed_commits: Option<bool>,
    /// Require source commit signature verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_source_verification: Option<bool>,
}

/// Abbreviated view of a Certification for list responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationSummary {
    /// Target environment (e.g. plo, zek)
    pub environment: String,
    /// Names of the SignatureGates included in this certification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gates: Option<Vec<String>>,
    /// Composite master signature across all gates
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_signature: Option<String>,
    /// Name of the Certification resource
    pub name: String,
    /// Kubernetes namespace
    pub namespace: String,
    pub phase: CertPhase,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Attestation of a Helm chart
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChartAttestation {
    /// BLAKE3 hash of the packaged chart
    pub chart_hash: String,
    /// Helm chart name
    pub chart_name: String,
    /// Helm chart version
    pub chart_version: String,
    /// BLAKE3 hashes of chart dependencies
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_hashes: Option<Vec<String>>,
    /// Whether the chart passed helm lint
    pub linter_passed: bool,
    /// Whether the chart passed OPA/Kyverno policies
    pub policy_passed: bool,
    /// Whether the chart provenance file was verified
    pub provenance_verified: bool,
    /// OCI registry reference for the chart
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_ref: Option<String>,
}

/// Attestation of a Kubernetes deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentAttestation {
    /// Whether all pods are in healthy state
    pub all_healthy: bool,
    /// Whether all HelmRelease resources have verified signatures
    pub all_releases_signed: bool,
    /// CIS Kubernetes benchmark pass rate (0.0 to 1.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cis_k8s_pass_rate: Option<f64>,
    /// FluxCD Kustomization name
    pub kustomization: String,
    /// BLAKE3 hash of rendered Kubernetes manifests
    pub manifest_hash: String,
    /// Kubernetes namespace
    pub namespace: String,
    /// Whether required NetworkPolicy resources are in place
    pub network_policies_verified: bool,
    /// Number of running pods in the deployment
    pub running_pods: i64,
    /// Git commit the deployment was sourced from
    pub source_commit: String,
    /// Whether the source commit signature was verified
    pub source_verified: bool,
}

/// Attestation of a container image
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageAttestation {
    /// Target CPU architecture (e.g. amd64, arm64)
    pub architecture: String,
    /// Whether the image signature was verified with cosign
    pub cosign_verified: bool,
    /// Number of critical and high severity vulnerabilities
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_high_vulns: Option<i64>,
    /// Full image reference (registry/repo)
    pub image_ref: String,
    /// OCI manifest digest
    pub manifest_hash: String,
    /// BLAKE3 hash of the image SBOM
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_hash: Option<String>,
    /// Identity of the cosign signer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
    /// Image tag
    pub tag: String,
    /// Total number of vulnerabilities found
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_count: Option<i64>,
    /// BLAKE3 hash of vulnerability scan results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_scan_hash: Option<String>,
}

/// Attestation of source code integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceAttestation {
    /// Whether all flake inputs are pinned to exact revisions
    pub all_inputs_pinned: bool,
    /// Full commit SHA
    pub commit: String,
    /// Whether the commit has a valid GPG/SSH signature
    pub commit_signed: bool,
    /// Number of flake inputs
    pub flake_input_count: i64,
    /// BLAKE3 hash of flake.lock
    pub flake_lock_hash: String,
    /// Git reference (branch or tag)
    pub git_ref: String,
    /// Git repository URL
    pub repository: String,
    /// Git tree hash of the commit
    pub tree_hash: String,
}

/// Request to certify a product deployment through the multi-stage pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertifyRequest {
    /// Build attestations for each service
    pub builds: Vec<BuildAttestation>,
    /// Helm chart attestations
    pub charts: Vec<ChartAttestation>,
    /// Kubernetes cluster name
    pub cluster: String,
    pub deployment: DeploymentAttestation,
    /// Target environment (e.g. plo, zek)
    pub environment: String,
    /// Container image attestations
    pub images: Vec<ImageAttestation>,
    /// Name of the CertificationPolicy to evaluate against
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Product name being certified
    pub product: String,
    pub source: SourceAttestation,
}

/// Per-node blast radius detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBlastRadius {
    /// Binary paths containing the compromised artifact
    pub binary_paths: Vec<String>,
    /// Total execution count
    pub execution_count: i64,
    /// First execution on this node
    pub first_execution: String,
    /// Most recent execution on this node
    pub last_execution: String,
    /// Node identifier
    pub node: String,
    /// Affected pods on this node
    pub pods: Vec<String>,
}

/// Per-cluster blast radius detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterBlastRadius {
    /// Cluster identifier
    pub cluster_id: String,
    /// First attestation in this cluster
    pub first_seen: String,
    /// Most recent attestation in this cluster
    pub last_seen: String,
    pub node_details: Vec<NodeBlastRadius>,
    /// Number of affected nodes in this cluster
    pub nodes_affected: i64,
    /// Number of affected pods in this cluster
    pub pods_affected: i64,
}

/// Algorithm used to sign a Merkle root
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    Ed25519Local,
    RemoteFragment,
    MockFragment,
    BreakGlass,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519Local => write!(f, "ed25519_local"),
            Self::RemoteFragment => write!(f, "remote_fragment"),
            Self::MockFragment => write!(f, "mock_fragment"),
            Self::BreakGlass => write!(f, "break_glass"),
        }
    }
}

/// A signed Merkle root with signature metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRoot {
    pub algorithm: SigningAlgorithm,
    pub root: Blake3Hash,
    /// Base64-encoded cryptographic signature
    pub signature: String,
    /// Timestamp when the root was signed
    pub signed_at: String,
    /// Identity of the signer (key fingerprint or secrets-manager key path)
    pub signer_id: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Cluster liveness status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClusterStatus {
    Active,
    Stale,
    Offline,
    Revoked,
}

impl std::fmt::Display for ClusterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Stale => write!(f, "stale"),
            Self::Offline => write!(f, "offline"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// A single cluster's contribution to the global state root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterRootEntry {
    /// Total number of CertificationArtifacts across all nodes
    pub artifact_count: i64,
    /// Unique cluster identifier (e.g. plo-us-east, edge-fleet-07)
    pub cluster_id: String,
    pub cluster_root: Blake3Hash,
    /// Last time this cluster reported its root
    pub last_reported: String,
    /// Number of nodes reporting attestations
    pub node_count: i64,
    pub signed_root: SignedRoot,
    pub status: ClusterStatus,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Report sent by a local cluster to the master server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterRootReport {
    /// Total number of CertificationArtifacts across all nodes
    pub artifact_count: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_delta: Option<ArtifactDelta>,
    /// Unique cluster identifier
    pub cluster_id: String,
    pub cluster_root: Blake3Hash,
    /// Number of nodes reporting attestations
    pub node_count: i64,
    /// When this report was generated
    pub reported_at: String,
    pub signed_root: SignedRoot,
}

/// Type of compliance dimension
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DimensionType {
    NistAssessment,
    VulnerabilityScan,
    Sbom,
    SlsaProvenance,
    CosignSignature,
    InTotoAttestation,
    CisBenchmark,
    DisaStig,
    Soc2,
    PciDss,
    OwaspAsvs,
    Iso27001,
    FedRamp,
    CsaStar,
    FrameworkSelfAttestation,
}

impl std::fmt::Display for DimensionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NistAssessment => write!(f, "NistAssessment"),
            Self::VulnerabilityScan => write!(f, "VulnerabilityScan"),
            Self::Sbom => write!(f, "Sbom"),
            Self::SlsaProvenance => write!(f, "SlsaProvenance"),
            Self::CosignSignature => write!(f, "CosignSignature"),
            Self::InTotoAttestation => write!(f, "InTotoAttestation"),
            Self::CisBenchmark => write!(f, "CisBenchmark"),
            Self::DisaStig => write!(f, "DisaStig"),
            Self::Soc2 => write!(f, "Soc2"),
            Self::PciDss => write!(f, "PciDss"),
            Self::OwaspAsvs => write!(f, "OwaspAsvs"),
            Self::Iso27001 => write!(f, "Iso27001"),
            Self::FedRamp => write!(f, "FedRamp"),
            Self::CsaStar => write!(f, "CsaStar"),
            Self::FrameworkSelfAttestation => write!(f, "FrameworkSelfAttestation"),
        }
    }
}

/// A single compliance dimension within an attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceDimension {
    /// When this dimension was assessed
    pub assessed_at: String,
    pub dimension_type: DimensionType,
    /// BLAKE3 hash of the dimension assessment data
    pub hash: String,
    /// Whether this dimension passed
    pub passed: bool,
    /// Whether this dimension is required for certification
    pub required: bool,
    /// Human-readable summary of the assessment
    pub summary: String,
}

/// Multi-dimensional compliance attestation for a deployment artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAttestation {
    /// Whether all required dimensions passed
    pub all_passed: bool,
    /// Artifact identifier being attested
    pub artifact: String,
    /// BLAKE3 hash of all dimension results combined
    pub compliance_hash: String,
    /// When the attestation was computed
    pub computed_at: String,
    /// Individual compliance dimensions assessed
    pub dimensions: Vec<ComplianceDimension>,
    /// Environment being attested
    pub environment: String,
    /// Name of the policy applied
    pub policy_name: String,
}

/// Gap analysis between current state and target baseline for a framework
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceDistance {
    /// Number of unsatisfied controls (targetControls - satisfied)
    pub gap: i64,
    /// Compliance percentage (0.0 to 100.0)
    pub percentage: f64,
    /// Number of controls currently satisfied
    pub satisfied: i64,
    /// Total number of controls required by the target baseline
    pub target_controls: i64,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Full compliance assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceResult {
    /// Whether all controls are satisfied
    pub all_satisfied: bool,
    /// Full OSCAL assessment result object
    pub assessment_result: serde_json::Value,
    pub baseline: ComplianceBaseline,
    /// BLAKE3 hash of the control catalog
    pub catalog_hash: String,
    /// BLAKE3 hash of the entire assessment result
    pub compliance_hash: String,
    /// When the result was computed
    pub computed_at: String,
    /// Environment that was assessed
    pub environment: String,
    /// BLAKE3 hash of the compliance framework definition
    pub framework_hash: String,
    /// Unique identifier for this compliance result
    pub id: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Overall compliance status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    Unknown,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compliant => write!(f, "compliant"),
            Self::NonCompliant => write!(f, "non_compliant"),
            Self::PartiallyCompliant => write!(f, "partially_compliant"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Aggregate compliance state across all active frameworks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceState {
    /// Aggregate distance from full compliance (0.0 = fully compliant, 1.0 = fully non-compliant)
    pub distance: f64,
    /// Active compliance frameworks being assessed
    pub frameworks: Vec<String>,
    pub hash: Blake3Hash,
    /// Timestamp of the most recent compliance assessment
    pub last_assessed_at: String,
    /// Overall compliance status
    pub status: Status,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Infrastructure layer type used for signature computation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerType {
    Nix,
    Oci,
    Helm,
    Tofu,
    Kubernetes,
    Kindling,
    Tatara,
    Fluxcd,
    Argocd,
    SecretsManager,
    SecretTarget,
    PangeaSynthesis,
    RspecResult,
    InspecResult,
}

impl std::fmt::Display for LayerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nix => write!(f, "nix"),
            Self::Oci => write!(f, "oci"),
            Self::Helm => write!(f, "helm"),
            Self::Tofu => write!(f, "tofu"),
            Self::Kubernetes => write!(f, "kubernetes"),
            Self::Kindling => write!(f, "kindling"),
            Self::Tatara => write!(f, "tatara"),
            Self::Fluxcd => write!(f, "fluxcd"),
            Self::Argocd => write!(f, "argocd"),
            Self::SecretsManager => write!(f, "secrets_manager"),
            Self::SecretTarget => write!(f, "secret_target"),
            Self::PangeaSynthesis => write!(f, "pangea_synthesis"),
            Self::RspecResult => write!(f, "rspec_result"),
            Self::InspecResult => write!(f, "inspec_result"),
        }
    }
}

/// Request to compute a deterministic composite signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeSignatureRequest {
    /// Target environment name
    pub environment: String,
    /// Infrastructure layers to include in the computation
    pub layers: Vec<LayerType>,
}

/// Result of a signature computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeSignatureResponse {
    /// Environment the signature was computed for
    pub environment: String,
    /// Layer types that contributed to the signature
    pub layers: Vec<String>,
    /// Computed BLAKE3 composite signature
    pub signature: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Proof that a chain prefix is consistent with a later chain state
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyProof {
    pub from_hash: Blake3Hash,
    /// Sequence number of the earlier chain state
    pub from_seq: i64,
    /// BLAKE3 intermediate hashes forming the consistency proof
    pub proof_nodes: Vec<String>,
    pub to_hash: Blake3Hash,
    /// Sequence number of the later chain state
    pub to_seq: i64,
    /// Whether the proof has been verified server-side
    pub verified: bool,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Request to verify a heartbeat consistency proof
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyProofVerifyRequest {
    pub expected_from_hash: Blake3Hash,
    pub expected_to_hash: Blake3Hash,
    pub proof: ConsistencyProof,
}

/// Standard error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Human-readable error message
    pub error: String,
    /// HTTP status code
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
}

/// An admission decision made by a signature gate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateDecision {
    /// Whether the admission request was allowed
    pub allowed: bool,
    /// Timestamp of the admission decision
    pub decided_at: String,
    /// Expected gate signature at time of decision
    pub expected: String,
    /// Name of the gate that made the decision
    pub gate: String,
    /// Human-readable reason for the decision
    pub reason: String,
    /// Current gate signature at time of decision
    pub signature: String,
}

/// Abbreviated view of a SignatureGate for list responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateSummary {
    /// Most recently computed composite signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_signature: Option<String>,
    /// Expected composite signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signature: Option<String>,
    /// Infrastructure layers this gate covers
    pub layers: Vec<LayerType>,
    /// Name of the SignatureGate resource
    pub name: String,
    /// Kubernetes namespace
    pub namespace: String,
    pub phase: GatePhase,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Verification status for a single infrastructure layer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerStatus {
    /// Error message if verification failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Computed BLAKE3 hash for this layer
    pub hash: String,
    /// Timestamp of the last verification for this layer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<String>,
    pub layer: LayerType,
    /// Whether the layer hash matches the expected value
    pub verified: bool,
}

/// Result of an on-demand gate verification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateVerifyResult {
    /// The freshly computed composite signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_signature: Option<String>,
    /// The expected composite signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_signature: Option<String>,
    /// Per-layer verification results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_statuses: Option<Vec<LayerStatus>>,
    /// Name of the verified gate
    pub name: String,
    pub phase: GatePhase,
    /// Whether the gate passed verification
    pub verified: bool,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Global blast radius report aggregating across all clusters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalBlastRadiusResponse {
    pub cluster_reports: Vec<ClusterBlastRadius>,
    /// Clusters confirmed NOT affected
    pub clusters_not_affected: Vec<String>,
    /// Earliest attestation of this hash across all clusters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_first_seen: Option<String>,
    /// Most recent attestation of this hash across all clusters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_last_seen: Option<String>,
    pub query_hash: Blake3Hash,
    /// Total clusters containing the compromised artifact
    pub total_clusters_affected: i64,
    /// Total nodes across all affected clusters
    pub total_nodes_affected: i64,
    /// Total pods across all affected clusters
    pub total_pods_affected: i64,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Result of a hash revocation operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    /// Number of nodes where the hash was revoked
    pub affected_nodes: i64,
    /// Whether kanshi BPF allow-maps were updated on all affected nodes
    pub bpf_maps_updated: bool,
    /// Sequence number of the Revocation event in the HeartbeatChain
    pub heartbeat_entry_sequence: i64,
    /// Whether the revocation was successfully applied
    pub revoked: bool,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Aggregate result of revoking a hash across all clusters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRevokeResponse {
    /// Per-cluster revocation results
    pub cluster_results: Vec<RevokeResponse>,
    /// Total BPF maps updated across all clusters
    pub total_bpf_maps_updated: i64,
    /// Number of clusters where revocation was applied
    pub total_clusters_revoked: i64,
    /// Total nodes across all clusters where hash was revoked
    pub total_nodes_affected: i64,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Global state root aggregating all cluster roots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStateRootResponse {
    /// Per-cluster state, keyed by cluster_id
    pub cluster_roots: serde_json::Value,
    /// When this global root was computed
    pub computed_at: String,
    pub previous_root: Blake3Hash,
    pub root_hash: Blake3Hash,
    /// Monotonically increasing sequence number
    pub sequence: i64,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Type of event recorded in the heartbeat chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeartbeatEvent {
    AdmissionDecision,
    GateVerification,
    ComplianceAssessment,
    Certification,
    GateCheck,
    BinaryVerification,
    ScriptVerification,
    BreakGlass,
    Revocation,
}

impl std::fmt::Display for HeartbeatEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdmissionDecision => write!(f, "admission_decision"),
            Self::GateVerification => write!(f, "gate_verification"),
            Self::ComplianceAssessment => write!(f, "compliance_assessment"),
            Self::Certification => write!(f, "certification"),
            Self::GateCheck => write!(f, "gate_check"),
            Self::BinaryVerification => write!(f, "binary_verification"),
            Self::ScriptVerification => write!(f, "script_verification"),
            Self::BreakGlass => write!(f, "break_glass"),
            Self::Revocation => write!(f, "revocation"),
        }
    }
}

/// Outcome of the verification or admission decision
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationOutcome {
    Allowed,
    Denied,
    Skipped,
    Error,
}

impl std::fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Denied => write!(f, "denied"),
            Self::Skipped => write!(f, "skipped"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Identity of the component that produced a heartbeat entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierIdentity {
    /// Component name (e.g. sekiban, kensa, inshou)
    pub component: String,
    /// Instance identifier (e.g. pod name, hostname)
    pub instance: String,
    /// Component version
    pub version: String,
}

/// Single entry in the heartbeat proof chain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatEntry {
    pub entry_hash: Blake3Hash,
    pub event: HeartbeatEvent,
    pub previous_hash: Blake3Hash,
    /// Identifier of the resource involved (e.g. apps/v1/Deployment/my-app)
    pub resource: String,
    pub result: VerificationOutcome,
    /// Monotonically increasing sequence number
    pub sequence: i64,
    /// BLAKE3 signature hash that was checked during this event
    pub signature_checked: String,
    /// When the heartbeat event occurred
    pub timestamp: String,
    pub verifier: VerifierIdentity,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Request to render and hash a Helm chart
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelmRenderRequest {
    /// Path to the Helm chart directory or packaged chart
    pub chart_path: String,
    /// Kubernetes namespace for the rendered output
    pub namespace: String,
    /// Helm release name to use during rendering
    pub release_name: String,
    /// Paths to values files to apply during rendering
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values_files: Option<Vec<String>>,
}

/// Hash of a single input artifact within a layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputHash {
    /// BLAKE3 hash of the input content
    pub hash: String,
    /// Logical name of the input artifact
    pub name: String,
    /// Size of the input in bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
}

/// Metadata about a signature computation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureMetadata {
    /// Version of the collector that produced this signature
    pub collector_version: String,
    /// Timestamp when the signature was computed
    pub computed_at: String,
    /// Environment context for the computation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Identifier for the source that produced the inputs
    pub source: String,
}

/// Signature data for a single infrastructure layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerSignature {
    /// BLAKE3 hash of all inputs for this layer
    pub hash: String,
    /// Individual input hashes that compose this layer signature
    pub inputs: Vec<InputHash>,
    pub layer: LayerType,
    pub metadata: SignatureMetadata,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Verification result for a single layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerVerification {
    /// Actual computed hash for this layer
    pub actual: String,
    /// Expected hash for this layer
    pub expected: String,
    pub layer: LayerType,
    /// Whether this layer passed verification
    pub passed: bool,
}

/// Composite master signature across all infrastructure layers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterSignature {
    /// Hash incorporating compliance assessment results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    /// Timestamp when the master signature was computed
    pub computed_at: String,
    /// Environment the master signature covers
    pub environment: String,
    /// Per-layer signatures that compose the master
    pub layers: Vec<LayerSignature>,
    /// Hash incorporating security scan results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<String>,
    /// Raw composite hash before compliance or security attestation
    pub untested: String,
}

/// Full CertificationArtifact (3-leaf Merkle binding provenance, compliance, intent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationArtifact {
    pub artifact_hash: Blake3Hash,
    pub composed_root: Blake3Hash,
    pub control_hash: Blake3Hash,
    pub intent_hash: Blake3Hash,
}

/// Deployment context at the queried timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentContext {
    /// Nix store paths or binary paths within the container
    pub binary_paths: Vec<String>,
    /// Kubernetes cluster name
    pub cluster: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_report_hash: Option<Blake3Hash>,
    /// Container name
    pub container: String,
    /// Full container image reference
    pub image_ref: String,
    /// Kubernetes namespace
    pub namespace: String,
    /// Node name
    pub node: String,
    /// Pod name
    pub pod: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdlc_chain_hash: Option<Blake3Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveArtifacts {
    /// Full CertificationArtifact (3-leaf Merkle binding provenance, compliance, intent)
    pub certification_artifact: CertificationArtifact,
    /// Deployment context at the queried timestamp
    pub deployment_context: DeploymentContext,
    pub signed_root: SignedRoot,
}

/// Point-in-time snapshot of all active artifacts on a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceResponse {
    /// All CertificationArtifacts active on the node at the queried time
    pub active_artifacts: Vec<ActiveArtifacts>,
    /// Node name queried
    pub node: String,
    /// Point-in-time that was queried
    pub timestamp: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Severity of the incident
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Request to revoke a compromised hash across all nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub hash: Blake3Hash,
    /// Identity of the operator performing the revocation (e.g. email)
    pub operator: String,
    /// CVE identifier or reason for revocation (e.g. CVE-2026-XXXX)
    pub reason: String,
    /// Severity of the incident
    pub severity: Severity,
}

/// Type of secrets-manager secret
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    Static,
    DynamicAwsIam,
    DynamicGcp,
    DynamicAzure,
    DynamicK8s,
    DynamicDatabase,
    DynamicCustom,
    RotatedSecret,
    SshCertificate,
    PkiCertificate,
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "Static"),
            Self::DynamicAwsIam => write!(f, "DynamicAwsIam"),
            Self::DynamicGcp => write!(f, "DynamicGcp"),
            Self::DynamicAzure => write!(f, "DynamicAzure"),
            Self::DynamicK8s => write!(f, "DynamicK8s"),
            Self::DynamicDatabase => write!(f, "DynamicDatabase"),
            Self::DynamicCustom => write!(f, "DynamicCustom"),
            Self::RotatedSecret => write!(f, "RotatedSecret"),
            Self::SshCertificate => write!(f, "SshCertificate"),
            Self::PkiCertificate => write!(f, "PkiCertificate"),
        }
    }
}

/// Record of a single secrets-manager secret access
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretAccess {
    /// Timestamp when the secret was accessed
    pub accessed_at: String,
    /// Secrets-manager secret path
    pub path: String,
    pub secret_type: SecretKind,
    /// BLAKE3 hash of the secret value (not the secret itself)
    pub value_hash: String,
    /// Secret version number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

/// Secrets-manager authentication method type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretAuthMethod {
    ApiKey,
    AwsIam,
    AzureAd,
    GcpGce,
    K8s,
    Saml,
    Oidc,
    Certificate,
    Universal,
}

impl std::fmt::Display for SecretAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "ApiKey"),
            Self::AwsIam => write!(f, "AwsIam"),
            Self::AzureAd => write!(f, "AzureAd"),
            Self::GcpGce => write!(f, "GcpGce"),
            Self::K8s => write!(f, "K8s"),
            Self::Saml => write!(f, "Saml"),
            Self::Oidc => write!(f, "Oidc"),
            Self::Certificate => write!(f, "Certificate"),
            Self::Universal => write!(f, "Universal"),
        }
    }
}

/// Attestation of secrets-manager secret access during deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretAttestation {
    pub auth_method: SecretAuthMethod,
    /// BLAKE3 hash of the gateway TLS certificate
    pub gateway_certificate_hash: String,
    /// URL of the secrets-manager Gateway
    pub gateway_url: String,
    /// List of secrets accessed during deployment
    pub secrets_accessed: Vec<SecretAccess>,
    /// BLAKE3 hash of the authentication session
    pub session_hash: String,
}

/// Request to sign a Merkle root
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub algorithm: SigningAlgorithm,
    /// Key name for remote signing (required for remote_fragment)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    pub root: Blake3Hash,
}

/// Kubernetes resource targeted by a gate for admission control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResource {
    /// API group (e.g. apps, batch, empty string for core)
    pub group: String,
    /// Resource kind (e.g. Deployment, Job)
    pub kind: String,
    /// Admission operations to intercept (CREATE, UPDATE, DELETE)
    pub operations: Vec<String>,
}

/// Desired state of a SignatureGate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureGateSpec {
    /// Name of the CertificationPolicy to enforce
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_policy: Option<String>,
    /// Expected certification hash from the compliance engine
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_certification_hash: Option<String>,
    /// Expected deterministic composite signature
    pub expected_signature: String,
    /// Infrastructure layers to include in signature computation
    pub layers: Vec<LayerType>,
    /// Kubernetes resources this gate controls admission for
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_resources: Option<Vec<TargetResource>>,
    /// How often to re-verify the gate in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_interval_secs: Option<i64>,
}

/// Observed state of a SignatureGate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureGateStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_decisions: Option<AdmissionDecisionCounts>,
    /// Most recently computed composite signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_signature: Option<String>,
    /// Number of consecutive verification failures
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_count: Option<i64>,
    /// Timestamp of the last successful verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<String>,
    /// Per-layer verification status
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_statuses: Option<Vec<LayerStatus>>,
    /// Human-readable status message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub phase: GatePhase,
}

/// Full SignatureGate resource with spec and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureGate {
    /// Name of the SignatureGate resource
    pub name: String,
    /// Kubernetes namespace
    pub namespace: String,
    pub spec: SignatureGateSpec,
    pub status: SignatureGateStatus,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Statistics about ledger storage usage across tiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Entries in the archive tier (Glacier/deep archive)
    pub archive_entries: i64,
    /// Entries in the cold tier (S3/object storage)
    pub cold_entries: i64,
    /// Entries in the hot tier (in-memory, fast access)
    pub hot_entries: i64,
    /// Total storage consumed across all tiers in bytes
    pub total_bytes: i64,
    /// Total number of ledger entries across all tiers
    pub total_entries: i64,
    /// Entries in the warm tier (local SSD)
    pub warm_entries: i64,
}

/// Storage tier for ledger data lifecycle
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
    Archive,
}

impl std::fmt::Display for StorageTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hot => write!(f, "hot"),
            Self::Warm => write!(f, "warm"),
            Self::Cold => write!(f, "cold"),
            Self::Archive => write!(f, "archive"),
        }
    }
}

/// A single verification event in the forensics timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Path of the binary being verified
    pub binary_path: String,
    pub composed_root: Blake3Hash,
    pub decision: VerificationOutcome,
    pub event_type: HeartbeatEvent,
    /// Node where the event occurred
    pub node: String,
    /// Pod that triggered the event
    pub pod: String,
    /// Ledger sequence number for this event
    pub sequence: i64,
    /// When the verification event occurred
    pub timestamp: String,
}

/// Chronological list of verification events for a specific hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineResponse {
    /// Ordered list of verification events
    pub events: Vec<TimelineEvent>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Result of a signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    /// Actual computed signature or hash value
    pub actual: String,
    /// Human-readable description of what was verified
    pub description: String,
    /// Expected signature or hash value
    pub expected: String,
    /// Per-layer verification results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_results: Option<Vec<LayerVerification>>,
    /// Whether verification passed
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Baseline {
    Low,
    Moderate,
    High,
}

impl std::fmt::Display for Baseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Moderate => write!(f, "moderate"),
            Self::High => write!(f, "high"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Nist,
    Oscal,
    Soc2,
    Pci,
    Fedramp,
    Stig,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nist => write!(f, "nist"),
            Self::Oscal => write!(f, "oscal"),
            Self::Soc2 => write!(f, "soc2"),
            Self::Pci => write!(f, "pci"),
            Self::Fedramp => write!(f, "fedramp"),
            Self::Stig => write!(f, "stig"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Oscal,
    Nist,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oscal => write!(f, "oscal"),
            Self::Nist => write!(f, "nist"),
        }
    }
}

