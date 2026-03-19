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

/// Akeyless authentication method type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AkeylessAuthMethod {
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

impl std::fmt::Display for AkeylessAuthMethod {
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

/// Type of Akeyless secret
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AkeylessSecretType {
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

impl std::fmt::Display for AkeylessSecretType {
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

/// Record of a single Akeyless secret access
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AkeylessSecretAccess {
    /// Timestamp when the secret was accessed
    pub accessed_at: String,
    /// Akeyless secret path
    pub path: String,
    pub secret_type: AkeylessSecretType,
    /// BLAKE3 hash of the secret value (not the secret itself)
    pub value_hash: String,
    /// Secret version number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

/// Attestation of Akeyless secret access during deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AkeylessSecretAttestation {
    pub auth_method: AkeylessAuthMethod,
    /// BLAKE3 hash of the gateway TLS certificate
    pub gateway_certificate_hash: String,
    /// URL of the Akeyless Gateway
    pub gateway_url: String,
    /// List of secrets accessed during deployment
    pub secrets_accessed: Vec<AkeylessSecretAccess>,
    /// BLAKE3 hash of the authentication session
    pub session_hash: String,
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

/// BLAKE3 hash in prefixed hex format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake3Hash {
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
    Akeyless,
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
            Self::Akeyless => write!(f, "akeyless"),
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

