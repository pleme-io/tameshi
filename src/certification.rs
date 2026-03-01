//! End-to-end certification pipeline for products.
//!
//! A product certification composes attestations across the full deployment
//! lifecycle: Nix build → OCI image → Helm chart → FluxCD → K8s deployment.
//!
//! Each stage produces hashable artifacts. The certification pipeline verifies
//! every artifact in the chain and composes them into a product-level attestation
//! that gates deployment.
//!
//! ## Pipeline Stages
//!
//! ```text
//! 1. SOURCE ATTESTATION
//!    ├── Git commit signature verification
//!    ├── flake.lock input pinning verification
//!    └── Source hash (BLAKE3 of git tree)
//!
//! 2. BUILD ATTESTATION
//!    ├── Nix closure hash (deterministic build)
//!    ├── SLSA provenance (L3 for Nix builds)
//!    ├── SBOM generation (CycloneDX via bombon/sbomnix)
//!    └── CVE scan of closure (Grype on SBOM)
//!
//! 3. IMAGE ATTESTATION
//!    ├── OCI manifest hash (per architecture)
//!    ├── Cosign signature verification
//!    ├── Trivy vulnerability scan
//!    ├── Image SBOM (Syft/Trivy)
//!    └── CIS Docker benchmark (if applicable)
//!
//! 4. CHART ATTESTATION
//!    ├── Helm chart hash (Chart.yaml + values + templates)
//!    ├── Chart provenance (.prov GPG signature)
//!    ├── Dependency verification (pleme-lib hash)
//!    └── kube-linter / Conftest policy scan
//!
//! 5. DEPLOYMENT ATTESTATION
//!    ├── FluxCD source verification (git SHA)
//!    ├── Kustomization hash (rendered manifests)
//!    ├── HelmRelease annotation signature
//!    ├── CIS Kubernetes benchmark (kube-bench)
//!    ├── Network policy verification
//!    └── DISA STIG K8s assessment
//!
//! 6. COMPLIANCE ATTESTATION
//!    ├── NIST 800-53 assessment (kensa)
//!    ├── All compliance dimensions (CVE + SBOM + SLSA + CIS + STIG + ...)
//!    └── Framework self-attestation
//!
//! 7. PRODUCT CERTIFICATION
//!    └── BLAKE3(source || build || image || chart || deployment || compliance)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use tameshi::certification::*;
//!
//! let cert = ProductCertification::builder("myapp", "staging", "plo")
//!     .with_source(source_attestation)
//!     .with_build(build_attestation)
//!     .with_images(vec![backend_image, web_image])
//!     .with_charts(vec![backend_chart, web_chart, workers_chart])
//!     .with_deployment(deployment_attestation)
//!     .with_compliance(compliance_attestation)
//!     .certify()?;
//!
//! assert!(cert.is_certified());
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::compliance::dimensions::ComplianceAttestation;
use crate::compliance::slsa::SlsaLevel;
use crate::hash::Blake3Hash;
use crate::signature::LayerType;

/// A complete product certification across all lifecycle stages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProductCertification {
    /// Product name (e.g., "myapp").
    pub product: String,
    /// Environment (e.g., "staging", "production").
    pub environment: String,
    /// Cluster name (e.g., "plo").
    pub cluster: String,
    /// Source attestation.
    pub source: SourceAttestation,
    /// Build attestations (one per service/binary).
    pub builds: Vec<BuildAttestation>,
    /// Image attestations (one per OCI image).
    pub images: Vec<ImageAttestation>,
    /// Chart attestations (one per Helm chart).
    pub charts: Vec<ChartAttestation>,
    /// Deployment attestation.
    pub deployment: DeploymentAttestation,
    /// Compliance attestation (all dimensions).
    pub compliance: ComplianceAttestation,
    /// Final product certification hash.
    pub certification_hash: Blake3Hash,
    /// Whether the product is fully certified.
    pub certified: bool,
    /// Certification timestamp.
    pub certified_at: DateTime<Utc>,
    /// Certification policy used.
    pub policy: CertificationPolicy,
    /// Per-stage status.
    pub stage_results: Vec<StageResult>,
}

impl ProductCertification {
    pub fn builder(product: &str, environment: &str, cluster: &str) -> CertificationBuilder {
        CertificationBuilder::new(product, environment, cluster)
    }

    pub fn is_certified(&self) -> bool {
        self.certified
    }
}

/// Source code attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceAttestation {
    /// Git repository URL.
    pub repository: String,
    /// Commit SHA.
    pub commit: String,
    /// Branch/ref.
    pub git_ref: String,
    /// Whether the commit is signed (GPG/SSH).
    pub commit_signed: bool,
    /// Hash of the git tree at this commit.
    pub tree_hash: Blake3Hash,
    /// Hash of the flake.lock (pinned dependencies).
    pub flake_lock_hash: Blake3Hash,
    /// Number of flake inputs.
    pub flake_input_count: usize,
    /// Whether all flake inputs are pinned to exact commits.
    pub all_inputs_pinned: bool,
}

/// Build attestation for a single service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildAttestation {
    /// Service name (e.g., "backend", "web").
    pub service: String,
    /// Nix derivation path.
    pub derivation: String,
    /// Nix closure hash (BLAKE3 of NAR-serialized closure).
    pub closure_hash: Blake3Hash,
    /// SLSA provenance level.
    pub slsa_level: SlsaLevel,
    /// Whether the build was verified as reproducible.
    pub reproducible: bool,
    /// Whether the build was hermetic (Nix sandbox).
    pub hermetic: bool,
    /// SBOM hash (CycloneDX).
    pub sbom_hash: Blake3Hash,
    /// CVE scan hash (from SBOM scan).
    pub vuln_scan_hash: Blake3Hash,
    /// Number of CVEs found.
    pub cve_count: usize,
    /// Number of critical/high CVEs.
    pub critical_high_cves: usize,
    /// Builder identity.
    pub builder: String,
    /// Build timestamp.
    pub built_at: DateTime<Utc>,
}

/// Image attestation for a single OCI image.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageAttestation {
    /// Image reference (e.g., "ghcr.io/pleme-io/myapp-backend").
    pub image_ref: String,
    /// Image tag (e.g., "amd64-8db543d").
    pub tag: String,
    /// Architecture (e.g., "amd64", "arm64").
    pub architecture: String,
    /// OCI manifest hash.
    pub manifest_hash: Blake3Hash,
    /// Whether signed with cosign/Sigstore.
    pub cosign_verified: bool,
    /// Cosign signer identity (if signed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
    /// Trivy vulnerability scan hash.
    pub vuln_scan_hash: Blake3Hash,
    /// Number of vulnerabilities.
    pub vuln_count: usize,
    /// Number of critical/high vulnerabilities.
    pub critical_high_vulns: usize,
    /// Image SBOM hash.
    pub sbom_hash: Blake3Hash,
    /// Layer type for tameshi signature.
    pub layer_type: LayerType,
}

/// Chart attestation for a single Helm chart.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChartAttestation {
    /// Chart name (e.g., "myapp-backend").
    pub chart_name: String,
    /// Chart version (e.g., "0.1.1").
    pub chart_version: String,
    /// Chart hash (BLAKE3 of Chart.yaml + values.yaml + templates/).
    pub chart_hash: Blake3Hash,
    /// Whether provenance file (.prov) exists and is valid.
    pub provenance_verified: bool,
    /// Dependency hashes (e.g., pleme-lib).
    pub dependency_hashes: Vec<DependencyHash>,
    /// kube-linter scan passed.
    pub linter_passed: bool,
    /// Conftest policy scan passed.
    pub policy_passed: bool,
    /// OCI registry reference.
    pub registry_ref: String,
}

/// Hash of a chart dependency.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyHash {
    /// Dependency name (e.g., "pleme-lib").
    pub name: String,
    /// Dependency version.
    pub version: String,
    /// BLAKE3 hash of the dependency chart.
    pub hash: Blake3Hash,
}

/// Deployment attestation for K8s deployment state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeploymentAttestation {
    /// Namespace.
    pub namespace: String,
    /// FluxCD Kustomization name.
    pub kustomization: String,
    /// Git commit SHA that FluxCD reconciled from.
    pub source_commit: String,
    /// Whether FluxCD source is verified.
    pub source_verified: bool,
    /// Hash of rendered manifests.
    pub manifest_hash: Blake3Hash,
    /// Whether all HelmReleases have valid signature annotations.
    pub all_releases_signed: bool,
    /// CIS Kubernetes benchmark pass rate.
    pub cis_k8s_pass_rate: f64,
    /// Network policies verified.
    pub network_policies_verified: bool,
    /// Number of pods running.
    pub running_pods: usize,
    /// All health checks passing.
    pub all_healthy: bool,
}

/// Certification policy — what must be true for a product to be certified.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificationPolicy {
    /// Policy name.
    pub name: String,
    /// Require signed git commits.
    pub require_signed_commits: bool,
    /// Require all flake inputs pinned.
    pub require_pinned_inputs: bool,
    /// Minimum SLSA level for builds.
    pub min_slsa_level: SlsaLevel,
    /// Require reproducible builds.
    pub require_reproducible: bool,
    /// Maximum allowed critical/high CVEs (0 = no tolerance).
    pub max_critical_high_cves: usize,
    /// Require cosign image signatures.
    pub require_image_signatures: bool,
    /// Require Helm chart provenance.
    pub require_chart_provenance: bool,
    /// Require FluxCD source verification.
    pub require_source_verification: bool,
    /// Minimum CIS K8s benchmark pass rate.
    pub min_cis_pass_rate: f64,
    /// Require network policies.
    pub require_network_policies: bool,
    /// Require compliance attestation to pass.
    pub require_compliance: bool,
}

impl Default for CertificationPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            require_signed_commits: false,
            require_pinned_inputs: true,
            min_slsa_level: SlsaLevel::L2,
            require_reproducible: false,
            max_critical_high_cves: 0,
            require_image_signatures: true,
            require_chart_provenance: true,
            require_source_verification: true,
            min_cis_pass_rate: 0.85,
            require_network_policies: true,
            require_compliance: true,
        }
    }
}

/// Result of evaluating a single certification stage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageResult {
    /// Stage name.
    pub stage: CertificationStage,
    /// Whether the stage passed.
    pub passed: bool,
    /// Hash of the stage's attestation.
    pub hash: Blake3Hash,
    /// Reasons for failure (empty if passed).
    pub violations: Vec<String>,
}

/// Certification pipeline stages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationStage {
    Source,
    Build,
    Image,
    Chart,
    Deployment,
    Compliance,
}

impl std::fmt::Display for CertificationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificationStage::Source => write!(f, "Source"),
            CertificationStage::Build => write!(f, "Build"),
            CertificationStage::Image => write!(f, "Image"),
            CertificationStage::Chart => write!(f, "Chart"),
            CertificationStage::Deployment => write!(f, "Deployment"),
            CertificationStage::Compliance => write!(f, "Compliance"),
        }
    }
}

/// Builder for constructing a product certification.
pub struct CertificationBuilder {
    product: String,
    environment: String,
    cluster: String,
    policy: CertificationPolicy,
    source: Option<SourceAttestation>,
    builds: Vec<BuildAttestation>,
    images: Vec<ImageAttestation>,
    charts: Vec<ChartAttestation>,
    deployment: Option<DeploymentAttestation>,
    compliance: Option<ComplianceAttestation>,
}

impl CertificationBuilder {
    pub fn new(product: &str, environment: &str, cluster: &str) -> Self {
        Self {
            product: product.to_string(),
            environment: environment.to_string(),
            cluster: cluster.to_string(),
            policy: CertificationPolicy::default(),
            source: None,
            builds: Vec::new(),
            images: Vec::new(),
            charts: Vec::new(),
            deployment: None,
            compliance: None,
        }
    }

    pub fn with_policy(mut self, policy: CertificationPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_source(mut self, source: SourceAttestation) -> Self {
        self.source = Some(source);
        self
    }

    pub fn with_build(mut self, build: BuildAttestation) -> Self {
        self.builds.push(build);
        self
    }

    pub fn with_builds(mut self, builds: Vec<BuildAttestation>) -> Self {
        self.builds = builds;
        self
    }

    pub fn with_image(mut self, image: ImageAttestation) -> Self {
        self.images.push(image);
        self
    }

    pub fn with_images(mut self, images: Vec<ImageAttestation>) -> Self {
        self.images = images;
        self
    }

    pub fn with_chart(mut self, chart: ChartAttestation) -> Self {
        self.charts.push(chart);
        self
    }

    pub fn with_charts(mut self, charts: Vec<ChartAttestation>) -> Self {
        self.charts = charts;
        self
    }

    pub fn with_deployment(mut self, deployment: DeploymentAttestation) -> Self {
        self.deployment = Some(deployment);
        self
    }

    pub fn with_compliance(mut self, compliance: ComplianceAttestation) -> Self {
        self.compliance = Some(compliance);
        self
    }

    /// Evaluate and build the certification.
    pub fn certify(self) -> crate::error::Result<ProductCertification> {
        let source = self.source.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("Source attestation required".to_string())
        })?;
        let deployment = self.deployment.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("Deployment attestation required".to_string())
        })?;
        let compliance = self.compliance.ok_or_else(|| {
            crate::error::TameshiError::InvalidInput("Compliance attestation required".to_string())
        })?;

        let mut stage_results = Vec::new();

        // Evaluate source stage
        stage_results.push(evaluate_source(&source, &self.policy));

        // Evaluate build stages
        for build in &self.builds {
            stage_results.push(evaluate_build(build, &self.policy));
        }

        // Evaluate image stages
        for image in &self.images {
            stage_results.push(evaluate_image(image, &self.policy));
        }

        // Evaluate chart stages
        for chart in &self.charts {
            stage_results.push(evaluate_chart(chart, &self.policy));
        }

        // Evaluate deployment stage
        stage_results.push(evaluate_deployment(&deployment, &self.policy));

        // Evaluate compliance stage
        stage_results.push(evaluate_compliance(&compliance, &self.policy));

        let certified = stage_results.iter().all(|s| s.passed);

        // Compose certification hash from all stage hashes
        let mut data = Vec::new();
        let mut sorted_results = stage_results.clone();
        sorted_results.sort_by(|a, b| format!("{}", a.stage).cmp(&format!("{}", b.stage)));
        for sr in &sorted_results {
            data.extend_from_slice(&sr.hash.0);
        }
        let certification_hash = Blake3Hash::digest(&data);

        Ok(ProductCertification {
            product: self.product,
            environment: self.environment,
            cluster: self.cluster,
            source,
            builds: self.builds,
            images: self.images,
            charts: self.charts,
            deployment,
            compliance,
            certification_hash,
            certified,
            certified_at: Utc::now(),
            policy: self.policy,
            stage_results,
        })
    }
}

fn evaluate_source(source: &SourceAttestation, policy: &CertificationPolicy) -> StageResult {
    let mut violations = Vec::new();

    if policy.require_signed_commits && !source.commit_signed {
        violations.push("Git commit is not signed".to_string());
    }
    if policy.require_pinned_inputs && !source.all_inputs_pinned {
        violations.push("Not all flake inputs are pinned to exact commits".to_string());
    }

    let hash = compute_source_hash(source);
    StageResult {
        stage: CertificationStage::Source,
        passed: violations.is_empty(),
        hash,
        violations,
    }
}

fn evaluate_build(build: &BuildAttestation, policy: &CertificationPolicy) -> StageResult {
    let mut violations = Vec::new();

    if build.slsa_level < policy.min_slsa_level {
        violations.push(format!(
            "{}: SLSA {} < required {}",
            build.service, build.slsa_level, policy.min_slsa_level
        ));
    }
    if policy.require_reproducible && !build.reproducible {
        violations.push(format!("{}: Build is not reproducible", build.service));
    }
    if build.critical_high_cves > policy.max_critical_high_cves {
        violations.push(format!(
            "{}: {} critical/high CVEs (max {})",
            build.service, build.critical_high_cves, policy.max_critical_high_cves
        ));
    }

    let hash = compute_build_hash(build);
    StageResult {
        stage: CertificationStage::Build,
        passed: violations.is_empty(),
        hash,
        violations,
    }
}

fn evaluate_image(image: &ImageAttestation, policy: &CertificationPolicy) -> StageResult {
    let mut violations = Vec::new();

    if policy.require_image_signatures && !image.cosign_verified {
        violations.push(format!(
            "{}:{} not signed with cosign",
            image.image_ref, image.tag
        ));
    }
    if image.critical_high_vulns > policy.max_critical_high_cves {
        violations.push(format!(
            "{}:{} has {} critical/high vulnerabilities (max {})",
            image.image_ref, image.tag, image.critical_high_vulns, policy.max_critical_high_cves
        ));
    }

    let hash = image.manifest_hash.clone();
    StageResult {
        stage: CertificationStage::Image,
        passed: violations.is_empty(),
        hash,
        violations,
    }
}

fn evaluate_chart(chart: &ChartAttestation, policy: &CertificationPolicy) -> StageResult {
    let mut violations = Vec::new();

    if policy.require_chart_provenance && !chart.provenance_verified {
        violations.push(format!(
            "{}-{}: Chart provenance not verified",
            chart.chart_name, chart.chart_version
        ));
    }
    if !chart.linter_passed {
        violations.push(format!(
            "{}: kube-linter scan failed",
            chart.chart_name
        ));
    }
    if !chart.policy_passed {
        violations.push(format!(
            "{}: Conftest policy scan failed",
            chart.chart_name
        ));
    }

    let hash = chart.chart_hash.clone();
    StageResult {
        stage: CertificationStage::Chart,
        passed: violations.is_empty(),
        hash,
        violations,
    }
}

fn evaluate_deployment(deployment: &DeploymentAttestation, policy: &CertificationPolicy) -> StageResult {
    let mut violations = Vec::new();

    if policy.require_source_verification && !deployment.source_verified {
        violations.push("FluxCD source not verified".to_string());
    }
    if !deployment.all_releases_signed {
        violations.push("Not all HelmReleases have valid signature annotations".to_string());
    }
    if deployment.cis_k8s_pass_rate < policy.min_cis_pass_rate {
        violations.push(format!(
            "CIS K8s pass rate {:.0}% < {:.0}% required",
            deployment.cis_k8s_pass_rate * 100.0,
            policy.min_cis_pass_rate * 100.0
        ));
    }
    if policy.require_network_policies && !deployment.network_policies_verified {
        violations.push("Network policies not verified".to_string());
    }
    if !deployment.all_healthy {
        violations.push("Not all pods are healthy".to_string());
    }

    let hash = deployment.manifest_hash.clone();
    StageResult {
        stage: CertificationStage::Deployment,
        passed: violations.is_empty(),
        hash,
        violations,
    }
}

fn evaluate_compliance(compliance: &ComplianceAttestation, policy: &CertificationPolicy) -> StageResult {
    let mut violations = Vec::new();

    if policy.require_compliance && !compliance.all_passed {
        let failed_dims: Vec<String> = compliance
            .dimensions
            .iter()
            .filter(|d| d.required && !d.passed)
            .map(|d| format!("{}: {}", d.dimension_type, d.summary))
            .collect();
        for dim in failed_dims {
            violations.push(format!("Compliance dimension failed: {}", dim));
        }
    }

    let hash = compliance.compliance_hash.clone();
    StageResult {
        stage: CertificationStage::Compliance,
        passed: violations.is_empty(),
        hash,
        violations,
    }
}

fn compute_source_hash(source: &SourceAttestation) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(source.commit.as_bytes());
    data.extend_from_slice(&source.tree_hash.0);
    data.extend_from_slice(&source.flake_lock_hash.0);
    Blake3Hash::digest(&data)
}

fn compute_build_hash(build: &BuildAttestation) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&build.closure_hash.0);
    data.extend_from_slice(&build.sbom_hash.0);
    data.extend_from_slice(&build.vuln_scan_hash.0);
    Blake3Hash::digest(&data)
}

/// Strict production certification policy preset.
///
/// Requires signed commits, SLSA L3, reproducible builds, zero CVE tolerance,
/// cosign image signatures, chart provenance, and 90% CIS pass rate.
pub fn strict_production_policy() -> CertificationPolicy {
    CertificationPolicy {
        name: "strict-production".to_string(),
        require_signed_commits: true,
        require_pinned_inputs: true,
        min_slsa_level: SlsaLevel::L3,
        require_reproducible: true,
        max_critical_high_cves: 0,
        require_image_signatures: true,
        require_chart_provenance: true,
        require_source_verification: true,
        min_cis_pass_rate: 0.90,
        require_network_policies: true,
        require_compliance: true,
    }
}

/// Relaxed staging certification policy preset.
///
/// Allows unsigned commits, SLSA L2, some CVEs, no cosign required,
/// and 80% CIS pass rate. Suitable for pre-production environments.
pub fn relaxed_staging_policy() -> CertificationPolicy {
    CertificationPolicy {
        name: "relaxed-staging".to_string(),
        require_signed_commits: false,
        require_pinned_inputs: true,
        min_slsa_level: SlsaLevel::L2,
        require_reproducible: false,
        max_critical_high_cves: 5,
        require_image_signatures: false,
        require_chart_provenance: false,
        require_source_verification: true,
        min_cis_pass_rate: 0.80,
        require_network_policies: true,
        require_compliance: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::dimensions::*;

    fn make_source() -> SourceAttestation {
        SourceAttestation {
            repository: "github.com/org/product".to_string(),
            commit: "8db543d".to_string(),
            git_ref: "refs/heads/main".to_string(),
            commit_signed: true,
            tree_hash: Blake3Hash::digest(b"git-tree"),
            flake_lock_hash: Blake3Hash::digest(b"flake-lock"),
            flake_input_count: 10,
            all_inputs_pinned: true,
        }
    }

    fn make_build(service: &str) -> BuildAttestation {
        BuildAttestation {
            service: service.to_string(),
            derivation: format!("/nix/store/xxx-myapp-{}.drv", service),
            closure_hash: Blake3Hash::digest(format!("closure-{}", service).as_bytes()),
            slsa_level: SlsaLevel::L3,
            reproducible: true,
            hermetic: true,
            sbom_hash: Blake3Hash::digest(b"sbom"),
            vuln_scan_hash: Blake3Hash::digest(b"vulns"),
            cve_count: 2,
            critical_high_cves: 0,
            builder: "nix-build@forge.pleme.io".to_string(),
            built_at: Utc::now(),
        }
    }

    fn make_image(service: &str) -> ImageAttestation {
        ImageAttestation {
            image_ref: format!("ghcr.io/pleme-io/myapp-{}", service),
            tag: "amd64-8db543d".to_string(),
            architecture: "amd64".to_string(),
            manifest_hash: Blake3Hash::digest(format!("manifest-{}", service).as_bytes()),
            cosign_verified: true,
            signer_identity: Some("github-actions[bot]".to_string()),
            vuln_scan_hash: Blake3Hash::digest(b"trivy-scan"),
            vuln_count: 3,
            critical_high_vulns: 0,
            sbom_hash: Blake3Hash::digest(b"image-sbom"),
            layer_type: LayerType::Oci,
        }
    }

    fn make_chart(name: &str) -> ChartAttestation {
        ChartAttestation {
            chart_name: name.to_string(),
            chart_version: "0.1.1".to_string(),
            chart_hash: Blake3Hash::digest(format!("chart-{}", name).as_bytes()),
            provenance_verified: true,
            dependency_hashes: vec![DependencyHash {
                name: "pleme-lib".to_string(),
                version: "0.3.1".to_string(),
                hash: Blake3Hash::digest(b"pleme-lib-chart"),
            }],
            linter_passed: true,
            policy_passed: true,
            registry_ref: format!("oci://ghcr.io/pleme-io/charts/{}", name),
        }
    }

    fn make_deployment() -> DeploymentAttestation {
        DeploymentAttestation {
            namespace: "myapp-staging".to_string(),
            kustomization: "myapp-staging".to_string(),
            source_commit: "8db543d".to_string(),
            source_verified: true,
            manifest_hash: Blake3Hash::digest(b"rendered-manifests"),
            all_releases_signed: true,
            cis_k8s_pass_rate: 0.92,
            network_policies_verified: true,
            running_pods: 6,
            all_healthy: true,
        }
    }

    fn make_compliance() -> ComplianceAttestation {
        ComplianceAttestation {
            environment: "staging".to_string(),
            artifact: "myapp".to_string(),
            dimensions: vec![ComplianceDimension {
                dimension_type: DimensionType::NistAssessment,
                hash: Blake3Hash::digest(b"nist"),
                passed: true,
                summary: "All controls satisfied".to_string(),
                assessed_at: Utc::now(),
                required: true,
            }],
            compliance_hash: Blake3Hash::digest(b"compliance"),
            computed_at: Utc::now(),
            policy_name: "default".to_string(),
            all_passed: true,
        }
    }

    #[test]
    fn full_certification_passes() {
        let cert = ProductCertification::builder("myapp", "staging", "plo")
            .with_policy(relaxed_staging_policy())
            .with_source(make_source())
            .with_build(make_build("backend"))
            .with_build(make_build("web"))
            .with_image(make_image("backend"))
            .with_image(make_image("web"))
            .with_chart(make_chart("myapp-backend"))
            .with_chart(make_chart("myapp-web"))
            .with_chart(make_chart("myapp-workers"))
            .with_deployment(make_deployment())
            .with_compliance(make_compliance())
            .certify()
            .unwrap();

        assert!(cert.is_certified());
        // 1 source + 2 builds + 2 images + 3 charts + 1 deployment + 1 compliance = 10
        assert_eq!(cert.stage_results.len(), 10);
    }

    #[test]
    fn certification_fails_with_cves() {
        let mut build = make_build("backend");
        build.critical_high_cves = 3;

        let cert = ProductCertification::builder("myapp", "staging", "plo")
            .with_policy(CertificationPolicy {
                max_critical_high_cves: 0,
                ..relaxed_staging_policy()
            })
            .with_source(make_source())
            .with_build(build)
            .with_image(make_image("backend"))
            .with_chart(make_chart("myapp-backend"))
            .with_deployment(make_deployment())
            .with_compliance(make_compliance())
            .certify()
            .unwrap();

        assert!(!cert.is_certified());
        let build_result = cert
            .stage_results
            .iter()
            .find(|s| s.stage == CertificationStage::Build)
            .unwrap();
        assert!(!build_result.passed);
        assert!(build_result.violations[0].contains("critical/high CVEs"));
    }

    #[test]
    fn certification_fails_unsigned_image() {
        let mut image = make_image("backend");
        image.cosign_verified = false;

        let cert = ProductCertification::builder("myapp", "production", "plo")
            .with_policy(strict_production_policy())
            .with_source(make_source())
            .with_build(make_build("backend"))
            .with_image(image)
            .with_chart(make_chart("myapp-backend"))
            .with_deployment(make_deployment())
            .with_compliance(make_compliance())
            .certify()
            .unwrap();

        assert!(!cert.is_certified());
    }

    #[test]
    fn certification_hash_deterministic() {
        let c1 = ProductCertification::builder("myapp", "staging", "plo")
            .with_policy(relaxed_staging_policy())
            .with_source(make_source())
            .with_build(make_build("backend"))
            .with_image(make_image("backend"))
            .with_chart(make_chart("myapp-backend"))
            .with_deployment(make_deployment())
            .with_compliance(make_compliance())
            .certify()
            .unwrap();

        let c2 = ProductCertification::builder("myapp", "staging", "plo")
            .with_policy(relaxed_staging_policy())
            .with_source(make_source())
            .with_build(make_build("backend"))
            .with_image(make_image("backend"))
            .with_chart(make_chart("myapp-backend"))
            .with_deployment(make_deployment())
            .with_compliance(make_compliance())
            .certify()
            .unwrap();

        assert_eq!(c1.certification_hash, c2.certification_hash);
    }

    #[test]
    fn staging_policy_is_relaxed() {
        let staging = relaxed_staging_policy();
        let prod = strict_production_policy();

        assert!(!staging.require_signed_commits);
        assert!(prod.require_signed_commits);
        assert!(staging.max_critical_high_cves > prod.max_critical_high_cves);
        assert!(!staging.require_image_signatures);
        assert!(prod.require_image_signatures);
    }
}
