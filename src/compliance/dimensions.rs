//! Compliance dimensions — unified composition of all compliance sources.
//!
//! Every compliance source (NIST assessment, CVE scan, SBOM, SLSA provenance,
//! CIS benchmark, DISA STIG, etc.) is a "dimension" of compliance. All dimensions
//! compose into the final compliance hash that combines with the untested master
//! signature to form the secure master signature.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                  Compliance Hash                         │
//! │                                                          │
//! │   = BLAKE3(                                              │
//! │       nist_assessment_hash    ||  // NIST 800-53         │
//! │       cve_scan_hash           ||  // Vulnerability scan  │
//! │       sbom_hash               ||  // SBOM attestation    │
//! │       slsa_provenance_hash    ||  // Build provenance    │
//! │       cis_benchmark_hash      ||  // CIS checks          │
//! │       stig_assessment_hash    ||  // DISA STIGs          │
//! │       soc2_assessment_hash    ||  // SOC 2 criteria      │
//! │       pci_assessment_hash     ||  // PCI DSS (if appl.)  │
//! │       owasp_assessment_hash   ||  // OWASP ASVS          │
//! │       iso27001_hash           ||  // ISO 27001           │
//! │       cosign_verification_hash||  // Image signatures    │
//! │       intoto_attestation_hash    // in-toto              │
//! │     )                                                    │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Not all dimensions are required for every artifact. The policy configuration
//! determines which dimensions are mandatory for each artifact type.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

use super::cis::CisBenchmarkResult;
use super::cve::VulnerabilityScan;
use super::result::ComplianceResult;
use super::sbom::SbomAttestation;
use super::slsa::{CosignVerification, InTotoAttestation, SlsaProvenance};
use super::standards::{StandardAssessment, StandardId};

/// A complete multi-dimensional compliance attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceAttestation {
    /// Environment being attested.
    pub environment: String,
    /// Artifact being attested.
    pub artifact: String,
    /// Individual compliance dimensions.
    pub dimensions: Vec<ComplianceDimension>,
    /// The final composed compliance hash.
    pub compliance_hash: Blake3Hash,
    /// When this attestation was computed.
    pub computed_at: DateTime<Utc>,
    /// Policy used for evaluation.
    pub policy_name: String,
    /// Whether all required dimensions passed.
    pub all_passed: bool,
}

/// A single compliance dimension.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceDimension {
    /// Dimension type.
    pub dimension_type: DimensionType,
    /// Hash of this dimension's assessment.
    pub hash: Blake3Hash,
    /// Whether this dimension passed its policy.
    pub passed: bool,
    /// Human-readable summary.
    pub summary: String,
    /// When this dimension was last assessed.
    pub assessed_at: DateTime<Utc>,
    /// Whether this dimension is required by policy.
    pub required: bool,
}

/// Types of compliance dimensions.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionType {
    /// NIST 800-53 control assessment (via InSpec, kensa, etc.).
    NistAssessment,
    /// CVE/vulnerability scanning (Trivy, Grype, vulnix).
    VulnerabilityScan,
    /// SBOM generation and verification (Syft, nix-sbom).
    Sbom,
    /// SLSA build provenance.
    SlsaProvenance,
    /// Sigstore/cosign image signature.
    CosignSignature,
    /// in-toto supply chain attestation.
    InTotoAttestation,
    /// CIS benchmark assessment (kube-bench, docker-bench).
    CisBenchmark,
    /// DISA STIG assessment.
    DisaStig,
    /// SOC 2 Trust Services Criteria.
    Soc2,
    /// PCI DSS requirements.
    PciDss,
    /// OWASP ASVS verification.
    OwaspAsvs,
    /// ISO 27001 Annex A controls.
    Iso27001,
    /// FedRAMP assessment.
    FedRamp,
    /// CSA STAR assessment.
    CsaStar,
    /// Framework self-attestation.
    FrameworkSelfAttestation,
}

impl std::fmt::Display for DimensionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DimensionType::NistAssessment => write!(f, "NIST 800-53"),
            DimensionType::VulnerabilityScan => write!(f, "CVE/Vulnerability Scan"),
            DimensionType::Sbom => write!(f, "SBOM"),
            DimensionType::SlsaProvenance => write!(f, "SLSA Provenance"),
            DimensionType::CosignSignature => write!(f, "Cosign Signature"),
            DimensionType::InTotoAttestation => write!(f, "in-toto Attestation"),
            DimensionType::CisBenchmark => write!(f, "CIS Benchmark"),
            DimensionType::DisaStig => write!(f, "DISA STIG"),
            DimensionType::Soc2 => write!(f, "SOC 2"),
            DimensionType::PciDss => write!(f, "PCI DSS"),
            DimensionType::OwaspAsvs => write!(f, "OWASP ASVS"),
            DimensionType::Iso27001 => write!(f, "ISO 27001"),
            DimensionType::FedRamp => write!(f, "FedRAMP"),
            DimensionType::CsaStar => write!(f, "CSA STAR"),
            DimensionType::FrameworkSelfAttestation => write!(f, "Framework Self-Attestation"),
        }
    }
}

/// Policy defining which compliance dimensions are required.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceDimensionPolicy {
    /// Policy name.
    pub name: String,
    /// Required dimensions (must pass for gating).
    pub required_dimensions: Vec<DimensionType>,
    /// Optional dimensions (tracked but don't block).
    pub optional_dimensions: Vec<DimensionType>,
    /// Maximum age of any dimension before attestation is stale.
    pub max_dimension_age_secs: u64,
}

impl Default for ComplianceDimensionPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            required_dimensions: vec![
                DimensionType::NistAssessment,
                DimensionType::VulnerabilityScan,
                DimensionType::Sbom,
                DimensionType::SlsaProvenance,
                DimensionType::CisBenchmark,
            ],
            optional_dimensions: vec![
                DimensionType::CosignSignature,
                DimensionType::DisaStig,
                DimensionType::Soc2,
                DimensionType::PciDss,
                DimensionType::OwaspAsvs,
                DimensionType::Iso27001,
                DimensionType::InTotoAttestation,
                DimensionType::FrameworkSelfAttestation,
            ],
            max_dimension_age_secs: 86400, // 24 hours
        }
    }
}

/// Builder for constructing a ComplianceAttestation from individual sources.
#[derive(Default)]
pub struct AttestationBuilder {
    environment: String,
    artifact: String,
    policy_name: String,
    dimensions: Vec<ComplianceDimension>,
}

impl AttestationBuilder {
    pub fn new(environment: &str, artifact: &str, policy_name: &str) -> Self {
        Self {
            environment: environment.to_string(),
            artifact: artifact.to_string(),
            policy_name: policy_name.to_string(),
            dimensions: Vec::new(),
        }
    }

    /// Add a NIST assessment dimension.
    pub fn with_nist(mut self, result: &ComplianceResult, required: bool) -> Self {
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::NistAssessment,
            hash: result.compliance_hash.clone(),
            passed: result.assessment.all_satisfied(),
            summary: format!(
                "{}/{} controls satisfied",
                result.assessment.status_counts().0,
                result.assessment.results.len()
            ),
            assessed_at: result.performed_at,
            required,
        });
        self
    }

    /// Add a vulnerability scan dimension.
    pub fn with_vuln_scan(mut self, scan: &VulnerabilityScan, passed: bool, required: bool) -> Self {
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::VulnerabilityScan,
            hash: super::cve::compute_vuln_hash(scan),
            passed,
            summary: format!(
                "{} vulns ({} critical, {} high) via {}",
                scan.summary.total, scan.summary.critical, scan.summary.high, scan.scanner
            ),
            assessed_at: scan.scanned_at,
            required,
        });
        self
    }

    /// Add an SBOM dimension.
    pub fn with_sbom(mut self, sbom: &SbomAttestation, required: bool) -> Self {
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::Sbom,
            hash: super::sbom::compute_sbom_hash(sbom),
            passed: sbom.ntia_compliant,
            summary: format!(
                "{} components, {} deps, NTIA: {}",
                sbom.component_count,
                sbom.dependency_count,
                if sbom.ntia_compliant { "compliant" } else { "non-compliant" }
            ),
            assessed_at: sbom.generated_at,
            required,
        });
        self
    }

    /// Add a SLSA provenance dimension.
    pub fn with_slsa(mut self, provenance: &SlsaProvenance, min_level: &super::slsa::SlsaLevel, required: bool) -> Self {
        let passed = provenance.level >= *min_level;
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::SlsaProvenance,
            hash: super::slsa::compute_provenance_hash(provenance),
            passed,
            summary: format!(
                "{}, hermetic: {}, reproducible: {}",
                provenance.level, provenance.hermetic, provenance.reproducible
            ),
            assessed_at: provenance.built_at,
            required,
        });
        self
    }

    /// Add a cosign verification dimension.
    pub fn with_cosign(mut self, verification: &CosignVerification, required: bool) -> Self {
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::CosignSignature,
            hash: verification.signature_hash.clone(),
            passed: verification.verified,
            summary: format!(
                "Signed by: {}, verified: {}",
                verification.signer_identity, verification.verified
            ),
            assessed_at: verification.verified_at,
            required,
        });
        self
    }

    /// Add an in-toto attestation dimension.
    pub fn with_intoto(mut self, attestation: &InTotoAttestation, required: bool) -> Self {
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::InTotoAttestation,
            hash: attestation.attestation_hash.clone(),
            passed: true, // in-toto presence is the check
            summary: format!(
                "in-toto by {}, {} subjects",
                attestation.signer, attestation.subjects.len()
            ),
            assessed_at: attestation.signed_at,
            required,
        });
        self
    }

    /// Add a CIS benchmark dimension.
    pub fn with_cis(mut self, result: &CisBenchmarkResult, min_pass_rate: f64, required: bool) -> Self {
        let passed = result.summary.scored_pass_rate >= min_pass_rate;
        self.dimensions.push(ComplianceDimension {
            dimension_type: DimensionType::CisBenchmark,
            hash: super::cis::compute_cis_hash(result),
            passed,
            summary: format!(
                "{}: {}/{} scored pass ({:.0}%)",
                result.benchmark,
                result.summary.scored_pass,
                result.summary.scored_pass + result.summary.scored_fail,
                result.summary.scored_pass_rate * 100.0
            ),
            assessed_at: result.assessed_at,
            required,
        });
        self
    }

    /// Add any standard assessment dimension.
    pub fn with_standard(mut self, assessment: &StandardAssessment, required: bool) -> Self {
        let dim_type = match assessment.standard {
            StandardId::DisaStig => DimensionType::DisaStig,
            StandardId::Soc2 => DimensionType::Soc2,
            StandardId::PciDss => DimensionType::PciDss,
            StandardId::OwaspAsvs => DimensionType::OwaspAsvs,
            StandardId::Iso27001 => DimensionType::Iso27001,
            StandardId::FedRamp => DimensionType::FedRamp,
            StandardId::CsaStar => DimensionType::CsaStar,
            _ => DimensionType::NistAssessment,
        };
        self.dimensions.push(ComplianceDimension {
            dimension_type: dim_type,
            hash: super::standards::compute_standard_hash(assessment),
            passed: assessment.summary.fail == 0,
            summary: format!(
                "{}: {}/{} pass ({:.0}%)",
                assessment.standard,
                assessment.summary.pass,
                assessment.summary.total,
                assessment.summary.automated_pass_rate * 100.0
            ),
            assessed_at: assessment.assessed_at,
            required,
        });
        self
    }

    /// Build the final attestation, composing all dimension hashes.
    pub fn build(self) -> ComplianceAttestation {
        let all_passed = self.dimensions.iter().all(|d| !d.required || d.passed);

        // Sort dimension hashes deterministically by type name
        let mut sorted_dims = self.dimensions.clone();
        sorted_dims.sort_by(|a, b| {
            format!("{}", a.dimension_type).cmp(&format!("{}", b.dimension_type))
        });

        // Compose all dimension hashes
        let mut data = Vec::new();
        for dim in &sorted_dims {
            data.extend_from_slice(&dim.hash.0);
        }
        let compliance_hash = Blake3Hash::digest(&data);

        ComplianceAttestation {
            environment: self.environment,
            artifact: self.artifact,
            dimensions: self.dimensions,
            compliance_hash,
            computed_at: Utc::now(),
            policy_name: self.policy_name,
            all_passed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::cve::*;
    use crate::compliance::sbom::*;
    use crate::compliance::slsa::*;

    fn make_vuln_scan() -> VulnerabilityScan {
        VulnerabilityScan {
            scanner: VulnerabilityScanner::Trivy,
            scanner_hash: Blake3Hash::digest(b"trivy"),
            db_version: "2026-02-28".to_string(),
            db_hash: Blake3Hash::digest(b"nvd"),
            target: ScanTarget {
                target_type: ScanTargetType::OciImage,
                identifier: "test".to_string(),
            },
            target_hash: Blake3Hash::digest(b"img"),
            vulnerabilities: vec![],
            summary: VulnSummary::default(),
            scanned_at: Utc::now(),
        }
    }

    fn make_sbom() -> SbomAttestation {
        SbomAttestation {
            format: SbomFormat::CycloneDx,
            generator: SbomGenerator::Syft,
            generator_hash: Blake3Hash::digest(b"syft"),
            sbom_hash: Blake3Hash::digest(b"sbom"),
            subject: SbomSubject {
                subject_type: SbomSubjectType::OciImage,
                identifier: "test".to_string(),
                artifact_hash: Blake3Hash::digest(b"img"),
            },
            component_count: 42,
            dependency_count: 20,
            licenses: vec![],
            generated_at: Utc::now(),
            ntia_compliant: true,
        }
    }

    fn make_provenance() -> SlsaProvenance {
        SlsaProvenance {
            level: SlsaLevel::L3,
            build_type: BuildType::NixBuild,
            builder_id: "nix".to_string(),
            source_repo: "test".to_string(),
            source_commit: "abc".to_string(),
            source_ref: "main".to_string(),
            build_config: "flake.nix".to_string(),
            materials: vec![],
            subject: ProvenanceSubject {
                name: "test".to_string(),
                digest: Blake3Hash::digest(b"output"),
                artifact_type: ArtifactType::OciImage,
            },
            reproducible: true,
            hermetic: true,
            built_at: Utc::now(),
            triggered_by: "ci".to_string(),
            two_person_reviewed: false,
        }
    }

    #[test]
    fn builder_composes_dimensions() {
        let scan = make_vuln_scan();
        let sbom = make_sbom();
        let prov = make_provenance();

        let attestation = AttestationBuilder::new("production", "myapp-backend", "default")
            .with_vuln_scan(&scan, true, true)
            .with_sbom(&sbom, true)
            .with_slsa(&prov, &SlsaLevel::L2, true)
            .build();

        assert_eq!(attestation.dimensions.len(), 3);
        assert!(attestation.all_passed);
    }

    #[test]
    fn builder_fails_when_required_fails() {
        let scan = make_vuln_scan();

        let attestation = AttestationBuilder::new("production", "test", "default")
            .with_vuln_scan(&scan, false, true) // passed=false, required=true
            .build();

        assert!(!attestation.all_passed);
    }

    #[test]
    fn builder_passes_when_optional_fails() {
        let scan = make_vuln_scan();

        let attestation = AttestationBuilder::new("production", "test", "default")
            .with_vuln_scan(&scan, true, true)   // passed, required
            .with_vuln_scan(&scan, false, false)  // failed, optional
            .build();

        assert!(attestation.all_passed);
    }

    #[test]
    fn compliance_hash_deterministic() {
        let scan = make_vuln_scan();
        let sbom = make_sbom();

        let a1 = AttestationBuilder::new("prod", "test", "default")
            .with_vuln_scan(&scan, true, true)
            .with_sbom(&sbom, true)
            .build();

        let a2 = AttestationBuilder::new("prod", "test", "default")
            .with_vuln_scan(&scan, true, true)
            .with_sbom(&sbom, true)
            .build();

        assert_eq!(a1.compliance_hash, a2.compliance_hash);
    }

    #[test]
    fn dimension_type_display() {
        assert_eq!(DimensionType::VulnerabilityScan.to_string(), "CVE/Vulnerability Scan");
        assert_eq!(DimensionType::Sbom.to_string(), "SBOM");
        assert_eq!(DimensionType::SlsaProvenance.to_string(), "SLSA Provenance");
    }
}
