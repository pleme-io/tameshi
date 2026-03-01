//! Additional compliance standards integration.
//!
//! Provides types and mappings for all major compliance frameworks beyond
//! NIST 800-53. Each standard is represented as a hashable control set
//! that can be assessed and included in the compliance chain.
//!
//! ## Supported Standards
//!
//! | Standard | Scope | Automatable Controls |
//! |----------|-------|---------------------|
//! | DISA STIG | DoD systems, containers, K8s | ~80% |
//! | FedRAMP | Federal cloud services | Maps to NIST 800-53 |
//! | SOC 2 Type II | SaaS trust services | ~40% |
//! | PCI DSS v4.0 | Payment card processing | ~60% |
//! | OWASP ASVS | Application security | ~70% |
//! | ISO 27001:2022 | Information security mgmt | ~30% |
//! | CSA STAR | Cloud security | ~50% |
//! | HIPAA | Health information | Maps to NIST |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A compliance standard with its control catalog.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceStandard {
    /// Standard identifier.
    pub id: StandardId,
    /// Version.
    pub version: String,
    /// Hash of the control catalog.
    pub catalog_hash: Blake3Hash,
    /// Number of controls in the catalog.
    pub total_controls: usize,
    /// Number of automatable controls.
    pub automatable_controls: usize,
    /// NIST 800-53 control crosswalk.
    pub nist_crosswalk: Vec<ControlCrosswalk>,
}

/// Supported compliance standard identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardId {
    Nist80053,
    DisaStig,
    FedRamp,
    Soc2,
    PciDss,
    OwaspAsvs,
    Iso27001,
    CsaStar,
    Hipaa,
    Cis,
    Slsa,
}

impl std::fmt::Display for StandardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StandardId::Nist80053 => write!(f, "NIST SP 800-53 Rev 5"),
            StandardId::DisaStig => write!(f, "DISA STIG"),
            StandardId::FedRamp => write!(f, "FedRAMP"),
            StandardId::Soc2 => write!(f, "SOC 2 Type II"),
            StandardId::PciDss => write!(f, "PCI DSS v4.0"),
            StandardId::OwaspAsvs => write!(f, "OWASP ASVS v4.0"),
            StandardId::Iso27001 => write!(f, "ISO 27001:2022"),
            StandardId::CsaStar => write!(f, "CSA STAR"),
            StandardId::Hipaa => write!(f, "HIPAA"),
            StandardId::Cis => write!(f, "CIS Benchmarks"),
            StandardId::Slsa => write!(f, "SLSA"),
        }
    }
}

/// Maps a control from one standard to another.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlCrosswalk {
    /// Source standard control ID.
    pub source_control: String,
    /// Source standard.
    pub source_standard: StandardId,
    /// Mapped NIST 800-53 control IDs.
    pub nist_controls: Vec<String>,
    /// Mapping confidence.
    pub confidence: MappingConfidence,
}

/// Confidence level of a control mapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MappingConfidence {
    /// Direct one-to-one mapping.
    Exact,
    /// Strong conceptual mapping.
    High,
    /// Partial or tangential mapping.
    Moderate,
    /// Weak or inferred mapping.
    Low,
}

/// Assessment result for any standard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StandardAssessment {
    /// Which standard was assessed.
    pub standard: StandardId,
    /// Version of the standard.
    pub version: String,
    /// Assessment tool and its hash.
    pub tool: String,
    pub tool_hash: Blake3Hash,
    /// Catalog hash.
    pub catalog_hash: Blake3Hash,
    /// Individual control results.
    pub controls: Vec<StandardControlResult>,
    /// Summary.
    pub summary: StandardSummary,
    /// When assessed.
    pub assessed_at: DateTime<Utc>,
    /// Environment/target.
    pub target: String,
}

/// Result of assessing a single control from any standard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StandardControlResult {
    /// Control ID (standard-specific).
    pub control_id: String,
    /// Control title.
    pub title: String,
    /// Status.
    pub status: StandardControlStatus,
    /// Evidence collected.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<String>,
    /// NIST 800-53 crosswalk.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub nist_controls: Vec<String>,
}

/// Status of a standard control assessment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StandardControlStatus {
    Pass,
    Fail,
    NotApplicable,
    Manual,
    NotAssessed,
}

/// Assessment summary.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StandardSummary {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub not_applicable: usize,
    pub manual: usize,
    pub not_assessed: usize,
    pub automated_pass_rate: f64,
}

impl StandardSummary {
    pub fn from_controls(controls: &[StandardControlResult]) -> Self {
        let mut s = StandardSummary::default();
        s.total = controls.len();
        for c in controls {
            match c.status {
                StandardControlStatus::Pass => s.pass += 1,
                StandardControlStatus::Fail => s.fail += 1,
                StandardControlStatus::NotApplicable => s.not_applicable += 1,
                StandardControlStatus::Manual => s.manual += 1,
                StandardControlStatus::NotAssessed => s.not_assessed += 1,
            }
        }
        let automated = s.pass + s.fail;
        if automated > 0 {
            s.automated_pass_rate = s.pass as f64 / automated as f64;
        }
        s
    }
}

/// Compute assessment hash for any standard.
pub fn compute_standard_hash(assessment: &StandardAssessment) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&assessment.tool_hash.0);
    data.extend_from_slice(&assessment.catalog_hash.0);

    let controls_canonical = serde_json::to_vec(&assessment.controls).unwrap_or_default();
    let controls_hash = Blake3Hash::digest(&controls_canonical);
    data.extend_from_slice(&controls_hash.0);

    Blake3Hash::digest(&data)
}

// --- DISA STIG ---

/// DISA STIG categories relevant to our artifact types.
pub fn stig_kubernetes_controls() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("V-242376", "K8s API server must use TLS 1.2+", vec!["SC-8", "SC-23"]),
        ("V-242377", "K8s etcd must use TLS for peer communication", vec!["SC-8"]),
        ("V-242378", "K8s kubelet must use TLS", vec!["SC-8"]),
        ("V-242381", "K8s must enforce RBAC", vec!["AC-3", "AC-6"]),
        ("V-242382", "K8s must use audit logging", vec!["AU-2", "AU-3", "AU-12"]),
        ("V-242383", "K8s must restrict pod security", vec!["CM-7", "SC-7"]),
        ("V-242386", "K8s must use network policies", vec!["SC-7", "AC-4"]),
        ("V-242390", "K8s secrets must be encrypted at rest", vec!["SC-28"]),
        ("V-242391", "K8s must verify image signatures", vec!["SI-7", "SR-11"]),
        ("V-242395", "K8s must restrict service account tokens", vec!["AC-6", "IA-5"]),
    ]
}

/// DISA STIG categories for container images.
pub fn stig_container_controls() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("V-235800", "Container images must be from trusted registries", vec!["CM-5", "SR-4"]),
        ("V-235801", "Container images must be scanned for vulnerabilities", vec!["RA-5", "SI-2"]),
        ("V-235802", "Containers must not run as root", vec!["AC-6", "CM-7"]),
        ("V-235803", "Containers must use read-only root filesystem", vec!["CM-7", "SC-28"]),
        ("V-235804", "Container images must not contain secrets", vec!["IA-5", "SC-28"]),
        ("V-235805", "Containers must have resource limits", vec!["SC-6"]),
        ("V-235806", "Container images must be signed", vec!["SI-7", "SR-11"]),
    ]
}

// --- SOC 2 ---

/// SOC 2 Trust Services Criteria automatable through our system.
pub fn soc2_automatable_criteria() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("CC6.1", "Logical access security controls", vec!["AC-2", "AC-3", "AC-6"]),
        ("CC6.2", "Access provisioning and revocation", vec!["AC-2"]),
        ("CC6.3", "Role-based access enforcement", vec!["AC-3", "AC-6"]),
        ("CC6.6", "Boundary protection and filtering", vec!["SC-7"]),
        ("CC6.7", "Data transmission encryption", vec!["SC-8"]),
        ("CC6.8", "Malicious software prevention", vec!["SI-3"]),
        ("CC7.1", "Monitoring for security events", vec!["SI-4", "AU-6"]),
        ("CC7.2", "Anomaly detection and response", vec!["SI-4", "IR-4"]),
        ("CC8.1", "Change management controls", vec!["CM-3", "CM-4"]),
        ("A1.2", "Recovery and availability controls", vec!["CP-2", "CP-10"]),
    ]
}

// --- PCI DSS ---

/// PCI DSS v4.0 requirements automatable through infrastructure attestation.
pub fn pci_dss_automatable() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("1.2.1", "Network segmentation controls", vec!["SC-7", "AC-4"]),
        ("2.2.1", "System hardening standards", vec!["CM-2", "CM-6"]),
        ("3.5.1", "Encryption of stored cardholder data", vec!["SC-28"]),
        ("4.2.1", "Strong cryptography for transmission", vec!["SC-8", "SC-13"]),
        ("5.2.1", "Anti-malware mechanisms", vec!["SI-3"]),
        ("6.3.1", "Vulnerability management process", vec!["RA-5", "SI-2"]),
        ("6.5.1", "Secure development practices", vec!["SA-11", "SA-15"]),
        ("7.2.1", "Access control enforcement", vec!["AC-3", "AC-6"]),
        ("8.3.1", "Authentication factor management", vec!["IA-2", "IA-5"]),
        ("10.2.1", "Audit logging mechanisms", vec!["AU-2", "AU-3", "AU-12"]),
        ("11.3.1", "Vulnerability scanning", vec!["RA-5"]),
    ]
}

// --- OWASP ASVS ---

/// OWASP ASVS v4.0 verification requirements (levels 1-3).
pub fn owasp_asvs_automatable() -> Vec<(&'static str, &'static str, u8, Vec<&'static str>)> {
    vec![
        ("V1.2.1", "Secure application architecture", 1, vec!["SA-8", "SA-17"]),
        ("V2.1.1", "Password requirements", 1, vec!["IA-5"]),
        ("V3.1.1", "Session management controls", 1, vec!["AC-12"]),
        ("V4.1.1", "Access control enforcement", 1, vec!["AC-3"]),
        ("V5.1.1", "Input validation", 1, vec!["SI-10"]),
        ("V6.1.1", "Cryptographic implementation", 2, vec!["SC-13"]),
        ("V7.1.1", "Error handling and logging", 1, vec!["AU-2", "SI-11"]),
        ("V8.1.1", "Data protection at rest", 2, vec!["SC-28"]),
        ("V9.1.1", "Communications security (TLS)", 1, vec!["SC-8"]),
        ("V10.1.1", "Code integrity verification", 2, vec!["SI-7"]),
        ("V12.1.1", "File upload validation", 2, vec!["SI-10"]),
        ("V13.1.1", "API security controls", 1, vec!["AC-3", "SC-8"]),
        ("V14.1.1", "Build and deploy security", 2, vec!["CM-3", "SA-10"]),
    ]
}

// --- ISO 27001 ---

/// ISO 27001:2022 Annex A controls automatable through infrastructure.
pub fn iso27001_automatable() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("A.5.15", "Access control policy enforcement", vec!["AC-2", "AC-3"]),
        ("A.5.23", "Information security for cloud services", vec!["SC-7", "SC-8"]),
        ("A.8.1", "User endpoint device management", vec!["CM-2"]),
        ("A.8.5", "Secure authentication", vec!["IA-2", "IA-5"]),
        ("A.8.9", "Configuration management", vec!["CM-2", "CM-6"]),
        ("A.8.12", "Data leakage prevention", vec!["SC-7", "AC-4"]),
        ("A.8.15", "Logging and monitoring", vec!["AU-2", "AU-6"]),
        ("A.8.20", "Network security controls", vec!["SC-7"]),
        ("A.8.24", "Cryptographic controls", vec!["SC-12", "SC-13"]),
        ("A.8.25", "Secure development lifecycle", vec!["SA-10", "SA-15"]),
        ("A.8.28", "Secure coding practices", vec!["SA-11"]),
        ("A.8.31", "Separation of environments", vec!["CM-4", "SC-7"]),
    ]
}

/// Compute a unified compliance hash across multiple standards.
pub fn compute_multi_standard_hash(assessments: &[StandardAssessment]) -> Blake3Hash {
    let mut hashes: Vec<Blake3Hash> = assessments.iter().map(|a| compute_standard_hash(a)).collect();
    hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));

    let mut data = Vec::new();
    for h in &hashes {
        data.extend_from_slice(&h.0);
    }
    Blake3Hash::digest(&data)
}

/// Get all standards relevant to a given artifact type.
pub fn standards_for_artifact(artifact: &ArtifactCategory) -> Vec<StandardId> {
    match artifact {
        ArtifactCategory::ContainerImage => vec![
            StandardId::Nist80053,
            StandardId::DisaStig,
            StandardId::Cis,
            StandardId::Slsa,
            StandardId::Soc2,
        ],
        ArtifactCategory::KubernetesResource => vec![
            StandardId::Nist80053,
            StandardId::DisaStig,
            StandardId::Cis,
            StandardId::Soc2,
            StandardId::PciDss,
        ],
        ArtifactCategory::HelmChart => vec![
            StandardId::Nist80053,
            StandardId::Cis,
            StandardId::Slsa,
        ],
        ArtifactCategory::NixDerivation => vec![
            StandardId::Nist80053,
            StandardId::Slsa,
        ],
        ArtifactCategory::InfrastructureCode => vec![
            StandardId::Nist80053,
            StandardId::Cis,
            StandardId::Soc2,
            StandardId::PciDss,
        ],
        ArtifactCategory::Application => vec![
            StandardId::Nist80053,
            StandardId::OwaspAsvs,
            StandardId::PciDss,
            StandardId::Soc2,
            StandardId::Iso27001,
        ],
        ArtifactCategory::SupplyChain => vec![
            StandardId::Nist80053,
            StandardId::Slsa,
            StandardId::FedRamp,
        ],
    }
}

/// Categories of artifacts for standard mapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    ContainerImage,
    KubernetesResource,
    HelmChart,
    NixDerivation,
    InfrastructureCode,
    Application,
    SupplyChain,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_display() {
        assert_eq!(StandardId::Nist80053.to_string(), "NIST SP 800-53 Rev 5");
        assert_eq!(StandardId::PciDss.to_string(), "PCI DSS v4.0");
    }

    #[test]
    fn container_has_multiple_standards() {
        let standards = standards_for_artifact(&ArtifactCategory::ContainerImage);
        assert!(standards.contains(&StandardId::Nist80053));
        assert!(standards.contains(&StandardId::DisaStig));
        assert!(standards.contains(&StandardId::Cis));
        assert!(standards.contains(&StandardId::Slsa));
    }

    #[test]
    fn application_has_owasp() {
        let standards = standards_for_artifact(&ArtifactCategory::Application);
        assert!(standards.contains(&StandardId::OwaspAsvs));
    }

    #[test]
    fn summary_from_controls() {
        let controls = vec![
            StandardControlResult {
                control_id: "CC6.1".to_string(),
                title: "Test".to_string(),
                status: StandardControlStatus::Pass,
                evidence: vec![],
                nist_controls: vec![],
            },
            StandardControlResult {
                control_id: "CC6.2".to_string(),
                title: "Test".to_string(),
                status: StandardControlStatus::Fail,
                evidence: vec![],
                nist_controls: vec![],
            },
            StandardControlResult {
                control_id: "CC6.3".to_string(),
                title: "Test".to_string(),
                status: StandardControlStatus::Manual,
                evidence: vec![],
                nist_controls: vec![],
            },
        ];
        let summary = StandardSummary::from_controls(&controls);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.pass, 1);
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.manual, 1);
        assert_eq!(summary.automated_pass_rate, 0.5);
    }

    #[test]
    fn stig_k8s_controls_non_empty() {
        let controls = stig_kubernetes_controls();
        assert!(!controls.is_empty());
        // Each control should have NIST mappings
        for (_, _, nist) in &controls {
            assert!(!nist.is_empty());
        }
    }

    #[test]
    fn standard_hash_deterministic() {
        let assessment = StandardAssessment {
            standard: StandardId::Soc2,
            version: "2023".to_string(),
            tool: "kensa".to_string(),
            tool_hash: Blake3Hash::digest(b"kensa-binary"),
            catalog_hash: Blake3Hash::digest(b"soc2-catalog"),
            controls: vec![StandardControlResult {
                control_id: "CC6.1".to_string(),
                title: "Test".to_string(),
                status: StandardControlStatus::Pass,
                evidence: vec![],
                nist_controls: vec!["AC-3".to_string()],
            }],
            summary: StandardSummary::default(),
            assessed_at: Utc::now(),
            target: "myapp-staging".to_string(),
        };
        let h1 = compute_standard_hash(&assessment);
        let h2 = compute_standard_hash(&assessment);
        assert_eq!(h1, h2);
    }
}
