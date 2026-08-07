//! Testing framework registry and Nix packaging integration.
//!
//! Each testing framework must be:
//! 1. Available in nixpkgs (for deterministic packaging)
//! 2. Hashable via Nix store closure (framework binary attestation)
//! 3. Produces machine-parseable output (JSON/XML)
//! 4. Maps to one or more compliance standards (NIST/OSCAL)
//!
//! ## Supported Frameworks
//!
//! | Framework | nixpkgs attr | Output Format | Domain |
//! |-----------|-------------|---------------|--------|
//! | InSpec | `inspec` | JSON | General compliance |
//! | OPA/Gatekeeper | `open-policy-agent` | JSON | K8s policy |
//! | kube-bench | `kube-bench` | JSON | CIS K8s benchmark |
//! | Trivy | `trivy` | JSON | Vulnerability scanning |
//! | Checkov | `checkov` | JSON | IaC security |
//! | kube-linter | `kube-linter` | JSON | K8s manifest linting |
//! | Conftest | `conftest` | JSON | Rego policy testing |
//! | Prowler | `prowler` | JSON | Cloud security |
//! | Lynis | `lynis` | Text/JSON | System hardening |
//! | OpenSCAP | `openscap-utils` | XML/ARF | SCAP/XCCDF |
//!
//! All frameworks are packaged via Nix, so their store paths are hashable.
//! The hash of the framework binary is included in the compliance hash chain,
//! ensuring you know exactly which version of the testing tool produced the results.

use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A registered testing framework.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestFramework {
    /// Framework identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// nixpkgs attribute for Nix packaging.
    pub nix_attr: String,
    /// Output format produced by the framework.
    pub output_format: OutputFormat,
    /// Compliance domains this framework covers.
    pub domains: Vec<ComplianceDomain>,
    /// NIST 800-53 control families this framework can test.
    pub nist_families: Vec<String>,
    /// Command to execute the framework (with placeholders).
    pub command_template: String,
    /// How to parse the output.
    pub parser: OutputParser,
}

/// Output formats supported by testing frameworks.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Xml,
    Sarif,
    JUnit,
    Text,
}

/// Compliance domains.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceDomain {
    /// General infrastructure compliance (InSpec, Lynis)
    InfrastructureCompliance,
    /// Kubernetes policy enforcement (OPA, kube-linter)
    KubernetesPolicy,
    /// CIS benchmarks (kube-bench, Lynis)
    CisBenchmark,
    /// Vulnerability scanning (Trivy)
    VulnerabilityScanning,
    /// Infrastructure-as-Code security (Checkov, Conftest)
    IacSecurity,
    /// Cloud security posture (Prowler)
    CloudSecurity,
    /// SCAP/XCCDF compliance (OpenSCAP)
    ScapCompliance,
    /// Container image security (Trivy, Grype)
    ContainerSecurity,
    /// Network policy validation
    NetworkPolicy,
    /// Supply chain security
    SupplyChainSecurity,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "JSON"),
            OutputFormat::Xml => write!(f, "XML"),
            OutputFormat::Sarif => write!(f, "SARIF"),
            OutputFormat::JUnit => write!(f, "JUnit"),
            OutputFormat::Text => write!(f, "Text"),
        }
    }
}

impl std::fmt::Display for ComplianceDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceDomain::InfrastructureCompliance => write!(f, "Infrastructure Compliance"),
            ComplianceDomain::KubernetesPolicy => write!(f, "Kubernetes Policy"),
            ComplianceDomain::CisBenchmark => write!(f, "CIS Benchmark"),
            ComplianceDomain::VulnerabilityScanning => write!(f, "Vulnerability Scanning"),
            ComplianceDomain::IacSecurity => write!(f, "IaC Security"),
            ComplianceDomain::CloudSecurity => write!(f, "Cloud Security"),
            ComplianceDomain::ScapCompliance => write!(f, "SCAP Compliance"),
            ComplianceDomain::ContainerSecurity => write!(f, "Container Security"),
            ComplianceDomain::NetworkPolicy => write!(f, "Network Policy"),
            ComplianceDomain::SupplyChainSecurity => write!(f, "Supply Chain Security"),
        }
    }
}

impl std::fmt::Display for OutputParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputParser::Inspec => write!(f, "InSpec"),
            OutputParser::Opa => write!(f, "OPA"),
            OutputParser::KubeBench => write!(f, "kube-bench"),
            OutputParser::Trivy => write!(f, "Trivy"),
            OutputParser::Checkov => write!(f, "Checkov"),
            OutputParser::Sarif => write!(f, "SARIF"),
            OutputParser::Junit => write!(f, "JUnit"),
            OutputParser::GenericJson => write!(f, "Generic JSON"),
            OutputParser::OpenscapArf => write!(f, "OpenSCAP ARF"),
        }
    }
}

/// How to parse framework output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputParser {
    /// InSpec JSON reporter format
    Inspec,
    /// OPA/Conftest JSON output
    Opa,
    /// kube-bench JSON output
    KubeBench,
    /// Trivy JSON output
    Trivy,
    /// Checkov JSON output
    Checkov,
    /// SARIF (Static Analysis Results Interchange Format)
    Sarif,
    /// JUnit XML
    Junit,
    /// Generic JSON with pass/fail fields
    GenericJson,
    /// OpenSCAP ARF (Asset Reporting Format)
    OpenscapArf,
}

/// Build the registry of all known testing frameworks.
pub fn framework_registry() -> Vec<TestFramework> {
    vec![
        TestFramework {
            id: "inspec".to_string(),
            name: "Chef InSpec".to_string(),
            nix_attr: "inspec".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::InfrastructureCompliance,
                ComplianceDomain::CisBenchmark,
            ],
            nist_families: vec![
                "AC".into(),
                "AU".into(),
                "CM".into(),
                "IA".into(),
                "SC".into(),
                "SI".into(),
            ],
            command_template: "inspec exec {profile} --reporter json --chef-license accept-silent"
                .to_string(),
            parser: OutputParser::Inspec,
        },
        TestFramework {
            id: "opa".to_string(),
            name: "Open Policy Agent".to_string(),
            nix_attr: "open-policy-agent".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::KubernetesPolicy,
                ComplianceDomain::IacSecurity,
            ],
            nist_families: vec!["AC".into(), "CM".into(), "SC".into(), "SI".into()],
            command_template:
                "opa eval --data {policy_dir} --input {input} --format json 'data.main.deny'"
                    .to_string(),
            parser: OutputParser::Opa,
        },
        TestFramework {
            id: "conftest".to_string(),
            name: "Conftest".to_string(),
            nix_attr: "conftest".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::KubernetesPolicy,
                ComplianceDomain::IacSecurity,
            ],
            nist_families: vec!["CM".into(), "SC".into()],
            command_template: "conftest test {input} --policy {policy_dir} --output json"
                .to_string(),
            parser: OutputParser::Opa,
        },
        TestFramework {
            id: "kube-bench".to_string(),
            name: "kube-bench".to_string(),
            nix_attr: "kube-bench".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::CisBenchmark,
                ComplianceDomain::KubernetesPolicy,
            ],
            nist_families: vec![
                "AC".into(),
                "AU".into(),
                "CM".into(),
                "IA".into(),
                "SC".into(),
            ],
            command_template: "kube-bench run --json".to_string(),
            parser: OutputParser::KubeBench,
        },
        TestFramework {
            id: "trivy".to_string(),
            name: "Trivy".to_string(),
            nix_attr: "trivy".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::VulnerabilityScanning,
                ComplianceDomain::ContainerSecurity,
                ComplianceDomain::IacSecurity,
            ],
            nist_families: vec!["RA".into(), "SI".into(), "SR".into()],
            command_template: "trivy {target_type} {target} --format json --severity HIGH,CRITICAL"
                .to_string(),
            parser: OutputParser::Trivy,
        },
        TestFramework {
            id: "checkov".to_string(),
            name: "Checkov".to_string(),
            nix_attr: "checkov".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::IacSecurity,
                ComplianceDomain::KubernetesPolicy,
            ],
            nist_families: vec!["CM".into(), "SC".into(), "SI".into()],
            command_template: "checkov -d {directory} --output json --compact".to_string(),
            parser: OutputParser::Checkov,
        },
        TestFramework {
            id: "kube-linter".to_string(),
            name: "kube-linter".to_string(),
            nix_attr: "kube-linter".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::KubernetesPolicy],
            nist_families: vec!["CM".into(), "SC".into()],
            command_template: "kube-linter lint {path} --format json".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "lynis".to_string(),
            name: "Lynis".to_string(),
            nix_attr: "lynis".to_string(),
            output_format: OutputFormat::Text,
            domains: vec![
                ComplianceDomain::CisBenchmark,
                ComplianceDomain::InfrastructureCompliance,
            ],
            nist_families: vec![
                "AC".into(),
                "AU".into(),
                "CM".into(),
                "IA".into(),
                "SC".into(),
                "SI".into(),
            ],
            command_template: "lynis audit system --quick --no-colors".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "openscap".to_string(),
            name: "OpenSCAP".to_string(),
            nix_attr: "openscap-utils".to_string(),
            output_format: OutputFormat::Xml,
            domains: vec![
                ComplianceDomain::ScapCompliance,
                ComplianceDomain::CisBenchmark,
            ],
            nist_families: vec![
                "AC".into(),
                "AU".into(),
                "CM".into(),
                "IA".into(),
                "SC".into(),
                "SI".into(),
                "SR".into(),
            ],
            command_template:
                "oscap xccdf eval --profile {profile} --results-arf {output} {datastream}"
                    .to_string(),
            parser: OutputParser::OpenscapArf,
        },
        TestFramework {
            id: "grype".to_string(),
            name: "Grype".to_string(),
            nix_attr: "grype".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::VulnerabilityScanning,
                ComplianceDomain::ContainerSecurity,
            ],
            nist_families: vec!["RA".into(), "SI".into(), "SR".into()],
            command_template: "grype {target} -o json".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "syft".to_string(),
            name: "Syft".to_string(),
            nix_attr: "syft".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::SupplyChainSecurity,
                ComplianceDomain::ContainerSecurity,
            ],
            nist_families: vec!["CM".into(), "SR".into()],
            command_template: "syft {target} -o cyclonedx-json".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "osv-scanner".to_string(),
            name: "OSV-Scanner".to_string(),
            nix_attr: "osv-scanner".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::VulnerabilityScanning,
                ComplianceDomain::SupplyChainSecurity,
            ],
            nist_families: vec!["RA".into(), "SI".into(), "SR".into()],
            command_template: "osv-scanner --format json {target}".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "semgrep".to_string(),
            name: "Semgrep".to_string(),
            nix_attr: "semgrep".to_string(),
            output_format: OutputFormat::Sarif,
            domains: vec![ComplianceDomain::IacSecurity],
            nist_families: vec!["SA".into(), "SI".into()],
            command_template: "semgrep scan --config auto --sarif {target}".to_string(),
            parser: OutputParser::Sarif,
        },
        TestFramework {
            id: "gitleaks".to_string(),
            name: "Gitleaks".to_string(),
            nix_attr: "gitleaks".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::SupplyChainSecurity],
            nist_families: vec!["IA".into(), "SC".into()],
            command_template:
                "gitleaks detect --report-format json --report-path {output} --source {target}"
                    .to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "cosign".to_string(),
            name: "Cosign (Sigstore)".to_string(),
            nix_attr: "cosign".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![
                ComplianceDomain::SupplyChainSecurity,
                ComplianceDomain::ContainerSecurity,
            ],
            nist_families: vec!["SI".into(), "SC".into(), "SR".into()],
            command_template: "cosign verify --output json {image}".to_string(),
            parser: OutputParser::GenericJson,
        },
    ]
}

/// Hash a testing framework binary via its Nix store path.
///
/// The framework must be installed via Nix so we can hash its store closure.
/// This hash is included in the compliance hash chain to attest the
/// verification tool itself.
pub async fn hash_framework_binary(nix_attr: &str) -> crate::error::Result<Blake3Hash> {
    // Get the Nix store path for the framework
    let output = tokio::process::Command::new("nix")
        .args(["eval", "--raw", &format!("nixpkgs#{}", nix_attr)])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        // Try nix-build as fallback
        let output2 = tokio::process::Command::new("nix-build")
            .args(["<nixpkgs>", "-A", nix_attr, "--no-out-link"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await?;

        if !output2.status.success() {
            return Err(crate::error::TameshiError::CollectorError {
                layer: "framework".to_string(),
                message: format!("could not resolve Nix path for {}", nix_attr),
            });
        }

        let store_path = String::from_utf8_lossy(&output2.stdout).trim().to_string();
        return crate::hash::blake3_file_async(
            &std::path::PathBuf::from(&store_path)
                .join("bin")
                .join(nix_attr),
        )
        .await;
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    crate::hash::blake3_file_async(
        &std::path::PathBuf::from(&store_path)
            .join("bin")
            .join(nix_attr),
    )
    .await
}

/// Get frameworks relevant to a specific compliance domain.
pub fn frameworks_for_domain(domain: &ComplianceDomain) -> Vec<&'static TestFramework> {
    // Use a leaked static for lifetime convenience
    let registry = Box::leak(Box::new(framework_registry()));
    registry
        .iter()
        .filter(|f| {
            f.domains
                .iter()
                .any(|d| std::mem::discriminant(d) == std::mem::discriminant(domain))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_non_empty() {
        let registry = framework_registry();
        assert!(!registry.is_empty());
    }

    #[test]
    fn all_frameworks_have_nist_families() {
        for fw in framework_registry() {
            assert!(
                !fw.nist_families.is_empty(),
                "{} needs NIST families",
                fw.id
            );
        }
    }

    #[test]
    fn all_frameworks_have_nix_attr() {
        for fw in framework_registry() {
            assert!(!fw.nix_attr.is_empty(), "{} needs nix_attr", fw.id);
        }
    }

    #[test]
    fn all_frameworks_have_domains() {
        for fw in framework_registry() {
            assert!(
                !fw.domains.is_empty(),
                "{} needs at least one domain",
                fw.id
            );
        }
    }

    #[test]
    fn all_frameworks_have_command_template() {
        for fw in framework_registry() {
            assert!(
                !fw.command_template.is_empty(),
                "{} needs a command template",
                fw.id
            );
        }
    }

    #[test]
    fn all_frameworks_unique_ids() {
        let registry = framework_registry();
        let mut ids: Vec<&str> = registry.iter().map(|f| f.id.as_str()).collect();
        let len_before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "framework IDs must be unique");
    }

    #[test]
    fn framework_serde_roundtrip() {
        let registry = framework_registry();
        let json = serde_json::to_string(&registry).unwrap();
        let deserialized: Vec<TestFramework> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), registry.len());
        assert_eq!(deserialized[0].id, registry[0].id);
    }

    #[test]
    fn output_format_display() {
        assert_eq!(OutputFormat::Json.to_string(), "JSON");
        assert_eq!(OutputFormat::Xml.to_string(), "XML");
        assert_eq!(OutputFormat::Sarif.to_string(), "SARIF");
        assert_eq!(OutputFormat::JUnit.to_string(), "JUnit");
        assert_eq!(OutputFormat::Text.to_string(), "Text");
    }

    #[test]
    fn compliance_domain_display() {
        assert_eq!(
            ComplianceDomain::InfrastructureCompliance.to_string(),
            "Infrastructure Compliance"
        );
        assert_eq!(
            ComplianceDomain::KubernetesPolicy.to_string(),
            "Kubernetes Policy"
        );
        assert_eq!(
            ComplianceDomain::SupplyChainSecurity.to_string(),
            "Supply Chain Security"
        );
    }

    #[test]
    fn output_parser_display() {
        assert_eq!(OutputParser::Inspec.to_string(), "InSpec");
        assert_eq!(OutputParser::Opa.to_string(), "OPA");
        assert_eq!(OutputParser::KubeBench.to_string(), "kube-bench");
        assert_eq!(OutputParser::Trivy.to_string(), "Trivy");
        assert_eq!(OutputParser::Checkov.to_string(), "Checkov");
        assert_eq!(OutputParser::Sarif.to_string(), "SARIF");
        assert_eq!(OutputParser::Junit.to_string(), "JUnit");
        assert_eq!(OutputParser::GenericJson.to_string(), "Generic JSON");
        assert_eq!(OutputParser::OpenscapArf.to_string(), "OpenSCAP ARF");
    }

    #[test]
    fn output_format_serde_roundtrip() {
        let formats = vec![
            OutputFormat::Json,
            OutputFormat::Xml,
            OutputFormat::Sarif,
            OutputFormat::JUnit,
            OutputFormat::Text,
        ];
        for fmt in formats {
            let json = serde_json::to_string(&fmt).unwrap();
            let deserialized: OutputFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.to_string(), fmt.to_string());
        }
    }

    #[test]
    fn compliance_domain_serde_roundtrip() {
        let domains = vec![
            ComplianceDomain::InfrastructureCompliance,
            ComplianceDomain::KubernetesPolicy,
            ComplianceDomain::CisBenchmark,
            ComplianceDomain::VulnerabilityScanning,
            ComplianceDomain::IacSecurity,
            ComplianceDomain::CloudSecurity,
            ComplianceDomain::ScapCompliance,
            ComplianceDomain::ContainerSecurity,
            ComplianceDomain::NetworkPolicy,
            ComplianceDomain::SupplyChainSecurity,
        ];
        for domain in domains {
            let json = serde_json::to_string(&domain).unwrap();
            let deserialized: ComplianceDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.to_string(), domain.to_string());
        }
    }

    #[test]
    fn known_framework_ids_present() {
        let registry = framework_registry();
        let ids: Vec<&str> = registry.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"inspec"));
        assert!(ids.contains(&"trivy"));
        assert!(ids.contains(&"opa"));
        assert!(ids.contains(&"kube-bench"));
        assert!(ids.contains(&"cosign"));
    }
}
