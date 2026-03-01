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
            domains: vec![ComplianceDomain::InfrastructureCompliance, ComplianceDomain::CisBenchmark],
            nist_families: vec!["AC".into(), "AU".into(), "CM".into(), "IA".into(), "SC".into(), "SI".into()],
            command_template: "inspec exec {profile} --reporter json --chef-license accept-silent".to_string(),
            parser: OutputParser::Inspec,
        },
        TestFramework {
            id: "opa".to_string(),
            name: "Open Policy Agent".to_string(),
            nix_attr: "open-policy-agent".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::KubernetesPolicy, ComplianceDomain::IacSecurity],
            nist_families: vec!["AC".into(), "CM".into(), "SC".into(), "SI".into()],
            command_template: "opa eval --data {policy_dir} --input {input} --format json 'data.main.deny'".to_string(),
            parser: OutputParser::Opa,
        },
        TestFramework {
            id: "conftest".to_string(),
            name: "Conftest".to_string(),
            nix_attr: "conftest".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::KubernetesPolicy, ComplianceDomain::IacSecurity],
            nist_families: vec!["CM".into(), "SC".into()],
            command_template: "conftest test {input} --policy {policy_dir} --output json".to_string(),
            parser: OutputParser::Opa,
        },
        TestFramework {
            id: "kube-bench".to_string(),
            name: "kube-bench".to_string(),
            nix_attr: "kube-bench".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::CisBenchmark, ComplianceDomain::KubernetesPolicy],
            nist_families: vec!["AC".into(), "AU".into(), "CM".into(), "IA".into(), "SC".into()],
            command_template: "kube-bench run --json".to_string(),
            parser: OutputParser::KubeBench,
        },
        TestFramework {
            id: "trivy".to_string(),
            name: "Trivy".to_string(),
            nix_attr: "trivy".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::VulnerabilityScanning, ComplianceDomain::ContainerSecurity, ComplianceDomain::IacSecurity],
            nist_families: vec!["RA".into(), "SI".into(), "SR".into()],
            command_template: "trivy {target_type} {target} --format json --severity HIGH,CRITICAL".to_string(),
            parser: OutputParser::Trivy,
        },
        TestFramework {
            id: "checkov".to_string(),
            name: "Checkov".to_string(),
            nix_attr: "checkov".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::IacSecurity, ComplianceDomain::KubernetesPolicy],
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
            domains: vec![ComplianceDomain::CisBenchmark, ComplianceDomain::InfrastructureCompliance],
            nist_families: vec!["AC".into(), "AU".into(), "CM".into(), "IA".into(), "SC".into(), "SI".into()],
            command_template: "lynis audit system --quick --no-colors".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "openscap".to_string(),
            name: "OpenSCAP".to_string(),
            nix_attr: "openscap-utils".to_string(),
            output_format: OutputFormat::Xml,
            domains: vec![ComplianceDomain::ScapCompliance, ComplianceDomain::CisBenchmark],
            nist_families: vec!["AC".into(), "AU".into(), "CM".into(), "IA".into(), "SC".into(), "SI".into(), "SR".into()],
            command_template: "oscap xccdf eval --profile {profile} --results-arf {output} {datastream}".to_string(),
            parser: OutputParser::OpenscapArf,
        },
        TestFramework {
            id: "grype".to_string(),
            name: "Grype".to_string(),
            nix_attr: "grype".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::VulnerabilityScanning, ComplianceDomain::ContainerSecurity],
            nist_families: vec!["RA".into(), "SI".into(), "SR".into()],
            command_template: "grype {target} -o json".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "syft".to_string(),
            name: "Syft".to_string(),
            nix_attr: "syft".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::SupplyChainSecurity, ComplianceDomain::ContainerSecurity],
            nist_families: vec!["CM".into(), "SR".into()],
            command_template: "syft {target} -o cyclonedx-json".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "osv-scanner".to_string(),
            name: "OSV-Scanner".to_string(),
            nix_attr: "osv-scanner".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::VulnerabilityScanning, ComplianceDomain::SupplyChainSecurity],
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
            command_template: "gitleaks detect --report-format json --report-path {output} --source {target}".to_string(),
            parser: OutputParser::GenericJson,
        },
        TestFramework {
            id: "cosign".to_string(),
            name: "Cosign (Sigstore)".to_string(),
            nix_attr: "cosign".to_string(),
            output_format: OutputFormat::Json,
            domains: vec![ComplianceDomain::SupplyChainSecurity, ComplianceDomain::ContainerSecurity],
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

        let store_path = String::from_utf8_lossy(&output2.stdout)
            .trim()
            .to_string();
        return crate::hash::blake3_file(&std::path::PathBuf::from(&store_path).join("bin").join(nix_attr)).await;
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    crate::hash::blake3_file(&std::path::PathBuf::from(&store_path).join("bin").join(nix_attr)).await
}

/// Get frameworks relevant to a specific compliance domain.
pub fn frameworks_for_domain(domain: &ComplianceDomain) -> Vec<&'static TestFramework> {
    // Use a leaked static for lifetime convenience
    let registry = Box::leak(Box::new(framework_registry()));
    registry
        .iter()
        .filter(|f| f.domains.iter().any(|d| std::mem::discriminant(d) == std::mem::discriminant(domain)))
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
            assert!(!fw.nist_families.is_empty(), "{} needs NIST families", fw.id);
        }
    }

    #[test]
    fn all_frameworks_have_nix_attr() {
        for fw in framework_registry() {
            assert!(!fw.nix_attr.is_empty(), "{} needs nix_attr", fw.id);
        }
    }
}
