//! SBOM (Software Bill of Materials) integration.
//!
//! SBOMs provide a complete inventory of components in any artifact (OCI image,
//! Nix closure, application binary). The SBOM itself is hashed as part of the
//! compliance chain, providing provenance and component transparency.
//!
//! ## Supported Formats
//!
//! | Format | Standard | Use Case |
//! |--------|----------|----------|
//! | SPDX | ISO/IEC 5962:2021 | License compliance, component inventory |
//! | CycloneDX | OWASP | Security-focused, VEX, dependency graph |
//!
//! ## Supported Generators
//!
//! | Tool | nixpkgs attr | Target |
//! |------|-------------|--------|
//! | Syft | `syft` | OCI images, filesystems, archives |
//! | nix-sbom | N/A (Nix native) | Nix closures |
//! | cyclonedx-cli | `cyclonedx-cli` | Convert/merge SBOMs |
//! | Trivy | `trivy` | OCI images (SBOM mode) |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// An SBOM document with attestation metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SbomAttestation {
    /// SBOM format.
    pub format: SbomFormat,
    /// Tool that generated the SBOM.
    pub generator: SbomGenerator,
    /// Hash of the generator binary.
    pub generator_hash: Blake3Hash,
    /// The SBOM content hash.
    pub sbom_hash: Blake3Hash,
    /// What the SBOM describes.
    pub subject: SbomSubject,
    /// Number of components in the SBOM.
    pub component_count: usize,
    /// Number of dependencies.
    pub dependency_count: usize,
    /// License summary.
    pub licenses: Vec<LicenseSummary>,
    /// When the SBOM was generated.
    pub generated_at: DateTime<Utc>,
    /// NTIA minimum elements compliance.
    pub ntia_compliant: bool,
}

/// SBOM formats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    /// SPDX (ISO/IEC 5962:2021).
    Spdx,
    /// CycloneDX (OWASP).
    CycloneDx,
}

/// SBOM generator tools.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomGenerator {
    Syft,
    NixSbom,
    CycloneDxCli,
    Trivy,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomFormat::Spdx => write!(f, "SPDX"),
            SbomFormat::CycloneDx => write!(f, "CycloneDX"),
        }
    }
}

impl std::fmt::Display for SbomGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomGenerator::Syft => write!(f, "Syft"),
            SbomGenerator::NixSbom => write!(f, "nix-sbom"),
            SbomGenerator::CycloneDxCli => write!(f, "cyclonedx-cli"),
            SbomGenerator::Trivy => write!(f, "Trivy"),
        }
    }
}

impl std::fmt::Display for SbomSubjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomSubjectType::OciImage => write!(f, "OCI Image"),
            SbomSubjectType::NixClosure => write!(f, "Nix Closure"),
            SbomSubjectType::NixDerivation => write!(f, "Nix Derivation"),
            SbomSubjectType::HelmChart => write!(f, "Helm Chart"),
            SbomSubjectType::RustCrate => write!(f, "Rust Crate"),
            SbomSubjectType::NpmPackage => write!(f, "NPM Package"),
            SbomSubjectType::Application => write!(f, "Application"),
        }
    }
}

impl SbomGenerator {
    pub fn nix_attr(&self) -> &str {
        match self {
            SbomGenerator::Syft => "syft",
            SbomGenerator::NixSbom => "nix", // Built into Nix
            SbomGenerator::CycloneDxCli => "cyclonedx-cli",
            SbomGenerator::Trivy => "trivy",
        }
    }
}

/// What the SBOM describes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SbomSubject {
    /// Subject type.
    pub subject_type: SbomSubjectType,
    /// Identifier (image ref, store path, etc.).
    pub identifier: String,
    /// Hash of the subject artifact.
    pub artifact_hash: Blake3Hash,
}

/// Types of SBOM subjects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SbomSubjectType {
    OciImage,
    NixClosure,
    NixDerivation,
    HelmChart,
    RustCrate,
    NpmPackage,
    Application,
}

/// License summary entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseSummary {
    /// SPDX license identifier.
    pub spdx_id: String,
    /// Number of components with this license.
    pub count: usize,
}

/// NTIA Minimum Elements for an SBOM.
///
/// Per Executive Order 14028 and NTIA guidelines, a compliant SBOM must contain:
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NtiaCompliance {
    /// Supplier name present for all components.
    pub has_supplier: bool,
    /// Component name present for all components.
    pub has_component_name: bool,
    /// Component version present for all components.
    pub has_version: bool,
    /// Unique identifiers (PURL, CPE) present.
    pub has_unique_id: bool,
    /// Dependency relationships documented.
    pub has_dependencies: bool,
    /// Author of SBOM identified.
    pub has_author: bool,
    /// Timestamp present.
    pub has_timestamp: bool,
}

impl NtiaCompliance {
    /// Whether all minimum elements are satisfied.
    pub fn is_compliant(&self) -> bool {
        self.has_supplier
            && self.has_component_name
            && self.has_version
            && self.has_unique_id
            && self.has_dependencies
            && self.has_author
            && self.has_timestamp
    }
}

/// Compute the SBOM attestation hash.
///
/// ```text
/// sbom_attestation_hash = BLAKE3(generator_hash || sbom_hash || artifact_hash)
/// ```
#[must_use]
pub fn compute_sbom_hash(attestation: &SbomAttestation) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&attestation.generator_hash.0);
    data.extend_from_slice(&attestation.sbom_hash.0);
    data.extend_from_slice(&attestation.subject.artifact_hash.0);
    Blake3Hash::digest(&data)
}

/// Combine multiple SBOM hashes (e.g., SPDX + CycloneDX for same artifact).
#[must_use]
pub fn combine_sbom_hashes(attestations: &[SbomAttestation]) -> Blake3Hash {
    let mut hashes: Vec<Blake3Hash> = attestations.iter().map(|a| compute_sbom_hash(a)).collect();
    hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));

    let mut data = Vec::new();
    for h in &hashes {
        data.extend_from_slice(&h.0);
    }
    Blake3Hash::digest(&data)
}

/// NIST controls satisfied by SBOM generation and tracking.
pub fn sbom_nist_controls() -> Vec<&'static str> {
    vec![
        "CM-8",    // System Component Inventory
        "CM-8(1)", // Updates During Installation and Removal
        "SR-3",    // Supply Chain Controls and Processes
        "SR-4",    // Provenance
        "SR-4(1)", // Identity
        "SR-4(2)", // Track and Trace
        "SR-4(3)", // Validate as Genuine and Not Altered
        "SR-11",   // Component Authenticity
        "SA-10",   // Developer Configuration Management
        "SA-17",   // Developer Security and Privacy Architecture and Design
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sbom() -> SbomAttestation {
        SbomAttestation {
            format: SbomFormat::CycloneDx,
            generator: SbomGenerator::Syft,
            generator_hash: Blake3Hash::digest(b"syft-binary"),
            sbom_hash: Blake3Hash::digest(b"sbom-content"),
            subject: SbomSubject {
                subject_type: SbomSubjectType::OciImage,
                identifier: "ghcr.io/example-org/myapp:latest".to_string(),
                artifact_hash: Blake3Hash::digest(b"image-manifest"),
            },
            component_count: 142,
            dependency_count: 89,
            licenses: vec![
                LicenseSummary {
                    spdx_id: "MIT".to_string(),
                    count: 80,
                },
                LicenseSummary {
                    spdx_id: "Apache-2.0".to_string(),
                    count: 45,
                },
            ],
            generated_at: Utc::now(),
            ntia_compliant: true,
        }
    }

    #[test]
    fn sbom_hash_deterministic() {
        let sbom = make_sbom();
        let h1 = compute_sbom_hash(&sbom);
        let h2 = compute_sbom_hash(&sbom);
        assert_eq!(h1, h2);
    }

    #[test]
    fn sbom_hash_changes_with_content() {
        let mut sbom1 = make_sbom();
        let mut sbom2 = make_sbom();
        sbom2.sbom_hash = Blake3Hash::digest(b"different-sbom");
        assert_ne!(compute_sbom_hash(&sbom1), compute_sbom_hash(&sbom2));

        sbom1.generator_hash = Blake3Hash::digest(b"different-syft");
        assert_ne!(compute_sbom_hash(&sbom1), compute_sbom_hash(&sbom2));
    }

    #[test]
    fn ntia_compliance_check() {
        let full = NtiaCompliance {
            has_supplier: true,
            has_component_name: true,
            has_version: true,
            has_unique_id: true,
            has_dependencies: true,
            has_author: true,
            has_timestamp: true,
        };
        assert!(full.is_compliant());

        let partial = NtiaCompliance {
            has_supplier: true,
            has_component_name: true,
            has_version: false, // missing
            ..Default::default()
        };
        assert!(!partial.is_compliant());
    }
}
