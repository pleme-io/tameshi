//! SLSA (Supply-chain Levels for Software Artifacts) provenance integration.
//!
//! SLSA defines increasing levels of supply chain integrity guarantees.
//! This module models SLSA provenance attestations and integrates them into
//! the compliance hash chain.
//!
//! ## SLSA Levels
//!
//! | Level | Requirement | How We Satisfy |
//! |-------|-------------|----------------|
//! | L1 | Provenance exists | Build metadata recorded |
//! | L2 | Hosted build platform | Nix builds, GitHub Actions |
//! | L3 | Hardened builds | Nix hermetic sandbox, reproducible |
//! | L4 | Two-person review + hermetic | Nix reproducibility + PR approval |
//!
//! ## Nix ↔ SLSA Mapping
//!
//! Nix's build model inherently satisfies many SLSA requirements:
//! - **Hermetic builds**: Nix sandbox prevents network and filesystem access
//! - **Reproducibility**: Same inputs → same output hash
//! - **Provenance**: Nix derivation records all inputs and build steps
//! - **Immutable outputs**: Nix store paths are content-addressed
//!
//! ## Sigstore Integration
//!
//! OCI images can be signed with cosign (Sigstore) and the signature
//! verified as part of the attestation chain. The cosign signature
//! is a separate attestation dimension from our BLAKE3 hash chain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// SLSA provenance attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlsaProvenance {
    /// SLSA level achieved.
    pub level: SlsaLevel,
    /// Build type (Nix, GitHub Actions, etc.).
    pub build_type: BuildType,
    /// Builder identity.
    pub builder_id: String,
    /// Source repository.
    pub source_repo: String,
    /// Source commit SHA.
    pub source_commit: String,
    /// Source branch/ref.
    pub source_ref: String,
    /// Build configuration (flake.nix path, workflow file, etc.).
    pub build_config: String,
    /// Build inputs and their hashes.
    pub materials: Vec<BuildMaterial>,
    /// Output artifact identifier.
    pub subject: ProvenanceSubject,
    /// Whether the build was reproducible (verified by rebuild).
    pub reproducible: bool,
    /// Whether the build was hermetic (no external access).
    pub hermetic: bool,
    /// Build timestamp.
    pub built_at: DateTime<Utc>,
    /// Who triggered the build.
    pub triggered_by: String,
    /// Whether two-person review was required (L4).
    #[serde(default)]
    pub two_person_reviewed: bool,
}

/// SLSA levels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlsaLevel {
    /// No SLSA guarantees.
    L0,
    /// Provenance exists (build metadata recorded).
    L1,
    /// Hosted build platform (not local).
    L2,
    /// Hardened builds (hermetic, reproducible).
    L3,
    /// Two-person review + hermetic + reproducible.
    L4,
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlsaLevel::L0 => write!(f, "SLSA L0"),
            SlsaLevel::L1 => write!(f, "SLSA L1"),
            SlsaLevel::L2 => write!(f, "SLSA L2"),
            SlsaLevel::L3 => write!(f, "SLSA L3"),
            SlsaLevel::L4 => write!(f, "SLSA L4"),
        }
    }
}

/// Build types for provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildType {
    /// Nix build (nix build, nix-build).
    NixBuild,
    /// GitHub Actions workflow.
    GithubActions,
    /// Local development build.
    LocalDev,
    /// Forge CI/CD pipeline.
    Forge,
    /// Other build system.
    Other(String),
}

/// A build material (input to the build).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildMaterial {
    /// URI identifying the material (git repo, Nix flake input, etc.).
    pub uri: String,
    /// Hash of the material.
    pub digest: Blake3Hash,
    /// Type of material.
    pub material_type: MaterialType,
}

/// Types of build materials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialType {
    SourceCode,
    NixFlakeInput,
    NixDerivation,
    NpmDependency,
    RustCrate,
    OciBaseImage,
    BuildTool,
    Configuration,
}

/// The subject of a provenance attestation (what was built).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenanceSubject {
    /// Artifact name/identifier.
    pub name: String,
    /// Content hash of the built artifact.
    pub digest: Blake3Hash,
    /// Artifact type.
    pub artifact_type: ArtifactType,
}

/// Types of build artifacts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    OciImage,
    NixStorePath,
    HelmChart,
    RustBinary,
    NpmPackage,
    StaticAsset,
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactType::OciImage => write!(f, "OCI Image"),
            ArtifactType::NixStorePath => write!(f, "Nix Store Path"),
            ArtifactType::HelmChart => write!(f, "Helm Chart"),
            ArtifactType::RustBinary => write!(f, "Rust Binary"),
            ArtifactType::NpmPackage => write!(f, "NPM Package"),
            ArtifactType::StaticAsset => write!(f, "Static Asset"),
        }
    }
}

impl std::fmt::Display for BuildType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildType::NixBuild => write!(f, "Nix Build"),
            BuildType::GithubActions => write!(f, "GitHub Actions"),
            BuildType::LocalDev => write!(f, "Local Dev"),
            BuildType::Forge => write!(f, "Forge"),
            BuildType::Other(s) => write!(f, "Other({s})"),
        }
    }
}

impl std::fmt::Display for MaterialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaterialType::SourceCode => write!(f, "Source Code"),
            MaterialType::NixFlakeInput => write!(f, "Nix Flake Input"),
            MaterialType::NixDerivation => write!(f, "Nix Derivation"),
            MaterialType::NpmDependency => write!(f, "NPM Dependency"),
            MaterialType::RustCrate => write!(f, "Rust Crate"),
            MaterialType::OciBaseImage => write!(f, "OCI Base Image"),
            MaterialType::BuildTool => write!(f, "Build Tool"),
            MaterialType::Configuration => write!(f, "Configuration"),
        }
    }
}

/// Sigstore/cosign signature verification result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CosignVerification {
    /// Whether the signature is valid.
    pub verified: bool,
    /// Signing identity (email, OIDC subject).
    pub signer_identity: String,
    /// Signing certificate issuer.
    pub issuer: String,
    /// Transparency log entry index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekor_log_index: Option<u64>,
    /// Image reference that was verified.
    pub image_ref: String,
    /// Cosign signature hash.
    pub signature_hash: Blake3Hash,
    /// When verified.
    pub verified_at: DateTime<Utc>,
}

/// in-toto attestation bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InTotoAttestation {
    /// Attestation type URI.
    pub predicate_type: String,
    /// Subjects of the attestation.
    pub subjects: Vec<ProvenanceSubject>,
    /// Attestation content hash.
    pub attestation_hash: Blake3Hash,
    /// Signer identity.
    pub signer: String,
    /// When signed.
    pub signed_at: DateTime<Utc>,
}

/// Compute the SLSA provenance hash for the compliance chain.
///
/// ```text
/// provenance_hash = BLAKE3(
///   builder_id  ||
///   source_commit ||
///   materials_hashes... ||
///   subject_digest ||
///   level ||
///   reproducible ||
///   hermetic
/// )
/// ```
#[must_use]
pub fn compute_provenance_hash(provenance: &SlsaProvenance) -> Blake3Hash {
    let material_count = provenance.materials.len();
    let mut data = Vec::with_capacity(
        provenance.builder_id.len()
            + provenance.source_commit.len()
            + material_count * 32
            + 32
            + 10,
    );
    data.extend_from_slice(provenance.builder_id.as_bytes());
    data.extend_from_slice(provenance.source_commit.as_bytes());

    // Include all material hashes in sorted order
    let mut material_hashes: Vec<&Blake3Hash> =
        provenance.materials.iter().map(|m| &m.digest).collect();
    material_hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));
    for h in material_hashes {
        data.extend_from_slice(&h.0);
    }

    data.extend_from_slice(&provenance.subject.digest.0);
    data.extend_from_slice(format!("{}", provenance.level).as_bytes());
    data.push(provenance.reproducible as u8);
    data.push(provenance.hermetic as u8);

    Blake3Hash::digest(&data)
}

/// Determine the SLSA level from build properties.
#[must_use]
pub fn determine_slsa_level(
    has_provenance: bool,
    hosted_build: bool,
    hermetic: bool,
    reproducible: bool,
    two_person_review: bool,
) -> SlsaLevel {
    if !has_provenance {
        return SlsaLevel::L0;
    }
    if !hosted_build {
        return SlsaLevel::L1;
    }
    if !hermetic || !reproducible {
        return SlsaLevel::L2;
    }
    if !two_person_review {
        return SlsaLevel::L3;
    }
    SlsaLevel::L4
}

/// NIST controls satisfied by SLSA provenance and supply chain attestation.
#[must_use]
pub fn slsa_nist_controls() -> Vec<&'static str> {
    vec![
        "SA-10",   // Developer Configuration Management
        "SA-11",   // Developer Testing and Evaluation
        "SA-15",   // Development Process, Standards, and Tools
        "SR-3",    // Supply Chain Controls and Processes
        "SR-4",    // Provenance
        "SR-4(1)", // Identity
        "SR-4(2)", // Track and Trace
        "SR-4(3)", // Validate as Genuine and Not Altered
        "SR-4(4)", // Supply Chain Integrity — Pedigree
        "SR-11",   // Component Authenticity
        "SI-7",    // Software, Firmware, and Information Integrity
        "SI-7(1)", // Integrity Checks
        "SI-7(6)", // Cryptographic Protection
        "CM-14",   // Signed Components
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provenance() -> SlsaProvenance {
        SlsaProvenance {
            level: SlsaLevel::L3,
            build_type: BuildType::NixBuild,
            builder_id: "nix-build@forge.pleme.io".to_string(),
            source_repo: "https://github.com/example-org/myapp".to_string(),
            source_commit: "abc123def456".to_string(),
            source_ref: "refs/heads/main".to_string(),
            build_config: "flake.nix#packages.x86_64-linux.default".to_string(),
            materials: vec![
                BuildMaterial {
                    uri: "github:pleme-io/substrate".to_string(),
                    digest: Blake3Hash::digest(b"substrate-flake"),
                    material_type: MaterialType::NixFlakeInput,
                },
                BuildMaterial {
                    uri: "github:NixOS/nixpkgs".to_string(),
                    digest: Blake3Hash::digest(b"nixpkgs-rev"),
                    material_type: MaterialType::NixFlakeInput,
                },
            ],
            subject: ProvenanceSubject {
                name: "ghcr.io/example-org/myapp".to_string(),
                digest: Blake3Hash::digest(b"oci-image-digest"),
                artifact_type: ArtifactType::OciImage,
            },
            reproducible: true,
            hermetic: true,
            built_at: Utc::now(),
            triggered_by: "github-actions[bot]".to_string(),
            two_person_reviewed: false,
        }
    }

    #[test]
    fn provenance_hash_deterministic() {
        let prov = make_provenance();
        let h1 = compute_provenance_hash(&prov);
        let h2 = compute_provenance_hash(&prov);
        assert_eq!(h1, h2);
    }

    #[test]
    fn provenance_hash_changes_with_commit() {
        let mut prov1 = make_provenance();
        let mut prov2 = make_provenance();
        prov2.source_commit = "different-commit".to_string();
        assert_ne!(
            compute_provenance_hash(&prov1),
            compute_provenance_hash(&prov2)
        );

        prov1.subject.digest = Blake3Hash::digest(b"different-output");
        assert_ne!(
            compute_provenance_hash(&prov1),
            compute_provenance_hash(&prov2)
        );
    }

    #[test]
    fn slsa_level_determination() {
        assert_eq!(
            determine_slsa_level(false, false, false, false, false),
            SlsaLevel::L0
        );
        assert_eq!(
            determine_slsa_level(true, false, false, false, false),
            SlsaLevel::L1
        );
        assert_eq!(
            determine_slsa_level(true, true, false, false, false),
            SlsaLevel::L2
        );
        assert_eq!(
            determine_slsa_level(true, true, true, true, false),
            SlsaLevel::L3
        );
        assert_eq!(
            determine_slsa_level(true, true, true, true, true),
            SlsaLevel::L4
        );
    }

    #[test]
    fn nix_build_is_l3() {
        // Nix builds are inherently hermetic and reproducible
        let level = determine_slsa_level(true, true, true, true, false);
        assert_eq!(level, SlsaLevel::L3);
    }
}
