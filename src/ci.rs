//! CI/CD integration for the attestation framework.
//!
//! Provides helpers for CI/CD pipelines (forge, GitHub Actions, etc.) to:
//! 1. Compute certification hashes at each build stage
//! 2. Generate FluxCD-compatible annotation values
//! 3. Submit certification requests to kensa
//! 4. Annotate Kubernetes resources with integrity signatures
//!
//! ## Pipeline flow
//!
//! ```text
//! CI Pipeline:
//!   1. source_attestation()    → SourceAttestation (git commit, flake.lock)
//!   2. build_attestation()     → BuildAttestation  (nix closure, SLSA, SBOM)
//!   3. image_attestation()     → ImageAttestation  (OCI manifest, cosign)
//!   4. chart_attestation()     → ChartAttestation  (Helm chart, provenance)
//!   5. submit_to_kensa()       → CertifyResponse   (hash for annotations)
//!   6. annotate_resources()    → FluxCD annotations (sekiban-compatible)
//! ```
//!
//! ## Annotations produced
//!
//! ```yaml
//! metadata:
//!   annotations:
//!     sekiban.pleme.io/signature: "blake3:abc..."
//!     sekiban.pleme.io/certification-hash: "blake3:def..."
//!     sekiban.pleme.io/compliance-hash: "blake3:ghi..."
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::certification::{
    BuildAttestation, ChartAttestation, DependencyHash, ImageAttestation,
    SourceAttestation,
};
use crate::compliance::slsa::SlsaLevel;
use crate::hash::Blake3Hash;
use crate::signature::LayerType;

use chrono::Utc;

/// Annotation keys matching sekiban's expected annotations.
pub const ANNOTATION_SIGNATURE: &str = "sekiban.pleme.io/signature";
pub const ANNOTATION_CERTIFICATION: &str = "sekiban.pleme.io/certification-hash";
pub const ANNOTATION_COMPLIANCE: &str = "sekiban.pleme.io/compliance-hash";
pub const ANNOTATION_CHANGESET: &str = "sekiban.pleme.io/changeset-hash";

/// Compute a source attestation from git metadata.
///
/// Called early in CI after checkout.
pub fn source_attestation(
    repository: &str,
    commit: &str,
    git_ref: &str,
    commit_signed: bool,
    tree_hash: Blake3Hash,
    flake_lock_hash: Blake3Hash,
    flake_input_count: usize,
    all_inputs_pinned: bool,
) -> SourceAttestation {
    SourceAttestation {
        repository: repository.to_string(),
        commit: commit.to_string(),
        git_ref: git_ref.to_string(),
        commit_signed,
        tree_hash,
        flake_lock_hash,
        flake_input_count,
        all_inputs_pinned,
    }
}

/// Compute a build attestation from Nix build outputs.
///
/// Called after `nix build` completes.
pub fn build_attestation(
    service: &str,
    derivation: &str,
    closure_hash: Blake3Hash,
    slsa_level: SlsaLevel,
    reproducible: bool,
    sbom_hash: Blake3Hash,
    vuln_scan_hash: Blake3Hash,
    cve_count: usize,
    critical_high_cves: usize,
    builder: &str,
) -> BuildAttestation {
    BuildAttestation {
        service: service.to_string(),
        derivation: derivation.to_string(),
        closure_hash,
        slsa_level,
        reproducible,
        hermetic: true, // Nix sandbox guarantees hermeticity
        sbom_hash,
        vuln_scan_hash,
        cve_count,
        critical_high_cves,
        builder: builder.to_string(),
        built_at: Utc::now(),
    }
}

/// Compute an image attestation from OCI image metadata.
///
/// Called after pushing the image to the registry.
pub fn image_attestation(
    image_ref: &str,
    tag: &str,
    architecture: &str,
    manifest_hash: Blake3Hash,
    cosign_verified: bool,
    signer_identity: Option<String>,
    vuln_scan_hash: Blake3Hash,
    vuln_count: usize,
    critical_high_vulns: usize,
    sbom_hash: Blake3Hash,
) -> ImageAttestation {
    ImageAttestation {
        image_ref: image_ref.to_string(),
        tag: tag.to_string(),
        architecture: architecture.to_string(),
        manifest_hash,
        cosign_verified,
        signer_identity,
        vuln_scan_hash,
        vuln_count,
        critical_high_vulns,
        sbom_hash,
        layer_type: LayerType::Oci,
    }
}

/// Compute a chart attestation from Helm chart metadata.
///
/// Called after packaging the chart.
pub fn chart_attestation(
    chart_name: &str,
    chart_version: &str,
    chart_hash: Blake3Hash,
    provenance_verified: bool,
    dependency_hashes: Vec<DependencyHash>,
    linter_passed: bool,
    policy_passed: bool,
    registry_ref: &str,
) -> ChartAttestation {
    ChartAttestation {
        chart_name: chart_name.to_string(),
        chart_version: chart_version.to_string(),
        chart_hash,
        provenance_verified,
        dependency_hashes,
        linter_passed,
        policy_passed,
        registry_ref: registry_ref.to_string(),
    }
}

/// Generate sekiban-compatible annotations for a Kubernetes resource.
///
/// These annotations are added to FluxCD Kustomizations and HelmReleases
/// so that sekiban's admission webhook can verify them.
pub fn sekiban_annotations(
    signature: &Blake3Hash,
    certification_hash: Option<&Blake3Hash>,
    compliance_hash: Option<&Blake3Hash>,
) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_SIGNATURE.to_string(),
        signature.to_prefixed(),
    );
    if let Some(cert) = certification_hash {
        annotations.insert(
            ANNOTATION_CERTIFICATION.to_string(),
            cert.to_prefixed(),
        );
    }
    if let Some(compliance) = compliance_hash {
        annotations.insert(
            ANNOTATION_COMPLIANCE.to_string(),
            compliance.to_prefixed(),
        );
    }
    annotations
}

/// Render annotations as YAML patch for kustomize or kubectl.
///
/// Produces a strategic merge patch that can be applied to any resource
/// to add the integrity annotations.
pub fn render_annotation_patch(annotations: &BTreeMap<String, String>) -> String {
    let mut lines = vec![
        "metadata:".to_string(),
        "  annotations:".to_string(),
    ];
    for (key, value) in annotations {
        lines.push(format!("    {}: \"{}\"", key, value));
    }
    lines.join("\n")
}

/// CI pipeline stage results for serialization.
///
/// Used to pass attestation data between CI steps (e.g., as JSON artifacts).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiStageOutput {
    /// Stage name.
    pub stage: String,
    /// Hash produced by this stage.
    pub hash: String,
    /// Whether the stage passed.
    pub passed: bool,
    /// Serialized attestation (JSON).
    pub attestation_json: String,
}

/// Serialize an attestation to a CI stage output.
pub fn stage_output<T: Serialize>(stage: &str, hash: &Blake3Hash, passed: bool, attestation: &T) -> CiStageOutput {
    CiStageOutput {
        stage: stage.to_string(),
        hash: hash.to_prefixed(),
        passed,
        attestation_json: serde_json::to_string(attestation).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_attestation_creation() {
        let att = source_attestation(
            "github.com/org/repo",
            "abc123",
            "refs/heads/main",
            true,
            Blake3Hash::digest(b"tree"),
            Blake3Hash::digest(b"lock"),
            10,
            true,
        );
        assert_eq!(att.commit, "abc123");
        assert!(att.commit_signed);
        assert!(att.all_inputs_pinned);
    }

    #[test]
    fn build_attestation_creation() {
        let att = build_attestation(
            "backend",
            "/nix/store/xxx.drv",
            Blake3Hash::digest(b"closure"),
            SlsaLevel::L3,
            true,
            Blake3Hash::digest(b"sbom"),
            Blake3Hash::digest(b"vulns"),
            2,
            0,
            "nix-build@forge",
        );
        assert_eq!(att.service, "backend");
        assert!(att.hermetic);
        assert_eq!(att.critical_high_cves, 0);
    }

    #[test]
    fn sekiban_annotations_basic() {
        let sig = Blake3Hash::digest(b"sig");
        let annotations = sekiban_annotations(&sig, None, None);
        assert_eq!(annotations.len(), 1);
        assert!(annotations.contains_key(ANNOTATION_SIGNATURE));
    }

    #[test]
    fn sekiban_annotations_full() {
        let sig = Blake3Hash::digest(b"sig");
        let cert = Blake3Hash::digest(b"cert");
        let comp = Blake3Hash::digest(b"comp");
        let annotations = sekiban_annotations(&sig, Some(&cert), Some(&comp));
        assert_eq!(annotations.len(), 3);
        assert!(annotations.contains_key(ANNOTATION_CERTIFICATION));
        assert!(annotations.contains_key(ANNOTATION_COMPLIANCE));
    }

    #[test]
    fn annotation_patch_renders_yaml() {
        let sig = Blake3Hash::digest(b"sig");
        let annotations = sekiban_annotations(&sig, None, None);
        let patch = render_annotation_patch(&annotations);
        assert!(patch.contains("metadata:"));
        assert!(patch.contains("annotations:"));
        assert!(patch.contains("sekiban.pleme.io/signature:"));
        assert!(patch.contains("blake3:"));
    }

    #[test]
    fn stage_output_serialization() {
        let hash = Blake3Hash::digest(b"test");
        let att = source_attestation(
            "repo", "abc", "main", true,
            hash.clone(), hash.clone(), 5, true,
        );
        let output = stage_output("source", &hash, true, &att);
        assert_eq!(output.stage, "source");
        assert!(output.passed);
        assert!(!output.attestation_json.is_empty());
    }
}
