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

use crate::akeyless_client::{AkeylessClient, AkeylessConfig, HttpAkeylessClient, TlsConfig};
use crate::certification::{
    BuildAttestation, ChartAttestation, DependencyHash, ImageAttestation,
    SourceAttestation,
};
use crate::compliance::akeyless::{AkeylessAuthMethod, AkeylessSecretAttestation};
use crate::compliance::akeyless_target::AkeylessTargetAttestation;
use crate::compliance::slsa::SlsaLevel;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::LayerType;
use crate::traits::ReqwestHttpClient;

use chrono::Utc;

/// Annotation keys matching sekiban's expected annotations.
pub const ANNOTATION_SIGNATURE: &str = "sekiban.pleme.io/signature";
pub const ANNOTATION_CERTIFICATION: &str = "sekiban.pleme.io/certification-hash";
pub const ANNOTATION_COMPLIANCE: &str = "sekiban.pleme.io/compliance-hash";
pub const ANNOTATION_CHANGESET: &str = "sekiban.pleme.io/changeset-hash";
pub const ANNOTATION_TARGET_ATTESTATION: &str = "sekiban.pleme.io/target-attestation-hash";

/// Compute a source attestation from git metadata.
///
/// Called early in CI after checkout.
#[must_use]
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
#[must_use]
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
#[must_use]
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
#[must_use]
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
#[must_use]
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
#[must_use]
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
#[must_use]
pub fn stage_output<T: Serialize>(stage: &str, hash: &Blake3Hash, passed: bool, attestation: &T) -> CiStageOutput {
    CiStageOutput {
        stage: stage.to_string(),
        hash: hash.to_prefixed(),
        passed,
        attestation_json: serde_json::to_string(attestation).unwrap_or_default(),
    }
}

/// Build an Akeyless secret attestation for CI pipelines.
///
/// This convenience function wraps the `AkeylessClient` workflow:
/// 1. Authenticate to the gateway
/// 2. Hash each specified secret (values are NEVER stored)
/// 3. Return an attestation suitable for inclusion in the Merkle tree
///
/// # Example
/// ```ignore
/// let attestation = akeyless_attestation(
///     "https://gw.akeyless.io",
///     AkeylessAuthMethod::ApiKey,
///     Some("p-abc123"),
///     Some("my-secret-key"),
///     &["/prod/db-password", "/prod/api-key"],
/// ).await?;
/// ```
pub async fn akeyless_attestation(
    gateway_url: &str,
    auth_method: AkeylessAuthMethod,
    access_id: Option<&str>,
    access_key: Option<&str>,
    secret_paths: &[&str],
) -> Result<AkeylessSecretAttestation> {
    use crate::akeyless_client::AkeylessClient;

    let config = AkeylessConfig {
        gateway_url: gateway_url.to_string(),
        auth_method,
        access_id: access_id.map(String::from),
        access_key: access_key.map(String::from),
        k8s_token_path: None,
        k8s_auth_config_name: None,
        tls: TlsConfig::default(),
    };
    let client = HttpAkeylessClient::new(config, ReqwestHttpClient::new());
    let paths: Vec<String> = secret_paths.iter().map(|s| s.to_string()).collect();
    client
        .build_attestation(&paths)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "akeyless".to_string(),
            message: format!("Akeyless CI attestation: {e}"),
        })
}

/// Build Akeyless target attestations for CI pipelines.
///
/// This convenience function wraps the `AkeylessClient` workflow:
/// 1. Authenticate to the gateway
/// 2. Fetch target details and associated producer metadata
/// 3. Return attestations suitable for inclusion in the Merkle tree
pub async fn akeyless_target_attestation(
    gateway_url: &str,
    auth_method: AkeylessAuthMethod,
    access_id: Option<&str>,
    access_key: Option<&str>,
    target_names: &[&str],
) -> Result<Vec<AkeylessTargetAttestation>> {
    let config = AkeylessConfig {
        gateway_url: gateway_url.to_string(),
        auth_method,
        access_id: access_id.map(String::from),
        access_key: access_key.map(String::from),
        k8s_token_path: None,
        k8s_auth_config_name: None,
        tls: TlsConfig::default(),
    };
    let client = HttpAkeylessClient::new(config, ReqwestHttpClient::new());
    let names: Vec<String> = target_names.iter().map(|s| s.to_string()).collect();
    client
        .build_target_attestation(&names)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "akeyless_target".to_string(),
            message: format!("Akeyless CI target attestation: {e}"),
        })
}

/// Build Akeyless target attestations using a custom HTTP client.
///
/// Like [`akeyless_target_attestation`], but accepts any
/// [`HttpClient`](crate::traits::HttpClient) implementation, making it testable
/// with [`MockHttpClient`](crate::traits::MockHttpClient).
pub async fn akeyless_target_attestation_with_client<H: crate::traits::HttpClient>(
    gateway_url: &str,
    auth_method: AkeylessAuthMethod,
    access_id: Option<&str>,
    access_key: Option<&str>,
    target_names: &[&str],
    http_client: H,
) -> Result<Vec<AkeylessTargetAttestation>> {
    let config = AkeylessConfig {
        gateway_url: gateway_url.to_string(),
        auth_method,
        access_id: access_id.map(String::from),
        access_key: access_key.map(String::from),
        k8s_token_path: None,
        k8s_auth_config_name: None,
        tls: TlsConfig::default(),
    };
    let client = HttpAkeylessClient::new(config, http_client);
    let names: Vec<String> = target_names.iter().map(|s| s.to_string()).collect();
    client
        .build_target_attestation(&names)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "akeyless_target".to_string(),
            message: format!("Akeyless CI target attestation: {e}"),
        })
}

/// Build an Akeyless secret attestation using a custom HTTP client.
///
/// Like [`akeyless_attestation`], but accepts any [`HttpClient`](crate::traits::HttpClient)
/// implementation, making it testable with [`MockHttpClient`](crate::traits::MockHttpClient).
pub async fn akeyless_attestation_with_client<H: crate::traits::HttpClient>(
    gateway_url: &str,
    auth_method: AkeylessAuthMethod,
    access_id: Option<&str>,
    access_key: Option<&str>,
    secret_paths: &[&str],
    http_client: H,
) -> Result<AkeylessSecretAttestation> {
    use crate::akeyless_client::AkeylessClient;

    let config = AkeylessConfig {
        gateway_url: gateway_url.to_string(),
        auth_method,
        access_id: access_id.map(String::from),
        access_key: access_key.map(String::from),
        k8s_token_path: None,
        k8s_auth_config_name: None,
        tls: TlsConfig::default(),
    };
    let client = HttpAkeylessClient::new(config, http_client);
    let paths: Vec<String> = secret_paths.iter().map(|s| s.to_string()).collect();
    client
        .build_attestation(&paths)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "akeyless".to_string(),
            message: format!("Akeyless CI attestation: {e}"),
        })
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

    #[test]
    fn image_attestation_creation() {
        let att = image_attestation(
            "ghcr.io/org/app",
            "latest",
            "amd64",
            Blake3Hash::digest(b"manifest"),
            true,
            Some("ci@org.com".to_string()),
            Blake3Hash::digest(b"vulns"),
            3,
            0,
            Blake3Hash::digest(b"sbom"),
        );
        assert_eq!(att.image_ref, "ghcr.io/org/app");
        assert!(att.cosign_verified);
        assert_eq!(att.layer_type, LayerType::Oci);
    }

    #[test]
    fn chart_attestation_creation() {
        let att = chart_attestation(
            "my-chart",
            "1.0.0",
            Blake3Hash::digest(b"chart"),
            true,
            vec![],
            true,
            true,
            "oci://ghcr.io/org/charts/my-chart",
        );
        assert_eq!(att.chart_name, "my-chart");
        assert!(att.provenance_verified);
        assert!(att.linter_passed);
    }

    #[test]
    fn ci_stage_output_serde_roundtrip() {
        let output = CiStageOutput {
            stage: "build".to_string(),
            hash: "blake3:abc".to_string(),
            passed: true,
            attestation_json: r#"{"key":"value"}"#.to_string(),
        };
        let json = serde_json::to_string(&output).unwrap();
        let deserialized: CiStageOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.stage, "build");
        assert!(deserialized.passed);
    }

    #[test]
    fn annotation_patch_deterministic() {
        let sig = Blake3Hash::digest(b"sig");
        let cert = Blake3Hash::digest(b"cert");
        let annotations = sekiban_annotations(&sig, Some(&cert), None);
        let patch1 = render_annotation_patch(&annotations);
        let patch2 = render_annotation_patch(&annotations);
        assert_eq!(patch1, patch2);
    }

    #[test]
    fn annotation_constants_have_pleme_prefix() {
        assert!(ANNOTATION_SIGNATURE.starts_with("sekiban.pleme.io/"));
        assert!(ANNOTATION_CERTIFICATION.starts_with("sekiban.pleme.io/"));
        assert!(ANNOTATION_COMPLIANCE.starts_with("sekiban.pleme.io/"));
        assert!(ANNOTATION_CHANGESET.starts_with("sekiban.pleme.io/"));
    }

    #[tokio::test]
    async fn akeyless_attestation_with_mock_client() {
        use crate::traits::MockHttpClient;

        let http = MockHttpClient::new();

        // Auth endpoint
        http.add_json_response(
            "https://gw.test.com/api/v1/auth",
            &serde_json::json!({"token": "t-ci-token"}),
        );

        // Secret endpoint
        http.add_json_response(
            "https://gw.test.com/api/v1/get-secret-value",
            &serde_json::json!({"/prod/db-password": "my-db-password"}),
        );

        let att = akeyless_attestation_with_client(
            "https://gw.test.com",
            AkeylessAuthMethod::ApiKey,
            Some("p-test-id"),
            Some("test-key"),
            &["/prod/db-password"],
            http,
        )
        .await
        .unwrap();

        assert_eq!(att.gateway_url, "https://gw.test.com");
        assert_eq!(att.auth_method, AkeylessAuthMethod::ApiKey);
        assert_eq!(att.secrets_accessed.len(), 1);
        assert_eq!(att.secrets_accessed[0].path, "/prod/db-password");
        // Value hash is now salted: BLAKE3(gateway_url:path:value)
        assert_eq!(
            att.secrets_accessed[0].value_hash,
            Blake3Hash::digest(b"https://gw.test.com:/prod/db-password:my-db-password")
        );
    }

    #[tokio::test]
    async fn akeyless_attestation_with_mock_auth_failure() {
        use crate::traits::MockHttpClient;

        let http = MockHttpClient::new();
        // No auth response registered -> will fail

        let result = akeyless_attestation_with_client(
            "https://gw.test.com",
            AkeylessAuthMethod::ApiKey,
            Some("p-test-id"),
            Some("test-key"),
            &["/prod/secret"],
            http,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Akeyless CI attestation"));
    }

    #[test]
    fn target_attestation_annotation_constant() {
        assert!(ANNOTATION_TARGET_ATTESTATION.starts_with("sekiban.pleme.io/"));
        assert!(ANNOTATION_TARGET_ATTESTATION.contains("target"));
    }

    #[tokio::test]
    async fn akeyless_target_attestation_with_mock_client() {
        use crate::traits::MockHttpClient;

        let http = MockHttpClient::new();

        // Auth endpoint
        http.add_json_response(
            "https://gw.test.com/api/v1/auth",
            &serde_json::json!({"token": "t-ci-token"}),
        );

        // Target details endpoint
        http.add_json_response(
            "https://gw.test.com/api/v1/target-get-details",
            &serde_json::json!({
                "target_type": "database",
                "endpoint": "db.prod.internal:5432",
                "tls_verified": true,
                "associations": []
            }),
        );

        let result = akeyless_target_attestation_with_client(
            "https://gw.test.com",
            AkeylessAuthMethod::ApiKey,
            Some("p-test-id"),
            Some("test-key"),
            &["/targets/prod/db"],
            http,
        )
        .await
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target_name, "/targets/prod/db");
    }

    #[tokio::test]
    async fn akeyless_target_attestation_auth_failure() {
        use crate::traits::MockHttpClient;

        let http = MockHttpClient::new();
        // No auth response registered -> will fail

        let result = akeyless_target_attestation_with_client(
            "https://gw.test.com",
            AkeylessAuthMethod::ApiKey,
            Some("p-test-id"),
            Some("test-key"),
            &["/targets/prod/db"],
            http,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Akeyless CI target attestation"));
    }
}
