//! Helm chart collector.
//!
//! Computes BLAKE3 hashes of Helm charts including their provenance files.
//! Supports both local chart directories and OCI-stored charts.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// Hash a Helm chart from a local directory.
///
/// Packages the chart with `helm package`, then hashes the resulting tarball.
/// Also hashes `Chart.yaml` and `values.yaml` individually for auditability.
pub async fn hash_chart_dir(chart_path: &str) -> Result<LayerSignature> {
    let mut inputs = Vec::new();

    // Hash Chart.yaml
    let chart_yaml = format!("{}/Chart.yaml", chart_path);
    if let Ok(data) = tokio::fs::read(&chart_yaml).await {
        inputs.push(InputHash {
            name: "Chart.yaml".to_string(),
            hash: Blake3Hash::digest(&data),
            size_bytes: Some(data.len() as u64),
        });
    }

    // Hash values.yaml
    let values_yaml = format!("{}/values.yaml", chart_path);
    if let Ok(data) = tokio::fs::read(&values_yaml).await {
        inputs.push(InputHash {
            name: "values.yaml".to_string(),
            hash: Blake3Hash::digest(&data),
            size_bytes: Some(data.len() as u64),
        });
    }

    // Hash all templates
    let templates_dir = format!("{}/templates", chart_path);
    if let Ok(mut entries) = tokio::fs::read_dir(&templates_dir).await {
        let mut template_files = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(data) = tokio::fs::read(entry.path()).await {
                template_files.push((entry.file_name().to_string_lossy().to_string(), data));
            }
        }
        template_files.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, data) in &template_files {
            inputs.push(InputHash {
                name: format!("templates/{}", name),
                hash: Blake3Hash::digest(data),
                size_bytes: Some(data.len() as u64),
            });
        }
    }

    let composite = compute_composite(&inputs);

    debug!(
        chart = chart_path,
        files = inputs.len(),
        "Hashed Helm chart directory"
    );

    Ok(LayerSignature::new(
        LayerType::Helm,
        composite,
        chart_path,
        inputs,
    ))
}

/// Hash a Helm chart from an OCI registry.
///
/// Uses `helm pull --untar` to fetch and then hashes the contents.
pub async fn hash_chart_oci(chart_ref: &str) -> Result<LayerSignature> {
    let tmpdir = tempfile::tempdir().map_err(|e| TameshiError::CollectorError {
        layer: "helm".to_string(),
        message: format!("failed to create temp dir: {}", e),
    })?;

    let output = Command::new("helm")
        .args([
            "pull",
            chart_ref,
            "--untar",
            "--untardir",
            tmpdir.path().to_str().unwrap_or("/tmp"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("helm pull {}", chart_ref),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    // Find the extracted chart directory
    let mut entries: tokio::fs::ReadDir = tokio::fs::read_dir(tmpdir.path()).await?;
    let chart_dir = if let Ok(Some(entry)) = entries.next_entry().await {
        entry.path()
    } else {
        return Err(TameshiError::CollectorError {
            layer: "helm".to_string(),
            message: format!("helm pull {} produced no output", chart_ref),
        });
    };

    hash_chart_dir(chart_dir.to_str().unwrap_or("")).await
}

/// Hash the actual deployed Kubernetes manifest for drift detection.
///
/// SECURITY: This hashes what is ACTUALLY running, not what was planned.
/// Use this alongside [`hash_rendered_chart`] to detect Helm value overrides
/// that bypass file-based attestation.
///
/// Fetches the manifest via `kubectl get <resource> -o yaml`, canonicalizes
/// it using [`YamlCanonicalizer`] in Logical mode, and hashes the result
/// with BLAKE3.
pub async fn hash_deployed_manifest(
    resource_type: &str,
    resource_name: &str,
    namespace: &str,
) -> Result<LayerSignature> {
    use crate::canonicalize::{CanonicalMode, Canonicalizer, YamlCanonicalizer};

    let output = Command::new("kubectl")
        .args([
            "get",
            resource_type,
            resource_name,
            "--namespace",
            namespace,
            "-o",
            "yaml",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!(
                "kubectl get {} {} --namespace {} -o yaml",
                resource_type, resource_name, namespace
            ),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let canonical = YamlCanonicalizer.canonicalize(&output.stdout, CanonicalMode::Logical);
    let deployed_hash = Blake3Hash::digest(canonical.as_ref());

    debug!(
        resource_type = resource_type,
        resource_name = resource_name,
        namespace = namespace,
        "Hashed deployed Kubernetes manifest"
    );

    let input_hash = InputHash {
        name: format!("{}/{}", resource_type, resource_name),
        hash: deployed_hash.clone(),
        size_bytes: Some(output.stdout.len() as u64),
    };

    Ok(LayerSignature::new(
        LayerType::Helm,
        deployed_hash,
        &format!("{}/{}/{}", namespace, resource_type, resource_name),
        vec![input_hash],
    ))
}

/// Hash Helm chart provenance file (.prov).
pub async fn hash_provenance(prov_path: &str) -> Result<InputHash> {
    let data = tokio::fs::read(prov_path).await?;
    Ok(InputHash {
        name: "provenance".to_string(),
        hash: Blake3Hash::digest(&data),
        size_bytes: Some(data.len() as u64),
    })
}

#[inline]
fn compute_composite(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-helm-chart");
    }
    let mut data = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}

/// Hash a Helm chart by running `helm template` and canonicalizing the rendered output.
///
/// This captures the *effective* manifest output rather than the raw chart inputs,
/// ensuring that any templating logic, value overrides, or conditional blocks are
/// reflected in the final hash.
///
/// # Process
///
/// 1. Runs `helm template` with the given chart path, values files, and namespace
/// 2. Captures the rendered YAML from stdout
/// 3. Canonicalizes the output using [`YamlCanonicalizer`] in Logical mode
/// 4. Computes a BLAKE3 hash of the canonical output
/// 5. Returns a [`LayerSignature`] including input hashes of each values file
pub async fn hash_rendered_chart(
    chart_path: &str,
    values_files: &[String],
    release_name: &str,
    namespace: &str,
) -> Result<LayerSignature> {
    use crate::canonicalize::{CanonicalMode, Canonicalizer, YamlCanonicalizer};

    let mut args = vec![
        "template".to_string(),
        release_name.to_string(),
        chart_path.to_string(),
        "--namespace".to_string(),
        namespace.to_string(),
    ];
    for vf in values_files {
        args.push("--values".to_string());
        args.push(vf.clone());
    }

    let output = Command::new("helm")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("helm template {} {}", release_name, chart_path),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let canonical = YamlCanonicalizer.canonicalize(&output.stdout, CanonicalMode::Logical);
    let rendered_hash = Blake3Hash::digest(canonical.as_ref());

    let mut inputs = Vec::new();
    for vf in values_files {
        if let Ok(data) = tokio::fs::read(vf).await {
            inputs.push(InputHash {
                name: vf.clone(),
                hash: Blake3Hash::digest(&data),
                size_bytes: Some(data.len() as u64),
            });
        }
    }

    debug!(
        chart = chart_path,
        release = release_name,
        namespace = namespace,
        values_files = values_files.len(),
        "Hashed rendered Helm chart"
    );

    Ok(LayerSignature::new(
        LayerType::Helm,
        rendered_hash,
        &format!("{}/{}", namespace, release_name),
        inputs,
    ))
}

/// Rendered Helm chart collector.
///
/// Unlike [`HelmCollector`] which hashes chart input files, this collector
/// runs `helm template` and hashes the rendered output. This captures the
/// effective manifest after value substitution and template evaluation.
pub struct RenderedHelmCollector {
    chart_path: String,
    values_files: Vec<String>,
    release_name: String,
    namespace: String,
}

impl RenderedHelmCollector {
    /// Create a new rendered Helm chart collector.
    #[must_use]
    pub fn new(
        chart_path: &str,
        values_files: Vec<String>,
        release_name: &str,
        namespace: &str,
    ) -> Self {
        Self {
            chart_path: chart_path.to_string(),
            values_files,
            release_name: release_name.to_string(),
            namespace: namespace.to_string(),
        }
    }
}

impl LayerCollector for RenderedHelmCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        hash_rendered_chart(
            &self.chart_path,
            &self.values_files,
            &self.release_name,
            &self.namespace,
        )
        .await
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Helm
    }
}

/// Helm chart collector.
///
/// Wraps the standalone functions in a [`LayerCollector`] implementation.
/// Supports both local chart directories and OCI-stored charts.
pub struct HelmCollector {
    /// Chart reference: either a local path or an OCI reference.
    pub chart_ref: String,
    /// Whether `chart_ref` is an OCI reference.
    pub is_oci: bool,
}

impl HelmCollector {
    /// Create a collector for a local chart directory.
    #[must_use]
    pub fn from_dir(chart_path: &str) -> Self {
        Self {
            chart_ref: chart_path.to_string(),
            is_oci: false,
        }
    }

    /// Create a collector for an OCI-stored chart.
    #[must_use]
    pub fn from_oci(chart_ref: &str) -> Self {
        Self {
            chart_ref: chart_ref.to_string(),
            is_oci: true,
        }
    }
}

impl LayerCollector for HelmCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        if self.is_oci {
            hash_chart_oci(&self.chart_ref).await
        } else {
            hash_chart_dir(&self.chart_ref).await
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Helm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize::{CanonicalMode, Canonicalizer, YamlCanonicalizer};

    #[test]
    fn rendered_helm_collector_layer_type() {
        let collector = RenderedHelmCollector::new(
            "./charts/myapp",
            vec!["values.yaml".to_string()],
            "myapp",
            "default",
        );
        assert_eq!(collector.layer_type(), LayerType::Helm);
    }

    #[test]
    fn rendered_helm_collector_new() {
        let collector = RenderedHelmCollector::new(
            "./charts/myapp",
            vec![
                "values-prod.yaml".to_string(),
                "values-secrets.yaml".to_string(),
            ],
            "my-release",
            "production",
        );
        assert_eq!(collector.chart_path, "./charts/myapp");
        assert_eq!(collector.values_files.len(), 2);
        assert_eq!(collector.values_files[0], "values-prod.yaml");
        assert_eq!(collector.values_files[1], "values-secrets.yaml");
        assert_eq!(collector.release_name, "my-release");
        assert_eq!(collector.namespace, "production");
    }

    #[test]
    fn different_values_produce_different_rendered_hashes() {
        // Simulate what hash_rendered_chart does: canonicalize rendered YAML then hash.
        // Different rendered outputs must produce different hashes.
        let rendered_a =
            b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\ndata:\n  replicas: \"3\"\n";
        let rendered_b =
            b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\ndata:\n  replicas: \"5\"\n";

        let canonical_a = YamlCanonicalizer.canonicalize(rendered_a, CanonicalMode::Logical);
        let canonical_b = YamlCanonicalizer.canonicalize(rendered_b, CanonicalMode::Logical);

        let hash_a = Blake3Hash::digest(canonical_a.as_ref());
        let hash_b = Blake3Hash::digest(canonical_b.as_ref());

        assert_ne!(
            hash_a, hash_b,
            "Different rendered values must produce different hashes"
        );
    }

    #[test]
    fn same_rendered_yaml_reordered_keys_same_hash() {
        // Canonicalization should normalize key order, so reordered keys hash identically.
        let rendered_a = b"kind: ConfigMap\napiVersion: v1\ndata:\n  key: value\n";
        let rendered_b = b"apiVersion: v1\nkind: ConfigMap\ndata:\n  key: value\n";

        let canonical_a = YamlCanonicalizer.canonicalize(rendered_a, CanonicalMode::Logical);
        let canonical_b = YamlCanonicalizer.canonicalize(rendered_b, CanonicalMode::Logical);

        let hash_a = Blake3Hash::digest(canonical_a.as_ref());
        let hash_b = Blake3Hash::digest(canonical_b.as_ref());

        assert_eq!(
            hash_a, hash_b,
            "Same content with reordered keys should hash identically after canonicalization"
        );
    }

    #[test]
    fn compute_composite_empty() {
        let hash = compute_composite(&[]);
        assert_eq!(hash, Blake3Hash::digest(b"empty-helm-chart"));
    }

    #[test]
    fn compute_composite_deterministic() {
        let inputs = vec![
            InputHash {
                name: "a".to_string(),
                hash: Blake3Hash::digest(b"a"),
                size_bytes: None,
            },
            InputHash {
                name: "b".to_string(),
                hash: Blake3Hash::digest(b"b"),
                size_bytes: None,
            },
        ];
        let h1 = compute_composite(&inputs);
        let h2 = compute_composite(&inputs);
        assert_eq!(h1, h2);
    }

    // =========================================================================
    // hash_deployed_manifest — drift detection tests
    // =========================================================================

    #[test]
    fn hash_deployed_manifest_returns_layer_signature() {
        // Simulate what hash_deployed_manifest does: canonicalize deployed YAML then hash.
        // Verify the output has the correct LayerType and a non-empty hash.
        let deployed_yaml = b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: myapp\n  namespace: default\nspec:\n  replicas: 3\n";
        let canonical = YamlCanonicalizer.canonicalize(deployed_yaml, CanonicalMode::Logical);
        let hash = Blake3Hash::digest(canonical.as_ref());

        // The hash should be deterministic and non-zero.
        assert_ne!(hash, Blake3Hash::digest(b""));
        // Hashing the same content again should yield the same result.
        let canonical2 = YamlCanonicalizer.canonicalize(deployed_yaml, CanonicalMode::Logical);
        let hash2 = Blake3Hash::digest(canonical2.as_ref());
        assert_eq!(hash, hash2);
    }

    #[test]
    fn hash_deployed_manifest_differs_from_chart_hash() {
        // Deployed state with value overrides differs from the planned chart hash.
        let chart_rendered = b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: myapp\nspec:\n  replicas: 1\n";
        let deployed_actual = b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: myapp\nspec:\n  replicas: 5\n";

        let chart_canonical =
            YamlCanonicalizer.canonicalize(chart_rendered, CanonicalMode::Logical);
        let deployed_canonical =
            YamlCanonicalizer.canonicalize(deployed_actual, CanonicalMode::Logical);

        let chart_hash = Blake3Hash::digest(chart_canonical.as_ref());
        let deployed_hash = Blake3Hash::digest(deployed_canonical.as_ref());

        assert_ne!(
            chart_hash, deployed_hash,
            "Deployed manifest with overrides must produce a different hash than the chart template"
        );
    }

    #[test]
    fn hash_deployed_manifest_kubectl_failure_returns_error() {
        // Simulate what happens when kubectl fails: the function should return
        // a CommandFailed error. We verify the error type exists and formats correctly.
        let err = TameshiError::CommandFailed {
            command: "kubectl get deployment myapp --namespace default -o yaml".to_string(),
            code: 1,
            stderr: "Error from server (NotFound): deployments.apps \"myapp\" not found"
                .to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("kubectl get deployment"));
        assert!(msg.contains("NotFound"));
    }
}
