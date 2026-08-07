//! Kindling identity/report collector.
//!
//! Computes BLAKE3 hashes of Kindling cluster identity documents and
//! compliance reports. Kindling manages cluster identity and attestation.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use tracing::debug;

/// Hash a Kindling identity document.
///
/// Identity documents are JSON files containing cluster identity claims,
/// certificates, and attestation metadata.
pub async fn hash_identity(identity_path: &str) -> Result<LayerSignature> {
    let data = tokio::fs::read(identity_path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "kindling".to_string(),
            message: format!("failed to read identity document {}: {}", identity_path, e),
        })?;

    // Parse and re-serialize for canonical form
    let identity: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
            layer: "kindling".to_string(),
            message: format!("failed to parse identity document: {}", e),
        })?;

    let canonical = serde_json::to_vec(&identity)?;
    let hash = Blake3Hash::digest(&canonical);

    let mut inputs = vec![InputHash {
        name: "identity-document".to_string(),
        hash: hash.clone(),
        size_bytes: Some(canonical.len() as u64),
    }];

    // Extract certificate hashes if present
    if let Some(certs) = identity.get("certificates").and_then(|c| c.as_array()) {
        for (i, cert) in certs.iter().enumerate() {
            let cert_json = serde_json::to_vec(cert)?;
            inputs.push(InputHash {
                name: format!("certificate-{}", i),
                hash: Blake3Hash::digest(&cert_json),
                size_bytes: Some(cert_json.len() as u64),
            });
        }
    }

    debug!(
        path = identity_path,
        inputs = inputs.len(),
        "Hashed Kindling identity"
    );

    Ok(LayerSignature::new(
        LayerType::Kindling,
        hash,
        identity_path,
        inputs,
    ))
}

/// Hash a Kindling compliance report.
pub async fn hash_report(report_path: &str) -> Result<LayerSignature> {
    let data = tokio::fs::read(report_path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "kindling".to_string(),
            message: format!("failed to read report {}: {}", report_path, e),
        })?;

    let report: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
            layer: "kindling".to_string(),
            message: format!("failed to parse report: {}", e),
        })?;

    let canonical = serde_json::to_vec(&report)?;
    let hash = Blake3Hash::digest(&canonical);

    let inputs = vec![InputHash {
        name: "compliance-report".to_string(),
        hash: hash.clone(),
        size_bytes: Some(canonical.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Kindling,
        hash,
        report_path,
        inputs,
    ))
}

/// Hash Kindling identity from a Kubernetes secret.
///
/// Reads the identity from a K8s secret and hashes it.
pub async fn hash_identity_from_secret(
    namespace: &str,
    secret_name: &str,
) -> Result<LayerSignature> {
    let output = tokio::process::Command::new("kubectl")
        .args([
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.data}",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("kubectl get secret {} -n {}", secret_name, namespace),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let hash = Blake3Hash::digest(&output.stdout);
    let inputs = vec![InputHash {
        name: format!("{}/{}", namespace, secret_name),
        hash: hash.clone(),
        size_bytes: Some(output.stdout.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Kindling,
        hash,
        &format!("secret:{}/{}", namespace, secret_name),
        inputs,
    ))
}

/// Source for Kindling collection.
#[derive(Clone, Debug)]
pub enum KindlingSource {
    /// Hash a local identity document file.
    IdentityFile(String),
    /// Hash a compliance report file.
    ReportFile(String),
    /// Hash identity from a Kubernetes secret.
    K8sSecret {
        /// Kubernetes namespace.
        namespace: String,
        /// Secret name.
        secret_name: String,
    },
}

/// Kindling identity/report collector.
///
/// Wraps the standalone functions in a [`LayerCollector`] implementation.
pub struct KindlingCollector {
    /// Source to collect from.
    pub source: KindlingSource,
}

impl KindlingCollector {
    /// Create a collector for a local identity document.
    #[must_use]
    pub fn from_identity(identity_path: &str) -> Self {
        Self {
            source: KindlingSource::IdentityFile(identity_path.to_string()),
        }
    }

    /// Create a collector for a compliance report.
    #[must_use]
    pub fn from_report(report_path: &str) -> Self {
        Self {
            source: KindlingSource::ReportFile(report_path.to_string()),
        }
    }

    /// Create a collector for a Kubernetes secret.
    #[must_use]
    pub fn from_k8s_secret(namespace: &str, secret_name: &str) -> Self {
        Self {
            source: KindlingSource::K8sSecret {
                namespace: namespace.to_string(),
                secret_name: secret_name.to_string(),
            },
        }
    }
}

impl LayerCollector for KindlingCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            KindlingSource::IdentityFile(path) => hash_identity(path).await,
            KindlingSource::ReportFile(path) => hash_report(path).await,
            KindlingSource::K8sSecret {
                namespace,
                secret_name,
            } => hash_identity_from_secret(namespace, secret_name).await,
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Kindling
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_identity_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let identity = serde_json::json!({
            "cluster_id": "prod-east-1",
            "node_id": "node-001"
        });
        tokio::fs::write(&path, serde_json::to_vec(&identity).unwrap())
            .await
            .unwrap();

        let sig = hash_identity(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::Kindling);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "identity-document");
    }

    #[tokio::test]
    async fn hash_identity_with_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity_certs.json");
        let identity = serde_json::json!({
            "cluster_id": "prod-east-1",
            "certificates": [
                {"cn": "node-001", "issuer": "ca-root"},
                {"cn": "node-002", "issuer": "ca-root"}
            ]
        });
        tokio::fs::write(&path, serde_json::to_vec(&identity).unwrap())
            .await
            .unwrap();

        let sig = hash_identity(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.inputs.len(), 3, "1 identity + 2 certificates");
        assert_eq!(sig.inputs[1].name, "certificate-0");
        assert_eq!(sig.inputs[2].name, "certificate-1");
    }

    #[tokio::test]
    async fn hash_identity_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let identity = serde_json::json!({"cluster_id": "test"});
        tokio::fs::write(&path, serde_json::to_vec(&identity).unwrap())
            .await
            .unwrap();

        let sig1 = hash_identity(path.to_str().unwrap()).await.unwrap();
        let sig2 = hash_identity(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[tokio::test]
    async fn hash_identity_missing_file() {
        let result = hash_identity("/nonexistent/identity.json").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hash_identity_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        tokio::fs::write(&path, b"not valid json!").await.unwrap();

        let result = hash_identity(path.to_str().unwrap()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hash_report_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let report = serde_json::json!({
            "status": "compliant",
            "checks_passed": 42
        });
        tokio::fs::write(&path, serde_json::to_vec(&report).unwrap())
            .await
            .unwrap();

        let sig = hash_report(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::Kindling);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "compliance-report");
    }

    #[tokio::test]
    async fn hash_report_missing_file() {
        let result = hash_report("/nonexistent/report.json").await;
        assert!(result.is_err());
    }

    #[test]
    fn kindling_collector_from_identity() {
        let c = KindlingCollector::from_identity("/path/to/identity.json");
        assert!(matches!(c.source, KindlingSource::IdentityFile(_)));
        assert_eq!(c.layer_type(), LayerType::Kindling);
    }

    #[test]
    fn kindling_collector_from_report() {
        let c = KindlingCollector::from_report("/path/to/report.json");
        assert!(matches!(c.source, KindlingSource::ReportFile(_)));
    }

    #[test]
    fn kindling_collector_from_k8s_secret() {
        let c = KindlingCollector::from_k8s_secret("kube-system", "kindling-identity");
        assert!(matches!(c.source, KindlingSource::K8sSecret { .. }));
    }

    #[test]
    fn kindling_source_clone_debug() {
        let source = KindlingSource::IdentityFile("/path".to_string());
        let cloned = source.clone();
        assert!(format!("{:?}", cloned).contains("IdentityFile"));
    }
}
