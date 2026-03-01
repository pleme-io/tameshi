//! Kindling identity/report collector.
//!
//! Computes BLAKE3 hashes of Kindling cluster identity documents and
//! compliance reports. Kindling manages cluster identity and attestation.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

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
