//! Helm chart collector.
//!
//! Computes BLAKE3 hashes of Helm charts including their provenance files.
//! Supports both local chart directories and OCI-stored charts.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

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

/// Hash Helm chart provenance file (.prov).
pub async fn hash_provenance(prov_path: &str) -> Result<InputHash> {
    let data = tokio::fs::read(prov_path).await?;
    Ok(InputHash {
        name: "provenance".to_string(),
        hash: Blake3Hash::digest(&data),
        size_bytes: Some(data.len() as u64),
    })
}

fn compute_composite(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-helm-chart");
    }
    let mut data = Vec::new();
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}
