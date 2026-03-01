//! OpenTofu/Terraform state collector.
//!
//! Computes BLAKE3 hashes of OpenTofu state files and plan outputs.
//! Ensures that the infrastructure state is deterministically attested.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// Hash an OpenTofu state file.
///
/// Reads the state JSON, sorts keys for deterministic hashing, and
/// computes BLAKE3 over the canonical representation.
pub async fn hash_state(state_path: &str) -> Result<LayerSignature> {
    let data = tokio::fs::read(state_path).await.map_err(|e| {
        TameshiError::CollectorError {
            layer: "tofu".to_string(),
            message: format!("failed to read state file {}: {}", state_path, e),
        }
    })?;

    // Parse and re-serialize to canonical JSON for deterministic hashing
    let state: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
            layer: "tofu".to_string(),
            message: format!("failed to parse state file {}: {}", state_path, e),
        })?;

    let canonical = serde_json::to_vec(&state)?;
    let state_hash = Blake3Hash::digest(&canonical);

    // Extract resource hashes for auditability
    let mut inputs = vec![InputHash {
        name: "state".to_string(),
        hash: state_hash.clone(),
        size_bytes: Some(canonical.len() as u64),
    }];

    // Hash individual resources from state
    if let Some(resources) = state.get("resources").and_then(|r| r.as_array()) {
        for resource in resources {
            let resource_type = resource
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            let resource_name = resource
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unnamed");
            let resource_json = serde_json::to_vec(resource)?;
            inputs.push(InputHash {
                name: format!("{}.{}", resource_type, resource_name),
                hash: Blake3Hash::digest(&resource_json),
                size_bytes: Some(resource_json.len() as u64),
            });
        }
    }

    debug!(
        state_path = state_path,
        resources = inputs.len() - 1,
        "Hashed OpenTofu state"
    );

    Ok(LayerSignature::new(
        LayerType::Tofu,
        state_hash,
        state_path,
        inputs,
    ))
}

/// Hash OpenTofu plan output.
///
/// Runs `tofu show -json <plan_file>` and hashes the output.
pub async fn hash_plan(plan_path: &str) -> Result<LayerSignature> {
    let output = Command::new("tofu")
        .args(["show", "-json", plan_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("tofu show -json {}", plan_path),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let plan_hash = Blake3Hash::digest(&output.stdout);
    let inputs = vec![InputHash {
        name: "plan".to_string(),
        hash: plan_hash.clone(),
        size_bytes: Some(output.stdout.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Tofu,
        plan_hash,
        plan_path,
        inputs,
    ))
}

/// Hash the remote state by pulling via `tofu state pull`.
pub async fn hash_remote_state(working_dir: &str) -> Result<LayerSignature> {
    let output = Command::new("tofu")
        .args(["state", "pull"])
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: "tofu state pull".to_string(),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    // Write to temp file and hash via hash_state
    let tmpfile = tempfile::NamedTempFile::new()?;
    tokio::fs::write(tmpfile.path(), &output.stdout).await?;
    hash_state(tmpfile.path().to_str().unwrap_or("/tmp/state.json")).await
}
