//! OpenTofu/Terraform state collector.
//!
//! Computes BLAKE3 hashes of OpenTofu state files and plan outputs.
//! Ensures that the infrastructure state is deterministically attested.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

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

/// Source for OpenTofu/Terraform state collection.
#[derive(Clone, Debug)]
pub enum TofuSource {
    /// Hash a local state file.
    StateFile(String),
    /// Hash a plan file.
    PlanFile(String),
    /// Hash remote state by pulling from the working directory.
    RemoteState(String),
}

/// OpenTofu/Terraform state collector.
///
/// Wraps the standalone functions in a [`LayerCollector`] implementation.
pub struct TofuCollector {
    /// Source to collect from.
    pub source: TofuSource,
}

impl TofuCollector {
    /// Create a collector for a local state file.
    #[must_use]
    pub fn from_state(state_path: &str) -> Self {
        Self {
            source: TofuSource::StateFile(state_path.to_string()),
        }
    }

    /// Create a collector for a plan file.
    #[must_use]
    pub fn from_plan(plan_path: &str) -> Self {
        Self {
            source: TofuSource::PlanFile(plan_path.to_string()),
        }
    }

    /// Create a collector for remote state.
    #[must_use]
    pub fn from_remote(working_dir: &str) -> Self {
        Self {
            source: TofuSource::RemoteState(working_dir.to_string()),
        }
    }
}

impl LayerCollector for TofuCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            TofuSource::StateFile(path) => hash_state(path).await,
            TofuSource::PlanFile(path) => hash_plan(path).await,
            TofuSource::RemoteState(dir) => hash_remote_state(dir).await,
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Tofu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_state_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terraform.tfstate");
        let state = serde_json::json!({
            "version": 4,
            "serial": 1,
            "lineage": "abc-123"
        });
        tokio::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).await.unwrap();

        let sig = hash_state(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.layer, LayerType::Tofu);
        assert_eq!(sig.inputs.len(), 1);
        assert_eq!(sig.inputs[0].name, "state");
    }

    #[tokio::test]
    async fn hash_state_with_resources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terraform.tfstate");
        let state = serde_json::json!({
            "version": 4,
            "resources": [
                {"type": "aws_instance", "name": "web"},
                {"type": "aws_s3_bucket", "name": "data"}
            ]
        });
        tokio::fs::write(&path, serde_json::to_vec(&state).unwrap()).await.unwrap();

        let sig = hash_state(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.inputs.len(), 3, "1 state + 2 resources");
        assert_eq!(sig.inputs[1].name, "aws_instance.web");
        assert_eq!(sig.inputs[2].name, "aws_s3_bucket.data");
    }

    #[tokio::test]
    async fn hash_state_resource_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terraform.tfstate");
        let state = serde_json::json!({
            "resources": [
                {"other_field": "value"},
                {"type": "aws_vpc"}
            ]
        });
        tokio::fs::write(&path, serde_json::to_vec(&state).unwrap()).await.unwrap();

        let sig = hash_state(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig.inputs.len(), 3);
        assert_eq!(sig.inputs[1].name, "unknown.unnamed");
        assert_eq!(sig.inputs[2].name, "aws_vpc.unnamed");
    }

    #[tokio::test]
    async fn hash_state_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terraform.tfstate");
        let state = serde_json::json!({"version": 4, "serial": 1});
        tokio::fs::write(&path, serde_json::to_vec(&state).unwrap()).await.unwrap();

        let sig1 = hash_state(path.to_str().unwrap()).await.unwrap();
        let sig2 = hash_state(path.to_str().unwrap()).await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[tokio::test]
    async fn hash_state_missing_file() {
        let result = hash_state("/nonexistent/terraform.tfstate").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hash_state_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.tfstate");
        tokio::fs::write(&path, b"not valid json!!").await.unwrap();

        let result = hash_state(path.to_str().unwrap()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hash_state_changed_content_different_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("state1.json");
        let path2 = dir.path().join("state2.json");
        let state1 = serde_json::json!({"version": 4, "serial": 1});
        let state2 = serde_json::json!({"version": 4, "serial": 2});
        tokio::fs::write(&path1, serde_json::to_vec(&state1).unwrap()).await.unwrap();
        tokio::fs::write(&path2, serde_json::to_vec(&state2).unwrap()).await.unwrap();

        let sig1 = hash_state(path1.to_str().unwrap()).await.unwrap();
        let sig2 = hash_state(path2.to_str().unwrap()).await.unwrap();
        assert_ne!(sig1.hash, sig2.hash);
    }

    #[test]
    fn tofu_collector_from_state() {
        let c = TofuCollector::from_state("/path/terraform.tfstate");
        assert!(matches!(c.source, TofuSource::StateFile(_)));
        assert_eq!(c.layer_type(), LayerType::Tofu);
    }

    #[test]
    fn tofu_collector_from_plan() {
        let c = TofuCollector::from_plan("/path/plan.out");
        assert!(matches!(c.source, TofuSource::PlanFile(_)));
    }

    #[test]
    fn tofu_collector_from_remote() {
        let c = TofuCollector::from_remote("/project/dir");
        assert!(matches!(c.source, TofuSource::RemoteState(_)));
    }

    #[test]
    fn tofu_source_clone_debug() {
        let source = TofuSource::StateFile("/path".to_string());
        let cloned = source.clone();
        assert!(format!("{:?}", cloned).contains("StateFile"));
    }
}
