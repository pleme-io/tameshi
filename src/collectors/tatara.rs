//! Tatara cluster state collector.
//!
//! Computes BLAKE3 hashes of Tatara cluster allocation state,
//! job specifications, and node configurations. Tatara manages
//! distributed compute allocation.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use super::traits::LayerCollector;

use tracing::debug;

/// Hash the current Tatara cluster state.
///
/// Reads the cluster state from the Tatara API or a state file,
/// canonicalizes it, and computes the BLAKE3 hash.
pub async fn hash_cluster_state(state_path: &str) -> Result<LayerSignature> {
    let data = tokio::fs::read(state_path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "tatara".to_string(),
            message: format!("failed to read cluster state {}: {}", state_path, e),
        })?;

    let state: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
            layer: "tatara".to_string(),
            message: format!("failed to parse cluster state: {}", e),
        })?;

    let canonical = serde_json::to_vec(&state)?;
    let hash = Blake3Hash::digest(&canonical);

    let mut inputs = vec![InputHash {
        name: "cluster-state".to_string(),
        hash: hash.clone(),
        size_bytes: Some(canonical.len() as u64),
    }];

    // Extract individual node states
    if let Some(nodes) = state.get("nodes").and_then(|n| n.as_array()) {
        for node in nodes {
            let node_id = node
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("unknown");
            let node_json = serde_json::to_vec(node)?;
            inputs.push(InputHash {
                name: format!("node-{}", node_id),
                hash: Blake3Hash::digest(&node_json),
                size_bytes: Some(node_json.len() as u64),
            });
        }
    }

    // Extract allocation state
    if let Some(allocations) = state.get("allocations").and_then(|a| a.as_array()) {
        for alloc in allocations {
            let alloc_id = alloc
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("unknown");
            let alloc_json = serde_json::to_vec(alloc)?;
            inputs.push(InputHash {
                name: format!("allocation-{}", alloc_id),
                hash: Blake3Hash::digest(&alloc_json),
                size_bytes: Some(alloc_json.len() as u64),
            });
        }
    }

    debug!(
        state_path = state_path,
        inputs = inputs.len(),
        "Hashed Tatara cluster state"
    );

    Ok(LayerSignature::new(
        LayerType::Tatara,
        hash,
        state_path,
        inputs,
    ))
}

/// Hash Tatara cluster state from the API.
pub async fn hash_cluster_from_api(api_url: &str) -> Result<LayerSignature> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/state", api_url))
        .send()
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "tatara".to_string(),
            message: format!("failed to fetch cluster state from {}: {}", api_url, e),
        })?;

    let state: serde_json::Value = resp.json().await.map_err(|e| TameshiError::CollectorError {
        layer: "tatara".to_string(),
        message: format!("failed to parse cluster state response: {}", e),
    })?;

    let canonical = serde_json::to_vec(&state)?;
    let hash = Blake3Hash::digest(&canonical);

    let inputs = vec![InputHash {
        name: "cluster-state-api".to_string(),
        hash: hash.clone(),
        size_bytes: Some(canonical.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Tatara,
        hash,
        api_url,
        inputs,
    ))
}

/// Hash a Tatara job specification.
///
/// Job specs must include a valid signature for gated execution.
pub async fn hash_job_spec(spec_path: &str) -> Result<LayerSignature> {
    let data = tokio::fs::read(spec_path)
        .await
        .map_err(|e| TameshiError::CollectorError {
            layer: "tatara".to_string(),
            message: format!("failed to read job spec {}: {}", spec_path, e),
        })?;

    let spec: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| TameshiError::CollectorError {
            layer: "tatara".to_string(),
            message: format!("failed to parse job spec: {}", e),
        })?;

    let canonical = serde_json::to_vec(&spec)?;
    let hash = Blake3Hash::digest(&canonical);

    let inputs = vec![InputHash {
        name: "job-spec".to_string(),
        hash: hash.clone(),
        size_bytes: Some(canonical.len() as u64),
    }];

    Ok(LayerSignature::new(
        LayerType::Tatara,
        hash,
        spec_path,
        inputs,
    ))
}

/// Source for Tatara state collection.
#[derive(Clone, Debug)]
pub enum TataraSource {
    /// Hash cluster state from a local file.
    StateFile(String),
    /// Hash cluster state from the Tatara API.
    Api(String),
    /// Hash a job specification file.
    JobSpec(String),
}

/// Tatara cluster state collector.
///
/// Wraps the standalone functions in a [`LayerCollector`] implementation.
pub struct TataraCollector {
    /// Source to collect from.
    pub source: TataraSource,
}

impl TataraCollector {
    /// Create a collector for a local cluster state file.
    #[must_use]
    pub fn from_state(state_path: &str) -> Self {
        Self {
            source: TataraSource::StateFile(state_path.to_string()),
        }
    }

    /// Create a collector for the Tatara API.
    #[must_use]
    pub fn from_api(api_url: &str) -> Self {
        Self {
            source: TataraSource::Api(api_url.to_string()),
        }
    }

    /// Create a collector for a job specification.
    #[must_use]
    pub fn from_job_spec(spec_path: &str) -> Self {
        Self {
            source: TataraSource::JobSpec(spec_path.to_string()),
        }
    }
}

impl LayerCollector for TataraCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        match &self.source {
            TataraSource::StateFile(path) => hash_cluster_state(path).await,
            TataraSource::Api(url) => hash_cluster_from_api(url).await,
            TataraSource::JobSpec(path) => hash_job_spec(path).await,
        }
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Tatara
    }
}
