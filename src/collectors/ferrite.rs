//! Ferrite Proof of Memory Safety (PoMS) collector.
//!
//! Ingests PoMS JSON artifacts from ferrite-check and produces a
//! [`LayerSignature`] for the Ferrite memory safety attestation layer.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Ferrite PoMS artifact (deserialized from JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PomsArtifact {
    pub version: String,
    pub tool: String,
    pub tool_version: String,
    #[serde(default)]
    pub target: PomsTarget,
    #[serde(default)]
    pub analysis: PomsAnalysis,
    #[serde(default)]
    pub hashes: PomsHashes,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PomsTarget {
    #[serde(default)]
    pub module: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PomsAnalysis {
    #[serde(default)]
    pub allocations_tracked: usize,
    #[serde(default)]
    pub violations_detected: usize,
    #[serde(default)]
    pub rules_enforced: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PomsHashes {
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub source_hash: String,
    #[serde(default)]
    pub ast_hash: String,
    #[serde(default)]
    pub program_hash: String,
}

/// Collector that produces a [`LayerSignature`] from a Ferrite PoMS artifact.
#[derive(Debug)]
pub struct FerriteCollector {
    pub artifact: PomsArtifact,
}

impl FerriteCollector {
    #[must_use]
    pub fn new(artifact: PomsArtifact) -> Self {
        Self { artifact }
    }

    /// Create a collector from PoMS JSON bytes.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        let artifact: PomsArtifact = serde_json::from_slice(json).map_err(|e| {
            crate::error::TameshiError::InvalidInput(format!("invalid PoMS JSON: {e}"))
        })?;

        if artifact.analysis.violations_detected > 0 {
            return Err(crate::error::TameshiError::InvalidInput(format!(
                "PoMS artifact has {} violations — cannot attest",
                artifact.analysis.violations_detected
            )));
        }

        Ok(Self { artifact })
    }

    fn compute_hash(&self) -> Blake3Hash {
        let canonical = serde_json::to_string(&self.artifact).unwrap_or_default();
        Blake3Hash::digest(canonical.as_bytes())
    }
}

impl LayerCollector for FerriteCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let hash = self.compute_hash();

        let mut inputs = Vec::new();

        if !self.artifact.hashes.source_hash.is_empty() {
            inputs.push(InputHash {
                name: "source_hash".into(),
                hash: Blake3Hash::digest(self.artifact.hashes.source_hash.as_bytes()),
                size_bytes: None,
            });
        }
        if !self.artifact.hashes.ast_hash.is_empty() {
            inputs.push(InputHash {
                name: "ast_hash".into(),
                hash: Blake3Hash::digest(self.artifact.hashes.ast_hash.as_bytes()),
                size_bytes: None,
            });
        }
        if !self.artifact.hashes.program_hash.is_empty() {
            inputs.push(InputHash {
                name: "program_hash".into(),
                hash: Blake3Hash::digest(self.artifact.hashes.program_hash.as_bytes()),
                size_bytes: None,
            });
        }

        Ok(LayerSignature {
            layer: LayerType::FerritePoms,
            hash,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.artifact.target.module.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::FerritePoms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_poms_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "1.0.0",
            "tool": "ferrite-check",
            "tool_version": "0.1.0",
            "target": { "module": "github.com/example/service" },
            "analysis": {
                "allocations_tracked": 47,
                "violations_detected": 0,
                "rules_enforced": ["linear_typing", "temporal_safety", "borrow_containment"]
            },
            "hashes": {
                "algorithm": "SHA-256",
                "source_hash": "abc123",
                "ast_hash": "def456",
                "program_hash": "789ghi"
            }
        }))
        .unwrap()
    }

    #[test]
    fn parse_poms_json() {
        let collector = FerriteCollector::from_json(&sample_poms_json()).unwrap();
        assert_eq!(collector.artifact.tool, "ferrite-check");
        assert_eq!(collector.artifact.analysis.allocations_tracked, 47);
        assert_eq!(collector.artifact.analysis.violations_detected, 0);
    }

    #[test]
    fn reject_poms_with_violations() {
        let json = serde_json::to_vec(&serde_json::json!({
            "version": "1.0.0",
            "tool": "ferrite-check",
            "tool_version": "0.1.0",
            "analysis": { "violations_detected": 3 }
        }))
        .unwrap();
        assert!(FerriteCollector::from_json(&json).is_err());
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = FerriteCollector::from_json(&sample_poms_json()).unwrap();
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::FerritePoms);
        assert_eq!(sig.metadata.source, "github.com/example/service");
        assert_eq!(sig.inputs.len(), 3);
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let collector = FerriteCollector::from_json(&sample_poms_json()).unwrap();
        let sig1 = collector.collect().await.unwrap();
        let sig2 = collector.collect().await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[test]
    fn layer_type_is_ferrite_poms() {
        let collector = FerriteCollector::from_json(&sample_poms_json()).unwrap();
        assert_eq!(collector.layer_type(), LayerType::FerritePoms);
    }

    #[tokio::test]
    async fn collect_with_empty_hashes_produces_no_inputs() {
        let json = serde_json::to_vec(&serde_json::json!({
            "version": "1.0.0",
            "tool": "ferrite-check",
            "tool_version": "0.1.0",
            "analysis": { "violations_detected": 0 }
        }))
        .unwrap();
        let collector = FerriteCollector::from_json(&json).unwrap();
        let sig = collector.collect().await.unwrap();
        assert!(sig.inputs.is_empty());
    }

    #[test]
    fn display_and_parse_roundtrip() {
        let display = LayerType::FerritePoms.to_string();
        assert_eq!(display, "ferrite_poms");
        let parsed: LayerType = display.parse().unwrap();
        assert_eq!(parsed, LayerType::FerritePoms);
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(
            "ferrite".parse::<LayerType>().unwrap(),
            LayerType::FerritePoms
        );
        assert_eq!("poms".parse::<LayerType>().unwrap(), LayerType::FerritePoms);
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&LayerType::FerritePoms).unwrap();
        assert_eq!(json, "\"ferrite_poms\"");
        let parsed: LayerType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, LayerType::FerritePoms);
    }
}
