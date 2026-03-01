//! Signature types for infrastructure layer attestation.
//!
//! Each infrastructure layer produces a [`LayerSignature`] containing its
//! BLAKE3 hash plus metadata. Layer signatures compose into a [`MasterSignature`]
//! via Merkle tree construction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::hash::Blake3Hash;

/// Infrastructure layer types that produce signatures.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerType {
    /// Nix store closure
    Nix,
    /// OCI container image
    Oci,
    /// Helm chart + provenance
    Helm,
    /// OpenTofu/Terraform state
    Tofu,
    /// Kubernetes manifest set
    Kubernetes,
    /// Kindling identity/report
    Kindling,
    /// Tatara cluster state
    Tatara,
    /// FluxCD reconciliation state
    FluxCD,
    /// ArgoCD application state
    ArgoCD,
}

impl fmt::Display for LayerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerType::Nix => write!(f, "nix"),
            LayerType::Oci => write!(f, "oci"),
            LayerType::Helm => write!(f, "helm"),
            LayerType::Tofu => write!(f, "tofu"),
            LayerType::Kubernetes => write!(f, "kubernetes"),
            LayerType::Kindling => write!(f, "kindling"),
            LayerType::Tatara => write!(f, "tatara"),
            LayerType::FluxCD => write!(f, "fluxcd"),
            LayerType::ArgoCD => write!(f, "argocd"),
        }
    }
}

/// Metadata about how a hash was produced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMetadata {
    /// When the signature was computed.
    pub computed_at: DateTime<Utc>,
    /// Version of the collector that produced it.
    pub collector_version: String,
    /// Source identifier (e.g., store path, image ref, chart name).
    pub source: String,
    /// Optional environment label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

/// A single input that was hashed as part of a layer signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputHash {
    /// Human-readable identifier for the input.
    pub name: String,
    /// BLAKE3 hash of this individual input.
    pub hash: Blake3Hash,
    /// Size in bytes of the input (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// A hash signature for a single infrastructure layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerSignature {
    /// Which infrastructure layer this signature covers.
    pub layer: LayerType,
    /// BLAKE3 hash of the layer's content.
    pub hash: Blake3Hash,
    /// Metadata about computation.
    pub metadata: SignatureMetadata,
    /// Individual inputs that were hashed (for auditability).
    pub inputs: Vec<InputHash>,
}

impl LayerSignature {
    /// Create a new layer signature.
    pub fn new(
        layer: LayerType,
        hash: Blake3Hash,
        source: &str,
        inputs: Vec<InputHash>,
    ) -> Self {
        Self {
            layer,
            hash,
            metadata: SignatureMetadata {
                computed_at: Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").to_string(),
                source: source.to_string(),
                environment: None,
            },
            inputs,
        }
    }

    /// Set the environment label.
    pub fn with_environment(mut self, env: &str) -> Self {
        self.metadata.environment = Some(env.to_string());
        self
    }

    /// Recompute and verify the layer hash from inputs.
    pub fn verify_inputs(&self) -> bool {
        if self.inputs.is_empty() {
            return true; // No inputs to verify against
        }
        let mut sorted_inputs = self.inputs.clone();
        sorted_inputs.sort_by(|a, b| a.name.cmp(&b.name));

        let mut hasher_data = Vec::new();
        for input in &sorted_inputs {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let recomputed = Blake3Hash::digest(&hasher_data);
        recomputed == self.hash
    }
}

/// The composed master signature for an environment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasterSignature {
    /// Merkle root of all layer signatures (before compliance).
    pub untested: Blake3Hash,
    /// Hash of compliance test results (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<Blake3Hash>,
    /// BLAKE3(untested || compliance) — the final gating signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<Blake3Hash>,
    /// All layer signatures that composed this master.
    pub layers: Vec<LayerSignature>,
    /// When this master signature was computed.
    pub computed_at: DateTime<Utc>,
    /// Environment identifier (e.g., "production", "staging").
    pub environment: String,
}

impl MasterSignature {
    /// Create a new master signature from an untested Merkle root.
    pub fn new(untested: Blake3Hash, layers: Vec<LayerSignature>, environment: &str) -> Self {
        Self {
            untested,
            compliance: None,
            secure: None,
            layers,
            computed_at: Utc::now(),
            environment: environment.to_string(),
        }
    }

    /// Add compliance hash and compute the final secure signature.
    pub fn with_compliance(mut self, compliance_hash: Blake3Hash) -> Self {
        let secure = Blake3Hash::combine(&self.untested, &compliance_hash);
        self.compliance = Some(compliance_hash);
        self.secure = Some(secure);
        self
    }

    /// Verify the untested signature by recomputing the Merkle root.
    pub fn verify_untested(&self) -> bool {
        let recomputed = crate::merkle::compute_merkle_root(&self.layers);
        recomputed == self.untested
    }

    /// Verify the secure signature (untested + compliance).
    pub fn verify_secure(&self) -> bool {
        match (&self.compliance, &self.secure) {
            (Some(compliance), Some(secure)) => {
                let expected = Blake3Hash::combine(&self.untested, compliance);
                expected == *secure
            }
            _ => false,
        }
    }

    /// Check if this signature is fully attested (has compliance).
    pub fn is_fully_attested(&self) -> bool {
        self.compliance.is_some() && self.secure.is_some()
    }

    /// Get the effective gating signature.
    /// Returns secure if available, otherwise untested.
    pub fn gating_signature(&self) -> &Blake3Hash {
        self.secure.as_ref().unwrap_or(&self.untested)
    }

    /// Return prefixed string of the gating signature.
    pub fn gating_signature_prefixed(&self) -> String {
        self.gating_signature().to_prefixed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layer(layer: LayerType, data: &[u8]) -> LayerSignature {
        LayerSignature::new(layer, Blake3Hash::digest(data), "test", vec![])
    }

    #[test]
    fn master_signature_untested_only() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix-content"),
            make_layer(LayerType::Oci, b"oci-content"),
        ];
        let root = crate::merkle::compute_merkle_root(&layers);
        let master = MasterSignature::new(root, layers, "test");

        assert!(master.verify_untested());
        assert!(!master.is_fully_attested());
    }

    #[test]
    fn master_signature_with_compliance() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix-content"),
            make_layer(LayerType::Oci, b"oci-content"),
        ];
        let root = crate::merkle::compute_merkle_root(&layers);
        let compliance = Blake3Hash::digest(b"all-tests-passed");
        let master = MasterSignature::new(root, layers, "production").with_compliance(compliance);

        assert!(master.verify_untested());
        assert!(master.verify_secure());
        assert!(master.is_fully_attested());
    }
}
