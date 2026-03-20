//! Signature types for infrastructure layer attestation.
//!
//! Each infrastructure layer produces a [`LayerSignature`] containing its
//! BLAKE3 hash plus metadata. Layer signatures compose into a [`MasterSignature`]
//! via Merkle tree construction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::hash::Blake3Hash;

/// Infrastructure layer types that produce signatures.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// Akeyless secret management
    Akeyless,
    /// Akeyless target infrastructure
    #[serde(rename = "akeyless_target")]
    AkeylessTarget,
    /// Pangea synthesis output (deterministic Terraform JSON).
    #[serde(rename = "pangea_synthesis")]
    PangeaSynthesis,
    /// RSpec test result JSON.
    #[serde(rename = "rspec_result")]
    RSpecResult,
    /// InSpec compliance result JSON.
    #[serde(rename = "inspec_result")]
    InSpecResult,
}

impl fmt::Display for LayerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nix => write!(f, "nix"),
            Self::Oci => write!(f, "oci"),
            Self::Helm => write!(f, "helm"),
            Self::Tofu => write!(f, "tofu"),
            Self::Kubernetes => write!(f, "kubernetes"),
            Self::Kindling => write!(f, "kindling"),
            Self::Tatara => write!(f, "tatara"),
            Self::FluxCD => write!(f, "fluxcd"),
            Self::ArgoCD => write!(f, "argocd"),
            Self::Akeyless => write!(f, "akeyless"),
            Self::AkeylessTarget => write!(f, "akeyless_target"),
            Self::PangeaSynthesis => write!(f, "pangea_synthesis"),
            Self::RSpecResult => write!(f, "rspec_result"),
            Self::InSpecResult => write!(f, "inspec_result"),
        }
    }
}

impl FromStr for LayerType {
    type Err = crate::error::TameshiError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nix" => Ok(Self::Nix),
            "oci" => Ok(Self::Oci),
            "helm" => Ok(Self::Helm),
            "tofu" | "terraform" => Ok(Self::Tofu),
            "kubernetes" | "k8s" => Ok(Self::Kubernetes),
            "kindling" => Ok(Self::Kindling),
            "tatara" => Ok(Self::Tatara),
            "fluxcd" | "flux" => Ok(Self::FluxCD),
            "argocd" | "argo" => Ok(Self::ArgoCD),
            "akeyless" => Ok(Self::Akeyless),
            "akeyless_target" | "akeylesstarget" => Ok(Self::AkeylessTarget),
            "pangea_synthesis" | "pangeasynthesis" | "pangea" => Ok(Self::PangeaSynthesis),
            "rspec_result" | "rspecresult" | "rspec" => Ok(Self::RSpecResult),
            "inspec_result" | "inspecresult" => Ok(Self::InSpecResult),
            other => Err(crate::error::TameshiError::InvalidInput(format!(
                "unknown layer type: '{other}'"
            ))),
        }
    }
}

impl<'a> TryFrom<&'a str> for LayerType {
    type Error = crate::error::TameshiError;

    /// Parse a layer type string into a `LayerType`.
    fn try_from(s: &'a str) -> std::result::Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Vec<LayerSignature>> for MasterSignature {
    /// Create a `MasterSignature` from a list of layer signatures using a default environment.
    ///
    /// Computes the Merkle root and creates an untested master signature with environment "default".
    fn from(layers: Vec<LayerSignature>) -> Self {
        let root = crate::merkle::compute_merkle_root(&layers);
        Self::new(root, layers, "default")
    }
}

/// Metadata about how a hash was produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[must_use]
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
    #[must_use]
    pub fn with_environment(mut self, env: &str) -> Self {
        self.metadata.environment = Some(env.to_string());
        self
    }

    /// Recompute and verify the layer hash from inputs.
    #[must_use]
    pub fn verify_inputs(&self) -> bool {
        if self.inputs.is_empty() {
            return true; // No inputs to verify against
        }
        let mut sorted_inputs = self.inputs.clone();
        sorted_inputs.sort_by(|a, b| a.name.cmp(&b.name));

        let mut hasher_data = Vec::with_capacity(sorted_inputs.len() * 32);
        for input in &sorted_inputs {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let recomputed = Blake3Hash::digest(&hasher_data);
        recomputed == self.hash
    }
}

/// The composed master signature for an environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// Optional certification artifacts for per-binary provenance.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub certification_artifacts: Vec<crate::certification_artifact::CertificationArtifact>,
}

impl MasterSignature {
    /// Create a new master signature from an untested Merkle root.
    #[must_use]
    pub fn new(untested: Blake3Hash, layers: Vec<LayerSignature>, environment: &str) -> Self {
        Self {
            untested,
            compliance: None,
            secure: None,
            layers,
            computed_at: Utc::now(),
            environment: environment.to_string(),
            certification_artifacts: Vec::new(),
        }
    }

    /// Add compliance hash and compute the final secure signature.
    #[must_use]
    pub fn with_compliance(mut self, compliance_hash: Blake3Hash) -> Self {
        let secure = Blake3Hash::combine(&self.untested, &compliance_hash);
        self.compliance = Some(compliance_hash);
        self.secure = Some(secure);
        self
    }

    /// Attach per-binary certification artifacts.
    #[must_use]
    pub fn with_certification_artifacts(
        mut self,
        artifacts: Vec<crate::certification_artifact::CertificationArtifact>,
    ) -> Self {
        self.certification_artifacts = artifacts;
        self
    }

    /// Verify the untested signature by recomputing the Merkle root.
    #[inline]
    #[must_use]
    pub fn verify_untested(&self) -> bool {
        let recomputed = crate::merkle::compute_merkle_root(&self.layers);
        recomputed == self.untested
    }

    /// Verify the secure signature (untested + compliance).
    #[inline]
    #[must_use]
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
    #[inline]
    #[must_use]
    pub fn is_fully_attested(&self) -> bool {
        self.compliance.is_some() && self.secure.is_some()
    }

    /// Get the effective gating signature.
    /// Returns secure if available, otherwise untested.
    #[inline]
    #[must_use]
    pub fn gating_signature(&self) -> &Blake3Hash {
        self.secure.as_ref().unwrap_or(&self.untested)
    }

    /// Return prefixed string of the gating signature.
    #[inline]
    #[must_use]
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

    #[test]
    fn layer_type_from_str() {
        assert_eq!("nix".parse::<LayerType>().unwrap(), LayerType::Nix);
        assert_eq!("oci".parse::<LayerType>().unwrap(), LayerType::Oci);
        assert_eq!("terraform".parse::<LayerType>().unwrap(), LayerType::Tofu);
        assert_eq!("k8s".parse::<LayerType>().unwrap(), LayerType::Kubernetes);
        assert_eq!("flux".parse::<LayerType>().unwrap(), LayerType::FluxCD);
        assert_eq!("argo".parse::<LayerType>().unwrap(), LayerType::ArgoCD);
        assert!("unknown_type".parse::<LayerType>().is_err());
    }

    #[test]
    fn layer_type_display_roundtrip() {
        let types = vec![
            LayerType::Nix,
            LayerType::Oci,
            LayerType::Helm,
            LayerType::Tofu,
            LayerType::Kubernetes,
            LayerType::Kindling,
            LayerType::Tatara,
            LayerType::FluxCD,
            LayerType::ArgoCD,
            LayerType::Akeyless,
            LayerType::AkeylessTarget,
            LayerType::PangeaSynthesis,
            LayerType::RSpecResult,
            LayerType::InSpecResult,
        ];
        for lt in types {
            let s = lt.to_string();
            let parsed: LayerType = s.parse().unwrap();
            assert_eq!(lt, parsed);
        }
    }

    #[test]
    fn layer_signature_serde_roundtrip() {
        let sig = make_layer(LayerType::Helm, b"helm-data");
        let json = serde_json::to_string(&sig).unwrap();
        let deserialized: LayerSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.layer, deserialized.layer);
        assert_eq!(sig.hash, deserialized.hash);
    }

    #[test]
    fn master_signature_serde_roundtrip() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        let root = crate::merkle::compute_merkle_root(&layers);
        let compliance = Blake3Hash::digest(b"compliance");
        let master = MasterSignature::new(root, layers, "prod").with_compliance(compliance);

        let json = serde_json::to_string(&master).unwrap();
        let deserialized: MasterSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(master.untested, deserialized.untested);
        assert_eq!(master.secure, deserialized.secure);
        assert_eq!(master.environment, deserialized.environment);
    }

    #[test]
    fn layer_signature_with_environment() {
        let sig = make_layer(LayerType::Nix, b"nix")
            .with_environment("production");
        assert_eq!(sig.metadata.environment, Some("production".to_string()));
    }

    #[test]
    fn layer_signature_verify_inputs_empty() {
        let sig = make_layer(LayerType::Nix, b"nix");
        assert!(sig.verify_inputs()); // No inputs = trivially valid
    }

    #[test]
    fn layer_signature_verify_inputs_valid() {
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
        // Compute the expected composite hash from sorted inputs
        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut data = Vec::new();
        for input in &sorted {
            data.extend_from_slice(&input.hash.0);
        }
        let composite = Blake3Hash::digest(&data);

        let sig = LayerSignature::new(LayerType::Nix, composite, "test", inputs);
        assert!(sig.verify_inputs());
    }

    #[test]
    fn master_signature_verify_secure_without_compliance() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let root = crate::merkle::compute_merkle_root(&layers);
        let master = MasterSignature::new(root, layers, "test");
        assert!(!master.verify_secure()); // No compliance = cannot verify secure
    }

    #[test]
    fn master_signature_gating_signature_prefixed() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let root = crate::merkle::compute_merkle_root(&layers);
        let master = MasterSignature::new(root, layers, "test");
        let prefixed = master.gating_signature_prefixed();
        assert!(prefixed.starts_with("blake3:"));
        assert_eq!(prefixed.len(), 71); // "blake3:" (7) + 64 hex chars
    }

    #[test]
    fn input_hash_serde_roundtrip() {
        let input = InputHash {
            name: "test-input".to_string(),
            hash: Blake3Hash::digest(b"data"),
            size_bytes: Some(1024),
        };
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: InputHash = serde_json::from_str(&json).unwrap();
        assert_eq!(input, deserialized);
    }

    // -- From/TryFrom conversion tests --

    #[test]
    fn layer_type_try_from_str() {
        let lt: LayerType = "nix".try_into().unwrap();
        assert_eq!(lt, LayerType::Nix);

        let lt: LayerType = "k8s".try_into().unwrap();
        assert_eq!(lt, LayerType::Kubernetes);

        let lt: LayerType = "terraform".try_into().unwrap();
        assert_eq!(lt, LayerType::Tofu);

        let result: std::result::Result<LayerType, _> = "invalid_layer".try_into();
        assert!(result.is_err());
    }

    #[test]
    fn master_signature_from_vec_layers() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix-content"),
            make_layer(LayerType::Oci, b"oci-content"),
        ];
        let master: MasterSignature = layers.into();
        assert_eq!(master.environment, "default");
        assert!(master.verify_untested());
        assert_eq!(master.layers.len(), 2);
    }

    // -- Property-based tests --

    #[test]
    fn layer_type_ordering_is_total() {
        // Verify all layer types have a total order
        let types = vec![
            LayerType::Nix, LayerType::Oci, LayerType::Helm,
            LayerType::Tofu, LayerType::Kubernetes, LayerType::Kindling,
            LayerType::Tatara, LayerType::FluxCD, LayerType::ArgoCD,
            LayerType::Akeyless, LayerType::AkeylessTarget,
            LayerType::PangeaSynthesis, LayerType::RSpecResult,
            LayerType::InSpecResult,
        ];
        for i in 0..types.len() {
            for j in 0..types.len() {
                // Verify that cmp is well-defined (no panic)
                let _ = types[i].cmp(&types[j]);
            }
        }
    }

    #[test]
    fn master_signature_gating_prefers_secure() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let root = crate::merkle::compute_merkle_root(&layers);
        let compliance = Blake3Hash::digest(b"compliance");
        let master = MasterSignature::new(root.clone(), layers, "test")
            .with_compliance(compliance.clone());
        let secure = Blake3Hash::combine(&root, &compliance);
        assert_eq!(*master.gating_signature(), secure);
    }

    #[test]
    fn master_signature_gating_fallback_to_untested() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let root = crate::merkle::compute_merkle_root(&layers);
        let master = MasterSignature::new(root.clone(), layers, "test");
        assert_eq!(*master.gating_signature(), root);
    }

    #[test]
    fn layer_signature_verify_inputs_mismatch() {
        let inputs = vec![InputHash {
            name: "a".to_string(),
            hash: Blake3Hash::digest(b"a"),
            size_bytes: None,
        }];
        // Use a wrong composite hash
        let wrong_hash = Blake3Hash::digest(b"wrong");
        let sig = LayerSignature::new(LayerType::Nix, wrong_hash, "test", inputs);
        assert!(!sig.verify_inputs(), "Mismatched inputs should fail verification");
    }
}
