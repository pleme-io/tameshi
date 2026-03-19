//! Mock collector for testing.
//!
//! Provides a [`MockCollector`] that returns pre-configured results,
//! allowing deterministic testing of the attestation pipeline without
//! requiring real infrastructure tools.

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Mock collector that returns pre-configured results for testing.
///
/// By default, returns a deterministic signature based on the layer type.
/// Use [`MockCollector::set_result`] to inject a custom result for the
/// next `collect()` call.
pub struct MockCollector {
    layer_type: LayerType,
    result: std::sync::Mutex<Option<Result<LayerSignature>>>,
    default_signature: LayerSignature,
}

impl MockCollector {
    /// Create a new mock collector for the given layer type.
    ///
    /// The default signature is deterministic based on the layer type name.
    #[must_use]
    pub fn new(layer_type: LayerType) -> Self {
        let default_signature = LayerSignature {
            layer: layer_type.clone(),
            hash: Blake3Hash::digest(format!("mock-{layer_type}").as_bytes()),
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: "mock-0.1.0".to_string(),
                source: "mock".to_string(),
                environment: None,
            },
            inputs: vec![InputHash {
                name: "mock-input".to_string(),
                hash: Blake3Hash::digest(b"mock-input-data"),
                size_bytes: Some(1024),
            }],
        };
        Self {
            layer_type,
            result: std::sync::Mutex::new(None),
            default_signature,
        }
    }

    /// Set a custom result to return on the next `collect()` call.
    ///
    /// The result is consumed (taken) on the next call, after which the
    /// collector reverts to returning the default signature.
    pub fn set_result(&self, result: Result<LayerSignature>) {
        *self.result.lock().unwrap() = Some(result);
    }

    /// Create a mock with a specific signature to return.
    #[must_use]
    pub fn with_signature(layer_type: LayerType, signature: LayerSignature) -> Self {
        Self {
            layer_type,
            result: std::sync::Mutex::new(None),
            default_signature: signature,
        }
    }
}

impl LayerCollector for MockCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        if let Some(result) = self.result.lock().unwrap().take() {
            return result;
        }
        Ok(self.default_signature.clone())
    }

    fn layer_type(&self) -> LayerType {
        self.layer_type.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TameshiError;

    #[tokio::test]
    async fn mock_collector_returns_default_signature() {
        let collector = MockCollector::new(LayerType::Nix);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::Nix);
        assert_eq!(sig.metadata.source, "mock");
    }

    #[tokio::test]
    async fn mock_collector_returns_custom_result() {
        let collector = MockCollector::new(LayerType::Oci);
        let custom_sig = LayerSignature::new(
            LayerType::Oci,
            Blake3Hash::digest(b"custom"),
            "custom-source",
            vec![],
        );
        collector.set_result(Ok(custom_sig.clone()));
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.metadata.source, "custom-source");

        // Second call returns default
        let sig2 = collector.collect().await.unwrap();
        assert_eq!(sig2.metadata.source, "mock");
    }

    #[tokio::test]
    async fn mock_collector_returns_error() {
        let collector = MockCollector::new(LayerType::Helm);
        collector.set_result(Err(TameshiError::CollectorError {
            layer: "helm".to_string(),
            message: "test error".to_string(),
        }));
        let result = collector.collect().await;
        assert!(result.is_err());
    }

    #[test]
    fn mock_collector_layer_type() {
        let collector = MockCollector::new(LayerType::Kubernetes);
        assert_eq!(collector.layer_type(), LayerType::Kubernetes);
    }
}
