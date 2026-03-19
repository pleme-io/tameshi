//! Trait definition for infrastructure layer collectors.
//!
//! All collectors implement [`LayerCollector`] to produce deterministic
//! [`LayerSignature`] values for their respective infrastructure layers.

use crate::error::Result;
use crate::signature::{LayerSignature, LayerType};

/// Trait for infrastructure layer collectors that produce deterministic signatures.
///
/// Each collector knows how to gather data from its infrastructure layer
/// (Nix stores, OCI registries, Helm charts, etc.) and compute a
/// content-addressable [`LayerSignature`].
///
/// # Example
///
/// ```rust,ignore
/// use tameshi::collectors::traits::LayerCollector;
/// use tameshi::signature::LayerType;
///
/// let collector = NixCollector { store_path: Some("/nix/store/...".into()) };
/// let sig = collector.collect().await?;
/// assert_eq!(collector.layer_type(), LayerType::Nix);
/// ```
pub trait LayerCollector: Send + Sync {
    /// Collect a deterministic signature for this infrastructure layer.
    fn collect(&self) -> impl std::future::Future<Output = Result<LayerSignature>> + Send;

    /// The type of infrastructure layer this collector handles.
    fn layer_type(&self) -> LayerType;
}
