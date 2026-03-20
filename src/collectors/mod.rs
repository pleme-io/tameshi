//! Infrastructure layer collectors.
//!
//! Each collector knows how to compute a [`LayerSignature`] for its respective
//! infrastructure layer. Collectors shell out to native tools (nix-store, skopeo,
//! helm, tofu) or query APIs to gather the data needed for hashing.
//!
//! All collectors implement the [`LayerCollector`] trait, which provides a
//! uniform interface for collecting layer signatures.

pub mod akeyless;
pub mod akeyless_target;
pub mod argocd;
pub mod fluxcd;
pub mod generic;
pub mod helm;
pub mod inspec_result;
pub mod kindling;
pub mod kubernetes;
pub mod mock;
pub mod nix;
pub mod oci;
pub mod pangea;
pub mod rspec;
pub mod tatara;
pub mod tofu;
pub mod traits;

pub use mock::MockCollector;
pub use traits::LayerCollector;
