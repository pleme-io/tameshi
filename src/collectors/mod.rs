//! Infrastructure layer collectors.
//!
//! Each collector knows how to compute a [`LayerSignature`] for its respective
//! infrastructure layer. Collectors shell out to native tools (nix-store, skopeo,
//! helm, tofu) or query APIs to gather the data needed for hashing.

pub mod helm;
pub mod kindling;
pub mod kubernetes;
pub mod nix;
pub mod oci;
pub mod tatara;
pub mod tofu;
