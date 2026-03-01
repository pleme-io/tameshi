//! Tameshi (試し) - Deterministic integrity attestation library
//!
//! Provides cryptographic hash computation, Merkle tree composition, and signature
//! verification for infrastructure layers. Every provisioning layer (Nix stores,
//! OCI images, Helm charts, OpenTofu state, Kubernetes manifests, Kindling identity,
//! Tatara allocations) produces a layer signature. These compose into a master
//! signature that gates provisioning at every level.
//!
//! # Architecture
//!
//! ```text
//! Collectors → LayerSignatures → Merkle Tree → Master Untested Signature
//!                                                        +
//!                                              Compliance Hash
//!                                                        =
//!                                              Master Secure Signature
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use tameshi::{collectors, merkle, signature::MasterSignature};
//!
//! # async fn example() -> Result<(), tameshi::error::TameshiError> {
//! // Collect layer signatures
//! let nix_sig = collectors::nix::hash_closure("/nix/store/...").await?;
//! let oci_sig = collectors::oci::hash_manifest("ghcr.io/pleme-io/app:latest").await?;
//!
//! // Compose into master signature
//! let master = merkle::compose_merkle(&[nix_sig, oci_sig], "production");
//!
//! // Verify
//! assert!(master.verify_untested());
//! # Ok(())
//! # }
//! ```

pub mod alerts;
pub mod api_types;
pub mod certification;
pub mod changeset;
pub mod ci;
pub mod collectors;
pub mod compliance;
pub mod config;
pub mod error;
pub mod gating;
pub mod hash;
pub mod merkle;
pub mod reporting;
pub mod selftest;
pub mod signature;
pub mod verify;
