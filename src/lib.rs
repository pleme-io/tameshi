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

pub mod akeyless_client;
pub mod alerts;
pub mod api_types;
pub mod cache;
pub mod canonicalize;
pub mod certification;
pub mod changeset;
pub mod ci;
pub mod collectors;
pub mod compliance;
pub mod config;
pub mod error;
pub mod gating;
pub mod hash;
pub mod heartbeat;
pub mod merkle;
pub mod reporting;
pub mod selftest;
pub mod signature;
pub mod signing;
pub mod testing;
pub mod traits;
pub mod verify;

/// Prelude module for convenient wildcard imports.
///
/// ```rust
/// use tameshi::prelude::*;
/// ```
pub mod prelude {
    pub use crate::canonicalize::{
        CanonicalMode, Canonicalizer, JsonCanonicalizer, RawCanonicalizer, YamlCanonicalizer,
        canonical_hash, canonicalizer_for,
    };
    pub use crate::akeyless_client::{
        AkeylessClient, AkeylessClientError, AkeylessConfig, DynamicSecretInfo,
        HttpAkeylessClient, ItemAssociation, MockAkeylessClient, TargetInfo, TlsConfig,
    };
    pub use crate::collectors::akeyless::LiveAkeylessCollector;
    pub use crate::collectors::akeyless_target::{
        AkeylessTargetCollector, LiveAkeylessTargetCollector,
    };
    pub use crate::collectors::traits::LayerCollector;
    pub use crate::collectors::MockCollector;
    pub use crate::compliance::akeyless_target::{
        AkeylessTargetAttestation, AkeylessTargetType, ProducerAssociation,
        compute_multi_target_hash, compute_target_attestation_hash,
    };
    pub use crate::config::ConfigLoader;
    pub use crate::hash::{AttestationHasher, Blake3Hash, Blake3Hasher, Sha256Hash};
    pub use crate::merkle::{compose_merkle, compute_merkle_root};
    pub use crate::signature::{InputHash, LayerSignature, LayerType, MasterSignature};
    pub use crate::traits::{
        Clock, CommandRunner, DefaultGatingEngine, DefaultVerifier, FileSystem, FixedClock,
        GatingEngine, HttpClient, MockCommandRunner, MockFileSystem, MockGatingEngine,
        MockHttpClient, MockVerifier, ReqwestHttpClient, SignatureVerifier, SystemClock,
        SystemCommandRunner,
    };
    pub use crate::selftest::{
        attest_framework, compute_framework_hash, framework_attestation_hash,
    };
    pub use crate::verify::{verify_master, VerificationResult};
}
