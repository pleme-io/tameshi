//! Testing utilities for the tameshi attestation ecosystem.
//!
//! Provides mock implementations of external services (The secrets manager, K8s, etc.)
//! for deterministic, offline testing without real infrastructure.

pub mod secrets_mock;
