//! Deployment gating property proofs.
//!
//! Tameshi uses a two-phase certification model: an artifact starts as
//! "untested" and transitions to "secure" only after compliance attestation.
//! These proofs verify the default-deny property of the gating logic.

use crate::Hash;

/// Gating policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(kani), allow(dead_code))]
enum GateDecision {
    /// Deployment is allowed.
    Allow,
    /// Deployment is denied.
    Deny,
}

/// A deployment gate that requires both an artifact hash and a compliance hash.
///
/// Models tameshi's two-phase certification:
/// - Phase 1: artifact is built and hashed (untested)
/// - Phase 2: compliance engine attests the artifact (secure)
///
/// The gate only opens when BOTH hashes are present and the compliance
/// hash covers the artifact hash.
#[cfg_attr(not(kani), allow(dead_code))]
struct DeploymentGate {
    /// The artifact's attestation root (always present after build).
    artifact_hash: Hash,
    /// The compliance attestation hash (None until compliance passes).
    compliance_hash: Option<Hash>,
    /// Whether the policy requires compliance attestation.
    requires_compliance: bool,
}

#[cfg_attr(not(kani), allow(dead_code))]
impl DeploymentGate {
    /// Evaluate the gate: allow or deny deployment.
    fn evaluate(&self) -> GateDecision {
        if self.requires_compliance {
            match self.compliance_hash {
                Some(compliance) => {
                    // Compliance hash must cover the artifact hash
                    let expected = crate::combine(&self.artifact_hash, &compliance);
                    // Gate opens only if the combined hash is non-zero
                    // (a real system would verify against a signed attestation)
                    if expected != crate::ZERO_HASH {
                        GateDecision::Allow
                    } else {
                        GateDecision::Deny
                    }
                }
                None => GateDecision::Deny,
            }
        } else {
            // No compliance required — always allow
            GateDecision::Allow
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Without a compliance hash, a gate that requires compliance always denies.
    ///
    /// This is the default-deny property: no artifact can be deployed through
    /// a compliance-requiring gate without explicit compliance attestation.
    /// This prevents accidentally deploying untested artifacts.
    #[kani::proof]
    fn gate_default_deny() {
        let artifact_hash: Hash = kani::any();

        let gate = DeploymentGate {
            artifact_hash,
            compliance_hash: None,
            requires_compliance: true,
        };

        assert_eq!(
            gate.evaluate(),
            GateDecision::Deny,
            "gate must deny when compliance hash is absent and policy requires it"
        );
    }
}
