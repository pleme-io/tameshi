//! Compliance heartbeat — periodic re-verification of active attestations.
//!
//! Runs a re-verification cycle that checks all active attestations against
//! the current compliance state. If an attestation's composed root no longer
//! matches the current Merkle root (compliance changed), the attestation is
//! revoked and the binary loses kernel authorization.

use crate::bpf_loader::BpfMapOps;
use crate::hash::Blake3Hash;
use crate::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};
use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for compliance state providers.
///
/// Returns the current composed root for a binary. If the compliance
/// state has changed since the last attestation, the root will differ.
pub trait ComplianceStateProvider: Send + Sync {
    /// Get the current composed root for a binary.
    fn current_root(&self, binary_hash: &Blake3Hash) -> Option<Blake3Hash>;
}

/// Mock compliance provider for testing.
pub struct MockComplianceProvider {
    roots: Mutex<HashMap<Blake3Hash, Blake3Hash>>,
}

impl MockComplianceProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            roots: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_root(&self, binary_hash: Blake3Hash, root: Blake3Hash) {
        self.roots.lock().unwrap().insert(binary_hash, root);
    }

    pub fn remove_root(&self, binary_hash: &Blake3Hash) {
        self.roots.lock().unwrap().remove(binary_hash);
    }
}

impl Default for MockComplianceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceStateProvider for MockComplianceProvider {
    fn current_root(&self, binary_hash: &Blake3Hash) -> Option<Blake3Hash> {
        self.roots.lock().unwrap().get(binary_hash).cloned()
    }
}

/// Result of a compliance heartbeat cycle.
#[derive(Debug, Clone)]
pub struct HeartbeatCycleResult {
    /// Number of attestations checked.
    pub checked: usize,
    /// Number that still match current compliance.
    pub passed: usize,
    /// Number revoked due to compliance drift.
    pub revoked: usize,
    /// Binary hashes that were revoked.
    pub revoked_hashes: Vec<Blake3Hash>,
}

/// Run a single compliance heartbeat cycle.
///
/// Checks every attested binary against the current compliance state.
/// If the composed root has changed (compliance drift), the binary is
/// revoked from the BPF map and a `HeartbeatEvent` is recorded.
pub fn run_compliance_heartbeat(
    attested_binaries: &[(Blake3Hash, Blake3Hash)], // (binary_hash, attested_root)
    compliance: &dyn ComplianceStateProvider,
    maps: &dyn BpfMapOps,
    chain: &HeartbeatChain,
) -> HeartbeatCycleResult {
    let verifier =
        VerifierIdentity::new("tameshi", "compliance-heartbeat", env!("CARGO_PKG_VERSION"));
    let mut passed = 0;
    let mut revoked = 0;
    let mut revoked_hashes = Vec::new();

    for (binary_hash, attested_root) in attested_binaries {
        match compliance.current_root(binary_hash) {
            Some(current_root) if current_root == *attested_root => {
                // Compliance unchanged — attestation still valid
                passed += 1;
                chain.append(
                    verifier.clone(),
                    HeartbeatEvent::ComplianceRecheck,
                    VerificationOutcome::Allowed,
                    &format!("compliance-recheck:{}", &binary_hash.to_hex()[..16]),
                    binary_hash.clone(),
                );
            }
            _ => {
                // Compliance changed or binary removed — revoke
                let _ = maps.revoke_poms(&binary_hash.0);
                revoked += 1;
                revoked_hashes.push(binary_hash.clone());
                chain.append(
                    verifier.clone(),
                    HeartbeatEvent::ComplianceRecheck,
                    VerificationOutcome::Denied,
                    &format!("compliance-drift:{}", &binary_hash.to_hex()[..16]),
                    binary_hash.clone(),
                );
            }
        }
    }

    HeartbeatCycleResult {
        checked: attested_binaries.len(),
        passed,
        revoked,
        revoked_hashes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_loader::MockBpfMaps;

    fn make_binary(seed: &[u8]) -> Blake3Hash {
        Blake3Hash::digest(seed)
    }

    fn make_root(seed: &[u8]) -> Blake3Hash {
        Blake3Hash::digest(seed)
    }

    #[test]
    fn all_compliant_passes() {
        let maps = MockBpfMaps::new();
        let chain = HeartbeatChain::new();
        let provider = MockComplianceProvider::new();

        let b1 = make_binary(b"binary-1");
        let b2 = make_binary(b"binary-2");
        let b3 = make_binary(b"binary-3");
        let r1 = make_root(b"root-1");
        let r2 = make_root(b"root-2");
        let r3 = make_root(b"root-3");

        provider.set_root(b1.clone(), r1.clone());
        provider.set_root(b2.clone(), r2.clone());
        provider.set_root(b3.clone(), r3.clone());

        let attested = vec![(b1, r1), (b2, r2), (b3, r3)];

        let result = run_compliance_heartbeat(&attested, &provider, &maps, &chain);

        assert_eq!(result.checked, 3);
        assert_eq!(result.passed, 3);
        assert_eq!(result.revoked, 0);
        assert!(result.revoked_hashes.is_empty());
    }

    #[test]
    fn compliance_drift_revokes() {
        let maps = MockBpfMaps::new();
        let chain = HeartbeatChain::new();
        let provider = MockComplianceProvider::new();

        let binary = make_binary(b"drifted-binary");
        let attested_root = make_root(b"old-root");
        let current_root = make_root(b"new-root");

        // Attest the binary in the BPF map
        maps.push_poms_to_kernel(&binary.0, &attested_root.0, 0)
            .unwrap();
        assert!(maps.lookup_poms(&binary.0).is_some());

        // Compliance now reports a different root
        provider.set_root(binary.clone(), current_root);

        let attested = vec![(binary.clone(), attested_root)];
        let result = run_compliance_heartbeat(&attested, &provider, &maps, &chain);

        assert_eq!(result.revoked, 1);
        assert_eq!(result.revoked_hashes.len(), 1);
        assert_eq!(result.revoked_hashes[0], binary);

        // Binary should be revoked from BPF map
        assert!(maps.lookup_poms(&binary.0).is_none());
    }

    #[test]
    fn missing_root_revokes() {
        let maps = MockBpfMaps::new();
        let chain = HeartbeatChain::new();
        let provider = MockComplianceProvider::new();
        // Provider has no roots at all

        let binary = make_binary(b"missing-binary");
        let root = make_root(b"some-root");

        // Attest the binary
        maps.push_poms_to_kernel(&binary.0, &root.0, 0).unwrap();

        let attested = vec![(binary.clone(), root)];
        let result = run_compliance_heartbeat(&attested, &provider, &maps, &chain);

        assert_eq!(result.checked, 1);
        assert_eq!(result.passed, 0);
        assert_eq!(result.revoked, 1);
        assert_eq!(result.revoked_hashes[0], binary);
    }

    #[test]
    fn mixed_results() {
        let maps = MockBpfMaps::new();
        let chain = HeartbeatChain::new();
        let provider = MockComplianceProvider::new();

        let b_pass1 = make_binary(b"pass-1");
        let b_pass2 = make_binary(b"pass-2");
        let b_drift = make_binary(b"drift-1");
        let r_pass1 = make_root(b"r-pass-1");
        let r_pass2 = make_root(b"r-pass-2");
        let r_old = make_root(b"r-old");
        let r_new = make_root(b"r-new");

        provider.set_root(b_pass1.clone(), r_pass1.clone());
        provider.set_root(b_pass2.clone(), r_pass2.clone());
        provider.set_root(b_drift.clone(), r_new); // drift: provider has new root

        let attested = vec![
            (b_pass1, r_pass1),
            (b_pass2, r_pass2),
            (b_drift.clone(), r_old), // attested with old root
        ];

        let result = run_compliance_heartbeat(&attested, &provider, &maps, &chain);

        assert_eq!(result.checked, 3);
        assert_eq!(result.passed, 2);
        assert_eq!(result.revoked, 1);
        assert_eq!(result.revoked_hashes[0], b_drift);
    }

    #[test]
    fn heartbeat_chain_records_events() {
        let maps = MockBpfMaps::new();
        let chain = HeartbeatChain::new();
        let provider = MockComplianceProvider::new();

        let b1 = make_binary(b"event-1");
        let b2 = make_binary(b"event-2");
        let b3 = make_binary(b"event-3");
        let r1 = make_root(b"er-1");
        let r2 = make_root(b"er-2");
        let r3 = make_root(b"er-3");

        // b1 passes, b2 drifts, b3 missing
        provider.set_root(b1.clone(), r1.clone());
        provider.set_root(b2.clone(), make_root(b"er-2-new"));

        let attested = vec![(b1, r1), (b2, r2), (b3, r3)];

        run_compliance_heartbeat(&attested, &provider, &maps, &chain);

        // Chain should have exactly 3 entries (one per binary)
        assert_eq!(chain.len(), 3);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn revoked_binary_removed_from_bpf() {
        let maps = MockBpfMaps::new();
        let chain = HeartbeatChain::new();
        let provider = MockComplianceProvider::new();

        let binary = make_binary(b"bpf-revoke-test");
        let attested_root = make_root(b"attested-root");

        // Attest via MockBpfMaps
        maps.push_poms_to_kernel(&binary.0, &attested_root.0, 0)
            .unwrap();
        assert!(maps.lookup_poms(&binary.0).is_some());

        // Compliance drifts: provider reports a different root
        let drifted_root = make_root(b"drifted-root");
        provider.set_root(binary.clone(), drifted_root);

        let attested = vec![(binary.clone(), attested_root)];
        let result = run_compliance_heartbeat(&attested, &provider, &maps, &chain);

        // Verify the binary was revoked from BPF
        assert!(maps.lookup_poms(&binary.0).is_none());
        assert_eq!(result.revoked, 1);
        assert_eq!(result.revoked_hashes[0], binary);
    }
}
