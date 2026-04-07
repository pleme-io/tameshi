//! Ephemeral attestation — time-limited binary authorization.
//!
//! Attestations expire after a configurable TTL. Expired attestations
//! must be re-authorized through the fragment collection pipeline.

use chrono::{DateTime, Duration, Utc};
use crate::hash::Blake3Hash;
use crate::bpf_loader::BpfMapOps;
use std::collections::HashMap;
use std::sync::Mutex;

/// An ephemeral attestation record with TTL.
#[derive(Clone, Debug)]
pub struct EphemeralAttestation {
    pub binary_hash: Blake3Hash,
    pub composed_root: Blake3Hash,
    pub attested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ttl_secs: u64,
}

impl EphemeralAttestation {
    pub fn new(binary_hash: Blake3Hash, composed_root: Blake3Hash, ttl_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            binary_hash,
            composed_root,
            attested_at: now,
            expires_at: now + Duration::seconds(ttl_secs as i64),
            ttl_secs,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn is_expired_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.expires_at
    }

    pub fn remaining_secs(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }
}

/// Manages ephemeral attestations with automatic expiry.
pub struct EphemeralAttestationManager {
    attestations: Mutex<HashMap<Blake3Hash, EphemeralAttestation>>,
    default_ttl_secs: u64,
}

impl EphemeralAttestationManager {
    pub fn new(default_ttl_secs: u64) -> Self {
        Self {
            attestations: Mutex::new(HashMap::new()),
            default_ttl_secs,
        }
    }

    /// Attest a binary with the default TTL.
    pub fn attest(&self, binary_hash: Blake3Hash, composed_root: Blake3Hash) -> EphemeralAttestation {
        self.attest_with_ttl(binary_hash, composed_root, self.default_ttl_secs)
    }

    /// Attest a binary with a custom TTL.
    pub fn attest_with_ttl(&self, binary_hash: Blake3Hash, composed_root: Blake3Hash, ttl_secs: u64) -> EphemeralAttestation {
        let att = EphemeralAttestation::new(binary_hash.clone(), composed_root, ttl_secs);
        self.attestations.lock().unwrap().insert(binary_hash, att.clone());
        att
    }

    /// Check if a binary is currently attested (not expired).
    pub fn is_attested(&self, binary_hash: &Blake3Hash) -> bool {
        let guard = self.attestations.lock().unwrap();
        guard.get(binary_hash).map_or(false, |a| !a.is_expired())
    }

    /// Sweep expired attestations. Returns the hashes that were revoked.
    pub fn sweep_expired(&self) -> Vec<Blake3Hash> {
        let mut guard = self.attestations.lock().unwrap();
        let now = Utc::now();
        let expired: Vec<Blake3Hash> = guard.iter()
            .filter(|(_, a)| a.is_expired_at(now))
            .map(|(k, _)| k.clone())
            .collect();
        for hash in &expired {
            guard.remove(hash);
        }
        expired
    }

    /// Sweep and revoke from BPF maps.
    pub fn sweep_and_revoke(&self, maps: &dyn BpfMapOps) -> Vec<Blake3Hash> {
        let expired = self.sweep_expired();
        for hash in &expired {
            let _ = maps.revoke_poms(&hash.0);
        }
        expired
    }

    /// Number of active (non-expired) attestations.
    pub fn active_count(&self) -> usize {
        let guard = self.attestations.lock().unwrap();
        guard.values().filter(|a| !a.is_expired()).count()
    }

    /// Total attestations including expired.
    pub fn total_count(&self) -> usize {
        self.attestations.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_loader::MockBpfMaps;

    fn test_hash(data: &[u8]) -> Blake3Hash {
        Blake3Hash::digest(data)
    }

    #[test]
    fn new_attestation_not_expired() {
        let att = EphemeralAttestation::new(
            test_hash(b"bin"),
            test_hash(b"root"),
            60,
        );
        assert!(!att.is_expired());
        assert!(att.remaining_secs() > 0);
        assert_eq!(att.ttl_secs, 60);
    }

    #[test]
    fn zero_ttl_immediately_expires() {
        let att = EphemeralAttestation::new(
            test_hash(b"bin"),
            test_hash(b"root"),
            0,
        );
        assert!(att.is_expired());
        assert_eq!(att.remaining_secs(), 0);
    }

    #[test]
    fn is_attested_returns_true_for_active() {
        let mgr = EphemeralAttestationManager::new(60);
        let hash = test_hash(b"active-binary");
        mgr.attest(hash.clone(), test_hash(b"root"));
        assert!(mgr.is_attested(&hash));
    }

    #[test]
    fn is_attested_returns_false_for_absent() {
        let mgr = EphemeralAttestationManager::new(60);
        let hash = test_hash(b"absent-binary");
        assert!(!mgr.is_attested(&hash));
    }

    #[test]
    fn sweep_removes_expired() {
        let mgr = EphemeralAttestationManager::new(60);
        let hash = test_hash(b"expired-binary");
        mgr.attest_with_ttl(hash.clone(), test_hash(b"root"), 0);
        // TTL=0 means it expired immediately.
        let expired = mgr.sweep_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], hash);
        assert_eq!(mgr.total_count(), 0);
    }

    #[test]
    fn sweep_and_revoke_removes_from_bpf() {
        let mgr = EphemeralAttestationManager::new(60);
        let hash = test_hash(b"bpf-binary");
        let root = test_hash(b"root");
        mgr.attest_with_ttl(hash.clone(), root.clone(), 0);

        let maps = MockBpfMaps::new();
        // Pre-populate BPF map so revocation has something to remove.
        maps.push_poms_to_kernel(&hash.0, &root.0, 0).unwrap();
        assert!(maps.lookup_poms(&hash.0).is_some());

        let expired = mgr.sweep_and_revoke(&maps);
        assert_eq!(expired.len(), 1);
        assert!(maps.lookup_poms(&hash.0).is_none());
    }

    #[test]
    fn active_count_excludes_expired() {
        let mgr = EphemeralAttestationManager::new(60);
        let h1 = test_hash(b"active-1");
        let h2 = test_hash(b"active-2");
        let h3 = test_hash(b"expired-1");

        mgr.attest(h1, test_hash(b"r1"));
        mgr.attest(h2, test_hash(b"r2"));
        mgr.attest_with_ttl(h3, test_hash(b"r3"), 0);

        assert_eq!(mgr.active_count(), 2);
        assert_eq!(mgr.total_count(), 3);
    }

    #[test]
    fn custom_ttl_overrides_default() {
        let mgr = EphemeralAttestationManager::new(3600); // 1 hour default
        let hash = test_hash(b"custom-ttl");
        let att = mgr.attest_with_ttl(hash, test_hash(b"root"), 10);
        assert_eq!(att.ttl_secs, 10);
        assert!(att.remaining_secs() <= 10);
    }

    #[test]
    fn attest_replaces_existing() {
        let mgr = EphemeralAttestationManager::new(60);
        let hash = test_hash(b"replace-binary");
        let root1 = test_hash(b"root-v1");
        let root2 = test_hash(b"root-v2");

        mgr.attest(hash.clone(), root1);
        mgr.attest(hash.clone(), root2);

        assert_eq!(mgr.total_count(), 1, "same binary hash should replace, not duplicate");
        assert!(mgr.is_attested(&hash));
    }

    #[test]
    fn sweep_preserves_active() {
        let mgr = EphemeralAttestationManager::new(3600);
        let active_hash = test_hash(b"active");
        let expired_hash = test_hash(b"expired");

        mgr.attest(active_hash.clone(), test_hash(b"r1"));
        mgr.attest_with_ttl(expired_hash.clone(), test_hash(b"r2"), 0);

        let swept = mgr.sweep_expired();
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0], expired_hash);
        assert!(mgr.is_attested(&active_hash), "active attestation must survive sweep");
        assert!(!mgr.is_attested(&expired_hash), "expired should be gone");
    }

    #[test]
    fn sweep_empty_manager() {
        let mgr = EphemeralAttestationManager::new(60);
        let swept = mgr.sweep_expired();
        assert!(swept.is_empty());
    }

    #[test]
    fn multiple_sweeps_idempotent() {
        let mgr = EphemeralAttestationManager::new(60);
        let hash = test_hash(b"multi-sweep");
        mgr.attest_with_ttl(hash, test_hash(b"root"), 0);

        let first = mgr.sweep_expired();
        assert_eq!(first.len(), 1);
        let second = mgr.sweep_expired();
        assert!(second.is_empty(), "second sweep should find nothing");
    }

    #[test]
    fn is_expired_at_boundary() {
        let att = EphemeralAttestation::new(
            test_hash(b"boundary"),
            test_hash(b"root"),
            60,
        );
        assert!(!att.is_expired_at(att.attested_at));
        assert!(att.is_expired_at(att.expires_at));
        assert!(att.is_expired_at(att.expires_at + chrono::Duration::seconds(1)));
    }
}
