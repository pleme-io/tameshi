//! Fragment Collector — threshold-based attestation authorization.
//!
//! Requires K-of-N fragment providers to submit their shares before
//! a binary can be attested. Models the DFC principle: no single
//! entity can authorize a binary alone.

use crate::hash::Blake3Hash;
use crate::shamir_dfc::{Share, reconstruct};
use std::sync::Mutex;

/// Trait for fragment providers (Build Server, Cloud, Local HSM, etc.).
pub trait FragmentProvider: Send + Sync {
    /// Provider identity.
    fn id(&self) -> &str;
    /// Submit a fragment for a binary attestation request.
    fn provide_fragment(&self, binary_hash: &Blake3Hash) -> Option<Share>;
}

/// Mock DFC cloud provider — provides fragment only if intent token is valid.
pub struct MockDfcCloud {
    pub id: String,
    pub fragment: Share,
    pub required_intent_token: String,
}

impl MockDfcCloud {
    pub fn new(id: &str, fragment: Share, intent_token: &str) -> Self {
        Self {
            id: id.to_string(),
            fragment,
            required_intent_token: intent_token.to_string(),
        }
    }

    /// Provide fragment only if the caller presents the correct intent token.
    pub fn provide_with_intent(&self, _binary_hash: &Blake3Hash, intent_token: &str) -> Option<Share> {
        if intent_token == self.required_intent_token {
            Some(self.fragment.clone())
        } else {
            None
        }
    }
}

impl FragmentProvider for MockDfcCloud {
    fn id(&self) -> &str { &self.id }
    fn provide_fragment(&self, _binary_hash: &Blake3Hash) -> Option<Share> {
        Some(self.fragment.clone())
    }
}

/// Mock build server provider.
pub struct MockBuildServer {
    pub id: String,
    pub fragment: Share,
}

impl MockBuildServer {
    pub fn new(id: &str, fragment: Share) -> Self {
        Self { id: id.to_string(), fragment }
    }
}

impl FragmentProvider for MockBuildServer {
    fn id(&self) -> &str { &self.id }
    fn provide_fragment(&self, _binary_hash: &Blake3Hash) -> Option<Share> {
        Some(self.fragment.clone())
    }
}

/// Mock local HSM provider.
pub struct MockLocalHsm {
    pub id: String,
    pub fragment: Share,
}

impl MockLocalHsm {
    pub fn new(id: &str, fragment: Share) -> Self {
        Self { id: id.to_string(), fragment }
    }
}

impl FragmentProvider for MockLocalHsm {
    fn id(&self) -> &str { &self.id }
    fn provide_fragment(&self, _binary_hash: &Blake3Hash) -> Option<Share> {
        Some(self.fragment.clone())
    }
}

/// A provider that always refuses (simulates offline/compromised node).
pub struct OfflineProvider {
    pub id: String,
}

impl OfflineProvider {
    pub fn new(id: &str) -> Self { Self { id: id.to_string() } }
}

impl FragmentProvider for OfflineProvider {
    fn id(&self) -> &str { &self.id }
    fn provide_fragment(&self, _binary_hash: &Blake3Hash) -> Option<Share> {
        None
    }
}

/// Result of a collection attempt.
#[derive(Debug, Clone)]
pub struct CollectionResult {
    pub binary_hash: Blake3Hash,
    pub fragments_collected: usize,
    pub fragments_needed: usize,
    pub providers_responded: Vec<String>,
    pub providers_failed: Vec<String>,
    pub reconstructed_root: Option<Blake3Hash>,
    pub authorized: bool,
}

/// The Fragment Collector — orchestrates threshold attestation.
pub struct FragmentCollector {
    providers: Vec<Box<dyn FragmentProvider>>,
    threshold: usize,
    /// Audit log of collection attempts.
    audit_log: Mutex<Vec<CollectionResult>>,
}

impl FragmentCollector {
    pub fn new(providers: Vec<Box<dyn FragmentProvider>>, threshold: usize) -> Self {
        assert!(threshold > 0, "threshold must be > 0");
        assert!(providers.len() >= threshold, "need at least {threshold} providers");
        Self {
            providers,
            threshold,
            audit_log: Mutex::new(Vec::new()),
        }
    }

    /// Collect fragments from providers and attempt reconstruction.
    pub fn collect_and_reconstruct(&self, binary_hash: &Blake3Hash) -> CollectionResult {
        let mut collected_shares = Vec::new();
        let mut responded = Vec::new();
        let mut failed = Vec::new();

        for provider in &self.providers {
            match provider.provide_fragment(binary_hash) {
                Some(share) => {
                    responded.push(provider.id().to_string());
                    collected_shares.push(share);
                }
                None => {
                    failed.push(provider.id().to_string());
                }
            }
        }

        let (reconstructed, authorized) = if collected_shares.len() >= self.threshold {
            let root_bytes = reconstruct(&collected_shares[..self.threshold]);
            let mut arr = [0u8; 32];
            if root_bytes.len() >= 32 {
                arr.copy_from_slice(&root_bytes[..32]);
            }
            (Some(Blake3Hash(arr)), true)
        } else {
            (None, false)
        };

        let result = CollectionResult {
            binary_hash: binary_hash.clone(),
            fragments_collected: collected_shares.len(),
            fragments_needed: self.threshold,
            providers_responded: responded,
            providers_failed: failed,
            reconstructed_root: reconstructed,
            authorized,
        };

        self.audit_log.lock().unwrap().push(result.clone());
        result
    }

    /// Get the audit log of all collection attempts.
    pub fn audit_log(&self) -> Vec<CollectionResult> {
        self.audit_log.lock().unwrap().clone()
    }

    /// Number of collection attempts recorded.
    pub fn audit_count(&self) -> usize {
        self.audit_log.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir_dfc::split;

    /// Helper: split a known root into shares for testing.
    fn test_shares(root: &[u8; 32], k: u8, n: u8) -> Vec<Share> {
        split(root, k, n)
    }

    #[test]
    fn threshold_met_authorizes() {
        let root = [0xAA; 32];
        let shares = test_shares(&root, 2, 3);
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
            Box::new(MockDfcCloud::new("cloud", shares[2].clone(), "token")),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(result.authorized);
        assert_eq!(result.fragments_collected, 3);
        assert_eq!(result.fragments_needed, 2);
        assert!(result.reconstructed_root.is_some());
        assert!(result.providers_failed.is_empty());
    }

    #[test]
    fn threshold_not_met_denies() {
        let root = [0xBB; 32];
        let shares = test_shares(&root, 2, 3);
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(OfflineProvider::new("hsm")),
            Box::new(OfflineProvider::new("cloud")),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(!result.authorized);
        assert_eq!(result.fragments_collected, 1);
        assert!(result.reconstructed_root.is_none());
    }

    #[test]
    fn exact_threshold_works() {
        let root = [0xCC; 32];
        let shares = test_shares(&root, 2, 3);
        // Only 2 providers, threshold 2 — exactly K fragments.
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(result.authorized);
        assert_eq!(result.fragments_collected, 2);
        assert_eq!(result.fragments_needed, 2);

        // Verify the reconstructed root matches the original.
        let reconstructed = result.reconstructed_root.unwrap();
        let expected = reconstruct(&shares[..2]);
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&expected);
        assert_eq!(reconstructed.0, expected_arr);
    }

    #[test]
    fn offline_provider_handled() {
        let root = [0xDD; 32];
        let shares = test_shares(&root, 2, 3);
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(OfflineProvider::new("offline-node")),
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(result.authorized);
        assert_eq!(result.fragments_collected, 2);
        assert_eq!(result.providers_failed, vec!["offline-node"]);
        assert_eq!(result.providers_responded.len(), 2);
    }

    #[test]
    fn all_offline_denies() {
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(OfflineProvider::new("a")),
            Box::new(OfflineProvider::new("b")),
            Box::new(OfflineProvider::new("c")),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(!result.authorized);
        assert_eq!(result.fragments_collected, 0);
        assert!(result.reconstructed_root.is_none());
        assert_eq!(result.providers_failed.len(), 3);
    }

    #[test]
    fn audit_log_records_attempts() {
        let root = [0xEE; 32];
        let shares = test_shares(&root, 2, 3);
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let h1 = Blake3Hash::digest(b"binary-1");
        let h2 = Blake3Hash::digest(b"binary-2");
        collector.collect_and_reconstruct(&h1);
        collector.collect_and_reconstruct(&h2);
        assert_eq!(collector.audit_count(), 2);
        let log = collector.audit_log();
        assert_eq!(log[0].binary_hash, h1);
        assert_eq!(log[1].binary_hash, h2);
    }

    #[test]
    fn reconstructed_root_matches_original() {
        let root = [0xFF; 32];
        let shares = test_shares(&root, 2, 3);
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
            Box::new(MockDfcCloud::new("cloud", shares[2].clone(), "tok")),
        ];
        let collector = FragmentCollector::new(providers, 2);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(result.authorized);
        let reconstructed = result.reconstructed_root.unwrap();
        assert_eq!(reconstructed.0, root);
    }

    #[test]
    fn intent_token_required() {
        let root = [0x11; 32];
        let shares = test_shares(&root, 2, 3);
        let cloud = MockDfcCloud::new("cloud", shares[0].clone(), "correct-token");
        let binary_hash = Blake3Hash::digest(b"test-binary");

        // Wrong token — fragment denied.
        let denied = cloud.provide_with_intent(&binary_hash, "wrong-token");
        assert!(denied.is_none());

        // Correct token — fragment provided.
        let granted = cloud.provide_with_intent(&binary_hash, "correct-token");
        assert!(granted.is_some());
        assert_eq!(granted.unwrap(), shares[0]);
    }

    #[test]
    fn anti_collusion_two_of_three() {
        // Even if 2 providers (build + hsm) are compromised, the cloud
        // provider must also provide its fragment for threshold to be met.
        // With threshold 3-of-3, ALL three must cooperate.
        let root = [0x22; 32];
        let shares = test_shares(&root, 3, 3);
        let _cloud = MockDfcCloud::new("cloud", shares[2].clone(), "intent");

        // Scenario: cloud refuses (wrong intent token via provide_with_intent).
        // Build + HSM have their fragments but threshold=3 requires all 3.
        let providers: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
            Box::new(OfflineProvider::new("cloud")), // cloud is "offline" (refuses)
        ];
        let collector = FragmentCollector::new(providers, 3);
        let binary_hash = Blake3Hash::digest(b"test-binary");
        let result = collector.collect_and_reconstruct(&binary_hash);
        assert!(!result.authorized, "2 of 3 must NOT authorize when threshold is 3");

        // Now with all 3 cooperating:
        let providers_all: Vec<Box<dyn FragmentProvider>> = vec![
            Box::new(MockBuildServer::new("build", shares[0].clone())),
            Box::new(MockLocalHsm::new("hsm", shares[1].clone())),
            Box::new(MockDfcCloud::new("cloud", shares[2].clone(), "intent")),
        ];
        let collector_all = FragmentCollector::new(providers_all, 3);
        let result_all = collector_all.collect_and_reconstruct(&binary_hash);
        assert!(result_all.authorized, "3 of 3 must authorize");
    }
}
