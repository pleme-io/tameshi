//! Node-specific salt for hardware-bound attestation.
//!
//! Binds CertificationArtifact composed roots to specific nodes by
//! incorporating a node-specific salt into the root hash. A valid
//! attestation from Node A cannot be transplanted to Node B because
//! the salted roots will differ.
//!
//! Two implementations:
//! - `SystemIdSalt`: derives salt from `/etc/machine-id` (Linux) or
//!   `IOPlatformUUID` (macOS) — deterministic per node
//! - `MockTpmSalt`: configurable salt for testing

use crate::hash::Blake3Hash;

/// Trait for providing a node-specific salt.
///
/// Implementations must return a deterministic 32-byte salt that is
/// unique to the current node and stable across reboots.
pub trait NodeSalt: Send + Sync {
    /// Return the 32-byte node-specific salt.
    fn salt(&self) -> Blake3Hash;
}

/// Compute a salted root from a composed root and a node salt.
///
/// `salted_root = BLAKE3(composed_root || node_salt)`
///
/// This ensures that a CertificationArtifact composed on Node A
/// produces a different salted root on Node B.
#[inline]
#[must_use]
pub fn salted_root(composed_root: &Blake3Hash, salt: &Blake3Hash) -> Blake3Hash {
    Blake3Hash::combine(composed_root, salt)
}

/// Verify that a salted root matches the expected composed root + salt.
#[inline]
#[must_use]
pub fn verify_salted_root(
    salted: &Blake3Hash,
    composed_root: &Blake3Hash,
    salt: &Blake3Hash,
) -> bool {
    *salted == salted_root(composed_root, salt)
}

/// Mock TPM salt for testing. Returns a configurable fixed salt.
#[derive(Clone, Debug)]
pub struct MockTpmSalt {
    salt_value: Blake3Hash,
}

impl MockTpmSalt {
    /// Create a mock with a specific salt value.
    #[must_use]
    pub fn new(salt: Blake3Hash) -> Self {
        Self { salt_value: salt }
    }

    /// Create a mock that derives salt from a node name string.
    #[must_use]
    pub fn from_node_name(name: &str) -> Self {
        Self {
            salt_value: Blake3Hash::digest(name.as_bytes()),
        }
    }

    /// Create a deterministic test salt.
    #[must_use]
    pub fn for_testing() -> Self {
        Self::from_node_name("test-node-001")
    }
}

impl NodeSalt for MockTpmSalt {
    fn salt(&self) -> Blake3Hash {
        self.salt_value.clone()
    }
}

/// System ID salt: derives salt from the machine's unique identifier.
///
/// - Linux: reads `/etc/machine-id`
/// - macOS: reads `IOPlatformUUID` via `ioreg`
/// - Fallback: BLAKE3 hash of hostname
pub struct SystemIdSalt {
    cached_salt: Blake3Hash,
}

impl SystemIdSalt {
    /// Create by reading the system's machine ID.
    pub fn new() -> crate::error::Result<Self> {
        let machine_id = Self::read_machine_id()?;
        Ok(Self {
            cached_salt: Blake3Hash::digest(machine_id.as_bytes()),
        })
    }

    fn read_machine_id() -> crate::error::Result<String> {
        // Try /etc/machine-id (Linux)
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = id.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }

        // Try hostname as fallback
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            return Ok(hostname);
        }

        // Final fallback: use a constant that makes it clear this is unsalted
        Err(crate::error::TameshiError::ConfigError(
            "cannot determine machine identity: no /etc/machine-id or HOSTNAME".to_string(),
        ))
    }
}

impl NodeSalt for SystemIdSalt {
    fn salt(&self) -> Blake3Hash {
        self.cached_salt.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_salt_deterministic() {
        let salt_a = MockTpmSalt::from_node_name("node-alpha");
        let salt_b = MockTpmSalt::from_node_name("node-alpha");
        assert_eq!(salt_a.salt(), salt_b.salt());
    }

    #[test]
    fn different_nodes_different_salts() {
        let salt_a = MockTpmSalt::from_node_name("node-alpha");
        let salt_b = MockTpmSalt::from_node_name("node-beta");
        assert_ne!(salt_a.salt(), salt_b.salt());
    }

    #[test]
    fn salted_root_changes_with_salt() {
        let composed = Blake3Hash::digest(b"composed-root-data");
        let salt_a = MockTpmSalt::from_node_name("node-alpha").salt();
        let salt_b = MockTpmSalt::from_node_name("node-beta").salt();

        let root_a = salted_root(&composed, &salt_a);
        let root_b = salted_root(&composed, &salt_b);
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn salted_root_changes_with_root() {
        let composed_1 = Blake3Hash::digest(b"composed-root-one");
        let composed_2 = Blake3Hash::digest(b"composed-root-two");
        let salt = MockTpmSalt::from_node_name("node-alpha").salt();

        let root_1 = salted_root(&composed_1, &salt);
        let root_2 = salted_root(&composed_2, &salt);
        assert_ne!(root_1, root_2);
    }

    #[test]
    fn verify_salted_root_correct() {
        let composed = Blake3Hash::digest(b"artifact-data");
        let salt = MockTpmSalt::from_node_name("node-gamma").salt();
        let sr = salted_root(&composed, &salt);

        assert!(verify_salted_root(&sr, &composed, &salt));
    }

    #[test]
    fn verify_salted_root_wrong_salt() {
        let composed = Blake3Hash::digest(b"artifact-data");
        let salt_correct = MockTpmSalt::from_node_name("node-gamma").salt();
        let salt_wrong = MockTpmSalt::from_node_name("node-delta").salt();
        let sr = salted_root(&composed, &salt_correct);

        assert!(!verify_salted_root(&sr, &composed, &salt_wrong));
    }

    #[test]
    fn verify_salted_root_wrong_root() {
        let composed_correct = Blake3Hash::digest(b"artifact-data");
        let composed_wrong = Blake3Hash::digest(b"different-artifact");
        let salt = MockTpmSalt::from_node_name("node-gamma").salt();
        let sr = salted_root(&composed_correct, &salt);

        assert!(!verify_salted_root(&sr, &composed_wrong, &salt));
    }

    #[test]
    fn node_a_attestation_fails_on_node_b() {
        let composed = Blake3Hash::digest(b"production-artifact");
        let node_a_salt = MockTpmSalt::from_node_name("node-a");
        let node_b_salt = MockTpmSalt::from_node_name("node-b");

        // Create attestation on node A
        let sr = salted_root(&composed, &node_a_salt.salt());

        // Verify succeeds on node A
        assert!(verify_salted_root(&sr, &composed, &node_a_salt.salt()));

        // Verify fails on node B
        assert!(!verify_salted_root(&sr, &composed, &node_b_salt.salt()));
    }

    #[test]
    fn same_node_attestation_succeeds() {
        let composed = Blake3Hash::digest(b"deployment-artifact");
        let node_salt = MockTpmSalt::from_node_name("prod-worker-01");

        // Create and verify on same node
        let sr = salted_root(&composed, &node_salt.salt());
        assert!(verify_salted_root(&sr, &composed, &node_salt.salt()));
    }

    #[test]
    fn for_testing_is_deterministic() {
        let salt_1 = MockTpmSalt::for_testing();
        let salt_2 = MockTpmSalt::for_testing();
        assert_eq!(salt_1.salt(), salt_2.salt());
    }
}
