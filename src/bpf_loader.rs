//! BPF control plane for the kanshi enforcer.
//!
//! Provides the Rust-side data structures and operations for interacting
//! with the kanshi eBPF maps. The structs here must have identical memory
//! layout to the C structs in `bpf/kanshi_enforcer.bpf.c`.
//!
//! In production, this module uses `libbpf-rs` or `aya` to open and
//! update the BPF maps. In test/mock mode, it uses an in-memory HashMap.

use crate::hash::Blake3Hash;

/// BLAKE3 hash size in bytes.
pub const HASH_SIZE: usize = 32;

/// PoMS attestation entry — must match `struct poms_entry` in the BPF C code.
///
/// Memory layout (C-compatible, no padding):
/// ```text
/// offset  0: binary_hash  [32]u8
/// offset 32: poms_hash    [32]u8
/// offset 64: attested_at  u64
/// offset 72: pid          u32
/// offset 76: violations   u32
/// total: 80 bytes
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PomsEntry {
    pub binary_hash: [u8; HASH_SIZE],
    pub poms_hash: [u8; HASH_SIZE],
    pub attested_at: u64,
    pub pid: u32,
    pub violations: u32,
}

/// Configuration entry — must match `struct kanshi_config` in the BPF C code.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KanshiConfig {
    pub enforce: u32,
    pub log_allowed: u32,
}

/// Audit event — must match `struct audit_event` in the BPF C code.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent {
    pub pid: u32,
    pub uid: u32,
    pub hash: [u8; HASH_SIZE],
    pub denied: u8,
}

/// Trait for BPF map operations. Production uses libbpf-rs/aya.
/// Tests use the in-memory mock.
pub trait BpfMapOps: Send + Sync {
    /// Insert or update a PoMS entry in the verified_poms_hashes map.
    fn push_poms_to_kernel(
        &self,
        binary_hash: &[u8; HASH_SIZE],
        poms_hash: &[u8; HASH_SIZE],
        violations: u32,
    ) -> Result<(), String>;

    /// Look up a binary hash in the verified_poms_hashes map.
    fn lookup_poms(&self, binary_hash: &[u8; HASH_SIZE]) -> Option<PomsEntry>;

    /// Delete a binary hash from the map (revocation).
    fn revoke_poms(&self, binary_hash: &[u8; HASH_SIZE]) -> Result<(), String>;

    /// Set the enforcement configuration.
    fn set_config(&self, config: KanshiConfig) -> Result<(), String>;
}

/// In-memory mock of the BPF maps for testing.
/// Structurally identical to the kernel maps but backed by a HashMap.
#[derive(Debug, Default)]
pub struct MockBpfMaps {
    entries: std::sync::Mutex<std::collections::HashMap<[u8; HASH_SIZE], PomsEntry>>,
    config: std::sync::Mutex<Option<KanshiConfig>>,
}

impl MockBpfMaps {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries in the map.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }
}

impl BpfMapOps for MockBpfMaps {
    fn push_poms_to_kernel(
        &self,
        binary_hash: &[u8; HASH_SIZE],
        poms_hash: &[u8; HASH_SIZE],
        violations: u32,
    ) -> Result<(), String> {
        let entry = PomsEntry {
            binary_hash: *binary_hash,
            poms_hash: *poms_hash,
            attested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            pid: std::process::id(),
            violations,
        };
        self.entries.lock().unwrap().insert(*binary_hash, entry);
        Ok(())
    }

    fn lookup_poms(&self, binary_hash: &[u8; HASH_SIZE]) -> Option<PomsEntry> {
        self.entries.lock().unwrap().get(binary_hash).copied()
    }

    fn revoke_poms(&self, binary_hash: &[u8; HASH_SIZE]) -> Result<(), String> {
        self.entries.lock().unwrap().remove(binary_hash);
        Ok(())
    }

    fn set_config(&self, config: KanshiConfig) -> Result<(), String> {
        *self.config.lock().unwrap() = Some(config);
        Ok(())
    }
}

/// Push a Ferrite PoMS attestation result to the kernel BPF map.
///
/// This is the bridge between tameshi's `FerriteCollector` and the kernel
/// enforcer. After collecting a `LayerSignature` from a clean PoMS,
/// this function inserts the binary hash into the kernel map so that
/// the LSM hook will ALLOW the binary to execute.
pub fn attest_binary(
    maps: &dyn BpfMapOps,
    binary_hash: &Blake3Hash,
    poms_hash: &Blake3Hash,
) -> Result<(), String> {
    maps.push_poms_to_kernel(
        &binary_hash.0,
        &poms_hash.0,
        0, // zero violations = safe
    )
}

/// Revoke a binary's attestation (e.g., on PoMS expiry or vulnerability).
pub fn revoke_binary(
    maps: &dyn BpfMapOps,
    binary_hash: &Blake3Hash,
) -> Result<(), String> {
    maps.revoke_poms(&binary_hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Struct layout tests (must match C) ---

    #[test]
    fn poms_entry_size_matches_c() {
        // C struct: 32 + 32 + 8 + 4 + 4 = 80 bytes
        assert_eq!(std::mem::size_of::<PomsEntry>(), 80);
    }

    #[test]
    fn poms_entry_alignment() {
        assert_eq!(std::mem::align_of::<PomsEntry>(), 8); // u64 field
    }

    #[test]
    fn kanshi_config_size_matches_c() {
        // C struct: 4 + 4 = 8 bytes
        assert_eq!(std::mem::size_of::<KanshiConfig>(), 8);
    }

    #[test]
    fn audit_event_size() {
        // C struct: 4 + 4 + 32 + 1 = 41, padded to 44 for alignment
        let size = std::mem::size_of::<AuditEvent>();
        assert!(size >= 41, "AuditEvent too small: {size}");
    }

    #[test]
    fn poms_entry_field_offsets() {
        let entry = PomsEntry {
            binary_hash: [0xAA; HASH_SIZE],
            poms_hash: [0xBB; HASH_SIZE],
            attested_at: 0x1234567890ABCDEF,
            pid: 42,
            violations: 0,
        };
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&entry as *const PomsEntry).cast::<u8>(),
                std::mem::size_of::<PomsEntry>(),
            )
        };
        // binary_hash at offset 0
        assert_eq!(bytes[0], 0xAA);
        assert_eq!(bytes[31], 0xAA);
        // poms_hash at offset 32
        assert_eq!(bytes[32], 0xBB);
        assert_eq!(bytes[63], 0xBB);
        // attested_at at offset 64 (little-endian u64)
        assert_eq!(bytes[64], 0xEF); // least significant byte
        // pid at offset 72 (little-endian u32)
        assert_eq!(bytes[72], 42);
        // violations at offset 76
        assert_eq!(bytes[76], 0);
    }

    // --- Mock map tests ---

    #[test]
    fn mock_push_and_lookup() {
        let maps = MockBpfMaps::new();
        let hash = [0x42u8; HASH_SIZE];
        let poms = [0xBBu8; HASH_SIZE];

        maps.push_poms_to_kernel(&hash, &poms, 0).unwrap();

        let entry = maps.lookup_poms(&hash).unwrap();
        assert_eq!(entry.binary_hash, hash);
        assert_eq!(entry.poms_hash, poms);
        assert_eq!(entry.violations, 0);
    }

    #[test]
    fn mock_lookup_missing() {
        let maps = MockBpfMaps::new();
        assert!(maps.lookup_poms(&[0u8; HASH_SIZE]).is_none());
    }

    #[test]
    fn mock_revoke() {
        let maps = MockBpfMaps::new();
        let hash = [0x42u8; HASH_SIZE];
        maps.push_poms_to_kernel(&hash, &[0; HASH_SIZE], 0).unwrap();
        assert!(maps.lookup_poms(&hash).is_some());

        maps.revoke_poms(&hash).unwrap();
        assert!(maps.lookup_poms(&hash).is_none());
    }

    #[test]
    fn mock_config() {
        let maps = MockBpfMaps::new();
        let cfg = KanshiConfig { enforce: 1, log_allowed: 1 };
        maps.set_config(cfg).unwrap();
    }

    #[test]
    fn mock_concurrent_access() {
        use std::sync::Arc;
        let maps = Arc::new(MockBpfMaps::new());

        let handles: Vec<_> = (0..100u8)
            .map(|i| {
                let m = Arc::clone(&maps);
                std::thread::spawn(move || {
                    let mut hash = [0u8; HASH_SIZE];
                    hash[0] = i;
                    m.push_poms_to_kernel(&hash, &[i; HASH_SIZE], 0).unwrap();
                    m.lookup_poms(&hash);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(maps.len(), 100);
    }

    // --- Integration with Blake3Hash ---

    #[test]
    fn attest_binary_via_blake3() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"gateway-binary-content");
        let poms = Blake3Hash::digest(b"poms-artifact-json");

        attest_binary(&maps, &binary, &poms).unwrap();

        let entry = maps.lookup_poms(&binary.0).unwrap();
        assert_eq!(entry.violations, 0);
        assert_eq!(&entry.poms_hash, &poms.0);
    }

    #[test]
    fn revoke_binary_via_blake3() {
        let maps = MockBpfMaps::new();
        let binary = Blake3Hash::digest(b"gateway-binary");
        let poms = Blake3Hash::digest(b"poms");

        attest_binary(&maps, &binary, &poms).unwrap();
        assert!(maps.lookup_poms(&binary.0).is_some());

        revoke_binary(&maps, &binary).unwrap();
        assert!(maps.lookup_poms(&binary.0).is_none());
    }
}
