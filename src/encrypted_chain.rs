//! Encrypted heartbeat chain entries.
//!
//! Encrypts chain entry payloads using a DFC-derived key before storage.
//! Even if the storage backend is compromised, entries are unreadable
//! without the encryption key fragments.

use crate::hash::Blake3Hash;
use crate::heartbeat::HeartbeatEntry;

/// An encrypted chain entry. The original entry is serialized to JSON,
/// then encrypted via BLAKE3 keyed hash (as a MAC — the "ciphertext"
/// is the entry JSON XOR'd with the keystream).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedEntry {
    /// The encrypted payload (entry JSON XOR'd with BLAKE3 keystream).
    pub ciphertext: Vec<u8>,
    /// The entry sequence number (visible for ordering, not secret).
    pub sequence: u64,
    /// BLAKE3 MAC of the ciphertext for integrity.
    pub mac: Blake3Hash,
}

/// Trait for heartbeat chain entry encryption.
///
/// Enables swapping the encryption algorithm or using a mock
/// that returns deterministic values for testing.
pub trait EntryEncryption: Send + Sync {
    /// Encrypt a heartbeat entry.
    fn encrypt(&self, entry: &HeartbeatEntry, key: &[u8; 32]) -> EncryptedEntry;
    /// Decrypt an encrypted entry.
    fn decrypt(&self, encrypted: &EncryptedEntry, key: &[u8; 32]) -> Result<HeartbeatEntry, String>;
    /// Verify the MAC without decrypting.
    fn verify_mac(&self, encrypted: &EncryptedEntry, key: &[u8; 32]) -> bool;
}

/// BLAKE3 counter-mode encryption (default).
#[derive(Clone, Debug, Default)]
pub struct Blake3CounterModeEncryption;

impl EntryEncryption for Blake3CounterModeEncryption {
    fn encrypt(&self, entry: &HeartbeatEntry, key: &[u8; 32]) -> EncryptedEntry {
        encrypt_entry(entry, key)
    }

    fn decrypt(&self, encrypted: &EncryptedEntry, key: &[u8; 32]) -> Result<HeartbeatEntry, String> {
        decrypt_entry(encrypted, key)
    }

    fn verify_mac(&self, encrypted: &EncryptedEntry, key: &[u8; 32]) -> bool {
        verify_mac(encrypted, key)
    }
}

/// Mock encryption that stores plaintext JSON as "ciphertext" (no actual encryption).
/// Useful for testing that the pipeline works without cryptographic overhead.
#[derive(Clone, Debug, Default)]
pub struct MockEntryEncryption;

impl EntryEncryption for MockEntryEncryption {
    fn encrypt(&self, entry: &HeartbeatEntry, key: &[u8; 32]) -> EncryptedEntry {
        let plaintext = serde_json::to_vec(entry).unwrap();
        let mac = Blake3Hash(blake3::keyed_hash(key, &plaintext).into());
        EncryptedEntry {
            ciphertext: plaintext, // NOT encrypted — mock for testing
            sequence: entry.sequence,
            mac,
        }
    }

    fn decrypt(&self, encrypted: &EncryptedEntry, key: &[u8; 32]) -> Result<HeartbeatEntry, String> {
        let expected_mac = Blake3Hash(blake3::keyed_hash(key, &encrypted.ciphertext).into());
        if encrypted.mac != expected_mac {
            return Err("MAC verification failed".to_string());
        }
        serde_json::from_slice(&encrypted.ciphertext)
            .map_err(|e| format!("invalid JSON: {e}"))
    }

    fn verify_mac(&self, encrypted: &EncryptedEntry, key: &[u8; 32]) -> bool {
        let expected = Blake3Hash(blake3::keyed_hash(key, &encrypted.ciphertext).into());
        encrypted.mac == expected
    }
}

/// Encrypt a heartbeat entry using a 32-byte key.
pub fn encrypt_entry(entry: &HeartbeatEntry, key: &[u8; 32]) -> EncryptedEntry {
    let plaintext = serde_json::to_vec(entry).expect("HeartbeatEntry serialization cannot fail");

    // Generate keystream: BLAKE3 in counter mode
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter = 0u64;
    let mut keystream_pos = 0;
    let mut keystream_block = [0u8; 32];

    for &byte in &plaintext {
        if keystream_pos % 32 == 0 {
            let mut counter_input = Vec::with_capacity(40);
            counter_input.extend_from_slice(key);
            counter_input.extend_from_slice(&counter.to_le_bytes());
            keystream_block = *blake3::hash(&counter_input).as_bytes();
            counter += 1;
            keystream_pos = 0;
        }
        ciphertext.push(byte ^ keystream_block[keystream_pos % 32]);
        keystream_pos += 1;
    }

    // MAC for integrity
    let mac = Blake3Hash(blake3::keyed_hash(key, &ciphertext).into());

    EncryptedEntry {
        ciphertext,
        sequence: entry.sequence,
        mac,
    }
}

/// Decrypt an encrypted entry using the same key.
pub fn decrypt_entry(encrypted: &EncryptedEntry, key: &[u8; 32]) -> Result<HeartbeatEntry, String> {
    // Verify MAC
    let expected_mac = Blake3Hash(blake3::keyed_hash(key, &encrypted.ciphertext).into());
    if encrypted.mac != expected_mac {
        return Err("MAC verification failed: entry may have been tampered".to_string());
    }

    // Decrypt (XOR is symmetric)
    let mut plaintext = Vec::with_capacity(encrypted.ciphertext.len());
    let mut counter = 0u64;
    let mut keystream_pos = 0;
    let mut keystream_block = [0u8; 32];

    for &byte in &encrypted.ciphertext {
        if keystream_pos % 32 == 0 {
            let mut counter_input = Vec::with_capacity(40);
            counter_input.extend_from_slice(key);
            counter_input.extend_from_slice(&counter.to_le_bytes());
            keystream_block = *blake3::hash(&counter_input).as_bytes();
            counter += 1;
            keystream_pos = 0;
        }
        plaintext.push(byte ^ keystream_block[keystream_pos % 32]);
        keystream_pos += 1;
    }

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("decryption produced invalid JSON: {e}"))
}

/// Verify a MAC without decrypting.
pub fn verify_mac(encrypted: &EncryptedEntry, key: &[u8; 32]) -> bool {
    let expected = Blake3Hash(blake3::keyed_hash(key, &encrypted.ciphertext).into());
    encrypted.mac == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::{HeartbeatEvent, VerificationOutcome, VerifierIdentity};
    use chrono::Utc;

    fn test_entry(seq: u64) -> HeartbeatEntry {
        HeartbeatEntry {
            sequence: seq,
            timestamp: Utc::now(),
            verifier: VerifierIdentity::new("test", "node-1", "1.0"),
            event: HeartbeatEvent::GateCheck,
            result: VerificationOutcome::Allowed,
            resource: "test/resource".to_string(),
            signature_checked: Blake3Hash::digest(b"sig"),
            entry_hash: Blake3Hash::digest(format!("entry-{seq}").as_bytes()),
            previous_hash: Blake3Hash::from([0u8; 32]),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let entry = test_entry(1);
        let key = [0xABu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        let decrypted = decrypt_entry(&encrypted, &key).unwrap();
        assert_eq!(entry, decrypted);
    }

    #[test]
    fn wrong_key_mac_fails() {
        let entry = test_entry(2);
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        let result = decrypt_entry(&encrypted, &wrong_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MAC verification failed"));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let entry = test_entry(3);
        let key = [0xABu8; 32];
        let mut encrypted = encrypt_entry(&entry, &key);
        // Tamper with the ciphertext
        if let Some(byte) = encrypted.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        let result = decrypt_entry(&encrypted, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MAC verification failed"));
    }

    #[test]
    fn sequence_visible() {
        let entry = test_entry(42);
        let key = [0xABu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        assert_eq!(encrypted.sequence, 42);
    }

    #[test]
    fn different_keys_different_ciphertext() {
        let entry = test_entry(4);
        let key_1 = [0xAAu8; 32];
        let key_2 = [0xBBu8; 32];
        let enc_1 = encrypt_entry(&entry, &key_1);
        let enc_2 = encrypt_entry(&entry, &key_2);
        assert_ne!(enc_1.ciphertext, enc_2.ciphertext);
    }

    #[test]
    fn verify_mac_correct() {
        let entry = test_entry(5);
        let key = [0xABu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        assert!(verify_mac(&encrypted, &key));
    }

    #[test]
    fn verify_mac_wrong_key() {
        let entry = test_entry(6);
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        assert!(!verify_mac(&encrypted, &wrong_key));
    }

    #[test]
    fn serde_roundtrip() {
        let entry = test_entry(7);
        let key = [0xABu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
        assert_eq!(encrypted.sequence, deserialized.sequence);
        assert_eq!(encrypted.mac, deserialized.mac);
    }

    #[test]
    fn mock_encryption_roundtrip() {
        let mock = MockEntryEncryption;
        let entry = test_entry(0);
        let key = [0x42u8; 32];
        let encrypted = mock.encrypt(&entry, &key);
        let decrypted = mock.decrypt(&encrypted, &key).unwrap();
        assert_eq!(entry.sequence, decrypted.sequence);
    }

    #[test]
    fn trait_object_dispatch_encryption() {
        let enc: Box<dyn EntryEncryption> = Box::new(Blake3CounterModeEncryption);
        let entry = test_entry(0);
        let key = [0x42u8; 32];
        let encrypted = enc.encrypt(&entry, &key);
        assert!(enc.verify_mac(&encrypted, &key));
        let decrypted = enc.decrypt(&encrypted, &key).unwrap();
        assert_eq!(entry.sequence, decrypted.sequence);
    }

    #[test]
    fn encrypt_decrypt_multi_block_payload() {
        let entry = test_entry(99);
        let key = [0x55u8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        assert!(encrypted.ciphertext.len() > 32, "payload should span multiple keystream blocks");
        let decrypted = decrypt_entry(&encrypted, &key).unwrap();
        assert_eq!(entry, decrypted);
    }

    #[test]
    fn ciphertext_not_plaintext() {
        let entry = test_entry(10);
        let key = [0xABu8; 32];
        let plaintext = serde_json::to_vec(&entry).unwrap();
        let encrypted = encrypt_entry(&entry, &key);
        assert_ne!(encrypted.ciphertext, plaintext, "ciphertext must differ from plaintext");
    }

    #[test]
    fn same_entry_same_key_same_ciphertext() {
        let key = [0xAAu8; 32];
        let entry1 = HeartbeatEntry {
            sequence: 1,
            timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap().with_timezone(&Utc),
            verifier: VerifierIdentity::new("test", "node-1", "1.0"),
            event: HeartbeatEvent::GateCheck,
            result: VerificationOutcome::Allowed,
            resource: "test/resource".to_string(),
            signature_checked: Blake3Hash::digest(b"sig"),
            entry_hash: Blake3Hash::digest(b"entry-1"),
            previous_hash: Blake3Hash::from([0u8; 32]),
        };
        let entry2 = entry1.clone();
        let enc1 = encrypt_entry(&entry1, &key);
        let enc2 = encrypt_entry(&entry2, &key);
        assert_eq!(enc1.ciphertext, enc2.ciphertext, "identical entries with same key must produce identical ciphertext");
    }

    #[test]
    fn mock_encryption_mac_fails_with_wrong_key() {
        let mock = MockEntryEncryption;
        let entry = test_entry(0);
        let key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let encrypted = mock.encrypt(&entry, &key);
        assert!(!mock.verify_mac(&encrypted, &wrong_key));
        let result = mock.decrypt(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_entry_serde_json_roundtrip_complete() {
        let entry = test_entry(100);
        let key = [0xCCu8; 32];
        let encrypted = encrypt_entry(&entry, &key);
        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedEntry = serde_json::from_str(&json).unwrap();
        let decrypted = decrypt_entry(&deserialized, &key).unwrap();
        assert_eq!(entry, decrypted, "full roundtrip: encrypt -> serialize -> deserialize -> decrypt");
    }

    #[test]
    fn tampered_mac_fails_verification() {
        let entry = test_entry(11);
        let key = [0xABu8; 32];
        let mut encrypted = encrypt_entry(&entry, &key);
        encrypted.mac = Blake3Hash::digest(b"tampered-mac");
        assert!(!verify_mac(&encrypted, &key));
        assert!(decrypt_entry(&encrypted, &key).is_err());
    }
}
