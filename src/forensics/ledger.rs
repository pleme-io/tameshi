//! MerkleLedger — append-only, BLAKE3-chained, tamper-proof ledger.
//!
//! Records every `CertificationArtifact` deployment as a
//! `MerkleLedgerEntry` in a hash-linked chain. Follows the same
//! pattern as `HeartbeatChain` in `src/heartbeat.rs`: `RwLock`
//! wrapping inner state, BLAKE3 hash chain with `previous_hash`
//! linkage, `verify_integrity()` walking the chain, and
//! `ConsistencyProof` for remote verification.

use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::certification_artifact::CertificationArtifact;
use crate::error;
use crate::hash::Blake3Hash;
use crate::heartbeat::ConsistencyProof;
use crate::signing::SignedRoot;
use crate::traits::Clock;

use super::index::LedgerIndex;
use super::types::{DeploymentContext, MerkleLedgerEntry};

// =============================================================================
// MerkleLedger
// =============================================================================

/// Append-only Merkle ledger for certification artifact deployments.
///
/// Maintains an ordered sequence of [`MerkleLedgerEntry`] values linked by
/// BLAKE3 hashes. Each new entry includes the hash of the previous entry,
/// making the chain tamper-evident.
///
/// # Thread Safety
///
/// `MerkleLedger` is thread-safe. Internal state is protected by a
/// `RwLock`, allowing concurrent reads and exclusive writes.
pub struct MerkleLedger {
    inner: RwLock<MerkleLedgerInner>,
}

struct MerkleLedgerInner {
    entries: Vec<MerkleLedgerEntry>,
    next_sequence: u64,
    last_hash: Blake3Hash,
}

impl MerkleLedger {
    /// Create a new empty Merkle ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(MerkleLedgerInner {
                entries: Vec::with_capacity(1024),
                next_sequence: 0,
                last_hash: Blake3Hash::from([0u8; 32]),
            }),
        }
    }

    /// Append a new entry to the ledger using the system clock.
    ///
    /// The entry's `sequence`, `entry_hash`, and `previous_hash` are
    /// computed automatically.
    pub fn append(
        &self,
        artifact: CertificationArtifact,
        signed_root: SignedRoot,
        deployment_context: DeploymentContext,
    ) -> MerkleLedgerEntry {
        self.append_with_clock(
            artifact,
            signed_root,
            deployment_context,
            &crate::traits::SystemClock,
        )
    }

    /// Append a new entry with an explicit clock (for deterministic testing).
    pub fn append_with_clock(
        &self,
        artifact: CertificationArtifact,
        signed_root: SignedRoot,
        deployment_context: DeploymentContext,
        clock: &impl Clock,
    ) -> MerkleLedgerEntry {
        let mut inner = self.inner.write().expect("MerkleLedger lock poisoned");
        let sequence = inner.next_sequence;
        let timestamp = clock.now();
        let previous_hash = inner.last_hash.clone();

        let entry_hash = compute_ledger_entry_hash(
            sequence,
            &timestamp,
            &artifact,
            &signed_root,
            &deployment_context,
            &previous_hash,
        );

        let entry = MerkleLedgerEntry {
            sequence,
            timestamp,
            certification_artifact: artifact,
            signed_root,
            deployment_context,
            entry_hash: entry_hash.clone(),
            previous_hash,
        };

        inner.last_hash = entry_hash;
        inner.next_sequence += 1;
        inner.entries.push(entry.clone());
        entry
    }

    /// Verify the integrity of the entire ledger chain.
    ///
    /// Returns `true` if every entry's hash matches its content and every
    /// `previous_hash` points to the correct predecessor.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        let mut expected_prev = Blake3Hash::from([0u8; 32]);

        for entry in &inner.entries {
            if entry.previous_hash != expected_prev {
                return false;
            }

            let recomputed = compute_ledger_entry_hash(
                entry.sequence,
                &entry.timestamp,
                &entry.certification_artifact,
                &entry.signed_root,
                &entry.deployment_context,
                &entry.previous_hash,
            );

            if entry.entry_hash != recomputed {
                return false;
            }

            expected_prev = entry.entry_hash.clone();
        }

        true
    }

    /// Get the number of entries in the ledger.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        inner.entries.len()
    }

    /// Check if the ledger is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        inner.entries.is_empty()
    }

    /// Get the last entry in the ledger.
    #[inline]
    #[must_use]
    pub fn last(&self) -> Option<MerkleLedgerEntry> {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        inner.entries.last().cloned()
    }

    /// Get all entries in the ledger.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> Vec<MerkleLedgerEntry> {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        inner.entries.clone()
    }

    /// Get the current chain head hash.
    #[inline]
    #[must_use]
    pub fn head_hash(&self) -> Blake3Hash {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        inner.last_hash.clone()
    }

    /// Get entries within a time range (inclusive).
    #[must_use]
    pub fn entries_in_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<MerkleLedgerEntry> {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .cloned()
            .collect()
    }

    /// Generate a consistency proof between two sequence numbers.
    ///
    /// # Errors
    ///
    /// Returns an error if `from_seq > to_seq` or if either sequence number
    /// is beyond the current ledger length.
    pub fn consistency_proof(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> error::Result<ConsistencyProof> {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");

        if from_seq > to_seq {
            return Err(error::TameshiError::InvalidInput(format!(
                "from_seq ({from_seq}) must be <= to_seq ({to_seq})"
            )));
        }

        let len = inner.entries.len() as u64;
        if to_seq >= len {
            return Err(error::TameshiError::InvalidInput(format!(
                "to_seq ({to_seq}) is beyond ledger length ({len})"
            )));
        }

        let from_idx = from_seq as usize;
        let to_idx = to_seq as usize;

        let proof_nodes: Vec<Blake3Hash> = inner.entries[from_idx..=to_idx]
            .iter()
            .map(|e| e.entry_hash.clone())
            .collect();

        let from_hash = inner.entries[from_idx].entry_hash.clone();
        let to_hash = inner.entries[to_idx].entry_hash.clone();

        Ok(ConsistencyProof {
            from_seq,
            to_seq,
            from_hash,
            to_hash,
            proof_nodes,
            verified: false,
        })
    }

    /// Verify a consistency proof against the current ledger state.
    #[must_use]
    pub fn verify_consistency_proof(&self, proof: &ConsistencyProof) -> bool {
        let inner = self.inner.read().expect("MerkleLedger lock poisoned");

        if proof.from_seq > proof.to_seq {
            return false;
        }

        let len = inner.entries.len() as u64;
        if proof.to_seq >= len {
            return false;
        }

        let expected_count = (proof.to_seq - proof.from_seq + 1) as usize;
        if proof.proof_nodes.len() != expected_count {
            return false;
        }

        let from_idx = proof.from_seq as usize;
        let to_idx = proof.to_seq as usize;

        // Verify proof nodes match actual entry hashes
        for (i, entry) in inner.entries[from_idx..=to_idx].iter().enumerate() {
            if entry.entry_hash != proof.proof_nodes[i] {
                return false;
            }
        }

        // Verify chain linkage within the range
        for window in inner.entries[from_idx..=to_idx].windows(2) {
            let recomputed = compute_ledger_entry_hash(
                window[1].sequence,
                &window[1].timestamp,
                &window[1].certification_artifact,
                &window[1].signed_root,
                &window[1].deployment_context,
                &window[1].previous_hash,
            );
            if recomputed != window[1].entry_hash {
                return false;
            }
            if window[1].previous_hash != window[0].entry_hash {
                return false;
            }
        }

        // Verify boundary hashes
        if proof.from_hash != inner.entries[from_idx].entry_hash {
            return false;
        }
        if proof.to_hash != inner.entries[to_idx].entry_hash {
            return false;
        }

        true
    }
}

impl Default for MerkleLedger {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Entry Hash Computation
// =============================================================================

/// Compute the BLAKE3 hash of a ledger entry's content.
fn compute_ledger_entry_hash(
    sequence: u64,
    timestamp: &DateTime<Utc>,
    artifact: &CertificationArtifact,
    signed_root: &SignedRoot,
    deployment_context: &DeploymentContext,
    previous_hash: &Blake3Hash,
) -> Blake3Hash {
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(&sequence.to_le_bytes());
    data.extend_from_slice(timestamp.to_rfc3339().as_bytes());
    data.push(0);
    // Include artifact composed root
    data.extend_from_slice(&artifact.composed_root.0);
    // Include signed root's root hash
    data.extend_from_slice(&signed_root.root.0);
    // Include deployment context hash (deterministic serialization)
    let ctx_hash = compute_deployment_context_hash(deployment_context);
    data.extend_from_slice(&ctx_hash.0);
    // Include previous hash
    data.extend_from_slice(&previous_hash.0);
    Blake3Hash::digest(&data)
}

/// Compute a deterministic hash of a `DeploymentContext`.
fn compute_deployment_context_hash(ctx: &DeploymentContext) -> Blake3Hash {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(ctx.cluster.as_bytes());
    data.push(0);
    data.extend_from_slice(ctx.namespace.as_bytes());
    data.push(0);
    data.extend_from_slice(ctx.node.as_bytes());
    data.push(0);
    data.extend_from_slice(ctx.pod.as_bytes());
    data.push(0);
    data.extend_from_slice(ctx.container.as_bytes());
    data.push(0);
    data.extend_from_slice(ctx.image_ref.as_bytes());
    data.push(0);
    for path in &ctx.binary_paths {
        data.extend_from_slice(path.as_bytes());
        data.push(0);
    }
    if let Some(ref h) = ctx.sdlc_chain_hash {
        data.extend_from_slice(&h.0);
    }
    if let Some(ref h) = ctx.compliance_report_hash {
        data.extend_from_slice(&h.0);
    }
    Blake3Hash::digest(&data)
}

// =============================================================================
// MerkleLedgerStore Trait
// =============================================================================

/// Async storage backend for Merkle ledger entries.
///
/// Implementations can persist entries to databases, object storage, or
/// in-memory stores.
pub trait MerkleLedgerStore: Send + Sync {
    /// Append an entry to the store.
    fn append(
        &self,
        entry: MerkleLedgerEntry,
    ) -> Pin<Box<dyn Future<Output = error::Result<u64>> + Send + '_>>;

    /// Get an entry by sequence number.
    fn get(
        &self,
        sequence: u64,
    ) -> Pin<Box<dyn Future<Output = error::Result<Option<MerkleLedgerEntry>>> + Send + '_>>;

    /// Get entries in a sequence range (inclusive).
    fn range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Pin<Box<dyn Future<Output = error::Result<Vec<MerkleLedgerEntry>>> + Send + '_>>;

    /// Get the latest entry.
    fn latest(
        &self,
    ) -> Pin<Box<dyn Future<Output = error::Result<Option<MerkleLedgerEntry>>> + Send + '_>>;

    /// Get the total number of entries.
    fn len(&self) -> Pin<Box<dyn Future<Output = error::Result<u64>> + Send + '_>>;
}

// =============================================================================
// In-Memory Store
// =============================================================================

/// In-memory implementation of `MerkleLedgerStore`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InMemoryLedgerStore {
    pub(crate) entries: std::sync::Mutex<Vec<MerkleLedgerEntry>>,
    #[serde(skip)]
    index: std::sync::Mutex<LedgerIndex>,
}

impl InMemoryLedgerStore {
    /// Create a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
            index: std::sync::Mutex::new(LedgerIndex::new()),
        }
    }
}

impl Default for InMemoryLedgerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleLedgerStore for InMemoryLedgerStore {
    fn append(
        &self,
        entry: MerkleLedgerEntry,
    ) -> Pin<Box<dyn Future<Output = error::Result<u64>> + Send + '_>> {
        Box::pin(async move {
            let mut entries = self.entries.lock().expect("InMemoryLedgerStore lock poisoned");
            let seq = entry.sequence;
            let mut index = self.index.lock().expect("InMemoryLedgerStore index lock poisoned");
            index.insert(&entry);
            entries.push(entry);
            Ok(seq)
        })
    }

    fn get(
        &self,
        sequence: u64,
    ) -> Pin<Box<dyn Future<Output = error::Result<Option<MerkleLedgerEntry>>> + Send + '_>> {
        Box::pin(async move {
            let entries = self.entries.lock().expect("InMemoryLedgerStore lock poisoned");
            Ok(entries.iter().find(|e| e.sequence == sequence).cloned())
        })
    }

    fn range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Pin<Box<dyn Future<Output = error::Result<Vec<MerkleLedgerEntry>>> + Send + '_>> {
        Box::pin(async move {
            let entries = self.entries.lock().expect("InMemoryLedgerStore lock poisoned");
            Ok(entries
                .iter()
                .filter(|e| e.sequence >= from_seq && e.sequence <= to_seq)
                .cloned()
                .collect())
        })
    }

    fn latest(
        &self,
    ) -> Pin<Box<dyn Future<Output = error::Result<Option<MerkleLedgerEntry>>> + Send + '_>> {
        Box::pin(async move {
            let entries = self.entries.lock().expect("InMemoryLedgerStore lock poisoned");
            Ok(entries.last().cloned())
        })
    }

    fn len(&self) -> Pin<Box<dyn Future<Output = error::Result<u64>> + Send + '_>> {
        Box::pin(async move {
            let entries = self.entries.lock().expect("InMemoryLedgerStore lock poisoned");
            Ok(entries.len() as u64)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;
    use crate::signing::{SignedRoot, SigningAlgorithm};
    use crate::traits::FixedClock;

    fn sample_artifact() -> CertificationArtifact {
        compose_certification_artifact(
            "/usr/bin/app",
            Blake3Hash::digest(b"nix-closure"),
            Blake3Hash::digest(b"kensa-result"),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        )
    }

    fn sample_artifact_2() -> CertificationArtifact {
        compose_certification_artifact(
            "/usr/bin/other",
            Blake3Hash::digest(b"nix-2"),
            Blake3Hash::digest(b"kensa-2"),
            Blake3Hash::digest(b"pangea-2"),
            "staging",
        )
    }

    fn sample_signed_root() -> SignedRoot {
        SignedRoot {
            root: Blake3Hash::digest(b"root"),
            signature: vec![1, 2, 3, 4],
            algorithm: SigningAlgorithm::Ed25519Local,
            signer_id: "test-signer".to_string(),
            signed_at: Utc::now(),
        }
    }

    fn sample_context() -> DeploymentContext {
        DeploymentContext {
            cluster: "prod".to_string(),
            namespace: "default".to_string(),
            node: "node-1".to_string(),
            pod: "app-abc".to_string(),
            container: "main".to_string(),
            image_ref: "ghcr.io/pleme-io/app:v1".to_string(),
            binary_paths: vec!["/usr/bin/app".to_string()],
            sdlc_chain_hash: None,
            compliance_report_hash: None,
        }
    }

    fn sample_context_2() -> DeploymentContext {
        DeploymentContext {
            cluster: "prod".to_string(),
            namespace: "backend".to_string(),
            node: "node-2".to_string(),
            pod: "svc-xyz".to_string(),
            container: "main".to_string(),
            image_ref: "ghcr.io/pleme-io/svc:v2".to_string(),
            binary_paths: vec!["/usr/bin/svc".to_string()],
            sdlc_chain_hash: Some(Blake3Hash::digest(b"sdlc")),
            compliance_report_hash: Some(Blake3Hash::digest(b"compliance")),
        }
    }

    fn fixed_clock() -> FixedClock {
        FixedClock::new(Utc::now())
    }

    // ---- Basic tests ----

    #[test]
    fn test_new_ledger_is_empty() {
        let ledger = MerkleLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert!(ledger.last().is_none());
    }

    #[test]
    fn test_append_single_entry() {
        let ledger = MerkleLedger::new();
        let entry = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert_eq!(entry.sequence, 0);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn test_append_multiple_entries_chain_linkage() {
        let ledger = MerkleLedger::new();
        let e0 = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        let e1 = ledger.append(sample_artifact_2(), sample_signed_root(), sample_context_2());

        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
        assert_eq!(e1.previous_hash, e0.entry_hash);
    }

    #[test]
    fn test_entry_hash_determinism() {
        let clock = fixed_clock();
        let ledger1 = MerkleLedger::new();
        let ledger2 = MerkleLedger::new();

        let e1 = ledger1.append_with_clock(
            sample_artifact(),
            sample_signed_root(),
            sample_context(),
            &clock,
        );
        let e2 = ledger2.append_with_clock(
            sample_artifact(),
            sample_signed_root(),
            sample_context(),
            &clock,
        );

        assert_eq!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn test_previous_hash_chain_integrity() {
        let ledger = MerkleLedger::new();
        let e0 = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        let e1 = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        let e2 = ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        assert_eq!(e0.previous_hash, Blake3Hash::from([0u8; 32]));
        assert_eq!(e1.previous_hash, e0.entry_hash);
        assert_eq!(e2.previous_hash, e1.entry_hash);
    }

    #[test]
    fn test_first_entry_has_zero_previous() {
        let ledger = MerkleLedger::new();
        let e = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert_eq!(e.previous_hash, Blake3Hash::from([0u8; 32]));
    }

    // ---- Verify integrity ----

    #[test]
    fn test_verify_integrity_empty() {
        let ledger = MerkleLedger::new();
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn test_verify_integrity_single() {
        let ledger = MerkleLedger::new();
        let _e = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn test_verify_integrity_multiple() {
        let ledger = MerkleLedger::new();
        for _ in 0..10 {
            ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        }
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn test_verify_integrity_tampered_entry_hash() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        // Tamper with an entry hash
        {
            let mut inner = ledger.inner.write().unwrap();
            inner.entries[0].entry_hash = Blake3Hash::digest(b"tampered");
        }

        assert!(!ledger.verify_integrity());
    }

    #[test]
    fn test_verify_integrity_tampered_previous_hash() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        // Tamper with previous hash
        {
            let mut inner = ledger.inner.write().unwrap();
            inner.entries[1].previous_hash = Blake3Hash::digest(b"wrong");
        }

        assert!(!ledger.verify_integrity());
    }

    // ---- len / is_empty / last / head_hash ----

    #[test]
    fn test_len_tracking() {
        let ledger = MerkleLedger::new();
        assert_eq!(ledger.len(), 0);
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert_eq!(ledger.len(), 1);
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn test_is_empty() {
        let ledger = MerkleLedger::new();
        assert!(ledger.is_empty());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert!(!ledger.is_empty());
    }

    #[test]
    fn test_last_returns_most_recent() {
        let ledger = MerkleLedger::new();
        let _e0 = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        let e1 = ledger.append(sample_artifact_2(), sample_signed_root(), sample_context_2());

        let last = ledger.last().unwrap();
        assert_eq!(last.sequence, e1.sequence);
        assert_eq!(last.entry_hash, e1.entry_hash);
    }

    #[test]
    fn test_head_hash_updates() {
        let ledger = MerkleLedger::new();
        let initial = ledger.head_hash();
        assert_eq!(initial, Blake3Hash::from([0u8; 32]));

        let e = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        assert_eq!(ledger.head_hash(), e.entry_hash);
    }

    #[test]
    fn test_entries_returns_all() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        let entries = ledger.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[1].sequence, 1);
        assert_eq!(entries[2].sequence, 2);
    }

    // ---- entries_in_range ----

    #[test]
    fn test_entries_in_range() {
        let ledger = MerkleLedger::new();
        let t1 = Utc::now();
        let clock1 = FixedClock::new(t1);
        let t2 = t1 + chrono::Duration::seconds(10);
        let clock2 = FixedClock::new(t2);
        let t3 = t1 + chrono::Duration::seconds(20);
        let clock3 = FixedClock::new(t3);

        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &clock1);
        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &clock2);
        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &clock3);

        let range = ledger.entries_in_range(t1, t2);
        assert_eq!(range.len(), 2);
    }

    #[test]
    fn test_entries_in_range_empty() {
        let ledger = MerkleLedger::new();
        let t1 = Utc::now();
        let clock = FixedClock::new(t1);
        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &clock);

        let future = t1 + chrono::Duration::hours(1);
        let range = ledger.entries_in_range(future, future + chrono::Duration::hours(1));
        assert!(range.is_empty());
    }

    #[test]
    fn test_entries_in_range_partial() {
        let ledger = MerkleLedger::new();
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(60);
        let t3 = t1 + chrono::Duration::seconds(120);

        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &FixedClock::new(t1));
        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &FixedClock::new(t2));
        ledger.append_with_clock(sample_artifact(), sample_signed_root(), sample_context(), &FixedClock::new(t3));

        // Only the middle entry
        let range = ledger.entries_in_range(
            t1 + chrono::Duration::seconds(30),
            t1 + chrono::Duration::seconds(90),
        );
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].sequence, 1);
    }

    // ---- Consistency proof ----

    #[test]
    fn test_consistency_proof_valid() {
        let ledger = MerkleLedger::new();
        for _ in 0..5 {
            ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        }

        let proof = ledger.consistency_proof(1, 3).unwrap();
        assert_eq!(proof.from_seq, 1);
        assert_eq!(proof.to_seq, 3);
        assert_eq!(proof.proof_nodes.len(), 3);
        assert!(!proof.verified);
        assert!(ledger.verify_consistency_proof(&proof));
    }

    #[test]
    fn test_consistency_proof_single_entry() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        let proof = ledger.consistency_proof(0, 0).unwrap();
        assert_eq!(proof.proof_nodes.len(), 1);
        assert!(ledger.verify_consistency_proof(&proof));
    }

    #[test]
    fn test_consistency_proof_invalid_range() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        let result = ledger.consistency_proof(2, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_consistency_proof_out_of_bounds() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        let result = ledger.consistency_proof(0, 5);
        assert!(result.is_err());
    }

    // ---- Serde roundtrip ----

    #[test]
    fn test_serde_roundtrip_entry() {
        let ledger = MerkleLedger::new();
        let entry = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        let json = serde_json::to_string(&entry).unwrap();
        let restored: MerkleLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.sequence, restored.sequence);
        assert_eq!(entry.entry_hash, restored.entry_hash);
        assert_eq!(entry.previous_hash, restored.previous_hash);
    }

    #[test]
    fn test_serde_roundtrip_ledger_entries() {
        let ledger = MerkleLedger::new();
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        let entries = ledger.entries();
        let json = serde_json::to_string(&entries).unwrap();
        let restored: Vec<MerkleLedgerEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries.len(), restored.len());
    }

    // ---- Thread safety ----

    #[test]
    fn test_concurrent_append() {
        use std::sync::Arc;

        let ledger = Arc::new(MerkleLedger::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let ledger = Arc::clone(&ledger);
            handles.push(std::thread::spawn(move || {
                ledger.append(sample_artifact(), sample_signed_root(), sample_context());
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(ledger.len(), 10);
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn test_thread_safety_rwlock() {
        use std::sync::Arc;

        let ledger = Arc::new(MerkleLedger::new());
        ledger.append(sample_artifact(), sample_signed_root(), sample_context());

        let ledger_clone = Arc::clone(&ledger);
        let reader = std::thread::spawn(move || {
            assert!(!ledger_clone.is_empty());
            assert_eq!(ledger_clone.len(), 1);
        });

        reader.join().unwrap();
    }

    // ---- Entry hash includes all fields ----

    #[test]
    fn test_entry_hash_includes_all_fields() {
        let clock = fixed_clock();
        let ledger1 = MerkleLedger::new();
        let ledger2 = MerkleLedger::new();

        // Same inputs -> same hash
        let e1 = ledger1.append_with_clock(
            sample_artifact(),
            sample_signed_root(),
            sample_context(),
            &clock,
        );
        let e2 = ledger2.append_with_clock(
            sample_artifact(),
            sample_signed_root(),
            sample_context(),
            &clock,
        );
        assert_eq!(e1.entry_hash, e2.entry_hash);

        // Different context -> different hash
        let ledger3 = MerkleLedger::new();
        let e3 = ledger3.append_with_clock(
            sample_artifact(),
            sample_signed_root(),
            sample_context_2(),
            &clock,
        );
        assert_ne!(e1.entry_hash, e3.entry_hash);
    }

    // ---- InMemoryLedgerStore tests ----

    #[tokio::test]
    async fn test_in_memory_store_append_and_get() {
        let store = InMemoryLedgerStore::new();
        let ledger = MerkleLedger::new();
        let entry = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        let seq = store.append(entry.clone()).await.unwrap();
        assert_eq!(seq, 0);

        let got = store.get(0).await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().sequence, 0);

        let missing = store.get(999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_store_range() {
        let store = InMemoryLedgerStore::new();
        let ledger = MerkleLedger::new();

        for _ in 0..5 {
            let entry = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
            store.append(entry).await.unwrap();
        }

        let range = store.range(1, 3).await.unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].sequence, 1);
        assert_eq!(range[2].sequence, 3);
    }

    #[tokio::test]
    async fn test_in_memory_store_latest() {
        let store = InMemoryLedgerStore::new();
        assert!(store.latest().await.unwrap().is_none());

        let ledger = MerkleLedger::new();
        let entry = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        store.append(entry).await.unwrap();

        let latest = store.latest().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().sequence, 0);
    }

    #[tokio::test]
    async fn test_in_memory_store_len() {
        let store = InMemoryLedgerStore::new();
        assert_eq!(store.len().await.unwrap(), 0);

        let ledger = MerkleLedger::new();
        let entry = ledger.append(sample_artifact(), sample_signed_root(), sample_context());
        store.append(entry).await.unwrap();
        assert_eq!(store.len().await.unwrap(), 1);
    }

    // ---- Default impl ----

    #[test]
    fn test_default_creates_empty_ledger() {
        let ledger = MerkleLedger::default();
        assert!(ledger.is_empty());
    }
}
