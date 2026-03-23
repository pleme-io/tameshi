//! Concurrent state modeling proofs.
//!
//! Uses Kani's `spawn` to model multiple threads operating on shared
//! attestation structures simultaneously. Proves that the abstract chain
//! and BPF map models are free of data races, deadlocks, and lost updates
//! regardless of thread interleaving.
//!
//! This corresponds to tameshi's `HeartbeatChain` (RwLock-protected) and
//! the eBPF sentinel map (atomically populated from `CertificationArtifact`).

use crate::{Hash, ZERO_HASH, combine};
#[cfg(kani)]
use crate::{domain_leaf, domain_internal};

/// Atomic-style u32 modeled as a wrapper for Kani's concurrency checking.
/// In real tameshi, this corresponds to `AtomicU64` sequence counters.
#[derive(Debug)]
#[cfg_attr(not(kani), allow(dead_code))]
struct AtomicSeq {
    /// Interior value — Kani tracks memory accesses for data-race detection.
    value: std::sync::atomic::AtomicU32,
}

#[cfg_attr(not(kani), allow(dead_code))]
impl AtomicSeq {
    fn new(v: u32) -> Self {
        Self {
            value: std::sync::atomic::AtomicU32::new(v),
        }
    }

    fn load(&self) -> u32 {
        self.value.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn fetch_add(&self, val: u32) -> u32 {
        self.value
            .fetch_add(val, std::sync::atomic::Ordering::SeqCst)
    }
}

/// Mutex-protected chain state, mirroring `HeartbeatChain`'s `RwLock<Inner>`.
#[cfg_attr(not(kani), allow(dead_code))]
struct ConcurrentChain {
    /// Mutex protects the chain entries and sequence counter.
    inner: std::sync::Mutex<ChainInner>,
}

#[derive(Clone)]
#[cfg_attr(not(kani), allow(dead_code))]
struct ChainInner {
    entries: Vec<ChainEntry>,
    next_seq: u32,
    last_hash: Hash,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(kani), allow(dead_code))]
struct ChainEntry {
    seq: u32,
    content: Hash,
    entry_hash: Hash,
    prev_hash: Hash,
}

#[cfg_attr(not(kani), allow(dead_code))]
impl ConcurrentChain {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(ChainInner {
                entries: Vec::new(),
                next_seq: 0,
                last_hash: ZERO_HASH,
            }),
        }
    }

    /// Append under lock — mirrors HeartbeatChain::append.
    fn append(&self, content: Hash) -> ChainEntry {
        let mut guard = self.inner.lock().unwrap();
        let seq = guard.next_seq;
        let prev = guard.last_hash;
        let entry_hash = combine(&prev, &content);

        let entry = ChainEntry {
            seq,
            content,
            entry_hash,
            prev_hash: prev,
        };

        guard.last_hash = entry_hash;
        guard.next_seq += 1;
        guard.entries.push(entry);
        entry
    }

    /// Verify integrity under lock — mirrors HeartbeatChain::verify_integrity.
    fn verify_integrity(&self) -> bool {
        let guard = self.inner.lock().unwrap();
        let mut expected_prev = ZERO_HASH;
        for entry in &guard.entries {
            if entry.prev_hash != expected_prev {
                return false;
            }
            let recomputed = combine(&entry.prev_hash, &entry.content);
            if entry.entry_hash != recomputed {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }
}

/// Mutex-protected BPF map model.
///
/// In real tameshi, the eBPF sentinel maintains a hash map of
/// `binary_path -> composed_root`. Updates are atomic; lookups must
/// never see partial writes.
#[cfg_attr(not(kani), allow(dead_code))]
struct MockBpfMap {
    /// Maps a "slot" index to a composed root hash.
    /// Mutex ensures no torn reads/writes.
    slots: std::sync::Mutex<[Option<Hash>; 4]>,
}

#[cfg_attr(not(kani), allow(dead_code))]
impl MockBpfMap {
    fn new() -> Self {
        Self {
            slots: std::sync::Mutex::new([None; 4]),
        }
    }

    /// Insert a composed root at a slot.
    fn insert(&self, slot: usize, root: Hash) {
        let mut guard = self.slots.lock().unwrap();
        if slot < 4 {
            guard[slot] = Some(root);
        }
    }

    /// Lookup a slot, returning the composed root if present.
    fn lookup(&self, slot: usize) -> Option<Hash> {
        let guard = self.slots.lock().unwrap();
        if slot < 4 { guard[slot] } else { None }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove: Two concurrent appends to a mutex-protected chain cannot
    /// produce data races, deadlocks, or lost updates.
    ///
    /// Kani explores ALL possible thread interleavings. The mutex ensures
    /// mutual exclusion: one thread acquires the lock, appends, releases;
    /// the other thread then acquires. The final chain always has exactly
    /// 2 entries with valid linkage.
    #[kani::proof]
    #[kani::unwind(5)]
    fn concurrent_chain_append_no_race() {
        let chain = std::sync::Arc::new(ConcurrentChain::new());

        let c1 = chain.clone();
        let c2 = chain.clone();

        let content_a: Hash = kani::any();
        let content_b: Hash = kani::any();

        // Thread 1: append content_a
        let t1 = kani::spawn(move || {
            c1.append(content_a);
        });

        // Thread 2: append content_b
        let t2 = kani::spawn(move || {
            c2.append(content_b);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        // Post-condition: chain has exactly 2 entries
        assert_eq!(chain.len(), 2, "both appends must complete");

        // Post-condition: chain integrity holds regardless of interleaving
        assert!(
            chain.verify_integrity(),
            "chain must be valid after concurrent appends"
        );
    }

    /// Prove: Concurrent BPF map insert and lookup are race-free.
    ///
    /// One thread writes a composed root to slot 0; another thread reads
    /// slot 0. The mutex ensures the reader sees either None (before write)
    /// or Some(root) (after write), never a torn/partial value.
    #[kani::proof]
    #[kani::unwind(3)]
    fn concurrent_bpf_map_no_torn_read() {
        let map = std::sync::Arc::new(MockBpfMap::new());

        let m1 = map.clone();
        let m2 = map.clone();

        // Build a composed root from a 3-leaf artifact
        let leaf_a: Hash = kani::any();
        let leaf_b: Hash = kani::any();
        let leaf_c: Hash = kani::any();
        let dl_a = domain_leaf(&leaf_a);
        let dl_b = domain_leaf(&leaf_b);
        let dl_c = domain_leaf(&leaf_c);
        let n_ab = domain_internal(&dl_a, &dl_b);
        let n_cc = domain_internal(&dl_c, &dl_c);
        let root = domain_internal(&n_ab, &n_cc);

        // Thread 1: insert composed root
        let t1 = kani::spawn(move || {
            m1.insert(0, root);
        });

        // Thread 2: lookup composed root
        let t2 = kani::spawn(move || {
            let val = m2.lookup(0);
            // The value is either None (not yet written) or the exact root
            if let Some(v) = val {
                assert_eq!(v, root, "lookup must return the exact root, not a torn value");
            }
            // None is also valid (write hasn't happened yet)
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }

    /// Prove: Concurrent chain append and integrity verification are
    /// linearizable — verify_integrity always returns true on a
    /// mutex-protected chain, even when interleaved with appends.
    #[kani::proof]
    #[kani::unwind(5)]
    fn concurrent_append_and_verify() {
        let chain = std::sync::Arc::new(ConcurrentChain::new());

        let c1 = chain.clone();
        let c2 = chain.clone();

        let content: Hash = kani::any();

        // Thread 1: append
        let t1 = kani::spawn(move || {
            c1.append(content);
        });

        // Thread 2: verify integrity (may see 0 or 1 entries)
        let t2 = kani::spawn(move || {
            let valid = c2.verify_integrity();
            assert!(valid, "integrity must hold at every linearization point");
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }

    /// Prove: Atomic sequence counter never loses an increment
    /// under concurrent access.
    #[kani::proof]
    #[kani::unwind(3)]
    fn atomic_sequence_no_lost_update() {
        let seq = std::sync::Arc::new(AtomicSeq::new(0));

        let s1 = seq.clone();
        let s2 = seq.clone();

        let t1 = kani::spawn(move || {
            s1.fetch_add(1);
        });

        let t2 = kani::spawn(move || {
            s2.fetch_add(1);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        // Both increments must be visible
        assert_eq!(seq.load(), 2, "both increments must be applied");
    }
}
