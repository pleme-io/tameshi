//! Temporal indexes for the Merkle ledger.
//!
//! `LedgerIndex` maintains five `BTreeMap` indexes over ledger entries,
//! enabling fast forensic lookups by hash, node, namespace, time, and
//! binary path.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::hash::Blake3Hash;

use super::types::{LedgerEntryRef, MerkleLedgerEntry};

// =============================================================================
// LedgerIndex
// =============================================================================

/// Multi-dimensional index over ledger entries.
///
/// Indexes entries by composed/artifact/control/intent hashes, node name,
/// namespace, timestamp, and binary path.
#[derive(Clone, Debug, Default)]
pub struct LedgerIndex {
    /// Index by hash (composed_root, artifact_hash, control_hash, intent_hash).
    pub by_hash: BTreeMap<Blake3Hash, Vec<LedgerEntryRef>>,
    /// Index by node name.
    pub by_node: BTreeMap<String, Vec<LedgerEntryRef>>,
    /// Index by namespace.
    pub by_namespace: BTreeMap<String, Vec<LedgerEntryRef>>,
    /// Index by timestamp.
    pub by_time: BTreeMap<DateTime<Utc>, Vec<LedgerEntryRef>>,
    /// Index by binary path.
    pub by_binary: BTreeMap<String, Vec<LedgerEntryRef>>,
}

impl LedgerIndex {
    /// Create a new empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a ledger entry across all dimensions.
    pub fn insert(&mut self, entry: &MerkleLedgerEntry) {
        let entry_ref = LedgerEntryRef {
            sequence: entry.sequence,
            timestamp: entry.timestamp,
            entry_hash: entry.entry_hash.clone(),
        };

        // Index by all 4 hashes from the certification artifact
        let artifact = &entry.certification_artifact;
        self.by_hash
            .entry(artifact.composed_root.clone())
            .or_default()
            .push(entry_ref.clone());
        self.by_hash
            .entry(artifact.artifact_hash.clone())
            .or_default()
            .push(entry_ref.clone());
        self.by_hash
            .entry(artifact.control_hash.clone())
            .or_default()
            .push(entry_ref.clone());
        self.by_hash
            .entry(artifact.intent_hash.clone())
            .or_default()
            .push(entry_ref.clone());

        // Index by node
        let ctx = &entry.deployment_context;
        self.by_node
            .entry(ctx.node.clone())
            .or_default()
            .push(entry_ref.clone());

        // Index by namespace
        self.by_namespace
            .entry(ctx.namespace.clone())
            .or_default()
            .push(entry_ref.clone());

        // Index by time
        self.by_time
            .entry(entry.timestamp)
            .or_default()
            .push(entry_ref.clone());

        // Index by each binary path
        for path in &ctx.binary_paths {
            self.by_binary
                .entry(path.clone())
                .or_default()
                .push(entry_ref.clone());
        }
    }

    /// Query entries that reference a given hash (any of the 4 hash fields).
    #[must_use]
    pub fn query_by_hash(&self, hash: &Blake3Hash) -> Vec<LedgerEntryRef> {
        self.by_hash.get(hash).cloned().unwrap_or_default()
    }

    /// Query entries deployed on a given node.
    #[must_use]
    pub fn query_by_node(&self, node: &str) -> Vec<LedgerEntryRef> {
        self.by_node.get(node).cloned().unwrap_or_default()
    }

    /// Query entries deployed in a given namespace.
    #[must_use]
    pub fn query_by_namespace(&self, namespace: &str) -> Vec<LedgerEntryRef> {
        self.by_namespace
            .get(namespace)
            .cloned()
            .unwrap_or_default()
    }

    /// Query entries within a time range (inclusive).
    #[must_use]
    pub fn query_by_time_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<LedgerEntryRef> {
        self.by_time
            .range(from..=to)
            .flat_map(|(_, refs)| refs.iter().cloned())
            .collect()
    }

    /// Query entries involving a given binary path.
    #[must_use]
    pub fn query_by_binary(&self, path: &str) -> Vec<LedgerEntryRef> {
        self.by_binary.get(path).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;
    use crate::forensics::types::DeploymentContext;
    use crate::hash::Blake3Hash;
    use crate::signing::{SignedRoot, SigningAlgorithm};

    fn sample_entry(
        seq: u64,
        node: &str,
        namespace: &str,
        binary_paths: Vec<&str>,
    ) -> MerkleLedgerEntry {
        let artifact = compose_certification_artifact(
            binary_paths.first().unwrap_or(&"/usr/bin/app"),
            Blake3Hash::digest(format!("nix-{seq}").as_bytes()),
            Blake3Hash::digest(format!("kensa-{seq}").as_bytes()),
            Blake3Hash::digest(format!("pangea-{seq}").as_bytes()),
            "production",
        );

        MerkleLedgerEntry {
            sequence: seq,
            timestamp: Utc::now(),
            certification_artifact: artifact,
            signed_root: SignedRoot {
                root: Blake3Hash::digest(format!("root-{seq}").as_bytes()),
                signature: vec![1, 2, 3],
                algorithm: SigningAlgorithm::Ed25519Local,
                signer_id: "test".to_string(),
                signed_at: Utc::now(),
            },
            deployment_context: DeploymentContext {
                cluster: "prod".to_string(),
                namespace: namespace.to_string(),
                node: node.to_string(),
                pod: format!("pod-{seq}"),
                container: "main".to_string(),
                image_ref: "img:latest".to_string(),
                binary_paths: binary_paths.into_iter().map(String::from).collect(),
                sdlc_chain_hash: None,
                compliance_report_hash: None,
            },
            entry_hash: Blake3Hash::digest(format!("entry-{seq}").as_bytes()),
            previous_hash: Blake3Hash::from([0u8; 32]),
        }
    }

    fn sample_entry_at(seq: u64, node: &str, ts: DateTime<Utc>) -> MerkleLedgerEntry {
        let mut entry = sample_entry(seq, node, "default", vec!["/usr/bin/app"]);
        entry.timestamp = ts;
        entry
    }

    // ---- Basic tests ----

    #[test]
    fn test_new_index_empty() {
        let idx = LedgerIndex::new();
        assert!(idx.by_hash.is_empty());
        assert!(idx.by_node.is_empty());
        assert!(idx.by_namespace.is_empty());
        assert!(idx.by_time.is_empty());
        assert!(idx.by_binary.is_empty());
    }

    #[test]
    fn test_insert_indexes_composed_root() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let composed = entry.certification_artifact.composed_root.clone();
        idx.insert(&entry);

        let results = idx.query_by_hash(&composed);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sequence, 0);
    }

    #[test]
    fn test_insert_indexes_artifact_hash() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let artifact_hash = entry.certification_artifact.artifact_hash.clone();
        idx.insert(&entry);

        let results = idx.query_by_hash(&artifact_hash);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_indexes_control_hash() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let control_hash = entry.certification_artifact.control_hash.clone();
        idx.insert(&entry);

        let results = idx.query_by_hash(&control_hash);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_indexes_intent_hash() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let intent_hash = entry.certification_artifact.intent_hash.clone();
        idx.insert(&entry);

        let results = idx.query_by_hash(&intent_hash);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_indexes_node() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        idx.insert(&entry);

        let results = idx.query_by_node("node-1");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sequence, 0);
    }

    #[test]
    fn test_insert_indexes_namespace() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "backend", vec!["/usr/bin/app"]);
        idx.insert(&entry);

        let results = idx.query_by_namespace("backend");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_indexes_time() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let ts = entry.timestamp;
        idx.insert(&entry);

        let results = idx.query_by_time_range(ts, ts);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_indexes_binary_paths() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(
            0,
            "node-1",
            "default",
            vec!["/usr/bin/app", "/usr/bin/worker"],
        );
        idx.insert(&entry);

        let r1 = idx.query_by_binary("/usr/bin/app");
        assert_eq!(r1.len(), 1);
        let r2 = idx.query_by_binary("/usr/bin/worker");
        assert_eq!(r2.len(), 1);
    }

    // ---- Query tests ----

    #[test]
    fn test_query_by_hash_found() {
        let mut idx = LedgerIndex::new();
        let entry = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let hash = entry.certification_artifact.composed_root.clone();
        idx.insert(&entry);

        assert!(!idx.query_by_hash(&hash).is_empty());
    }

    #[test]
    fn test_query_by_hash_not_found() {
        let idx = LedgerIndex::new();
        let result = idx.query_by_hash(&Blake3Hash::digest(b"nonexistent"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_query_by_hash_multiple_entries() {
        let mut idx = LedgerIndex::new();
        // Create two entries with the same artifact hash by using same seq
        let e1 = sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]);
        let shared_hash = e1.certification_artifact.artifact_hash.clone();
        idx.insert(&e1);

        // Create another entry that happens to share the same artifact_hash
        let mut e2 = sample_entry(1, "node-2", "default", vec!["/usr/bin/app"]);
        // Manually set the same artifact hash by using same nix input
        let artifact2 = compose_certification_artifact(
            "/usr/bin/app",
            shared_hash.clone(),
            Blake3Hash::digest(b"other-kensa"),
            Blake3Hash::digest(b"other-pangea"),
            "production",
        );
        e2.certification_artifact = artifact2;
        idx.insert(&e2);

        let results = idx.query_by_hash(&shared_hash);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_node_found() {
        let mut idx = LedgerIndex::new();
        idx.insert(&sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]));
        assert_eq!(idx.query_by_node("node-1").len(), 1);
    }

    #[test]
    fn test_query_by_node_not_found() {
        let idx = LedgerIndex::new();
        assert!(idx.query_by_node("nonexistent").is_empty());
    }

    #[test]
    fn test_query_by_time_range() {
        let mut idx = LedgerIndex::new();
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);
        let t3 = t1 + chrono::Duration::seconds(20);

        idx.insert(&sample_entry_at(0, "n", t1));
        idx.insert(&sample_entry_at(1, "n", t2));
        idx.insert(&sample_entry_at(2, "n", t3));

        let results = idx.query_by_time_range(t1, t2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_time_range_empty() {
        let mut idx = LedgerIndex::new();
        let t = Utc::now();
        idx.insert(&sample_entry_at(0, "n", t));

        let future = t + chrono::Duration::hours(1);
        let results = idx.query_by_time_range(future, future + chrono::Duration::hours(1));
        assert!(results.is_empty());
    }

    #[test]
    fn test_query_by_time_range_boundary() {
        let mut idx = LedgerIndex::new();
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(10);

        idx.insert(&sample_entry_at(0, "n", t1));
        idx.insert(&sample_entry_at(1, "n", t2));

        // Exact boundaries are inclusive
        let results = idx.query_by_time_range(t1, t1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sequence, 0);
    }

    #[test]
    fn test_query_by_binary_found() {
        let mut idx = LedgerIndex::new();
        idx.insert(&sample_entry(0, "node-1", "default", vec!["/usr/bin/app"]));
        assert_eq!(idx.query_by_binary("/usr/bin/app").len(), 1);
    }

    #[test]
    fn test_query_by_binary_not_found() {
        let idx = LedgerIndex::new();
        assert!(idx.query_by_binary("/usr/bin/nonexistent").is_empty());
    }

    #[test]
    fn test_multiple_binaries_per_entry() {
        let mut idx = LedgerIndex::new();
        idx.insert(&sample_entry(
            0,
            "node-1",
            "default",
            vec!["/bin/a", "/bin/b", "/bin/c"],
        ));

        assert_eq!(idx.query_by_binary("/bin/a").len(), 1);
        assert_eq!(idx.query_by_binary("/bin/b").len(), 1);
        assert_eq!(idx.query_by_binary("/bin/c").len(), 1);
    }

    #[test]
    fn test_multiple_entries_same_node() {
        let mut idx = LedgerIndex::new();
        idx.insert(&sample_entry(0, "node-1", "default", vec!["/bin/a"]));
        idx.insert(&sample_entry(1, "node-1", "default", vec!["/bin/b"]));
        idx.insert(&sample_entry(2, "node-1", "default", vec!["/bin/c"]));

        let results = idx.query_by_node("node-1");
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_index_after_many_inserts() {
        let mut idx = LedgerIndex::new();
        for i in 0..50 {
            idx.insert(&sample_entry(
                i,
                &format!("node-{}", i % 5),
                "default",
                vec!["/bin/app"],
            ));
        }

        assert_eq!(idx.query_by_node("node-0").len(), 10);
        assert_eq!(idx.query_by_node("node-4").len(), 10);
        assert_eq!(idx.query_by_binary("/bin/app").len(), 50);
    }

    #[test]
    fn test_query_by_namespace() {
        let mut idx = LedgerIndex::new();
        idx.insert(&sample_entry(0, "n", "frontend", vec!["/bin/a"]));
        idx.insert(&sample_entry(1, "n", "backend", vec!["/bin/b"]));
        idx.insert(&sample_entry(2, "n", "frontend", vec!["/bin/c"]));

        assert_eq!(idx.query_by_namespace("frontend").len(), 2);
        assert_eq!(idx.query_by_namespace("backend").len(), 1);
        assert!(idx.query_by_namespace("missing").is_empty());
    }

    #[test]
    fn test_entry_ref_equality() {
        let now = Utc::now();
        let r1 = LedgerEntryRef {
            sequence: 5,
            timestamp: now,
            entry_hash: Blake3Hash::digest(b"same"),
        };
        let r2 = LedgerEntryRef {
            sequence: 5,
            timestamp: now,
            entry_hash: Blake3Hash::digest(b"same"),
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_multiple_entries_same_hash() {
        let mut idx = LedgerIndex::new();
        let e1 = sample_entry(0, "node-1", "default", vec!["/bin/a"]);
        let hash = e1.certification_artifact.composed_root.clone();
        idx.insert(&e1);

        // Insert a second entry with the same composed_root
        let mut e2 = sample_entry(1, "node-2", "default", vec!["/bin/b"]);
        let artifact_with_same_root = compose_certification_artifact(
            "/bin/b",
            e1.certification_artifact.artifact_hash.clone(),
            e1.certification_artifact.control_hash.clone(),
            e1.certification_artifact.intent_hash.clone(),
            "production",
        );
        e2.certification_artifact = artifact_with_same_root;
        idx.insert(&e2);

        let results = idx.query_by_hash(&hash);
        assert!(results.len() >= 2);
    }
}
