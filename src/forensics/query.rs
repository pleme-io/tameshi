//! Blast-radius engine — forensic queries over the Merkle ledger.
//!
//! Provides three forensic queries:
//! - **blast_radius** — given a compromised hash, find all affected nodes,
//!   co-resident artifacts, and compute an evidence hash.
//! - **timeline** — chronological reconstruction of events for a hash.
//! - **provenance** — point-in-time snapshot of active artifacts on a node.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::hash::Blake3Hash;

use super::index::LedgerIndex;
use super::ledger::MerkleLedger;
use super::types::{
    ActiveArtifact, AffectedNodeDetail, BlastRadiusReport, CoResidentArtifact, ProvenanceSnapshot,
    TimeRange, TimelineEvent,
};

// =============================================================================
// Blast Radius
// =============================================================================

/// Compute the blast radius for a compromised hash.
///
/// Queries the index for all entries referencing the hash within the time
/// range, aggregates affected nodes, finds co-resident artifacts, verifies
/// chain integrity, and produces a deterministic evidence hash.
#[must_use]
pub fn blast_radius(
    ledger: &MerkleLedger,
    index: &LedgerIndex,
    hash: &Blake3Hash,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> BlastRadiusReport {
    let refs = index.query_by_hash(hash);
    let entries = ledger.entries();

    // Filter to time range
    let matched_entries: Vec<_> = refs
        .iter()
        .filter(|r| r.timestamp >= from && r.timestamp <= to)
        .filter_map(|r| entries.iter().find(|e| e.sequence == r.sequence))
        .collect();

    // Aggregate affected nodes
    let mut node_map: BTreeMap<String, AffectedNodeBuilder> = BTreeMap::new();

    for entry in &matched_entries {
        let ctx = &entry.deployment_context;
        let builder = node_map
            .entry(ctx.node.clone())
            .or_insert_with(|| AffectedNodeBuilder {
                node: ctx.node.clone(),
                cluster: ctx.cluster.clone(),
                first_execution: entry.timestamp,
                last_execution: entry.timestamp,
                execution_count: 0,
                pods: BTreeSet::new(),
                namespaces: BTreeSet::new(),
            });

        builder.execution_count += 1;
        if entry.timestamp < builder.first_execution {
            builder.first_execution = entry.timestamp;
        }
        if entry.timestamp > builder.last_execution {
            builder.last_execution = entry.timestamp;
        }
        builder.pods.insert(ctx.pod.clone());
        builder.namespaces.insert(ctx.namespace.clone());
    }

    let affected_nodes: Vec<AffectedNodeDetail> = node_map
        .into_values()
        .map(|b| AffectedNodeDetail {
            node: b.node,
            cluster: b.cluster,
            first_execution: b.first_execution,
            last_execution: b.last_execution,
            execution_count: b.execution_count,
            pods: b.pods.into_iter().collect(),
            namespaces: b.namespaces.into_iter().collect(),
        })
        .collect();

    // Find co-resident artifacts (other artifacts on the same nodes)
    let affected_node_names: BTreeSet<_> = affected_nodes.iter().map(|n| n.node.clone()).collect();
    let mut co_resident_set: BTreeSet<Blake3Hash> = BTreeSet::new();
    let mut co_resident_artifacts = Vec::new();

    for entry in &entries {
        if affected_node_names.contains(&entry.deployment_context.node)
            && entry.timestamp >= from
            && entry.timestamp <= to
        {
            let art = &entry.certification_artifact;
            // Only include if it's a different artifact
            if &art.composed_root != hash
                && &art.artifact_hash != hash
                && &art.control_hash != hash
                && &art.intent_hash != hash
                && !co_resident_set.contains(&art.composed_root)
            {
                co_resident_set.insert(art.composed_root.clone());
                co_resident_artifacts.push(CoResidentArtifact {
                    composed_root: art.composed_root.clone(),
                    artifact_hash: art.artifact_hash.clone(),
                    control_hash: art.control_hash.clone(),
                    intent_hash: art.intent_hash.clone(),
                    binary_path: art.binary_path.clone(),
                });
            }
        }
    }

    let chain_integrity = ledger.verify_integrity();

    // Compute time range
    let time_range = if matched_entries.is_empty() {
        TimeRange {
            first_seen: from,
            last_seen: to,
        }
    } else {
        let first = matched_entries
            .iter()
            .map(|e| e.timestamp)
            .min()
            .unwrap_or(from);
        let last = matched_entries
            .iter()
            .map(|e| e.timestamp)
            .max()
            .unwrap_or(to);
        TimeRange {
            first_seen: first,
            last_seen: last,
        }
    };

    let total_affected = affected_nodes.len();

    // Build report (without evidence hash first, then compute it)
    let mut report = BlastRadiusReport {
        query_hash: hash.clone(),
        total_affected,
        time_range,
        affected_nodes,
        co_resident_artifacts,
        chain_integrity,
        evidence_hash: Blake3Hash::from([0u8; 32]), // placeholder
    };

    report.evidence_hash = compute_evidence_hash(&report);
    report
}

// =============================================================================
// Timeline
// =============================================================================

/// Reconstruct a chronological timeline of events for a given hash.
///
/// Optionally filter by node name. Returns events sorted by timestamp.
#[must_use]
pub fn timeline(
    ledger: &MerkleLedger,
    index: &LedgerIndex,
    hash: &Blake3Hash,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    node_filter: Option<&str>,
) -> Vec<TimelineEvent> {
    let refs = index.query_by_hash(hash);
    let entries = ledger.entries();

    let mut events: Vec<TimelineEvent> = refs
        .iter()
        .filter(|r| r.timestamp >= from && r.timestamp <= to)
        .filter_map(|r| entries.iter().find(|e| e.sequence == r.sequence))
        .filter(|entry| node_filter.map_or(true, |node| entry.deployment_context.node == node))
        .map(|entry| TimelineEvent {
            timestamp: entry.timestamp,
            event_type: "deployment".to_string(),
            decision: "allowed".to_string(),
            node: entry.deployment_context.node.clone(),
            pod: entry.deployment_context.pod.clone(),
            binary_path: entry.certification_artifact.binary_path.clone(),
            composed_root: entry.certification_artifact.composed_root.clone(),
            sequence: entry.sequence,
        })
        .collect();

    events.sort_by_key(|e| e.timestamp);
    events
}

// =============================================================================
// Provenance
// =============================================================================

/// Compute a point-in-time provenance snapshot for a node.
///
/// Returns all artifacts that were active on the given node at or before
/// the specified timestamp.
#[must_use]
pub fn provenance(
    ledger: &MerkleLedger,
    index: &LedgerIndex,
    node: &str,
    at: DateTime<Utc>,
) -> ProvenanceSnapshot {
    let node_refs = index.query_by_node(node);
    let entries = ledger.entries();

    // Find all entries for this node at or before `at`
    let mut seen_roots = BTreeSet::new();
    let mut active_artifacts = Vec::new();

    for r in &node_refs {
        if r.timestamp <= at {
            if let Some(entry) = entries.iter().find(|e| e.sequence == r.sequence) {
                let root = &entry.certification_artifact.composed_root;
                if !seen_roots.contains(root) {
                    seen_roots.insert(root.clone());
                    active_artifacts.push(ActiveArtifact {
                        certification_artifact: entry.certification_artifact.clone(),
                        signed_root: entry.signed_root.clone(),
                        deployment_context: entry.deployment_context.clone(),
                    });
                }
            }
        }
    }

    ProvenanceSnapshot {
        node: node.to_string(),
        timestamp: at,
        active_artifacts,
    }
}

// =============================================================================
// Evidence Hash
// =============================================================================

/// Compute a deterministic evidence hash of a blast radius report.
///
/// Serializes the report to JSON and hashes it. The `evidence_hash` field
/// is set to all zeros during computation to avoid circular dependency.
#[must_use]
pub fn compute_evidence_hash(report: &BlastRadiusReport) -> Blake3Hash {
    // Create a copy with zeroed evidence_hash to avoid circularity
    let mut canonical = report.clone();
    canonical.evidence_hash = Blake3Hash::from([0u8; 32]);
    let json = serde_json::to_string(&canonical).expect("report serialization should not fail");
    Blake3Hash::digest(json.as_bytes())
}

// =============================================================================
// Internal Helpers
// =============================================================================

struct AffectedNodeBuilder {
    node: String,
    cluster: String,
    first_execution: DateTime<Utc>,
    last_execution: DateTime<Utc>,
    execution_count: u64,
    pods: BTreeSet<String>,
    namespaces: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;
    use crate::forensics::types::DeploymentContext;
    use crate::hash::Blake3Hash;
    use crate::signing::{SignedRoot, SigningAlgorithm};
    use crate::traits::FixedClock;

    fn make_artifact(label: &str) -> crate::certification_artifact::CertificationArtifact {
        compose_certification_artifact(
            &format!("/usr/bin/{label}"),
            Blake3Hash::digest(format!("nix-{label}").as_bytes()),
            Blake3Hash::digest(format!("kensa-{label}").as_bytes()),
            Blake3Hash::digest(format!("pangea-{label}").as_bytes()),
            "production",
        )
    }

    fn make_signed_root() -> SignedRoot {
        SignedRoot {
            root: Blake3Hash::digest(b"root"),
            signature: vec![1, 2, 3],
            algorithm: SigningAlgorithm::Ed25519Local,
            signer_id: "test".to_string(),
            signed_at: Utc::now(),
        }
    }

    fn make_context(node: &str, ns: &str, pod: &str, binaries: Vec<&str>) -> DeploymentContext {
        DeploymentContext {
            cluster: "prod".to_string(),
            namespace: ns.to_string(),
            node: node.to_string(),
            pod: pod.to_string(),
            container: "main".to_string(),
            image_ref: "img:latest".to_string(),
            binary_paths: binaries.into_iter().map(String::from).collect(),
            sdlc_chain_hash: None,
            compliance_report_hash: None,
        }
    }

    fn make_context_cluster(node: &str, cluster: &str, ns: &str, pod: &str) -> DeploymentContext {
        DeploymentContext {
            cluster: cluster.to_string(),
            namespace: ns.to_string(),
            node: node.to_string(),
            pod: pod.to_string(),
            container: "main".to_string(),
            image_ref: "img:latest".to_string(),
            binary_paths: vec!["/usr/bin/app".to_string()],
            sdlc_chain_hash: None,
            compliance_report_hash: None,
        }
    }

    /// Populate a ledger and index with entries, returning the ledger, index, and timestamps.
    fn setup_ledger_and_index() -> (MerkleLedger, LedgerIndex, Vec<DateTime<Utc>>) {
        let ledger = MerkleLedger::new();
        let mut index = LedgerIndex::new();
        let mut timestamps = Vec::new();

        let t_base = Utc::now();

        // Entry 0: artifact "app" on node-1
        let t0 = t_base;
        let clock0 = FixedClock::new(t0);
        let e0 = ledger.append_with_clock(
            make_artifact("app"),
            make_signed_root(),
            make_context("node-1", "default", "pod-1", vec!["/usr/bin/app"]),
            &clock0,
        );
        index.insert(&e0);
        timestamps.push(t0);

        // Entry 1: same artifact "app" on node-2
        let t1 = t_base + chrono::Duration::seconds(10);
        let clock1 = FixedClock::new(t1);
        let e1 = ledger.append_with_clock(
            make_artifact("app"),
            make_signed_root(),
            make_context("node-2", "backend", "pod-2", vec!["/usr/bin/app"]),
            &clock1,
        );
        index.insert(&e1);
        timestamps.push(t1);

        // Entry 2: different artifact "worker" on node-1 (co-resident)
        let t2 = t_base + chrono::Duration::seconds(20);
        let clock2 = FixedClock::new(t2);
        let e2 = ledger.append_with_clock(
            make_artifact("worker"),
            make_signed_root(),
            make_context("node-1", "default", "pod-3", vec!["/usr/bin/worker"]),
            &clock2,
        );
        index.insert(&e2);
        timestamps.push(t2);

        // Entry 3: same artifact "app" on node-1 again (second deployment)
        let t3 = t_base + chrono::Duration::seconds(30);
        let clock3 = FixedClock::new(t3);
        let e3 = ledger.append_with_clock(
            make_artifact("app"),
            make_signed_root(),
            make_context("node-1", "default", "pod-4", vec!["/usr/bin/app"]),
            &clock3,
        );
        index.insert(&e3);
        timestamps.push(t3);

        (ledger, index, timestamps)
    }

    // ---- blast_radius tests ----

    #[test]
    fn test_blast_radius_single_node() {
        let ledger = MerkleLedger::new();
        let mut index = LedgerIndex::new();

        let t = Utc::now();
        let clock = FixedClock::new(t);
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let e = ledger.append_with_clock(
            artifact,
            make_signed_root(),
            make_context("node-1", "default", "pod-1", vec!["/usr/bin/app"]),
            &clock,
        );
        index.insert(&e);

        let report = blast_radius(
            &ledger,
            &index,
            &hash,
            t - chrono::Duration::hours(1),
            t + chrono::Duration::hours(1),
        );

        assert_eq!(report.total_affected, 1);
        assert_eq!(report.affected_nodes[0].node, "node-1");
        assert_eq!(report.affected_nodes[0].execution_count, 1);
        assert!(report.chain_integrity);
    }

    #[test]
    fn test_blast_radius_multiple_nodes() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let from = timestamps[0] - chrono::Duration::hours(1);
        let to = *timestamps.last().unwrap() + chrono::Duration::hours(1);

        let report = blast_radius(&ledger, &index, &hash, from, to);

        assert_eq!(report.total_affected, 2); // node-1 and node-2
        assert!(report.chain_integrity);
    }

    #[test]
    fn test_blast_radius_multiple_clusters() {
        let ledger = MerkleLedger::new();
        let mut index = LedgerIndex::new();
        let t = Utc::now();

        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let e1 = ledger.append_with_clock(
            artifact.clone(),
            make_signed_root(),
            make_context_cluster("n1", "prod-us", "default", "p1"),
            &FixedClock::new(t),
        );
        index.insert(&e1);

        let e2 = ledger.append_with_clock(
            artifact,
            make_signed_root(),
            make_context_cluster("n2", "prod-eu", "default", "p2"),
            &FixedClock::new(t + chrono::Duration::seconds(5)),
        );
        index.insert(&e2);

        let report = blast_radius(
            &ledger,
            &index,
            &hash,
            t - chrono::Duration::hours(1),
            t + chrono::Duration::hours(1),
        );

        assert_eq!(report.total_affected, 2);
        let clusters: BTreeSet<_> = report
            .affected_nodes
            .iter()
            .map(|n| n.cluster.clone())
            .collect();
        assert!(clusters.contains("prod-us"));
        assert!(clusters.contains("prod-eu"));
    }

    #[test]
    fn test_blast_radius_time_filtering() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        // Only include the first entry (t0)
        let report = blast_radius(
            &ledger,
            &index,
            &hash,
            timestamps[0],
            timestamps[0] + chrono::Duration::seconds(5),
        );

        assert_eq!(report.total_affected, 1);
        assert_eq!(report.affected_nodes[0].node, "node-1");
    }

    #[test]
    fn test_blast_radius_co_resident_artifacts() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let from = timestamps[0] - chrono::Duration::hours(1);
        let to = *timestamps.last().unwrap() + chrono::Duration::hours(1);

        let report = blast_radius(&ledger, &index, &hash, from, to);

        // "worker" was co-resident on node-1
        assert!(!report.co_resident_artifacts.is_empty());
        assert!(
            report
                .co_resident_artifacts
                .iter()
                .any(|c| c.binary_path == "/usr/bin/worker")
        );
    }

    #[test]
    fn test_blast_radius_chain_integrity_true() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let report = blast_radius(
            &ledger,
            &index,
            &hash,
            timestamps[0] - chrono::Duration::hours(1),
            *timestamps.last().unwrap() + chrono::Duration::hours(1),
        );

        assert!(report.chain_integrity);
    }

    #[test]
    fn test_blast_radius_evidence_hash_determinism() {
        let ledger = MerkleLedger::new();
        let mut index = LedgerIndex::new();
        let t = Utc::now();
        let clock = FixedClock::new(t);

        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let e = ledger.append_with_clock(
            artifact,
            make_signed_root(),
            make_context("node-1", "default", "pod-1", vec!["/usr/bin/app"]),
            &clock,
        );
        index.insert(&e);

        let r1 = blast_radius(
            &ledger,
            &index,
            &hash,
            t - chrono::Duration::hours(1),
            t + chrono::Duration::hours(1),
        );
        let r2 = blast_radius(
            &ledger,
            &index,
            &hash,
            t - chrono::Duration::hours(1),
            t + chrono::Duration::hours(1),
        );

        assert_eq!(r1.evidence_hash, r2.evidence_hash);
    }

    #[test]
    fn test_blast_radius_hash_not_found() {
        let ledger = MerkleLedger::new();
        let index = LedgerIndex::new();

        let report = blast_radius(
            &ledger,
            &index,
            &Blake3Hash::digest(b"nonexistent"),
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
        );

        assert_eq!(report.total_affected, 0);
        assert!(report.affected_nodes.is_empty());
        assert!(report.co_resident_artifacts.is_empty());
    }

    #[test]
    fn test_blast_radius_empty_ledger() {
        let ledger = MerkleLedger::new();
        let index = LedgerIndex::new();

        let report = blast_radius(
            &ledger,
            &index,
            &Blake3Hash::digest(b"anything"),
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
        );

        assert_eq!(report.total_affected, 0);
        assert!(report.chain_integrity);
    }

    #[test]
    fn test_blast_radius_serde_roundtrip() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let report = blast_radius(
            &ledger,
            &index,
            &hash,
            timestamps[0] - chrono::Duration::hours(1),
            *timestamps.last().unwrap() + chrono::Duration::hours(1),
        );

        let json = serde_json::to_string(&report).unwrap();
        let restored: BlastRadiusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.total_affected, restored.total_affected);
        assert_eq!(report.chain_integrity, restored.chain_integrity);
        assert_eq!(report.evidence_hash, restored.evidence_hash);
    }

    #[test]
    fn test_blast_radius_with_real_certification_artifacts() {
        let ledger = MerkleLedger::new();
        let mut index = LedgerIndex::new();
        let t = Utc::now();

        let art1 = compose_certification_artifact(
            "/usr/bin/myapp",
            Blake3Hash::digest(b"real-nix"),
            Blake3Hash::digest(b"real-kensa"),
            Blake3Hash::digest(b"real-pangea"),
            "production",
        );
        let hash = art1.composed_root.clone();

        let e = ledger.append_with_clock(
            art1,
            make_signed_root(),
            make_context("real-node", "prod", "real-pod", vec!["/usr/bin/myapp"]),
            &FixedClock::new(t),
        );
        index.insert(&e);

        let report = blast_radius(
            &ledger,
            &index,
            &hash,
            t - chrono::Duration::hours(1),
            t + chrono::Duration::hours(1),
        );

        assert_eq!(report.total_affected, 1);
        assert_eq!(report.affected_nodes[0].node, "real-node");
    }

    // ---- timeline tests ----

    #[test]
    fn test_timeline_chronological_order() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let events = timeline(
            &ledger,
            &index,
            &hash,
            timestamps[0] - chrono::Duration::hours(1),
            *timestamps.last().unwrap() + chrono::Duration::hours(1),
            None,
        );

        assert!(!events.is_empty());
        for w in events.windows(2) {
            assert!(w[0].timestamp <= w[1].timestamp);
        }
    }

    #[test]
    fn test_timeline_node_filter() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let events = timeline(
            &ledger,
            &index,
            &hash,
            timestamps[0] - chrono::Duration::hours(1),
            *timestamps.last().unwrap() + chrono::Duration::hours(1),
            Some("node-1"),
        );

        assert!(!events.is_empty());
        for ev in &events {
            assert_eq!(ev.node, "node-1");
        }
    }

    #[test]
    fn test_timeline_time_range() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let events = timeline(
            &ledger,
            &index,
            &hash,
            timestamps[0],
            timestamps[0] + chrono::Duration::seconds(5),
            None,
        );

        // Should only have entries at t0
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_timeline_empty() {
        let ledger = MerkleLedger::new();
        let index = LedgerIndex::new();

        let events = timeline(
            &ledger,
            &index,
            &Blake3Hash::digest(b"nope"),
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
            None,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn test_timeline_multiple_events() {
        let (ledger, index, timestamps) = setup_ledger_and_index();
        let artifact = make_artifact("app");
        let hash = artifact.composed_root.clone();

        let events = timeline(
            &ledger,
            &index,
            &hash,
            timestamps[0] - chrono::Duration::hours(1),
            *timestamps.last().unwrap() + chrono::Duration::hours(1),
            None,
        );

        // 3 entries with artifact "app": seq 0, 1, 3
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_timeline_event_serde_roundtrip() {
        let ev = TimelineEvent {
            timestamp: Utc::now(),
            event_type: "deployment".to_string(),
            decision: "allowed".to_string(),
            node: "node-1".to_string(),
            pod: "pod-1".to_string(),
            binary_path: "/usr/bin/app".to_string(),
            composed_root: Blake3Hash::digest(b"root"),
            sequence: 42,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: TimelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    // ---- provenance tests ----

    #[test]
    fn test_provenance_single_artifact() {
        let (ledger, index, timestamps) = setup_ledger_and_index();

        let snap = provenance(
            &ledger,
            &index,
            "node-2",
            timestamps[1] + chrono::Duration::seconds(5),
        );

        assert_eq!(snap.node, "node-2");
        assert_eq!(snap.active_artifacts.len(), 1);
    }

    #[test]
    fn test_provenance_multiple_artifacts() {
        let (ledger, index, timestamps) = setup_ledger_and_index();

        // node-1 has "app" at t0 and "worker" at t2
        let snap = provenance(
            &ledger,
            &index,
            "node-1",
            *timestamps.last().unwrap() + chrono::Duration::seconds(5),
        );

        assert_eq!(snap.node, "node-1");
        // "app" (deduplicated) + "worker" = 2 unique artifacts
        assert_eq!(snap.active_artifacts.len(), 2);
    }

    #[test]
    fn test_provenance_at_specific_time() {
        let (ledger, index, timestamps) = setup_ledger_and_index();

        // At t0+5s, node-1 only has "app" (worker deployed at t2)
        let snap = provenance(
            &ledger,
            &index,
            "node-1",
            timestamps[0] + chrono::Duration::seconds(5),
        );

        assert_eq!(snap.active_artifacts.len(), 1);
    }

    #[test]
    fn test_provenance_no_artifacts() {
        let ledger = MerkleLedger::new();
        let index = LedgerIndex::new();

        let snap = provenance(&ledger, &index, "nonexistent-node", Utc::now());

        assert_eq!(snap.node, "nonexistent-node");
        assert!(snap.active_artifacts.is_empty());
    }

    #[test]
    fn test_provenance_returns_deployment_context() {
        let (ledger, index, timestamps) = setup_ledger_and_index();

        let snap = provenance(
            &ledger,
            &index,
            "node-1",
            timestamps[0] + chrono::Duration::seconds(5),
        );

        assert!(!snap.active_artifacts.is_empty());
        let dc = &snap.active_artifacts[0].deployment_context;
        assert_eq!(dc.node, "node-1");
        assert_eq!(dc.cluster, "prod");
    }

    #[test]
    fn test_provenance_snapshot_serde_roundtrip() {
        let snap = ProvenanceSnapshot {
            node: "node-1".to_string(),
            timestamp: Utc::now(),
            active_artifacts: vec![],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ProvenanceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap.node, restored.node);
    }

    // ---- evidence hash tests ----

    #[test]
    fn test_compute_evidence_hash_determinism() {
        let now = Utc::now();
        let report = BlastRadiusReport {
            query_hash: Blake3Hash::digest(b"q"),
            total_affected: 1,
            time_range: TimeRange {
                first_seen: now,
                last_seen: now,
            },
            affected_nodes: vec![AffectedNodeDetail {
                node: "n".to_string(),
                cluster: "c".to_string(),
                first_execution: now,
                last_execution: now,
                execution_count: 1,
                pods: vec!["p".to_string()],
                namespaces: vec!["ns".to_string()],
            }],
            co_resident_artifacts: vec![],
            chain_integrity: true,
            evidence_hash: Blake3Hash::from([0u8; 32]),
        };

        let h1 = compute_evidence_hash(&report);
        let h2 = compute_evidence_hash(&report);
        assert_eq!(h1, h2);
    }

    // ---- Serde roundtrip tests for remaining types ----

    #[test]
    fn test_deployment_context_serde_roundtrip() {
        let ctx = make_context("n1", "ns1", "p1", vec!["/bin/a"]);
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: DeploymentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
    }

    #[test]
    fn test_revoke_request_serde_roundtrip() {
        use super::super::types::RevokeRequest;
        let req = RevokeRequest {
            hash: Blake3Hash::digest(b"bad"),
            reason: "compromised".to_string(),
            severity: "critical".to_string(),
            operator: "admin".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let restored: RevokeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, restored);
    }

    #[test]
    fn test_revoke_result_serde_roundtrip() {
        use super::super::types::RevokeResult;
        let res = RevokeResult {
            revoked: true,
            affected_nodes: 3,
            bpf_maps_updated: true,
            heartbeat_entry_sequence: 7,
        };
        let json = serde_json::to_string(&res).unwrap();
        let restored: RevokeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, restored);
    }

    #[test]
    fn test_affected_node_detail_serde() {
        let now = Utc::now();
        let node = AffectedNodeDetail {
            node: "n".to_string(),
            cluster: "c".to_string(),
            first_execution: now,
            last_execution: now,
            execution_count: 5,
            pods: vec!["p1".to_string(), "p2".to_string()],
            namespaces: vec!["ns1".to_string()],
        };
        let json = serde_json::to_string(&node).unwrap();
        let restored: AffectedNodeDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(node, restored);
    }

    #[test]
    fn test_co_resident_artifact_serde() {
        let co = CoResidentArtifact {
            composed_root: Blake3Hash::digest(b"r"),
            artifact_hash: Blake3Hash::digest(b"a"),
            control_hash: Blake3Hash::digest(b"c"),
            intent_hash: Blake3Hash::digest(b"i"),
            binary_path: "/bin/co".to_string(),
        };
        let json = serde_json::to_string(&co).unwrap();
        let restored: CoResidentArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(co, restored);
    }

    #[test]
    fn test_time_range_serde() {
        let now = Utc::now();
        let tr = TimeRange {
            first_seen: now,
            last_seen: now + chrono::Duration::hours(1),
        };
        let json = serde_json::to_string(&tr).unwrap();
        let restored: TimeRange = serde_json::from_str(&json).unwrap();
        assert_eq!(tr, restored);
    }
}
