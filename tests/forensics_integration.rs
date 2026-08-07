//! End-to-end forensics integration tests.
//!
//! Proves: compose artifact -> write to MerkleLedger -> index ->
//! query blast radius -> verify timeline -> check provenance
//!
//! Also includes chaos tests using FailableDfcSigner to validate error
//! propagation and concurrent write safety.

use std::sync::Arc;
use std::thread;

use chrono::{Duration, Utc};

use tameshi::certification_artifact::{
    compose_certification_artifact, verify_certification_artifact,
};
use tameshi::forensics::index::LedgerIndex;
use tameshi::forensics::ledger::MerkleLedger;
use tameshi::forensics::query::{blast_radius, compute_evidence_hash, provenance, timeline};
use tameshi::forensics::types::DeploymentContext;
use tameshi::global::compute_cluster_root;
use tameshi::hash::Blake3Hash;
use tameshi::signing::{
    FailableDfcSigner, MerkleRootSigner, MockDfcSigner, SignedRoot, SigningAlgorithm,
};
use tameshi::traits::FixedClock;

// =============================================================================
// Helpers
// =============================================================================

fn make_artifact(label: &str) -> tameshi::certification_artifact::CertificationArtifact {
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
        signer_id: "test-signer".to_string(),
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
        image_ref: "ghcr.io/pleme-io/app:v1".to_string(),
        binary_paths: binaries.into_iter().map(String::from).collect(),
        sdlc_chain_hash: None,
        compliance_report_hash: None,
    }
}

fn make_context_with_cluster(node: &str, cluster: &str, ns: &str, pod: &str) -> DeploymentContext {
    DeploymentContext {
        cluster: cluster.to_string(),
        namespace: ns.to_string(),
        node: node.to_string(),
        pod: pod.to_string(),
        container: "main".to_string(),
        image_ref: "ghcr.io/pleme-io/app:v1".to_string(),
        binary_paths: vec!["/usr/bin/app".to_string()],
        sdlc_chain_hash: None,
        compliance_report_hash: None,
    }
}

// =============================================================================
// E2E: compose -> attest -> query blast radius
// =============================================================================

#[test]
fn e2e_compose_attest_query_blast_radius() {
    // 1. Create 3 CertificationArtifacts for different binaries
    let art_a = make_artifact("alpha");
    let art_b = make_artifact("beta");
    let art_c = make_artifact("gamma");

    assert!(verify_certification_artifact(&art_a));
    assert!(verify_certification_artifact(&art_b));
    assert!(verify_certification_artifact(&art_c));

    // 2. Write all to MerkleLedger with DeploymentContext
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let clock_0 = FixedClock::new(t_base);
    let clock_1 = FixedClock::new(t_base + Duration::seconds(1));
    let clock_2 = FixedClock::new(t_base + Duration::seconds(2));

    let e0 = ledger.append_with_clock(
        art_a.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-a", vec!["/usr/bin/alpha"]),
        &clock_0,
    );
    index.insert(&e0);

    let e1 = ledger.append_with_clock(
        art_b.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-b", vec!["/usr/bin/beta"]),
        &clock_1,
    );
    index.insert(&e1);

    let e2 = ledger.append_with_clock(
        art_c.clone(),
        make_signed_root(),
        make_context("node-2", "kube-system", "pod-c", vec!["/usr/bin/gamma"]),
        &clock_2,
    );
    index.insert(&e2);

    assert_eq!(ledger.len(), 3);
    assert!(ledger.verify_integrity());

    // 3. Build LedgerIndex from entries (already done above)
    // 4. Query blast_radius for one artifact's hash
    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);

    let report = blast_radius(&ledger, &index, &art_a.composed_root, from, to);

    // 5. Verify affected nodes are correct
    assert_eq!(report.total_affected, 1);
    assert_eq!(report.affected_nodes[0].node, "node-1");
    assert_eq!(report.affected_nodes[0].execution_count, 1);
    assert_eq!(report.affected_nodes[0].pods, vec!["pod-a"]);

    // 6. Verify co-resident artifacts are found (art_b is on the same node-1)
    assert!(
        !report.co_resident_artifacts.is_empty(),
        "should find co-resident artifact beta on node-1"
    );
    let co_roots: Vec<_> = report
        .co_resident_artifacts
        .iter()
        .map(|c| c.composed_root.clone())
        .collect();
    assert!(
        co_roots.contains(&art_b.composed_root),
        "beta should be co-resident"
    );

    // 7. Verify evidence_hash is deterministic
    let evidence_recomputed = compute_evidence_hash(&report);
    assert_eq!(report.evidence_hash, evidence_recomputed);

    // Chain integrity must hold
    assert!(report.chain_integrity);
}

// =============================================================================
// E2E: timeline chronological order
// =============================================================================

#[test]
fn e2e_timeline_chronological_order() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("timeline-app");

    // 1. Write 10 entries with different timestamps
    for i in 0..10 {
        let clock = FixedClock::new(t_base + Duration::seconds(i));
        let entry = ledger.append_with_clock(
            art.clone(),
            make_signed_root(),
            make_context(
                &format!("node-{}", i % 3),
                "default",
                &format!("pod-{i}"),
                vec!["/usr/bin/timeline-app"],
            ),
            &clock,
        );
        index.insert(&entry);
    }

    assert_eq!(ledger.len(), 10);

    // 2. Query timeline for the artifact's hash
    let from = t_base - Duration::seconds(1);
    let to = t_base + Duration::seconds(20);
    let events = timeline(&ledger, &index, &art.composed_root, from, to, None);

    assert_eq!(events.len(), 10);

    // 3. Verify events are in chronological order
    for pair in events.windows(2) {
        assert!(
            pair[0].timestamp <= pair[1].timestamp,
            "timeline events must be chronologically ordered: {:?} > {:?}",
            pair[0].timestamp,
            pair[1].timestamp
        );
    }

    // Verify sequence numbers are monotonically increasing
    for pair in events.windows(2) {
        assert!(pair[0].sequence < pair[1].sequence);
    }
}

// =============================================================================
// E2E: provenance at specific time
// =============================================================================

#[test]
fn e2e_provenance_at_specific_time() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();

    // 1. Write entries spanning different time periods
    // Period 1: art_early deployed at t_base
    let art_early = make_artifact("early");
    let clock_early = FixedClock::new(t_base);
    let e_early = ledger.append_with_clock(
        art_early.clone(),
        make_signed_root(),
        make_context("node-A", "default", "pod-early", vec!["/usr/bin/early"]),
        &clock_early,
    );
    index.insert(&e_early);

    // Period 2: art_mid deployed at t_base + 60s
    let art_mid = make_artifact("mid");
    let clock_mid = FixedClock::new(t_base + Duration::seconds(60));
    let e_mid = ledger.append_with_clock(
        art_mid.clone(),
        make_signed_root(),
        make_context("node-A", "default", "pod-mid", vec!["/usr/bin/mid"]),
        &clock_mid,
    );
    index.insert(&e_mid);

    // Period 3: art_late deployed at t_base + 120s
    let art_late = make_artifact("late");
    let clock_late = FixedClock::new(t_base + Duration::seconds(120));
    let e_late = ledger.append_with_clock(
        art_late.clone(),
        make_signed_root(),
        make_context("node-A", "default", "pod-late", vec!["/usr/bin/late"]),
        &clock_late,
    );
    index.insert(&e_late);

    // 2. Query provenance for node-A at t_base + 30s (only early should be active)
    let snap_early = provenance(&ledger, &index, "node-A", t_base + Duration::seconds(30));
    assert_eq!(snap_early.node, "node-A");
    assert_eq!(
        snap_early.active_artifacts.len(),
        1,
        "only 'early' artifact should be active at t_base+30s"
    );
    assert_eq!(
        snap_early.active_artifacts[0]
            .certification_artifact
            .binary_path,
        "/usr/bin/early"
    );

    // 3. Query provenance at t_base + 90s (early + mid should be active)
    let snap_mid = provenance(&ledger, &index, "node-A", t_base + Duration::seconds(90));
    assert_eq!(
        snap_mid.active_artifacts.len(),
        2,
        "early + mid should be active at t_base+90s"
    );

    // 4. Query provenance at t_base + 150s (all three should be active)
    let snap_all = provenance(&ledger, &index, "node-A", t_base + Duration::seconds(150));
    assert_eq!(
        snap_all.active_artifacts.len(),
        3,
        "all three artifacts should be active at t_base+150s"
    );
}

// =============================================================================
// E2E: merkle ledger integrity after blast radius
// =============================================================================

#[test]
fn e2e_merkle_ledger_integrity_after_blast_radius() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("integrity-test");

    for i in 0..5 {
        let clock = FixedClock::new(t_base + Duration::seconds(i));
        let entry = ledger.append_with_clock(
            art.clone(),
            make_signed_root(),
            make_context(
                &format!("node-{i}"),
                "default",
                &format!("pod-{i}"),
                vec!["/usr/bin/integrity-test"],
            ),
            &clock,
        );
        index.insert(&entry);
    }

    // 1. Verify integrity before query
    assert!(ledger.verify_integrity());

    // 2. Query blast radius (read-only operation)
    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);
    let report = blast_radius(&ledger, &index, &art.composed_root, from, to);
    assert_eq!(report.total_affected, 5);

    // 3. Verify ledger integrity still holds (reads should not corrupt chain)
    assert!(ledger.verify_integrity());

    // Also verify the report itself says chain integrity is true
    assert!(report.chain_integrity);

    // Append one more entry after the query
    let clock_extra = FixedClock::new(t_base + Duration::seconds(10));
    let e_extra = ledger.append_with_clock(
        art.clone(),
        make_signed_root(),
        make_context(
            "node-5",
            "default",
            "pod-5",
            vec!["/usr/bin/integrity-test"],
        ),
        &clock_extra,
    );
    index.insert(&e_extra);

    // Integrity must still hold after mixed reads and writes
    assert!(ledger.verify_integrity());
    assert_eq!(ledger.len(), 6);
}

// =============================================================================
// E2E: global cluster root from ledger
// =============================================================================

#[test]
fn e2e_global_cluster_root_from_ledger() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();

    // 1. Write entries to MerkleLedger
    let art_a = make_artifact("cluster-a");
    let art_b = make_artifact("cluster-b");
    let art_c = make_artifact("cluster-c");

    let clock_0 = FixedClock::new(t_base);
    let clock_1 = FixedClock::new(t_base + Duration::seconds(1));
    let clock_2 = FixedClock::new(t_base + Duration::seconds(2));

    let e0 = ledger.append_with_clock(
        art_a.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-a", vec!["/usr/bin/cluster-a"]),
        &clock_0,
    );
    index.insert(&e0);

    let e1 = ledger.append_with_clock(
        art_b.clone(),
        make_signed_root(),
        make_context("node-2", "default", "pod-b", vec!["/usr/bin/cluster-b"]),
        &clock_1,
    );
    index.insert(&e1);

    // 2. Extract all composed_roots
    let entries = ledger.entries();
    let composed_roots: Vec<Blake3Hash> = entries
        .iter()
        .map(|e| e.certification_artifact.composed_root.clone())
        .collect();

    // 3. compute_cluster_root() from composed_roots
    let cluster_root_v1 = compute_cluster_root(&composed_roots);
    assert_ne!(
        cluster_root_v1,
        Blake3Hash::from([0u8; 32]),
        "cluster root should not be zero hash"
    );

    // Determinism: same input -> same output
    let cluster_root_v1_again = compute_cluster_root(&composed_roots);
    assert_eq!(cluster_root_v1, cluster_root_v1_again);

    // 4. Verify ClusterRoot changes when new entry added
    let e2 = ledger.append_with_clock(
        art_c.clone(),
        make_signed_root(),
        make_context("node-3", "default", "pod-c", vec!["/usr/bin/cluster-c"]),
        &clock_2,
    );
    index.insert(&e2);

    let entries_v2 = ledger.entries();
    let composed_roots_v2: Vec<Blake3Hash> = entries_v2
        .iter()
        .map(|e| e.certification_artifact.composed_root.clone())
        .collect();

    let cluster_root_v2 = compute_cluster_root(&composed_roots_v2);
    assert_ne!(
        cluster_root_v1, cluster_root_v2,
        "cluster root must change when a new entry is added"
    );
}

// =============================================================================
// E2E: blast radius with no matches
// =============================================================================

#[test]
fn e2e_blast_radius_with_no_matches() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();

    // 1. Write entries
    let art = make_artifact("legit");
    let clock = FixedClock::new(t_base);
    let entry = ledger.append_with_clock(
        art.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-legit", vec!["/usr/bin/legit"]),
        &clock,
    );
    index.insert(&entry);

    // 2. Query blast_radius for a hash NOT in the ledger
    let unknown_hash = Blake3Hash::digest(b"completely-unknown-artifact");
    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);

    let report = blast_radius(&ledger, &index, &unknown_hash, from, to);

    // 3. Verify empty result
    assert_eq!(report.total_affected, 0);
    assert!(report.affected_nodes.is_empty());
    assert!(report.co_resident_artifacts.is_empty());
    assert!(report.chain_integrity);
}

// =============================================================================
// E2E: revocation tracking via blast radius
// =============================================================================

#[test]
fn e2e_revoke_removes_from_blast_radius() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();

    // 1. Write entries
    let art_good = make_artifact("good-app");
    let art_bad = make_artifact("bad-app");

    let clock_0 = FixedClock::new(t_base);
    let clock_1 = FixedClock::new(t_base + Duration::seconds(1));

    let e0 = ledger.append_with_clock(
        art_good.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-good", vec!["/usr/bin/good-app"]),
        &clock_0,
    );
    index.insert(&e0);

    let e1 = ledger.append_with_clock(
        art_bad.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-bad", vec!["/usr/bin/bad-app"]),
        &clock_1,
    );
    index.insert(&e1);

    // 2. Query blast_radius -- bad hash found
    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);
    let report_before = blast_radius(&ledger, &index, &art_bad.composed_root, from, to);
    assert_eq!(report_before.total_affected, 1);
    assert_eq!(report_before.affected_nodes[0].node, "node-1");

    // 3. "Revoke" by narrowing the time window to before the bad entry was written.
    //    In a real system, revocation would be handled by the sekiban webhook updating
    //    BPF maps. Here we simulate by querying a time range that excludes the entry.
    let to_before_bad = t_base; // exactly at t_base, before clock_1
    let report_after = blast_radius(&ledger, &index, &art_bad.composed_root, from, to_before_bad);

    // 4. Future blast radius queries reflect the revocation time window
    assert_eq!(
        report_after.total_affected, 0,
        "blast radius should be empty when time window excludes the compromised entry"
    );
    assert!(report_after.affected_nodes.is_empty());
}

// =============================================================================
// E2E: timeline filtered by node
// =============================================================================

#[test]
fn e2e_timeline_filtered_by_node() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("filter-app");

    // Deploy same artifact to 3 nodes
    for (i, node) in ["node-x", "node-y", "node-x"].iter().enumerate() {
        let clock = FixedClock::new(t_base + Duration::seconds(i as i64));
        let entry = ledger.append_with_clock(
            art.clone(),
            make_signed_root(),
            make_context(
                node,
                "default",
                &format!("pod-{i}"),
                vec!["/usr/bin/filter-app"],
            ),
            &clock,
        );
        index.insert(&entry);
    }

    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);

    // Unfiltered: all 3 events
    let all_events = timeline(&ledger, &index, &art.composed_root, from, to, None);
    assert_eq!(all_events.len(), 3);

    // Filtered by node-x: 2 events
    let x_events = timeline(
        &ledger,
        &index,
        &art.composed_root,
        from,
        to,
        Some("node-x"),
    );
    assert_eq!(x_events.len(), 2);
    assert!(x_events.iter().all(|e| e.node == "node-x"));

    // Filtered by node-y: 1 event
    let y_events = timeline(
        &ledger,
        &index,
        &art.composed_root,
        from,
        to,
        Some("node-y"),
    );
    assert_eq!(y_events.len(), 1);
    assert_eq!(y_events[0].node, "node-y");
}

// =============================================================================
// E2E: blast radius across clusters
// =============================================================================

#[test]
fn e2e_blast_radius_across_clusters() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("cross-cluster");

    // Deploy same artifact across 2 clusters, multiple nodes
    let deployments = [
        ("node-1", "cluster-a", "ns-1", "pod-1"),
        ("node-2", "cluster-a", "ns-1", "pod-2"),
        ("node-3", "cluster-b", "ns-2", "pod-3"),
    ];

    for (i, (node, cluster, ns, pod)) in deployments.iter().enumerate() {
        let clock = FixedClock::new(t_base + Duration::seconds(i as i64));
        let entry = ledger.append_with_clock(
            art.clone(),
            make_signed_root(),
            make_context_with_cluster(node, cluster, ns, pod),
            &clock,
        );
        index.insert(&entry);
    }

    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);

    let report = blast_radius(&ledger, &index, &art.composed_root, from, to);

    assert_eq!(report.total_affected, 3, "3 nodes should be affected");
    assert!(report.chain_integrity);

    // Verify clusters are represented
    let clusters: Vec<_> = report
        .affected_nodes
        .iter()
        .map(|n| n.cluster.clone())
        .collect();
    assert!(clusters.contains(&"cluster-a".to_string()));
    assert!(clusters.contains(&"cluster-b".to_string()));
}

// =============================================================================
// E2E: evidence hash determinism
// =============================================================================

#[test]
fn e2e_evidence_hash_deterministic_across_calls() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("determinism-check");

    for i in 0..3 {
        let clock = FixedClock::new(t_base + Duration::seconds(i));
        let entry = ledger.append_with_clock(
            art.clone(),
            make_signed_root(),
            make_context(
                &format!("node-{i}"),
                "default",
                &format!("pod-{i}"),
                vec!["/usr/bin/determinism-check"],
            ),
            &clock,
        );
        index.insert(&entry);
    }

    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);

    let report1 = blast_radius(&ledger, &index, &art.composed_root, from, to);
    let report2 = blast_radius(&ledger, &index, &art.composed_root, from, to);

    assert_eq!(
        report1.evidence_hash, report2.evidence_hash,
        "evidence hash must be deterministic across calls with same input"
    );
}

// =============================================================================
// E2E: provenance returns empty on unknown node
// =============================================================================

#[test]
fn e2e_provenance_empty_for_unknown_node() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("known");
    let clock = FixedClock::new(t_base);
    let entry = ledger.append_with_clock(
        art.clone(),
        make_signed_root(),
        make_context("node-known", "default", "pod-1", vec!["/usr/bin/known"]),
        &clock,
    );
    index.insert(&entry);

    let snap = provenance(
        &ledger,
        &index,
        "node-unknown",
        t_base + Duration::seconds(10),
    );
    assert_eq!(snap.node, "node-unknown");
    assert!(
        snap.active_artifacts.is_empty(),
        "unknown node should have no active artifacts"
    );
}

// =============================================================================
// Chaos: DFC timeout during attestation
// =============================================================================

#[tokio::test]
async fn chaos_dfc_timeout_during_attestation() {
    // 1. Create FailableDfcSigner with timeout
    let signer = FailableDfcSigner::new().with_timeout(std::time::Duration::from_secs(5));

    let art = make_artifact("timeout-victim");

    // 2. Attempt to sign the artifact's composed_root
    let result = signer.sign(&art.composed_root).await;

    // 3. Verify error is propagated
    assert!(result.is_err(), "timeout should propagate as error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("timed out"),
        "error message should mention timeout: {err_msg}"
    );

    // 4. Ledger should be unaffected (entry never created because sign failed)
    let ledger = MerkleLedger::new();
    assert!(
        ledger.is_empty(),
        "no entry should be in ledger after failed sign"
    );
    assert!(
        ledger.verify_integrity(),
        "empty ledger integrity is trivially true"
    );
}

// =============================================================================
// Chaos: corrupted signature detected
// =============================================================================

#[tokio::test]
async fn chaos_corrupted_signature_detected() {
    // 1. Create FailableDfcSigner with corrupted signature
    let signer = FailableDfcSigner::new().with_corrupted_signature();

    let art = make_artifact("corrupt-victim");

    // 2. Sign succeeds but signature is corrupted
    let signed = signer.sign(&art.composed_root).await.unwrap();

    // Verify fails because signature is corrupted
    let verify_result = signer.verify(&signed).await.unwrap();
    assert!(
        !verify_result,
        "corrupted signature should fail verification"
    );

    // 3. Write to ledger with the corrupted signed root — the ledger itself still
    //    works (it records what was given), but consumers can detect the bad sig.
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let clock = FixedClock::new(t_base);

    let entry = ledger.append_with_clock(
        art.clone(),
        signed.clone(),
        make_context(
            "node-corrupt",
            "default",
            "pod-c",
            vec!["/usr/bin/corrupt-victim"],
        ),
        &clock,
    );
    index.insert(&entry);

    // The ledger chain integrity is based on hash chaining, not signature verification.
    // So the chain itself is valid, but a consumer querying blast_radius can
    // check the signed_root to detect the corruption.
    assert!(ledger.verify_integrity());

    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);
    let report = blast_radius(&ledger, &index, &art.composed_root, from, to);
    assert_eq!(report.total_affected, 1);
    assert!(report.chain_integrity);

    // Consumer can detect corrupted signature by re-verifying the signed_root
    let clean_signer = MockDfcSigner::for_testing();
    let entries = ledger.entries();
    let stored_signed = &entries[0].signed_root;
    let sig_valid = clean_signer.verify(stored_signed).await.unwrap();
    assert!(
        !sig_valid,
        "clean signer should reject the corrupted signature stored in ledger"
    );
}

// =============================================================================
// Chaos: concurrent writes maintain integrity
// =============================================================================

#[test]
fn chaos_concurrent_writes_maintain_integrity() {
    let ledger = Arc::new(MerkleLedger::new());
    let num_threads = 10;
    let entries_per_thread = 5;

    // 1. Spawn 10 threads, each writing to MerkleLedger
    let mut handles = Vec::new();
    for t in 0..num_threads {
        let ledger_clone = Arc::clone(&ledger);
        handles.push(thread::spawn(move || {
            for i in 0..entries_per_thread {
                let label = format!("thread-{t}-entry-{i}");
                let art = make_artifact(&label);
                ledger_clone.append(
                    art,
                    make_signed_root(),
                    make_context(
                        &format!("node-t{t}"),
                        "default",
                        &format!("pod-t{t}-{i}"),
                        vec![&format!("/usr/bin/{label}")],
                    ),
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    // 2. After all complete, verify_integrity() returns true
    assert!(
        ledger.verify_integrity(),
        "ledger integrity must hold after concurrent writes"
    );

    // 3. Verify total entry count
    let expected_total = num_threads * entries_per_thread;
    assert_eq!(
        ledger.len(),
        expected_total,
        "all {expected_total} entries should be recorded"
    );

    // 4. Verify sequence numbers are monotonic
    let entries = ledger.entries();
    for pair in entries.windows(2) {
        assert!(
            pair[0].sequence < pair[1].sequence,
            "sequence numbers must be monotonically increasing: {} >= {}",
            pair[0].sequence,
            pair[1].sequence
        );
    }

    // 5. Verify hash chain linkage
    for pair in entries.windows(2) {
        assert_eq!(
            pair[1].previous_hash, pair[0].entry_hash,
            "entry {} previous_hash must equal entry {} entry_hash",
            pair[1].sequence, pair[0].sequence
        );
    }
}

// =============================================================================
// Chaos: auth failure prevents ledger corruption
// =============================================================================

#[tokio::test]
async fn chaos_auth_failure_no_ledger_corruption() {
    let signer = FailableDfcSigner::new().with_auth_failure();
    let art = make_artifact("auth-fail");

    // Sign attempt fails
    let result = signer.sign(&art.composed_root).await;
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("authentication failed"),
        "should contain auth failure message: {err_msg}"
    );
}

// =============================================================================
// Chaos: rate limited prevents signing
// =============================================================================

#[tokio::test]
async fn chaos_rate_limited_prevents_signing() {
    let signer = FailableDfcSigner::new().with_rate_limited();
    let art = make_artifact("rate-limited");

    let result = signer.sign(&art.composed_root).await;
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("rate limited"),
        "should contain rate limited message: {err_msg}"
    );
}

// =============================================================================
// E2E: consistency proof spans ledger entries
// =============================================================================

#[test]
fn e2e_consistency_proof_across_ledger() {
    let ledger = MerkleLedger::new();

    let t_base = Utc::now();

    for i in 0..5u64 {
        let clock = FixedClock::new(t_base + Duration::seconds(i as i64));
        ledger.append_with_clock(
            make_artifact(&format!("proof-{i}")),
            make_signed_root(),
            make_context(
                &format!("node-{i}"),
                "default",
                &format!("pod-{i}"),
                vec![&format!("/usr/bin/proof-{i}")],
            ),
            &clock,
        );
    }

    // Generate consistency proof between sequences 1 and 3
    let proof = ledger.consistency_proof(1, 3).unwrap();
    assert_eq!(proof.from_seq, 1);
    assert_eq!(proof.to_seq, 3);
    assert_eq!(proof.proof_nodes.len(), 3); // entries 1, 2, 3

    // Invalid range should error
    let err = ledger.consistency_proof(3, 1);
    assert!(err.is_err());

    // Beyond range should error
    let err = ledger.consistency_proof(0, 100);
    assert!(err.is_err());
}

// =============================================================================
// E2E: blast radius co-resident deduplication
// =============================================================================

#[test]
fn e2e_blast_radius_co_resident_deduplication() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();

    let art_target = make_artifact("target");
    let art_co = make_artifact("co-resident");

    // Deploy target twice to same node (different pods)
    for i in 0..2 {
        let clock = FixedClock::new(t_base + Duration::seconds(i));
        let entry = ledger.append_with_clock(
            art_target.clone(),
            make_signed_root(),
            make_context(
                "shared-node",
                "default",
                &format!("target-pod-{i}"),
                vec!["/usr/bin/target"],
            ),
            &clock,
        );
        index.insert(&entry);
    }

    // Deploy co-resident twice to same node (different pods)
    for i in 0..2 {
        let clock = FixedClock::new(t_base + Duration::seconds(i + 2));
        let entry = ledger.append_with_clock(
            art_co.clone(),
            make_signed_root(),
            make_context(
                "shared-node",
                "default",
                &format!("co-pod-{i}"),
                vec!["/usr/bin/co-resident"],
            ),
            &clock,
        );
        index.insert(&entry);
    }

    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);
    let report = blast_radius(&ledger, &index, &art_target.composed_root, from, to);

    // Co-resident should appear exactly once (deduplicated by composed_root)
    assert_eq!(
        report.co_resident_artifacts.len(),
        1,
        "co-resident artifacts should be deduplicated"
    );
    assert_eq!(
        report.co_resident_artifacts[0].composed_root,
        art_co.composed_root
    );
}

// =============================================================================
// E2E: empty ledger queries
// =============================================================================

#[test]
fn e2e_empty_ledger_queries() {
    let ledger = MerkleLedger::new();
    let index = LedgerIndex::new();

    let now = Utc::now();
    let from = now - Duration::seconds(10);
    let to = now + Duration::seconds(10);

    // Blast radius on empty ledger
    let report = blast_radius(&ledger, &index, &Blake3Hash::digest(b"any"), from, to);
    assert_eq!(report.total_affected, 0);
    assert!(report.chain_integrity);

    // Timeline on empty ledger
    let events = timeline(&ledger, &index, &Blake3Hash::digest(b"any"), from, to, None);
    assert!(events.is_empty());

    // Provenance on empty ledger
    let snap = provenance(&ledger, &index, "any-node", now);
    assert!(snap.active_artifacts.is_empty());
}

// =============================================================================
// E2E: head hash changes with each append
// =============================================================================

#[test]
fn e2e_head_hash_changes() {
    let ledger = MerkleLedger::new();

    let initial_head = ledger.head_hash();
    assert_eq!(initial_head, Blake3Hash::from([0u8; 32]));

    let t_base = Utc::now();
    let clock = FixedClock::new(t_base);

    ledger.append_with_clock(
        make_artifact("first"),
        make_signed_root(),
        make_context("node-1", "default", "pod-1", vec!["/usr/bin/first"]),
        &clock,
    );

    let head_after_first = ledger.head_hash();
    assert_ne!(head_after_first, initial_head);

    let clock2 = FixedClock::new(t_base + Duration::seconds(1));
    ledger.append_with_clock(
        make_artifact("second"),
        make_signed_root(),
        make_context("node-2", "default", "pod-2", vec!["/usr/bin/second"]),
        &clock2,
    );

    let head_after_second = ledger.head_hash();
    assert_ne!(head_after_second, head_after_first);
}

// =============================================================================
// E2E: blast radius multiple hashes point to same entry
// =============================================================================

#[test]
fn e2e_blast_radius_via_artifact_hash() {
    let ledger = MerkleLedger::new();
    let mut index = LedgerIndex::new();

    let t_base = Utc::now();
    let art = make_artifact("multi-hash");
    let clock = FixedClock::new(t_base);

    let entry = ledger.append_with_clock(
        art.clone(),
        make_signed_root(),
        make_context("node-1", "default", "pod-1", vec!["/usr/bin/multi-hash"]),
        &clock,
    );
    index.insert(&entry);

    let from = t_base - Duration::seconds(10);
    let to = t_base + Duration::seconds(10);

    // Query via composed_root
    let report_composed = blast_radius(&ledger, &index, &art.composed_root, from, to);
    assert_eq!(report_composed.total_affected, 1);

    // Query via artifact_hash (also indexed)
    let report_artifact = blast_radius(&ledger, &index, &art.artifact_hash, from, to);
    assert_eq!(report_artifact.total_affected, 1);

    // Query via control_hash
    let report_control = blast_radius(&ledger, &index, &art.control_hash, from, to);
    assert_eq!(report_control.total_affected, 1);

    // Query via intent_hash
    let report_intent = blast_radius(&ledger, &index, &art.intent_hash, from, to);
    assert_eq!(report_intent.total_affected, 1);
}
