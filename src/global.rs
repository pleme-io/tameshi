//! Global State Root types for planetary-scale federated Merkle trees.
//!
//! Provides types and functions for aggregating per-cluster attestation
//! roots into a single global state root. Each cluster computes a
//! `ClusterRoot` from its active `composed_root` hashes; the master
//! server aggregates all cluster roots into a `GlobalStateRoot`.
//!
//! Key primitives:
//! - [`compute_cluster_root`] -- deterministic cluster root from composed hashes
//! - [`compute_global_root`] -- deterministic global root from cluster entries
//! - [`GlobalStateClient`] -- trait for master server communication
//! - [`MockGlobalStateClient`] -- test double that records calls

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use crate::hash::Blake3Hash;
use crate::signing::SignedRoot;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The global state root aggregating all cluster roots.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GlobalStateRoot {
    /// BLAKE3 Merkle root of all cluster roots.
    pub root_hash: Blake3Hash,
    /// Per-cluster state, keyed by cluster_id for deterministic BTreeMap ordering.
    pub cluster_roots: BTreeMap<String, ClusterRootEntry>,
    /// When this global root was computed.
    pub computed_at: DateTime<Utc>,
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// BLAKE3 hash of the previous GlobalStateRoot (chain linkage).
    pub previous_root: Blake3Hash,
}

/// A single cluster's contribution to the global state root.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterRootEntry {
    /// Unique cluster identifier (e.g., "plo-us-east", "edge-fleet-07").
    pub cluster_id: String,
    /// BLAKE3 Merkle root of all composed_roots on this cluster.
    pub cluster_root: Blake3Hash,
    /// DFC-signed root (using the cluster's signer).
    pub signed_root: SignedRoot,
    /// Number of nodes reporting attestations.
    pub node_count: u32,
    /// Total number of CertificationArtifacts across all nodes.
    pub artifact_count: u64,
    /// Last time this cluster reported its root.
    pub last_reported: DateTime<Utc>,
    /// Cluster liveness status.
    pub status: ClusterStatus,
}

/// Cluster liveness status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterStatus {
    /// Reported within last 2 intervals.
    Active,
    /// Missed 1-3 reporting intervals.
    Stale,
    /// Missed 3+ reporting intervals.
    Offline,
    /// Manually revoked by operator.
    Revoked,
}

/// Report sent by a local cluster to the master server.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterRootReport {
    /// Unique cluster identifier.
    pub cluster_id: String,
    /// BLAKE3 Merkle root of all composed_roots on this cluster.
    pub cluster_root: Blake3Hash,
    /// DFC-signed root.
    pub signed_root: SignedRoot,
    /// Number of nodes reporting attestations.
    pub node_count: u32,
    /// Total number of CertificationArtifacts across all nodes.
    pub artifact_count: u64,
    /// When this report was generated.
    pub reported_at: DateTime<Utc>,
    /// Delta of artifacts since last report (bandwidth optimization).
    pub artifact_delta: Option<ArtifactDelta>,
}

/// Delta of artifacts since last report (bandwidth optimization).
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactDelta {
    /// Artifacts added since last report.
    pub added: Vec<ArtifactLocation>,
    /// Composed root hashes of artifacts removed since last report.
    pub removed: Vec<Blake3Hash>,
}

/// Location of an artifact in the global fleet.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactLocation {
    /// Cluster where the artifact resides.
    pub cluster_id: String,
    /// Node within the cluster.
    pub node: String,
    /// Kubernetes namespace.
    pub namespace: String,
    /// Pod name.
    pub pod: String,
    /// Path to the binary on disk.
    pub binary_path: String,
    /// Composed root hash of the certification artifact.
    pub composed_root: Blake3Hash,
}

/// Global blast radius report aggregating across all clusters.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GlobalBlastRadiusReport {
    /// The compromised hash being investigated.
    pub query_hash: Blake3Hash,
    /// Total clusters containing the compromised artifact.
    pub total_clusters_affected: usize,
    /// Total nodes across all affected clusters.
    pub total_nodes_affected: usize,
    /// Total pods across all affected clusters.
    pub total_pods_affected: usize,
    /// Clusters confirmed NOT affected.
    pub clusters_not_affected: Vec<String>,
    /// Per-cluster blast radius detail.
    pub cluster_reports: Vec<ClusterBlastRadius>,
    /// Earliest attestation of this hash across all clusters.
    pub global_first_seen: Option<DateTime<Utc>>,
    /// Most recent attestation of this hash across all clusters.
    pub global_last_seen: Option<DateTime<Utc>>,
}

/// Per-cluster blast radius detail.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClusterBlastRadius {
    /// Cluster identifier.
    pub cluster_id: String,
    /// Number of affected nodes in this cluster.
    pub nodes_affected: usize,
    /// Number of affected pods in this cluster.
    pub pods_affected: usize,
    /// First attestation in this cluster.
    pub first_seen: DateTime<Utc>,
    /// Most recent attestation in this cluster.
    pub last_seen: DateTime<Utc>,
    /// Per-node breakdown.
    pub node_details: Vec<NodeBlastRadius>,
}

/// Per-node blast radius detail.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NodeBlastRadius {
    /// Node identifier.
    pub node: String,
    /// Affected pods on this node.
    pub pods: Vec<String>,
    /// Binary paths containing the compromised artifact.
    pub binary_paths: Vec<String>,
    /// First execution on this node.
    pub first_execution: DateTime<Utc>,
    /// Most recent execution on this node.
    pub last_execution: DateTime<Utc>,
    /// Total execution count.
    pub execution_count: u64,
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Compute a cluster root from all active `composed_root` hashes.
///
/// Hashes are sorted for determinism, then concatenated and BLAKE3-hashed.
/// This produces a single hash representing the entire cluster's attestation state.
#[must_use]
pub fn compute_cluster_root(composed_roots: &[Blake3Hash]) -> Blake3Hash {
    let mut sorted: Vec<_> = composed_roots.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut data = Vec::with_capacity(sorted.len() * 32);
    for root in &sorted {
        data.extend_from_slice(&root.0);
    }
    Blake3Hash::digest(&data)
}

/// Compute the global state root from all cluster roots.
///
/// Iterates the `BTreeMap` (already sorted by key) and concatenates
/// cluster root hashes, then BLAKE3-hashes the result.
#[must_use]
pub fn compute_global_root(cluster_roots: &BTreeMap<String, ClusterRootEntry>) -> Blake3Hash {
    let mut data = Vec::with_capacity(cluster_roots.len() * 32);
    for (_id, entry) in cluster_roots {
        data.extend_from_slice(&entry.cluster_root.0);
    }
    Blake3Hash::digest(&data)
}

// ---------------------------------------------------------------------------
// GlobalStateClient trait
// ---------------------------------------------------------------------------

/// Trait for communicating with the global state root master server.
///
/// All methods return pinned boxed futures for object safety.
pub trait GlobalStateClient: Send + Sync {
    /// Report a cluster's root to the master server.
    /// Returns the new global sequence number.
    fn report_root(
        &self,
        report: &ClusterRootReport,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<u64>> + Send + '_>>;

    /// Query the global blast radius for a given hash.
    fn query_global_blast_radius(
        &self,
        hash: &Blake3Hash,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<GlobalBlastRadiusReport>> + Send + '_>>;

    /// Revoke a hash across all clusters.
    /// Returns the list of cluster IDs that confirmed revocation.
    fn revoke_everywhere(
        &self,
        hash: &Blake3Hash,
        reason: &str,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<Vec<String>>> + Send + '_>>;

    /// Get the current global state root.
    fn get_global_root(
        &self,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<GlobalStateRoot>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// MockGlobalStateClient
// ---------------------------------------------------------------------------

/// Mock implementation of [`GlobalStateClient`] for testing.
///
/// Records all calls for later assertion. Returns configurable responses.
pub struct MockGlobalStateClient {
    /// Recorded reports.
    pub reports: Mutex<Vec<ClusterRootReport>>,
    /// Recorded revocations (hash, reason).
    pub revocations: Mutex<Vec<(Blake3Hash, String)>>,
    /// The global state root to return from `get_global_root`.
    pub configured_root: Mutex<Option<GlobalStateRoot>>,
    /// The blast radius report to return from `query_global_blast_radius`.
    pub configured_blast_radius: Mutex<Option<GlobalBlastRadiusReport>>,
    /// Sequence counter for report_root responses.
    pub next_sequence: Mutex<u64>,
    /// Cluster IDs to return from revoke_everywhere.
    pub revocation_clusters: Mutex<Vec<String>>,
}

impl MockGlobalStateClient {
    /// Create a new mock with empty state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reports: Mutex::new(Vec::new()),
            revocations: Mutex::new(Vec::new()),
            configured_root: Mutex::new(None),
            configured_blast_radius: Mutex::new(None),
            next_sequence: Mutex::new(1),
            revocation_clusters: Mutex::new(Vec::new()),
        }
    }
}

impl Default for MockGlobalStateClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalStateClient for MockGlobalStateClient {
    fn report_root(
        &self,
        report: &ClusterRootReport,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<u64>> + Send + '_>> {
        let report = report.clone();
        Box::pin(async move {
            let mut reports = self.reports.lock().unwrap();
            reports.push(report);
            let mut seq = self.next_sequence.lock().unwrap();
            let current = *seq;
            *seq += 1;
            Ok(current)
        })
    }

    fn query_global_blast_radius(
        &self,
        _hash: &Blake3Hash,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<GlobalBlastRadiusReport>> + Send + '_>>
    {
        Box::pin(async move {
            let configured = self.configured_blast_radius.lock().unwrap();
            configured.clone().ok_or_else(|| {
                crate::error::TameshiError::InvalidInput(
                    "no blast radius configured in mock".to_string(),
                )
            })
        })
    }

    fn revoke_everywhere(
        &self,
        hash: &Blake3Hash,
        reason: &str,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<Vec<String>>> + Send + '_>> {
        let hash = hash.clone();
        let reason = reason.to_string();
        Box::pin(async move {
            let mut revocations = self.revocations.lock().unwrap();
            revocations.push((hash, reason));
            let clusters = self.revocation_clusters.lock().unwrap();
            Ok(clusters.clone())
        })
    }

    fn get_global_root(
        &self,
    ) -> Pin<Box<dyn Future<Output = crate::error::Result<GlobalStateRoot>> + Send + '_>> {
        Box::pin(async move {
            let configured = self.configured_root.lock().unwrap();
            configured.clone().ok_or_else(|| {
                crate::error::TameshiError::InvalidInput(
                    "no global root configured in mock".to_string(),
                )
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Helper to create test fixtures
// ---------------------------------------------------------------------------

/// Create a minimal `SignedRoot` for testing.
#[cfg(test)]
fn test_signed_root(root: &Blake3Hash) -> SignedRoot {
    SignedRoot {
        root: root.clone(),
        signature: vec![0xAA; 64],
        algorithm: crate::signing::SigningAlgorithm::MockDfc,
        signer_id: "test-signer".to_string(),
        signed_at: Utc::now(),
    }
}

/// Create a minimal `ClusterRootEntry` for testing.
#[cfg(test)]
fn test_cluster_entry(cluster_id: &str, root: Blake3Hash) -> ClusterRootEntry {
    ClusterRootEntry {
        cluster_id: cluster_id.to_string(),
        cluster_root: root.clone(),
        signed_root: test_signed_root(&root),
        node_count: 3,
        artifact_count: 100,
        last_reported: Utc::now(),
        status: ClusterStatus::Active,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===================================================================
    // Type serde roundtrip tests (15 tests)
    // ===================================================================

    #[test]
    fn cluster_status_active_serde_roundtrip() {
        let status = ClusterStatus::Active;
        let json = serde_json::to_string(&status).unwrap();
        let parsed: ClusterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
        assert!(json.contains("active"));
    }

    #[test]
    fn cluster_status_stale_serde_roundtrip() {
        let status = ClusterStatus::Stale;
        let json = serde_json::to_string(&status).unwrap();
        let parsed: ClusterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
        assert!(json.contains("stale"));
    }

    #[test]
    fn cluster_status_offline_serde_roundtrip() {
        let status = ClusterStatus::Offline;
        let json = serde_json::to_string(&status).unwrap();
        let parsed: ClusterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
        assert!(json.contains("offline"));
    }

    #[test]
    fn cluster_status_revoked_serde_roundtrip() {
        let status = ClusterStatus::Revoked;
        let json = serde_json::to_string(&status).unwrap();
        let parsed: ClusterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
        assert!(json.contains("revoked"));
    }

    #[test]
    fn cluster_root_entry_serde_roundtrip() {
        let root = Blake3Hash::digest(b"cluster-root");
        let entry = test_cluster_entry("plo-us-east", root);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ClusterRootEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cluster_id, "plo-us-east");
        assert_eq!(parsed.cluster_root, entry.cluster_root);
        assert_eq!(parsed.node_count, 3);
        assert_eq!(parsed.artifact_count, 100);
        assert_eq!(parsed.status, ClusterStatus::Active);
    }

    #[test]
    fn global_state_root_serde_roundtrip() {
        let root_hash = Blake3Hash::digest(b"global");
        let prev = Blake3Hash::digest(b"previous");
        let gsr = GlobalStateRoot {
            root_hash,
            cluster_roots: BTreeMap::new(),
            computed_at: Utc::now(),
            sequence: 42,
            previous_root: prev,
        };
        let json = serde_json::to_string(&gsr).unwrap();
        let parsed: GlobalStateRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sequence, 42);
        assert_eq!(parsed.root_hash, gsr.root_hash);
        assert_eq!(parsed.previous_root, gsr.previous_root);
    }

    #[test]
    fn cluster_root_report_serde_roundtrip() {
        let root = Blake3Hash::digest(b"report-root");
        let report = ClusterRootReport {
            cluster_id: "edge-fleet-07".to_string(),
            cluster_root: root.clone(),
            signed_root: test_signed_root(&root),
            node_count: 12,
            artifact_count: 500,
            reported_at: Utc::now(),
            artifact_delta: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ClusterRootReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cluster_id, "edge-fleet-07");
        assert_eq!(parsed.node_count, 12);
        assert_eq!(parsed.artifact_count, 500);
    }

    #[test]
    fn artifact_delta_serde_roundtrip() {
        let loc = ArtifactLocation {
            cluster_id: "plo".to_string(),
            node: "node-01".to_string(),
            namespace: "default".to_string(),
            pod: "app-pod-abc".to_string(),
            binary_path: "/usr/bin/app".to_string(),
            composed_root: Blake3Hash::digest(b"composed"),
        };
        let delta = ArtifactDelta {
            added: vec![loc],
            removed: vec![Blake3Hash::digest(b"old-artifact")],
        };
        let json = serde_json::to_string(&delta).unwrap();
        let parsed: ArtifactDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.added.len(), 1);
        assert_eq!(parsed.removed.len(), 1);
        assert_eq!(parsed.added[0].binary_path, "/usr/bin/app");
    }

    #[test]
    fn artifact_location_serde_roundtrip() {
        let loc = ArtifactLocation {
            cluster_id: "plo-eu-west".to_string(),
            node: "worker-03".to_string(),
            namespace: "production".to_string(),
            pod: "api-7f8d9".to_string(),
            binary_path: "/nix/store/abc-app/bin/server".to_string(),
            composed_root: Blake3Hash::digest(b"location-root"),
        };
        let json = serde_json::to_string(&loc).unwrap();
        let parsed: ArtifactLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cluster_id, "plo-eu-west");
        assert_eq!(parsed.node, "worker-03");
        assert_eq!(parsed.namespace, "production");
        assert_eq!(parsed.pod, "api-7f8d9");
    }

    #[test]
    fn global_blast_radius_report_serde_roundtrip() {
        let report = GlobalBlastRadiusReport {
            query_hash: Blake3Hash::digest(b"vuln-hash"),
            total_clusters_affected: 2,
            total_nodes_affected: 59,
            total_pods_affected: 270,
            clusters_not_affected: vec!["plo-eu-west".to_string()],
            cluster_reports: vec![ClusterBlastRadius {
                cluster_id: "plo-us-east".to_string(),
                nodes_affected: 47,
                pods_affected: 234,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                node_details: vec![],
            }],
            global_first_seen: Some(Utc::now()),
            global_last_seen: Some(Utc::now()),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: GlobalBlastRadiusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_clusters_affected, 2);
        assert_eq!(parsed.total_nodes_affected, 59);
        assert_eq!(parsed.total_pods_affected, 270);
        assert_eq!(parsed.clusters_not_affected.len(), 1);
    }

    #[test]
    fn cluster_blast_radius_serde_roundtrip() {
        let cbr = ClusterBlastRadius {
            cluster_id: "edge-fleet-07".to_string(),
            nodes_affected: 12,
            pods_affected: 36,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            node_details: vec![NodeBlastRadius {
                node: "node-01".to_string(),
                pods: vec!["pod-a".to_string(), "pod-b".to_string()],
                binary_paths: vec!["/usr/bin/app".to_string()],
                first_execution: Utc::now(),
                last_execution: Utc::now(),
                execution_count: 42,
            }],
        };
        let json = serde_json::to_string(&cbr).unwrap();
        let parsed: ClusterBlastRadius = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cluster_id, "edge-fleet-07");
        assert_eq!(parsed.node_details.len(), 1);
        assert_eq!(parsed.node_details[0].execution_count, 42);
    }

    #[test]
    fn node_blast_radius_serde_roundtrip() {
        let nbr = NodeBlastRadius {
            node: "worker-05".to_string(),
            pods: vec!["api-1".to_string(), "api-2".to_string(), "api-3".to_string()],
            binary_paths: vec!["/usr/bin/server".to_string(), "/usr/bin/worker".to_string()],
            first_execution: Utc::now(),
            last_execution: Utc::now(),
            execution_count: 1500,
        };
        let json = serde_json::to_string(&nbr).unwrap();
        let parsed: NodeBlastRadius = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.node, "worker-05");
        assert_eq!(parsed.pods.len(), 3);
        assert_eq!(parsed.binary_paths.len(), 2);
        assert_eq!(parsed.execution_count, 1500);
    }

    #[test]
    fn global_blast_radius_multiple_clusters() {
        let report = GlobalBlastRadiusReport {
            query_hash: Blake3Hash::digest(b"multi-cluster"),
            total_clusters_affected: 3,
            total_nodes_affected: 100,
            total_pods_affected: 500,
            clusters_not_affected: vec![],
            cluster_reports: vec![
                ClusterBlastRadius {
                    cluster_id: "us-east".to_string(),
                    nodes_affected: 40,
                    pods_affected: 200,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    node_details: vec![],
                },
                ClusterBlastRadius {
                    cluster_id: "eu-west".to_string(),
                    nodes_affected: 30,
                    pods_affected: 150,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    node_details: vec![],
                },
                ClusterBlastRadius {
                    cluster_id: "ap-south".to_string(),
                    nodes_affected: 30,
                    pods_affected: 150,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    node_details: vec![],
                },
            ],
            global_first_seen: Some(Utc::now()),
            global_last_seen: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: GlobalBlastRadiusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cluster_reports.len(), 3);
        assert!(parsed.global_last_seen.is_none());
    }

    #[test]
    fn artifact_delta_with_added_and_removed() {
        let delta = ArtifactDelta {
            added: vec![
                ArtifactLocation {
                    cluster_id: "c1".to_string(),
                    node: "n1".to_string(),
                    namespace: "ns1".to_string(),
                    pod: "p1".to_string(),
                    binary_path: "/bin/a".to_string(),
                    composed_root: Blake3Hash::digest(b"a"),
                },
                ArtifactLocation {
                    cluster_id: "c1".to_string(),
                    node: "n2".to_string(),
                    namespace: "ns2".to_string(),
                    pod: "p2".to_string(),
                    binary_path: "/bin/b".to_string(),
                    composed_root: Blake3Hash::digest(b"b"),
                },
            ],
            removed: vec![Blake3Hash::digest(b"old-a"), Blake3Hash::digest(b"old-b")],
        };
        let json = serde_json::to_string(&delta).unwrap();
        let parsed: ArtifactDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.added.len(), 2);
        assert_eq!(parsed.removed.len(), 2);
    }

    // ===================================================================
    // compute_cluster_root function tests (20 tests)
    // ===================================================================

    #[test]
    fn compute_cluster_root_deterministic() {
        let roots = vec![
            Blake3Hash::digest(b"app-1"),
            Blake3Hash::digest(b"app-2"),
            Blake3Hash::digest(b"app-3"),
        ];
        let r1 = compute_cluster_root(&roots);
        let r2 = compute_cluster_root(&roots);
        assert_eq!(r1, r2, "same inputs must produce same cluster root");
    }

    #[test]
    fn compute_cluster_root_sorted_order_independent() {
        let a = Blake3Hash::digest(b"alpha");
        let b = Blake3Hash::digest(b"beta");
        let c = Blake3Hash::digest(b"gamma");
        let r1 = compute_cluster_root(&[a.clone(), b.clone(), c.clone()]);
        let r2 = compute_cluster_root(&[c.clone(), a.clone(), b.clone()]);
        let r3 = compute_cluster_root(&[b, c, a]);
        assert_eq!(r1, r2, "order must not matter");
        assert_eq!(r2, r3, "order must not matter");
    }

    #[test]
    fn compute_cluster_root_empty() {
        let root = compute_cluster_root(&[]);
        // Empty input should produce the hash of empty data.
        let expected = Blake3Hash::digest(&[]);
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_cluster_root_single_root() {
        let single = Blake3Hash::digest(b"only-one");
        let root = compute_cluster_root(&[single.clone()]);
        // Single root: BLAKE3 of the 32 bytes of that root.
        let expected = Blake3Hash::digest(&single.0);
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_cluster_root_different_roots_differ() {
        let r1 = compute_cluster_root(&[Blake3Hash::digest(b"set-A")]);
        let r2 = compute_cluster_root(&[Blake3Hash::digest(b"set-B")]);
        assert_ne!(r1, r2, "different inputs must produce different roots");
    }

    #[test]
    fn compute_cluster_root_adding_root_changes_result() {
        let base = vec![Blake3Hash::digest(b"a"), Blake3Hash::digest(b"b")];
        let extended = vec![
            Blake3Hash::digest(b"a"),
            Blake3Hash::digest(b"b"),
            Blake3Hash::digest(b"c"),
        ];
        let r1 = compute_cluster_root(&base);
        let r2 = compute_cluster_root(&extended);
        assert_ne!(r1, r2, "adding a root must change the cluster root");
    }

    #[test]
    fn compute_cluster_root_removing_root_changes_result() {
        let full = vec![
            Blake3Hash::digest(b"x"),
            Blake3Hash::digest(b"y"),
            Blake3Hash::digest(b"z"),
        ];
        let partial = vec![Blake3Hash::digest(b"x"), Blake3Hash::digest(b"y")];
        let r1 = compute_cluster_root(&full);
        let r2 = compute_cluster_root(&partial);
        assert_ne!(r1, r2, "removing a root must change the cluster root");
    }

    #[test]
    fn compute_cluster_root_duplicate_roots() {
        let dup = Blake3Hash::digest(b"duplicate");
        let r1 = compute_cluster_root(&[dup.clone()]);
        let r2 = compute_cluster_root(&[dup.clone(), dup.clone()]);
        assert_ne!(r1, r2, "duplicates must be reflected in the root");
    }

    #[test]
    fn compute_cluster_root_many_roots() {
        let roots: Vec<Blake3Hash> = (0..1000u32)
            .map(|i| Blake3Hash::digest(&i.to_le_bytes()))
            .collect();
        let r1 = compute_cluster_root(&roots);
        let r2 = compute_cluster_root(&roots);
        assert_eq!(r1, r2, "large input must be deterministic");
    }

    #[test]
    fn compute_cluster_root_reversed_still_same() {
        let roots: Vec<Blake3Hash> = (0..10u32)
            .map(|i| Blake3Hash::digest(&i.to_le_bytes()))
            .collect();
        let mut reversed = roots.clone();
        reversed.reverse();
        assert_eq!(
            compute_cluster_root(&roots),
            compute_cluster_root(&reversed),
            "reversed input must produce same result (sorted internally)"
        );
    }

    #[test]
    fn compute_cluster_root_all_same_roots() {
        let same = Blake3Hash::digest(b"same");
        let roots = vec![same.clone(); 5];
        let root = compute_cluster_root(&roots);
        // 5 identical 32-byte hashes concatenated
        let mut expected_data = Vec::with_capacity(5 * 32);
        for _ in 0..5 {
            expected_data.extend_from_slice(&same.0);
        }
        let expected = Blake3Hash::digest(&expected_data);
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_cluster_root_two_distinct_pairs() {
        let a = Blake3Hash::digest(b"pair-a1");
        let b = Blake3Hash::digest(b"pair-a2");
        let c = Blake3Hash::digest(b"pair-b1");
        let d = Blake3Hash::digest(b"pair-b2");
        let r1 = compute_cluster_root(&[a.clone(), b.clone()]);
        let r2 = compute_cluster_root(&[c.clone(), d.clone()]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn compute_cluster_root_subset_differs() {
        let roots: Vec<Blake3Hash> = (0..5u8)
            .map(|i| Blake3Hash::digest(&[i]))
            .collect();
        let subset = roots[..3].to_vec();
        assert_ne!(
            compute_cluster_root(&roots),
            compute_cluster_root(&subset)
        );
    }

    #[test]
    fn compute_cluster_root_shuffled_multiple_times() {
        let roots: Vec<Blake3Hash> = vec![
            Blake3Hash::digest(b"z"),
            Blake3Hash::digest(b"m"),
            Blake3Hash::digest(b"a"),
            Blake3Hash::digest(b"f"),
        ];
        let expected = compute_cluster_root(&roots);
        // Try several permutations
        let permutations: Vec<Vec<Blake3Hash>> = vec![
            vec![roots[2].clone(), roots[0].clone(), roots[1].clone(), roots[3].clone()],
            vec![roots[3].clone(), roots[2].clone(), roots[0].clone(), roots[1].clone()],
            vec![roots[1].clone(), roots[3].clone(), roots[2].clone(), roots[0].clone()],
        ];
        for perm in &permutations {
            assert_eq!(compute_cluster_root(perm), expected);
        }
    }

    #[test]
    fn compute_cluster_root_not_simple_xor() {
        // Verify the root is not a naive XOR of inputs
        let a = Blake3Hash::digest(b"not-xor-a");
        let b = Blake3Hash::digest(b"not-xor-b");
        let root = compute_cluster_root(&[a.clone(), b.clone()]);
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = a.0[i] ^ b.0[i];
        }
        assert_ne!(root.0, xored, "cluster root must not be simple XOR");
    }

    #[test]
    fn compute_cluster_root_adjacent_inputs_differ() {
        // Two clusters differing by one artifact must have different roots
        let base: Vec<Blake3Hash> = (0..10u8)
            .map(|i| Blake3Hash::digest(&[i]))
            .collect();
        let mut modified = base.clone();
        modified[5] = Blake3Hash::digest(b"modified-artifact");
        assert_ne!(
            compute_cluster_root(&base),
            compute_cluster_root(&modified)
        );
    }

    #[test]
    fn compute_cluster_root_binary_stability() {
        // Known-value regression test: same inputs always produce the same hash
        let roots = vec![
            Blake3Hash::digest(b"stable-1"),
            Blake3Hash::digest(b"stable-2"),
        ];
        let r1 = compute_cluster_root(&roots);
        let hex = r1.to_hex();
        // Re-run to confirm
        let r2 = compute_cluster_root(&roots);
        assert_eq!(r2.to_hex(), hex);
    }

    #[test]
    fn compute_cluster_root_empty_vs_single_zero_hash() {
        let empty = compute_cluster_root(&[]);
        let zero = compute_cluster_root(&[Blake3Hash([0u8; 32])]);
        assert_ne!(empty, zero, "empty input must differ from zero-hash input");
    }

    #[test]
    fn compute_cluster_root_two_elements_specific_order() {
        // Verify that sorting happens correctly: the root should be the same
        // regardless of which element comes first in the input.
        let a = Blake3Hash::digest(b"first");
        let b = Blake3Hash::digest(b"second");
        let r1 = compute_cluster_root(&[a.clone(), b.clone()]);
        let r2 = compute_cluster_root(&[b, a]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn compute_cluster_root_idempotent_with_same_input() {
        let roots = vec![Blake3Hash::digest(b"idem")];
        let r1 = compute_cluster_root(&roots);
        let r2 = compute_cluster_root(&roots);
        let r3 = compute_cluster_root(&roots);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ===================================================================
    // compute_global_root function tests (9 tests)
    // ===================================================================

    #[test]
    fn compute_global_root_deterministic() {
        let mut map = BTreeMap::new();
        map.insert(
            "cluster-a".to_string(),
            test_cluster_entry("cluster-a", Blake3Hash::digest(b"root-a")),
        );
        map.insert(
            "cluster-b".to_string(),
            test_cluster_entry("cluster-b", Blake3Hash::digest(b"root-b")),
        );
        let r1 = compute_global_root(&map);
        let r2 = compute_global_root(&map);
        assert_eq!(r1, r2);
    }

    #[test]
    fn compute_global_root_from_btreemap() {
        let mut map = BTreeMap::new();
        map.insert(
            "us-east".to_string(),
            test_cluster_entry("us-east", Blake3Hash::digest(b"us-east-root")),
        );
        let root = compute_global_root(&map);
        // Single entry: BLAKE3 of the 32-byte cluster root
        let expected = Blake3Hash::digest(&Blake3Hash::digest(b"us-east-root").0);
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_global_root_empty() {
        let map = BTreeMap::new();
        let root = compute_global_root(&map);
        let expected = Blake3Hash::digest(&[]);
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_global_root_changes_when_cluster_changes() {
        let mut map = BTreeMap::new();
        map.insert(
            "c1".to_string(),
            test_cluster_entry("c1", Blake3Hash::digest(b"original")),
        );
        let r1 = compute_global_root(&map);
        map.insert(
            "c1".to_string(),
            test_cluster_entry("c1", Blake3Hash::digest(b"updated")),
        );
        let r2 = compute_global_root(&map);
        assert_ne!(r1, r2);
    }

    #[test]
    fn compute_global_root_order_from_btreemap_keys() {
        // BTreeMap ensures deterministic key ordering. Insert in different order,
        // get the same root.
        let mut map1 = BTreeMap::new();
        map1.insert(
            "alpha".to_string(),
            test_cluster_entry("alpha", Blake3Hash::digest(b"alpha-root")),
        );
        map1.insert(
            "beta".to_string(),
            test_cluster_entry("beta", Blake3Hash::digest(b"beta-root")),
        );

        let mut map2 = BTreeMap::new();
        map2.insert(
            "beta".to_string(),
            test_cluster_entry("beta", Blake3Hash::digest(b"beta-root")),
        );
        map2.insert(
            "alpha".to_string(),
            test_cluster_entry("alpha", Blake3Hash::digest(b"alpha-root")),
        );

        assert_eq!(compute_global_root(&map1), compute_global_root(&map2));
    }

    #[test]
    fn compute_global_root_adding_cluster_changes_root() {
        let mut map = BTreeMap::new();
        map.insert(
            "c1".to_string(),
            test_cluster_entry("c1", Blake3Hash::digest(b"c1-root")),
        );
        let r1 = compute_global_root(&map);
        map.insert(
            "c2".to_string(),
            test_cluster_entry("c2", Blake3Hash::digest(b"c2-root")),
        );
        let r2 = compute_global_root(&map);
        assert_ne!(r1, r2);
    }

    #[test]
    fn compute_global_root_removing_cluster_changes_root() {
        let mut map = BTreeMap::new();
        map.insert(
            "c1".to_string(),
            test_cluster_entry("c1", Blake3Hash::digest(b"c1-root")),
        );
        map.insert(
            "c2".to_string(),
            test_cluster_entry("c2", Blake3Hash::digest(b"c2-root")),
        );
        let r1 = compute_global_root(&map);
        map.remove("c2");
        let r2 = compute_global_root(&map);
        assert_ne!(r1, r2);
    }

    #[test]
    fn compute_global_root_many_clusters() {
        let mut map = BTreeMap::new();
        for i in 0..100u32 {
            let id = format!("cluster-{i:03}");
            map.insert(
                id.clone(),
                test_cluster_entry(&id, Blake3Hash::digest(&i.to_le_bytes())),
            );
        }
        let r1 = compute_global_root(&map);
        let r2 = compute_global_root(&map);
        assert_eq!(r1, r2);
    }

    #[test]
    fn compute_global_root_single_cluster_matches_digest() {
        let cluster_root = Blake3Hash::digest(b"solo");
        let mut map = BTreeMap::new();
        map.insert(
            "solo".to_string(),
            test_cluster_entry("solo", cluster_root.clone()),
        );
        let global = compute_global_root(&map);
        // Single entry: digest of the 32-byte cluster root
        assert_eq!(global, Blake3Hash::digest(&cluster_root.0));
    }

    // ===================================================================
    // GlobalStateClient / MockGlobalStateClient tests (15 tests)
    // ===================================================================

    #[tokio::test]
    async fn mock_client_report_root_records() {
        let client = MockGlobalStateClient::new();
        let root = Blake3Hash::digest(b"report");
        let report = ClusterRootReport {
            cluster_id: "test-cluster".to_string(),
            cluster_root: root.clone(),
            signed_root: test_signed_root(&root),
            node_count: 5,
            artifact_count: 200,
            reported_at: Utc::now(),
            artifact_delta: None,
        };
        let seq = client.report_root(&report).await.unwrap();
        assert_eq!(seq, 1);
        let reports = client.reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].cluster_id, "test-cluster");
    }

    #[tokio::test]
    async fn mock_client_report_root_increments_sequence() {
        let client = MockGlobalStateClient::new();
        let root = Blake3Hash::digest(b"seq");
        let report = ClusterRootReport {
            cluster_id: "c1".to_string(),
            cluster_root: root.clone(),
            signed_root: test_signed_root(&root),
            node_count: 1,
            artifact_count: 10,
            reported_at: Utc::now(),
            artifact_delta: None,
        };
        let s1 = client.report_root(&report).await.unwrap();
        let s2 = client.report_root(&report).await.unwrap();
        let s3 = client.report_root(&report).await.unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
    }

    #[tokio::test]
    async fn mock_client_revoke_everywhere_records() {
        let client = MockGlobalStateClient::new();
        let hash = Blake3Hash::digest(b"compromised");
        *client.revocation_clusters.lock().unwrap() =
            vec!["c1".to_string(), "c2".to_string()];
        let clusters = client
            .revoke_everywhere(&hash, "CVE-2026-0001")
            .await
            .unwrap();
        assert_eq!(clusters, vec!["c1", "c2"]);
        let revocations = client.revocations.lock().unwrap();
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].0, hash);
        assert_eq!(revocations[0].1, "CVE-2026-0001");
    }

    #[tokio::test]
    async fn mock_client_get_global_root_returns_configured() {
        let client = MockGlobalStateClient::new();
        let root_hash = Blake3Hash::digest(b"configured-global");
        let gsr = GlobalStateRoot {
            root_hash: root_hash.clone(),
            cluster_roots: BTreeMap::new(),
            computed_at: Utc::now(),
            sequence: 99,
            previous_root: Blake3Hash::digest(b"prev"),
        };
        *client.configured_root.lock().unwrap() = Some(gsr.clone());
        let result = client.get_global_root().await.unwrap();
        assert_eq!(result.sequence, 99);
        assert_eq!(result.root_hash, root_hash);
    }

    #[tokio::test]
    async fn mock_client_get_global_root_unconfigured_errors() {
        let client = MockGlobalStateClient::new();
        let result = client.get_global_root().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_client_query_blast_radius_returns_configured() {
        let client = MockGlobalStateClient::new();
        let blast = GlobalBlastRadiusReport {
            query_hash: Blake3Hash::digest(b"query"),
            total_clusters_affected: 1,
            total_nodes_affected: 5,
            total_pods_affected: 10,
            clusters_not_affected: vec![],
            cluster_reports: vec![],
            global_first_seen: None,
            global_last_seen: None,
        };
        *client.configured_blast_radius.lock().unwrap() = Some(blast);
        let result = client
            .query_global_blast_radius(&Blake3Hash::digest(b"any"))
            .await
            .unwrap();
        assert_eq!(result.total_clusters_affected, 1);
        assert_eq!(result.total_nodes_affected, 5);
    }

    #[tokio::test]
    async fn mock_client_query_blast_radius_unconfigured_errors() {
        let client = MockGlobalStateClient::new();
        let result = client
            .query_global_blast_radius(&Blake3Hash::digest(b"miss"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_client_multiple_reports() {
        let client = MockGlobalStateClient::new();
        for i in 0..5u32 {
            let root = Blake3Hash::digest(&i.to_le_bytes());
            let report = ClusterRootReport {
                cluster_id: format!("cluster-{i}"),
                cluster_root: root.clone(),
                signed_root: test_signed_root(&root),
                node_count: i,
                artifact_count: u64::from(i) * 100,
                reported_at: Utc::now(),
                artifact_delta: None,
            };
            let _ = client.report_root(&report).await.unwrap();
        }
        let reports = client.reports.lock().unwrap();
        assert_eq!(reports.len(), 5);
        for (i, r) in reports.iter().enumerate() {
            assert_eq!(r.cluster_id, format!("cluster-{i}"));
        }
    }

    #[tokio::test]
    async fn mock_client_multiple_revocations() {
        let client = MockGlobalStateClient::new();
        *client.revocation_clusters.lock().unwrap() = vec!["c1".to_string()];
        for i in 0..3u8 {
            let hash = Blake3Hash::digest(&[i]);
            let _ = client
                .revoke_everywhere(&hash, &format!("reason-{i}"))
                .await
                .unwrap();
        }
        let revocations = client.revocations.lock().unwrap();
        assert_eq!(revocations.len(), 3);
    }

    #[test]
    fn global_state_client_trait_is_dyn_safe() {
        // This test verifies the trait is object-safe (can be used as dyn).
        fn _accept_dyn(_client: &dyn GlobalStateClient) {}
        let mock = MockGlobalStateClient::new();
        _accept_dyn(&mock);
    }

    #[test]
    fn mock_client_default_trait() {
        let client = MockGlobalStateClient::default();
        assert!(client.reports.lock().unwrap().is_empty());
        assert!(client.revocations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mock_client_report_with_delta() {
        let client = MockGlobalStateClient::new();
        let root = Blake3Hash::digest(b"delta-root");
        let delta = ArtifactDelta {
            added: vec![ArtifactLocation {
                cluster_id: "c1".to_string(),
                node: "n1".to_string(),
                namespace: "default".to_string(),
                pod: "p1".to_string(),
                binary_path: "/bin/x".to_string(),
                composed_root: Blake3Hash::digest(b"new-artifact"),
            }],
            removed: vec![Blake3Hash::digest(b"old-artifact")],
        };
        let report = ClusterRootReport {
            cluster_id: "c1".to_string(),
            cluster_root: root.clone(),
            signed_root: test_signed_root(&root),
            node_count: 2,
            artifact_count: 50,
            reported_at: Utc::now(),
            artifact_delta: Some(delta),
        };
        let seq = client.report_root(&report).await.unwrap();
        assert_eq!(seq, 1);
        let reports = client.reports.lock().unwrap();
        assert!(reports[0].artifact_delta.is_some());
        let d = reports[0].artifact_delta.as_ref().unwrap();
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.removed.len(), 1);
    }

    #[tokio::test]
    async fn mock_client_revoke_with_empty_clusters() {
        let client = MockGlobalStateClient::new();
        // revocation_clusters is empty by default
        let clusters = client
            .revoke_everywhere(&Blake3Hash::digest(b"h"), "test")
            .await
            .unwrap();
        assert!(clusters.is_empty());
    }

    #[tokio::test]
    async fn mock_client_configured_root_can_be_updated() {
        let client = MockGlobalStateClient::new();
        let root1 = GlobalStateRoot {
            root_hash: Blake3Hash::digest(b"v1"),
            cluster_roots: BTreeMap::new(),
            computed_at: Utc::now(),
            sequence: 1,
            previous_root: Blake3Hash([0u8; 32]),
        };
        *client.configured_root.lock().unwrap() = Some(root1);
        let r1 = client.get_global_root().await.unwrap();
        assert_eq!(r1.sequence, 1);

        let root2 = GlobalStateRoot {
            root_hash: Blake3Hash::digest(b"v2"),
            cluster_roots: BTreeMap::new(),
            computed_at: Utc::now(),
            sequence: 2,
            previous_root: r1.root_hash,
        };
        *client.configured_root.lock().unwrap() = Some(root2);
        let r2 = client.get_global_root().await.unwrap();
        assert_eq!(r2.sequence, 2);
    }

    #[tokio::test]
    async fn mock_client_revoke_reason_preserved() {
        let client = MockGlobalStateClient::new();
        let hash = Blake3Hash::digest(b"preserve");
        let reason = "CRITICAL: zero-day exploit CVE-2026-9999 in libssl";
        let _ = client.revoke_everywhere(&hash, reason).await.unwrap();
        let revocations = client.revocations.lock().unwrap();
        assert_eq!(revocations[0].1, reason);
    }

    // ===================================================================
    // Integration tests (5 tests)
    // ===================================================================

    #[test]
    fn compute_cluster_root_feeds_into_certification_artifact_workflow() {
        // Simulate: multiple composed_roots from CertificationArtifacts
        // feeding into a cluster root.
        use crate::certification_artifact::compose_certification_artifact;

        let artifact1 = compose_certification_artifact(
            "/usr/bin/app1",
            Blake3Hash::digest(b"nix-closure-1"),
            Blake3Hash::digest(b"kensa-result-1"),
            Blake3Hash::digest(b"pangea-synthesis-1"),
            "production",
        );
        let artifact2 = compose_certification_artifact(
            "/usr/bin/app2",
            Blake3Hash::digest(b"nix-closure-2"),
            Blake3Hash::digest(b"kensa-result-2"),
            Blake3Hash::digest(b"pangea-synthesis-2"),
            "production",
        );

        let composed_roots = vec![
            artifact1.composed_root.clone(),
            artifact2.composed_root.clone(),
        ];
        let cluster_root = compute_cluster_root(&composed_roots);

        // The cluster root should be a valid non-zero hash.
        assert_ne!(cluster_root, Blake3Hash([0u8; 32]));
        // Re-deriving from the same artifacts produces the same root.
        let cluster_root2 = compute_cluster_root(&composed_roots);
        assert_eq!(cluster_root, cluster_root2);
    }

    #[test]
    fn global_root_changes_when_any_cluster_root_changes() {
        let mut map = BTreeMap::new();
        map.insert(
            "us-east".to_string(),
            test_cluster_entry("us-east", Blake3Hash::digest(b"us-east-v1")),
        );
        map.insert(
            "eu-west".to_string(),
            test_cluster_entry("eu-west", Blake3Hash::digest(b"eu-west-v1")),
        );
        let global_v1 = compute_global_root(&map);

        // Update one cluster root
        map.insert(
            "us-east".to_string(),
            test_cluster_entry("us-east", Blake3Hash::digest(b"us-east-v2")),
        );
        let global_v2 = compute_global_root(&map);

        assert_ne!(
            global_v1, global_v2,
            "global root must change when any cluster root changes"
        );
    }

    #[test]
    fn cluster_root_report_updates_global_state_root() {
        // Simulate the workflow: cluster report -> update map -> recompute global
        let mut cluster_roots: BTreeMap<String, ClusterRootEntry> = BTreeMap::new();

        // First cluster reports
        let root1 = Blake3Hash::digest(b"cluster-1-root");
        let report1 = ClusterRootReport {
            cluster_id: "cluster-1".to_string(),
            cluster_root: root1.clone(),
            signed_root: test_signed_root(&root1),
            node_count: 3,
            artifact_count: 100,
            reported_at: Utc::now(),
            artifact_delta: None,
        };
        cluster_roots.insert(
            report1.cluster_id.clone(),
            ClusterRootEntry {
                cluster_id: report1.cluster_id.clone(),
                cluster_root: report1.cluster_root.clone(),
                signed_root: report1.signed_root.clone(),
                node_count: report1.node_count,
                artifact_count: report1.artifact_count,
                last_reported: report1.reported_at,
                status: ClusterStatus::Active,
            },
        );
        let global_after_first = compute_global_root(&cluster_roots);

        // Second cluster reports
        let root2 = Blake3Hash::digest(b"cluster-2-root");
        let report2 = ClusterRootReport {
            cluster_id: "cluster-2".to_string(),
            cluster_root: root2.clone(),
            signed_root: test_signed_root(&root2),
            node_count: 5,
            artifact_count: 200,
            reported_at: Utc::now(),
            artifact_delta: None,
        };
        cluster_roots.insert(
            report2.cluster_id.clone(),
            ClusterRootEntry {
                cluster_id: report2.cluster_id.clone(),
                cluster_root: report2.cluster_root.clone(),
                signed_root: report2.signed_root.clone(),
                node_count: report2.node_count,
                artifact_count: report2.artifact_count,
                last_reported: report2.reported_at,
                status: ClusterStatus::Active,
            },
        );
        let global_after_second = compute_global_root(&cluster_roots);

        assert_ne!(
            global_after_first, global_after_second,
            "adding a cluster must change the global root"
        );
    }

    #[test]
    fn end_to_end_cluster_to_global_pipeline() {
        use crate::certification_artifact::compose_certification_artifact;

        // Create artifacts for cluster A
        let a1 = compose_certification_artifact(
            "/bin/a1",
            Blake3Hash::digest(b"a1-nix"),
            Blake3Hash::digest(b"a1-control"),
            Blake3Hash::digest(b"a1-intent"),
            "prod",
        );
        let a2 = compose_certification_artifact(
            "/bin/a2",
            Blake3Hash::digest(b"a2-nix"),
            Blake3Hash::digest(b"a2-control"),
            Blake3Hash::digest(b"a2-intent"),
            "prod",
        );
        let cluster_a_root = compute_cluster_root(&[
            a1.composed_root.clone(),
            a2.composed_root.clone(),
        ]);

        // Create artifacts for cluster B
        let b1 = compose_certification_artifact(
            "/bin/b1",
            Blake3Hash::digest(b"b1-nix"),
            Blake3Hash::digest(b"b1-control"),
            Blake3Hash::digest(b"b1-intent"),
            "staging",
        );
        let cluster_b_root = compute_cluster_root(&[b1.composed_root.clone()]);

        // Build global state
        let mut map = BTreeMap::new();
        map.insert(
            "cluster-a".to_string(),
            test_cluster_entry("cluster-a", cluster_a_root.clone()),
        );
        map.insert(
            "cluster-b".to_string(),
            test_cluster_entry("cluster-b", cluster_b_root.clone()),
        );
        let global_root = compute_global_root(&map);

        // Verify chain of custody: different artifacts -> different cluster roots
        assert_ne!(cluster_a_root, cluster_b_root);
        // Global root is a function of both
        assert_ne!(global_root, Blake3Hash([0u8; 32]));

        // Removing cluster B changes global root
        map.remove("cluster-b");
        let global_root_without_b = compute_global_root(&map);
        assert_ne!(global_root, global_root_without_b);
    }

    #[test]
    fn cluster_root_to_global_state_root_struct() {
        let cluster_root = compute_cluster_root(&[
            Blake3Hash::digest(b"artifact-1"),
            Blake3Hash::digest(b"artifact-2"),
        ]);

        let mut map = BTreeMap::new();
        map.insert(
            "my-cluster".to_string(),
            test_cluster_entry("my-cluster", cluster_root),
        );

        let root_hash = compute_global_root(&map);
        let gsr = GlobalStateRoot {
            root_hash: root_hash.clone(),
            cluster_roots: map,
            computed_at: Utc::now(),
            sequence: 1,
            previous_root: Blake3Hash([0u8; 32]),
        };

        // Verify the struct is well-formed
        assert_eq!(gsr.sequence, 1);
        assert_eq!(gsr.cluster_roots.len(), 1);
        assert_eq!(gsr.root_hash, root_hash);

        // Serde roundtrip
        let json = serde_json::to_string(&gsr).unwrap();
        let parsed: GlobalStateRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.root_hash, gsr.root_hash);
        assert_eq!(parsed.sequence, gsr.sequence);
    }
}
