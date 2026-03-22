//! Forensics types — all data structures for the forensics subsystem.
//!
//! Every type that crosses API boundaries derives `schemars::JsonSchema`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::certification_artifact::CertificationArtifact;
use crate::hash::Blake3Hash;
use crate::signing::SignedRoot;

// =============================================================================
// Deployment Context
// =============================================================================

/// Context describing where a certified artifact was deployed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeploymentContext {
    /// Kubernetes cluster name.
    pub cluster: String,
    /// Kubernetes namespace.
    pub namespace: String,
    /// Node where the artifact runs.
    pub node: String,
    /// Pod name.
    pub pod: String,
    /// Container name.
    pub container: String,
    /// OCI image reference.
    pub image_ref: String,
    /// Paths to certified binaries within the container.
    pub binary_paths: Vec<String>,
    /// Optional SDLC chain hash linking to the build pipeline.
    pub sdlc_chain_hash: Option<Blake3Hash>,
    /// Optional compliance report hash from kensa.
    pub compliance_report_hash: Option<Blake3Hash>,
}

// =============================================================================
// Merkle Ledger Entry
// =============================================================================

/// A single entry in the Merkle ledger — records one certification artifact deployment.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MerkleLedgerEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// When this deployment was recorded.
    pub timestamp: DateTime<Utc>,
    /// The certification artifact that was deployed.
    pub certification_artifact: CertificationArtifact,
    /// The signed Merkle root that authorized deployment.
    pub signed_root: SignedRoot,
    /// Where the artifact was deployed.
    pub deployment_context: DeploymentContext,
    /// BLAKE3 hash of this entry's content (excluding `entry_hash` itself).
    pub entry_hash: Blake3Hash,
    /// BLAKE3 hash of the previous entry (all zeros for the first entry).
    pub previous_hash: Blake3Hash,
}

// =============================================================================
// Ledger Entry Reference
// =============================================================================

/// Lightweight reference to a ledger entry, used in index values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntryRef {
    /// Sequence number of the referenced entry.
    pub sequence: u64,
    /// Timestamp of the referenced entry.
    pub timestamp: DateTime<Utc>,
    /// Entry hash for quick validation.
    pub entry_hash: Blake3Hash,
}

// =============================================================================
// Time Range
// =============================================================================

/// A time range with inclusive bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TimeRange {
    /// First observed time.
    pub first_seen: DateTime<Utc>,
    /// Last observed time.
    pub last_seen: DateTime<Utc>,
}

// =============================================================================
// Affected Node Detail
// =============================================================================

/// Detail about a node affected by a compromised artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectedNodeDetail {
    /// Node name.
    pub node: String,
    /// Cluster the node belongs to.
    pub cluster: String,
    /// First time the artifact executed on this node.
    pub first_execution: DateTime<Utc>,
    /// Last time the artifact executed on this node.
    pub last_execution: DateTime<Utc>,
    /// Number of times the artifact was deployed to this node.
    pub execution_count: u64,
    /// Pods that ran the artifact on this node.
    pub pods: Vec<String>,
    /// Namespaces on this node that ran the artifact.
    pub namespaces: Vec<String>,
}

// =============================================================================
// Co-Resident Artifact
// =============================================================================

/// An artifact that was co-resident on the same node as a compromised artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoResidentArtifact {
    /// The composed Merkle root of the co-resident artifact.
    pub composed_root: Blake3Hash,
    /// Artifact provenance hash.
    pub artifact_hash: Blake3Hash,
    /// Compliance control hash.
    pub control_hash: Blake3Hash,
    /// Infrastructure intent hash.
    pub intent_hash: Blake3Hash,
    /// Binary path of the co-resident artifact.
    pub binary_path: String,
}

// =============================================================================
// Blast Radius Report
// =============================================================================

/// Report describing the blast radius of a compromised artifact.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlastRadiusReport {
    /// The hash that was queried.
    pub query_hash: Blake3Hash,
    /// Total number of affected nodes.
    pub total_affected: usize,
    /// Time range over which the artifact was active.
    pub time_range: TimeRange,
    /// Details for each affected node.
    pub affected_nodes: Vec<AffectedNodeDetail>,
    /// Other artifacts that shared nodes with the compromised artifact.
    pub co_resident_artifacts: Vec<CoResidentArtifact>,
    /// Whether the underlying chain passed integrity verification.
    pub chain_integrity: bool,
    /// Deterministic hash of this entire report (for evidence).
    pub evidence_hash: Blake3Hash,
}

// =============================================================================
// Timeline Event
// =============================================================================

/// A single event in a forensic timeline reconstruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TimelineEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Type of event (e.g., "deployment", "admission").
    pub event_type: String,
    /// Decision made (e.g., "allowed", "denied").
    pub decision: String,
    /// Node where the event occurred.
    pub node: String,
    /// Pod involved in the event.
    pub pod: String,
    /// Binary path involved.
    pub binary_path: String,
    /// Composed root of the artifact involved.
    pub composed_root: Blake3Hash,
    /// Ledger sequence number.
    pub sequence: u64,
}

// =============================================================================
// Provenance Snapshot
// =============================================================================

/// Point-in-time snapshot of all active artifacts on a given node.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProvenanceSnapshot {
    /// Node this snapshot is for.
    pub node: String,
    /// The point in time this snapshot represents.
    pub timestamp: DateTime<Utc>,
    /// All artifacts active on the node at the given time.
    pub active_artifacts: Vec<ActiveArtifact>,
}

// =============================================================================
// Active Artifact
// =============================================================================

/// An artifact actively deployed on a node.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActiveArtifact {
    /// The certification artifact.
    pub certification_artifact: CertificationArtifact,
    /// The signed root authorizing it.
    pub signed_root: SignedRoot,
    /// Deployment context.
    pub deployment_context: DeploymentContext,
}

// =============================================================================
// Revoke Request / Result
// =============================================================================

/// Request to revoke a compromised artifact hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevokeRequest {
    /// The hash to revoke.
    pub hash: Blake3Hash,
    /// Reason for revocation.
    pub reason: String,
    /// Severity level.
    pub severity: String,
    /// Operator performing the revocation.
    pub operator: String,
}

/// Result of a revocation operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevokeResult {
    /// Whether the revocation was applied.
    pub revoked: bool,
    /// Number of affected nodes.
    pub affected_nodes: u32,
    /// Whether BPF maps were updated.
    pub bpf_maps_updated: bool,
    /// Heartbeat entry sequence for this revocation event.
    pub heartbeat_entry_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification_artifact::compose_certification_artifact;
    use crate::signing::{SignedRoot, SigningAlgorithm};

    fn sample_deployment_context() -> DeploymentContext {
        DeploymentContext {
            cluster: "prod-us-east".to_string(),
            namespace: "default".to_string(),
            node: "node-1".to_string(),
            pod: "app-abc-123".to_string(),
            container: "main".to_string(),
            image_ref: "ghcr.io/pleme-io/app:v1.0.0".to_string(),
            binary_paths: vec!["/usr/bin/app".to_string()],
            sdlc_chain_hash: Some(Blake3Hash::digest(b"sdlc-chain")),
            compliance_report_hash: Some(Blake3Hash::digest(b"compliance-report")),
        }
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

    fn sample_artifact() -> CertificationArtifact {
        compose_certification_artifact(
            "/usr/bin/app",
            Blake3Hash::digest(b"nix-closure"),
            Blake3Hash::digest(b"kensa-result"),
            Blake3Hash::digest(b"pangea-synthesis"),
            "production",
        )
    }

    // ---- DeploymentContext tests ----

    #[test]
    fn deployment_context_serde_roundtrip() {
        let ctx = sample_deployment_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: DeploymentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
    }

    #[test]
    fn deployment_context_all_fields() {
        let ctx = sample_deployment_context();
        assert_eq!(ctx.cluster, "prod-us-east");
        assert_eq!(ctx.namespace, "default");
        assert_eq!(ctx.node, "node-1");
        assert_eq!(ctx.pod, "app-abc-123");
        assert_eq!(ctx.container, "main");
        assert_eq!(ctx.image_ref, "ghcr.io/pleme-io/app:v1.0.0");
        assert_eq!(ctx.binary_paths.len(), 1);
        assert!(ctx.sdlc_chain_hash.is_some());
        assert!(ctx.compliance_report_hash.is_some());
    }

    #[test]
    fn deployment_context_optional_fields_none() {
        let ctx = DeploymentContext {
            cluster: "test".to_string(),
            namespace: "ns".to_string(),
            node: "n".to_string(),
            pod: "p".to_string(),
            container: "c".to_string(),
            image_ref: "img".to_string(),
            binary_paths: vec![],
            sdlc_chain_hash: None,
            compliance_report_hash: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: DeploymentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
        assert!(restored.sdlc_chain_hash.is_none());
        assert!(restored.compliance_report_hash.is_none());
    }

    #[test]
    fn deployment_context_clone() {
        let ctx = sample_deployment_context();
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
    }

    // ---- TimeRange tests ----

    #[test]
    fn time_range_serde_roundtrip() {
        let tr = TimeRange {
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        let json = serde_json::to_string(&tr).unwrap();
        let restored: TimeRange = serde_json::from_str(&json).unwrap();
        assert_eq!(tr, restored);
    }

    // ---- AffectedNodeDetail tests ----

    #[test]
    fn affected_node_detail_serde_roundtrip() {
        let node = AffectedNodeDetail {
            node: "node-1".to_string(),
            cluster: "prod".to_string(),
            first_execution: Utc::now(),
            last_execution: Utc::now(),
            execution_count: 42,
            pods: vec!["pod-a".to_string(), "pod-b".to_string()],
            namespaces: vec!["default".to_string()],
        };
        let json = serde_json::to_string(&node).unwrap();
        let restored: AffectedNodeDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(node, restored);
    }

    #[test]
    fn affected_node_detail_multiple_pods() {
        let node = AffectedNodeDetail {
            node: "n".to_string(),
            cluster: "c".to_string(),
            first_execution: Utc::now(),
            last_execution: Utc::now(),
            execution_count: 3,
            pods: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            namespaces: vec!["ns1".to_string(), "ns2".to_string()],
        };
        assert_eq!(node.pods.len(), 3);
        assert_eq!(node.namespaces.len(), 2);
    }

    // ---- CoResidentArtifact tests ----

    #[test]
    fn co_resident_artifact_serde_roundtrip() {
        let co = CoResidentArtifact {
            composed_root: Blake3Hash::digest(b"root"),
            artifact_hash: Blake3Hash::digest(b"artifact"),
            control_hash: Blake3Hash::digest(b"control"),
            intent_hash: Blake3Hash::digest(b"intent"),
            binary_path: "/usr/bin/co".to_string(),
        };
        let json = serde_json::to_string(&co).unwrap();
        let restored: CoResidentArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(co, restored);
    }

    // ---- BlastRadiusReport tests ----

    #[test]
    fn blast_radius_report_serde_roundtrip() {
        let now = Utc::now();
        let report = BlastRadiusReport {
            query_hash: Blake3Hash::digest(b"query"),
            total_affected: 2,
            time_range: TimeRange { first_seen: now, last_seen: now },
            affected_nodes: vec![
                AffectedNodeDetail {
                    node: "n1".to_string(),
                    cluster: "c1".to_string(),
                    first_execution: now,
                    last_execution: now,
                    execution_count: 1,
                    pods: vec!["p1".to_string()],
                    namespaces: vec!["ns1".to_string()],
                },
            ],
            co_resident_artifacts: vec![],
            chain_integrity: true,
            evidence_hash: Blake3Hash::digest(b"evidence"),
        };
        let json = serde_json::to_string(&report).unwrap();
        let restored: BlastRadiusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.total_affected, restored.total_affected);
        assert_eq!(report.chain_integrity, restored.chain_integrity);
    }

    #[test]
    fn blast_radius_report_with_multiple_affected_nodes() {
        let now = Utc::now();
        let report = BlastRadiusReport {
            query_hash: Blake3Hash::digest(b"q"),
            total_affected: 3,
            time_range: TimeRange { first_seen: now, last_seen: now },
            affected_nodes: vec![
                AffectedNodeDetail {
                    node: "n1".to_string(),
                    cluster: "c1".to_string(),
                    first_execution: now,
                    last_execution: now,
                    execution_count: 5,
                    pods: vec!["p1".to_string()],
                    namespaces: vec!["ns1".to_string()],
                },
                AffectedNodeDetail {
                    node: "n2".to_string(),
                    cluster: "c1".to_string(),
                    first_execution: now,
                    last_execution: now,
                    execution_count: 3,
                    pods: vec!["p2".to_string()],
                    namespaces: vec!["ns2".to_string()],
                },
                AffectedNodeDetail {
                    node: "n3".to_string(),
                    cluster: "c2".to_string(),
                    first_execution: now,
                    last_execution: now,
                    execution_count: 1,
                    pods: vec!["p3".to_string()],
                    namespaces: vec!["ns3".to_string()],
                },
            ],
            co_resident_artifacts: vec![],
            chain_integrity: true,
            evidence_hash: Blake3Hash::digest(b"ev"),
        };
        assert_eq!(report.affected_nodes.len(), 3);
    }

    // ---- TimelineEvent tests ----

    #[test]
    fn timeline_event_serde_roundtrip() {
        let ev = TimelineEvent {
            timestamp: Utc::now(),
            event_type: "deployment".to_string(),
            decision: "allowed".to_string(),
            node: "n1".to_string(),
            pod: "p1".to_string(),
            binary_path: "/bin/app".to_string(),
            composed_root: Blake3Hash::digest(b"root"),
            sequence: 42,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: TimelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn timeline_event_ordering_by_timestamp() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(1);
        let ev1 = TimelineEvent {
            timestamp: t1,
            event_type: "deploy".to_string(),
            decision: "allowed".to_string(),
            node: "n".to_string(),
            pod: "p".to_string(),
            binary_path: "/bin/a".to_string(),
            composed_root: Blake3Hash::digest(b"r1"),
            sequence: 0,
        };
        let ev2 = TimelineEvent {
            timestamp: t2,
            event_type: "deploy".to_string(),
            decision: "allowed".to_string(),
            node: "n".to_string(),
            pod: "p".to_string(),
            binary_path: "/bin/a".to_string(),
            composed_root: Blake3Hash::digest(b"r2"),
            sequence: 1,
        };
        assert!(ev1.timestamp < ev2.timestamp);
    }

    // ---- ProvenanceSnapshot tests ----

    #[test]
    fn provenance_snapshot_serde_roundtrip() {
        let snap = ProvenanceSnapshot {
            node: "node-1".to_string(),
            timestamp: Utc::now(),
            active_artifacts: vec![],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ProvenanceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap.node, restored.node);
        assert_eq!(snap.active_artifacts.len(), restored.active_artifacts.len());
    }

    #[test]
    fn provenance_snapshot_with_multiple_artifacts() {
        let snap = ProvenanceSnapshot {
            node: "node-1".to_string(),
            timestamp: Utc::now(),
            active_artifacts: vec![
                ActiveArtifact {
                    certification_artifact: sample_artifact(),
                    signed_root: sample_signed_root(),
                    deployment_context: sample_deployment_context(),
                },
                ActiveArtifact {
                    certification_artifact: sample_artifact(),
                    signed_root: sample_signed_root(),
                    deployment_context: sample_deployment_context(),
                },
            ],
        };
        assert_eq!(snap.active_artifacts.len(), 2);
    }

    // ---- RevokeRequest tests ----

    #[test]
    fn revoke_request_serde_roundtrip() {
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

    // ---- RevokeResult tests ----

    #[test]
    fn revoke_result_serde_roundtrip() {
        let res = RevokeResult {
            revoked: true,
            affected_nodes: 5,
            bpf_maps_updated: true,
            heartbeat_entry_sequence: 99,
        };
        let json = serde_json::to_string(&res).unwrap();
        let restored: RevokeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, restored);
    }

    // ---- ActiveArtifact tests ----

    #[test]
    fn active_artifact_serde_roundtrip() {
        let aa = ActiveArtifact {
            certification_artifact: sample_artifact(),
            signed_root: sample_signed_root(),
            deployment_context: sample_deployment_context(),
        };
        let json = serde_json::to_string(&aa).unwrap();
        let _restored: ActiveArtifact = serde_json::from_str(&json).unwrap();
    }

    // ---- LedgerEntryRef tests ----

    #[test]
    fn ledger_entry_ref_equality() {
        let now = Utc::now();
        let r1 = LedgerEntryRef {
            sequence: 0,
            timestamp: now,
            entry_hash: Blake3Hash::digest(b"a"),
        };
        let r2 = LedgerEntryRef {
            sequence: 0,
            timestamp: now,
            entry_hash: Blake3Hash::digest(b"a"),
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn ledger_entry_ref_serde_roundtrip() {
        let r = LedgerEntryRef {
            sequence: 42,
            timestamp: Utc::now(),
            entry_hash: Blake3Hash::digest(b"ref"),
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: LedgerEntryRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }

    #[test]
    fn merkle_ledger_entry_serde_roundtrip() {
        let entry = MerkleLedgerEntry {
            sequence: 0,
            timestamp: Utc::now(),
            certification_artifact: sample_artifact(),
            signed_root: sample_signed_root(),
            deployment_context: sample_deployment_context(),
            entry_hash: Blake3Hash::digest(b"entry"),
            previous_hash: Blake3Hash::from([0u8; 32]),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let _restored: MerkleLedgerEntry = serde_json::from_str(&json).unwrap();
    }
}
