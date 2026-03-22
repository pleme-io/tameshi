# Integration Plan: Tameshi Forensics, Global State Root, and Incident Response

I now have a thorough understanding of the complete codebase, all architecture documents, existing types, traits, and patterns. Let me produce the definitive integration plan.

---

Here is the definitive feature integration plan for turning all documented architecture into implemented, tested, shipped features across the tameshi product ecosystem.

---

## INTEGRATION PLAN: Tameshi Forensics, Global State Root, and Incident Response

### Executive Summary

This plan converts four architecture documents (FORENSICS_ROADMAP.md, FORENSICS_AND_IR.md, GLOBAL_STATE_ROOT.md, ARCHITECTURE.md) into ten implementation sprints across six repositories (tameshi, sekiban, kensa, kanshi, tameshi-watch, and the new tameshi-global). The current codebase has zero forensics or global state root implementation -- the OpenAPI spec defines the API shapes and the architecture docs define the types, but no code exists. The HeartbeatChain pattern in `tameshi/src/heartbeat.rs` is the primary reference pattern for all new chain structures.

---

### Sprint 1: MerkleLedger Core (tameshi)

**Goal**: Build the foundational append-only tamper-proof ledger that all forensics features depend on.

**Dependencies**: None (foundation sprint)

**Can run in parallel with**: Nothing -- all other sprints depend on this.

**Estimated test count**: ~85 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/mod.rs`**
```
pub mod ledger;
pub mod index;
pub mod query;
pub mod types;
```

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/types.rs`**
Types to define:
- `DeploymentContext` -- struct with fields: `cluster: String`, `namespace: String`, `node: String`, `pod: String`, `container: String`, `image_ref: String`, `binary_paths: Vec<String>`, `sdlc_chain_hash: Option<Blake3Hash>`, `compliance_report_hash: Option<Blake3Hash>`. Derive: `Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema`.
- `MerkleLedgerEntry` -- struct with fields: `sequence: u64`, `timestamp: DateTime<Utc>`, `certification_artifact: CertificationArtifact`, `signed_root: SignedRoot`, `deployment_context: DeploymentContext`, `entry_hash: Blake3Hash`, `previous_hash: Blake3Hash`. Derive: `Clone, Debug, Serialize, Deserialize, schemars::JsonSchema`.
- `LedgerEntryRef` -- lightweight reference: `sequence: u64`, `timestamp: DateTime<Utc>`, `entry_hash: Blake3Hash`. Derive: `Clone, Debug, PartialEq, Eq, Serialize, Deserialize`.
- `BlastRadiusReport` -- struct with fields: `query_hash: Blake3Hash`, `total_affected: usize`, `time_range: TimeRange`, `affected_nodes: Vec<AffectedNodeDetail>`, `co_resident_artifacts: Vec<CoResidentArtifact>`, `chain_integrity: bool`, `evidence_hash: Blake3Hash`. Derive: `Clone, Debug, Serialize, Deserialize, schemars::JsonSchema`.
- `TimeRange` -- struct: `first_seen: DateTime<Utc>`, `last_seen: DateTime<Utc>`.
- `AffectedNodeDetail` -- struct: `node: String`, `cluster: String`, `first_execution: DateTime<Utc>`, `last_execution: DateTime<Utc>`, `execution_count: u64`, `pods: Vec<String>`, `namespaces: Vec<String>`.
- `CoResidentArtifact` -- struct: `composed_root: Blake3Hash`, `artifact_hash: Blake3Hash`, `control_hash: Blake3Hash`, `intent_hash: Blake3Hash`, `binary_path: String`.
- `TimelineEvent` -- struct: `timestamp: DateTime<Utc>`, `event_type: String`, `decision: String`, `node: String`, `pod: String`, `binary_path: String`, `composed_root: Blake3Hash`, `sequence: u64`.
- `ProvenanceSnapshot` -- struct: `node: String`, `timestamp: DateTime<Utc>`, `active_artifacts: Vec<ActiveArtifact>`.
- `ActiveArtifact` -- struct: `certification_artifact: CertificationArtifact`, `signed_root: SignedRoot`, `deployment_context: DeploymentContext`.
- `RevokeRequest` -- struct: `hash: Blake3Hash`, `reason: String`, `severity: String`, `operator: String`.
- `RevokeResult` -- struct: `revoked: bool`, `affected_nodes: u32`, `bpf_maps_updated: bool`, `heartbeat_entry_sequence: u64`.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/ledger.rs`**
Types and functions:
- `MerkleLedger` -- struct wrapping `RwLock<MerkleLedgerInner>` (follow `HeartbeatChain` pattern exactly from `/Users/luis.d/code/github/pleme-io/tameshi/src/heartbeat.rs` lines 158-190).
- `MerkleLedgerInner` -- private struct: `entries: Vec<MerkleLedgerEntry>`, `next_sequence: u64`, `last_hash: Blake3Hash`.
- `MerkleLedger::new()` -- constructor.
- `MerkleLedger::append(artifact, signed_root, deployment_context) -> MerkleLedgerEntry` -- appends entry, computes `entry_hash` as `BLAKE3(sequence || timestamp || artifact_composed_root || signed_root.root || deployment_context_hash || previous_hash)`, sets `previous_hash` from `last_hash`.
- `MerkleLedger::len()`, `is_empty()`, `last()`, `entries()`, `head_hash()`.
- `MerkleLedger::verify_integrity() -> bool` -- walks chain, verifies each entry hash and previous_hash linkage (mirror `HeartbeatChain::verify_integrity()`).
- `MerkleLedger::entries_in_range(from, to) -> Vec<MerkleLedgerEntry>`.
- `MerkleLedger::consistency_proof(from_seq, to_seq) -> Result<ConsistencyProof>` -- reuse tameshi's `ConsistencyProof` type.
- `fn compute_ledger_entry_hash(...)` -- private, mirrors `compute_entry_hash` pattern.

**Trait**: `MerkleLedgerStore: Send + Sync` -- async methods: `append(entry) -> Result<()>`, `get(sequence) -> Result<Option<MerkleLedgerEntry>>`, `range(from_seq, to_seq) -> Result<Vec<MerkleLedgerEntry>>`, `latest() -> Result<Option<MerkleLedgerEntry>>`.
- `InMemoryLedgerStore` -- in-memory impl using `RwLock<Vec<MerkleLedgerEntry>>`.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/index.rs`**
Types:
- `LedgerIndex` -- struct with fields: `by_hash: BTreeMap<Blake3Hash, Vec<LedgerEntryRef>>`, `by_node: BTreeMap<String, Vec<LedgerEntryRef>>`, `by_namespace: BTreeMap<String, Vec<LedgerEntryRef>>`, `by_time: BTreeMap<DateTime<Utc>, Vec<LedgerEntryRef>>`, `by_binary: BTreeMap<String, Vec<LedgerEntryRef>>`.
- `LedgerIndex::new()` -- empty index.
- `LedgerIndex::insert(entry: &MerkleLedgerEntry)` -- indexes entry across all maps. Must extract `composed_root`, `artifact_hash`, `control_hash`, `intent_hash` into `by_hash`; `deployment_context.node` into `by_node`; `deployment_context.namespace` into `by_namespace`; `timestamp` into `by_time`; each `binary_path` in `deployment_context.binary_paths` into `by_binary`.
- `LedgerIndex::query_by_hash(hash) -> Vec<LedgerEntryRef>`.
- `LedgerIndex::query_by_node(node) -> Vec<LedgerEntryRef>`.
- `LedgerIndex::query_by_time_range(from, to) -> Vec<LedgerEntryRef>`.
- `LedgerIndex::query_by_binary(path) -> Vec<LedgerEntryRef>`.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/query.rs`**
Functions:
- `blast_radius(ledger, index, hash, from, to) -> BlastRadiusReport` -- queries `by_hash` index, computes affected nodes/pods/namespaces, finds co-resident artifacts, computes evidence hash.
- `timeline(ledger, index, hash, from, to, node_filter) -> Vec<TimelineEvent>` -- chronological events for a hash.
- `provenance(ledger, index, node, at) -> ProvenanceSnapshot` -- point-in-time snapshot of active artifacts on a node.
- `fn compute_evidence_hash(report: &BlastRadiusReport) -> Blake3Hash` -- BLAKE3 of the serialized report.

#### Files to Modify

**`/Users/luis.d/code/github/pleme-io/tameshi/src/lib.rs`** -- Add `pub mod forensics;` and extend prelude with key forensics types.

#### Tests to Write (in `src/forensics/*.rs` as `#[cfg(test)] mod tests`)

ledger.rs tests (~30):
- `test_new_ledger_is_empty`
- `test_append_single_entry`
- `test_append_multiple_entries_chain_linkage`
- `test_entry_hash_determinism`
- `test_previous_hash_chain_integrity`
- `test_verify_integrity_empty`
- `test_verify_integrity_single`
- `test_verify_integrity_multiple`
- `test_verify_integrity_tampered_entry_hash`
- `test_verify_integrity_tampered_previous_hash`
- `test_len_tracking`
- `test_is_empty`
- `test_last_returns_most_recent`
- `test_head_hash_updates`
- `test_entries_in_range`
- `test_entries_in_range_empty`
- `test_entries_in_range_partial`
- `test_consistency_proof_valid`
- `test_consistency_proof_single_entry`
- `test_consistency_proof_invalid_range`
- `test_consistency_proof_out_of_bounds`
- `test_serde_roundtrip_entry`
- `test_serde_roundtrip_ledger_entries`
- `test_concurrent_append` (use `Arc` and spawn tasks)
- `test_in_memory_store_append_and_get`
- `test_in_memory_store_range`
- `test_in_memory_store_latest`
- `test_thread_safety_rwlock`
- `test_first_entry_has_zero_previous`
- `test_entry_hash_includes_all_fields`

index.rs tests (~25):
- `test_new_index_empty`
- `test_insert_indexes_composed_root`
- `test_insert_indexes_artifact_hash`
- `test_insert_indexes_control_hash`
- `test_insert_indexes_intent_hash`
- `test_insert_indexes_node`
- `test_insert_indexes_namespace`
- `test_insert_indexes_time`
- `test_insert_indexes_binary_paths`
- `test_query_by_hash_found`
- `test_query_by_hash_not_found`
- `test_query_by_hash_multiple_entries`
- `test_query_by_node_found`
- `test_query_by_node_not_found`
- `test_query_by_time_range`
- `test_query_by_time_range_empty`
- `test_query_by_time_range_boundary`
- `test_query_by_binary_found`
- `test_query_by_binary_not_found`
- `test_multiple_binaries_per_entry`
- `test_multiple_entries_same_hash`
- `test_multiple_entries_same_node`
- `test_index_after_many_inserts`
- `test_query_by_namespace`
- `test_entry_ref_equality`

query.rs tests (~30):
- `test_blast_radius_single_node`
- `test_blast_radius_multiple_nodes`
- `test_blast_radius_multiple_clusters`
- `test_blast_radius_time_filtering`
- `test_blast_radius_co_resident_artifacts`
- `test_blast_radius_chain_integrity_true`
- `test_blast_radius_evidence_hash_determinism`
- `test_blast_radius_hash_not_found`
- `test_blast_radius_empty_ledger`
- `test_timeline_chronological_order`
- `test_timeline_node_filter`
- `test_timeline_time_range`
- `test_timeline_empty`
- `test_timeline_multiple_events`
- `test_provenance_single_artifact`
- `test_provenance_multiple_artifacts`
- `test_provenance_at_specific_time`
- `test_provenance_no_artifacts`
- `test_provenance_returns_deployment_context`
- `test_compute_evidence_hash_determinism`
- `test_blast_radius_serde_roundtrip`
- `test_timeline_event_serde_roundtrip`
- `test_provenance_snapshot_serde_roundtrip`
- `test_deployment_context_serde_roundtrip`
- `test_revoke_request_serde_roundtrip`
- `test_revoke_result_serde_roundtrip`
- `test_affected_node_detail_serde`
- `test_co_resident_artifact_serde`
- `test_time_range_serde`
- `test_blast_radius_with_real_certification_artifacts`

#### Agent Prompt Template

> You are implementing Sprint 1 of the tameshi forensics integration. Build the MerkleLedger -- an append-only, BLAKE3-chained, tamper-proof ledger of CertificationArtifact deployments. Follow the HeartbeatChain pattern in `src/heartbeat.rs` exactly: RwLock wrapping inner state, BLAKE3 hash chain with `previous_hash` linkage, `verify_integrity()` walking the chain, `ConsistencyProof` for remote verification. Create `src/forensics/mod.rs`, `types.rs`, `ledger.rs`, `index.rs`, `query.rs`. All types must derive `Serialize, Deserialize, schemars::JsonSchema` where they are API-facing. The `MerkleLedgerStore` trait must be async and `Send + Sync`. Write ~85 unit tests. Register the module in `lib.rs` and add key types to the prelude.

---

### Sprint 2: Forensics API (sekiban + kensa)

**Goal**: Wire the blast-radius, timeline, provenance, and revoke REST endpoints in sekiban, backed by the MerkleLedger from Sprint 1.

**Dependencies**: Sprint 1

**Can run in parallel with**: Sprint 3 (after Sprint 1 completes)

**Estimated test count**: ~45 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/sekiban/src/api/forensics.rs`**
Functions (axum handlers following the pattern in `/Users/luis.d/code/github/pleme-io/sekiban/src/api/rest.rs`):
- `create_forensics_router(service: Arc<ForensicsService>) -> Router` -- routes for all 4 endpoints.
- `async fn get_blast_radius(Query(params), State(service)) -> impl IntoResponse` -- parses `hash`, `from`, `to` query params; calls `forensics::query::blast_radius()`; returns `BlastRadiusResponse` JSON.
- `async fn get_timeline(Query(params), State(service)) -> impl IntoResponse` -- parses `hash`, `from`, `to`, `node` query params; calls `forensics::query::timeline()`; returns `TimelineResponse` JSON.
- `async fn get_provenance(Query(params), State(service)) -> impl IntoResponse` -- parses `node`, `at` query params; calls `forensics::query::provenance()`; returns `ProvenanceResponse` JSON.
- `async fn revoke_hash(State(service), Json(body)) -> impl IntoResponse` -- accepts `RevokeRequest`; removes hash from kanshi BPF allow map (via trait); records `HeartbeatEvent::Revocation` in HeartbeatChain; returns `RevokeResponse` JSON.
- Query parameter structs: `BlastRadiusParams`, `TimelineParams`, `ProvenanceParams`.

**`/Users/luis.d/code/github/pleme-io/sekiban/src/api/forensics_service.rs`**
- `ForensicsService` -- struct holding: `Arc<MerkleLedger>`, `Arc<LedgerIndex>`, `Arc<HeartbeatChain>`, revocation callback (trait object).
- `ForensicsService::new(ledger, index, heartbeat_chain)`.
- `ForensicsService::blast_radius(hash, from, to) -> Result<BlastRadiusReport>`.
- `ForensicsService::timeline(hash, from, to, node) -> Result<Vec<TimelineEvent>>`.
- `ForensicsService::provenance(node, at) -> Result<ProvenanceSnapshot>`.
- `ForensicsService::revoke(request) -> Result<RevokeResult>`.

**Trait**: `RevocationDispatcher: Send + Sync` -- `async fn revoke_hash(hash: &Blake3Hash) -> Result<RevocationConfirmation>`. Mocked for tests; real impl talks to kanshi BPF loader.

#### Files to Modify

- `/Users/luis.d/code/github/pleme-io/sekiban/src/api/mod.rs` -- add `pub mod forensics;` and `pub mod forensics_service;`, wire forensics router into the main router.
- `/Users/luis.d/code/github/pleme-io/sekiban/src/api/rest.rs` -- integrate forensics router alongside existing routes.
- `/Users/luis.d/code/github/pleme-io/sekiban/Cargo.toml` -- add tameshi dependency update if needed for forensics types.

#### Tests to Write

forensics.rs handler tests (~25):
- `test_blast_radius_200_valid_hash`
- `test_blast_radius_400_invalid_hash_format`
- `test_blast_radius_404_hash_not_found`
- `test_blast_radius_default_time_range`
- `test_blast_radius_custom_time_range`
- `test_timeline_200_valid`
- `test_timeline_400_missing_hash`
- `test_timeline_node_filter`
- `test_timeline_time_range_filtering`
- `test_provenance_200_valid`
- `test_provenance_400_missing_node`
- `test_provenance_400_missing_timestamp`
- `test_revoke_200_success`
- `test_revoke_400_invalid_body`
- `test_revoke_records_heartbeat_entry`
- `test_revoke_returns_affected_count`
- `test_blast_radius_evidence_hash_in_response`
- `test_blast_radius_chain_integrity_field`
- `test_blast_radius_co_resident_artifacts_populated`
- `test_forensics_router_creation`
- `test_forensics_service_creation`
- `test_blast_radius_empty_results`
- `test_timeline_empty_results`
- `test_provenance_empty_results`
- `test_revoke_dispatches_to_kanshi`

forensics_service.rs tests (~20):
- `test_service_blast_radius_delegates_to_query`
- `test_service_timeline_delegates_to_query`
- `test_service_provenance_delegates_to_query`
- `test_service_revoke_records_heartbeat`
- `test_service_revoke_calls_dispatcher`
- `test_service_concurrent_blast_radius_queries`
- `test_service_with_populated_ledger`
- `test_service_revoke_returns_sequence_number`
- `test_mock_revocation_dispatcher`
- `test_service_time_range_defaults`
- (10 more serde/edge-case tests)

#### Agent Prompt Template

> You are implementing Sprint 2: Forensics REST API in sekiban. Create `src/api/forensics.rs` and `src/api/forensics_service.rs`. Follow the existing axum handler pattern in `src/api/rest.rs` (State extraction, Router creation, JSON responses). Implement GET `/api/v1/forensics/blast-radius`, GET `/api/v1/forensics/timeline`, GET `/api/v1/forensics/provenance`, POST `/api/v1/forensics/revoke`. The handlers delegate to `ForensicsService` which holds `Arc<MerkleLedger>` and `Arc<LedgerIndex>` from tameshi. Create a `RevocationDispatcher` trait for kanshi BPF map updates. Wire into the main router. Write ~45 tests. The OpenAPI spec shapes are already defined in `tameshi/spec/openapi.yaml` lines 687-858 and schemas at lines 2534-2835.

---

### Sprint 3: Forensics Writers (sekiban + kanshi)

**Goal**: Every admission decision and binary verification writes a MerkleLedgerEntry with full deployment context.

**Dependencies**: Sprint 1

**Can run in parallel with**: Sprint 2 (after Sprint 1 completes)

**Estimated test count**: ~40 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/sekiban/src/webhook/ledger_writer.rs`**
- `LedgerWriter` -- struct holding `Arc<MerkleLedger>`, `Arc<LedgerIndex>`.
- `LedgerWriter::record_admission(artifact, signed_root, admission_review) -> Result<()>` -- extracts `DeploymentContext` from the K8s `AdmissionReview` (pod spec, namespace, node affinity), appends to MerkleLedger, updates LedgerIndex.
- `LedgerWriter::record_gate_verification(artifact, signed_root, gate_spec) -> Result<()>`.
- Helper: `fn extract_deployment_context(admission_review) -> DeploymentContext`.

**`/Users/luis.d/code/github/pleme-io/kanshi/src/ledger_writer.rs`**
- `KanshiLedgerWriter` -- struct holding HTTP client to push entries to sekiban's forensics API (or direct `Arc<MerkleLedger>` if in-process).
- `KanshiLedgerWriter::record_binary_verification(hash, binary_path, node, pod, namespace, outcome) -> Result<()>` -- constructs a `MerkleLedgerEntry` with deployment context from BPF event metadata.
- Integration with `EventMetricsCollector::poll_and_record()` -- after recording to HeartbeatChain, also write to MerkleLedger.

#### Files to Modify

- `/Users/luis.d/code/github/pleme-io/sekiban/src/webhook/admission.rs` -- after admission decision, call `LedgerWriter::record_admission()`.
- `/Users/luis.d/code/github/pleme-io/kanshi/src/event_metrics.rs` -- after appending to HeartbeatChain (line 71-77), also call `KanshiLedgerWriter::record_binary_verification()`.
- `/Users/luis.d/code/github/pleme-io/sekiban/src/controller/gate_reconciler.rs` -- after gate verification, call `LedgerWriter::record_gate_verification()`.

#### Tests

sekiban ledger_writer.rs tests (~20):
- `test_record_admission_creates_entry`
- `test_record_admission_sets_deployment_context`
- `test_record_admission_updates_index`
- `test_record_admission_chain_linkage`
- `test_extract_deployment_context_from_pod`
- `test_extract_deployment_context_from_deployment`
- `test_extract_deployment_context_missing_fields`
- `test_record_gate_verification_creates_entry`
- `test_record_gate_verification_sets_signed_root`
- `test_concurrent_writes_from_multiple_webhooks`
- (10 more edge case tests)

kanshi ledger_writer.rs tests (~20):
- `test_record_binary_verification_creates_entry`
- `test_record_binary_verification_deployment_context`
- `test_record_binary_verification_captures_binary_path`
- `test_record_binary_verification_captures_node`
- `test_record_binary_verification_captures_pod`
- `test_poll_and_record_writes_to_ledger`
- `test_poll_and_record_writes_to_both_heartbeat_and_ledger`
- `test_ledger_writer_with_mock_http_client`
- `test_ledger_writer_handles_network_error`
- `test_ledger_writer_retries_on_failure`
- (10 more tests)

#### Agent Prompt Template

> You are implementing Sprint 3: Forensics Writers. Every sekiban admission decision and kanshi binary verification must produce a `MerkleLedgerEntry`. In sekiban, create `src/webhook/ledger_writer.rs` with `LedgerWriter` that extracts `DeploymentContext` from K8s `AdmissionReview` objects. In kanshi, create `src/ledger_writer.rs` with `KanshiLedgerWriter` that captures BPF event metadata into ledger entries. Modify `sekiban/src/webhook/admission.rs` to call the writer after decisions. Modify `kanshi/src/event_metrics.rs` to call the writer after `HeartbeatChain.append()`. Write ~40 tests total across both repos.

---

### Sprint 4: tameshi-watch Blast Radius Actions

**Goal**: When a CVE is ingested, automatically query blast radius and optionally revoke affected hashes.

**Dependencies**: Sprint 1, Sprint 2

**Can run in parallel with**: Sprint 5 (after Sprints 1-2 complete)

**Estimated test count**: ~35 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/tameshi-watch/src/actions/blast_radius.rs`**
Types:
- `BlastRadiusAction` -- implements `Action` trait. Holds HTTP client for forensics API.
- Fields: `forensics_api_url: String`, `http_client: Box<dyn HttpClient>`, `auto_revoke_threshold: CveSeverity`.
- `Action::name()` returns `"blast_radius"`.
- `Action::handles(event)` -- returns true for `ComplianceEvent::NewCve` and `ComplianceEvent::PackageVulnerable`.
- `Action::execute(event)` -- on CVE: hash the affected package identifier with BLAKE3, call `GET /api/v1/forensics/blast-radius?hash=...`, if severity >= threshold call `POST /api/v1/forensics/revoke`. Returns `ActionResult` with blast radius summary.

**`/Users/luis.d/code/github/pleme-io/tameshi-watch/src/actions/revocation.rs`**
Types:
- `AutoRevocationAction` -- implements `Action` trait. Calls the revoke endpoint when a CVE matches known binary hashes.
- `RevocationPolicy` -- struct: `severity_threshold: CveSeverity`, `require_operator_approval: bool`, `auto_revoke_namespaces: Vec<String>`.
- Integrates with HeartbeatChain via HTTP call to sekiban to log the revocation event.

#### Files to Modify

- `/Users/luis.d/code/github/pleme-io/tameshi-watch/src/actions/mod.rs` -- add `pub mod blast_radius;` and `pub mod revocation;`, re-export types.
- `/Users/luis.d/code/github/pleme-io/tameshi-watch/src/main.rs` -- wire `BlastRadiusAction` and `AutoRevocationAction` into the `EventPipeline`.

#### Tests

blast_radius.rs tests (~20):
- `test_blast_radius_action_handles_new_cve`
- `test_blast_radius_action_handles_package_vulnerable`
- `test_blast_radius_action_ignores_profile_updated`
- `test_blast_radius_action_queries_forensics_api`
- `test_blast_radius_action_auto_revoke_critical`
- `test_blast_radius_action_no_revoke_low_severity`
- `test_blast_radius_action_returns_affected_count`
- `test_blast_radius_action_handles_api_error`
- `test_blast_radius_action_handles_404_hash_not_found`
- `test_blast_radius_action_serde_roundtrip`
- `test_blast_radius_action_name`
- `test_blast_radius_action_concurrent_cves`
- `test_revocation_policy_default`
- `test_revocation_policy_custom_threshold`
- `test_revocation_policy_require_approval`
- `test_auto_revocation_action_name`
- `test_auto_revocation_action_handles`
- `test_auto_revocation_action_execute`
- `test_auto_revocation_action_namespace_filtering`
- `test_blast_radius_integration_with_pipeline`

revocation.rs tests (~15):
- `test_auto_revocation_critical_severity`
- `test_auto_revocation_below_threshold`
- `test_auto_revocation_with_approval_required`
- `test_auto_revocation_namespace_filter`
- `test_auto_revocation_records_heartbeat`
- `test_auto_revocation_handles_revoke_failure`
- `test_auto_revocation_multiple_hashes`
- `test_auto_revocation_dedup`
- `test_revocation_policy_serde`
- `test_auto_revocation_action_result_format`
- (5 more edge case tests)

#### Agent Prompt Template

> You are implementing Sprint 4: tameshi-watch Blast Radius Actions. Create `src/actions/blast_radius.rs` and `src/actions/revocation.rs` in the tameshi-watch repo. Both implement the `Action` trait (see `src/actions/mod.rs` for the trait definition). `BlastRadiusAction` handles `ComplianceEvent::NewCve` and `PackageVulnerable` -- queries the forensics API blast-radius endpoint, optionally auto-revokes. `AutoRevocationAction` manages the revocation lifecycle with `RevocationPolicy`. Wire both into the `EventPipeline` in `main.rs`. Write ~35 tests.

---

### Sprint 5: Global State Root Types (tameshi)

**Goal**: Add ClusterRoot computation, GlobalStateRoot chain, and reverse index types to tameshi core.

**Dependencies**: Sprint 1

**Can run in parallel with**: Sprint 4 (after Sprint 1 completes)

**Estimated test count**: ~70 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/tameshi/src/global/mod.rs`**
```
pub mod cluster;
pub mod state_root;
pub mod reverse_index;
pub mod types;
```

**`/Users/luis.d/code/github/pleme-io/tameshi/src/global/types.rs`**
Types:
- `ClusterStatus` -- enum: `Active`, `Stale`, `Offline`, `Revoked`. Derive: `Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema`.
- `ClusterRootEntry` -- struct: `cluster_id: String`, `cluster_root: Blake3Hash`, `signed_root: SignedRoot`, `node_count: u32`, `artifact_count: u64`, `last_reported: DateTime<Utc>`, `status: ClusterStatus`.
- `GlobalStateRoot` -- struct: `root_hash: Blake3Hash`, `cluster_roots: BTreeMap<String, ClusterRootEntry>`, `computed_at: DateTime<Utc>`, `sequence: u64`, `previous_root: Blake3Hash`.
- `ArtifactLocation` -- struct: `cluster_id: String`, `node_id: String`, `binary_path: String`, `first_seen: DateTime<Utc>`, `last_seen: DateTime<Utc>`.
- `ClusterRootReport` -- struct: `cluster_id: String`, `cluster_root: Blake3Hash`, `signed_root: SignedRoot`, `node_count: u32`, `artifact_count: u64`, `added_artifacts: Vec<ArtifactDelta>`, `removed_artifacts: Vec<Blake3Hash>`, `last_ack_sequence: u64`.
- `ArtifactDelta` -- struct: `composed_root: Blake3Hash`, `node_id: String`, `binary_path: String`.
- `GlobalBlastRadiusReport` -- struct: `target_hash: Blake3Hash`, `cve_id: Option<String>`, `affected_clusters: Vec<ClusterBlastRadius>`, `unaffected_clusters: Vec<String>`, `total_affected_nodes: u32`, `total_affected_pods: u64`, `first_seen_global: DateTime<Utc>`, `computed_at: DateTime<Utc>`, `computation_time_ms: u64`.
- `ClusterBlastRadius` -- struct: `cluster_id: String`, `affected_nodes: u32`, `affected_pods: u64`, `first_seen: DateTime<Utc>`, `last_seen: DateTime<Utc>`, `node_details: Vec<NodeBlastRadius>`.
- `NodeBlastRadius` -- struct: `node_id: String`, `binary_paths: Vec<String>`, `pod_names: Vec<String>`, `certification_artifact: CertificationArtifact`.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/global/cluster.rs`**
Functions:
- `pub fn compute_cluster_root(artifacts: &[CertificationArtifact]) -> Blake3Hash` -- if empty, return `Blake3Hash::digest(b"empty-cluster")`. Otherwise: extract composed_roots, sort, apply `domain_separated_leaf()` to each, build MerkleTree with `Blake3Algorithm`, return root. Must use existing `domain_separated_leaf` and `Blake3Algorithm` from `/Users/luis.d/code/github/pleme-io/tameshi/src/merkle.rs`.
- `pub fn compute_cluster_root_from_hashes(composed_roots: &[Blake3Hash]) -> Blake3Hash` -- same but from raw hashes.
- `pub fn verify_cluster_root(artifacts: &[CertificationArtifact], expected: &Blake3Hash) -> bool`.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/global/state_root.rs`**
Types and functions:
- `GlobalStateRootChain` -- struct wrapping `RwLock<GlobalStateRootChainInner>` (HeartbeatChain pattern).
- `GlobalStateRootChainInner` -- `entries: Vec<GlobalStateRoot>`, `next_sequence: u64`, `last_root: Blake3Hash`.
- `GlobalStateRootChain::new()`.
- `GlobalStateRootChain::update_cluster(report: ClusterRootReport) -> GlobalStateRoot` -- updates internal `BTreeMap<String, ClusterRootEntry>`, recomputes root_hash from sorted cluster roots using `Blake3Algorithm` with domain separation, increments sequence, sets `previous_root`, appends to chain.
- `GlobalStateRootChain::current() -> Option<GlobalStateRoot>`.
- `GlobalStateRootChain::history(from, to) -> Vec<GlobalStateRoot>`.
- `GlobalStateRootChain::verify_integrity() -> bool`.
- `GlobalStateRootChain::consistency_proof(from_seq, to_seq) -> Result<ConsistencyProof>`.
- `fn compute_global_root(cluster_roots: &BTreeMap<String, ClusterRootEntry>) -> Blake3Hash` -- sorted cluster root hashes, domain-separated leaves, Blake3Algorithm Merkle tree.
- `fn determine_cluster_status(last_reported: DateTime<Utc>, interval_secs: u64, now: DateTime<Utc>) -> ClusterStatus` -- Active if within 2 intervals, Stale if 1-3 missed, Offline if 3+ missed.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/global/reverse_index.rs`**
Types:
- `ReverseIndex` -- struct: `index: RwLock<HashMap<Blake3Hash, Vec<ArtifactLocation>>>`.
- `ReverseIndex::new()`.
- `ReverseIndex::insert(composed_root, location)`.
- `ReverseIndex::remove(composed_root, cluster_id)`.
- `ReverseIndex::lookup(hash) -> Vec<ArtifactLocation>` -- O(1) lookup.
- `ReverseIndex::update_from_report(report: &ClusterRootReport)` -- processes added/removed deltas.

#### Files to Modify

- `/Users/luis.d/code/github/pleme-io/tameshi/src/lib.rs` -- add `pub mod global;`, extend prelude.

#### Tests (~70)

cluster.rs tests (~20):
- `test_compute_cluster_root_empty`
- `test_compute_cluster_root_single`
- `test_compute_cluster_root_multiple`
- `test_compute_cluster_root_deterministic_ordering`
- `test_compute_cluster_root_order_independent`
- `test_compute_cluster_root_domain_separation`
- `test_verify_cluster_root_valid`
- `test_verify_cluster_root_invalid`
- `test_compute_from_hashes`
- `test_compute_from_hashes_matches_artifacts`
- (10 more property tests)

state_root.rs tests (~30):
- `test_new_chain_empty`
- `test_update_cluster_creates_entry`
- `test_update_cluster_recomputes_root`
- `test_update_cluster_chain_linkage`
- `test_update_multiple_clusters`
- `test_current_returns_latest`
- `test_history_range`
- `test_verify_integrity`
- `test_verify_integrity_tampered`
- `test_consistency_proof`
- `test_global_root_deterministic`
- `test_global_root_order_independent`
- `test_cluster_status_active`
- `test_cluster_status_stale`
- `test_cluster_status_offline`
- `test_cluster_status_boundary`
- `test_cluster_root_report_serde`
- `test_global_state_root_serde`
- `test_concurrent_cluster_updates`
- `test_sequence_monotonic`
- (10 more tests)

reverse_index.rs tests (~20):
- `test_new_index_empty`
- `test_insert_and_lookup`
- `test_insert_multiple_locations`
- `test_lookup_not_found`
- `test_remove_location`
- `test_remove_nonexistent`
- `test_update_from_report_adds`
- `test_update_from_report_removes`
- `test_update_from_report_both`
- `test_concurrent_inserts`
- `test_o1_lookup_performance`
- (9 more tests)

#### Agent Prompt Template

> You are implementing Sprint 5: Global State Root Types in tameshi core. Create `src/global/mod.rs`, `types.rs`, `cluster.rs`, `state_root.rs`, `reverse_index.rs`. Key function: `compute_cluster_root()` must sort composed_roots, apply `domain_separated_leaf()` from `src/merkle.rs`, build a `MerkleTree::<Blake3Algorithm>` and return the root. `GlobalStateRootChain` follows the `HeartbeatChain` pattern (RwLock, sequence, previous_hash linkage, verify_integrity, consistency_proof). The `ReverseIndex` uses `HashMap` for O(1) hash lookups. All types in `types.rs` must derive schemars::JsonSchema. Write ~70 tests. Register in lib.rs.

---

### Sprint 6: tameshi-global Server (new repo)

**Goal**: Create the master state server binary that accepts cluster reports, maintains the global chain, and serves global API endpoints.

**Dependencies**: Sprint 5

**Can run in parallel with**: Sprint 7 (after Sprint 5 completes)

**Estimated test count**: ~60 tests

#### New Repository: `tameshi-global`

**`/Users/luis.d/code/github/pleme-io/tameshi-global/Cargo.toml`**
```toml
[package]
name = "tameshi-global"
version = "0.1.0"
edition = "2024"
rust-version = "1.89.0"
license = "MIT"

[dependencies]
tameshi = { git = "https://github.com/pleme-io/tameshi" }
axum = "0.8"
tokio = { version = "1.50", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = "0.3"
figment = { version = "0.10", features = ["yaml", "env"] }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
object_store = { version = "0.13", features = ["aws"] }
```

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/main.rs`**
- Binary entry point. Loads config, initializes `GlobalStateRootChain`, `ReverseIndex`, starts HTTP server, starts cluster heartbeat monitor task.

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/lib.rs`**
```
pub mod api;
pub mod config;
pub mod error;
pub mod service;
```

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/config.rs`**
- `GlobalConfig` -- struct: `listen_addr: String`, `s3_bucket: String`, `s3_region: String`, `master_dfc_key_name: String`, `cluster_heartbeat_interval_secs: u64`, `stale_threshold_intervals: u32`, `offline_threshold_intervals: u32`.

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/service.rs`**
- `GlobalService` -- struct: `chain: Arc<GlobalStateRootChain>`, `reverse_index: Arc<ReverseIndex>`, `signer: Arc<dyn MerkleRootSigner>`, `federation_verifier: FederationVerifier`, `config: GlobalConfig`.
- `GlobalService::accept_cluster_report(report: ClusterRootReport) -> Result<GlobalStateRoot>` -- verify cluster signature via `FederationVerifier`, update chain, update reverse index.
- `GlobalService::global_blast_radius(hash, cve_id) -> Result<GlobalBlastRadiusReport>` -- O(1) reverse index lookup, fan out to affected clusters for detail.
- `GlobalService::revoke_everywhere(hash, reason) -> Result<Vec<ClusterRevocationResult>>` -- fan out POST /api/v1/forensics/revoke to all affected clusters.
- `GlobalService::cluster_monitor_loop()` -- periodic task that checks `last_reported` and updates `ClusterStatus`.

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/api.rs`**
Routes (following GLOBAL_STATE_ROOT.md section 5):
- `GET /api/v1/global/state-root` -- returns current `GlobalStateRoot`.
- `GET /api/v1/global/blast-radius?hash=...` -- returns `GlobalBlastRadiusReport`.
- `GET /api/v1/global/clusters` -- list clusters with status.
- `GET /api/v1/global/clusters/{id}/state` -- specific cluster state.
- `POST /api/v1/global/clusters/{id}/report` -- accept `ClusterRootReport`.
- `GET /api/v1/global/history?from=...&to=...` -- GlobalStateRoot chain history.
- `POST /api/v1/global/revoke-everywhere` -- fan-out revocation.
- `GET /api/v1/global/reverse-index?hash=...` -- raw reverse index lookup.

**`/Users/luis.d/code/github/pleme-io/tameshi-global/chart/tameshi-global/`** -- Helm chart (values.yaml, templates/deployment.yaml, templates/service.yaml, Chart.yaml).

#### Tests (~60)

service.rs tests (~35):
- `test_accept_cluster_report_updates_chain`
- `test_accept_cluster_report_updates_reverse_index`
- `test_accept_cluster_report_verifies_signature`
- `test_accept_cluster_report_rejects_unknown_cluster`
- `test_accept_cluster_report_rejects_invalid_signature`
- `test_accept_cluster_report_replay_protection`
- `test_global_blast_radius_o1_lookup`
- `test_global_blast_radius_multiple_clusters`
- `test_global_blast_radius_unaffected_clusters`
- `test_global_blast_radius_computation_time`
- `test_revoke_everywhere_fans_out`
- `test_revoke_everywhere_partial_failure`
- `test_cluster_monitor_active`
- `test_cluster_monitor_stale`
- `test_cluster_monitor_offline`
- `test_cluster_monitor_revoked`
- (19 more tests)

api.rs tests (~25):
- `test_get_state_root_200`
- `test_get_state_root_empty`
- `test_get_blast_radius_200`
- `test_get_blast_radius_400`
- `test_list_clusters_200`
- `test_list_clusters_filter_status`
- `test_get_cluster_state_200`
- `test_get_cluster_state_404`
- `test_post_cluster_report_200`
- `test_post_cluster_report_401_untrusted`
- `test_get_history_200`
- `test_get_history_time_range`
- `test_revoke_everywhere_200`
- `test_revoke_everywhere_partial`
- `test_reverse_index_200`
- `test_reverse_index_404`
- (9 more tests)

#### Agent Prompt Template

> You are implementing Sprint 6: tameshi-global, a new Rust binary. This is the master state server for the GlobalStateRoot system. It uses tameshi's `GlobalStateRootChain`, `ReverseIndex`, `FederationVerifier`, and `MerkleRootSigner` traits. Create a standard Rust project with `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/config.rs`, `src/service.rs`, `src/api.rs`, `src/error.rs`. The API serves 8 endpoints documented in GLOBAL_STATE_ROOT.md section 5. Use axum for HTTP. `GlobalService` is the core -- it accepts cluster reports (verifying DFC signatures), maintains the GlobalStateRoot chain, serves blast radius queries via the reverse index, and fans out revocations. Include a Helm chart. Write ~60 tests.

---

### Sprint 7: S3 Object Lock + Tiered Storage

**Goal**: Persistent WORM storage for the MerkleLedger with hot/warm/cold tier management.

**Dependencies**: Sprint 1

**Can run in parallel with**: Sprint 6 (after Sprint 1 completes)

**Estimated test count**: ~40 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/storage.rs`**
Types:
- `S3LedgerStore` -- implements `MerkleLedgerStore` trait. Uses `object_store` crate (already a dependency). Writes each entry as a versioned S3 object with legal hold enabled.
- `S3LedgerConfig` -- struct: `bucket: String`, `region: String`, `prefix: String`, `object_lock_mode: ObjectLockMode`, `retention_days: u32`.
- `ObjectLockMode` -- enum: `Governance`, `Compliance`.
- `S3LedgerStore::new(config) -> Self`.
- Methods implement `MerkleLedgerStore`: `append`, `get`, `range`, `latest`.
- Object key format: `{prefix}/{sequence:020}.json` (zero-padded for lexicographic ordering).
- `S3LedgerStore::verify_object_lock(sequence) -> Result<bool>` -- verifies object lock is set on the entry.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/tiering.rs`**
Types:
- `StorageTier` -- enum: `Hot`, `Warm`, `Cold`.
- `TierPolicy` -- struct: `hot_hours: u64` (default 72), `warm_days: u64` (default 90), `cold_threshold: Duration`.
- `TieredLedgerStore` -- composite store: holds in-memory hot tier, `S3LedgerStore` for warm, manages S3 Glacier transition markers for cold.
- `TieredLedgerStore::promote(sequence)` -- retrieves from cold/warm to hot tier on-demand.
- `TieredLedgerStore::demote()` -- moves entries past hot threshold to warm, past warm threshold to cold.
- `TieredLedgerStore::tier_for(entry) -> StorageTier`.

**`/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/akeyless_audit.rs`**
Types:
- `AkeylessAuditEmitter` -- implements `HeartbeatEmitter` for dual-write to Akeyless Secure Audit Log.
- `AkeylessAuditConfig` -- struct: `gateway_url: String`, `access_id: String`, `audit_log_path: String`.
- On each ledger entry append, also writes to Akeyless audit log via REST API.

#### Files to Modify

- `/Users/luis.d/code/github/pleme-io/tameshi/src/forensics/mod.rs` -- add `pub mod storage;`, `pub mod tiering;`, `pub mod akeyless_audit;`.

#### Tests (~40)

storage.rs tests (~15):
- `test_s3_store_append_and_get`
- `test_s3_store_range`
- `test_s3_store_latest`
- `test_s3_store_object_key_format`
- `test_s3_store_sequential_keys`
- `test_s3_config_serde`
- `test_s3_config_defaults`
- `test_object_lock_mode_serde`
- `test_s3_store_empty`
- `test_s3_store_concurrent_appends`
- (5 more using mock object_store)

tiering.rs tests (~15):
- `test_tier_for_hot`
- `test_tier_for_warm`
- `test_tier_for_cold`
- `test_tier_policy_defaults`
- `test_tier_policy_custom`
- `test_promote_from_warm`
- `test_demote_hot_to_warm`
- `test_demote_warm_to_cold`
- `test_tiered_store_query_hot`
- `test_tiered_store_query_warm_fallback`
- `test_tiered_store_transparent_promotion`
- (4 more)

akeyless_audit.rs tests (~10):
- `test_audit_emitter_creation`
- `test_audit_emitter_emit`
- `test_audit_config_serde`
- `test_dual_write_both_succeed`
- `test_dual_write_audit_failure_logged`
- (5 more with mock HTTP client)

#### Agent Prompt Template

> You are implementing Sprint 7: S3 Object Lock + Tiered Storage. Create `src/forensics/storage.rs`, `src/forensics/tiering.rs`, `src/forensics/akeyless_audit.rs` in tameshi. `S3LedgerStore` implements the `MerkleLedgerStore` trait using the `object_store` crate (already in Cargo.toml). Object keys are zero-padded sequence numbers for lexicographic ordering. `TieredLedgerStore` composes in-memory hot tier (72h), S3 Standard warm tier (90d), and S3 Glacier cold tier. `AkeylessAuditEmitter` implements `HeartbeatEmitter` for dual-write to Akeyless Secure Audit Log. Follow the `S3Emitter` pattern from `src/heartbeat.rs` (lines 798+). Write ~40 tests.

---

### Sprint 8: Cross-Cluster Revocation

**Goal**: Revoke-everywhere endpoint that fans out to all clusters and records HeartbeatChain evidence.

**Dependencies**: Sprint 2, Sprint 5, Sprint 6

**Can run in parallel with**: Sprint 7

**Estimated test count**: ~35 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/revocation.rs`**
Types:
- `RevocationOrchestrator` -- struct: `clusters: Vec<ClusterEndpoint>`, `http_client: Arc<dyn HttpClient>`, `heartbeat_chain: Arc<HeartbeatChain>`.
- `ClusterEndpoint` -- struct: `cluster_id: String`, `forensics_api_url: String`, `auth_token: String`.
- `ClusterRevocationResult` -- struct: `cluster_id: String`, `success: bool`, `affected_nodes: u32`, `bpf_maps_updated: bool`, `heartbeat_entry_sequence: Option<u64>`, `error: Option<String>`.
- `RevocationOrchestrator::revoke_everywhere(hash, reason, severity, operator) -> Vec<ClusterRevocationResult>` -- concurrent fan-out using `tokio::join_all`, each calling `POST /api/v1/forensics/revoke` on the target cluster's sekiban instance. Records a `HeartbeatEvent::Revocation` in the global HeartbeatChain for each cluster response.
- `RevocationOrchestrator::revoke_cluster(endpoint, hash, reason, severity, operator) -> ClusterRevocationResult` -- single cluster revocation with retry.

**`/Users/luis.d/code/github/pleme-io/tameshi-global/src/evidence.rs`**
Types:
- `EvidenceCollector` -- struct holding `HeartbeatChain` ref.
- `EvidenceCollector::record_evidence_query(query_hash, response_hash) -> HeartbeatEntry` -- records in HeartbeatChain that an evidence query was made, producing a tamper-proof audit trail of forensics API usage.
- `EvidenceCollector::generate_circia_package(from, to) -> CirciaEvidencePackage` -- collects all evidence from the time window.
- `CirciaEvidencePackage` -- struct: `window_start`, `window_end`, `blast_radius_reports: Vec<BlastRadiusReport>`, `revocations: Vec<RevokeResult>`, `heartbeat_entries: Vec<HeartbeatEntry>`, `chain_integrity: bool`, `package_hash: Blake3Hash`.

#### Files to Modify

- `/Users/luis.d/code/github/pleme-io/tameshi-global/src/api.rs` -- wire `POST /api/v1/global/revoke-everywhere` to `RevocationOrchestrator`.
- `/Users/luis.d/code/github/pleme-io/tameshi-global/src/service.rs` -- add `RevocationOrchestrator` and `EvidenceCollector` to service.

#### Tests (~35)

revocation.rs tests (~20):
- `test_revoke_everywhere_all_succeed`
- `test_revoke_everywhere_partial_failure`
- `test_revoke_everywhere_all_fail`
- `test_revoke_everywhere_empty_clusters`
- `test_revoke_everywhere_concurrent_fan_out`
- `test_revoke_everywhere_records_heartbeat`
- `test_revoke_cluster_success`
- `test_revoke_cluster_failure`
- `test_revoke_cluster_retry`
- `test_revoke_cluster_timeout`
- `test_cluster_revocation_result_serde`
- `test_cluster_endpoint_serde`
- `test_revoke_everywhere_returns_all_results`
- `test_revoke_everywhere_heartbeat_per_cluster`
- (6 more)

evidence.rs tests (~15):
- `test_record_evidence_query`
- `test_record_evidence_query_chain_linkage`
- `test_generate_circia_package`
- `test_circia_package_integrity`
- `test_circia_package_time_window`
- `test_circia_package_hash_determinism`
- `test_circia_package_empty_window`
- `test_circia_package_serde`
- `test_evidence_collector_concurrent`
- (6 more)

#### Agent Prompt Template

> You are implementing Sprint 8: Cross-Cluster Revocation in tameshi-global. Create `src/revocation.rs` and `src/evidence.rs`. `RevocationOrchestrator` fans out `POST /api/v1/forensics/revoke` to all affected clusters concurrently via `tokio::join_all`. Each revocation is recorded as a `HeartbeatEvent::Revocation` in the global HeartbeatChain. `EvidenceCollector` generates CIRCIA-compliant evidence packages from the HeartbeatChain with `package_hash` for tamper detection. Wire into the API and service layers. Write ~35 tests.

---

### Sprint 9: Integration Testing + Hardening

**Goal**: End-to-end tests across all components, proptest properties for new chain structures, chaos testing.

**Dependencies**: Sprints 1-8

**Can run in parallel with**: Sprint 10

**Estimated test count**: ~50 tests

#### Files to Create

**`/Users/luis.d/code/github/pleme-io/tameshi/tests/forensics_e2e.rs`**
Integration tests (~15):
- `test_full_forensics_pipeline` -- compose artifact, append to ledger, index, query blast radius, verify results.
- `test_ledger_to_blast_radius_roundtrip` -- create 100 entries, query blast radius for a known hash, verify all entries found.
- `test_ledger_integrity_after_many_appends` -- append 10,000 entries, verify_integrity.
- `test_blast_radius_with_real_certification_artifacts` -- use `compose_certification_artifact()` to create real artifacts, append to ledger, query.
- `test_timeline_across_multiple_nodes` -- entries on 5 nodes, timeline query returns chronological order.
- `test_provenance_at_point_in_time` -- entries across time, query at specific moment.
- `test_evidence_hash_changes_with_content` -- same query with different results produces different evidence hashes.
- `test_ledger_consistency_proof_after_appends`.
- `test_ledger_index_consistency_with_ledger`.
- `test_blast_radius_empty_ledger`.
- `test_blast_radius_hash_in_multiple_trees`.
- `test_deployment_context_full_lifecycle`.
- (3 more)

**`/Users/luis.d/code/github/pleme-io/tameshi/tests/global_state_e2e.rs`**
Integration tests (~15):
- `test_cluster_root_computation_deterministic`.
- `test_global_state_root_with_multiple_clusters`.
- `test_global_state_root_chain_integrity`.
- `test_reverse_index_consistency_with_chain`.
- `test_global_blast_radius_with_reverse_index`.
- `test_cluster_status_transitions`.
- `test_cluster_report_updates_global_root`.
- `test_cluster_report_updates_reverse_index`.
- `test_cluster_root_order_independence`.
- `test_global_root_order_independence`.
- `test_replay_protection_last_ack_sequence`.
- `test_delta_protocol_adds_and_removes`.
- (3 more)

**`/Users/luis.d/code/github/pleme-io/tameshi/tests/proptest_forensics.rs`**
Property tests (~10):
- `prop_ledger_entry_hash_determinism` -- same inputs always produce same hash.
- `prop_ledger_chain_integrity_holds` -- arbitrary sequence of appends always passes verify_integrity.
- `prop_cluster_root_order_independent` -- shuffled artifacts produce same root.
- `prop_global_root_order_independent` -- shuffled cluster roots produce same global root.
- `prop_reverse_index_lookup_matches_forward` -- every hash in reverse index corresponds to a real artifact.
- `prop_blast_radius_finds_all_occurrences` -- every entry containing a hash appears in blast radius.
- `prop_consistency_proof_valid_after_appends`.
- `prop_tiering_preserves_chain_integrity`.
- `prop_evidence_hash_unique_per_report`.
- `prop_deployment_context_roundtrip`.

**`/Users/luis.d/code/github/pleme-io/tameshi/tests/chaos_forensics.rs`**
Chaos tests (~10):
- `test_ledger_under_concurrent_load` -- 100 threads appending simultaneously.
- `test_blast_radius_under_concurrent_queries`.
- `test_index_consistency_under_concurrent_inserts`.
- `test_global_chain_under_concurrent_cluster_updates`.
- `test_reverse_index_under_concurrent_updates`.
- `test_s3_store_retry_on_failure` (with mock failing store).
- `test_tiered_store_under_tier_transitions`.
- `test_revocation_under_concurrent_fan_out`.
- `test_evidence_collector_under_load`.
- `test_federation_verifier_with_malformed_signatures`.

#### Agent Prompt Template

> You are implementing Sprint 9: Integration Testing + Hardening for tameshi. Create `tests/forensics_e2e.rs`, `tests/global_state_e2e.rs`, `tests/proptest_forensics.rs`, `tests/chaos_forensics.rs`. The e2e tests compose real `CertificationArtifact`s using `compose_certification_artifact()`, append to `MerkleLedger`, build `LedgerIndex`, and query with the forensics functions. The proptest properties verify hash determinism, order independence, and chain integrity under arbitrary inputs. The chaos tests use 100+ concurrent threads. Follow the existing test patterns in `tests/e2e_attestation.rs` and `tests/proptest_properties.rs`. Write ~50 tests total.

---

### Sprint 10: OpenAPI Spec + Documentation Update

**Goal**: All new endpoints in the OpenAPI spec, forge-gen regeneration, updated CLAUDE.md files.

**Dependencies**: Sprints 1-9

**Can run in parallel with**: Nothing (final sprint)

**Estimated test count**: ~15 tests (spec validation)

#### Files to Modify

**`/Users/luis.d/code/github/pleme-io/tameshi/spec/openapi.yaml`** -- Add new sections:
- Tag: `global` -- "Global state root and cross-cluster operations"
- Paths (8 new endpoints):
  - `GET /api/v1/global/state-root`
  - `GET /api/v1/global/blast-radius`
  - `GET /api/v1/global/clusters`
  - `GET /api/v1/global/clusters/{id}/state`
  - `POST /api/v1/global/clusters/{id}/report`
  - `GET /api/v1/global/history`
  - `POST /api/v1/global/revoke-everywhere`
  - `GET /api/v1/global/reverse-index`
- Schemas (new):
  - `GlobalStateRootResponse`
  - `ClusterRootEntry`
  - `ClusterStatus`
  - `ClusterRootReport`
  - `ArtifactDelta`
  - `GlobalBlastRadiusReport`
  - `ClusterBlastRadius`
  - `NodeBlastRadius`
  - `ArtifactLocation`
  - `MerkleLedgerEntry`
  - `DeploymentContext`
  - `RevokeEverywhereRequest`
  - `RevokeEverywhereResponse`
  - `ClusterRevocationResult`
  - `CirciaEvidencePackage`

**`/Users/luis.d/code/github/pleme-io/tameshi/CLAUDE.md`** -- Add forensics and global modules to module listing, add new types, add new traits.

**`/Users/luis.d/code/github/pleme-io/tameshi/ARCHITECTURE.md`** -- Update to reference implemented forensics system rather than planned.

**`/Users/luis.d/code/github/pleme-io/tameshi/README.md`** -- Update test counts, add forensics section, add global state root section.

**`/Users/luis.d/code/github/pleme-io/tameshi-global/CLAUDE.md`** -- Create new CLAUDE.md documenting the master state server.

#### Tests

**`/Users/luis.d/code/github/pleme-io/tameshi/tests/spec_validation.rs`** -- Add spec validation tests (~15):
- `test_global_state_root_response_schema_roundtrip`
- `test_cluster_root_entry_schema_roundtrip`
- `test_cluster_root_report_schema_roundtrip`
- `test_global_blast_radius_report_schema_roundtrip`
- `test_artifact_delta_schema_roundtrip`
- `test_deployment_context_schema_roundtrip`
- `test_merkle_ledger_entry_schema_roundtrip`
- `test_revoke_everywhere_request_schema_roundtrip`
- `test_circia_evidence_package_schema_roundtrip`
- `test_cluster_status_schema_roundtrip`
- `test_artifact_location_schema_roundtrip`
- `test_cluster_blast_radius_schema_roundtrip`
- `test_node_blast_radius_schema_roundtrip`
- `test_cluster_revocation_result_schema_roundtrip`
- `test_revoke_everywhere_response_schema_roundtrip`

#### Agent Prompt Template

> You are implementing Sprint 10: OpenAPI Spec + Documentation Update. Add 8 new global endpoints and 15 new schemas to `spec/openapi.yaml`. Follow the existing spec patterns (see the forensics endpoints at lines 687-858 for format). Update CLAUDE.md with new modules (forensics/, global/), new types, new traits. Update ARCHITECTURE.md to reference the implemented forensics system. Update README.md with new test counts. Create CLAUDE.md for tameshi-global. Add 15 spec validation tests to `tests/spec_validation.rs` following the existing roundtrip pattern.

---

### Summary Table

| Sprint | Repo(s) | New Files | Tests | Depends On | Parallel With |
|--------|---------|-----------|-------|------------|---------------|
| 1 | tameshi | 5 | ~85 | None | None |
| 2 | sekiban | 2 | ~45 | 1 | 3 |
| 3 | sekiban, kanshi | 2 | ~40 | 1 | 2 |
| 4 | tameshi-watch | 2 | ~35 | 1, 2 | 5 |
| 5 | tameshi | 5 | ~70 | 1 | 4 |
| 6 | tameshi-global (new) | 7+ | ~60 | 5 | 7 |
| 7 | tameshi | 3 | ~40 | 1 | 6 |
| 8 | tameshi-global | 2 | ~35 | 2, 5, 6 | 7 |
| 9 | tameshi | 4 | ~50 | 1-8 | 10 |
| 10 | tameshi, tameshi-global | 0 (modify only) | ~15 | 1-9 | 9 |
| **Total** | | **32+** | **~475** | | |

### Execution Timeline (Optimized Parallelism)

```
Week 1:  Sprint 1 (foundation)
Week 2:  Sprint 2 + Sprint 3 + Sprint 5 (parallel, all depend on Sprint 1)
Week 3:  Sprint 4 + Sprint 6 + Sprint 7 (parallel, depend on previous week)
Week 4:  Sprint 8 (depends on 2, 5, 6)
Week 5:  Sprint 9 + Sprint 10 (final hardening + docs, parallel)
```

### Post-Implementation Test Counts

| Repo | Current | Added | New Total |
|------|---------|-------|-----------|
| tameshi | 925 | ~260 | ~1,185 |
| sekiban | 315 | ~85 | ~400 |
| kanshi | 130 | ~20 | ~150 |
| tameshi-watch | 144 | ~35 | ~179 |
| tameshi-global | 0 | ~95 | ~95 |
| **Total ecosystem** | **2,287** | **~475** | **~2,762** |

### Critical Files for Implementation

- `/Users/luis.d/code/github/pleme-io/tameshi/src/heartbeat.rs` - Primary pattern to follow for all append-only chain structures (RwLock, BLAKE3 linkage, ConsistencyProof, S3Emitter)
- `/Users/luis.d/code/github/pleme-io/tameshi/src/certification_artifact.rs` - The CertificationArtifact type that MerkleLedgerEntry wraps, and the compose/verify functions
- `/Users/luis.d/code/github/pleme-io/tameshi/src/merkle.rs` - Blake3Algorithm, domain_separated_leaf(), compute_merkle_root() -- all new tree constructions (ClusterRoot, GlobalStateRoot) must use these
- `/Users/luis.d/code/github/pleme-io/sekiban/src/api/rest.rs` - Axum handler pattern to follow for forensics API endpoints
- `/Users/luis.d/code/github/pleme-io/tameshi-watch/src/actions/mod.rs` - Action trait definition that BlastRadiusAction and AutoRevocationAction must implement