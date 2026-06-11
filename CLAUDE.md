# tameshi -- Deterministic integrity attestation library

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


<!-- Blackmatter alignment: pillars 10 -->
<!-- See ~/code/github/pleme-io/BLACKMATTER.md for pillar definitions. -->

## Blackmatter pillars upheld

- **Pillar 10** (Proof discipline): Tameshi IS Pillar 10's cryptographic spine. Every artifact in the pleme-io platform hashes through a BLAKE3 Merkle tree rooted at tameshi. `Attested<T>` (arch-synthesizer) refuses to seal without a tameshi-verified proof; `sekiban` enforces at K8s admission; `kensa` enforces compliance; `inshou` gates Nix rebuilds. Cross-infra attestation chains compose here.

Core library for the Unified Theory of Infrastructure Proof. Provides cryptographic hash computation, Merkle tree composition, signature verification, compliance attestation, and tamper-evident audit trails across infrastructure layers. Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test          # 1834 tests (1712 lib + 122 across 6 integration files; counts include proptest, spec, doctests)
cargo build --release
```

## Test Breakdown

| Category | Count | What It Covers |
|----------|------:|----------------|
| Unit (lib) | 1289 | All modules, every trait method, every type variant, every error path |
| End-to-end (tests/) | 95 | Full attestation pipelines, forensics integration, artifact matrix, chaos tests |
| Property-based (proptest) | 38 | Hash determinism, collision resistance, Merkle ordering, combine non-commutativity |
| Specification (spec) | 13 | OpenAPI schema serde roundtrips, API type compatibility |
| Documentation (doc-tests) | 11 | Inline code examples compile and produce correct results |
| **Total** | **1446** | |

## OpenAPI-First Development Flow

tameshi uses an **OpenAPI-first** approach. The spec is the single source of truth for all API surfaces.

```
spec/openapi.yaml                <-- single source of truth
       |
       +-- forge-gen generate    <-- auto-generates:
       |     +-- MCP server      (mcp-forge -> Rust rmcp 0.15)
       |     +-- SDKs            (Go, Python, TypeScript)
       |     +-- Shell completions (skim-tab, fish)
       |     +-- Documentation   (Markdown)
       |
       +-- src/api_types.rs      <-- hand-written types matching spec schemas
       +-- sekiban/src/api/       <-- hand-written axum handlers conforming to spec
       +-- kensa/src/api/         <-- hand-written axum handlers conforming to spec
```

See `docs/openapi-development-flow.md` for the full workflow.

## Architecture

```
src/
  lib.rs                        -- 23 module declarations + prelude (75+ re-exports)
  hash.rs                       -- Blake3Hash, Sha256Hash, AttestationHasher trait, blake3_file, blake3_file_async
  signature.rs                  -- LayerType (14 variants), LayerSignature, MasterSignature, InputHash
  merkle.rs                     -- Blake3Algorithm (RFC 9162 domain separation), compose_merkle, compute_merkle_root, domain_separated_leaf
  verify.rs                     -- verify_master, verify_untested, verify_secure, VerificationResult
  gating.rs                     -- GatingPolicy, evaluate_gate, evaluate_gate_with_clock
  changeset.rs                  -- CertifiedChangeset, hash_changeset
  certification.rs              -- ProductCertification builder (7-stage pipeline)
  certification_artifact.rs     -- CertificationArtifact (3-leaf Merkle: provenance + compliance + intent), ArtifactProofPaths, verify_certification_artifact, verify_proof_path
  signing.rs                    -- MerkleRootSigner trait, LocalSigner (real public-key Ed25519 + verify_signed_root pubkey-only verify), AkeylessDfcSigner (DFC threshold), MockDfcSigner (split-knowledge XOR), BreakGlassToken, SignedRoot, SigningAlgorithm
  heartbeat.rs                  -- HeartbeatChain (RwLock thread-safe), HeartbeatEntry, HeartbeatEvent (14 variants), VerificationOutcome, VerifierIdentity, ConsistencyProof, S3Emitter, HeartbeatEmitter trait
  compliance_api.rs             -- ComplianceQuery trait, ComplianceState, ComplianceStatus, ComplianceDistance, FrameworkState, CertificationQueryStatus, DynamicComplianceCheck, CheckDefinition
  iac_attestation.rs            -- IacTestAttester trait, IacTestPhase, IacTestPhaseResult, IacTestSuiteReport, MockIacTestAttester
  config.rs                     -- ConfigLoader trait, load_config (figment: defaults -> YAML -> env)
  api_types.rs                  -- GateDecision, CertificationStatus, AuditEntry (schemars::JsonSchema)
  reporting.rs                  -- EnvironmentReport, ComplianceSummary, DriftReport
  selftest.rs                   -- FrameworkAttestation, attest_framework, compute_framework_hash, framework_nist_controls
  alerts.rs                     -- AlertSeverity, AlertTarget, AlertMessage
  ci.rs                         -- CI/CD helpers, akeyless_attestation
  error.rs                      -- TameshiError (8 variants)
  cache.rs                      -- CacheEntry, CacheStore
  canonicalize.rs               -- CanonicalMode, Canonicalizer, JsonCanonicalizer, RawCanonicalizer, YamlCanonicalizer, canonical_hash, canonicalizer_for
  testing.rs                    -- testing utilities, MockAkeylessGateway
  traits.rs                     -- 10 core abstraction traits (see below)
  forensics/
    mod.rs                      -- re-exports
    types.rs                    -- MerkleLedgerEntry, DeploymentContext, BlastRadiusReport, TimelineEvent, ProvenanceSnapshot, ActiveArtifact, RevokeRequest, RevokeResult, CoResidentArtifact, AffectedNodeDetail, TimeRange, LedgerEntryRef
    ledger.rs                   -- MerkleLedger (RwLock thread-safe append-only chain), MerkleLedgerStore trait, InMemoryLedgerStore, compute_ledger_entry_hash, verify_integrity, consistency_proof
    index.rs                    -- LedgerIndex (5 BTreeMap indexes: by_hash, by_node, by_namespace, by_time, by_binary)
    query.rs                    -- blast_radius, timeline, provenance, compute_evidence_hash
  global.rs                     -- GlobalStateRoot, ClusterRootEntry, ClusterStatus, ClusterRootReport, ArtifactDelta, ArtifactLocation, GlobalBlastRadiusReport, ClusterBlastRadius, NodeBlastRadius, compute_cluster_root, compute_global_root, GlobalStateClient trait, MockGlobalStateClient
  collectors/
    traits.rs                   -- LayerCollector trait (async fn collect -> LayerSignature)
    mock.rs                     -- MockCollector
    nix.rs                      -- hash_closure, NixCollector
    oci.rs                      -- hash_manifest, OciCollector
    helm.rs                     -- hash_chart_dir, hash_rendered_chart, RenderedHelmCollector
    kubernetes.rs               -- hash_manifests, KubernetesCollector
    tofu.rs                     -- hash_state, TofuCollector
    kindling.rs                 -- hash_identity, KindlingCollector
    tatara.rs                   -- hash_allocation, TataraCollector
    akeyless.rs                 -- LiveAkeylessCollector
    akeyless_target.rs          -- AkeylessTargetCollector, LiveAkeylessTargetCollector (30 target types)
    fluxcd.rs                   -- FluxCDCollector
    argocd.rs                   -- ArgoCDCollector
    generic.rs                  -- GenericCollector
    pangea.rs                   -- PangeaSynthesisCollector, hash_synthesis_json, hash_synthesis_file
    rspec.rs                    -- RSpecResultCollector, hash_rspec_output
    inspec_result.rs            -- InSpecResultCollector, hash_inspec_output
    mod.rs                      -- re-exports
  compliance/
    mod.rs                      -- re-exports
    nist.rs                     -- NIST 800-53 control mapping
    oscal.rs                    -- OSCAL output generation
    cis.rs                      -- CIS Kubernetes Benchmark
    cve.rs                      -- CVE ingestion and tracking
    sbom.rs                     -- SBOM hash attestation
    slsa.rs                     -- SLSA provenance levels
    inspec.rs                   -- InSpec profile integration
    frameworks.rs               -- Framework registry
    standards.rs                -- Standards enumeration
    dimensions.rs               -- Compliance dimensions
    result.rs                   -- Compliance result types
    akeyless.rs                 -- Akeyless secret attestation
    akeyless_target.rs          -- AkeylessTargetAttestation, AkeylessTargetType (30 variants), ProducerAssociation, compute_target_attestation_hash, compute_multi_target_hash
spec/
  openapi.yaml                  -- OpenAPI 3.0.3 spec (sekiban + kensa + tameshi endpoints)
```

## All Traits

### Core Abstraction Traits (traits.rs)

| Trait | Methods | Real Impl | Mock Impl | Purpose |
|-------|---------|-----------|-----------|---------|
| `CommandRunner` | `run()`, `run_in_dir()`, `run_raw()` | `SystemCommandRunner` | `MockCommandRunner` | Subprocess execution |
| `FileSystem` | `read_file()`, `read_dir()`, `file_exists()`, `file_metadata()` | `RealFileSystem` | `MockFileSystem` | File I/O |
| `HttpClient` | `get()`, `post()`, `put()`, `delete()` | `ReqwestHttpClient` | `MockHttpClient` | Network requests |
| `Clock` | `now()` | `SystemClock` | `FixedClock` | Wall-clock time |
| `SignatureVerifier` | `verify()`, `verify_master()` | `DefaultVerifier` | `MockVerifier` | Signature verification |
| `GatingEngine` | `evaluate()`, `evaluate_with_policy()` | `DefaultGatingEngine` | `MockGatingEngine` | Gate decisions |
| `MetricsRecorder` | `increment()`, `gauge()`, `histogram()` | (prometheus) | `NoopMetrics` | Telemetry |
| `Store<T>` | `get()`, `put()`, `delete()`, `list()` | (disk) | `MemStore<T>` | Persistent storage |

### Domain Traits

| Trait | Module | Methods | Purpose |
|-------|--------|---------|---------|
| `LayerCollector` | `collectors/traits.rs` | `collect() -> LayerSignature`, `layer_type() -> LayerType` | Infrastructure layer hashing |
| `AttestationHasher` | `hash.rs` | `hash()`, `hash_file()`, `combine()`, `to_hex()`, `from_hex()` | Pluggable hash algorithms |
| `MerkleRootSigner` | `signing.rs` | `sign(root) -> SignedRoot`, `verify(signed) -> bool` | Merkle root signing |
| `ComplianceQuery` | `compliance_api.rs` | `state() -> ComplianceState`, `distance()`, `certification_status()` | Compliance queries |
| `HeartbeatEmitter` | `heartbeat.rs` | `emit_chain()`, `emit_entry()` | Audit trail persistence |
| `IacTestAttester` | `iac_attestation.rs` | `attest_phase()`, `attest_suite() -> Blake3Hash` | IaC test attestation |
| `ConfigLoader` | `config.rs` | `load()`, `reload()` | Configuration management |
| `MerkleLedgerStore` | `forensics/ledger.rs` | `append()`, `entries()`, `verify_integrity()` | Persistent forensic ledger |
| `GlobalStateClient` | `global.rs` | `report_root()`, `get_global_state()`, `get_blast_radius()` | Master server communication |
| `ForensicsWriter` | `forensics/ledger.rs` | `write_entry()`, `flush()` | Forensic ledger write abstraction |

## Key Types

### Hashing

- **`Blake3Hash([u8; 32])`** -- Primary hash. `digest()`, `combine()`, `from_hex()`, `to_hex()`, `to_prefixed()`, `from_prefixed()`. Implements `Serialize`, `Deserialize`, `Hash`, `Eq`, `FromStr`, `schemars::JsonSchema`.
- **`Sha256Hash([u8; 32])`** -- SHA-256 for FIPS 140-3 compliance. Same API surface.
- **`Blake3Hasher`** / **`Sha256Hasher`** -- `AttestationHasher` trait implementations.

### Layer Signatures

- **`LayerType`** -- enum with 14 variants: `Nix`, `Oci`, `Helm`, `Tofu`, `Kubernetes`, `Kindling`, `Tatara`, `FluxCD`, `ArgoCD`, `Akeyless`, `AkeylessTarget`, `PangeaSynthesis`, `RSpecResult`, `InSpecResult`. All derive `Serialize`, `Deserialize`, `JsonSchema`, `Ord`.
- **`LayerSignature`** -- layer type + BLAKE3 hash + metadata + input hashes. The atomic unit of attestation.
- **`InputHash`** -- named sub-hash within a layer (e.g., per-resource within a Helm chart).
- **`MasterSignature`** -- composite: untested hash (Merkle root of layers) + compliance hash + secure hash (both combined).

### Certification Artifact (Pillar 1)

- **`CertificationArtifact`** -- Binds 3 sources into a single cryptographic commitment:
  - Leaf 0: `artifact_hash` (Nix derivation hash or OCI digest)
  - Leaf 1: `control_hash` (kensa compliance assessment hash)
  - Leaf 2: `intent_hash` (Pangea synthesis output hash)
  - Result: `composed_root` (3-leaf Merkle tree root with RFC 9162 domain separation)
  - Method: `binary_hash()` returns the composed root for BPF map population
- **`ArtifactProofPaths`** -- Inclusion proofs for each of the 3 leaves.
- **`compose_certification_artifact()`** -- Constructs the artifact and all proofs.
- **`verify_certification_artifact()`** -- Recomputes the Merkle root from inputs and verifies match.
- **`verify_proof_path()`** -- Verifies a single leaf's inclusion proof against the root.

### Signing (Pillar 2)

- **`SignedRoot`** -- root hash + signature bytes + algorithm + signer ID + timestamp.
- **`SigningAlgorithm`** -- enum: `Ed25519Local`, `AkeylessDfc { key_name }`, `MockDfc`, `BreakGlass`.
- **`LocalSigner`** -- real public-key **Ed25519** (ed25519-dalek), seed-derived + deterministic (RFC 8032). `verifying_key()` is the 32-byte public key; the free function `verify_signed_root(signed, &pubkey)` verifies with **no secret** (`verify_strict`) — the property that lets mutually-untrusting peers verify each other's attestations. (Was a symmetric BLAKE3 keyed MAC before 2026-06-11; the `Ed25519Local` name is now truthful.) Development/testing.
- **`AkeylessDfcSigner`** -- Calls Akeyless gateway REST API for threshold signing. Key never exists in one piece. Supports mTLS via `TlsConfig`.
- **`MockDfcSigner`** -- Split-knowledge simulation. Two 32-byte fragments (`fragment_a`, `fragment_b`). Key = `BLAKE3(fragment_a XOR fragment_b)`. Neither fragment alone reveals the key. Debug output redacts fragments.
- **`BreakGlassToken`** -- Emergency bypass with cryptographic logging. Every break-glass event is signed and logged for the 72-hour CIRCIA report.

### Heartbeat Chain (Audit Trail)

- **`HeartbeatChain`** -- Thread-safe (`RwLock<HeartbeatChainInner>`) append-only chain. Methods: `append()`, `len()`, `is_empty()`, `verify_integrity()`, `entries()`, `entries_in_range()`, `entries_by_event()`, `consistency_proof()`.
- **`HeartbeatEntry`** -- sequence + timestamp + verifier + event + result + resource + signature_checked + entry_hash + previous_hash.
- **`HeartbeatEvent`** -- 14 variants: `AdmissionDecision`, `GateVerification`, `ComplianceAssessment`, `Certification`, `GateCheck`, `BinaryVerification`, `ScriptVerification`, `BreakGlass`, `Revocation`, `IacTestInit`, `IacTestApply`, `IacTestVerify`, `IacTestTeardown`, `IacTestSuiteComplete`.
- **`VerificationOutcome`** -- `Allowed`, `Denied`, `Skipped`, `Error`.
- **`VerifierIdentity`** -- component name + instance ID + version.
- **`ConsistencyProof`** -- CT-style proof between two chain states (from_seq, to_seq, proof_nodes).
- **`S3Emitter`** -- Persists chain to S3-compatible storage via `object_store`.

### IaC Test Attestation

- **`IacTestPhase`** -- enum: `Init`, `Apply`, `Verify`, `Teardown`.
- **`IacTestPhaseResult`** -- phase + success + output_hash + duration_ms + completed_at + details.
- **`IacTestSuiteReport`** -- suite_name + platform + environment + phases + all_passed + suite_hash + completed_at. `compute_suite_hash()` produces composite BLAKE3 from phase hashes. `verify_passed()` checks the Verify phase specifically. `suite_hash` can feed directly into `compose_certification_artifact()` as the `control_hash`.
- **`MockIacTestAttester`** -- Records phases and suites in `Mutex<Vec<_>>` for test assertions.

### Forensic Ledger

- **`MerkleLedger`** -- Thread-safe (`RwLock`) append-only BLAKE3-chained ledger. Records every `CertificationArtifact` deployment. Methods: `append()`, `append_with_clock()`, `verify_integrity()`, `len()`, `entries()`, `entries_in_range()`, `consistency_proof()`, `head_hash()`.
- **`MerkleLedgerEntry`** -- sequence + timestamp + certification_artifact + signed_root + deployment_context + entry_hash + previous_hash.
- **`DeploymentContext`** -- cluster + namespace + node + pod + container + image_ref + binary_paths + optional sdlc_chain_hash + optional compliance_report_hash.
- **`MerkleLedgerStore`** trait -- pluggable persistence for the ledger. `InMemoryLedgerStore` for testing.
- **`LedgerIndex`** -- 5 BTreeMap indexes over ledger entries (by_hash, by_node, by_namespace, by_time, by_binary). Methods: `insert()`, `query_by_hash()`, `query_by_node()`, `query_by_namespace()`, `query_by_time_range()`, `query_by_binary()`.
- **`blast_radius()`** -- Given a compromised hash + time range, returns `BlastRadiusReport` with affected nodes, co-resident artifacts, chain integrity check, and deterministic evidence hash.
- **`timeline()`** -- Chronological reconstruction of events for a hash, optionally filtered by node.
- **`provenance()`** -- Point-in-time snapshot of active artifacts on a node.
- **`compute_evidence_hash()`** -- Deterministic BLAKE3 hash of a `BlastRadiusReport`.
- **`BlastRadiusReport`** -- query_hash + total_affected + time_range + affected_nodes + co_resident_artifacts + chain_integrity + evidence_hash.

### Global State

- **`GlobalStateRoot`** -- root_hash + cluster_roots (BTreeMap) + computed_at + sequence + previous_root.
- **`ClusterRootEntry`** -- cluster_id + cluster_root + signed_root + node_count + artifact_count + last_reported + status.
- **`ClusterStatus`** -- enum: `Active`, `Stale`, `Offline`, `Revoked`.
- **`compute_cluster_root()`** -- Deterministic BLAKE3 hash from sorted composed_root hashes.
- **`compute_global_root()`** -- Deterministic BLAKE3 hash from BTreeMap of cluster roots.
- **`GlobalStateClient`** trait -- async communication with master server. `MockGlobalStateClient` for testing.
- **`GlobalBlastRadiusReport`** -- Aggregates blast radius across all clusters.

### Collectors

| Collector | Layer Type | What It Hashes |
|-----------|-----------|----------------|
| `NixCollector` | `Nix` | Nix store closure (via `nix-store --query --requisites`) |
| `OciCollector` | `Oci` | OCI manifest digest (via `skopeo inspect`) |
| `RenderedHelmCollector` | `Helm` | Rendered Helm chart YAML (via `helm template`) |
| `TofuCollector` | `Tofu` | OpenTofu state file (via `tofu show -json`) |
| `KubernetesCollector` | `Kubernetes` | Kubernetes manifest set (via `kubectl get -o json`) |
| `KindlingCollector` | `Kindling` | Kindling identity document |
| `TataraCollector` | `Tatara` | Tatara cluster allocation state |
| `FluxCDCollector` | `FluxCD` | FluxCD reconciliation state |
| `ArgoCDCollector` | `ArgoCD` | ArgoCD application state |
| `LiveAkeylessCollector` | `Akeyless` | Akeyless secret metadata (hashes VALUES, never stores them) |
| `LiveAkeylessTargetCollector` | `AkeylessTarget` | 30 Akeyless target types with producer associations |
| `PangeaSynthesisCollector` | `PangeaSynthesis` | Pangea deterministic Terraform JSON |
| `RSpecResultCollector` | `RSpecResult` | RSpec JSON reporter output (per-example hashes) |
| `InSpecResultCollector` | `InSpecResult` | InSpec JSON reporter output (per-control hashes) |
| `MockCollector` | (any) | Configurable mock for testing |

### schemars Integration

All API-facing types derive `schemars::JsonSchema`: `Blake3Hash`, `LayerType`, `LayerSignature`, `MasterSignature`, `SignedRoot`, `SigningAlgorithm`, `CertificationArtifact`, `ArtifactProofPaths`, `HeartbeatEntry`, `HeartbeatEvent`, `VerificationOutcome`, `VerifierIdentity`, `ConsistencyProof`, `ComplianceState`, `ComplianceStatus`, `ComplianceDistance`, `FrameworkState`, `CertificationQueryStatus`, `DynamicComplianceCheck`, `CheckDefinition`, `GateDecision`, `CertificationStatus`, `AuditEntry`, `IacTestPhase`, `IacTestPhaseResult`, `IacTestSuiteReport`, `BreakGlassToken`, `MerkleLedgerEntry`, `DeploymentContext`, `BlastRadiusReport`, `TimelineEvent`, `ProvenanceSnapshot`, `ActiveArtifact`, `RevokeRequest`, `RevokeResult`, `CoResidentArtifact`, `AffectedNodeDetail`, `TimeRange`, `GlobalStateRoot`, `ClusterRootEntry`, `ClusterStatus`, `ClusterRootReport`, `ArtifactDelta`, `ArtifactLocation`, `GlobalBlastRadiusReport`, `ClusterBlastRadius`, `NodeBlastRadius`.

## Testing

```bash
cargo test                           # all 1427 tests
cargo test hash                      # hash module (42 tests)
cargo test merkle                    # merkle tree
cargo test signing                   # signing + MockDfcSigner + BreakGlassToken + FailableDfcSigner
cargo test certification_artifact    # 3-leaf Merkle artifact
cargo test heartbeat                 # heartbeat chain + consistency proofs
cargo test compliance_api            # compliance query types
cargo test iac_attestation           # IaC test attestation + integration
cargo test collectors::helm          # rendered Helm hashing
cargo test collectors::pangea        # Pangea synthesis hashing
cargo test collectors::rspec         # RSpec result hashing
cargo test collectors::inspec_result # InSpec result hashing
cargo test gating                    # gate policy evaluation
cargo test forensics                 # forensic ledger, index, query, blast radius
cargo test global                    # global state root, cluster root computation
cargo test --test forensics_integration  # e2e forensics + chaos tests (21 tests)
```

Mock types: `MockCollector`, `MockCommandRunner`, `MockFileSystem`, `MockHttpClient`, `MockGatingEngine`, `MockVerifier`, `MockIacTestAttester`, `MockDfcSigner`, `FailableDfcSigner` (chaos testing), `MockAkeylessClient`, `MockAkeylessGateway`, `MockGlobalStateClient`, `InMemoryLedgerStore`, `FixedClock`, `NoopMetrics`, `MemStore<T>`.

## Dependencies

| Crate | Purpose |
|-------|---------|
| blake3 | Primary hash (BLAKE3, 256-bit) |
| sha2 | SHA-256 for FIPS 140-3 compatibility |
| rs_merkle | Merkle tree construction + inclusion proofs |
| const-hex | Zero-allocation hex encode/decode |
| figment | Layered config (YAML + env vars) |
| chrono | Timestamps (DateTime<Utc>) |
| uuid | Unique identifiers |
| reqwest | HTTP client (OCI, Akeyless, S3) |
| object_store | S3-compatible storage (heartbeat persistence) |
| schemars | JSON Schema generation for API types |
| thiserror | Error type derivation |
| tracing | Structured logging |
| serde + serde_json | Serialization |
| tokio | Async runtime |
| tempfile | Test isolation (dev-dependency) |
| proptest | Property-based testing (dev-dependency) |

## Ecosystem

```
tameshi (this repo, 1427 tests)
     +---> sekiban  (K8s admission webhook, 315 tests)
     +---> kensa   (compliance engine, 377 tests)
     +---> inshou  (Nix gate CLI, 366 tests)
     +---> kanshi  (eBPF runtime sentinel, 130 tests)
     +---> inspec-rspec (InSpec->RSpec transpiler, 94 tests)
     +---> iac-test-runner (K8s IaC test orchestrator, 180 tests)
```

Total ecosystem test count: **2,789 tests**.

## Formal Verification

Three-layer verification strategy. See `docs/verification-strategy.md` for full details.

| Layer | Tool | Coverage | Run |
|-------|------|----------|-----|
| 1 | proptest (38 properties × 10k cases) | All 15 theorems + 7 corollaries | `nix run .#verify-proptest` |
| 2 | Kani (30 bounded model checking harnesses) | Crypto, concurrency, liveness, FFI, refinement | `nix run .#verify-kani` |
| 3 | F* (10 formal proof modules) | Thms 2.2, 3.1, 4.1, 7.1, 10.1, 11.1 + non-interference + refinement | `nix run .#verify-fstar` |

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/OVERVIEW.md` | **Start here.** Plain-language stakeholder guide: what it is, how it works, what we've proved, where doubts are addressed with real tests, and where to go deeper. |
| `docs/grand-unified-specification.md` | Grand Unified Specification: 7-level narrative from executive business case through data hierarchy, integration bridge, kernel enforcement, verification matrix, performance attestation, and sovereign integrity. |
| `docs/quick-start-guide.md` | Quick start for the Akeyless dev team: prerequisites, key files, common tasks, do-nots. Zero to verified in 5 minutes. |
| `docs/tameshi-technical-specification.md` | System architecture: CertificationArtifact → HeartbeatChain → BPF bridge → kanshi eBPF → verification matrix. Full top-down trace from Merkle root to CPU registers. |
| `docs/mathematical-foundations.md` | Formal mathematical proofs: 15 theorems, 7 corollaries, security reductions, complexity analysis. All Merkle tree properties, hash chain integrity, split-knowledge security, and ecosystem components derived as consequences. |
| `docs/verification-strategy.md` | Three-layer verification strategy: proptest (380k random checks), Kani (exhaustive bounded proofs), F* (unbounded formal proofs). Theorem coverage matrix, trust model explanation. |
| `docs/FORMAL_VERIFICATION_SUMMARY.md` | Board-level summary: regulatory alignment, full-stack refinement mapping, business impact. |
| `docs/unified-theory-of-infrastructure-proof.md` | Constructive proof with test evidence: 3,288 tests mapped to security properties, attack surface analysis, regulatory alignment (NIST 800-53, CIRCIA, SLSA, FedRAMP). |
| `docs/compliance-coverage-comparison.md` | Quantitative comparison: ~14,800 controls vs commercial platforms (AWS Security Hub, Prisma Cloud, Wiz, Chef Automate). |
