# tameshi -- Deterministic integrity attestation library

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering**. The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read it before non-trivial changes.


<!-- Blackmatter alignment: pillars 10 -->
<!-- See ~/code/github/pleme-io/BLACKMATTER.md for pillar definitions. -->

## Blackmatter pillars upheld

- **Pillar 10** (Proof discipline): Tameshi IS Pillar 10's cryptographic spine. Every artifact in the pleme-io platform hashes through a BLAKE3 Merkle tree rooted at tameshi. `Attested<T>` (arch-synthesizer) refuses to seal without a tameshi-verified proof; `sekiban` enforces at K8s admission; `kensa` enforces compliance; `inshou` gates Nix rebuilds. Cross-infra attestation chains compose here.

Core library for the Unified Theory of Infrastructure Proof. Provides cryptographic hash computation, Merkle tree composition, signature verification, compliance attestation, and tamper-evident audit trails across infrastructure layers. Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test          # 1834 tests (1712 lib + 122 across 6 integration files; counts include proptest, spec, doctests)
cargo test --no-default-features --features threshold   # the lean build: the threshold module alone
cargo test --no-default-features --features content-address   # ContentAddress alone (serde_json only)
cargo test --no-default-features --features merkle --test merkle_lean   # hash, merkle, sparse_merkle alone
cargo build --release
```

Features: `full` (default) is every module and the `tameshi` binary; `os-rng`
adds the threshold entry points that draw from the operating system
(`trusted_dealer`, `dkg::start`, `commit`); `threshold` is the threshold module
alone with randomness from the caller. `content-address` is `content_address::ContentAddress`
alone: BLAKE3 over one canonical JSON (keys sorted by byte order in a
`BTreeMap` tree, compact, `b3:` text); a failed `Serialize`, a non-finite
float, a non-string key or a duplicate key is refused, never hashed. Golden
vectors: `tests/content_address.rs`. `merkle` is the `hash`, `merkle` and
`sparse_merkle` modules alone (`Blake3Hash`, `compute_leaf_root`,
`leaf_inclusion_proof`, `verify_leaf_inclusion`, `SparseMerkleTree`); it links
blake3, rs_merkle, serde and const-hex, nothing else
(`tests/merkle_lean.rs`). `ed25519-dalek`, `zeroize` and `thiserror` are
optional: `full` and `threshold` link them, `content-address` links
`thiserror`. blue's runtime depends on
`default-features = false, features = ["threshold"]`, which links no tokio,
reqwest, object_store, axum, ring or getrandom.

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
  main.rs                       -- the `tameshi` CLI: receipt {run,write,verify,leaves,sign}, ledger {fold,prove,verify}, incident ingest
  hash.rs                       -- Blake3Hash (to_b3/from_b3, digest_fields), Sha256Hash, AttestationHasher trait, length_prefixed, blake3_tree, blake3_file, blake3_file_async
  signature.rs                  -- LayerType (14 variants), LayerSignature, MasterSignature, InputHash
  merkle.rs                     -- Blake3Algorithm (RFC 9162 domain separation), compute_leaf_root / leaf_inclusion_proof / verify_leaf_inclusion (the one tree every root uses), compose_merkle, compute_merkle_root, domain_separated_leaf
  receipt/
    mod.rs                      -- tameshi-receipt.v1: Receipt (strict parse, canonical bytes, digest, leaves), ReceiptParts, ControlId, B3, tuple_leaf (length-prefixed 5-field leaf)
    fragment.rs                 -- AttestationFragment: Ed25519 SignedRoot over a receipt's leaf root; KeyMode test | seed-file | threshold-shares; sign_fragment (one key), sign_fragment_with (any Ed25519Signer), sign_test_fragment + FragmentSettings (threshold.enabled, default on)
    runner.rs                   -- run_command (any argv, red recorded never raised, TAMESHI_FACTS), count_assertions (cargo/pytest/go/blue), receipt_from_run
  verify.rs                     -- verify_master, verify_untested, verify_secure, VerificationResult
  gating.rs                     -- GatingPolicy, evaluate_gate, evaluate_gate_with_clock
  changeset.rs                  -- CertifiedChangeset, hash_changeset
  certification.rs              -- ProductCertification builder (7-stage pipeline)
  certification_artifact.rs     -- CertificationArtifact (3-leaf Merkle: provenance + compliance + intent), ArtifactProofPaths, verify_certification_artifact, verify_proof_path
  signing.rs                    -- MerkleRootSigner + Ed25519Signer traits, LocalSigner (real public-key Ed25519 + verify_signed_root pubkey-only verify), RemoteFragmentSigner (Fragment threshold), MockFragmentSigner (split-knowledge XOR), BreakGlassToken, SignedRoot, SigningAlgorithm
  ed25519.rs                    -- verify_ed25519 (verify_strict), the one Ed25519 check signing.rs and threshold/ share; built with `full` or `threshold`
  threshold/                    -- feature `threshold`; the OS-randomness entry points need `os-rng`, party.rs needs `full`
    mod.rs                      -- FROST(Ed25519, SHA-512) k-of-n signing (RFC 9591, frost-ed25519): ThresholdParams, ParticipantId, KeyShare, GroupKey, ThresholdError; the group secret is never one scalar
    keygen.rs                   -- dkg::{start_with_rng, start, exchange, finish} (Pedersen DKG, no dealer), trusted_dealer_with_rng / trusted_dealer (test path), the public 2-of-3 test group; Round1Package / Round2Package to_bytes / from_bytes
    signing.rs                  -- commit_with_rng, commit, sign, aggregate; Commitment, SigningRequest (new, from_commitments), SignatureShare (typed round messages, serde and frost bytes)
    party.rs                    -- SigningParty, LocalParty, ThresholdSigner (a MerkleRootSigner), re-exported from signing
    audit.rs                    -- source guard: frost is named only through per-file allowlists, none holding keys::reconstruct, keys::split or SigningKey
    seeded.rs                   -- tests that run in the lean build: a seeded RNG deals, starts a DKG and commits the same way twice; frost-byte round trips
  shamir_fragment.rs            -- GF(256) Shamir split/reconstruct, ShamirFragmentSigner (RECONSTRUCTS the key in memory on every sign and verify; kept, not a default)
  heartbeat.rs                  -- HeartbeatChain (RwLock thread-safe), HeartbeatEntry, HeartbeatEvent (14 variants), VerificationOutcome, VerifierIdentity, ConsistencyProof, S3Emitter, HeartbeatEmitter trait
  compliance_api.rs             -- ComplianceQuery trait, ComplianceState, ComplianceStatus, ComplianceDistance, FrameworkState, CertificationQueryStatus, DynamicComplianceCheck, CheckDefinition
  iac_attestation.rs            -- IacTestAttester trait, IacTestPhase, IacTestPhaseResult, IacTestSuiteReport, MockIacTestAttester
  config.rs                     -- ConfigLoader trait, load_config (figment: defaults -> YAML -> env)
  api_types.rs                  -- GateDecision, CertificationStatus, AuditEntry (schemars::JsonSchema)
  reporting.rs                  -- EnvironmentReport, ComplianceSummary, DriftReport
  selftest.rs                   -- FrameworkAttestation, attest_framework, compute_framework_hash, framework_nist_controls
  alerts.rs                     -- AlertSeverity, AlertTarget, AlertMessage
  ci.rs                         -- CI/CD helpers, secrets_manager_attestation
  error.rs                      -- TameshiError (8 variants)
  cache.rs                      -- CacheEntry, CacheStore
  canonicalize.rs               -- CanonicalMode, Canonicalizer, JsonCanonicalizer, RawCanonicalizer, YamlCanonicalizer, canonical_hash, canonicalizer_for
  testing.rs                    -- testing utilities, MockSecretsGateway
  traits.rs                     -- 10 core abstraction traits (see below)
  forensics/
    mod.rs                      -- re-exports
    types.rs                    -- MerkleLedgerEntry, DeploymentContext, BlastRadiusReport, TimelineEvent, ProvenanceSnapshot, ActiveArtifact, RevokeRequest, RevokeResult, CoResidentArtifact, AffectedNodeDetail, TimeRange, LedgerEntryRef
    ledger.rs                   -- MerkleLedger (RwLock thread-safe append-only chain), MerkleLedgerStore trait, InMemoryLedgerStore, compute_ledger_entry_hash, verify_integrity, consistency_proof
    index.rs                    -- LedgerIndex (5 BTreeMap indexes: by_hash, by_node, by_namespace, by_time, by_binary)
    query.rs                    -- blast_radius, timeline, provenance, compute_evidence_hash
    evidence.rs                 -- EvidenceLedger (Attested Verification Tuple leaves, evidence held and recomputed on read), InclusionProof (tameshi-inclusion.v1)
    bluecrash.rs                -- BlueCrash (.bluecrash as IR-4/5/6 incident evidence), IncidentBlastRadius
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
    secrets_manager.rs          -- LiveSecretsManagerCollector
    secret_target.rs            -- SecretTargetCollector, LiveSecretTargetCollector (30 target types)
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
    secrets.rs                  -- secrets-manager secret attestation
    secret_target.rs            -- SecretTargetAttestation, SecretTargetType (30 variants), ProducerAssociation, compute_target_attestation_hash, compute_multi_target_hash
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

## Attested Verification Tuples (receipts)

A receipt (`tameshi-receipt.v1`, canonical JSON) records one test run in one
sandbox. `ReceiptDigest = BLAKE3(canonical bytes)`. Each control gets one leaf:
`BLAKE3(lp(ControlID) ‖ lp(TargetHash) ‖ lp(TestHash) ‖ lp(ReceiptDigest) ‖ lp(NixDerivationHash))`,
where `lp` is a u32 big-endian length and the UTF-8 bytes. The hashes are the
`b3:<hex>` strings, and `NixDerivationHash` is `sandbox.derivation` verbatim.
Leaves fold into `EvidenceLedger`. Its root and proofs are `merkle::compute_leaf_root`
and `leaf_inclusion_proof`, the same domain-separated `rs_merkle` tree as
`CertificationArtifact`.

The forensic `MerkleLedger` is a hash chain of deployment entries. It has no
per-leaf inclusion proofs, so receipts do not fold into it.

Nix: `tameshi.lib.wrapTest { name, command, controls, target, test, src ? null, nativeBuildInputs ? [], env ? {}, threshold ? true, system ? currentSystem }`
(also `pkgs.tameshi.wrapTest` through `overlays.default`). It runs the command
in one derivation (`<name>-run`). A red test never fails the build. Then
`tameshi receipt write` writes `$out/tameshi-receipt.v1.json` and
`$out/tameshi-fragment.v1.json`, signed with public test key material: no secret
enters a sandbox. By default the public FROST 2-of-3 test group signs
(`frost_ed25519:2-of-3`, nonces derived from the root so the fragment is
reproducible). `threshold = false`, `TAMESHI_FRAGMENT_THRESHOLD__ENABLED=false`
or `threshold: {enabled: false}` in `~/.config/tameshi/fragment.yaml` switches
it to the single public test key (`ed25519_local`). Both have `key_mode: test`.
A real single key signs later with `tameshi receipt sign --seed-file`, which
refuses a seed under `/nix/store`; a real threshold group signs through the
library (`sign_fragment_with(receipt, &ThresholdSigner, KeyMode::ThresholdShares)`).
`sandbox.network` is measured with a UDP route probe that sends no packet. On a
darwin host with `sandbox = false`, it reads `true`. Checks:
`receipt-{pass,fail,single-key}`, `receipt-{pass,fail,incident}-proof`.

## Key Types

### Hashing

- **`Blake3Hash([u8; 32])`** -- Primary hash. `digest()`, `combine()`, `from_hex()`, `to_hex()`, `to_prefixed()`, `from_prefixed()`. Implements `Serialize`, `Deserialize`, `Hash`, `Eq`, `FromStr`, `schemars::JsonSchema`.
- **`Sha256Hash([u8; 32])`** -- SHA-256 for FIPS 140-3 compliance. Same API surface.
- **`Blake3Hasher`** / **`Sha256Hasher`** -- `AttestationHasher` trait implementations.

### Layer Signatures

- **`LayerType`** -- enum with 14 variants: `Nix`, `Oci`, `Helm`, `Tofu`, `Kubernetes`, `Kindling`, `Tatara`, `FluxCD`, `ArgoCD`, `SecretsManager`, `SecretTarget`, `PangeaSynthesis`, `RSpecResult`, `InSpecResult`. All derive `Serialize`, `Deserialize`, `JsonSchema`, `Ord`.
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
- **`SigningAlgorithm`** -- enum: `Ed25519Local`, `RemoteFragment { key_name }`, `MockFragment`, `BreakGlass`, `FrostEd25519 { min_signers, max_signers }`. `is_ed25519()` is true for `Ed25519Local` and `FrostEd25519`: both are RFC 8032 signatures, and `verify_signed_root` accepts exactly those two.
- **`LocalSigner`** -- real public-key **Ed25519** (ed25519-dalek), seed-derived + deterministic (RFC 8032). `verifying_key()` is the 32-byte public key; the free function `verify_signed_root(signed, &pubkey)` verifies with **no secret** (`verify_strict`) — the property that lets mutually-untrusting peers verify each other's attestations. (Was a symmetric BLAKE3 keyed MAC before 2026-06-11; the `Ed25519Local` name is now truthful.) Development/testing.
- **`RemoteFragmentSigner`** -- Calls secrets-manager gateway REST API for threshold signing. Key never exists in one piece. Supports mTLS via `TlsConfig`.
- **`ThresholdSigner<P: SigningParty>`** -- `k`-of-`n` FROST(Ed25519, SHA-512) (RFC 9591, `frost-ed25519` 3.x, wrapped in `src/threshold/`). Keys come from `keygen::dkg` (no party or dealer ever holds the group secret) or `keygen::trusted_dealer` (test path). Signing is two rounds: each party `commit`s, the coordinator builds a `SigningRequest` from at least `k` commitments (fewer is `BelowThreshold`), each party `sign`s (consumes its nonces), `aggregate` adds the signature shares and refuses a forged one naming its participant (`InvalidShares`). The result is an ordinary Ed25519 signature under `GroupKey::verifying_key()`: ed25519-dalek, `verify_signed_root` and `verify_fragment` accept it. `LocalParty` keeps a share in this process; implement `SigningParty` over a transport to keep each share on its own machine. `ThresholdSigner::public_test()` is the public 2-of-3 test group. The `threshold::audit` tests read the module source and fail if it names `keys::reconstruct`, `keys::split` or `SigningKey`. Every randomness-drawing step has a `_with_rng` form taking any `rand_core::CryptoRngCore` (`keygen::trusted_dealer_with_rng`, `keygen::dkg::start_with_rng`, `signing::commit_with_rng`), and every round message reads and writes frost's own bytes (`to_bytes` / `from_bytes`), so blue's runtime (`crates/blue-lang-runtime/src/threshold.rs`) runs its seeded provider on this one implementation.
- **`ShamirFragmentSigner`** -- GF(256) Shamir `k`-of-`n` shares, but `sign` and `verify` **reconstruct the whole key in memory** and MAC with BLAKE3 (tagged `MockFragment`). Kept (behaviour is configured off, never deleted); no default selects it. Use `ThresholdSigner` where the key must never exist in one piece.
- **`MockFragmentSigner`** -- Split-knowledge simulation. Two 32-byte fragments (`fragment_a`, `fragment_b`). Key = `BLAKE3(fragment_a XOR fragment_b)`. Neither fragment alone reveals the key. Debug output redacts fragments.
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
| `LiveSecretsManagerCollector` | `SecretsManager` | Secrets-manager secret metadata (hashes VALUES, never stores them) |
| `LiveSecretTargetCollector` | `SecretTarget` | 30 secrets-manager target types with producer associations |
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
cargo test signing                   # signing + MockFragmentSigner + BreakGlassToken + FailableFragmentSigner
cargo test threshold                 # FROST DKG, two-round signing, k-1 refusal, forged shares, source audit
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

Mock types: `MockCollector`, `MockCommandRunner`, `MockFileSystem`, `MockHttpClient`, `MockGatingEngine`, `MockVerifier`, `MockIacTestAttester`, `MockFragmentSigner`, `FailableFragmentSigner` (chaos testing), `MockSecretsManagerClient`, `MockSecretsGateway`, `MockGlobalStateClient`, `InMemoryLedgerStore`, `FixedClock`, `NoopMetrics`, `MemStore<T>`.

## Dependencies

| Crate | Purpose |
|-------|---------|
| blake3 | Primary hash (BLAKE3, 256-bit) |
| ed25519-dalek | Ed25519 signing and strict verification |
| frost-ed25519 | FROST(Ed25519, SHA-512) threshold signing, RFC 9591 (only `src/threshold/` names it) |
| rand_core | Operating-system randomness (`OsRng`) for DKG and nonces |
| zeroize | `Zeroizing` buffer for a serialized key share |
| sha2 | SHA-256 for FIPS 140-3 compatibility |
| rs_merkle | Merkle tree construction + inclusion proofs |
| const-hex | Zero-allocation hex encode/decode |
| figment | Layered config (YAML + env vars) |
| chrono | Timestamps (DateTime<Utc>) |
| uuid | Unique identifiers |
| reqwest | HTTP client (OCI, the secrets manager, S3) |
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
| `docs/quick-start-guide.md` | Quick start for an integrating team: prerequisites, key files, common tasks, do-nots. Zero to verified in 5 minutes. |
| `docs/tameshi-technical-specification.md` | System architecture: CertificationArtifact → HeartbeatChain → BPF bridge → kanshi eBPF → verification matrix. Full top-down trace from Merkle root to CPU registers. |
| `docs/mathematical-foundations.md` | Formal mathematical proofs: 15 theorems, 7 corollaries, security reductions, complexity analysis. All Merkle tree properties, hash chain integrity, split-knowledge security, and ecosystem components derived as consequences. |
| `docs/verification-strategy.md` | Three-layer verification strategy: proptest (380k random checks), Kani (exhaustive bounded proofs), F* (unbounded formal proofs). Theorem coverage matrix, trust model explanation. |
| `docs/FORMAL_VERIFICATION_SUMMARY.md` | Board-level summary: regulatory alignment, full-stack refinement mapping, business impact. |
| `docs/unified-theory-of-infrastructure-proof.md` | Constructive proof with test evidence: 3,288 tests mapped to security properties, attack surface analysis, regulatory alignment (NIST 800-53, CIRCIA, SLSA, FedRAMP). |
| `docs/compliance-coverage-comparison.md` | Quantitative comparison: ~14,800 controls vs commercial platforms (AWS Security Hub, Prisma Cloud, Wiz, Chef Automate). |
