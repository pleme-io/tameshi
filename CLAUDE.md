# tameshi -- Deterministic integrity attestation library

Core library for cryptographic hash computation, Merkle tree composition, and signature verification across infrastructure layers (Nix, OCI, Helm, K8s, etc.). Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test          # 564+ tests (518 lib + 22 e2e + 15 proptest + 9 doc)
cargo build --release
```

## OpenAPI-First Development Flow

tameshi uses an **OpenAPI-first** approach. The spec is the single source of truth for all API surfaces.

```
spec/openapi.yaml                ← single source of truth
       │
       ├── forge-gen generate    ← auto-generates:
       │     ├── MCP server      (mcp-forge → Rust rmcp 0.15)
       │     ├── SDKs            (Go, Python, TypeScript)
       │     ├── Shell completions (skim-tab, fish)
       │     └── Documentation   (Markdown)
       │
       ├── src/api_types.rs      ← hand-written types matching spec schemas
       ├── sekiban/src/api/       ← hand-written axum handlers conforming to spec
       └── kensa/src/api/         ← hand-written axum handlers conforming to spec
```

### Workflow: Adding a New API Endpoint

1. **Define in spec first**: Add the endpoint to `spec/openapi.yaml` with path, request/response schemas, operationId
2. **Add Rust types**: Create matching serde types in the appropriate `api_types.rs` or handler module
3. **Implement handler**: Write the axum handler in the consuming service (sekiban or kensa)
4. **Regenerate**: Run `forge-gen generate --spec spec/openapi.yaml --mcp mcp-rust --mcp-name tameshi`
5. **Test**: Ensure handler types match spec schemas via serde roundtrip tests

### forge-gen.toml

```toml
[spec]
path = "spec/openapi.yaml"

[output]
dir = "generated"

[mcp]
targets = ["mcp-rust"]
name = "tameshi"

[completions]
targets = ["skim-tab", "fish"]
name = "tameshi"

[docs]
targets = ["markdown"]
```

### API Exposure Pattern

The same OpenAPI spec drives three transport layers:
- **REST** (axum) — primary, hand-implemented handlers
- **GraphQL** (async-graphql) — derived from same types
- **gRPC** (tonic/prost) — optional, from `.proto` generated alongside spec

All three share the same central data structures from `api_types.rs` and `compliance_api.rs`.

## Architecture

```
src/
  lib.rs                 -- module declarations + prelude
  hash.rs                -- Blake3Hash, Sha256Hash, AttestationHasher trait
  signature.rs           -- LayerType, LayerSignature, MasterSignature, InputHash
  merkle.rs              -- Merkle tree (rs_merkle), compose_merkle, proofs
  verify.rs              -- verify_master, verify_untested, verify_secure
  gating.rs              -- GatingPolicy, evaluate_gate
  changeset.rs           -- CertifiedChangeset, hash_changeset
  certification.rs       -- ProductCertification builder (7-stage pipeline)
  signing.rs             -- MerkleRootSigner trait, LocalSigner, AkeylessDfcSigner
  heartbeat.rs           -- HeartbeatChain, ConsistencyProof, S3Emitter, HeartbeatEmitter trait
  compliance_api.rs      -- ComplianceQuery trait, ComplianceState, DynamicComplianceCheck
  compliance/            -- NIST, OSCAL, CIS, CVE, SBOM, SLSA, InSpec, frameworks
  collectors/
    traits.rs            -- LayerCollector trait
    mock.rs              -- MockCollector
    nix.rs, oci.rs       -- Nix/OCI collectors
    helm.rs              -- hash_chart_dir, hash_rendered_chart, RenderedHelmCollector
    kubernetes.rs, tofu.rs, kindling.rs, tatara.rs, akeyless.rs, akeyless_target.rs
  akeyless_client.rs     -- AkeylessClient trait, HttpAkeylessClient, TlsConfig, mTLS wiring
  config.rs              -- load_config (figment: defaults -> YAML -> env)
  api_types.rs           -- GateDecision, CertificationStatus, AuditEntry
  reporting.rs           -- EnvironmentReport, ComplianceSummary, DriftReport
  selftest.rs            -- FrameworkAttestation, framework_nist_controls
  alerts.rs, ci.rs       -- alert types, CI/CD helpers
  error.rs               -- TameshiError
  cache.rs, canonicalize.rs, testing.rs, traits.rs
spec/
  openapi.yaml           -- OpenAPI 3.0.3 spec (sekiban + kensa endpoints)
```

## Key Traits

### `LayerCollector` (collectors/traits.rs)
- `async fn collect(&self) -> Result<LayerSignature>`
- `fn layer_type(&self) -> LayerType`
- Mock: `MockCollector::new(LayerType)`, `.set_result(Result<LayerSignature>)`

### `AttestationHasher` (hash.rs)
- `fn hash(data: &[u8]) -> Self::Output`
- `fn hash_file(path: &Path) -> Result<Self::Output>`
- `fn combine(a: &Self::Output, b: &Self::Output) -> Self::Output`
- Impl: `Blake3Hasher`, `Sha256Hasher`

### `MerkleRootSigner` (signing.rs)
- `async fn sign(&self, root: &Blake3Hash) -> Result<SignedRoot>`
- `async fn verify(&self, signed: &SignedRoot) -> Result<bool>`
- Impl: `LocalSigner` (Ed25519), `AkeylessDfcSigner` (DFC threshold signing)

### `ComplianceQuery` (compliance_api.rs)
- `async fn state(&self) -> Result<ComplianceState>`
- `async fn distance(&self, baseline, framework) -> Result<ComplianceDistance>`
- `async fn certification_status(&self) -> Result<CertificationQueryStatus>`

### `HeartbeatEmitter` (heartbeat.rs)
- `async fn emit_chain(&self, chain) -> Result<String>`
- `async fn emit_entry(&self, entry) -> Result<String>`
- Impl: `S3Emitter`

## Types

- **`Blake3Hash([u8; 32])`** -- primary hash. `digest()`, `combine()`, `from_hex()`, `to_prefixed()`
- **`LayerType`** -- enum: Nix, Oci, Helm, Tofu, Kubernetes, Kindling, Tatara, FluxCD, ArgoCD, Akeyless, AkeylessTarget
- **`LayerSignature`** -- layer + hash + metadata + inputs
- **`MasterSignature`** -- untested + compliance + secure hashes
- **`SignedRoot`** -- root + signature + algorithm + provenance
- **`HeartbeatEntry`** -- append-only chain entry with BLAKE3 linkage
- **`ConsistencyProof`** -- CT-style proof between chain states
- **`ComplianceState`** -- current compliance status, distance, frameworks
- **`DynamicComplianceCheck`** -- runtime check definition (binary revocation, config assertion, CVE, custom)

## Testing

```bash
cargo test                    # all tests
cargo test hash               # hash module
cargo test merkle             # merkle tree
cargo test gating             # gate policy
cargo test certification      # product certification
cargo test heartbeat          # heartbeat chain + consistency proofs
cargo test compliance_api     # compliance query types
cargo test collectors::helm   # helm rendered hashing
```

Mock types: `MockCollector`, `MockCommandRunner`, `MockFileSystem`, `MockHttpClient`, `MockGatingEngine`, `MockVerifier`, `FixedClock`.

## Dependencies

| Crate | Purpose |
|-------|---------|
| blake3 | Primary hash (BLAKE3) |
| sha2 | SHA-256 compatibility |
| rs_merkle | Merkle tree construction + proofs |
| const-hex | Hex encode/decode |
| figment | Layered config (YAML + env) |
| chrono | Timestamps |
| uuid | Identifiers |
| reqwest | HTTP client (OCI, Akeyless, S3) |
| thiserror | Error types |
| tracing | Structured logging |
