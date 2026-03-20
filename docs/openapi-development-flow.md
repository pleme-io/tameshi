# OpenAPI-First Development Flow

## Overview

The tameshi attestation platform uses an **OpenAPI-first** approach where the API specification (`spec/openapi.yaml`) is the single source of truth for all API surfaces. All data structures, endpoints, and protocol bindings are derived from or validated against this specification.

## Pipeline

```
                     spec/openapi.yaml
                           │
              ┌────────────┼────────────────┐
              │            │                │
              ▼            ▼                ▼
        forge-gen     Hand-written      Proto generation
        (auto-gen)    Rust handlers     (optional gRPC)
              │            │                │
    ┌─────────┤       src/api/          proto/*.proto
    │         │     (axum handlers)
    │         │
    ▼         ▼
MCP server  SDKs, Docs, Completions
(Rust rmcp) (Go, Python, TS, Markdown)
```

## Spec → Central Data Structures

The OpenAPI spec defines schemas that map directly to Rust types:

| Spec Schema | Rust Type | Location |
|------------|-----------|----------|
| `Blake3Hash` | `hash::Blake3Hash` | `src/hash.rs` |
| `LayerType` | `signature::LayerType` | `src/signature.rs` |
| `LayerSignature` | `signature::LayerSignature` | `src/signature.rs` |
| `MasterSignature` | `signature::MasterSignature` | `src/signature.rs` |
| `HeartbeatEntry` | `heartbeat::HeartbeatEntry` | `src/heartbeat.rs` |
| `ConsistencyProof` | `heartbeat::ConsistencyProof` | `src/heartbeat.rs` |
| `SignedRoot` | `signing::SignedRoot` | `src/signing.rs` |
| `ComplianceState` | `compliance_api::ComplianceState` | `src/compliance_api.rs` |
| `ComplianceDistance` | `compliance_api::ComplianceDistance` | `src/compliance_api.rs` |
| `GateSummary` | sekiban API type | `sekiban/src/api/rest.rs` |
| `CertificationSummary` | sekiban API type | `sekiban/src/api/rest.rs` |
| `ResultSummary` | kensa API type | `kensa/src/api/rest.rs` |
| `CertifyRequest` | kensa API type | `kensa/src/certification.rs` |

All Rust types derive `Serialize`/`Deserialize` with serde, ensuring JSON schema compatibility with the OpenAPI definitions.

## Central Data Structures → Generic API Exposure

The same central types power three transport layers:

### REST (axum)
```rust
// src/api/rest.rs — primary implementation
use axum::{Json, Router, routing::get};

async fn list_gates(State(state): State<AppState>) -> Json<Vec<GateSummary>> {
    // GateSummary matches the OpenAPI GateSummary schema
}
```

### GraphQL (async-graphql)
```rust
// src/api/graphql.rs — query resolvers use the same types
#[Object]
impl QueryRoot {
    async fn gates(&self, ctx: &Context<'_>) -> Vec<GateSummary> {
        // Same GateSummary type, different transport
    }
}
```

### gRPC (tonic/prost)
```rust
// Proto messages map 1:1 to the OpenAPI schemas
// proto/tameshi.proto generated from spec
// Rust types implement From<ProtoType> for seamless conversion
```

## Auto-Generation via forge-gen

### Running Generation

```bash
# Generate MCP server + shell completions + docs
forge-gen generate \
  --spec spec/openapi.yaml \
  --mcp mcp-rust --mcp-name tameshi \
  --completions skim-tab,fish --completion-name tameshi \
  --docs markdown

# Or use the manifest
forge-gen generate --manifest forge-gen.toml
```

### What Gets Generated

| Target | Output | Purpose |
|--------|--------|---------|
| `mcp-rust` | `generated/src/` | MCP server with rmcp 0.15, one tool per operationId |
| `skim-tab` | `generated/tameshi.yaml` | skim-tab fuzzy completion spec |
| `fish` | `generated/tameshi.fish` | Fish shell completions |
| `markdown` | `generated/docs/` | API reference documentation |

### Generated MCP Server

mcp-forge produces a complete Rust project:
- `src/api/types.rs` — serde structs matching spec schemas (with `schemars::JsonSchema`)
- `src/client.rs` — typed HTTP client for all endpoints
- `src/mcp.rs` — MCP tools with `#[tool_router]` / `#[tool_handler]`
- `src/format.rs` — text formatters for each response type
- `Cargo.toml`, `flake.nix`, `module/default.nix` — full Nix packaging

## Adding a New Endpoint

### Step 1: Define in OpenAPI Spec

```yaml
# spec/openapi.yaml
paths:
  /api/v1/heartbeat/consistency-proof:
    get:
      operationId: getConsistencyProof
      summary: Get consistency proof between chain states
      tags: [heartbeat]
      parameters:
        - name: from_seq
          in: query
          required: true
          schema:
            type: integer
        - name: to_seq
          in: query
          required: true
          schema:
            type: integer
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ConsistencyProof"

components:
  schemas:
    ConsistencyProof:
      type: object
      required: [from_seq, to_seq, from_hash, to_hash, proof_nodes]
      properties:
        from_seq:
          type: integer
        to_seq:
          type: integer
        from_hash:
          $ref: "#/components/schemas/Blake3Hash"
        to_hash:
          $ref: "#/components/schemas/Blake3Hash"
        proof_nodes:
          type: array
          items:
            $ref: "#/components/schemas/Blake3Hash"
```

### Step 2: Create Rust Types

```rust
// src/heartbeat.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub from_seq: u64,
    pub to_seq: u64,
    pub from_hash: Blake3Hash,
    pub to_hash: Blake3Hash,
    pub proof_nodes: Vec<Blake3Hash>,
}
```

### Step 3: Implement Handler

```rust
// In the consuming service (sekiban or kensa)
async fn get_consistency_proof(
    State(state): State<AppState>,
    Query(params): Query<ConsistencyProofQuery>,
) -> Result<Json<ConsistencyProof>, ApiError> {
    let proof = state.heartbeat_chain.consistency_proof(params.from_seq, params.to_seq)?;
    Ok(Json(proof))
}
```

### Step 4: Regenerate

```bash
forge-gen generate --manifest forge-gen.toml
```

### Step 5: Validate

- Serde roundtrip tests ensure Rust types match spec schemas
- `forge-gen validate --spec spec/openapi.yaml` checks spec consistency
- `cargo test` runs handler unit tests

## Spec Tags → Service Mapping

| Tag | Service | Description |
|-----|---------|-------------|
| `gates` | sekiban | Signature gate management |
| `certifications` | sekiban | Environment certification |
| `audit` | sekiban | Audit trail |
| `signatures` | sekiban | Signature computation |
| `compliance` | kensa | Compliance results |
| `reports` | kensa | Compliance reports |
| `certification-pipeline` | kensa | Product certification |
| `heartbeat` | tameshi | Heartbeat chain + consistency proofs |
| `collectors` | tameshi | Layer hash collection |
| `signing` | tameshi | Merkle root signing |
| `compliance-query` | tameshi | Compliance state queries |
| `cve` | kensa | CVE ingestion |
| `dynamic-checks` | kensa | Dynamic compliance checks |
| `health` | both | Health and readiness probes |
