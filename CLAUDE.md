# tameshi -- Deterministic integrity attestation library

Core library for cryptographic hash computation, Merkle tree composition, and signature verification across infrastructure layers (Nix, OCI, Helm, K8s, etc.). Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test          # 457 tests
cargo build --release
```

## Architecture

```
src/
  lib.rs                 -- module declarations
  hash.rs                -- Blake3Hash, Sha256Hash, AttestationHasher trait, blake3_file
  signature.rs           -- LayerType, LayerSignature, MasterSignature, InputHash
  merkle.rs              -- Merkle tree (rs_merkle), compose_merkle, proofs
  verify.rs              -- verify_master, verify_untested, verify_secure, verify_prefixed
  gating.rs              -- GatingPolicy, evaluate_gate, gate_fluxcd_resource, gate_tatara_job
  changeset.rs           -- CertifiedChangeset, hash_changeset, certify_changeset
  certification.rs       -- ProductCertification builder (7-stage pipeline)
  compliance/            -- NIST, OSCAL, CIS, CVE, SBOM, SLSA, InSpec, frameworks
  collectors/
    traits.rs            -- LayerCollector trait
    mock.rs              -- MockCollector
    nix.rs, oci.rs, helm.rs, kubernetes.rs, tofu.rs, kindling.rs, tatara.rs, akeyless.rs, akeyless_target.rs
  config.rs              -- load_config (figment: defaults -> YAML -> env)
  api_types.rs           -- GateDecision, CertificationStatus, AuditEntry
  reporting.rs           -- EnvironmentReport, ComplianceSummary, DriftReport
  selftest.rs            -- FrameworkAttestation, framework_nist_controls
  alerts.rs              -- alert types
  ci.rs                  -- CI/CD helpers, sekiban_annotations, render_annotation_patch, target_attestation helpers
  error.rs               -- TameshiError
```

## Key Traits

### `LayerCollector` (collectors/traits.rs)
- `async fn collect(&self) -> Result<LayerSignature>` -- collect layer hash
- `fn layer_type(&self) -> LayerType` -- which layer this collector handles
- Mock: `MockCollector::new(LayerType)`, `.set_result(Result<LayerSignature>)`

### `AttestationHasher` (hash.rs)
- `fn hash(data: &[u8]) -> Self::Output`
- `fn hash_file(path: &Path) -> Result<Self::Output>`
- `fn combine(a: &Self::Output, b: &Self::Output) -> Self::Output`
- `fn to_hex(output: &Self::Output) -> String`
- `fn from_hex(hex: &str) -> Result<Self::Output>`
- Impl: `Blake3Hasher`

## Types

- **`Blake3Hash([u8; 32])`** -- primary hash type. `digest()`, `combine()`, `from_hex()`, `to_prefixed()`
- **`Sha256Hash([u8; 32])`** -- compatibility hash for OCI/Nix
- **`LayerType`** -- enum: Nix, Oci, Helm, Tofu, Kubernetes, Kindling, Tatara, FluxCD, ArgoCD, Akeyless, AkeylessTarget
- **`AkeylessTargetType`** -- enum with 30 variants (Web, Ssh, SshCert, AwsAssociateTarget, GcpTarget, AzureTarget, RabbitMq, DynamicSecretTarget, RotatedSecretTarget, ClassicKey, DfcKey, TokenizationTarget, SalesforceTarget, LdapTarget, WindowsTarget, MongoDbTarget, EksTarget, GkeTarget, NativeK8sTarget, CustomTarget, PingTarget, GitHubTarget, GlobalSignTarget, HashiCorpVaultTarget, LinkedTarget, ZeroSslTarget, VenafiTarget, CertificateStoreTarget, SshCertIssuerTarget, Unknown)
- **`ProducerAssociation`** -- target + producer_type + association metadata
- **`AkeylessTargetCollector`** / **`LiveAkeylessTargetCollector`** -- collect target configuration hashes
- **`LayerSignature`** -- layer + hash + metadata + inputs. `verify_inputs()`
- **`MasterSignature`** -- untested + compliance + secure hashes. `verify_untested()`, `verify_secure()`, `gating_signature()`
- **`AkeylessTargetVerification`** -- compliance dimension for target attestation state
- **`GatingPolicy`** -- required_layers, require_compliance, max_signature_age_secs, fail_open
- **`GateDecision`** -- allowed, reason, signature, expected. `allow()`, `deny()`
- **`ProductCertification`** -- 7-stage certification (source, build, image, chart, deployment, compliance, product)
- **`CertifiedChangeset`** -- K8s mutation hash chain (operation, resource, before/after state, env signature)

## Testing

```bash
cargo test                    # 457 tests
cargo test hash               # hash module tests
cargo test merkle             # merkle tree tests
cargo test gating             # gate policy tests
cargo test certification      # product certification tests
```

Mock types: `MockCollector` (collectors/mock.rs).

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
| reqwest | HTTP client (OCI, remote endpoints) |
| thiserror | Error types |
| tracing | Structured logging |
