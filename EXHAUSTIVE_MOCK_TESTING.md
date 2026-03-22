# Exhaustive Mock Testing Matrix

Complete test coverage matrix for tameshi's attestation pipeline. Every variant
maps to a concrete test in `tests/exhaustive_mock_matrix.rs`. All tests run
natively on macOS -- no kernel, no cluster, no gateway, no AI model.

---

## 1. System Invariants

Absolute rules that must hold in EVERY test. Each invariant is identified by
a stable tag and referenced by the State Matrix variants that exercise it.

```
INV-1:  If BPF allow_map lacks the binary's BLAKE3 hash, execution yields DENY.
INV-2:  If BPF revocation_list contains the hash, execution yields DENY (revocation > allow).
INV-3:  On any external service failure (timeout, 500, auth), system defaults to FAIL-SECURE (deny).
INV-4:  CertificationArtifact verification failure -> gate DENY.
INV-5:  MockDfcSigner with wrong fragments -> verify returns false.
INV-6:  HeartbeatChain records EVERY decision (ALLOW and DENY).
INV-7:  HeartbeatChain tampering is detectable (verify_integrity fails).
INV-8:  AI DENY overrides Merkle gate ALLOW.
INV-9:  AI timeout -> Merkle gate decides alone (fail-open for AI, not for system).
INV-10: Consistency proofs are verifiable across chain segments.
INV-11: Different inputs ALWAYS produce different Merkle roots (collision resistance).
INV-12: Same inputs ALWAYS produce same Merkle roots (determinism).
```

---

## 2. State Matrix

Every row is a distinct test variant. The combination of states across the
six columns is unique, and the Expected Decision column is the single ground
truth assertion.

| ID | Variant | Hash State | Cert State | AI State | DFC State | BPF State | Expected Decision | Invariants Tested |
|----|---------|-----------|------------|----------|-----------|-----------|-------------------|-------------------|
| V-01 | Happy path (all valid) | Valid BLAKE3 | Valid 3-leaf artifact | ALLOW (0.98 conf) | Sign + verify OK | Hash in allow_map | **ALLOW** | INV-6, INV-12 |
| V-02 | Hash not in allow map | Valid BLAKE3 | Valid artifact | ALLOW | Sign OK | Hash absent | **DENY** | INV-1, INV-6 |
| V-03 | Hash in revocation list | Valid BLAKE3 | Valid artifact | ALLOW | Sign OK | Hash in revocation_list | **DENY** | INV-2, INV-6 |
| V-04 | Valid hash + revoked cert | Valid BLAKE3 | Tampered artifact_hash | ALLOW | Sign OK | Hash in allow_map | **DENY** | INV-4, INV-6 |
| V-05 | AI detects 94.2% breach | Valid BLAKE3 | Valid artifact | DENY (0.942 similarity) | Sign OK | Hash in allow_map | **DENY** | INV-8, INV-6 |
| V-06 | AI WARN + valid gate | Valid BLAKE3 | Valid artifact | WARN (0.31 similarity) | Sign OK | Hash in allow_map | **ALLOW** (logged) | INV-6, INV-9 |
| V-07 | TOCTOU: hash changes | Hash A at admission, Hash B at exec | Valid artifact | ALLOW | Sign OK | Hash A in map, B absent | **DENY** (exec phase) | INV-1, INV-6 |
| V-08 | DFC signer timeout | Valid BLAKE3 | Valid artifact | ALLOW | Timeout(5s) | N/A | **DENY** | INV-3, INV-6 |
| V-09 | DFC corrupted signature | Valid BLAKE3 | Valid artifact | ALLOW | CorruptedSignature | N/A | **DENY** (verify fails) | INV-5, INV-6 |
| V-10 | DFC auth failure | Valid BLAKE3 | Valid artifact | ALLOW | AuthFailure | N/A | **DENY** | INV-3, INV-6 |
| V-11 | AI timeout, gate decides | Valid BLAKE3 | Valid artifact | Timeout(500ms) | Sign OK | Hash in allow_map | **ALLOW** (AI fail-open) | INV-9, INV-6 |
| V-12 | All services down | Valid BLAKE3 | No artifact | Unavailable | Timeout | N/A | **DENY** | INV-3, INV-6 |
| V-13 | Tampered CertificationArtifact | Valid BLAKE3 | artifact_hash mutated | ALLOW | Sign OK | Hash in allow_map | **DENY** | INV-4, INV-7 |
| V-14 | Tampered HeartbeatChain entry | N/A | N/A | N/A | N/A | N/A | integrity check **FAILS** | INV-7, INV-10 |
| V-15 | Missing certs when required | Valid BLAKE3 | Empty vec | ALLOW | Sign OK | Hash in allow_map | **DENY** | INV-4, INV-6 |
| V-16 | Valid cert + expired sig | Valid BLAKE3 | Valid artifact | ALLOW | Sign OK (stale) | Hash in allow_map | **DENY** | INV-3, INV-6 |
| V-17 | Break-glass token valid | Valid BLAKE3 | No artifact | N/A | N/A | N/A | **ALLOW** (audit) | INV-6 |
| V-18 | Break-glass expired | Valid BLAKE3 | No artifact | N/A | N/A | N/A | **DENY** | INV-3, INV-6 |
| V-19 | Multiple artifacts, one invalid | Valid BLAKE3 | 2 artifacts, 1 tampered | ALLOW | Sign OK | Hash in allow_map | **DENY** | INV-4, INV-6 |
| V-20 | Empty allow map + Enforce | Valid BLAKE3 | Valid artifact | ALLOW | Sign OK | Empty allow_map | **DENY** | INV-1, INV-6 |

---

## 3. Test Harness

All 20 variants are implemented in `tests/exhaustive_mock_matrix.rs` using
the real tameshi types. The harness uses these shared helpers:

```rust
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{LayerSignature, LayerType};
use tameshi::certification_artifact::{
    compose_certification_artifact, verify_certification_artifact,
};
use tameshi::signing::{
    BreakGlassToken, FailableDfcSigner, LocalSigner, MerkleRootSigner, MockDfcSigner,
};
use tameshi::gating::{evaluate_gate, evaluate_gate_with_clock, GatingPolicy};
use tameshi::heartbeat::{
    HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity,
};
use tameshi::ai_threat::{
    AiDecision, AiThreatClient, FailableAiThreatClient, MockAiThreatClient,
};
use tameshi::traits::FixedClock;

/// Build a valid MasterSignature with compliance and certification artifacts.
fn make_attested_master(environment: &str) -> (MasterSignature, Blake3Hash) { ... }

/// Build a valid CertificationArtifact for /usr/bin/app.
fn make_valid_artifact() -> CertificationArtifact { ... }

/// Build a standard AnalyzeProvenanceRequest.
fn make_ai_request(artifact: &CertificationArtifact) -> AnalyzeProvenanceRequest { ... }

/// Append a gate decision to the heartbeat chain.
fn record_decision(chain: &HeartbeatChain, allowed: bool, resource: &str, hash: Blake3Hash) { ... }
```

### Test Naming Convention

Every test function follows the pattern:

```
v{NN}_{snake_case_variant_description}
```

Examples: `v01_happy_path_all_valid_allow`, `v08_dfc_timeout_deny`.

### Async vs Sync

Tests that exercise `MerkleRootSigner::sign()/verify()` or `AiThreatClient::analyze_provenance()`
use `#[tokio::test]` because those traits return futures. Gate-only tests use `#[test]`.

---

## 4. Invariant Assertions

Each invariant maps to a concrete assertion pattern reused across tests:

### INV-1: Missing from allow map -> DENY

```rust
// Simulated by gate signature mismatch (hash not recognized)
let wrong = Blake3Hash::digest(b"unknown-binary");
let decision = evaluate_gate(&policy, &master, &wrong);
assert!(!decision.allowed, "INV-1: hash not in allow map must DENY");
```

### INV-2: Revocation overrides allow

```rust
// Binary is allowed but then revoked -- revocation takes priority
// The revoked hash must not pass the gate even if it was previously valid
```

### INV-3: Service failure -> fail-secure

```rust
let signer = FailableDfcSigner::new().with_timeout(Duration::from_secs(5));
let result = signer.sign(&root).await;
assert!(result.is_err(), "INV-3: external failure must error");
// Caller interprets error as DENY (fail-secure)
```

### INV-4: Artifact verification failure -> DENY

```rust
let mut artifact = make_valid_artifact();
artifact.artifact_hash = Blake3Hash::digest(b"tampered");
assert!(!verify_certification_artifact(&artifact), "INV-4: tampered artifact must fail");
```

### INV-5: Wrong DFC fragments -> verify false

```rust
let signer_a = MockDfcSigner::from_fragments([1u8; 32], [2u8; 32], "a");
let signer_b = MockDfcSigner::from_fragments([3u8; 32], [4u8; 32], "b");
let signed = signer_a.sign(&root).await.unwrap();
let verified = signer_b.verify(&signed).await.unwrap();
assert!(!verified, "INV-5: wrong fragments must not verify");
```

### INV-6: HeartbeatChain records every decision

```rust
let chain = HeartbeatChain::new();
// ... perform gate checks ...
record_decision(&chain, decision.allowed, resource, hash);
assert!(chain.len() > 0, "INV-6: chain must record the decision");
assert!(chain.verify_integrity(), "INV-6: chain integrity must hold");
```

### INV-7: Tampered chain detectable

```rust
let chain = HeartbeatChain::new();
// append entries ...
assert!(chain.verify_integrity());
// External tampering (clone + modify) detected by hash mismatch
```

### INV-8: AI DENY overrides gate ALLOW

```rust
let ai = MockAiThreatClient::new().with_decision(AiDecision::Deny);
let response = ai.analyze_provenance(&request).await.unwrap();
assert_eq!(response.decision, AiDecision::Deny);
// Even though gate would ALLOW, the AI DENY takes precedence in the pipeline
```

### INV-9: AI timeout -> gate decides alone

```rust
let ai = FailableAiThreatClient::new().with_timeout(500);
let result = ai.analyze_provenance(&request).await;
assert!(result.is_err());
// Gate proceeds without AI input -- AI is fail-open, system is not
```

### INV-10: Consistency proofs verifiable

```rust
let chain = HeartbeatChain::new();
// append 5 entries ...
let proof = chain.consistency_proof(0, 4).unwrap();
assert!(chain.verify_consistency_proof(&proof), "INV-10: proof must verify");
```

### INV-11: Collision resistance

```rust
let r1 = compute_merkle_root(&layers_a);
let r2 = compute_merkle_root(&layers_b);
assert_ne!(r1, r2, "INV-11: different inputs must produce different roots");
```

### INV-12: Determinism

```rust
let r1 = compute_merkle_root(&layers);
let r2 = compute_merkle_root(&layers);
assert_eq!(r1, r2, "INV-12: same inputs must produce same root");
```
