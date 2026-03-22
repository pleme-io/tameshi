# Tameshi Testing Strategy: Production Readiness Plan

## Overview

This document defines the testing and performance telemetry required to greenlight the tameshi attestation ecosystem for enterprise Kubernetes deployments. The strategy covers four dimensions: correctness, performance, security, and operational readiness.

---

## 1. Test Infrastructure Summary

### Current State

| Repo | Total Tests | Benchmarks | Property Tests | Fuzz Targets | CI/CD |
|------|------------|------------|----------------|--------------|-------|
| tameshi | 472 (433 lib + 22 e2e + 15 proptest + 2 doc) | 8 suites (criterion) | 15 properties (proptest) | 8 targets | 3 workflows |
| sekiban | 337 (233 lib + 82 integration + 22 proptest) | 3 suites (criterion) | 22 properties (proptest) | 5 targets | 3 workflows |
| kensa | 390 (308 lib + 69 integration + 13 proptest) | 3 suites (criterion) | 13 properties (proptest) | 6 targets | 3 workflows |
| inshou | 375 (356 lib + 10 integration + 9 proptest) | 3 suites (criterion) | 9 properties (proptest) | 5 targets | 3 workflows |
| **Total** | **1,574** | **17 suites** | **59 properties** | **24 targets** | **12 workflows** |

### Cross-Repo Integration

- **tameshi-integration** repo: 4 integration test files, full pipeline test
- **repository_dispatch**: tameshi release triggers downstream CI in sekiban/kensa/inshou

---

## 2. Webhook Latency (sekiban)

### The Constraint

Kubernetes admission webhooks have a configurable timeout (default 10s, recommended <5s for production). The sekiban webhook must:

1. Parse the AdmissionReview JSON
2. Look up matching SignatureGate CRDs
3. Extract the `sekiban.pleme.io/signature` annotation
4. Compute the BLAKE3 changeset hash
5. Verify against expected signature
6. Return allow/deny decision

**Target: p99 < 50ms for typical deployments**

### Benchmarks

| Benchmark | What it measures | Target |
|-----------|-----------------|--------|
| `changeset_create/10` | Typical Deployment (10 fields) | < 1ms |
| `changeset_create/1000` | Large ConfigMap (1000 fields) | < 5ms |
| `admission_review_parsing` | JSON parse of AdmissionReview | < 1ms |
| `evaluate_gate_single_verified` | Full gate evaluation | < 1ms |
| `evaluate_gate_multiple/50` | 50-gate environment | < 10ms |

### Load Tests (k6)

| Scenario | VUs | Duration | Assertions |
|----------|-----|----------|------------|
| Baseline throughput | 100 | 5min | p99 < 50ms, error < 0.1% |
| Burst capacity | 0→1000 ramp | 3min | p99 < 200ms, no 5xx |
| Sustained load | 500 | 10min | Memory growth < 50MB |

### How to Run

```bash
# Deploy sekiban to test cluster
helm install sekiban chart/sekiban --namespace sekiban-system

# Run baseline load test
k6 run tests/load/k6/webhook_baseline.js --env SEKIBAN_URL=https://sekiban.sekiban-system.svc:8443

# Run burst test
k6 run tests/load/k6/webhook_burst.js --env SEKIBAN_URL=https://sekiban.sekiban-system.svc:8443
```

---

## 3. Sad Path Velocity

### The Question

How fast does the system mathematically reject a tampered deployment?

### Benchmarks

| Scenario | What changes | Expected behavior |
|----------|-------------|-------------------|
| Tampered container image | OCI layer hash changes | Merkle root changes → signature mismatch → DENY |
| Mutated Akeyless target | Target config hash changes | AkeylessTarget layer hash changes → DENY |
| Stale signature | Signature older than max_age | evaluate_gate detects staleness → DENY |
| Missing compliance | No compliance hash | require_compliance policy → DENY |
| Missing required layer | Layer not in Merkle tree | required_layers policy → DENY |

**Target: Deny decision in < 5ms** (no I/O required — pure computation)

### Criterion Benchmarks

```
gating/evaluate_gate_deny_mismatch: measures time to reject a wrong signature
gating/evaluate_gate_deny_no_compliance: measures time to reject missing compliance
changeset/verify_changeset (tampered): measures tamper detection speed
```

---

## 4. Payload Scaling & Parallelization

### BLAKE3's Infinite Parallelization

BLAKE3 is a Merkle tree internally. It can hash data at the speed of memory bandwidth by parallelizing across CPU cores. This is critical for:

- **Nix closures**: Can be gigabytes (full system profile)
- **Container images**: Multi-layer, multi-GB OCI manifests
- **Large ConfigMaps**: Kubernetes resources with embedded data

### Benchmarks

| Benchmark | Input size | What it proves |
|-----------|-----------|----------------|
| `blake3_digest/64` | 64 bytes | Baseline overhead |
| `blake3_digest/1048576` | 1 MB | Throughput scaling |
| `blake3_digest/10485760` | 10 MB | Memory bandwidth saturation |
| `merkle_root/128` | 128 layers | Tree construction scaling |
| `merkle_root/1024` | 1024 layers | Large tree performance |

### Expected Results

On modern hardware (Apple M-series, AMD Zen 4):
- **BLAKE3 throughput**: 5-8 GB/s single-threaded, scales linearly with cores
- **Merkle root (11 layers)**: < 1μs
- **Merkle root (1024 layers)**: < 100μs
- **Merkle proof verification**: O(log n) hashes, < 10μs for any tree size

### Streaming File Hashing

`blake3_file_async()` now uses streaming 64KB buffers instead of loading entire files into memory. This means:
- 10GB Nix closure: ~1.3s at memory bandwidth, constant 64KB memory
- No OOM risk regardless of file size

---

## 5. Concurrency Stress Testing

### Webhook Concurrency

The sekiban webhook must handle 50-100 simultaneous deployment requests without bottlenecking the K8s API pipeline.

| k6 Scenario | VUs | Target |
|-------------|-----|--------|
| `webhook_baseline.js` | 100 constant | p99 < 50ms |
| `webhook_burst.js` | 0→1000 ramp | p99 < 200ms |
| `webhook_sustained.js` | 500 for 10min | No memory leak |

### Reconciler Parallelization

Gate and certification reconcilers now use `futures::future::join_all` for parallel layer/gate collection:

- **Before**: O(N × latency) for N layers
- **After**: O(latency) — all layers collected in parallel

### kensa Store Contention

```bash
k6 run tests/load/k6/store_contention.js --env KENSA_URL=http://kensa:8080
```

Tests 50 concurrent writers + 200 concurrent readers. Assertions:
- No data corruption
- Read p99 < 100ms
- Write p99 < 500ms

---

## 6. Property-Based Testing

### Why Proptest

Unit tests verify specific inputs. Property tests verify **invariants across all possible inputs**. For a cryptographic system, this is essential.

### Key Properties

| Property | Why it matters |
|----------|---------------|
| Hash determinism | Same input must always produce same hash |
| Hash sensitivity | Different inputs must produce different hashes |
| Combine non-commutativity | `combine(a,b) ≠ combine(b,a)` — tree structure matters |
| Merkle order independence | Layer ordering must not affect root |
| Merkle tamper detection | Changing any leaf must change root |
| Merkle proof validity | Every leaf must have a valid inclusion proof |
| Two-phase consistency | untested + compliance always produces valid secure sig |
| Gating transitivity | Matching signature always produces ALLOW |
| Changeset roundtrip | certify → verify always passes |
| Changeset tamper detection | Any modification → verify fails |
| Serde roundtrip | All types survive JSON serialization |

### Running Property Tests

```bash
# Default (256 cases per property)
cargo test --test proptest_properties

# Extensive (1000 cases)
PROPTEST_CASES=1000 cargo test --test proptest_properties

# Find minimal failing case
PROPTEST_MAX_SHRINK_ITERS=10000 cargo test --test proptest_properties
```

---

## 7. Fuzzing

### Why Fuzz

Fuzzing finds crashes, panics, and undefined behavior that neither unit tests nor property tests can reach. For a security-critical system that processes untrusted input (AdmissionReview JSON, K8s resource YAML), fuzzing is mandatory.

### Fuzz Targets (24 total)

**tameshi (8):** merkle_tree, hash_computation, signature_verification, gating_policy, hex_parsing, changeset_computation, compliance_dimension, serde_roundtrip

**sekiban (5):** admission_review, crd_deser, changeset_hash, annotation_parsing, config_parsing

**kensa (6):** inspec_json, compliance_result_deser, nist_control_mapping, rest_api_body, signature_computation, config_parsing

**inshou (5):** hash_string_parsing, config_yaml, profile_json, sekiban_response, gate_inputs

### Running Fuzz Tests

```bash
# Quick run (60 seconds per target)
cd tameshi && cargo +nightly fuzz run merkle_tree -- -max_total_time=60

# Extended run (1 hour)
cargo +nightly fuzz run merkle_tree -- -max_total_time=3600

# All targets
for target in merkle_tree hash_computation signature_verification gating_policy hex_parsing changeset_computation serde_roundtrip compliance_dimension; do
    cargo +nightly fuzz run $target -- -max_total_time=60
done
```

### Success Criteria

- Zero crashes across all 24 targets after 1 hour each
- No panics from any input shape
- All deserialization targets handle malformed input gracefully

---

## 8. CI/CD Pipeline

### Per-Repo Workflows

| Job | Duration | Tool | Threshold |
|-----|----------|------|-----------|
| `fmt` | ~2min | `cargo fmt --check` | Zero violations |
| `clippy` | ~5min | `cargo clippy -- -D warnings` | Zero warnings |
| `test` | ~8min | `cargo nextest run` (ubuntu + macos) | All pass |
| `coverage` | ~10min | `cargo-llvm-cov` | tameshi 85%, sekiban 75%, kensa 80%, inshou 80% |
| `security` | ~5min | `cargo-deny` | No advisories, approved licenses only |
| `bench` | ~5min | `cargo bench --no-run` | Compiles |
| `nix-build` | ~15min | `nix flake check` + `nix build` | Builds |
| `helm-lint` | ~3min | `helm lint` + `helm template` | (sekiban/kensa only) |

### Cross-Repo Automation

```
tameshi release v0.2.0
  → repository_dispatch to sekiban, kensa, inshou
  → each: cargo update -p tameshi && cargo test
  → if pass: create PR with version bump
```

### Quality Gates (PR Merge Requirements)

- All CI jobs pass
- Coverage does not drop > 2%
- No new cargo-deny advisories
- `nix flake check` passes
- Helm lint passes (sekiban/kensa)

---

## 9. Production Readiness Checklist

### Must-Have (Before Production)

| Item | Repo | Status |
|------|------|--------|
| Webhook p99 < 50ms under 100 VU | sekiban | Benchmark + k6 |
| Deny decision < 5ms | tameshi/sekiban | Benchmark |
| Rainbow-table-proof secret hashing | tameshi | **DONE** (salted) |
| Merkle tamper detection verified | tameshi | Property tests |
| Graceful shutdown | sekiban, kensa | Done |
| Structured logging | sekiban, kensa | Done |
| Prometheus metrics | sekiban | Done |
| Health checks | sekiban | Done |
| RBAC in Helm charts | sekiban | Done |
| TLS for webhook | sekiban | cert-manager |

### Should-Have (Week 3-4)

| Item | Repo |
|------|------|
| Circuit breaker on webhook | sekiban |
| OpenTelemetry tracing | sekiban, kensa |
| PrometheusRule alerts | sekiban, kensa |
| Leader election (multi-replica) | sekiban |
| Connection pooling (shared reqwest) | all |

### Nice-to-Have (Week 5-8)

| Item | Repo |
|------|------|
| SLSA provenance for release artifacts | tameshi |
| Layer hash caching (CachedCollector with TTL) | tameshi |
| Gate signature cache (DashMap/moka) | sekiban |
| Benchmark regression CI (criterion compare) | tameshi |

---

## 10. The Dynamometer Test

### Analogy

We are testing the Ferrari engine on the dynamometer before putting it on the track. The dynamometer metrics are:

| Metric | Tool | Target | Why |
|--------|------|--------|-----|
| **Webhook latency** | k6 + Prometheus | p99 < 50ms | K8s webhook timeout budget |
| **Deny velocity** | criterion | < 5ms | Security response time |
| **Hash throughput** | criterion | > 5 GB/s | Nix closure sizing |
| **Tree construction** | criterion | < 100μs @ 1024 leaves | Scalability ceiling |
| **Concurrent webhooks** | k6 burst | 1000 VU, p99 < 200ms | Cluster-scale deployment |
| **Memory stability** | k6 sustained | < 50MB growth over 10min | Leak detection |
| **Fuzzing resilience** | cargo-fuzz | 0 crashes in 24 hours | Input robustness |
| **Property coverage** | proptest | 59 invariants, 1000 cases each | Correctness |

### How to Run the Full Dynamometer Suite

```bash
# 1. Unit tests (all repos)
for repo in tameshi sekiban kensa inshou; do
    (cd ~/code/github/pleme-io/$repo && cargo nextest run)
done

# 2. Property tests
for repo in tameshi sekiban kensa inshou; do
    (cd ~/code/github/pleme-io/$repo && PROPTEST_CASES=1000 cargo test --test proptest_properties)
done

# 3. Benchmarks
for repo in tameshi sekiban kensa inshou; do
    (cd ~/code/github/pleme-io/$repo && cargo bench)
done

# 4. Integration tests
cd ~/code/github/pleme-io/tameshi-integration && cargo test

# 5. Fuzz (1 hour per target, run overnight)
cd ~/code/github/pleme-io/tameshi
for target in $(cargo +nightly fuzz list); do
    cargo +nightly fuzz run $target -- -max_total_time=3600 &
done
wait

# 6. Load tests (requires running cluster)
k6 run sekiban/tests/load/k6/webhook_baseline.js
k6 run sekiban/tests/load/k6/webhook_burst.js
k6 run kensa/tests/load/k6/certification_baseline.js
k6 run kensa/tests/load/k6/store_contention.js
```

---

## 11. Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Supply chain injection (modified image between build and deploy) | BLAKE3 Merkle root detects any change |
| Secret value exposure in attestation logs | Salted hashing: `BLAKE3(gateway:path:value)` |
| Rainbow table attack on low-entropy secrets | Salt includes unique gateway URL + path |
| Replay attack (old valid signature) | `max_signature_age_secs` in GatingPolicy |
| Compromised CI pipeline | Two-phase composition: infrastructure + compliance must both be fresh |
| Webhook bypass | K8s `failurePolicy: Fail` — if webhook is down, all mutations are rejected |
| Merkle tree manipulation | `rs_merkle` with deterministic leaf ordering prevents tree structure attacks |

### What Tameshi Does NOT Protect Against

- Compromise of the BLAKE3 algorithm itself (256-bit security margin)
- Physical access to the Kubernetes control plane
- Insider with kubectl access who modifies CRDs directly (requires RBAC hardening)
- Bugs in the application code itself (testing catches bugs; attestation catches tampering)
