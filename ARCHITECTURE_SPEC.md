# Tameshi Architecture Specification v2

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-14 | Initial architecture |
| 2.0 | 2026-03-20 | Added canonicalization, LSM hooks, DFC signing, proof heartbeat, version-pinned attestations |

---

## System Overview

```
                    ┌──────────────────────────────────────────────┐
                    │            Attestation Pipeline              │
                    │                                              │
                    │  Nix → OCI → Helm → K8s → Flux → Akeyless  │
                    │     ↓      ↓      ↓     ↓      ↓      ↓    │
                    │  ┌─────────────────────────────────────────┐ │
                    │  │     tameshi (BLAKE3 Merkle Tree)        │ │
                    │  │                                         │ │
                    │  │  Canonicalize → Hash → Compose → Sign   │ │
                    │  └──────────────────┬──────────────────────┘ │
                    │                     │                        │
                    │              Untested Signature              │
                    │                     │                        │
                    │  ┌──────────────────┴──────────────────────┐ │
                    │  │     kensa (Compliance Engine)           │ │
                    │  │                                         │ │
                    │  │  NIST → OSCAL → Assessment → Hash      │ │
                    │  └──────────────────┬──────────────────────┘ │
                    │                     │                        │
                    │            Compliance Hash                   │
                    │                     │                        │
                    │     Secure Sig = BLAKE3(Untested || Compl)   │
                    │                     │                        │
                    │     DFC Sign via Akeyless (Phase 3)         │
                    └─────────────────────┬────────────────────────┘
                                          │
                    ┌─────────────────────┼────────────────────────┐
                    │                     │                        │
              ┌─────┴─────┐      ┌───────┴───────┐      ┌────────┴────────┐
              │  inshou    │      │   sekiban      │      │    kanshi       │
              │  Nix Gate  │      │   K8s Webhook  │      │  eBPF Sentinel │
              │            │      │                │      │   (Phase 2)    │
              │  Pre-build │      │  Admission     │      │  Runtime       │
              │  verify    │      │  verify        │      │  verify        │
              └────────────┘      └────────────────┘      └────────────────┘
                    │                     │                        │
                    └─────────────────────┼────────────────────────┘
                                          │
                              ┌────────────┴────────────┐
                              │  Proof Heartbeat Chain   │
                              │  (Phase 2)               │
                              │                          │
                              │  Append-only, signed,    │
                              │  chronological proofs    │
                              └──────────────────────────┘
```

---

## Component Specifications

### 1. tameshi — Core Attestation Library

**Responsibility:** Hash computation, Merkle tree composition, signature lifecycle, gating primitives, canonicalization.

#### 1.1 Hash Pipeline

```
Raw Content → Canonicalizer → BLAKE3 → LayerSignature
```

The canonicalizer is format-aware and mode-aware:

```rust
pub enum CanonicalMode {
    /// Byte-for-byte: any change is a mutation.
    /// Recommended for GovCloud/FedRAMP environments.
    Strict,
    /// Parse → normalize → hash: non-functional changes
    /// (whitespace, comments, key ordering) are ignored.
    /// Recommended for enterprise DevOps velocity.
    Logical,
}

pub trait Canonicalizer: Send + Sync {
    fn canonicalize(&self, content: &[u8], mode: CanonicalMode) -> Vec<u8>;
    fn format_name(&self) -> &str;
}
```

| Format | Strict behavior | Logical behavior |
|--------|----------------|-----------------|
| YAML | Hash raw bytes | Parse → BTreeMap sort keys → strip comments → serialize |
| JSON | Hash raw bytes | Parse → BTreeMap sort keys → serialize |
| Nix | Hash raw bytes | Parse → strip comments → normalize whitespace → serialize |
| HCL | Hash raw bytes | Parse → canonical JSON → serialize |
| Binary | Hash raw bytes | Hash raw bytes (same as Strict) |

#### 1.2 Merkle Composition

Unchanged from v1. Layers sorted by `LayerType`, composed via `rs_merkle` with `Blake3Algorithm`. The Merkle root is the Untested Signature.

#### 1.3 Two-Phase Signatures

```
Untested = MerkleRoot(canonicalized layer hashes)
Compliance = BLAKE3(assessment results from kensa)
Secure = BLAKE3(Untested || Compliance)
```

#### 1.4 Secret Value Hashing (Rainbow-Table Proof)

```rust
// Salt with gateway URL + secret path to defeat dictionary attacks
let value_hash = Blake3Hash::digest(
    &[gateway_url, ":", path, ":", secret_value].concat()
);
```

**Security property:** Even identical secret values produce different hashes across different gateways and paths. An attacker with access to the attestation log cannot reverse or rainbow-table the hash.

#### 1.5 Signing (Phase 3: DFC)

```rust
pub trait MerkleRootSigner: Send + Sync {
    /// Sign the Merkle root hash. The implementation determines
    /// whether the key is local or distributed.
    async fn sign(&self, root: &Blake3Hash) -> Result<SignedRoot>;
    /// Verify a previously signed root.
    async fn verify(&self, signed: &SignedRoot) -> Result<bool>;
}

pub struct SignedRoot {
    pub root: Blake3Hash,
    pub signature: Vec<u8>,
    pub algorithm: SigningAlgorithm,
    pub signer_id: String,
    pub signed_at: DateTime<Utc>,
}

pub enum SigningAlgorithm {
    /// Ed25519 with local key (development)
    Ed25519Local,
    /// Akeyless DFC-backed signing (production)
    /// Key never exists in one piece.
    AkeylessDfc { key_name: String },
}
```

**DFC flow:**

1. kensa computes the compliance-approved Merkle root
2. kensa calls `AkeylessDfcSigner::sign(root)`
3. Signer sends signing request to Akeyless Gateway
4. Gateway coordinates fragment holders (threshold signing)
5. Partial signatures combine into full Ed25519/ECDSA signature
6. Full key never exists in memory on any single machine
7. Signed root stored in sekiban's SignatureGate CRD

---

### 2. sekiban — K8s Admission Webhook

**Responsibility:** Gate every K8s API mutation against approved signatures.

#### 2.1 Admission Flow

```
AdmissionReview JSON
  → Parse request
  → Look up matching SignatureGate CRDs
  → Extract sekiban.pleme.io/signature annotation
  → Canonicalize changeset (BTreeMap sort, strip volatile fields)
  → Compute changeset BLAKE3 hash
  → Verify against expected signature
  → Check version-pinned history (new)
  → Emit proof heartbeat (Phase 2)
  → Return allow/deny
```

#### 2.2 Version-Pinned Attestations (PLANNED — Not Yet Implemented)

The current `SignatureGateStatus` CRD has `current_signature` only. The following extension is planned for Phase 1.4 to support rollback tolerance during rolling updates:

```rust
// PLANNED extension to SignatureGateStatus
pub struct SignatureGateStatus {
    pub phase: GatePhase,
    pub current_signature: Option<String>,
    /// PLANNED: Versioned signature history for rollback tolerance.
    /// Accepts any signature in history that hasn't expired.
    pub signature_history: Vec<VersionedSignature>,  // NOT YET IN CODE
    pub layer_statuses: Vec<LayerStatus>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub audit_trail: Vec<AuditEntry>,
}

pub struct VersionedSignature {
    pub signature: String,
    pub commit_ref: String,
    pub valid_from: DateTime<Utc>,
    /// None = valid until explicitly superseded.
    /// Some(time) = rolling deployment window.
    pub valid_until: Option<DateTime<Utc>>,
}
```

**Evaluation change:**

```rust
fn signature_matches(expected: &SignatureGateSpec, actual: &str) -> bool {
    // Check current signature first (fast path)
    if expected.expected_signature == actual {
        return true;
    }
    // Check versioned history (rollback tolerance)
    expected.signature_history.iter().any(|v| {
        v.signature == actual && !v.is_expired(Utc::now())
    })
}
```

This eliminates flapping during rolling updates where the CI has already computed a new signature but in-flight deployments carry the previous one.

#### 2.3 Existing Canonicalization

sekiban already implements canonical JSON processing:

- `canonical_json()` — BTreeMap-sorted key serialization
- `strip_volatile_fields()` — removes resourceVersion, uid, creationTimestamp, managedFields, selfLink, generation, status
- `normalize_value()` — recursive BTreeMap normalization

This handles the K8s JSON admission path. The Helm/Nix canonicalization concern applies to the upstream collectors in tameshi, not sekiban.

---

### 3. kensa — Compliance Engine

**Responsibility:** Run compliance tests, produce NIST/OSCAL reports, compute compliance hash, sign approved roots.

#### 3.1 Signing Architecture (Phase 3)

```
kensa runs compliance tests → AssessmentResult
  → compute compliance hash → Blake3Hash
  → compose with untested → Secure Signature
  → sign via MerkleRootSigner trait
    ├── LocalSigner (dev/test)
    └── AkeylessDfcSigner (production)
  → push SignedRoot to sekiban via API
```

The signing key for production is NEVER a file. It's an Akeyless DFC key that requires threshold cooperation of multiple gateway fragments.

---

### 4. kanshi — eBPF Runtime Sentinel (Phase 2)

**Responsibility:** Verify binary integrity at exec time using kernel-level LSM hooks.

#### 4.1 LSM Hook Architecture

```
Process calls execve()
  → Kernel invokes bprm_check_security LSM hook
  → kanshi eBPF program runs (binary is LOCKED by kernel)
  → Look up expected hash in BPF_MAP_TYPE_HASH
  → BLAKE3 hash the binary pages
  → Compare: match → allow (return 0), mismatch → deny (return -EPERM)
  → Emit proof heartbeat
```

**Key constraint:** The LSM hook runs with the binary locked. There is no TOCTOU race window. This is the critical difference from tracepoint-based approaches.

#### 4.2 Policy Model

```rust
pub struct KanshiPolicy {
    /// Namespace-scoped enforcement.
    pub namespace: String,
    /// Enforcement mode.
    pub mode: EnforcementMode,
    /// Expected binary hashes (populated from tameshi layer signatures).
    pub expected_hashes: HashMap<PathBuf, Blake3Hash>,
}

pub enum EnforcementMode {
    /// Log violations but allow execution.
    Audit,
    /// Block execution of unverified binaries.
    Enforce,
    /// Only verify binaries in expected_hashes, allow unknown.
    AllowUnknown,
}
```

#### 4.3 BPF Map Structure

```c
// Hash map: inode → expected BLAKE3 hash
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);          // inode number
    __type(value, u8[32]);     // BLAKE3 hash
} hash_map SEC(".maps");

// Policy map: cgroup_id → enforcement mode
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);          // cgroup ID (maps to K8s namespace)
    __type(value, u8);         // 0=audit, 1=enforce, 2=allow_unknown
} policy_map SEC(".maps");
```

#### 4.4 JIT Language Limitations

For compiled binaries (Go, Rust, C, C++): **Full integrity guarantee** via exec-time hash verification.

For interpreted/JIT binaries (Node, Python, Java, Ruby):

| Protection Layer | What it verifies |
|-----------------|-----------------|
| OCI layer hash (tameshi) | Filesystem at deploy time |
| Read-only rootfs (K8s) | Prevents post-deploy modification |
| LSM exec hook (kanshi) | Interpreter binary integrity |
| LSM file_open hook (kanshi) | Application code loading (optional, perf cost) |

**Documented gap:** Runtime code generation (eval, dynamic classloading) cannot be verified by filesystem-level integrity. This is a fundamental limitation, not a tameshi bug.

---

### 5. Proof Heartbeat Chain (Phase 2)

**Responsibility:** Continuous, signed, tamper-evident verification logging for CIRCIA compliance.

#### 5.1 Chain Structure

```
Entry[0] ──→ Entry[1] ──→ Entry[2] ──→ ... ──→ Entry[N]
  │              │              │                    │
  hash           hash           hash                 hash
  ↓              ↓              ↓                    ↓
  H(genesis)     H(E[0]+E[1])   H(E[1]+E[2])        H(E[N-1]+E[N])
```

Each entry's `entry_hash` is `BLAKE3(previous_hash || serialized_entry)`. Modifying any entry breaks all subsequent hashes.

#### 5.2 Entry Schema

```rust
pub struct HeartbeatEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub verifier: VerifierIdentity,
    pub event: HeartbeatEvent,
    pub result: VerificationOutcome,
    pub resource: String,
    pub signature_checked: Blake3Hash,
    pub entry_hash: Blake3Hash,
    pub previous_hash: Blake3Hash,
}

pub enum HeartbeatEvent {
    Admission { namespace: String, resource_id: String, operation: String },
    ExecVerify { binary_path: String, pid: u32 },
    ComplianceCheck { framework: String, baseline: String },
    NixGate { store_path: String },
    KeyRotation { old_key_id: String, new_key_id: String },
}

pub enum VerificationOutcome {
    Pass,
    Fail { reason: String },
    Skip { reason: String },
}
```

#### 5.3 Emission Points

| Verifier | Event | Frequency |
|----------|-------|-----------|
| sekiban | Every admission decision | Per-mutation (high volume) |
| kanshi | Every exec verification | Per-process (high volume) |
| kensa | Every compliance assessment | Periodic (minutes-hours) |
| inshou | Every Nix gate check | Per-rebuild (low volume) |
| kensa | Key rotation events | Rare |

#### 5.4 Storage

Heartbeat entries are emitted to configurable backends:

```rust
pub trait HeartbeatEmitter: Send + Sync {
    async fn emit(&self, entry: &HeartbeatEntry) -> Result<()>;
}

// Implementations:
// - StdoutEmitter (development)
// - FileEmitter (local append-only log)
// - HttpEmitter (SIEM/Splunk/Datadog)
// - S3Emitter (immutable object storage)
// - KafkaEmitter (event streaming)
```

---

## Security Analysis

### Threat Model

| Threat | Tameshi Layer | Mitigation |
|--------|--------------|-----------|
| Modified container image | OCI collector | Merkle root changes → sekiban DENY |
| Tampered Helm chart | Helm collector | Merkle root changes → sekiban DENY |
| Injected K8s manifest | K8s collector + sekiban canonical_json | Changeset hash mismatch → DENY |
| Compromised CI pipeline | Two-phase composition | Both infra + compliance must be fresh |
| Secret rainbow table | Salted hashing | `BLAKE3(gateway:path:value)` |
| Stolen signing key | DFC signing (Phase 3) | Key never exists in one piece |
| Binary swap at runtime | kanshi LSM hook (Phase 2) | Kernel lock prevents TOCTOU |
| Whitespace/comment injection | Canonicalizer (Strict mode) | Byte-for-byte = any change detected |
| Replay old valid signature | `max_signature_age_secs` | Stale signatures rejected |
| Flapping during rolling update | Version-pinned history | Multiple valid signatures in window |
| Post-incident evidence gap | Proof heartbeat chain | Chronological verification log for CIRCIA |

### What Tameshi Does NOT Protect Against

| Threat | Why | Complementary control |
|--------|-----|----------------------|
| Zero-day in application code | Testing, not attestation | Code review, SAST/DAST |
| In-memory exploitation post-deploy | Admission-time, not runtime | Falco, Tetragon |
| JIT dynamic code generation | File integrity, not memory | Seccomp, AppArmor |
| Compromised BLAKE3 algorithm | 256-bit security margin | None needed (2^128 operations) |
| Physical access to control plane | Software boundary | Physical security, HSMs |

---

## Configuration Reference

```yaml
# tameshi.yaml — Collector configuration
canonicalization:
  mode: strict              # strict | logical
  yaml:
    strip_comments: true
    sort_keys: true
  nix:
    strip_comments: true

signing:
  algorithm: ed25519_local  # ed25519_local | akeyless_dfc
  # For DFC:
  akeyless:
    gateway_url: "https://gw.akeyless.prod"
    key_name: "/signing/tameshi-root"
    auth_method: k8s

heartbeat:
  enabled: true
  emitter: http             # stdout | file | http | s3 | kafka
  http:
    endpoint: "https://siem.internal/api/v1/events"
    batch_size: 100
    flush_interval_ms: 5000
```
