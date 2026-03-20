# Tameshi Roadmap: From Prototype to Federal Compliance Engine

---

## The Three-Layer Security Model

Tameshi is not 20 features — it is **three layers of defense**:

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   THE SHIELD (Admission)                                    │
│   Stops the wrong things from entering.                     │
│                                                             │
│   sekiban webhook → Merkle root verification                │
│   CEL fail-safe → annotation guard                          │
│   inshou gate → Nix pre-rebuild check                       │
│   Break-glass → emergency bypass with audit                 │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   THE PULSE (Runtime)                                       │
│   Watches the heart of the kernel.                          │
│                                                             │
│   kanshi eBPF → binary verification at execve               │
│   file_open hooks → script/config integrity                 │
│   Revocation map → zero-day kill-switch (<100ms)            │
│   Self-healing → automatic rollback on tamper               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   THE MEMORY (Compliance)                                   │
│   Remembers every proof for the auditors.                   │
│                                                             │
│   kensa → NIST/SOC2/PCI/FedRAMP assessments                │
│   Heartbeat chain → append-only BLAKE3 audit trail          │
│   DFC signing → threshold cryptographic proof               │
│   CIRCIA evidence → 72-hour reporting chain                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

Every feature in this roadmap strengthens one of these three layers.
Every adversarial hole maps to a gap in one of these three layers.
Every NIST control is covered by at least one layer.

---

## Phase 1: Integrity & Purity (Current → Week 4)

### 1.1 Core Attestation — DONE

| Capability | Status | Repo |
|-----------|--------|------|
| BLAKE3 Merkle tree composition (11 layer types) | Done | tameshi |
| Two-phase signatures (untested + compliance = secure) | Done | tameshi |
| K8s admission webhook (ValidatingAdmissionWebhook) | Done | sekiban |
| NIST 800-53 compliance engine (OSCAL/InSpec/native) | Done | kensa |
| Nix gate CLI (hash/verify/gate/report) | Done | inshou |
| Salted secret hashing (rainbow-table proof) | Done | tameshi |
| Canonical JSON with BTreeMap key sorting | Done | sekiban |
| Volatile field stripping (resourceVersion, uid, status) | Done | sekiban |

### 1.2 Testing Infrastructure — DONE

| Capability | Status | Count |
|-----------|--------|-------|
| Unit/integration tests | Done | 1,574 |
| Criterion benchmarks | Done | 17 suites |
| Property-based tests (proptest) | Done | 59 properties |
| Fuzz targets (cargo-fuzz) | Done | 24 targets |
| Cross-repo integration tests | Done | tameshi-integration |
| k6 load tests | Done | 5 scenarios |
| CI/CD pipelines (GitHub Actions) | Done | 12 workflows |

### 1.3 Canonicalization Layer — DONE (Sprint 1A)

**Implemented:** `tameshi/src/canonicalize.rs` — 40 tests passing.

- `CanonicalMode` enum: `Strict` (byte-for-byte) / `Logical` (parse→normalize→hash)
- `Canonicalizer` trait with 4 implementations: `YamlCanonicalizer`, `JsonCanonicalizer`, `HclCanonicalizer`, `RawCanonicalizer`
- `canonical_hash()` convenience function
- `canonicalizer_for()` factory function
- K8s manifest key reordering produces identical hashes in Logical mode
- YAML comments stripped, whitespace normalized
- Cross-format determinism: same YAML/JSON content produces same hash

**Previous state:** sekiban ALREADY implements canonical JSON processing for K8s objects via `canonical_json()` (BTreeMap-sorted keys), `strip_volatile_fields()`, and `normalize_value()`.

**The Solution:** Two-mode canonicalization strategy (now implemented).

#### Strict Mode (Default for GovCloud/Federal)

Byte-for-byte hashing. Any change — including comments, whitespace, key ordering — is a mutation. This enforces "GitOps Purity" where the cluster state is a bit-perfect mirror of the signed commit.

**Rationale:** In high-security environments, the argument "a change is a change" is correct. If the file changed, it should be re-attested. This prevents the class of attacks where malicious content is hidden in comments or whitespace.

#### Logical Mode (Enterprise DevOps)

Parse → normalize → hash. Non-functional changes (whitespace, comments, key ordering) do not invalidate the signature.

**Implementation:**

```
tameshi/src/canonicalize.rs (new module)
  ├── CanonicalMode enum { Strict, Logical }
  ├── trait Canonicalizer { fn canonicalize(&self, content: &[u8]) -> Vec<u8> }
  ├── YamlCanonicalizer — parse YAML → BTreeMap → strip comments → serialize
  ├── JsonCanonicalizer — parse JSON → BTreeMap → serialize (already in sekiban)
  ├── NixCanonicalizer — parse Nix expression → normalize → serialize
  └── RawCanonicalizer — identity (Strict mode, passthrough)
```

**Configuration:**
```yaml
# tameshi.yaml
canonicalization:
  mode: strict  # or "logical"
  yaml:
    strip_comments: true
    sort_keys: true
    normalize_whitespace: true
  nix:
    strip_comments: true
    normalize_lets: false  # Nix let-in ordering is semantic
```

**Where it applies:**

| Collector | Strict Mode | Logical Mode |
|-----------|------------|--------------|
| Nix | Hash raw derivation output | Hash normalized closure manifest |
| OCI | Hash manifest digest (already canonical) | Same (manifests are canonical) |
| Helm | Hash raw chart files | Parse values.yaml + templates → canonical YAML |
| K8s | Hash raw manifests | Already canonical (sekiban changeset.rs) |
| Tofu | Hash raw state file | Parse HCL → canonical JSON |

### 1.4 Version-Pinned Attestations — IN PROGRESS (Sprint 1B)

**The Problem (Gemini's "State Synchronization" concern):** If inshou finishes a build and updates the approved root hash while sekiban is simultaneously processing a deployment for the previous version, the deployment is rejected even though it was valid at the time of submission.

**The Solution:** The SignatureGate CRD already contains `expected_signature` as a specific hash, not "latest." The deployment includes the commit SHA in its annotations. sekiban verifies against the gate that matches that commit, not against a global "current" hash.

**Enhancement:** Add a `signature_history` field to SignatureGate status:

```rust
pub struct SignatureGateStatus {
    pub phase: GatePhase,
    pub current_signature: Option<String>,
    // NEW: Versioned signature history for rollback tolerance
    pub signature_history: Vec<VersionedSignature>,
    // ...
}

pub struct VersionedSignature {
    pub signature: String,
    pub commit_ref: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}
```

**Gate evaluation change:** Accept any signature in `signature_history` that hasn't expired, not just `current_signature`. This eliminates flapping during rolling updates.

---

## Phase 2: Kernel Enforcement & Runtime (Week 5-12)

### 2.1 kanshi — eBPF Runtime Sentinel

**New repo:** `pleme-io/kanshi`

kanshi is a kernel-level enforcement agent that verifies binary integrity at exec time. It is the runtime complement to sekiban's admission-time verification.

#### Architecture

```
kanshi (Rust + eBPF)
  ├── src/
  │   ├── main.rs          — daemon entry point
  │   ├── verifier.rs      — BLAKE3 hash verification against tameshi signatures
  │   ├── policy.rs        — per-namespace enforcement policies
  │   ├── metrics.rs       — Prometheus metrics
  │   └── heartbeat.rs     — signed proof heartbeat emission
  ├── ebpf/
  │   ├── lsm_exec.rs      — bprm_check_security LSM hook (aya-rs)
  │   └── maps.rs          — BPF maps for hash cache + policy
  └── chart/kanshi/        — Helm chart (DaemonSet)
```

#### LSM Hooks vs. Tracepoints

**The Problem (Gemini's TOCTOU concern):** A tracepoint-based `execve` check has a race window between when the binary is hashed and when it's mapped into memory. An attacker using `userfaultfd` or a page-fault race can swap the binary after verification.

**The Fix:** Use LSM (Linux Security Module) hooks via aya-rs:

```rust
// ebpf/lsm_exec.rs
#[lsm(hook = "bprm_check_security")]
pub fn verify_exec(ctx: LsmContext) -> i32 {
    // The kernel holds a lock on the binary while this runs.
    // No TOCTOU race is possible.
    let bprm = unsafe { ctx.arg::<linux_binprm>(0) };
    let inode = bprm.file.f_inode;

    // Look up expected hash in BPF map
    let expected = match HASH_MAP.get(&inode) {
        Some(hash) => hash,
        None => return 0, // Not in policy — allow (fail-open for unmanaged binaries)
    };

    // Compute BLAKE3 of the binary pages (kernel holds the lock)
    let actual = blake3_inode(inode);

    if actual == *expected {
        0  // Allow
    } else {
        -1 // Deny (EPERM)
    }
}
```

**Key properties:**
- `bprm_check_security` is called with the binary locked — no race window
- The BPF map is populated by the userspace daemon from tameshi signatures
- Policy is per-namespace (K8s pod → cgroup → BPF map lookup)
- Fail-open for unmanaged binaries (configurable to fail-closed)

#### JIT Language Handling (Unresolved Friction)

**The Problem:** Node.js, Java, Python, and other JIT/interpreted languages don't have a static binary to hash at `execve` time. The `node` or `java` binary is always the same — the application code is loaded dynamically.

**Mitigation strategies (none are perfect):**

| Strategy | Coverage | Limitation |
|----------|----------|-----------|
| Hash the interpreter binary | Verifies runtime, not application | Application code is unverified |
| Hash the application directory (OCI layer) | Covered by tameshi OCI collector | Doesn't prevent runtime code injection |
| eBPF `file_open` hook on application paths | Verifies loaded files | Performance overhead, complex policy |
| Seccomp + read-only rootfs | Prevents modification post-deploy | Doesn't verify initial state |

**Recommended approach:** For JIT languages, rely on the OCI layer hash (tameshi) + read-only rootfs (K8s securityContext) + `file_open` LSM hook for critical paths. kanshi's `exec` verification is most valuable for compiled binaries (Go, Rust, C).

**Phase 2 honest assessment:** kanshi provides kernel-level enforcement for compiled binaries and runtime integrity for interpreters via file-open hooks, but it cannot provide the same bit-level guarantee for JIT languages that it provides for static binaries. This is documented, not hidden.

### 2.2 Proof Heartbeat System — Week 6-8

**The Problem (Gemini's CIRCIA concern):** CIRCIA requires 72-hour incident reporting with exploitation timeline evidence. A single deployment hash proves state at one point in time, not continuity.

**The Solution:** Every verification event emits a signed, immutable heartbeat.

#### Architecture

```
tameshi/src/heartbeat.rs (new module)
  ├── HeartbeatEntry — timestamp, verifier, result, signature, previous_hash
  ├── HeartbeatChain — append-only linked list via BLAKE3(prev_hash + entry)
  ├── HeartbeatEmitter trait — emit(entry) async
  └── Impls: StdoutEmitter, FileEmitter, HttpEmitter (to SIEM)

sekiban/src/heartbeat.rs
  └── Emits heartbeat on every admission decision (allow or deny)

kanshi/src/heartbeat.rs
  └── Emits heartbeat on every exec verification

kensa/src/heartbeat.rs
  └── Emits heartbeat on every compliance assessment
```

#### Heartbeat Entry

```rust
pub struct HeartbeatEntry {
    pub timestamp: DateTime<Utc>,
    pub verifier: String,           // "sekiban", "kanshi", "kensa", "inshou"
    pub event_type: HeartbeatEvent, // Admission, ExecVerify, ComplianceCheck, NixGate
    pub result: VerificationResult, // Pass, Fail, Skip
    pub resource: String,           // What was verified
    pub signature: Blake3Hash,      // Current expected signature
    pub entry_hash: Blake3Hash,     // BLAKE3(previous_hash + this entry)
    pub previous_hash: Blake3Hash,  // Chain link
    pub sequence: u64,              // Monotonic counter
}
```

#### Chain Properties

- **Append-only:** Each entry includes the hash of the previous entry
- **Tamper-evident:** Modifying any entry breaks the chain
- **Chronological:** Monotonic sequence numbers + UTC timestamps
- **Non-repudiable:** Each entry is signed by the verifier's identity

#### CIRCIA Deliverable

When CISA requests breach evidence, the heartbeat chain provides:

```
Entry #1:  2026-03-15T00:00:00Z  sekiban  Admission PASS  deployment/app  sig:blake3:abc...
Entry #2:  2026-03-15T00:05:00Z  kanshi   Exec PASS       /usr/bin/app    sig:blake3:abc...
Entry #3:  2026-03-15T00:10:00Z  kensa    Compliance PASS  NIST-moderate  sig:blake3:abc...
...
Entry #9847: 2026-03-17T14:32:00Z  sekiban  Admission PASS  deployment/app  sig:blake3:abc...
Entry #9848: 2026-03-17T14:33:00Z  kanshi   Exec FAIL       /tmp/backdoor   sig:NONE
                                                              ^^^ BREACH DETECTED
```

This proves the infrastructure was verified 9,847 times over 48 hours and remained untampered until the exact moment of the breach.

---

## Phase 3: Distributed Trust & Enterprise Scaling (Week 13-24)

### 3.1 Akeyless DFC Integration — Week 13-16

**The Problem (Gemini's "Root of Trust" concern):** kensa signs the approved Merkle root with a private key. If that key is a file on a CI server, an attacker who compromises the server can sign malicious roots.

**The Solution:** Integrate with Akeyless DFC (Distributed Fragments Cryptography). The signing key never exists in one piece.

#### How DFC Works

Instead of a single private key, the key is split into fragments distributed across multiple Akeyless Gateway nodes. Signing requires a threshold of fragments to cooperate — no single node (or attacker) can reconstruct the full key.

```
kensa signs Merkle root:
  1. Compute root hash locally
  2. Send signing request to Akeyless DFC API
  3. Gateway nodes each contribute a partial signature
  4. Partial signatures combine into a full signature
  5. Full key never exists in memory on any single machine
```

#### Implementation

```
tameshi/src/signing.rs (new module)
  ├── trait MerkleRootSigner { async fn sign(&self, root: &Blake3Hash) -> SignedRoot }
  ├── LocalSigner — file-based key (development/testing)
  ├── AkeylessDfcSigner — DFC-backed signing (production)
  └── SignedRoot { root: Blake3Hash, signature: Vec<u8>, signer_id: String }

kensa/src/signing.rs
  └── Uses MerkleRootSigner trait to sign compliance-approved roots
```

#### Trust Chain

```
Developer commits code
  → Nix builds hermetically (inshou verifies)
  → CI computes layer hashes (tameshi collectors)
  → Merkle root composed (tameshi)
  → kensa runs compliance tests
  → kensa signs approved root via Akeyless DFC
     └── Key never exists in one piece
  → sekiban stores SignedRoot in CRD
  → K8s deployment carries root annotation
  → sekiban webhook verifies signature + root
  → kanshi verifies binaries at exec time
```

### 3.2 CNI Integration Layer (Cilium/Calico) — Week 17-18

**Key insight:** kanshi is CNI-agnostic. It uses eBPF LSM hooks (CPU/memory path), not networking hooks (packet path). It works with any CNI — AWS VPC, Flannel, Calico, Cilium.

**However,** when Cilium is present, kanshi can provide enhanced observability by sharing attestation state with the Cilium BPF filesystem.

#### Without Cilium (Baseline — All CNIs)

kanshi operates standalone:
- LSM `bprm_check_security` hook for binary verification
- Own BPF maps for hash storage and policy
- Heartbeat chain for CIRCIA evidence
- Full attestation capability, zero CNI dependency

**Requirement:** Linux kernel 5.15+ with LSM BPF support (standard on all 2026 K8s distributions).

#### With Cilium (Enhanced — Automatic Detection)

kanshi detects Cilium by probing for pinned BPF maps at `/sys/fs/bpf/cilium_ipcache` (not by pod name — pod names can be spoofed):

```rust
pub struct CiliumDetector;

impl CiliumDetector {
    /// Detect Cilium by checking for its pinned BPF maps.
    /// This is unforgeable — only the real Cilium datapath creates these.
    pub fn detect() -> Option<CiliumIntegration> {
        let ipcache = Path::new("/sys/fs/bpf/cilium_ipcache");
        if ipcache.exists() {
            Some(CiliumIntegration {
                bpf_root: PathBuf::from("/sys/fs/bpf"),
                version: detect_cilium_version(),
            })
        } else {
            None
        }
    }
}
```

When Cilium is detected, kanshi enables:

| Feature | Baseline (any CNI) | With Cilium |
|---------|-------------------|-------------|
| Binary integrity (exec gate) | Yes | Yes |
| Process attestation hash | Yes | Yes |
| Network identity correlation | No | **Yes** — correlate process hash with Cilium identity |
| DNS audit trail | No | **Yes** — which attested process queried which domain |
| Egress policy enrichment | No | **Yes** — "allow only attested processes to reach external APIs" |
| CIRCIA 3D incident map | Process + time only | **Process + time + network destination** |

The Cilium integration is purely additive. kanshi never depends on Cilium for its core security guarantees.

### 3.3 Multi-Cluster Federation — Week 19-20

**Problem:** Enterprise deployments span multiple K8s clusters. Each cluster has its own sekiban instance, but they must share a consistent view of approved signatures.

**Solution:** Certification CRD replication via FluxCD/ArgoCD with signed attestation transfer.

### 3.4 Compliance Framework Expansion — Week 21-24

| Framework | Status | Priority |
|-----------|--------|----------|
| NIST 800-53 Rev 5 | Done (kensa) | — |
| OSCAL 1.1.2 | Done (kensa) | — |
| CIRCIA reporting | Phase 2 (heartbeat) | High |
| OMB M-22-18 attestation | Phase 1 (current) | High |
| SOC 2 Type II mapping | Planned | Medium |
| PCI DSS 4.0 mapping | Planned | Medium |
| FedRAMP mapping | Planned | High |
| DISA STIG mapping | Planned | Medium |

---

## Unresolved Friction

### 1. JIT Language Verification

kanshi's LSM exec hook provides strong guarantees for compiled binaries but weaker guarantees for interpreted/JIT languages. The OCI layer hash covers the initial filesystem state, but runtime code loading (eval, dynamic imports, classloading) is not verified. This is a fundamental limitation of file-based integrity — not a bug in the architecture.

**Mitigation:** Combine kanshi exec verification with read-only rootfs, Seccomp profiles, and `file_open` LSM hooks on critical application paths. Document the reduced guarantee for JIT workloads.

### 2. Canonicalization Semantic Equivalence

Two YAML files can produce identical K8s manifests through different Helm template logic. Canonical hashing of the template output (rather than input) would be ideal but requires running `helm template` during attestation, adding latency and complexity.

**Current approach:** Hash the chart input files in Strict mode. For Logical mode, hash the rendered output.

### 3. Nix Reproducibility Gaps

Nix derivations are reproducible by design, but some edge cases (timestamp-dependent builds, network fetches with floating hashes) can produce different outputs from the same input. tameshi relies on Nix's content-addressing — if the output hash changes, the signature changes.

**Mitigation:** Use `nix build --check` to verify reproducibility before attestation.

### 4. Key Rotation During Active Deployments

When the DFC signing key is rotated, in-flight deployments carry signatures from the old key. The heartbeat chain must record key rotation events so verifiers know which key was active at each point in time.

---

---

## Phase 4: Adversarial Hardening (Operational Reality)

> These items address the "Adversarial Architect" analysis — production-critical
> holes that must be closed before enterprise deployment. Full details in
> PROVISIONING_AND_REVOCATION_SPEC.md and PRODUCTION_HARDENING.md.

### CRITICAL: Configuration Integrity (Input Poisoning) — Week 25-26

**The Problem:** A verified binary fed malicious configuration is a verified weapon.
ConfigMaps, environment variables, and volume mounts are not currently attested.

**The Fix:** Hash all rendered Helm output (fully substituted manifests) into the
Merkle tree. If any configuration changes — `DB_HOST`, `runAsUser`, volume mounts,
resource limits — the Merkle root changes and sekiban rejects the deployment.

**Two Paths:**
- **Helm Rendered Hashing:** `helm template → YamlCanonicalizer → BLAKE3 → Merkle leaf`
- **Nix Derivation Hashing:** Already captures all config state for Nix-managed workloads

**NIST Controls:** CM-2 (Baseline), CM-3 (Change Control), CM-6 (Settings), SI-7 (Integrity)

**Status:** DONE — `tameshi/src/canonicalize.rs` provides the canonicalization layer.
Helm rendered hashing integration pending in `tameshi/src/collectors/helm.rs`.

### OCI Digest Check (Webhook Timeout Fix) — Week 25

**The Problem:** Hashing a 2GB image inside the webhook = 30s timeout = cluster rejection.

**The Fix:** sekiban verifies the OCI manifest digest annotation against a CI-produced
receipt, never pulling image bytes. Admission drops from ~30s to <50ms.

**Status:** Architecture defined in PROVISIONING_AND_REVOCATION_SPEC.md.

### Break-Glass Mechanism (Availability) — Week 26

**The Problem:** Fail-closed + network blip = entire cluster paralyzed.

**The Fix:** Ed25519-signed emergency bypass tokens with:
- Time-bounded validity (e.g., 4 hours)
- Namespace-scoped authorization
- Cryptographic audit trail (every break-glass logged to heartbeat chain)
- Automatic revocation when outage resolves

**Status:** DONE — `tameshi/src/signing.rs` implements `BreakGlassToken` with
`create_signed()`, `is_valid()`, `covers_namespace()`, `verify_signature()`. 19 tests.

### CEL Fail-Safe (Resilient Admission) — Week 27

**The Problem:** If sekiban webhook crashes, K8s API blocks all deployments.

**The Fix:** Three-tier defense:
1. **Tier 1:** sekiban webhook (full Merkle verification)
2. **Tier 2:** `ValidatingAdmissionPolicy` (CEL) — runs inside API server, survives webhook outages
3. **Tier 3:** Break-glass mechanism (emergency bypass)

**Status:** Architecture defined in PRODUCTION_HARDENING.md.

### Bootstrap Protocol (Self-Attestation) — Week 27

**The Problem:** Chicken-and-egg — sekiban needs attestation to deploy, but can't
enforce attestation before it's deployed.

**The Fix:** Static admission path — CI-embedded self-attestation ConfigMap, sekiban
verifies its own binary hash at startup before registering the webhook.

**Status:** Architecture defined in PRODUCTION_HARDENING.md.

### Multi-Architecture Attestations — Week 28

**The Problem:** x86_64 and ARM64 binaries have different hashes from the same source.

**The Fix:** Architecture-keyed binary map in the Merkle tree. OCI index manifest
(which contains per-platform digests) is the stable hash. sekiban verifies the
platform-specific digest matches the running node's architecture.

**Status:** Architecture defined in PRODUCTION_HARDENING.md.

### kanshi: Interpreter Gap (file_open hooks) — Week 29-30

**The Problem:** kanshi hashes binaries at `execve`, but Python/Node/Java attackers
swap script files — the interpreter binary is unchanged.

**The Fix:** Hook `file_open` and `mmap_file` LSM hooks in addition to
`bprm_check_security`. Three BPF maps:
- `tameshi_allow_map` — binary hashes
- `tameshi_content_map` — script/library hashes
- `tameshi_policy_map` — per-namespace enforcement

**Status:** Architecture defined in PROVISIONING_AND_REVOCATION_SPEC.md.

### kanshi: eBPF Portability (CO-RE) — Week 29

**The Problem:** Different kernels break eBPF programs.

**The Fix:** CO-RE (Compile Once — Run Everywhere) with bundled `vmlinux.h`.
Requires Linux 5.15+ with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
Graceful degradation: audit-only mode if BTF unavailable.

**Status:** Architecture defined in PROVISIONING_AND_REVOCATION_SPEC.md.

### Global Revocation Map (Zero-Day Kill-Switch) — Week 30

**The Problem:** Certified binary found to have a zero-day after deployment.

**The Fix:** `tameshi_revocation_list` BPF map in kanshi. Logic:
`exists_in_allow_map(hash) && !exists_in_revocation_map(hash)`.
CLI: `kensa revoke --hash blake3:... --reason "CVE-2026-XXXX"`.
Propagation: <100ms via ConfigMap watch or direct BPF map write.

**Status:** Architecture defined in PROVISIONING_AND_REVOCATION_SPEC.md.

### Audit-First (Shadow) Mode — Week 25 (DAY ONE DEPLOYMENT)

> **This is the single most important operational requirement for initial rollout.**
> Ship enforcement on day one = angry developers. Ship observation on day one = trust.

**The Problem:** Going "Fail-Closed" immediately will break developer workflows on
any false positive (whitespace change, key ordering, timing race). Developers will
hate the system before they understand it.

**The Fix: Telemetry-Only Mode ("Observation Mode")**

The webhook and eBPF sentinel run and verify everything, but they **do not block
execution**. Instead, they:
1. Log every verification result (allowed/denied/skipped) to the heartbeat chain
2. Emit Prometheus metrics for every would-be denial
3. Fire "Critical Alert" to a dashboard for every attestation failure
4. Record the exact reason each deployment would have been rejected

**The Pitch:** *"For the first 30 days, Tameshi runs in 'Observation Mode.' We
gather the data, prove the concept, and fix any false positives before we flip
the switch to 'Hard Enforcement.' This ensures 100% uptime while we build trust
with the dev teams."*

**Implementation:**

```yaml
# sekiban.yaml — enforcement mode
enforcement:
  mode: audit        # audit | enforce | break_glass_only
  audit:
    log_denials: true
    emit_metrics: true
    alert_on_deny: true
    dashboard_url: "https://grafana.internal/d/tameshi-audit"
```

```rust
// sekiban/src/webhook/admission.rs — mode-aware gating
pub enum EnforcementMode {
    /// Log everything, block nothing. Default for initial rollout.
    Audit,
    /// Full enforcement — deny on attestation failure.
    Enforce,
    /// Only enforce when break-glass is NOT active.
    BreakGlassOnly,
}
```

**Rollout timeline:**
- Week 0-4: Audit mode (observe, zero risk)
- Week 4-6: Enforce on staging only
- Week 6-8: Enforce on production (with break-glass ready)

**NIST Controls:** AU-2 (Audit Events), AU-6 (Audit Review), SI-4 (Information System Monitoring)

### Hubble Observability Integration — Week 31-32

**The Problem:** Security is invisible until it breaks. If Tameshi is just a silent
protector, no one sees the value. The CISO needs real-time proof.

**The Fix: Live Compliance Dashboard**

Every verification event across the ecosystem exports metrics to Prometheus/Grafana
and optionally to Cilium Hubble for network-correlated security observability.

**Metrics emitted by kanshi:**
```prometheus
# Binary verification at execve
tameshi_verification_total{app="auth-service", arch="x86_64", result="allowed"} 42
tameshi_verification_total{app="auth-service", arch="x86_64", result="denied"} 0

# Per-namespace compliance percentage
tameshi_compliance_ratio{namespace="production"} 1.0
tameshi_compliance_ratio{namespace="staging"} 0.95

# Heartbeat chain health
tameshi_heartbeat_chain_length{component="sekiban"} 9847
tameshi_heartbeat_chain_last_entry_seconds{component="sekiban"} 2.3

# Break-glass events (should be zero in normal operation)
tameshi_break_glass_active{namespace="production"} 0
```

**Grafana Dashboard Panels:**
1. **Cluster Integrity Score** — percentage of pods running in "Proven State"
2. **Verification Timeline** — real-time stream of allow/deny decisions
3. **Compliance Heatmap** — per-namespace compliance status
4. **Heartbeat Chain Health** — chain length, last entry age, integrity status
5. **Alert History** — break-glass events, revocations, attestation failures

**Hubble Integration (Cilium):**
- kanshi annotates process verification results on Cilium network flows
- Hubble UI shows which network connections originate from attested binaries
- Unattested processes highlighted in red on the network topology graph

**The Pitch:** *"Tameshi provides a 'Live Compliance Dashboard.' At any moment, the
CISO can see exactly what percentage of the cluster is currently running in a
'Proven State.' We turn 'Trust' into a real-time graph."*

### Self-Healing Attestation (Auto-Rollback) — Week 33-34

**The Problem:** If a binary fails verification at runtime, just killing it
(`SIGKILL`) causes a service outage. Killing is not healing.

**The Fix: Tameshi Controller — Automatic Rollback to Last Known Good**

When kanshi detects a runtime integrity violation, it doesn't just kill the process.
It sends an event to a dedicated "Tameshi Controller" that:

1. Identifies the Deployment/StatefulSet/DaemonSet that owns the pod
2. Looks up the last-known-good Merkle root in the heartbeat chain
3. Triggers `kubectl rollout undo` to the last verified revision
4. Emits a heartbeat entry: `SelfHeal` event type
5. Fires a PagerDuty/Slack alert with full forensic context

**Architecture:**

```
kanshi detects mutation
    │
    ▼
K8s Event: TameshiIntegrityViolation
    │
    ▼
Tameshi Controller (new sekiban controller)
    │
    ├── Look up last-known-good revision (heartbeat chain)
    ├── kubectl rollout undo deployment/<name> --to-revision=<good>
    ├── Emit heartbeat: SelfHeal event
    └── Alert: "Pod auto-reverted due to integrity violation"
```

**Safeguards:**
- Rate limiting: max 3 auto-rollbacks per deployment per hour
- Escalation: if rollback fails, page on-call SRE
- Audit: every auto-rollback recorded in heartbeat chain with full context
- Configurable: opt-in per namespace (`tameshi.pleme.io/auto-heal: "true"`)

**The Pitch:** *"Tameshi isn't just a gatekeeper; it's a self-healing immune system.
If a pod is tampered with, the cluster automatically reverts to the last
mathematically proven version without human intervention."*

**NIST Controls:** IR-4 (Incident Handling), IR-5 (Incident Monitoring),
SI-7(5) (Automated Response to Integrity Violations)

---

## Phase 5: Advanced Threat Model (Research Roadmap)

> These items address state-of-the-art threats at the "Security Researcher" level.
> Not required for initial production deployment but planned for future phases.

### TPM 2.0 Remote Attestation (Root of Trust) — Phase 5

**The Problem:** If the node is compromised at firmware level (BIOS/UEFI/bootloader),
the kernel can lie about eBPF program status.

**The Fix:** TPM 2.0 remote attestation — node proves hardware integrity before
receiving Merkle root keys. Measured boot chain: TPM PCR values for BIOS, bootloader,
kernel, and kanshi eBPF program.

**NIST Controls:** SC-51 (Hardware-Rooted Integrity), SI-7(1) (Integrity Checks)

### Continuous Runtime Integrity (Memory Sampling) — Phase 5

**The Problem:** Binary verified at load-time, but memory exploit (buffer overflow,
ROP chain) modifies program behavior in RAM.

**The Fix:** kanshi periodically re-hashes `.text` sections of running processes
via eBPF, comparing against load-time hashes. Configurable sampling rate per namespace.

**NIST Controls:** SI-7(6) (Cryptographic Protection), SI-16 (Memory Protection)

### Dynamic Secret Policy Drift Detection — Phase 5

**The Problem:** Akeyless dynamic secret rotates values, but the access policy
(path + target + role) could drift.

**The Fix:** Periodic re-attestation of Akeyless policy metadata. Heartbeat chain
records policy hash at each verification. Drift alert if policy hash changes
between verifications.

---

## Phase 6: Micro-Fracture Hardening (Year-One Production Survival)

> These items address the "Quantum of Solace" edge cases — problems that only
> surface after a system survives its first year in production and faces an
> adversary who has **also read your documentation**.

### Identity Masquerade (Contextual Binding) — Phase 6

**The Problem:** Two binaries are both "Proven" — `auth-service` and
`metrics-exporter`. An attacker takes the proven hash of `auth-service` and
launches a malicious process that claims to be `metrics-exporter`.

**The Hole:** The attestation is `Hash(Binary)`, not `Hash(Binary + Context)`.
A "good" binary used in the "wrong" place is still a vulnerability.

**The Fix:** Bind the Merkle Root to the Akeyless Identity.

```rust
// The attestation must be:
Hash(Binary + K8s_ServiceAccount + Akeyless_Role + Namespace)
// NOT just:
Hash(Binary)
```

**Implementation:**
- `tameshi/src/signature.rs` — add `ContextualBinding` struct with
  `service_account`, `namespace`, `akeyless_role` fields
- `sekiban/src/webhook/admission.rs` — verify the binary hash + context match
  the incoming pod's service account and namespace
- `kanshi/src/verifier.rs` — BPF map keyed by `(inode, cgroup_id)` not just `inode`

**Result:** Even if a binary is "proven," it is only allowed to run if its
Identity Context matches the signature.

### Supply Chain Pre-Commit (Developer Environment Attestation) — Phase 6

**The Problem:** If a developer's laptop is compromised and an attacker injects
a backdoor *before* `git commit`, Tameshi will faithfully hash the backdoored
code, the tests will "pass" (because the attacker modified the tests too), and
Tameshi will sign it.

**The Fix:** Move the Root of Trust further back — attest the developer environment.

Use Nix to ensure the developer is working in a "Locked Down Shell":
- The editor, compiler, and linting tools are themselves "Proven" versions
- The development shell derivation is hashed as an additional Merkle leaf
- The commit includes a `devenv-attestation` annotation proving the shell was clean

**Implementation:**
- `inshou` — new `hash --devenv` command that hashes the developer's Nix shell
- `tameshi/src/collectors/` — new `DevenvCollector` that attests the build environment
- CI: verify the devenv attestation annotation on every commit
- `blackmatter-shell` — emit attestation hash on shell entry

**Limitation (documented honestly):** This requires all developers to use
Nix-managed shells. For teams not on Nix, this is mitigated by CI-only
attestation (the CI environment IS Nix-managed).

### eBPF Map Exhaustion (Resource DoS) — Phase 6

**The Problem:** eBPF maps have a fixed size (defined at load-time). If the cluster
grows to 10,000+ unique microservices, or an attacker floods the system with
garbage binaries forcing new hash entries, the map hits its limit.

**The Risk:** Map full → either fail-closed (block everything) or fail-open
(allow everything), depending on kernel behavior.

**The Fix:** LRU Maps + Generational Garbage Collection.

```rust
// kanshi-ebpf — use LRU hash maps instead of fixed hash maps
// BPF_MAP_TYPE_LRU_HASH automatically evicts oldest, least-used entries
```

- `kanshi-common/src/lib.rs` — use `BPF_MAP_TYPE_LRU_HASH` for allow/revocation maps
- Set map size to 2^20 (1M entries) with LRU eviction
- kanshi userspace daemon monitors map utilization via BPF map stats
- Alert at 80% utilization: `tameshi_bpf_map_utilization{map="allow"} > 0.8`
- Generational GC: periodically walk the map and remove entries for deleted pods

### Time-Drift Attestation (Compliance TTL) — Phase 6

**The Problem:** A binary is certified against NIST standards today. Is that
certification valid in 5 years? Standards change. Cryptography weakens. A
"one-and-done" compliance check is a ticking time bomb.

**The Fix: Short-Lived Attestations with Mandatory Re-Verification.**

```rust
// kensa compliance result with TTL
pub struct ComplianceAttestation {
    pub hash: Blake3Hash,
    pub certified_at: DateTime<Utc>,
    pub ttl_days: u32,        // Default: 30 days
    pub baseline_version: String, // e.g., "NIST-800-53-rev5-2024"
}
```

- Every 30 days, kensa must re-verify the Merkle root against the current
  compliance baseline
- If the standard has changed (e.g., "RSA-2048 is no longer allowed"),
  re-verification fails and the pod is marked for mandatory rolling update
- Heartbeat chain records re-verification events
- Configurable TTL per namespace: critical namespaces = 7 days, dev = 90 days

**Result:** Compliance isn't a "one-and-done" event — it's a heartbeat.

**NIST Controls:** CA-2 (Security Assessments), CA-7 (Continuous Monitoring)

---

## Phase 7: Operational Combat Hardening (Adversary-Who-Read-Your-Docs)

> These holes only matter when facing an adversary sophisticated enough to
> understand the Tameshi architecture and exploit its operational seams.

### Webhook Ordering Race (Mutation-After-Validation) — Phase 7

**The Problem:** K8s allows multiple Mutating Webhooks (Istio, Linkerd, Datadog)
to modify a Pod **before** it starts. If sekiban (Validating) runs before a
Mutating Webhook, the mutation happens **after** verification. Istio injects a
sidecar container that Tameshi never inspected.

**The Fix:** Configure sekiban's webhook with `reinvocationPolicy: IfNeeded`.

```yaml
# sekiban ValidatingWebhookConfiguration
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: sekiban-integrity-gate
webhooks:
- name: integrity.sekiban.pleme.io
  reinvocationPolicy: IfNeeded   # <-- CRITICAL
  failurePolicy: Fail
  sideEffects: None
```

This tells K8s: *"If any other webhook changes this Pod after I verified it,
invoke me again."* Tameshi is always the **final judge**.

**Implementation:**
- `sekiban/chart/sekiban/templates/webhook.yaml` — add `reinvocationPolicy: IfNeeded`
- `sekiban/src/webhook/admission.rs` — handle re-invocation (idempotent verification)
- Track re-invocation count in metrics: `sekiban_admission_reinvocations_total`

**NIST Controls:** CM-3 (Configuration Change Control)

### Ephemeral Container Backdoor (kubectl debug) — Phase 7

**The Problem:** K8s 1.25+ allows `kubectl debug` to inject an Ephemeral Container
into a **running** Pod. An attacker with `patch` permissions can inject a malicious
shell. Since the Pod is already running, the initial admission check is bypassed.

**The Fix:** kanshi watches for **any** new process in the kernel, regardless of
whether it was present at Pod startup.

**Implementation:**
- kanshi `bprm_check_security` hook fires on **every** `execve`, including from
  ephemeral containers started after pod admission
- If a process starts from an ephemeral container source (detected via cgroup path
  containing `/ephemeral/`), kanshi checks for a "Debug Attestation" signed by
  a Senior SRE via Akeyless
- No signature → `SIGKILL` immediately + heartbeat entry + PagerDuty alert

```yaml
# kanshi policy for ephemeral containers
policy:
  ephemeral_containers:
    require_attestation: true
    allowed_signers:
      - "sre-oncall@pleme.io"
      - "security-team@pleme.io"
    action_on_violation: kill  # kill | audit | alert
```

**sekiban enhancement:**
- `sekiban/src/webhook/admission.rs` — also gate `CONNECT` operations for
  ephemeral container subresources (`pods/ephemeralcontainers`)
- Add to `TargetResource` spec: `subresources: ["ephemeralcontainers"]`

**NIST Controls:** AC-6 (Least Privilege), SI-4 (System Monitoring)

### Dirty Write — mmap W^X Enforcement — Phase 7

**The Problem:** An attacker doesn't replace the binary file. They wait for it
to be loaded into memory, then use `mmap` with `PROT_WRITE` to overwrite the
program's instructions in RAM. The file on disk passes the hash check, but the
code in memory is poisoned.

**The Fix:** W^X (Write XOR Execute) enforcement at the kernel level via eBPF.

```c
// kanshi-ebpf — LSM mprotect hook
SEC("lsm/file_mprotect")
int tameshi_mprotect_check(struct vm_area_struct *vma, unsigned long reqprot) {
    // Rule: Once a page is marked Executable, it can NEVER be made Writable
    if ((vma->vm_flags & VM_EXEC) && (reqprot & PROT_WRITE)) {
        emit_wx_violation_event(vma);
        return -EPERM;
    }
    // Rule: Once a page is marked Writable, it can NEVER be made Executable
    if ((vma->vm_flags & VM_WRITE) && (reqprot & PROT_EXEC)) {
        emit_wx_violation_event(vma);
        return -EPERM;
    }
    return 0;
}
```

**Result:** In-memory patching becomes mathematically impossible on tameshi-protected
nodes. This is the same enforcement that OpenBSD's `W^X` policy provides, but
enforced at the eBPF level without requiring kernel recompilation.

**Exceptions:** JIT engines (V8, JVM HotSpot) legitimately need W+X pages.
Mitigated via:
- Per-cgroup exception list in the BPF policy map
- JIT processes rely on OCI layer hash + read-only rootfs instead of W^X

**NIST Controls:** SI-16 (Memory Protection), SC-39 (Process Isolation)

### Registry Mirror Spoof (Immutable Digest Referencing) — Phase 7

**The Problem:** Companies use internal registry mirrors (Artifactory, Harbor).
If an attacker compromises the mirror, they can replace the image bytes but keep
the OCI tag (`v1.0.0`) the same. The Helm chart says `v1.0.0`, but the bytes
behind that tag are different.

**The Fix:** Tameshi refuses to deploy any image referenced by a mutable tag.
All images MUST use the SHA-256 digest.

```yaml
# REJECTED by sekiban:
image: my-app:v1.0.0          # Mutable tag — DENIED

# ACCEPTED by sekiban:
image: my-app@sha256:abcdef... # Immutable digest — ALLOWED
```

**Implementation:**
- `sekiban/src/webhook/admission.rs` — new validation: reject pods where any
  container image uses a tag reference instead of a digest reference
- Configurable per namespace: `tameshi.pleme.io/require-digest: "true"`
- Nix already produces digest-only references by default (deterministic outputs)
- Helm: use `--set image.tag=@sha256:...` or generate digest refs in CI

**Metrics:**
- `sekiban_tag_reference_rejections_total{namespace, image}` — track how many
  deployments are rejected for using mutable tags

**NIST Controls:** SA-10 (Developer Configuration Management),
SI-7 (Software Integrity)

---

## Phase 8: Deep Kernel & Forensic Hardening

> These holes require an adversary with root access, NTP compromise capability,
> or the ability to generate thousands of requests per second. This is the
> "nation-state" tier of the threat model.

### Symlink Switcheroo (Filesystem TOCTOU) — Phase 8

**The Problem:** sekiban verifies the binary at `/usr/bin/app`. Between
verification and execution, an attacker with filesystem access swaps the path
with a symlink to a malicious binary. Time-Of-Check-To-Time-Of-Use (TOCTOU).

**The Fix:** Use `O_PATH` + `fexecve` pattern.

Instead of executing a path (string), the kernel opens a File Descriptor (FD),
verifies the hash of the FD, and executes that specific FD. Once an FD is open,
the file it points to cannot be swapped out from under it.

**Implementation:**
- kanshi's `bprm_check_security` LSM hook already operates at the kernel level
  where the binary is **locked** by the kernel during exec — this is why we chose
  LSM over userspace verification. The TOCTOU window is zero.
- Additional defense: `file_open` hook resolves symlinks and verifies the **target**
  inode, not the symlink inode
- Metric: `tameshi_symlink_resolution_total{result="resolved|blocked"}`

**Note:** This is already partially mitigated by the LSM hook architecture.
The kernel holds a reference to the binary during `bprm_check_security`, making
filesystem swaps impossible during the check. This item documents the guarantee
and adds symlink-specific tracking.

### Time-Travel Attack (NTP/Clock Skew) — Phase 8

**The Problem:** Tameshi uses TTLs and revocation timestamps. If an attacker
compromises NTP on K8s nodes, they can "roll back the clock" — making a revoked
binary appear valid by tricking the node into thinking it's last week.

**The Fix:** Trusted Monotonic Clock.

```rust
// kanshi — use kernel monotonic clock, not wall clock
// bpf_ktime_get_ns() returns nanoseconds since boot — cannot be set back
let monotonic_ns = unsafe { bpf_ktime_get_ns() };
```

- kanshi uses `bpf_ktime_get_ns()` (system uptime) for TTL checks, not wall clock
- Heartbeat chain entries include **both** wall clock AND monotonic timestamp
- If wall clock goes backwards relative to monotonic clock → alert:
  `tameshi_clock_skew_detected{node="..."}`
- Akeyless Trusted Time Service heartbeat: node periodically verifies its wall
  clock against Akeyless, alerting on drift > 5 seconds

**NIST Controls:** AU-8 (Time Stamps), SC-45 (System Time Synchronization)

### Log-Erasure Hole (CIRCIA Chain Integrity) — Phase 8

**The Problem:** If an attacker gets root on a node, they delete `/var/log/`
or kill the logging daemon. The breach happens, but the proof that Tameshi was
working is gone. No report for CISA.

**The Fix:** Streaming Immutable Telemetry.

- Tameshi does **not** rely on local file logs as the primary evidence store
- The heartbeat chain is streamed in real-time to an external, append-only store:
  - Primary: Akeyless Log Vault (signed protobuf messages)
  - Secondary: S3 bucket with object lock (WORM)
  - Tertiary: Local file (defense-in-depth only)
- Every heartbeat entry contains its Merkle-proof link to the previous entry
- If a log entry is missing, the chain is **broken** — the gap is cryptographic
  proof of tampering, and its exact timestamp is known

**Implementation:**
- `tameshi/src/heartbeat.rs` — `S3Emitter` implementation (already architectured)
- `HttpEmitter` streams to Akeyless Log Vault in real-time
- `FileEmitter` is defense-in-depth, not primary evidence
- Chain verification: `verify_integrity()` detects any gap or tampering

**NIST Controls:** AU-9 (Protection of Audit Information),
AU-10 (Non-Repudiation), AU-4 (Audit Storage Capacity)

### Resource Exhaustion (Bloom Filter Pre-Verification) — Phase 8

**The Problem:** An attacker floods the K8s API with thousands of dummy Pod
requests per second. sekiban spends 100% CPU verifying fake hashes. The security
tool becomes a DoS weapon against the cluster.

**The Fix:** Bloom Filter pre-verification.

```rust
// sekiban — Bloom filter for O(1) rejection of unknown hashes
use probabilistic_collections::bloom::BloomFilter;

struct AdmissionCache {
    /// Bloom filter: "definitely NOT in allowed set" check in ~100ns
    bloom: BloomFilter<Blake3Hash>,
    /// Verified cache: recent successful verifications (moka TTL cache)
    verified: moka::sync::Cache<Blake3Hash, bool>,
}

impl AdmissionCache {
    fn quick_reject(&self, hash: &Blake3Hash) -> bool {
        // If bloom says "not present" → definitely reject (zero false negatives)
        !self.bloom.contains(hash)
    }
}
```

**Flow:**
1. Request arrives → check Bloom filter (~100ns)
2. Bloom says "not present" → **reject immediately** (no crypto)
3. Bloom says "maybe present" → check moka cache (~1us)
4. Cache miss → full Merkle verification (~50ms)

**Result:** 99% of garbage requests rejected in nanoseconds without touching
the crypto stack. The remaining 1% (Bloom false positives) hit the full path.

**Implementation:**
- `sekiban/Cargo.toml` — add `probabilistic-collections` or custom Bloom filter
- `sekiban/src/webhook/admission.rs` — pre-check before `evaluate_gate()`
- Bloom filter rebuilt on gate reconciliation (when allowed hashes change)
- Metric: `sekiban_bloom_filter_rejections_total`

**NIST Controls:** SC-5 (Denial of Service Protection)

---

## Phase 8b: Service Mesh & API Trust Hardening

> These holes target the trust boundaries between Tameshi and its dependencies:
> service meshes, host kernel pseudo-filesystems, and the Akeyless API itself.

### Sidecar Injection Race (Istio/Linkerd MITM) — Phase 8b

**The Problem:** Service meshes inject sidecar containers via Mutating Admission
Webhooks. If their webhook runs **after** sekiban's Validating Webhook, a sidecar
is added that Tameshi never verified. An attacker who compromises the Istio control
plane injects a malicious sidecar into a "Proven" Pod.

**The Fix:** `reinvocationPolicy: IfNeeded` (already defined in Phase 7 Webhook
Ordering). Additionally:

- sekiban must **re-hash the entire Pod spec** on reinvocation, not just check annotations
- The full container list (including injected sidecars) must match the attested
  Helm rendered manifest
- If any container is present that was NOT in the original Merkle tree → deny

**Implementation:**
- `sekiban/src/webhook/admission.rs` — on reinvocation, compute canonical hash of
  the full pod spec (all containers, init containers, volumes) and compare against
  the `helm-rendered` Merkle leaf
- New annotation: `sekiban.pleme.io/expected-container-count` — quick sanity check
  before full hash comparison
- Metric: `sekiban_sidecar_injection_detected_total{namespace, mesh}`

**NIST Controls:** CM-3 (Configuration Change Control), SI-7 (Integrity)

### Procfs/Sysfs Write-Back (Kernel Escape) — Phase 8b

**The Problem:** A Pod running with `privileged: true` or `CAP_SYS_ADMIN` can
write to `/proc/sys/kernel/core_pattern` or disable kanshi's eBPF programs
directly via `/sys/fs/bpf/`.

**The Fix:** LSM Masking via eBPF.

```c
// kanshi-ebpf — block writes to sensitive host paths
SEC("lsm/inode_permission")
int tameshi_inode_guard(struct inode *inode, int mask) {
    // If the process is in a tameshi-attested cgroup AND
    // the target path is /proc/sys/* or /sys/fs/bpf/* → DENY
    if (is_attested_cgroup() && is_sensitive_path(inode)) {
        if (mask & MAY_WRITE) {
            return -EPERM;
        }
    }
    return 0;
}
```

**Rule:** *"I don't care who you are — you stay in your sandbox."*

Even root-privileged containers cannot:
- Write to `/proc/sys/kernel/core_pattern` (code execution via core dumps)
- Unload eBPF programs via `/sys/fs/bpf/`
- Modify `/sys/kernel/security/` (LSM bypass)
- Mount host paths that weren't in the attested manifest

**NIST Controls:** AC-6(9) (Auditing Use of Privileged Functions), SC-39 (Process Isolation)

### Akeyless API Spoof (MITM Prevention) — Phase 8b

**The Problem:** When sekiban or kensa calls the Akeyless API for hash verification
or DFC signing, a DNS poisoning or MITM attack could return a fake Merkle root
matching the attacker's binary.

**The Fix:** Certificate Pinning + mTLS.

1. **Certificate Pinning:** The Akeyless root CA hash is compiled into the
   Tameshi Rust binary at build time (via Nix). No reliance on the system CA store.

```rust
// tameshi/src/akeyless_client.rs — certificate pinning
const AKEYLESS_CA_HASH: &str = "sha256:EXPECTED_CA_FINGERPRINT";

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)  // Don't trust system CAs
        .add_root_certificate(pinned_akeyless_ca())
        .build()
        .expect("failed to build pinned HTTP client")
}
```

2. **mTLS:** Every connection to Akeyless is mutually authenticated:
   - Pod proves its identity to Akeyless (client certificate from K8s)
   - Akeyless proves its identity to the Pod (pinned server certificate)
   - Neither side can be spoofed by a local network attacker

3. **Nix Integration:** The Akeyless CA fingerprint is a Nix build input.
   If the CA changes, the Nix derivation hash changes, the Merkle root changes,
   and all attestations must be re-signed. This makes CA rotation an audited,
   intentional operation.

**NIST Controls:** IA-5 (Authenticator Management), SC-8 (Transmission Confidentiality),
SC-23 (Session Authenticity)

---

## Phase 9: Cryptographic & Kernel Edge Cases

> These are the "Unit 8200" tier holes — timing side-channels, identity confusion,
> IPC poisoning, and eBPF verifier limits. Addressing these leverages the full
> Akeyless architecture and product map.

### Constant-Time Comparison (Timing Side-Channel) — Phase 9

**The Problem:** Standard byte comparison (`if hash_a == hash_b`) exits on the
first mismatched byte. An attacker can measure nanosecond-level timing differences
to brute-force one byte at a time, eventually "guessing" a valid Merkle root.

**The Fix:** Use the `subtle` crate for constant-time comparison.

```rust
// tameshi/src/hash.rs — constant-time PartialEq
use subtle::ConstantTimeEq;

impl PartialEq for Blake3Hash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
```

- All hash comparisons across tameshi, sekiban, kensa, inshou, and kanshi MUST
  use constant-time comparison
- `subtle` crate: zero-overhead, no branching, immune to timing attacks
- This is a **one-line fix** with ecosystem-wide impact

**Akeyless Leverage:** Akeyless DFC signing inherently uses constant-time operations
in its threshold cryptography. By using `subtle` on our side, the entire chain
from signing to verification is timing-safe.

**NIST Controls:** SC-13 (Cryptographic Protection)

### Confused Deputy (Scope-Bound Attestation) — Phase 9

**The Problem:** App-A accesses the credit card database. App-B accesses public
metrics. Both are "Proven." An attacker exploits App-B to request App-A's secret.
The Merkle proof only checks the binary, so the system says: "Yes, this is a
proven binary (App-B), here is App-A's secret."

**The Fix:** Cryptographic binding of scope — the Merkle leaf is:
`Hash(Binary + K8s_Namespace + ServiceAccount_ID)`

Akeyless MUST only release the secret if the **entire tuple** matches:

```yaml
# Akeyless Access Role binding (enforced by tameshi)
access_role:
  binary_hash: "blake3:abc..."
  namespace: "production"
  service_account: "auth-service-sa"
  # Akeyless will ONLY release secrets if ALL three match
```

**Akeyless Leverage:** This maps directly to Akeyless Access Roles + Sub-Claims.
The Akeyless K8s auth method already binds to namespace + service account. Tameshi
adds the binary hash as an additional claim, creating a three-factor attestation:
1. **What** is running (binary hash)
2. **Where** it's running (namespace)
3. **Who** it's running as (service account)

**Relationship to Phase 6 Identity Masquerade:** This is the implementation
detail for the contextual binding architecture defined in Phase 6. Phase 6
defines the concept; Phase 9 defines the Akeyless integration path.

**NIST Controls:** AC-3 (Access Enforcement), AC-6 (Least Privilege),
IA-2 (Identification and Authentication)

### IPC Poisoning (Shared Memory Hole) — Phase 9

**The Problem:** Two pods on the same node: one is Tameshi-protected ("Proven"),
the other is a legacy pod. If they share a volume (`emptyDir`) or use IPC
(shared memory), the legacy pod can write malicious data that the proven pod reads.

**The Fix:** Memory Namespace Isolation via eBPF.

kanshi enforces that any pod with a Tameshi attestation **cannot** mount shared
volumes or use IPC with pods that lack the same attestation level.

```c
// kanshi-ebpf — IPC isolation hook
SEC("lsm/ipc_permission")
int tameshi_ipc_check(struct kern_ipc_perm *ipcp, short flag) {
    u64 caller_cgroup = get_current_cgroup_id();
    u64 target_cgroup = /* from ipcp */;

    u8 *caller_attested = bpf_map_lookup_elem(&tameshi_policy_map, &caller_cgroup);
    u8 *target_attested = bpf_map_lookup_elem(&tameshi_policy_map, &target_cgroup);

    // If caller is attested but target is NOT → deny IPC
    if (caller_attested && !target_attested) {
        return -EPERM;
    }
    return 0;
}
```

**Result:** A "Cryptographic Air-Gap" inside the Linux kernel. Proven pods
cannot be data-poisoned by unproven neighbors.

**Akeyless Leverage:** Akeyless dynamic secrets for IPC channels — the shared
secret for inter-pod communication is only released if both pods pass attestation.

**NIST Controls:** SC-39 (Process Isolation), SC-4 (Information in Shared System Resources)

### eBPF Verifier Complexity (Map-Driven Architecture) — Phase 9

**The Problem:** As we add LSM hooks (bprm_check, file_open, mprotect, ipc_permission),
the eBPF program grows in complexity. The Linux BPF verifier limits programs to
~1 million instructions. If kanshi gets too complex, the kernel refuses to load it.

**The Fix:** Map-Driven Logic — keep the eBPF program as a simple "router" that
looks up decisions in hash maps.

```
eBPF Program (< 100 instructions per hook):
  1. Read inode/cgroup from context
  2. Look up decision in BPF map
  3. Return allow/deny

All complexity lives in USERSPACE:
  - Policy evaluation → populate BPF maps
  - Merkle verification → populate BPF maps
  - Revocation checks → populate BPF maps
  - W^X rules → populate BPF maps
```

**Architectural Principle:** The eBPF program is a **data plane** (fast, simple,
BPF-verified). The userspace daemon is the **control plane** (complex, testable,
not instruction-limited). This is the same split used by Cilium, Falco, and
every production eBPF project.

**Implementation:**
- Each LSM hook is a separate, small eBPF program (not one monolithic program)
- Tail calls between programs if needed (extends instruction budget)
- All policy logic in userspace kanshi daemon, pushed to maps
- CI: verify BPF program loads on target kernel as part of test suite

**Akeyless Leverage:** Akeyless Access Policies map cleanly to BPF map entries.
The userspace daemon translates Akeyless role bindings into BPF map key/value
pairs, keeping the eBPF program minimal.

---

---

## Phase 10: Edge, IoT & Robotics (Cyber-Physical Systems)

> In the cloud, an "infection" means a data leak. In robotics, an infection means
> a 500lb industrial arm moving in a direction it wasn't supposed to. Tameshi's
> architecture extends naturally to cyber-physical systems.

### ROS2/DDS Node Attestation — Phase 10

**The Problem:** Robots run ROS2 with DDS (Data Distribution Service) for inter-node
communication. An attacker can inject "Ghost Nodes" that publish to sensitive topics
like `/cmd_vel` (motor commands), `/joint_states`, or `/localization`.

**The Fix:** kanshi watches DDS sockets. Only nodes whose binary hashes are in the
Merkle tree can publish to safety-critical topics.

**Implementation:**
- kanshi eBPF `socket_sendmsg` hook — intercept DDS UDP multicast traffic
- BPF map: `publisher_hash(inode) → allowed_topics(bitmap)`
- If a process publishes to `/cmd_vel` without being in the allow map → drop packet
- Heartbeat records all DDS publish attempts (attested or not)

**NIST IR 8259 compliance:** Device Integrity + Authenticated Updates

### Deterministic Edge Devices (Nix + Immutable Rootfs) — Phase 10

**The Problem:** Field robots suffer "Configuration Drift" — a technician tweaks
a PID controller value, and the robot becomes unstable. Or an attacker replaces
`motor_params.yaml` with poisoned values.

**The Fix:** The entire robot filesystem — drivers, configs, ROS graph — is a
single immutable Nix derivation hash. If ANY file changes, the Merkle root breaks,
and the device enters **Safety-Lock mode** before actuators engage.

**Implementation:**
- inshou runs on the robot's boot sequence (NixOS on ARM64)
- Verifies the system profile hash against the fleet's Merkle tree
- If mismatch → refuse to start actuator control loops
- Over-the-air updates are Nix profile switches (atomic, rollback-safe)

### Hardware-Bound Identity (TPM for Edge/IoT) — Phase 10

**The Problem:** Robots are physically "out there." An attacker can steal the device,
open it, and extract keys from the filesystem.

**The Fix:** Bind the Tameshi Merkle tree to the TPM 2.0 chip on the device.

**Implementation:**
- TPM PCR[14] extended with kanshi eBPF program hash at boot
- Akeyless releases fleet credentials ONLY after TPM remote attestation
- Device won't decrypt mission parameters unless hardware integrity is verified
- Physical tamper evidence: opening the chassis triggers TPM PCR change

### Fleet-Scale Attestation — Phase 10

**The Problem:** A fleet of 10,000 edge devices needs centralized attestation
management with disconnected operation support.

**The Fix:** Hierarchical Merkle trees.

```
Fleet Root
├── Region A Root
│   ├── Device 001 Merkle
│   ├── Device 002 Merkle
│   └── ...
├── Region B Root
│   └── ...
└── Fleet Compliance Hash
```

- Each device carries its own Merkle tree + the region root hash
- Offline devices verify against cached region root
- When reconnected, sync against fleet root via Akeyless

### Regulatory Hooks

| Regulation | Requirement | Tameshi Coverage |
|-----------|------------|-----------------|
| **NIST IR 8259** | Device Integrity | kanshi eBPF + TPM binding |
| **NIST IR 8259** | Authenticated Updates | Nix atomic profile switches + Merkle verification |
| **EU CRA** (Article 13) | Vulnerability handling for IoT | Global revocation map (<100ms) |
| **EU CRA** (Annex I) | Secure-by-default for products with digital elements | Immutable Nix rootfs + Safety-Lock mode |
| **IEC 62443** | Industrial cybersecurity | kanshi DDS attestation for OT networks |
| **ISO/SAE 21434** | Automotive cybersecurity | Fleet-scale attestation for connected vehicles |

---

## Summary Timeline (Updated)

| Week | Phase | Key Deliverables | Status |
|------|-------|-----------------|--------|
| 1-2 | 1.3 | Canonicalization layer (Strict/Logical modes) | DONE |
| 2-3 | 1.4 | Version-pinned attestations (signature_history) | DONE |
| 3 | 3.1 | Heartbeat chain (append-only BLAKE3 linked) | DONE |
| 3 | 3.3 | DFC Signing + Break-Glass tokens | DONE |
| 3-4 | 1 | Production hardening (kensa metrics, error classification) | DONE |
| 5-8 | 2.1 | kanshi scaffold (config, policy, verifier, health, metrics) | DONE |
| 5-8 | 2.1 | kanshi Helm chart (DaemonSet, RBAC, ServiceMonitor) | DONE |
| 9-12 | 2 | kanshi eBPF programs (Linux-only, aya-rs) | PENDING |
| 13 | 3.1 | **P0: Wire DFC signing** (`sign_data_with_classic_key`) | PENDING |
| 13 | 3.1 | **P0: K8s auth method** (JWT + sub-claims for binary hash) | PENDING |
| 14 | 3.1 | **P1: mTLS + cert pinning** (Akeyless PKI → compiled CA) | PENDING |
| 14 | 3.1 | **P1: Log forwarding** (heartbeat → S3/Splunk/Datadog) | PENDING |
| 15-16 | 3.1 | **P2: HMAC server-side verify + heartbeat encryption** | PENDING |
| 17-18 | 3.2 | CNI integration layer (Cilium) | PENDING |
| 19-20 | 3.3 | Multi-cluster federation (sekiban) | DONE |
| 21-24 | 3.4 | SOC 2, PCI DSS, FedRAMP, DISA STIG | DONE |
| 25 | 4 | **Audit-First (Shadow) Mode — DAY ONE** | PENDING |
| 25-26 | 4 | Config integrity, OCI digest, bootstrap | PENDING |
| 27 | 4 | CEL fail-safe, self-attestation | PENDING |
| 28 | 4 | Multi-architecture attestations | PENDING |
| 29-30 | 4 | file_open hooks, CO-RE, revocation map | PENDING |
| 31-32 | 4 | Hubble observability + compliance dashboard | PENDING |
| 33-34 | 4 | Self-healing attestation (auto-rollback) | PENDING |
| Future | 5 | TPM 2.0, memory sampling, policy drift | RESEARCH |
| Future | 6 | Identity masquerade, devenv attestation | RESEARCH |
| Future | 6 | eBPF map exhaustion (LRU), compliance TTL | RESEARCH |
| Future | 7 | Webhook ordering, ephemeral containers, W^X, digest-only | RESEARCH |
| Future | 8 | Symlink TOCTOU, NTP skew, log erasure, Bloom filter DoS | RESEARCH |
| Future | 8b | Sidecar injection, procfs masking, Akeyless cert pinning | RESEARCH |
| Future | 9 | Constant-time comparison, confused deputy, IPC isolation | RESEARCH |
| Future | 9 | eBPF verifier limits (map-driven architecture) | RESEARCH |
| Future | 10 | Edge/IoT/Robotics: DDS attestation, TPM binding, NIST IR 8259 | RESEARCH |

## Test Count (All Sprints Complete)

| Repo | Before | After | Delta | New Modules |
|------|--------|-------|-------|-------------|
| tameshi | 457 | 518 | +61 | canonicalize (40), heartbeat (26), signing (19) |
| sekiban | 315 | 365 | +50 | version-pinned (6), federation (22), reconciler updates |
| kensa | 377 | 438 | +61 | metrics (10), error classification (8), SOC2/PCI/FedRAMP/STIG modules |
| kanshi | 0 | 31 | +31 | NEW REPO: common (7), error (6), config (4), policy (5), verifier (10), health (2), metrics (3) |
| inshou | 366 | 366 | 0 | (heartbeat wiring pending) |
| **Total** | **1,515** | **1,718** | **+203** |

## Repository Visibility

> **IMPORTANT:** All tameshi ecosystem repos MUST be **private** repositories.
> This includes: tameshi, sekiban, kensa, inshou, kanshi.
> Consider using `akeyless-helmworks` (private) for Helm chart distribution.

## Kubernetes Integration Testing Strategy

When the ecosystem reaches K8s integration testing phase, use:

### KUTTL (Kubernetes Test Tool)

```yaml
# tests/kuttl/happy-path/00-deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  annotations:
    sekiban.pleme.io/signature: "blake3:VALID_HASH"
---
# tests/kuttl/happy-path/00-assert.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
status:
  readyReplicas: 1
```

### Security Gauntlet (Automated Attack Tests)

| Test | Action | Expected Result |
|------|--------|----------------|
| Happy Path | Deploy with valid Merkle root | Pod starts |
| Supply Chain Attack | Change one byte in binary | Webhook rejects (403) |
| TOCTOU Attack | Swap binary after pod start | kanshi SIGKILLs |
| Config Poison | Change Helm value outside Merkle | Admission denied |
| Sidecar Injection | Inject container after validation | Reinvocation rejects |
| Break-Glass | Deploy during simulated outage | Allowed with Level 1 alert |
| Revocation | Revoke running binary hash | kanshi kills process |

### Nix Integration Test Environment

```nix
# test.nix — spins up the full environment
{
  cluster = kind;           # K8s in Docker
  sentinel = kanshi;        # eBPF binary (Linux only)
  secrets = akeyless-mock;  # Mock Akeyless gateway
  attestation = kensa-cli;  # Merkle root generation
}
```
