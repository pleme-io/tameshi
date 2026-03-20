# Provisioning & Revocation Specification

> Tameshi Attestation Ecosystem — Adversarial Architecture Analysis & Mitigations

**Status:** Living document
**Audience:** Principal Engineers, Security Architects, Compliance Officers
**Last Updated:** 2026-03-20

---

## Preamble: What Tameshi Proves

Tameshi provides **Integrity** and **Provenance** — not **Moral Certainty**.

The system cryptographically guarantees: *"The artifact tested is the artifact executed."*
It does **not** guarantee: *"The artifact is free of malicious logic."*

This is a mathematical boundary (Rice's Theorem), not an engineering shortcoming.
The "Leftover Gap" (malicious logic inside a signed binary) is mitigated by the
**Kensa Compliance Layer** (human audit + automated scanning), not by cryptographic
hashing. This document defines where the machine's job ends and the human's
responsibility begins.

---

## Hole 1: OCI Image Hashing Bottleneck ("Webhook Timeout" Trap)

### Problem

A standard `ValidatingAdmissionWebhook` has a 10–30 second timeout. Hashing a
2GB container image bit-for-bit inside the sekiban webhook during deployment
will cause the K8s API server to timeout and reject the pod.

**You cannot hash large blobs in the hot path of admission.**

### Mitigation: Digest Check (CI-Time Attestation)

**Shift the work to CI.** During the `inshou` build phase, hash the image and
the Nix derivation. Produce a **Signed Receipt** — a small JSON object containing
the BLAKE3 hash of the OCI manifest digest.

**Webhook behavior:**
1. Read `imageDigest` from the Pod spec (already present in K8s admission request)
2. Look up the Signed Receipt in the `SignatureGate` CRD
3. Verify the receipt's signature matches the CI-attested hash
4. Verify the `imageDigest` in the cluster matches what was signed in CI

**Result:** Admission decisions drop from ~30 seconds to <50 milliseconds.

### Implementation

```rust
// sekiban/src/webhook/admission.rs — OCI digest check
// The webhook NEVER pulls or hashes image bytes.
// It verifies: annotation["sekiban.pleme.io/oci-digest"] == gate.spec.oci_digest
```

**Files affected:**
- `sekiban/src/crd/signature_gate.rs` — add `oci_digest: Option<String>` to spec
- `sekiban/src/webhook/admission.rs` — check OCI digest annotation against gate
- `inshou/src/gate.rs` — emit OCI digest receipt during CI gate check

### Feasibility

| Metric | Before | After |
|--------|--------|-------|
| Webhook latency | 10–30s (image pull+hash) | <50ms (signature verify) |
| Network I/O | Full image pull | Zero (digest in annotation) |
| Reliability | Fails on large images | Always fast |

---

## Hole 2: Environment Blind Spot ("Manifest Leaf")

### Problem

Tameshi proves Code (Nix) and Secrets (Akeyless) but not Infrastructure State.
If an attacker compromises K8s RBAC, changes a ServiceMesh policy, or modifies
a deployment's `runAsUser: 0`, the Merkle tree won't detect it because it only
attests the artifact, not the runtime environment.

**A "secure" binary running in a "poisoned" environment is still a vulnerability.**

### Mitigation: Hash the Intent (Manifest Leaf Node)

When `inshou` generates deployment manifests (Helm/Nix), it hashes the entire
**canonicalized** YAML object (sorted keys, stripped volatile fields). This hash
becomes a **mandatory leaf node** in the Tameshi Merkle tree.

**Webhook behavior:**
1. When sekiban receives a deployment request, it canonicalizes the incoming manifest
2. Computes BLAKE3 hash of the canonical form
3. Checks against the "Kubernetes" layer leaf in the Merkle tree
4. If an attacker changes `runAsUser`, adds a malicious volume mount, or modifies
   CPU limits, the Merkle root fails to compute

### Semantic Boundary (Trust Anchor Declaration)

**What Tameshi proves about manifests:**
- The manifest deployed matches the manifest tested (bit-for-bit, post-canonicalization)
- No drift between CI intent and runtime reality

**What Tameshi does NOT prove:**
- The manifest itself is "safe" (that's the compliance layer's job)
- Runtime behavior matches the manifest (that's kanshi's job)

This is the **Trust Anchor Declaration**: Tameshi guarantees artifact integrity
and provenance. Semantic safety requires the Kensa compliance layer (NIST controls,
CIS benchmarks, custom security policies) and human review.

### Implementation

The `Kubernetes` layer collector already exists in `tameshi/src/collectors/kubernetes.rs`.
The canonicalization layer (see Sprint 1A) ensures deterministic hashing regardless
of key ordering or whitespace.

**Files affected:**
- `tameshi/src/canonicalize.rs` — new canonicalization module
- `tameshi/src/collectors/kubernetes.rs` — use `YamlCanonicalizer` in Logical mode
- `sekiban/src/webhook/changeset.rs` — already implements `canonical_json()` + `normalize_value()`

---

## Hole 3: eBPF Kernel Portability ("BTF Headache")

### Problem

eBPF programs rely on BTF (BPF Type Format) to understand kernel structures.
If production K8s nodes run a different kernel version than dev, or lack
`CONFIG_DEBUG_INFO_BTF=y`, kanshi will fail to load.

**"Works on my machine" is 10x worse with eBPF.**

### Mitigation: CO-RE (Compile Once — Run Everywhere)

Since kanshi uses Aya (Rust), we leverage BTF and CO-RE patterns:

1. **Bundle `vmlinux.h`** — the kernel's type map — into the kanshi binary at build time
2. **At runtime**, Aya uses the node's local BTF data (`/sys/kernel/btf/vmlinux`) to
   relocate eBPF instructions to match the specific kernel version
3. **Nix ensures reproducibility** — the exact kernel headers for target production
   nodes are packaged in the Nix build environment

**Result:** kanshi becomes a single portable binary that runs on any modern Linux
kernel (5.15+) without needing a C compiler on the node.

### Requirements

- Kernel: Linux 5.15+ with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`
- kanshi-ebpf: Use `aya-bpf` with CO-RE relocations (no raw struct offset hardcoding)
- Nix: Package kernel headers matching production nodes
- CI: Linux runner (eBPF tests cannot run on macOS)
- Graceful degradation: If BTF is unavailable, kanshi logs error and operates in
  audit-only mode (no enforcement)

### Kernel Compatibility Matrix

| Kernel | BTF | LSM BPF | Status |
|--------|-----|---------|--------|
| 5.15+ | Yes | Yes | Full support (CO-RE) |
| 5.8–5.14 | Yes | Partial | Audit-only (no LSM hooks) |
| <5.8 | No | No | Not supported |

---

## Hole 4: Dead Man's Switch (Availability Risk)

### Problem

Tameshi is fail-closed. If the Akeyless API is down, or kensa's attestation store
has a network blip, sekiban cannot verify the Merkle root. In fail-closed mode,
**no new pods can start**, potentially taking down the entire production cluster.

### Mitigation: Signed Break-Glass Mechanism

An emergency bypass system with full cryptographic auditability:

1. **Generate an "Emergency Attestation" Ed25519 key pair**
   - Private key stored in a physical safe or offline HSM
   - Public key configured in sekiban's `SignatureGate` CRD

2. **Break-Glass Bypass Token:**
   ```json
   {
     "type": "break_glass",
     "issued_at": "2026-03-20T10:00:00Z",
     "valid_until": "2026-03-20T14:00:00Z",
     "issuer": "oncall-sre@pleme.io",
     "reason": "Akeyless API outage — INC-2847",
     "scope": ["namespace:production"],
     "signature": "ed25519:<hex>"
   }
   ```

3. **sekiban behavior during outage:**
   - If primary verification fails AND a valid break-glass token exists in a
     designated K8s Secret, allow deployments within the token's scope and TTL
   - Every break-glass admission triggers a **Level 1 audit alert** immediately
   - Heartbeat chain records all break-glass events as `BreakGlass` event type
   - When the outage resolves, break-glass tokens are automatically revoked

4. **CIRCIA compliance:**
   - Every break-glass event is logged with full provenance
   - 72-hour CIRCIA report includes break-glass window, affected resources, issuer

### Implementation

**Files affected:**
- `tameshi/src/signing.rs` — `BreakGlassToken` type with Ed25519 verification
- `sekiban/src/webhook/admission.rs` — check break-glass token on primary failure
- `sekiban/src/crd/signature_gate.rs` — `break_glass_public_key: Option<String>`
- `sekiban/chart/sekiban/templates/prometheusrule.yaml` — alert on break-glass use

### Operational Procedures

| Step | Action | Owner |
|------|--------|-------|
| 1 | Detect primary verification failure | sekiban (automated) |
| 2 | Page on-call SRE | PagerDuty (automated) |
| 3 | SRE signs break-glass token | On-call SRE (manual) |
| 4 | Apply token as K8s Secret | On-call SRE (manual) |
| 5 | sekiban allows deployments in scope | sekiban (automated) |
| 6 | Outage resolved → revoke token | On-call SRE (manual) |
| 7 | Post-incident: re-attest all resources | inshou/kensa (automated) |

---

## Hole 5: JIT/Dynamic Language Gap ("Interpreter Problem")

### Problem

kanshi hashes binaries at `execve`. This works for Rust, Go, C++. But for
Python, Node.js, Java: the "binary" is just the interpreter. The actual logic
(`.js`, `.py` files) is read later. An attacker can swap script files without
kanshi noticing because the interpreter binary itself hasn't changed.

**Tameshi is 100% effective for compiled code, ~20% for interpreted code.**

### Mitigation: Kernel-Level FIM (File Integrity Monitoring)

kanshi hooks `openat` and `mmap` syscalls in addition to `execve`:

1. When `python` or `node` opens a file for reading, kanshi intercepts `openat`
2. Hashes the file being opened
3. Checks against the Merkle tree's "content hash map"
4. If the script hash isn't in the tree, the kernel denies the read operation

### Implementation

**kanshi-ebpf LSM hooks:**
```
bprm_check_security  → binary verification at execve (compiled languages)
file_open            → script verification at open (interpreted languages)
mmap_file            → shared library verification at mmap (JIT/dlopen)
```

**BPF Maps:**
```
tameshi_allow_map:    inode(u64) → expected_blake3([u8; 32])  // binary hashes
tameshi_content_map:  inode(u64) → expected_blake3([u8; 32])  // script/lib hashes
tameshi_policy_map:   cgroup_id(u64) → policy(u8)             // per-namespace enforcement
```

### Performance Impact

| Hook | Overhead | Frequency |
|------|----------|-----------|
| `bprm_check_security` | ~1μs (hash lookup) | Per exec (rare) |
| `file_open` | ~1μs (hash lookup) | Per open (frequent) |
| `mmap_file` | ~1μs (hash lookup) | Per mmap (moderate) |

The `file_open` hook has higher frequency. Mitigation:
- Only intercept opens from processes in attested cgroups
- Only intercept files matching configured path prefixes (e.g., `/app/`, `/opt/`)
- Pre-populate BPF map at pod start, not on every open

### OCI Layer Hash Optimization

For containerized interpreters, kanshi can verify the OCI layer hash at container
start rather than individual script hashes at runtime. Combined with read-only
rootfs enforcement, this provides equivalent security with lower overhead:

1. Container starts → kanshi verifies OCI layer digest against Merkle tree
2. Read-only rootfs prevents script modification after start
3. `file_open` hook only needed for writable volumes (if any)

---

## Additional Concern 1: Dynamic Secret Paradox (Policy-Path Hashing)

### Problem

Akeyless Dynamic Secrets rotate values constantly. Hashing the secret **value**
into the Merkle tree breaks the deployment on every rotation — the hash changes
even though the security posture hasn't.

### Mitigation: Hash the Authorization Policy, Not the Value

The Merkle leaf node for a secret hashes:
- **Secret Path** (e.g., `/pleme/production/db-credentials`)
- **Target ID** (the Akeyless target that backs this secret)
- **Access Role** (the role that grants access to this secret)
- **Producer Type** (dynamic-secret, rotated-secret, static-secret)

```rust
// tameshi/src/collectors/akeyless.rs — policy-path hashing
fn hash_secret_policy(path: &str, target_id: &str, access_role: &str) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(path.as_bytes());
    data.push(0);
    data.extend_from_slice(target_id.as_bytes());
    data.push(0);
    data.extend_from_slice(access_role.as_bytes());
    Blake3Hash::digest(&data)
}
```

**What this proves:** The authorization policy is untampered. The secret path,
target, and role haven't been changed by an attacker. The actual secret value
rotates freely within the Akeyless DFC ecosystem — as designed.

**What this does NOT prove:** The secret value itself (by design — dynamic secrets
must rotate without breaking attestation).

### Already Implemented

The `AkeylessTargetCollector` and `LiveAkeylessTargetCollector` in tameshi already
hash target configuration (30 target types) rather than secret values. The
`ProducerAssociation` type captures the target + producer relationship. This
approach is architecturally sound and already in production.

---

## Additional Concern 2: Semantic Boundary (Trust Anchor Declaration)

### The Mathematical Reality

Per **Rice's Theorem**, no program can decide non-trivial semantic properties
of another program. Tameshi cannot look at a signed binary and decide if it
will "do something bad."

### Trust Anchor Declaration

Tameshi provides a **three-layer trust model**:

| Layer | Guarantees | Limitation |
|-------|-----------|------------|
| **Integrity** (tameshi) | Artifact X at time T₁ is bit-identical to artifact X at time T₂ | Cannot detect malicious logic in X |
| **Compliance** (kensa) | Artifact X passes controls C₁..Cₙ at time T | Controls are finite; zero-days exist |
| **Runtime** (kanshi) | Only attested artifacts execute | Cannot prevent logic bugs in attested code |

### Where the Machine Stops and the Human Begins

```
┌─────────────────────────────────────────────────────────┐
│  MACHINE DOMAIN (Tameshi + Kensa + Kanshi)              │
│                                                         │
│  ✓ Bit-perfect integrity (BLAKE3 Merkle)                │
│  ✓ Provenance chain (who built, when, from what source) │
│  ✓ Compliance scanning (NIST, SOC2, PCI DSS, CIS)      │
│  ✓ Runtime enforcement (eBPF LSM hooks)                 │
│  ✓ Cryptographic audit trail (heartbeat chain)          │
│  ✓ Revocation (eBPF kill-switch)                        │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  HUMAN DOMAIN (Code Review + Threat Modeling)           │
│                                                         │
│  ✓ Logic correctness (is the code doing the right thing)│
│  ✓ Architectural security (is the design sound)         │
│  ✓ Insider threat mitigation (n-of-m approval gates)    │
│  ✓ Zero-day response (judgment calls under uncertainty) │
│  ✓ Compliance interpretation (are controls sufficient)  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Documentation for Review

When presenting to senior staff, lead with:

> "Tameshi guarantees that the artifact tested is the artifact executed.
> It does not guarantee that the artifact is free of malicious logic —
> that is the domain of code review, compliance testing, and threat modeling.
> This is a mathematical boundary (Rice's Theorem), not an engineering gap."

---

## Additional Concern 3: Global Revocation Map (eBPF Kill-Switch)

### Problem

A "certified" binary might be found to have a zero-day vulnerability **after**
it is already running in production. The heartbeat chain proves it was verified,
but it's still vulnerable. You need a <100ms global kill-switch.

### Architecture: BPF Revocation Map

kanshi maintains a second BPF hash map called `tameshi_revocation_list`:

```c
// kanshi-ebpf/src/main.rs — eBPF verification logic
SEC("lsm/bprm_check_security")
int tameshi_verify(struct linux_binprm *bprm) {
    u64 inode = bprm->file->f_inode->i_ino;
    u8 *hash = bpf_map_lookup_elem(&tameshi_allow_map, &inode);
    if (!hash) {
        // Unknown binary — check policy
        return enforce_policy(bprm);
    }
    // Check revocation AFTER allow check
    u8 *revoked = bpf_map_lookup_elem(&tameshi_revocation_list, hash);
    if (revoked) {
        // Binary is revoked — DENY
        emit_revocation_event(inode, hash);
        return -EPERM;
    }
    return 0; // ALLOW
}
```

**Logic:** `exists_in_allow_map(hash) && !exists_in_revocation_map(hash)`

### Revocation CLI

```bash
# Emergency revocation — pushes hash to all nodes via BPF filesystem
kensa revoke --hash blake3:deadbeef... --reason "CVE-2026-XXXX" --severity critical

# Bulk revocation from CVE scan results
kensa revoke --from-scan /tmp/trivy-results.json --severity high,critical

# List active revocations
kensa revocations list

# Remove revocation (after patched version deployed)
kensa revoke --remove --hash blake3:deadbeef...
```

### Orchestration Flow

```
1. CVE discovered in production binary
2. kensa revoke --hash <hash> --reason "CVE-2026-XXXX"
3. kensa pushes revocation to kanshi DaemonSet via K8s API
4. kanshi updates tameshi_revocation_list BPF map on ALL nodes
5. eBPF program blocks revoked binary at next execve (~0ms propagation)
6. Heartbeat chain logs revocation event
7. PrometheusRule fires alert: "Binary revoked on N nodes"
8. Patched binary deployed → old revocation entry cleaned up
```

### Propagation Latency

| Method | Latency | Reliability |
|--------|---------|-------------|
| K8s ConfigMap watch | 1–5s | High (K8s native) |
| Direct BPF map write | <1ms | Requires node access |
| DaemonSet rolling update | 30–120s | Very high |

**Recommended:** ConfigMap watch for normal revocations, direct BPF write for
critical zero-day response (via kanshi's admin API endpoint).

---

## Feasibility Scorecard

| Component | Technical Feasibility | Operational Risk | Verdict |
|-----------|----------------------|-----------------|---------|
| inshou (Nix) | 10/10 | Low | Bulletproof |
| sekiban (Webhook) | 9/10 | Medium | Digest check eliminates timeout. Break-glass prevents outages |
| kanshi (eBPF) | 7/10 | Medium | CO-RE solves portability. Audit-only fallback for old kernels |
| Akeyless Integration | 9/10 | Low | Policy-path hashing is architecturally sound |
| kensa (Compliance) | 9/10 | Low | Compliance scanning + revocation = defense in depth |

### Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Webhook timeout on large images | High (without fix) | Critical | Digest check (Hole 1) |
| K8s manifest drift | Medium | High | Manifest leaf node (Hole 2) |
| eBPF portability failure | Medium | Medium | CO-RE + audit-only fallback (Hole 3) |
| Availability outage from verification | Low (with fix) | Critical | Break-glass mechanism (Hole 4) |
| Script tampering in interpreted langs | Medium | High | file_open + mmap hooks (Hole 5) |
| Dynamic secret rotation breaks hash | N/A (solved) | N/A | Policy-path hashing (already implemented) |
| Zero-day in certified binary | Low | Critical | BPF revocation map (Concern 3) |

---

## Appendix: Why This Protects You

By addressing these holes proactively, the Tameshi ecosystem demonstrates:

1. **Performance awareness** — Digest check proves we understand webhook SLAs
2. **Operational maturity** — Break-glass proves we won't take down production
3. **Portability planning** — CO-RE proves we understand kernel diversity
4. **Mathematical honesty** — Trust Anchor Declaration proves we know where
   cryptographic proof ends and human judgment begins
5. **Incident response** — Global revocation proves we can respond to zero-days
   in <100ms, not hours

This is not a prototype. This is a **production-grade specification** designed
for the operational reality of enterprise infrastructure.
