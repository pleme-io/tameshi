# Research Findings — Technical Due Diligence

> Comprehensive research across eBPF, cryptography, compliance, and supply chain
> security to ensure tameshi covers all features and concerns.

**Date:** 2026-03-20
**Classification:** PRIVATE — Internal architecture reference

---

## 1. eBPF / kanshi Architecture Validation

### Confirmed: Hash in Userspace, Lookup in BPF Map

BLAKE3 **cannot** run inside eBPF programs (instruction limit ~1M, BLAKE3 for a
multi-MB binary would require millions). The correct architecture is:

```
Userspace daemon (kanshi)              Kernel (eBPF LSM hooks)
┌─────────────────────┐                ┌──────────────────────────┐
│ Compute BLAKE3 hash │──populate──▶  │ BPF_MAP_TYPE_LRU_HASH    │
│ of allowed binaries │                │   key: inode (u64)       │
│                     │                │   val: hash ([u8;32])    │
│ Watch CRDs via      │                │                          │
│ kube-rs             │   ◀──events── │ bprm_check_security:     │
│                     │                │   lookup inode in map    │
│ Emit heartbeat      │                │   allow/deny             │
└─────────────────────┘                └──────────────────────────┘
```

This is the same pattern used by **Tetragon**, **Tracee**, and **bpf-lsm** examples.

**Alternative:** Use `bpf_ima_inode_hash()` kernel helper (SHA-256, kernel 5.11+)
to get the kernel's own hash without userspace computation. Requires IMA subsystem
enabled or kernel 6.1+ for BPF-only IMA.

### Aya-rs CO-RE Limitation

**Critical finding:** Aya supports loading CO-RE programs, but **rustc cannot emit
BTF relocations** from pure Rust eBPF code (issue aya-rs/aya#349, still open).

**Workarounds:**
1. C shim for CO-RE-sensitive field access (compile to LLVM bitcode, link with bpf-linker)
2. Runtime offset discovery via `EbpfLoader::override_global()`
3. For kanshi: our LSM hooks access well-defined kernel structures
   (`linux_binprm`, `file`, `vm_area_struct`) — field offsets are stable
   across kernel versions for these core types

**Recommendation:** Start with direct struct access (non-CO-RE) targeting kernel
5.15+. Add CO-RE support when aya ships BTF emission.

### Production eBPF LSM Reference Implementations

| Tool | How It Does Binary Verification |
|------|-------------------------------|
| **Tetragon** | `bprm_check_security` + `imaHash: true` → returns `algorithm:hash_value` |
| **Tracee** | Syscall tracing + LSM hooks for TOCTOU-safe argument capture |
| **Falco** | Modern eBPF probe (CO-RE, embedded) for 330 syscalls |

**Key insight from Tetragon:** `Sigkill` alone may not prevent operations (data
may be written before signal delivery). Use `Override` + `Signal` for guaranteed
prevention. kanshi should use LSM hook return value (`-EPERM`) rather than
`SIGKILL` for atomic denial.

### BPF Verifier Strategy

Our map-driven architecture (Phase 9) is validated:
- Each LSM hook should be a **separate BPF program** (<100 instructions)
- Use **tail calls** for any complex logic paths
- All policy decisions via **map lookups** (O(1), ~200-300ns)
- Max 33 tail call depth, 512-byte stack, 1M instruction limit per program

---

## 2. Cryptographic Foundations

### BLAKE3 Properties (Confirmed)

- ~3x faster than SHA-256 on modern hardware
- Parallelizable (SIMD, multi-threaded)
- Merkle tree built-in to the algorithm design
- **NOT FIPS 140-3 approved** (SHA-2 and SHA-3 are)
- Keyed hashing mode suitable for HMAC-like operations

**FIPS consideration:** For federal customers requiring FIPS 140-3, tameshi should
offer a SHA-256 alternative Merkle tree mode. The `AttestationHasher` trait already
supports this via `Blake3Hasher` vs a future `Sha256Hasher`.

**Constant-time comparison:** The `subtle` crate is the correct approach. Used by
all major Rust crypto libraries (ring, rustls, ed25519-dalek).

### Sigstore Integration Opportunity

Sigstore (cosign + Fulcio + Rekor) and tameshi are **complementary**:
- Sigstore: **who** signed it (identity, via OIDC) + **when** (transparency log)
- tameshi: **what** was signed (bit-for-bit content integrity via BLAKE3 Merkle)

**Actionable:** Embed tameshi BLAKE3 Merkle roots as in-toto attestation predicates
in Sigstore cosign signatures. This gives both identity-based provenance AND
content integrity in a single attestation artifact.

### SLSA Level Assessment

| SLSA Requirement | Nix + tameshi Status |
|-----------------|---------------------|
| L1: Provenance exists | Yes — Nix derivation + BLAKE3 Merkle |
| L2: Hosted build platform | Yes — Forge CI pipeline |
| L3: Hardened/hermetic builds | Yes — Nix sandbox (chroot, no network, no env) |
| L3: Signing keys inaccessible to build steps | Yes — Akeyless DFC (key never in memory) |

**tameshi achieves SLSA Build L3** with Nix + Forge + Akeyless DFC.

### TUF for Merkle Root Distribution

TUF (The Update Framework) solves a problem tameshi needs:
**How do nodes securely get the latest trusted Merkle root?**

TUF's delegation model maps cleanly:
- **Root role** → tameshi ecosystem trust anchor (DFC-signed)
- **Targets role** → per-environment Merkle roots
- **Snapshot role** → version numbers of all targets (prevents rollback)
- **Timestamp role** → freshness (prevents freeze attacks)

**Recommendation:** Use TUF metadata format for distributing Merkle roots via
sekiban CRDs. This provides rollback protection and freshness guarantees.

---

## 3. Kubernetes Admission Patterns

### ValidatingAdmissionPolicy (CEL) — GA in K8s 1.30

Confirmed production-ready. Key properties:
- Runs **in-process** in the API server (no network hop)
- Bounded execution cost (CEL cost estimation)
- Cannot make external API calls (limitation, not a bug)
- Ideal as Tier 2 fail-safe behind sekiban webhook

### Webhook Best Practices (Applied to sekiban)

| Practice | sekiban Status |
|----------|---------------|
| `reinvocationPolicy: IfNeeded` | Documented in ROADMAP Phase 7 |
| `sideEffects: None` | Should be set |
| `namespaceSelector` for scope limiting | Implemented |
| Timeout 2-5s recommended | Currently default (10s), should reduce |
| `failurePolicy: Fail` for validating | Set correctly |
| HA deployment across AZs | Architecture defined |

**New finding:** Webhook timeout should be reduced from 10s default to **3s**.
Combined with the OCI digest check (no image pull in webhook), 3s is plenty.

---

## 4. Supply Chain Tool Integration Map

```
┌─────────────────────────────────────────────────────────┐
│                TAMESHI ECOSYSTEM                        │
│                                                         │
│  tameshi ──── BLAKE3 Merkle content integrity           │
│  sekiban ──── K8s admission gating                      │
│  kensa ────── Compliance assessment                     │
│  inshou ───── Nix build gate                            │
│  kanshi ───── eBPF runtime enforcement                  │
│                                                         │
├─────────────────────────────────────────────────────────┤
│              INTEGRATIONS (to add)                      │
│                                                         │
│  Sigstore ─── cosign signatures on OCI images           │
│               Embed Merkle root as in-toto predicate    │
│  SLSA ─────── Provenance attestation (L3 via Nix)       │
│  TUF ──────── Secure Merkle root distribution           │
│  IMA ──────── Kernel file integrity (bpf_ima_*helpers)  │
│  Tetragon ─── Reference for eBPF LSM patterns           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Gaps Identified — Action Items

### Must Address (Affects Architecture)

| Gap | Impact | Action |
|-----|--------|--------|
| BLAKE3 not FIPS 140-3 | Federal customers | Add SHA-256 Merkle mode behind `AttestationHasher` trait |
| Aya CO-RE not working | Kernel portability | Use direct struct access for kanshi v1, plan CO-RE for v2 |
| No Sigstore integration | Missing provenance layer | Embed Merkle roots in cosign attestations |
| No TUF for root distribution | Merkle root freshness/rollback | Use TUF metadata in sekiban CRDs |
| Webhook timeout 10s | Slow admission | Reduce to 3s in Helm values |

### Should Address (Best Practices)

| Gap | Impact | Action |
|-----|--------|--------|
| No IMA integration | Missing kernel-native hashing | Use `bpf_ima_inode_hash()` as secondary hash source |
| No SLSA provenance document | Missing supply chain metadata | Generate SLSA provenance in Forge CI |
| No in-toto step attestation | Missing pipeline step verification | Generate in-toto predicates per build step |
| sideEffects not set | Webhook best practice | Set `sideEffects: None` in Helm template |

### Nice to Have (Future)

| Gap | Impact | Action |
|-----|--------|--------|
| No Tetragon interop | Complementary runtime security | Document how kanshi + Tetragon coexist |
| No cosign verification in sekiban | OCI image signing | Add cosign sig check in admission webhook |
| No sparse Merkle trees | Scale to millions of binaries | Evaluate sparse Merkle for kanshi BPF maps |
