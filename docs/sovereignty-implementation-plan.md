# Sovereignty Implementation Plan

*Closing the gaps between what is proved and what is built.*

---

## Current State (Honest Inventory)

| Capability | Status | Evidence |
|-----------|--------|---------|
| Ownership analysis (use-after-free, double-free, channel move) | **Shipped** | 391 Go tests, 87% coverage |
| Merkle composition (15 layer types, domain separation) | **Shipped** | 1,579 Rust tests, 39 proptest properties |
| eBPF enforcement (LSM hook, BPF map, audit events) | **Shipped** | 12 struct layout tests, C code reviewed |
| DFC split-knowledge (2-of-2 XOR fragments) | **Shipped** | F* proof + Kani harnesses + unit tests |
| Selective disclosure (prove one leaf, hide others) | **Shipped** | proptest `selective_disclosure_hides_other_leaves` |
| Fragment extension (Merkle root as DFC fragment N+1) | **Proved in F*** | `Tameshi.FragmentedSovereignty.fst` — no Rust impl |
| Taint tracking (information flow control) | **Not built** | Architecture assessed, SSA infra ready |
| Sparse Merkle Tree | **Not built** | Crates assessed, module boundary defined |
| Shamir Secret Sharing (k-of-n threshold) | **Not built** | Crates assessed, trait boundary defined |
| Hardware salt / TPM binding | **Not built** | No code, no design |
| Encrypted heartbeat chain | **Not built** | Described in AKEYLESS_INTEGRATION.md |

---

## The Five Gaps (Priority Order)

### Gap 1: Fragment Extension in Rust

**What:** Make the F* theorem executable. Implement `reconstruct_key_extended(frag_a, frag_b, root)`
in Rust with witness tests that validate each F* lemma.

**Why first:** This is the lowest-effort, highest-value gap. The math is already proved. The
implementation is ~100 lines. It turns an F* sketch into a shipping feature that binds the
signing key to the specific attestation — meaning even correct DFC fragments cannot sign a
different artifact.

**Effort:** 1 day

**Files:**
- `src/fragment_extension.rs` — ~100 lines (function + 4 witness tests)
- `tests/proptest_properties.rs` — 2 new properties (~40 lines)
- `proofs/kani/src/fragment_extension_proofs.rs` — 2 harnesses (~60 lines)

**Dependencies:** None. Uses existing `Blake3Hash`, `MockDfcSigner` patterns.

**Verification:**
- 4 unit tests witnessing F* lemmas
- 2 proptest properties (10k cases each)
- 2 Kani harnesses (exhaustive)
- Existing F* proof (`Tameshi.FragmentedSovereignty.fst`) remains valid

**What it buys:** The "no single entity" story becomes executable, not just theoretical.
A demo can show: "Here are fragment A, fragment B, and the Merkle root. Change any one
of them and the signature breaks."

---

### Gap 2: Taint Tracking in Ferrite

**What:** Add an information flow pass to the SSA analyzer that prevents `Owned[T]` values
produced by sensitive sources (DFC decryption, secret fetch) from flowing to insecure sinks
(logging, serialization, network output).

**Why second:** This is the most architecturally valuable gap for the Akeyless story.
It means Ferrite doesn't just prove "no memory bugs" — it proves "secrets don't leak."
The existing SSA infrastructure (`resolveValue`, `OwnershipFact`, fixed-point iteration)
handles 90% of the work.

**Effort:** 2-3 days

**Files:**
- `check/facts.go` — add `TaintFact` (~25 lines)
- `check/ssa.go` — add `checkTaintPropagation()` as Phase 7 (~150 lines)
- `check/taint_sinks.go` — hardcoded sink registry (~50 lines)
- `check/testdata/src/ssa_taint/taint.go` — 5 test cases (~80 lines)
- `check/ssa_test.go` — add `TestSSA_TaintTracking` (~10 lines)

**Dependencies:** None. Reuses existing `resolveValue()`, `pass.ExportObjectFact`,
`analysistest.Run` infrastructure with zero changes.

**What can be reused from existing code:**
- `resolveValue()` (line 909, ssa.go) — follow SSA value chains to find taint origin
- `OwnershipFact` pattern (facts.go) — same export/import mechanism for cross-function taint
- Fixed-point iteration (line 36-51, ssa.go) — same loop structure for taint discovery
- `analysistest` framework — same `// want "diagnostic"` annotations

**MVP scope (what gets tested):**
- `// ferrite:sensitive` comment annotation on function return types
- Direct assignment propagation: `x := sensitiveFunc()` taints `x`
- Phi-node union: if either branch is tainted, the merge is tainted
- Sink detection for: `fmt.Print*`, `log.*`, `encoding/json.Marshal`, `io.Writer.Write`
- Cross-function taint via `TaintFact` export/import

**What is NOT in MVP:**
- No field-level taint (struct is tainted as a whole)
- No sanitization detection (no "this function cleans the taint")
- No configurable sink registry (hardcoded list)

**Verification:**
- 5 analysistest cases (pattern-matched diagnostics)
- `go test ./check -run TestSSA_TaintTracking`

**What it buys:** "Ferrite proves secrets can't leak" — the most powerful sentence in the pitch.

---

### Gap 3: Shamir DFC Signer

**What:** Implement a `ShamirDfcSigner` that uses k-of-n threshold reconstruction
instead of the current 2-of-2 XOR scheme. Compatible with the existing `MerkleRootSigner` trait.

**Why third:** This upgrades the DFC model from "both fragments required" to "any k of n
fragments sufficient." Combined with Gap 1 (fragment extension), this means the Merkle root
is fragment N+1 in a (k+1)-of-(N+1) threshold scheme. The `vsss-rs` crate provides
verifiable secret sharing (Feldman commitments) out of the box.

**Effort:** 2-3 days

**Files:**
- `Cargo.toml` — add `vsss-rs = "5.3"` or `sharks = "0.5"` dependency
- `src/shamir_dfc.rs` — ~250 lines
  - `ShamirDfcSigner` struct (threshold, shares)
  - `create_shares(key, k, n) -> Vec<Share>`
  - `reconstruct_key(shares) -> [u8; 32]`
  - `MerkleRootSigner` trait implementation
  - 10+ unit tests
- `tests/proptest_properties.rs` — 2 new properties (~40 lines)
  - `shamir_threshold_reconstruction` — k shares reconstruct, k-1 don't
  - `shamir_shares_independent` — any k-subset works

**Dependencies:** Gap 1 (fragment extension) should land first so Shamir can include the
Merkle root as an automatic additional share.

**What it buys:** "Any 2 of 3 custodians can attest, but none alone" — the threshold
trust story that maps directly to Akeyless DFC's value proposition.

---

### Gap 4: Sparse Merkle Tree

**What:** Add a parallel `src/sparse_merkle.rs` module implementing a key-value
Merkle tree alongside the existing balanced tree.

**Why fourth:** The current balanced tree works perfectly for the 15-layer composition.
The SMT adds value for two specific use cases:
1. **Akeyless target attestation** — 30 target types as key-value leaves instead of a flat list
2. **Non-inclusion proofs** — prove a binary is NOT in the tree (the balanced tree can only
   prove inclusion)

The `sparse-merkle-tree` crate (0.6.1) is mature and supports custom hashers.

**Effort:** 3-4 days

**Files:**
- `Cargo.toml` — add `sparse-merkle-tree = "0.6"` dependency
- `src/sparse_merkle.rs` — ~300 lines
  - `SparseMerkleTree<H>` wrapper with BLAKE3 hasher
  - `insert(key, value)`, `get_proof(key)`, `verify_proof(key, value, proof, root)`
  - `verify_non_inclusion(key, proof, root)` — the new capability
  - 15+ unit tests
- `tests/proptest_properties.rs` — 3 new properties
  - `smt_tamper_detection` — changing a value changes the root
  - `smt_non_inclusion_correct` — absent keys produce valid non-inclusion proofs
  - `smt_inclusion_correct` — present keys verify
- `proofs/kani/src/smt_proofs.rs` — 2 harnesses
  - `smt_insert_changes_root`
  - `smt_non_inclusion_sound`

**Dependencies:** None. Parallel to existing Merkle tree.

**What it buys:** "We can prove a binary was NOT authorized" — non-inclusion is the
missing piece for revocation proofs and compliance evidence ("this malicious binary was
never in our allow-list").

---

### Gap 5: Hardware Salt / TPM Binding

**What:** Add a `NodeSalt` trait that binds attestations to specific hardware via
a TPM-derived or machine-specific salt.

**Why last:** This is the most speculative gap. It requires assumptions about deployment
environment (TPM availability, node identity model). The value is real — a valid attestation
from Node A should not work on Node B — but the implementation depends on target platform
decisions that aren't made yet.

**Effort:** 2 days (mock only), 1-2 weeks (real TPM integration)

**Files (mock-only):**
- `src/node_salt.rs` — ~150 lines
  - `NodeSalt` trait: `fn salt(&self) -> [u8; 32]`
  - `MockTpmSalt` — deterministic test implementation
  - `SystemIdSalt` — derives salt from `/etc/machine-id` or equivalent
  - Salted Merkle root: `salted_root = BLAKE3(composed_root || node_salt)`
- `tests/proptest_properties.rs` — 1 new property
  - `node_salt_prevents_transplant` — same artifact, different salt, different root

**Dependencies:** Gap 4 (SMT) would benefit from per-node salting but isn't required.

**What it buys:** "An attestation cannot be transplanted between nodes" — the hardware
binding story. But only meaningful when we know the deployment target.

---

## Dependency Graph

```
Gap 1: Fragment Extension  ──────────────────────────────┐
  (1 day, no deps)                                       │
                                                         ▼
Gap 2: Taint Tracking      Gap 3: Shamir DFC  ◀── uses Gap 1
  (2-3 days, no deps)        (2-3 days)
                                                         │
                              Gap 4: Sparse Merkle Tree  │
                                (3-4 days, no deps)      │
                                         │               │
                                         ▼               ▼
                              Gap 5: Hardware Salt ◀── uses Gap 4
                                (2 days mock, deps on platform)
```

Gaps 1, 2, and 4 are fully independent. Gap 3 benefits from Gap 1.
Gap 5 benefits from Gap 4. Maximum parallelism: 3 gaps simultaneously.

---

## Total Effort

| Gap | Effort | New LoC | New Tests | Risk |
|-----|--------|---------|-----------|------|
| 1. Fragment Extension | 1 day | ~200 | ~8 | Low — math is proved |
| 2. Taint Tracking | 2-3 days | ~315 | ~5 | Medium — new analysis pass |
| 3. Shamir DFC | 2-3 days | ~330 | ~12 | Low — crate does the math |
| 4. Sparse Merkle Tree | 3-4 days | ~400 | ~20 | Low — crate is mature |
| 5. Hardware Salt (mock) | 2 days | ~200 | ~5 | Low — mock only |
| **Total** | **10-13 days** | **~1,445** | **~50** | |

---

## Verification After All Gaps

| Metric | Current | After |
|--------|---------|-------|
| Rust tests | 1,579 | ~1,630 |
| Go tests | 391 | ~396 |
| Proptest properties | 39 | ~47 |
| Kani harnesses | 44 | ~48 |
| F* modules | 11 | 11 (unchanged — Rust witnesses the proofs) |
| Layer types | 15 | 15 (unchanged — SMT is parallel, not replacing) |

---

## Recommended Execution Order

**Week 1:**
- Day 1: Gap 1 (Fragment Extension) — ship immediately
- Days 2-3: Gap 2 (Taint Tracking) — start in parallel
- Days 3-4: Gap 3 (Shamir DFC) — start after Gap 1 lands

**Week 2:**
- Days 5-8: Gap 4 (Sparse Merkle Tree)
- Days 9-10: Gap 5 (Hardware Salt mock)
- Day 10: Integration testing, OVERVIEW update, `nix run .#verify-all`

**What we do NOT build:**
- ZK-SNARKs in the kernel (requires eBPF verifier changes, not practical)
- Pedersen commitments in the BPF map (adds complexity without clear benefit over hash)
- Encrypted heartbeat chain (DFC encryption of chain entries — deferred to post-MVP)

These remain documented as future architecture directions, not shipped features.
