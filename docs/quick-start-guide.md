# Quick Start Guide

*For the Akeyless development team. Get from zero to verified in 5 minutes.*

---

## Prerequisites

```bash
# You need: Rust 1.89+, Nix with flakes enabled
rustc --version   # 1.89.0 or later
nix --version     # 2.18+ with flakes
```

## 1. Run the Test Suite

```bash
cd tameshi
cargo test
```

Expected: **1,446+ tests pass**, 0 failures. Takes ~30 seconds.

## 2. Run Formal Verification (Layer 1)

```bash
nix run .#verify-proptest
```

Expected: **38 properties pass**, each with 10,000 random inputs (380,000 total checks). Takes ~80 seconds.

This is the layer you run after every code change. If any property fails,
a theorem from `docs/mathematical-foundations.md` has been violated.

## 3. What the Verification Proves

| Command | Time | What It Guarantees |
|---------|------|--------------------|
| `cargo test` | 30s | Every function works correctly for known inputs |
| `nix run .#verify-proptest` | 80s | Every security invariant holds for 380,000 random hostile inputs |
| `nix run .#verify-kani` | ~10m | No memory bugs, no deadlocks, no FFI layout errors (exhaustive) |
| `nix run .#verify-fstar` | ~2m | Mathematical proofs: tamper evidence, non-interference, refinement |
| `nix run .#verify-all` | ~15m | Everything above, in sequence |

## 4. Key Files to Know

| File | What It Is | When to Read It |
|------|-----------|-----------------|
| `src/certification_artifact.rs` | The 3-leaf Merkle tree that governs every binary | When you need to understand what `composed_root` means |
| `src/bpf_loader.rs` | The `#[repr(C)]` structs shared with the kernel | When touching the FFI boundary — do not change field order |
| `src/collectors/ferrite.rs` | FerriteCollector: ingests PoMS JSON, rejects violations > 0 | When integrating a new Ferrite output format |
| `src/heartbeat.rs` | The append-only audit chain | When adding new event types or querying the ledger |
| `src/signing.rs` | MockDfcSigner: split-knowledge fragment signing | When testing signing without Akeyless gateway |

## 5. The Critical Invariant

The entire system enforces one rule:

> **A binary executes on the node if and only if it has a CertificationArtifact
> with `violations == 0` in the kernel BPF map.**

This is proved in `fstar/Tameshi.Refinement.fst` (the Refinement + Soundness theorems).
If you change any code that touches `PomsEntry`, `CertificationArtifact`,
`attest_binary()`, or `push_poms_to_kernel()`, re-run:

```bash
nix run .#verify-proptest && cargo test
```

## 6. Adding a New Infrastructure Layer

To add a new `LayerType` (e.g., a new cloud provider):

1. Add the variant to `LayerType` enum in `src/signature.rs`
2. Add `Display` and `FromStr` implementations
3. Create a collector in `src/collectors/your_layer.rs` implementing `LayerCollector`
4. Add it to the `arb_layer_type()` strategy in `tests/proptest_properties.rs`
5. Run `nix run .#verify-proptest` — all 38 properties must still pass

## 7. Common Tasks

### Attest a binary (in tests)

```rust
use tameshi::bpf_loader::{MockBpfMaps, attest_binary};
use tameshi::hash::Blake3Hash;

let maps = MockBpfMaps::new();
let binary = Blake3Hash::digest(b"my-binary-content");
let poms = Blake3Hash::digest(b"poms-artifact");
attest_binary(&maps, &binary, &poms).unwrap();
// Binary is now authorized in the mock map
```

### Compose a certification artifact

```rust
use tameshi::certification_artifact::{compose_certification_artifact, verify_certification_artifact};
use tameshi::hash::Blake3Hash;

let artifact = compose_certification_artifact(
    "/usr/bin/gateway",
    Blake3Hash::digest(b"nix-closure"),      // artifact provenance
    Blake3Hash::digest(b"kensa-assessment"),  // compliance control
    Blake3Hash::digest(b"ferrite-poms"),      // memory safety proof
    "production",
);
assert!(verify_certification_artifact(&artifact));
println!("Composed root: {}", artifact.composed_root.to_hex());
```

### Build and verify a heartbeat chain

```rust
use tameshi::heartbeat::*;
use tameshi::hash::Blake3Hash;

let chain = HeartbeatChain::new();
chain.append(
    VerifierIdentity::new("sekiban", "pod-abc", "1.0.0"),
    HeartbeatEvent::AdmissionDecision,
    VerificationOutcome::Allowed,
    "prod/Deployment/gateway",
    Blake3Hash::digest(b"signature-checked"),
);
assert!(chain.verify_integrity());
assert_eq!(chain.len(), 1);
```

## 8. Documentation Map

| If you need to... | Read this |
|-------------------|-----------|
| Understand the business case | `docs/grand-unified-specification.md` Level 1 |
| Understand the data structures | `docs/grand-unified-specification.md` Level 2 |
| Understand the Ferrite→Kernel pipeline | `docs/grand-unified-specification.md` Level 3 |
| Understand the eBPF enforcement | `docs/grand-unified-specification.md` Level 4 |
| Understand the proof strategy | `docs/grand-unified-specification.md` Level 5 |
| Read the mathematical theorems | `docs/mathematical-foundations.md` |
| See the full theorem coverage matrix | `docs/verification-strategy.md` |
| Present to executives/auditors | `docs/FORMAL_VERIFICATION_SUMMARY.md` |

## 9. Do Not

- **Do not** change field order in `#[repr(C)]` structs (`PomsEntry`, `KanshiConfig`, `AuditEvent`) — the kernel reads at fixed byte offsets
- **Do not** skip `nix run .#verify-proptest` after changing cryptographic code — the 38 properties catch subtle invariant violations that unit tests miss
- **Do not** accept a PoMS with `violations > 0` — the `FerriteCollector::from_json()` enforces this, but never bypass it
- **Do not** modify `HeartbeatChain` entries after append — the chain is append-only by design and the hash linkage will break
