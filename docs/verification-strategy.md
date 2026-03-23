# Verification Strategy

tameshi uses three complementary verification layers, each providing progressively
stronger guarantees. Together they ensure that every theorem in
`mathematical-foundations.md` is machine-verified.

## Layer 1: Property-Based Testing (proptest)

**38 properties × 10,000 cases = 380,000 randomized checks**

Proptest generates random inputs and verifies that security invariants hold
across a wide distribution. This catches implementation bugs but does not
constitute proof — it is bounded empirical evidence.

### Running

```bash
# Default (10,000 cases per new property, 256 per original)
cargo test --test proptest_properties

# Nightly CI (100,000 cases)
PROPTEST_CASES=100000 cargo test --test proptest_properties
```

### Coverage

| Theorem | Property | What It Checks |
|---------|----------|----------------|
| 2.1 | `hash_combine_non_commutative` | `H(a\|\|b) != H(b\|\|a)` |
| 2.1 | `avalanche_effect` | 1-bit flip changes ~128/256 output bits |
| 2.2 | `domain_separation_leaf_vs_internal` | 0x00 prefix != 0x01 prefix |
| 3.1 | `merkle_tamper_detection` | Modified leaf changes root |
| 3.3 | `merkle_proof_validity` | Valid proofs verify |
| 3.3 | `merkle_proof_tamper_with_sibling` | Corrupted proof fails |
| 4.1 | `certification_artifact_*` (6 props) | 3-leaf binding, tamper, roundtrip |
| 4.1 | `certification_artifact_three_paths_independent` | All 3 proof paths verify |
| 4.1 | `certification_artifact_partial_tamper` | Tampered control fails |
| 4.1.1 | `certification_artifact_root_guessing` | Random roots never match |
| 4.1.2 | `selective_disclosure_hides_other_leaves` | Proof hides sibling leaves |
| 5.1 | `merkle_order_independence` | Same layers, any order, same root |
| 5.1 | `canonical_sort_stability` | Duplicate types, stable root |
| 6.1 | `global_root_order_independence` | BTreeMap order doesn't matter |
| 6.2 | `hierarchical_tamper_detection` | Artifact change propagates to global |
| 7.1 | `chain_integrity_random_tampering` | Tampered entry breaks chain |
| 7.1.1 | `chain_deletion_detection` | Removed entry detected |
| 7.1.2 | `chain_reorder_detection` | Swapped entries detected |
| 8.1 | `consistency_proof_after_extend` | Proof anchors across extensions |
| 9.1 | `two_phase_binding_different_compliance` | Different c => different s |
| 9.1 | `two_phase_binding_different_untested` | Different u => different s |
| 10.1 | `split_knowledge_fragment_change` | Changed fragment => different sig |
| 10.1 | `split_knowledge_both_fragments_needed` | Wrong fragment => verify fails |
| — | `gating_default_deny` | Default policy denies without compliance |

## Layer 2: Bounded Model Checking (Kani)

**12 harnesses, exhaustive over 4-byte state space**

Kani exhaustively checks ALL possible inputs within bounds. Unlike proptest,
this is not sampling — it is complete for the bounded domain. Properties
that hold for any injective hash function hold for any collision-resistant
function (CR implies injectivity on distinct inputs w.o.p.).

### Running

```bash
# Requires kani toolchain: cargo install --locked kani-verifier && cargo kani setup
cargo kani --manifest-path proofs/kani/Cargo.toml
```

### Harnesses

| Module | Harness | Theorem | What It Proves |
|--------|---------|---------|----------------|
| `hash_proofs` | `hash_determinism` | — | Same input => same output |
| `hash_proofs` | `combine_non_commutative` | 2.1 | Swap detection for distinct inputs |
| `merkle_proofs` | `merkle_tamper_4_leaf` | 3.1 | Any leaf tamper changes root (4-leaf) |
| `merkle_proofs` | `canonical_sort` | 5.1 | Sorted leaves produce stable root |
| `merkle_proofs` | `domain_disjoint` | 2.2 | Leaf/internal domains never collide |
| `artifact_proofs` | `compose_verify_roundtrip` | 4.1 | Deterministic 3-leaf artifact root |
| `artifact_proofs` | `tamper_any_leaf` | 4.1 | Any component tamper changes root |
| `chain_proofs` | `chain_linkage_invariant` | 7.1 | Correct chain passes verification |
| `chain_proofs` | `chain_tamper_detection` | 7.1 | Content tamper breaks linkage |
| `signing_proofs` | `xor_bijection` | 10.1 | `xor(xor(a,b),b) == a` |
| `signing_proofs` | `split_knowledge_key_changes` | 10.1 | Distinct fragments => distinct keys |
| `gating_proofs` | `gate_default_deny` | — | No compliance => deny |

### Trust Model

The Kani proofs use a 4-byte FNV-1a hash as an abstract model. This is
correct because:

1. FNV-1a is deterministic and injective on small inputs
2. `combine(a,b) = hash(0x02 || a || b)` — ordered concatenation guarantees non-commutativity
3. Domain separation uses distinct prefixes (0x00 leaf, 0x01 internal, 0x02 combine)
4. If a property holds for ANY deterministic injective function, it holds for BLAKE3
   (CR ⊂ injectivity on distinct inputs)

## Layer 3: Formal Proofs (F*)

**7 modules, unbounded proofs over abstract CR hash**

F* proofs are the strongest guarantee: they hold for ALL inputs of ANY size.
BLAKE3 is modeled as an abstract collision-resistant hash function via axioms
(`admit()` for the CR assumption). Every security theorem is proved as an F*
lemma that reduces to these axioms.

### Running

```bash
# Requires F* toolchain: opam install fstar
cd fstar && fstar.exe --include . Tameshi.Hash.fst Tameshi.Merkle.fst \
  Tameshi.Artifact.fst Tameshi.Chain.fst Tameshi.Signing.fst Tameshi.Reduction.fst
```

### Modules

| Module | Theorem | Proof Technique |
|--------|---------|----------------|
| `Tameshi.Hash` | Axioms | CR, injectivity, domain separation, XOR axioms (`admit()`) |
| `Tameshi.Merkle` | 3.1, 3.2 | Structural induction on tree depth |
| `Tameshi.Artifact` | 4.1 | Reduction to Merkle tamper evidence |
| `Tameshi.Chain` | 7.1 | Induction on chain length |
| `Tameshi.Signing` | 10.1 | XOR perfect cipher argument |
| `Tameshi.Reduction` | 11.1 | Meta-theorem: all reductions compose |

### Trust Model

The F* proofs `admit()` these axioms about BLAKE3:

- **Collision resistance**: distinct inputs => distinct outputs
- **Combine injectivity**: left and right arguments are independently injective
- **Domain separation**: `hash(0x00 || x) != hash(0x01 || y || z)` for all x,y,z
- **XOR involutivity**: `xor(xor(a,b),b) = a`
- **XOR injectivity**: `a1 != a2 => xor(a1,b) != xor(a2,b)`

Everything else is mechanically verified. If BLAKE3 is broken (collision found),
the admitted axioms become invalid and the proofs no longer hold — but this is
exactly the trust model of every cryptographic system.

## Theorem Coverage Matrix

| Theorem | Layer 1 (proptest) | Layer 2 (Kani) | Layer 3 (F*) |
|---------|-------------------|----------------|--------------|
| 2.1 Non-commutativity | `hash_combine_non_commutative` + `avalanche_effect` | `combine_non_commutative` | Hash axiom |
| 2.2 Domain separation | `domain_separation_leaf_vs_internal` | `domain_disjoint` | Hash axiom |
| 3.1 Tamper evidence | `merkle_tamper_detection` + `hierarchical_tamper_detection` | `merkle_tamper_4_leaf` | `Tameshi.Merkle` |
| 3.2 Second-preimage | Covered by 2.2 | `domain_disjoint` | `Tameshi.Merkle` |
| 3.3 Proof soundness | `merkle_proof_validity` + `merkle_proof_tamper_with_sibling` | `compose_verify_roundtrip` | — |
| 4.1 Binding | `certification_artifact_*` (6 properties) | `tamper_any_leaf` | `Tameshi.Artifact` |
| 5.1 Order independence | `merkle_order_independence` + `canonical_sort_stability` | `canonical_sort` | — |
| 6.1 Global determinism | `global_root_order_independence` | — | — |
| 6.2 Hierarchical tamper | `hierarchical_tamper_detection` | — | — |
| 7.1 Chain integrity | `chain_integrity_random_tampering` | `chain_linkage_invariant` + `chain_tamper_detection` | `Tameshi.Chain` |
| 8.1 Consistency proof | `consistency_proof_after_extend` | — | — |
| 9.1 Two-phase binding | `two_phase_binding_different_*` (2 properties) | — | — |
| 10.1 Split-knowledge | `split_knowledge_*` (2 properties) | `xor_bijection` + `split_knowledge_key_changes` | `Tameshi.Signing` |
| 11.1 Security reduction | — (theoretical) | — | `Tameshi.Reduction` |
| 11.2 Ledger reduction | Covered by 7.1 | — | Part of `Tameshi.Chain` |
