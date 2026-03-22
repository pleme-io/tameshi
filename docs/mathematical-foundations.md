# Mathematical Foundations of Tameshi

## Formal Cryptographic Proofs for Deterministic Infrastructure Attestation

---

## Table of Contents

1. [Notation and Preliminaries](#1-notation-and-preliminaries)
2. [The Hash Function Model](#2-the-hash-function-model)
3. [Domain-Separated Merkle Trees](#3-domain-separated-merkle-trees)
4. [The Certification Artifact: A 3-Leaf Binding Commitment](#4-the-certification-artifact-a-3-leaf-binding-commitment)
5. [N-Layer Composition: The Master Signature](#5-n-layer-composition-the-master-signature)
6. [Hierarchical Fleet Aggregation: The Global Root](#6-hierarchical-fleet-aggregation-the-global-root)
7. [The Forensic Hash Chain: Append-Only Ledger](#7-the-forensic-hash-chain-append-only-ledger)
8. [Consistency Proofs: Certificate Transparency Extension](#8-consistency-proofs-certificate-transparency-extension)
9. [The Two-Phase Attestation Model](#9-the-two-phase-attestation-model)
10. [Threshold Signing and Split-Knowledge Security](#10-threshold-signing-and-split-knowledge-security)
11. [Security Reductions](#11-security-reductions)
12. [Complexity Analysis](#12-complexity-analysis)
13. [Ecosystem Integrations as Consequences](#13-ecosystem-integrations-as-consequences)

---

## 1. Notation and Preliminaries

This section establishes the formal language used throughout. Every subsequent theorem, proof, and definition builds on these primitives — precision here prevents ambiguity everywhere else.

### 1.1 Sets and Spaces

| Symbol | Definition |
|--------|-----------|
| `{0,1}^n` | The set of all binary strings of exactly `n` bits |
| `{0,1}^*` | The set of all finite-length binary strings |
| `B_256` | `{0,1}^256` — the 256-bit hash output space, with `\|B_256\| = 2^256` |
| `a \|\| b` | Concatenation of byte strings `a` and `b` |
| `a XOR b` | Bitwise exclusive-or of equal-length strings `a` and `b` |
| `[n]` | The set `{0, 1, ..., n-1}` |
| `negl(k)` | A negligible function: for all polynomials `p`, there exists `k_0` such that for all `k > k_0`, `negl(k) < 1/p(k)` |

### 1.2 Security Parameter

**Definition 1.1 (Security Parameter).** The security parameter `k` quantifies the computational hardness of breaking cryptographic primitives. For BLAKE3 with 256-bit output:

| Property | Security Parameter | Meaning |
|----------|--------------------|---------|
| Preimage resistance | `k = 256` | An adversary needs `~2^256` operations to find a preimage |
| Collision resistance | `k = 128` | An adversary needs `~2^128` operations to find a collision (birthday bound) |

All `negl(k)` bounds in this document use the collision resistance parameter `k = 128` unless stated otherwise. This means `negl(k) <= 2^(-128)` — a quantity so small that no adversary can achieve it with polynomially-bounded computation.

### 1.3 Cryptographic Hash Functions

**Definition 1.2 (Cryptographic Hash Function).** A hash function `H: {0,1}^* -> B_256` is a deterministic, efficiently computable function satisfying the following properties:

- **(P1) Preimage Resistance.** For a uniformly random `y` drawn from the range of `H`, no efficient adversary `A` can find `x` such that `H(x) = y`:

  ```
  Pr[H(A(y)) = y] <= negl(k)       where k = 256
  ```

- **(P2) Second-Preimage Resistance.** Given `x`, no efficient adversary `A` can find `x' != x` such that `H(x') = H(x)`:

  ```
  Pr[A(x) = x' : x' != x, H(x') = H(x)] <= negl(k)       where k = 128
  ```

- **(P3) Collision Resistance.** No efficient adversary `A` can find any pair `(x, x')` with `x != x'` such that `H(x) = H(x')`:

  ```
  Pr[A() = (x, x') : x != x', H(x) = H(x')] <= negl(k)       where k = 128
  ```

- **(P4) Determinism.** `H` is a pure function — for all `x in {0,1}^*`, repeated evaluation always yields the same output:

  ```
  H(x) = H(x)       (same input, same output, always)
  ```

Note that (P3) implies (P2), which in turn implies (P1) for random preimages. We state all four because different tameshi properties rely on different levels of the hierarchy.

### 1.4 BLAKE3 Instantiation

**Definition 1.3 (BLAKE3).** Let `B3: {0,1}^* -> B_256` denote the BLAKE3 hash function. BLAKE3 is constructed from the BLAKE2s round function with Bao tree hashing, providing:
- 256-bit preimage resistance
- 128-bit collision resistance (birthday bound)
- 2-3x faster than SHA-256 on modern CPUs (SIMD vectorization)
- Streaming mode via incremental `Hasher` API

Throughout this document, `H` refers to `B3` unless stated otherwise. The system also supports `SHA256` as a FIPS 140-3 alternative via the `AttestationHasher` trait — all proofs hold for any `H` satisfying (P1)-(P4).

### 1.5 Asymptotic Notation

| Symbol | Meaning |
|--------|---------|
| `O(f(n))` | Asymptotic upper bound |
| `log(n)` | Base-2 logarithm (all trees are binary) |
| `ceil(x)` | Ceiling function (smallest integer `>= x`) |
| `\|S\|` | Cardinality of set `S` |
| `\|x\|` | Byte length of string `x` |

---

## 2. The Hash Function Model

The entire tameshi security model reduces to properties of the hash function `H`. This section establishes the two fundamental derived properties that power the rest of the system: combine non-commutativity and domain separation. Every subsequent section is a consequence of these foundations.

### 2.1 The Combination Function

**Definition 2.1 (Hash Combination).** The combination function `C: B_256 x B_256 -> B_256` is defined as:

```
C(a, b) = H(a || b)
```

This function takes two 256-bit hashes and produces a single 256-bit hash of their 512-bit concatenation.

**Theorem 2.1 (Combine Non-Commutativity).** For the combination function `C(a, b) = H(a || b)`, if `a != b` then `C(a, b) != C(b, a)` with overwhelming probability:

```
Pr[C(a, b) = C(b, a) : a != b] <= negl(k)       where k = 128
```

*Proof.* Assume `a != b`. Then `a || b` and `b || a` are distinct 512-bit strings (since swapping two distinct 256-bit halves produces a different string). If `C(a, b) = C(b, a)`, then `H(a || b) = H(b || a)` with `a || b != b || a`, which is a collision in `H`. By (P3), this occurs with probability at most `negl(k)`. **QED**

**Significance.** This property ensures that the *order* of inputs to hash combinations carries meaning. Composing layer `A` with layer `B` produces a different result than composing layer `B` with layer `A`. The system resolves this into a feature via canonical sorting (Section 5): by always sorting inputs before composition, the result is order-independent while the non-commutativity guarantees that *different* input sets produce different results.

### 2.2 Domain Separation

**Definition 2.2 (Domain-Separated Hash).** Given distinct domain identifiers `d_0, d_1 in {0,1}^8` (single bytes), define the domain-separated hash functions:

```
H_{d_0}(x) = H(d_0 || x)
H_{d_1}(x) = H(d_1 || x)
```

**Theorem 2.2 (Domain Separation Prevents Cross-Domain Collisions).** For `d_0 != d_1`, no efficient adversary can find `x, x'` such that `H_{d_0}(x) = H_{d_1}(x')`:

```
Pr[H_{d_0}(x) = H_{d_1}(x')] <= negl(k)       where k = 128
```

*Proof.* Since `d_0 != d_1`, the strings `d_0 || x` and `d_1 || x'` always differ in their first byte, regardless of the choice of `x` and `x'`. They are therefore distinct inputs to `H`. If `H(d_0 || x) = H(d_1 || x')`, this constitutes a collision in `H`. By (P3), the probability is bounded by `negl(k)`. **QED**

**Implementation.** Tameshi uses RFC 9162 (Certificate Transparency) domain separation:
- `d_0 = 0x00` — leaf domain
- `d_1 = 0x01` — internal node domain

This is enforced at the type level by `Blake3Algorithm::concat_and_hash()` (internal prefix) and `domain_separated_leaf()` (leaf prefix) in `src/merkle.rs`.

---

## 3. Domain-Separated Merkle Trees

Merkle trees are the central data structure of tameshi. They enable a set of `n` hashes to be compressed into a single 256-bit root, with the property that any modification to any input is detectable, and any individual input can be proved a member of the set in `O(log n)` space. This section formalizes the construction and proves its security properties.

### 3.1 Formal Definition

**Definition 3.1 (Domain-Separated Binary Merkle Tree).** Given an ordered sequence of leaf values `L = (l_0, l_1, ..., l_{n-1})` where each `l_i in B_256`, the domain-separated Merkle tree `MT(L)` is constructed as follows:

**Padding.** If `n = 0`, the tree is empty and has no root. If `n >= 1`, pad the sequence to the next power of 2:

```
n' = max(1, 2^{ceil(log2(n))})       (for n = 1, n' = 1; for n = 2, n' = 2; etc.)
```

Padding is achieved by duplicating the last leaf: for `j in {n, n+1, ..., n'-1}`, set `l_j = l_{n-1}`.

**Leaf level.** For each `l_j` (where `j in [n']`):

```
h_j = H(0x00 || l_j)
```

**Internal levels.** For level `m` from `0` to `ceil(log2(n')) - 1`, combine siblings:

```
node(m+1, j) = H(0x01 || node(m, 2j) || node(m, 2j+1))
```

where `node(0, j) = h_j` (the leaf hashes).

**Root.** The unique value at the top level is `root(MT(L))`.

### 3.2 Tree Visualizations

**4-leaf tree** — `L = (l_0, l_1, l_2, l_3)`:

```
Level 2 (root):       R = H(0x01 || N_L || N_R)
                      +
                     / \
                    /   \
Level 1:       N_L       N_R
            H(01||h0||h1)  H(01||h2||h3)
              / \           / \
             /   \         /   \
Level 0:   h_0  h_1     h_2  h_3
          H(00||l0) H(00||l1) H(00||l2) H(00||l3)
            |       |       |       |
Input:     l_0     l_1     l_2     l_3
```

**3-leaf tree** (CertificationArtifact case) — padded to 4 with duplication of `l_2`:

```
Level 2 (root):       R = H(0x01 || N_L || N_R)
                      +
                     / \
                    /   \
Level 1:       N_L       N_R
            H(01||h0||h1)  H(01||h2||h2)
              / \           / \
             /   \         /   \
Level 0:   h_0  h_1     h_2  h_2
            |    |       |    |
Input:     l_0  l_1     l_2  (pad = l_2)
            |    |       |
         provenance  compliance  intent
```

**14-leaf tree** (all layer types) — padded to 16:

```
Level 4 (root):                    R
                                 /   \
Level 3:                      /       \
                            /           \
                          N              N
                        / \            / \
Level 2:              N    N         N    N
                     /\   /\        /\   /\
Level 1:            N  N N  N      N  N N  N
                   /\ /\ /\ /\   /\ /\ /\ /\
Level 0:          h0 h1 ... h13 h13 h13 (padded to 16)
                  |  |      |
Input layers:   Nix Oci ... InSpecResult
```

### 3.3 Security Properties

**Theorem 3.1 (Tamper Evidence).** For any `i in [n]`, let `L' = L` except `l'_i != l_i`. Then:

```
Pr[root(MT(L')) = root(MT(L))] <= negl(k)
```

That is, changing any single leaf changes the root with overwhelming probability.

*Proof.* Let the path from leaf `i` to the root be the sequence of nodes `(v_0, v_1, ..., v_d)` where `d = ceil(log2(n'))`, `v_0 = h_i = H(0x00 || l_i)`, and `v_d = root(MT(L))`.

We prove by induction that `v'_j != v_j` for all `j in {0, 1, ..., d}`:

**Base case** (`j = 0`):

```
v'_0 = H(0x00 || l'_i) != H(0x00 || l_i) = v_0
```

This holds by (P2): `l'_i != l_i` implies `0x00 || l'_i != 0x00 || l_i`, so equal output would be a second preimage.

**Inductive step** (`j -> j+1`): Assume `v'_j != v_j`. At level `j+1`, the node is computed as:

```
v_{j+1} = H(0x01 || v_j || sibling_j)       (if v_j is the left child)
   or   = H(0x01 || sibling_j || v_j)       (if v_j is the right child)
```

In either case, since `v'_j != v_j` and the sibling is unchanged, the input to `H` at level `j+1` differs between the original and modified trees. By (P2), `v'_{j+1} != v_{j+1}` except with probability `negl(k)`.

**Conclusion.** By induction over `d` levels, applying a union bound over the `d` applications of (P2):

```
Pr[root(MT(L')) = root(MT(L))] <= d * negl(k) = ceil(log2(n')) * negl(k) = negl(k)
```

(since `d` is at most logarithmic in `n`, multiplying a negligible function by a polynomial yields a negligible function). **QED**

**Theorem 3.2 (Second-Preimage Resistance via Domain Separation).** No efficient adversary can present an internal node hash as a valid leaf hash, or vice versa:

```
Pr[H(0x01 || left || right) = H(0x00 || l)] <= negl(k)       for any (left, right, l)
```

*Proof.* The inputs `0x01 || left || right` and `0x00 || l` differ in their first byte (regardless of the values of `left`, `right`, `l`). They are therefore distinct inputs to `H`. Equal outputs constitute a collision, bounded by `negl(k)` via (P3). **QED**

**Significance.** Without domain separation, an adversary could construct a leaf value `l^*` whose hash `H(l^*)` equals `H(left || right)` for some known internal node. This would allow the adversary to forge a subtree. Domain separation closes this attack vector at the type level.

### 3.4 Inclusion Proofs

**Definition 3.2 (Merkle Inclusion Proof).** For leaf `l_i` in tree `MT(L)` with `n'` leaves and depth `d = ceil(log2(n'))`, the inclusion proof `pi_i` is the sequence of sibling hashes along the path from leaf `i` to the root:

```
pi_i = (s_0, s_1, ..., s_{d-1})
```

where `s_j` is the sibling of the node on the path at level `j`.

**Definition 3.3 (Verification Algorithm).** `Verify(l_i, i, pi_i, root)`:

```
1.  v <- H(0x00 || l_i)                      // Domain-separated leaf hash
2.  For j = 0 to d-1:
      bit <- (i >> j) AND 1                   // Path direction at level j
      If bit = 0:
        v <- H(0x01 || v || pi_i[j])          // v is left child
      Else:
        v <- H(0x01 || pi_i[j] || v)          // v is right child
3.  Return (v = root)
```

**Theorem 3.3 (Inclusion Proof Soundness).** If `Verify(l_i, i, pi_i, root) = true`, then either:
1. `l_i` is the `i`-th leaf of the tree whose root is `root`, or
2. The adversary has found a collision in `H`.

*Proof.* Suppose `Verify(l_i, i, pi_i, root) = true` but `l_i` is not the `i`-th leaf. Let `l^*_i` be the actual `i`-th leaf, so `l_i != l^*_i`.

The verification reconstructs a path `(v_0, v_1, ..., v_d = root)` from `H(0x00 || l_i)`. The actual tree has a path `(v^*_0, v^*_1, ..., v^*_d = root)` from `H(0x00 || l^*_i)`.

At level 0: `v_0 = H(0x00 || l_i) != H(0x00 || l^*_i) = v^*_0` (by P2, since `l_i != l^*_i`).

At level `d`: `v_d = root = v^*_d` (both paths arrive at the same root).

Since the paths start at different values and end at the same value, there must exist some level `j` where `v_j != v^*_j` but `v_{j+1} = v^*_{j+1}`. At that level:

```
H(0x01 || v_j || s_j) = H(0x01 || v^*_j || s_j)       (same sibling)
```

with `v_j != v^*_j`. The inputs `0x01 || v_j || s_j` and `0x01 || v^*_j || s_j` are distinct, so this is a collision in `H`. **QED**

**Corollary 3.3.1 (Proof Size).** For a tree with `n` leaves:

```
|pi_i| = ceil(log2(n')) hash values = ceil(log2(n')) * 32 bytes
```

| Leaves (n) | Padded (n') | Depth (d) | Proof size (bytes) |
|-----------|-------------|-----------|-------------------|
| 1 | 1 | 0 | 0 |
| 2 | 2 | 1 | 32 |
| 3 | 4 | 2 | 64 |
| 4 | 4 | 2 | 64 |
| 5-8 | 8 | 3 | 96 |
| 9-16 | 16 | 4 | 128 |
| 14 (all layers) | 16 | 4 | 128 |

---

## 4. The Certification Artifact: A 3-Leaf Binding Commitment

The CertificationArtifact is the atomic unit of tameshi attestation. It cryptographically binds three independently-produced values — provenance, compliance, and intent — into a single 256-bit root. This binding is the foundation upon which all gating decisions rest: if the root matches, all three sources are authentic; if any source changes, the root changes.

### 4.1 Construction

**Definition 4.1 (Certification Artifact).** A `CertificationArtifact` is a tuple `CA = (a, c, i, r, Pi)` where:

| Component | Symbol | Description |
|-----------|--------|-------------|
| Artifact hash | `a in B_256` | Build provenance (Nix derivation hash or OCI manifest digest) |
| Control hash | `c in B_256` | Compliance assessment (kensa evaluation output) |
| Intent hash | `i in B_256` | Infrastructure intent (Pangea synthesis output) |
| Composed root | `r in B_256` | `root(MT([a, c, i]))` — the 3-leaf Merkle root |
| Proof paths | `Pi = (pi_0, pi_1, pi_2)` | Inclusion proofs for each leaf |

The composed root `r` is computed as:

```
h_a = H(0x00 || a)               // Leaf 0: provenance (domain-separated)
h_c = H(0x00 || c)               // Leaf 1: compliance (domain-separated)
h_i = H(0x00 || i)               // Leaf 2: intent (domain-separated)
h_p = H(0x00 || i)               // Leaf 3: padding (duplicate of leaf 2)

N_L = H(0x01 || h_a || h_c)      // Left internal node
N_R = H(0x01 || h_i || h_p)      // Right internal node

r   = H(0x01 || N_L || N_R)      // Root
```

Total hash evaluations: 7 (4 leaves + 2 internal + 1 root). All are constant-time for fixed-size inputs.

### 4.2 Visualization

```
     +===================================+
     |         r = composed_root         |   256 bits — the single
     |  H(0x01 || N_L || N_R)           |   value that represents
     +===========+===========+===========+   the entire attestation
                 |
          +------+------+
          |             |
    +-----+-----+ +----+-----+
    |    N_L    | |    N_R    |
    | H(01||..) | | H(01||..) |
    +--+-----+--+ +--+-----+--+
       |     |        |     |
     +-+-+ +-+-+    +-+-+ +-+-+
     |h_a| |h_c|    |h_i| |h_i|
     +-+-+ +-+-+    +-+-+ +-+-+
       |     |        |     |
       a     c        i   (pad)
       |     |        |
  Provenance Compliance Intent
  (Nix/OCI)  (kensa)   (Pangea)
```

### 4.3 Binding Theorem

**Theorem 4.1 (Simultaneous Binding).** The composed root `r` is a cryptographic commitment to the triple `(a, c, i)` simultaneously, satisfying:

1. **Completeness.** Given `(a, c, i)`, the root `r` is computable deterministically.
2. **Binding.** No efficient adversary can find `(a', c', i') != (a, c, i)` such that `root(MT([a', c', i'])) = r`, except with probability `negl(k)`.
3. **Independent Sensitivity.** Changing any single input changes the root.

*Proof of (1).* The construction in Definition 4.1 is a composition of `H` (deterministic by P4) applied to deterministically-constructed inputs. No randomness, no state, no I/O. **QED**

*Proof of (2).* Let `(a', c', i') != (a, c, i)`. At least one component differs. We consider the case `a' != a` (the cases `c' != c` and `i' != i` are symmetric).

Step 1: `a' != a` implies `0x00 || a' != 0x00 || a`, so by (P2):
```
h'_a = H(0x00 || a') != H(0x00 || a) = h_a
```

Step 2: Since `h'_a != h_a` and `h_c` is unchanged:
```
0x01 || h'_a || h_c != 0x01 || h_a || h_c
```
so by (P2):
```
N'_L = H(0x01 || h'_a || h_c) != H(0x01 || h_a || h_c) = N_L
```

Step 3: Since `N'_L != N_L` and `N_R` is unchanged:
```
0x01 || N'_L || N_R != 0x01 || N_L || N_R
```
so by (P2):
```
r' = H(0x01 || N'_L || N_R) != H(0x01 || N_L || N_R) = r
```

Each step fails (producing equality) with probability at most `negl(k)`. By union bound over 3 steps: `Pr[r' = r] <= 3 * negl(k) = negl(k)`. **QED**

*Proof of (3).* This is a special case of (2): set exactly one component to differ and the others equal. The chain of (P2) applications from proof (2) applies identically. **QED**

**Corollary 4.1.1 (Non-Forgery).** An adversary who knows fewer than all three values `(a, c, i)` cannot produce the correct composed root `r`. Specifically, if one value is unknown, guessing the root succeeds with probability at most `2^(-256)` per attempt (preimage resistance of a 3-level hash chain).

*Proof.* The unknown input feeds through at least one `H` evaluation. By (P1), inverting `H` to find an input producing a specific output requires `~2^256` work. **QED**

**Corollary 4.1.2 (Selective Disclosure).** Given `r` and the inclusion proof `pi_j`, a verifier can confirm that leaf `j` has value `v_j` without learning the other leaf values.

*Proof.* The verification algorithm (Definition 3.3) uses only `v_j`, the sibling hashes in `pi_j`, and the root `r`. The sibling hashes are outputs of `H`, which by (P1) do not reveal their preimages. **QED**

### 4.4 Inclusion Proof Paths

For the 3-leaf tree (padded to 4), each leaf has a 2-node proof path:

```
Leaf 0 (artifact):     pi_0 = (h_c,  N_R)     // sibling at level 0, sibling at level 1
Leaf 1 (control):      pi_1 = (h_a,  N_R)     // sibling at level 0, sibling at level 1
Leaf 2 (intent):       pi_2 = (h_i,  N_L)     // sibling at level 0 (= self, padded), sibling at level 1
```

**Verification walkthrough for leaf 0 (artifact hash `a`):**

```
Step 1:  v = H(0x00 || a)                          // = h_a
Step 2:  v = H(0x01 || v || pi_0[0])               // = H(0x01 || h_a || h_c) = N_L
Step 3:  v = H(0x01 || v || pi_0[1])               // = H(0x01 || N_L || N_R) = r
Step 4:  Return (v == r)                            // true iff a is authentic
```

---

## 5. N-Layer Composition: The Master Signature

Infrastructure systems consist of multiple layers — Nix closures, OCI images, Helm charts, Kubernetes manifests, and more. The master signature compresses all layer hashes into a single Merkle root. The key challenge is ensuring this compression is deterministic: the same set of layers must always produce the same root, regardless of the order in which layers are collected.

### 5.1 Layer Model

**Definition 5.1 (Infrastructure Layer).** An infrastructure layer is a pair `(t, h)` where:
- `t in T` — the layer type, drawn from the ordered set:

  ```
  T = { Nix, Oci, Helm, Tofu, Kubernetes, Kindling, Tatara,
        FluxCD, ArgoCD, Akeyless, AkeylessTarget,
        PangeaSynthesis, RSpecResult, InSpecResult }
  ```

  with `|T| = 14`, equipped with a total order (the `Ord` trait in Rust).

- `h in B_256` — the layer hash, computed by the corresponding `LayerCollector`.

**Definition 5.2 (Layer Signature).** A `LayerSignature` is a triple `LS = (t, h, M)` where `M` is metadata (source identifier, input sub-hashes, etc.). The metadata does not participate in root computation.

### 5.2 Canonical Ordering and Composition

**Definition 5.3 (Canonical Layer Ordering).** Given a set of layer signatures `S = {LS_0, ..., LS_{n-1}}`, the canonical ordering is:

```
sort(S) = (LS_{sigma(0)}, LS_{sigma(1)}, ..., LS_{sigma(n-1)})
```

where `sigma` is the unique permutation such that `t_{sigma(j)} <= t_{sigma(j+1)}` for all `j`, with ties broken by the lexicographic order of the layer hashes `h`.

**Definition 5.4 (Master Signature Composition).** The untested master hash for a set of layers `S` is:

```
untested(S) = root(MT([h_{sigma(0)}, h_{sigma(1)}, ..., h_{sigma(n-1)}]))
```

where the hashes are taken in canonical order from `sort(S)`, and `MT` is the domain-separated Merkle tree (Definition 3.1).

### 5.3 Determinism Theorem

**Theorem 5.1 (Order-Independent Composition).** For any two permutations `pi_1, pi_2` of the same layer set `S`:

```
compose(pi_1(S)) = compose(pi_2(S))
```

*Proof.* The `compose` function applies `sort()` to its input before computing the Merkle root.

1. `sort()` is a deterministic function that depends only on the *set* of layer signatures (via the `Ord` implementation on `LayerType` and lexicographic tiebreaking on hashes), not their input ordering.
2. Given the same sorted sequence, `MT` constructs the same tree (Definition 3.1 is deterministic).
3. `root(MT(...))` is deterministic by (P4) of `H`.

Therefore `compose(pi_1(S)) = sort(pi_1(S)) = sort(S) = sort(pi_2(S)) = compose(pi_2(S))`. **QED**

### 5.4 Layer Composition Visualization

For 4 layers `{Nix, Oci, Helm, Kubernetes}` (shown in canonical sort order):

```
                     Master Root (untested)
                    /                      \
                   /                        \
          H(0x01 || h_Nix || h_Oci)   H(0x01 || h_Helm || h_K8s)
             /          \                /          \
          h_Nix       h_Oci          h_Helm       h_K8s
            |            |              |            |
     Nix closure    OCI manifest   Helm chart    K8s manifests
    (nix-store)    (skopeo)      (helm template) (kubectl)
```

**Size table for all possible layer counts:**

| Layers (n) | Padded (n') | Tree depth | Proof size (hashes) | Total hash operations |
|-----------|-------------|-----------|--------------------|-----------------------|
| 1 | 1 | 0 | 0 | 1 (leaf only) |
| 2 | 2 | 1 | 1 | 3 |
| 3-4 | 4 | 2 | 2 | 7 |
| 5-8 | 8 | 3 | 3 | 15 |
| 9-14 | 16 | 4 | 4 | 31 |
| 14 (all types) | 16 | 4 | 4 | 31 |

---

## 6. Hierarchical Fleet Aggregation: The Global Root

When tameshi operates across a fleet of clusters, each cluster independently computes its own attestation state. The global root compresses the entire fleet into a single 256-bit value, enabling a monitoring system to verify fleet-wide integrity by checking one hash.

**Important distinction.** The global root uses *concatenation hashing* (a flat hash over sorted inputs), not a Merkle tree. This is a deliberate design choice: Merkle trees provide `O(log n)` inclusion proofs, but at the fleet level, the number of clusters `k` is small (typically < 100) and proofs of individual cluster membership are not needed. Concatenation hashing is simpler and sufficient.

### 6.1 Two-Level Construction

**Definition 6.1 (Cluster Root).** For a cluster `c` with artifact composed roots `R_c = {r_0, r_1, ..., r_{m-1}}`:

```
cluster_root(c) = H(sort(R_c)[0] || sort(R_c)[1] || ... || sort(R_c)[m-1])
```

where `sort(R_c)` sorts the 32-byte hashes in lexicographic (byte-by-byte) order. This produces a deterministic hash regardless of the order in which artifacts are reported.

**Definition 6.2 (Global Root).** For a fleet of clusters `F` with cluster IDs `{id_0, id_1, ..., id_{k-1}}`:

```
global_root(F) = H(cluster_root(c_{sigma(0)}) || cluster_root(c_{sigma(1)}) || ... || cluster_root(c_{sigma(k-1)}))
```

where `sigma` sorts cluster IDs lexicographically. In the implementation, `BTreeMap<String, ClusterRootEntry>` guarantees this ordering by construction.

### 6.2 Visualization

```
  global_root = H(cr_a || cr_b || cr_c)
        |
        +--- cluster_root(a) = H(r_0 || r_1 || r_2)        <-- 3 artifacts
        |         |         |         |
        |        r_0       r_1       r_2
        |    (CertArtifact) (CertArtifact) (CertArtifact)
        |
        +--- cluster_root(b) = H(r_3 || r_4)                <-- 2 artifacts
        |         |         |
        |        r_3       r_4
        |
        +--- cluster_root(c) = H(r_5 || r_6 || r_7 || r_8) <-- 4 artifacts
                  |         |         |         |
                 r_5       r_6       r_7       r_8
```

### 6.3 Properties

**Theorem 6.1 (Deterministic Global Aggregation).** The global root is a deterministic function of the set of `(cluster_id, artifact_set)` pairs, independent of:
1. The order in which clusters report their roots
2. The order in which artifacts within a cluster are discovered
3. The wall-clock time at which computation occurs

*Proof.*
1. *Cluster root determinism:* Within each cluster, artifacts are sorted by their 32-byte hash value (lexicographic order). This ordering depends only on the hash values, not on discovery order. The concatenation is therefore deterministic, and `H` applied to a deterministic input is deterministic by (P4).

2. *Global root determinism:* Cluster IDs are stored in a `BTreeMap`, which maintains lexicographic key order regardless of insertion order. Iterating produces a deterministic sequence. `H` applied to this deterministic concatenation is deterministic by (P4).

3. *Time independence:* Neither `cluster_root()` nor `global_root()` has any time-dependent input. The functions operate purely on hash values and string identifiers. **QED**

**Theorem 6.2 (Hierarchical Tamper Evidence).** If any single `CertificationArtifact` in any cluster is modified, the global root changes (with overwhelming probability).

*Proof.* Let `CA_j` in cluster `c_i` be modified. By Theorem 4.1 (binding), `CA_j`'s composed root `r_j` changes. Since `r_j` is part of the concatenation input to `cluster_root(c_i)`, and the concatenation changes, `cluster_root(c_i)` changes by (P2). Since `cluster_root(c_i)` is part of the concatenation input to `global_root(F)`, `global_root(F)` changes by (P2). **QED**

### 6.4 Temporal Chain Linkage

**Definition 6.3 (Temporal Chain).** Each `GlobalStateRoot` stores a `previous_root` field and a monotonic `sequence` counter:

```
GSR_0: { root_hash: R_0, previous_root: [0; 32], sequence: 0 }
GSR_1: { root_hash: R_1, previous_root: R_0,     sequence: 1 }
GSR_n: { root_hash: R_n, previous_root: R_{n-1}, sequence: n }
```

This chain provides temporal ordering and ensures no intermediate fleet states are omitted.

---

## 7. The Forensic Hash Chain: Append-Only Ledger

The forensic hash chain is tameshi's tamper-evident audit trail. Every deployment, gate decision, and verification event is recorded as a cryptographically-linked entry. The chain provides three properties that no traditional database can: entries cannot be modified, deleted, or reordered without detection.

### 7.1 Formal Definition

**Definition 7.1 (Forensic Hash Chain).** A forensic hash chain `C = (e_0, e_1, ..., e_{n-1})` is an ordered sequence of entries where each entry `e_i` is a tuple:

```
e_i = (seq_i, ts_i, ca_i, sr_i, dc_i, eh_i, ph_i)
```

| Field | Type | Description |
|-------|------|-------------|
| `seq_i` | `N` | Monotonically increasing sequence number |
| `ts_i` | ISO 8601 | Timestamp with nanosecond precision |
| `ca_i` | `CertificationArtifact` | The attestation being recorded |
| `sr_i` | `SignedRoot` | DFC threshold signature over the artifact |
| `dc_i` | `DeploymentContext` | Where this artifact was deployed |
| `eh_i` | `B_256` | Entry hash (computed — see below) |
| `ph_i` | `B_256` | Previous hash (links to prior entry) |

### 7.2 Entry Hash Computation

The entry hash commits to every field of the entry, including the link to the previous entry:

```
eh_i = H(
    seq_i.to_le_bytes()                        ||
    ts_i.to_rfc3339(nanos, utc).as_bytes()     ||
    ca_i.composed_root                         ||
    sr_i.root                                  ||
    hash_context(dc_i)                         ||
    ph_i
)
```

The deployment context is hashed in a fixed canonical order to ensure determinism:

```
hash_context(dc) = H(
    dc.cluster       ||  dc.namespace    ||  dc.node       ||
    dc.pod           ||  dc.container    ||  dc.image_ref   ||
    dc.binary_paths.sorted().join(":")                      ||
    dc.sdlc_chain_hash.unwrap_or([0; 32])                  ||
    dc.compliance_report_hash.unwrap_or([0; 32])
)
```

### 7.3 Chain Linkage Invariant

The chain is linked by the rule:

```
ph_0  =  [0; 32]           (genesis entry — no predecessor)
ph_i  =  eh_{i-1}          for all i > 0
```

### 7.4 Visualization

```
  +============+       +============+       +============+       +============+
  |    e_0     |       |    e_1     |       |    e_2     |       |    e_3     |
  |------------|       |------------|       |------------|       |------------|
  | seq:  0    |       | seq:  1    |       | seq:  2    |       | seq:  3    |
  | ts:   t_0  |       | ts:   t_1  |       | ts:   t_2  |       | ts:   t_3  |
  | ca:   CA_0 |       | ca:   CA_1 |       | ca:   CA_2 |       | ca:   CA_3 |
  | sr:   S_0  |       | sr:   S_1  |       | sr:   S_2  |       | sr:   S_3  |
  | dc:   D_0  |       | dc:   D_1  |       | dc:   D_2  |       | dc:   D_3  |
  |            |       |            |       |            |       |            |
  | ph: [0;32] |------>| ph: eh_0   |------>| ph: eh_1   |------>| ph: eh_2   |
  | eh: eh_0   |       | eh: eh_1   |       | eh: eh_2   |       | eh: eh_3   |
  +============+       +============+       +============+       +============+
        |                    |                    |                    |
        v                    v                    v                    v
   H(all fields)        H(all fields)        H(all fields)        H(all fields)
   including ph_0       including ph_1       including ph_2       including ph_3
   = [0; 32]            = eh_0               = eh_1               = eh_2
```

The chain linkage means each entry commits to the *entire history* before it. Modifying `e_0` changes `eh_0`, which invalidates `ph_1 = eh_0` in `e_1`, which changes `eh_1`, and so on — a cascade of invalidation.

### 7.5 Integrity Theorem

**Theorem 7.1 (Chain Integrity).** For a forensic hash chain `C = (e_0, ..., e_{n-1})`, any modification to any entry `e_j` (where `0 <= j <= n-1`) is detectable by the verification algorithm, with the following caveat for the last entry.

The `verify_integrity()` algorithm checks, for each `i in [n]`:
1. Recompute `eh'_i` from the entry's fields and `ph_i`. Check `eh'_i = eh_i`.
2. For `i > 0`: check `ph_i = eh_{i-1}`.
3. For `i = 0`: check `ph_0 = [0; 32]`.

*Proof.* Consider an adversary modifying entry `e_j`:

**Case 1 — Field modification without hash update.** The adversary changes a non-hash field of `e_j` but leaves `eh_j` unchanged. Then `recomputed_eh_j != eh_j` (the hash input changed but the stored hash did not), and verification fails at step 1 for entry `j`.

**Case 2 — Field modification with hash update, `j < n-1`.** The adversary changes a field and updates `eh_j` to match. Then `eh_j` has a new value, but `e_{j+1}.ph_{j+1}` still equals the *original* `eh_j`. Verification fails at step 2 for entry `j+1`: `ph_{j+1} != eh_j`.

**Case 3 — Modification of the last entry (`j = n-1`).** The adversary modifies `e_{n-1}` and updates `eh_{n-1}` to match. Since there is no `e_n` to check `ph_n = eh_{n-1}`, this modification is undetectable by the chain alone.

**Mitigation for Case 3.** The head hash `eh_{n-1}` must be *externally anchored*: published to a transparency log, compared across clusters via the `GlobalStateClient`, or persisted to S3 via the `S3Emitter`. With external anchoring, modification of the last entry is detectable because the externally-stored `eh_{n-1}` no longer matches.

**Case 4 — Cascade rewrite (`j` through `n-1`).** The adversary modifies `e_j` and rewrites all subsequent entries to maintain internal consistency. This requires producing valid `SignedRoot` values (`sr_i`) for each rewritten entry. Since `SignedRoot` is produced by the DFC threshold signer (Section 10), the adversary would need the signing key — which is computationally infeasible to obtain. Without valid signatures, the rewritten entries contain the original `sr_i` values, which no longer correspond to the modified `ca_i` fields, and this inconsistency is detectable by any verifier that checks the signature. **QED**

**Corollary 7.1.1 (Append-Only).** Deletion of entry `e_j` (where `j < n-1`) is detectable: the chain breaks at `e_{j+1}` because `ph_{j+1} = eh_j` but `eh_j` is missing. Additionally, the sequence gap `seq_{j+1} - seq_{j-1} > 1` is detectable.

**Corollary 7.1.2 (Reordering Detection).** Swapping entries `e_j` and `e_{j+1}` breaks the chain at both positions: `ph_j` no longer equals `eh_{j-1}`, and `ph_{j+1}` no longer equals `eh_j`.

---

## 8. Consistency Proofs: Certificate Transparency Extension

Consistency proofs allow an auditor who has previously verified the chain up to some point to efficiently verify that the chain has been faithfully extended — without re-downloading and re-checking the entire history. This is the same mechanism used by Certificate Transparency (RFC 9162) for TLS certificate logs, adapted here for infrastructure attestation.

### 8.1 Definition

**Definition 8.1 (Consistency Proof).** Given a chain `C` at two states — `C_m = (e_0, ..., e_{m-1})` and `C_n = (e_0, ..., e_{n-1})` where `m <= n` — a consistency proof is:

```
ConsistencyProof = {
    from_seq:    m,
    to_seq:      n,
    proof_nodes: [eh_m, eh_{m+1}, ..., eh_{n-1}]
}
```

The proof contains the entry hashes for all entries in the extension `[m, n)`.

### 8.2 Verification

The verifier holds the chain head `eh_{m-1}` from their last audit. Verification proceeds:

```
1. Check proof_nodes[0] was computed from an entry with ph = eh_{m-1}
   (This confirms the extension starts from the known good state)

2. For each consecutive pair (proof_nodes[j], proof_nodes[j+1]):
   Check that proof_nodes[j+1] was computed from an entry with ph = proof_nodes[j]
   (This confirms the extension is internally consistent)

3. Accept the new chain head as proof_nodes[n-m-1] = eh_{n-1}
```

### 8.3 Properties

**Theorem 8.1 (Consistency Soundness).** If a consistency proof from `(m, eh_{m-1})` to `(n, eh_{n-1})` verifies, then either:
1. The chain prefix `C_n[0..m] = C_m` was not modified, or
2. The adversary has found a collision in `H`.

*Proof.* The chain linkage rule `ph_i = eh_{i-1}` means that `eh_{m-1}` commits to the entire history `C[0..m]`. Specifically, `eh_{m-1}` is computed as:

```
eh_{m-1} = H(seq_{m-1} || ts_{m-1} || ... || ph_{m-1})
where ph_{m-1} = eh_{m-2}
where eh_{m-2} = H(... || ph_{m-2})
...
where ph_0 = [0; 32]
```

If the prefix `C_n[0..m]` were modified to produce a different history but the same `eh_{m-1}`, this would require finding an input to `H` that produces `eh_{m-1}` — a second preimage, which succeeds with probability at most `negl(k)` by (P2).

The consistency proof then checks that entries `[m, n)` form a valid chain starting from `eh_{m-1}`. Since each `eh_i` depends on `ph_i = eh_{i-1}`, and the starting point `eh_{m-1}` is the verifier's trusted anchor, the extension is verified. **QED**

**Corollary 8.1.1 (Incremental Auditing Complexity).** An auditor who verified up to sequence `m` needs:
- **Computation:** `O(n - m)` hash verifications to confirm the extension
- **Bandwidth:** `(n - m) * 32` bytes of proof nodes
- **No re-verification** of the `[0, m)` prefix

---

## 9. The Two-Phase Attestation Model

A deployment is not secure merely because its binaries are authentic (Phase 1). It must also be *compliant* — assessed against regulatory and organizational policies (Phase 2). The two-phase model binds these concepts cryptographically: the "secure" hash proves both authenticity AND compliance in a single value.

### 9.1 Formal Definition

**Definition 9.1 (Two-Phase Master Signature).** A `MasterSignature` is a tuple `MS = (u, c, s)` where:

| Component | Symbol | Description |
|-----------|--------|-------------|
| Untested | `u in B_256` | Merkle root of infrastructure layer signatures (Section 5) |
| Compliance hash | `c in B_256` | Compliance assessment hash from kensa |
| Secure | `s in B_256` | `H(u \|\| c)` — cryptographic binding of both phases |

### 9.2 Phase Diagram

```
  Phase 1: UNTESTED                        Phase 2: SECURE
  (infrastructure only)                    (infrastructure + compliance)

  Layer_0  ----+
  Layer_1  ----+
  Layer_2  ----+---- compose_merkle ---> [u]
  ...      ----+     (sorted, Def 5.4)    |
  Layer_13 ----+                          |
                                          +--- H(u || c) ---> [s] = secure hash
                                          |
                    kensa assessment ---> [c]
                    (NIST 800-53,          |
                     CIS, OSCAL)          compliance hash

  Timeline:  collect layers ---> assess compliance ---> bind both ---> gate
```

### 9.3 Phase Composition Theorem

**Theorem 9.1 (Two-Phase Binding).** The secure hash `s = H(u || c)` is a binding commitment to both the infrastructure state `u` and the compliance assessment `c`. No efficient adversary can find `(u', c') != (u, c)` such that `H(u' || c') = s`:

```
Pr[H(u' || c') = H(u || c) : (u', c') != (u, c)] <= negl(k)
```

*Proof.* The pair `(u, c)` determines the 512-bit input `u || c` to `H`. A different pair `(u', c') != (u, c)` produces a different 512-bit input `u' || c' != u || c` (since either `u' != u` or `c' != c` or both, and the concatenation of two 256-bit values is injective). Finding equal outputs from distinct inputs is a collision, bounded by `negl(k)` via (P3). **QED**

**Corollary 9.1.1 (Compliance Cannot Be Retrofitted).** Given a published untested hash `u` and secure hash `s`, an adversary cannot substitute a different compliance hash `c' != c`:

```
Pr[H(u || c') = H(u || c) : c' != c] <= negl(k)
```

*Proof.* `u || c' != u || c` (since `c' != c`), so equal output is a collision. **QED**

**Significance.** This means a deployment that passed compliance assessment `c` cannot later be claimed to have passed a different assessment `c'`. The compliance state is immutably bound at attestation time.

### 9.4 Relationship to CertificationArtifact

The `MasterSignature` and `CertificationArtifact` serve complementary roles:

| Aspect | MasterSignature | CertificationArtifact |
|--------|----------------|----------------------|
| Structure | Flat: `H(u \|\| c)` | Merkle tree: 3-leaf |
| Purpose | Gate evaluation | Independent verification |
| Inputs | N layers + compliance | Provenance + compliance + intent |
| Proofs | None (all-or-nothing) | Per-leaf inclusion proofs |
| Use case | "Is this deployment allowed?" | "Prove provenance without revealing intent" |

Both are combined in practice:
```
CA.artifact_hash = derived from MS.untested     // Build provenance
CA.control_hash  = MS.compliance_hash           // Compliance assessment
CA.intent_hash   = pangea_synthesis_hash        // Infrastructure intent
```

---

## 10. Threshold Signing and Split-Knowledge Security

The cryptographic hashes established in Sections 3-9 prove *what* was attested. Signatures prove *who* attested it. Tameshi supports three signing modes with increasing security guarantees: local development signing, split-knowledge mock signing, and production distributed fragment cryptography.

### 10.1 The MockDfcSigner Construction

**Definition 10.1 (XOR Split-Knowledge Signer).** Given two 256-bit fragments `F_a, F_b in B_256`:

```
key  = H(F_a XOR F_b)
sig(m) = H_key(m)              // BLAKE3 keyed hash mode (MAC)
```

where `H_key` denotes BLAKE3's keyed hash mode: `H_key(m) = BLAKE3(key, m)`, a pseudorandom function keyed by `key`.

### 10.2 Information-Theoretic Security

**Theorem 10.1 (One-Time Pad Property).** Given only `F_a` (or symmetrically, only `F_b`), the key `key = H(F_a XOR F_b)` has full 256-bit uncertainty.

*Proof.* Let `F_a` be known and `F_b` be uniformly distributed over `B_256`.

Step 1: The function `f(F_b) = F_a XOR F_b` is a bijection on `B_256` (since XOR with a fixed value is its own inverse). Therefore, as `F_b` ranges uniformly over `B_256`, the value `F_a XOR F_b` also ranges uniformly over `B_256`.

Step 2: Under the random oracle model, `H` applied to a uniformly random input produces a uniformly random output. Therefore:

```
key = H(F_a XOR F_b) is uniformly distributed over B_256
```

Step 3: A uniformly random 256-bit value has min-entropy `H_inf(key) = 256` bits.

Conclusion: An adversary who knows only `F_a` has zero information about `key` — every possible key is equally likely. **QED**

**Visualization:**

```
  Fragment A (disk)         Fragment B (env var)
  +------------------+     +------------------+
  | F_a: a1 a2 .. a32|     | F_b: b1 b2 .. b32|
  +--------+---------+     +--------+---------+
           |                        |
           +-------- XOR ----------+
                     |
                     v
           (a1^b1)(a2^b2)..(a32^b32)     <-- uniform over B_256
                     |
                     v
                   H(...)                 <-- uniform over B_256
                     |
                     v
                    key                   <-- 256-bit signing key
                     |
                     v
               H_key(message)            <-- signature (MAC)
```

**Security model:** Compromising either storage medium alone (the filesystem for `F_a`, or the environment for `F_b`) reveals zero information about the signing key. Both fragments must be obtained simultaneously.

### 10.3 Production DFC (Akeyless)

In production, the `AkeylessDfcSigner` provides stronger guarantees than split-knowledge XOR:

**Definition 10.2 (Distributed Fragment Cryptography).** The signing key `K` is split into `t` fragments `K_1, ..., K_t` held by distinct infrastructure nodes within the Akeyless gateway. The following properties hold:

1. **Threshold security.** Any `t-1` fragments reveal zero information about `K`.
2. **Key never assembled.** The signing operation occurs inside the gateway; the key is never reconstructed in any single memory space.
3. **Signature-only output.** The gateway API returns `sig(m)` — never key material, fragments, or intermediate state.

---

## 11. Security Reductions

This section shows that breaking tameshi's security guarantees requires breaking BLAKE3. These are standard cryptographic reductions: we construct algorithms that transform any successful attack on tameshi into a successful attack on the underlying hash function.

### 11.1 Reduction to BLAKE3 Collision Resistance

**Theorem 11.1 (Master Security Reduction).** If an efficient adversary `A` can forge a tameshi attestation — that is, produce a valid composed root for a modified artifact — then there exists an efficient algorithm `R` that finds BLAKE3 collisions.

*Proof.* Construction of reduction `R`:

```
R receives: a BLAKE3 collision-finding challenge

R does:
  1. Choose arbitrary (a, c, i) in B_256^3
  2. Compute r = compose_certification_artifact(a, c, i)  // Definition 4.1
  3. Give (a, c, i, r) to adversary A
  4. A returns (a', c', i') with (a', c', i') != (a, c, i) and
     compose_certification_artifact(a', c', i') = r

R extracts a collision:
  5. Since (a', c', i') != (a, c, i), at least one component differs.
     WLOG assume a' != a (other cases are symmetric).

  6. Compute h'_a = H(0x00 || a') and h_a = H(0x00 || a).
     Case 6a: h'_a = h_a.
       Then (0x00 || a', 0x00 || a) is a collision in H. Output it.

     Case 6b: h'_a != h_a.
       Then N'_L = H(0x01 || h'_a || h_c) and N_L = H(0x01 || h_a || h_c).
       Since inputs differ, if N'_L = N_L:
         Output collision (0x01 || h'_a || h_c, 0x01 || h_a || h_c).
       If N'_L != N_L:
         Then r' = H(0x01 || N'_L || N_R) and r = H(0x01 || N_L || N_R).
         Since inputs differ and r' = r (by assumption):
         Output collision (0x01 || N'_L || N_R, 0x01 || N_L || N_R).

  7. In all cases, R outputs a valid BLAKE3 collision.
```

Since finding BLAKE3 collisions requires `~2^128` operations, no efficient adversary can forge tameshi attestations. **QED**

### 11.2 Reduction to Chain Integrity

**Theorem 11.2 (Ledger Forgery Reduction).** An adversary who modifies a forensic ledger entry without detection can either:
1. Find a second preimage in `H`, or
2. Forge a DFC threshold signature.

*Proof.* By Theorem 7.1, undetected modification of entry `e_j` requires one of:

- **Modifying `e_j` alone:** Requires `recomputed_eh_j = eh_j` despite changed input. This is a second preimage in `H`, requiring `~2^128` operations by (P2).

- **Cascade rewrite from `e_j` to `e_{n-1}`:** Requires valid `SignedRoot` values for each rewritten entry. The `SignedRoot` is a BLAKE3 keyed MAC (or DFC threshold signature) that the adversary cannot produce without the signing key. Obtaining the key requires `~2^256` operations (preimage on key derivation) or breaking the DFC threshold scheme.

In both cases, the adversary must solve a problem known to be computationally infeasible. **QED**

### 11.3 Quantitative Security Bounds

| Attack | Operations Required | Underlying Assumption |
|--------|--------------------|-----------------------|
| Forge composed root | `~2^128` | BLAKE3 collision resistance |
| Find preimage of any hash | `~2^256` | BLAKE3 preimage resistance |
| Forge MockDfc signature | `~2^256` | Both fragments unknown (Thm 10.1) |
| Forge production DFC signature | `~2^128+` | Akeyless DFC threshold security |
| Tamper with ledger entry | `min(2^128, DFC)` | Whichever is weaker (Thm 11.2) |
| Present internal node as leaf | `~2^128` | Domain separation (Thm 3.2) |
| Forge consistency proof | `~2^128` | BLAKE3 collision resistance |
| Modify any artifact in global fleet | `~2^128` | Hierarchical composition (Thm 6.2) |

**Context:** `2^128` operations is approximately `10^38` hash evaluations. At `10^12` hashes/second (a large GPU cluster), this would take `~10^{18}` years — roughly `10^8` times the age of the universe.

---

## 12. Complexity Analysis

### 12.1 Time Complexity

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| Hash `H(x)` | `O(len(x))` | Linear in input byte length |
| Domain-separated leaf | `O(33)` | 1-byte prefix + 32-byte hash = constant |
| Merkle tree (n leaves) | `O(n)` | `n' - 1` internal hash operations |
| Merkle root | `O(n)` | Same as tree construction |
| Inclusion proof generation | `O(log n)` | Extract sibling path |
| Inclusion proof verification | `O(log n)` | Reconstruct path, compare root |
| CertificationArtifact compose | `O(1)` | Fixed 3 leaves = 7 hash operations |
| CertificationArtifact verify | `O(1)` | Fixed-depth (2 levels) |
| N-layer master signature | `O(n log n)` | Sort: `O(n log n)`, tree: `O(n)` |
| Chain append | `O(1)` | One entry hash + pointer update |
| Chain integrity verification | `O(n)` | Walk and recompute all `n` entries |
| Consistency proof generation | `O(n - m)` | Extract extension hashes |
| Consistency proof verification | `O(n - m)` | Verify extension linkage |
| Cluster root computation | `O(m log m)` | Sort `m` artifacts + one hash |
| Global root computation | `O(k)` | Iterate `k` clusters (pre-sorted) |
| Blast radius (indexed) | `O(log n + r)` | BTreeMap lookup + `r` result entries |
| Blast radius (unindexed) | `O(n)` | Full ledger scan |

### 12.2 Space Complexity

| Structure | Size | Notes |
|-----------|------|-------|
| Single hash value | 32 bytes | BLAKE3 / SHA-256 output |
| LayerSignature | ~100 bytes | Type enum + hash + metadata |
| MasterSignature `(u, c, s)` | 96 bytes | 3 x 32-byte hashes |
| CertificationArtifact | ~288 bytes | 4 hashes + 3 proofs of 2 hashes each |
| Inclusion proof (3-leaf tree) | 64 bytes | 2 sibling hashes |
| Inclusion proof (n-leaf tree) | `32 * ceil(log2(n))` bytes | Logarithmic growth |
| Forensic ledger entry | ~500 bytes | All fields + deployment context |
| Forensic chain (n entries) | `~500n` bytes | Linear growth |
| Ledger index | `O(n)` | 5 BTreeMaps with entry references |
| Global state root | `~100k` bytes | `k` cluster entries |

### 12.3 Bandwidth Complexity

| Operation | Bandwidth | Context |
|-----------|-----------|---------|
| Cluster report to master | `32m` bytes | `m` artifact hashes |
| Cluster delta report | `32d` bytes | `d` changed artifacts |
| Consistency proof transfer | `32(n - m)` bytes | Extension segment |
| Inclusion proof transfer | `32 * ceil(log2(n))` bytes | Single leaf proof |
| Full ledger sync | `~500n` bytes | Entire history |

---

## 13. Ecosystem Integrations as Consequences

The preceding twelve sections establish a self-contained mathematical framework. This final section demonstrates that every component of the tameshi ecosystem — sekiban, inshou, kensa, the forensic ledger, global fleet monitoring, and distributed auditing — arises as a *logical consequence* of these mathematical properties. The engineering follows from the mathematics; the mathematics does not follow from the engineering.

This is the foundational design principle: **define the mathematical properties first, then build the system as a realization of those properties**. Any system that satisfies the same properties provides the same guarantees.

### 13.1 sekiban (K8s Admission Webhook)

**Consequence of:** Theorem 4.1 (Simultaneous Binding)

```
Theorem 4.1:  (a', c', i') != (a, c, i)  ==>  root' != root   [w.o.p.]
Contrapositive: root' = root  ==>  (a', c', i') = (a, c, i)    [w.o.p.]

sekiban stores:  expected_root in SignatureGate CRD
sekiban checks:  computed_root == expected_root

Therefore:       computed_root == expected_root
                 ==> (artifact, compliance, intent) are authentic
                 ==> ALLOW deployment

                 computed_root != expected_root
                 ==> at least one of (artifact, compliance, intent) was modified
                 ==> DENY deployment
```

The `ValidatingAdmissionWebhook` is invoked by Kubernetes itself — not by tameshi — providing an independent enforcement point. The mathematical guarantee that no modified triple can produce the expected root (Theorem 4.1) is what makes the gate sound.

### 13.2 inshou (Nix Rebuild Gate)

**Consequence of:** Theorems 3.1 (Tamper Evidence) and 5.1 (Order-Independent Composition)

```
Theorem 3.1:  modified leaf  ==>  different root   [w.o.p.]
Theorem 5.1:  same layer set ==>  same root        [deterministic]

Nix closure = content-addressed set of store paths
Layer hash  = compose_merkle(hash(path_0), hash(path_1), ..., hash(path_m))

Modified package ==> different path hash ==> different layer hash ==> different root
Same packages    ==> same path hashes    ==> same layer hash     ==> same root

inshou checks root against sekiban's expected value before rebuild.
```

Theorem 5.1 is essential here: Nix dependency resolution may traverse the closure in different orders across machines, but the sorted composition always produces the same root.

### 13.3 kensa (Compliance Engine)

**Consequence of:** Theorem 9.1 (Two-Phase Binding) and Corollary 9.1.1

```
Theorem 9.1:     s = H(u || c) binds infrastructure AND compliance
Corollary 9.1.1: cannot find c' != c with H(u || c') = s

Therefore:
  - Publishing s commits to both the infrastructure state u AND compliance result c
  - Neither can be changed after publication without changing s
  - Compliance results are immutably bound to the specific infrastructure state
    they assessed — they cannot be swapped, backdated, or forged
```

### 13.4 Forensic Ledger

**Consequence of:** Theorem 7.1 (Chain Integrity) and Corollaries 7.1.1, 7.1.2

The three forensic queries — blast radius, timeline, and provenance — are made trustworthy by the chain integrity guarantee:

| Query | What it answers | Why integrity matters |
|-------|----------------|---------------------|
| **Blast radius** | Which nodes ran a compromised artifact? | Without integrity, an adversary could delete entries showing affected nodes |
| **Timeline** | When did events occur for an artifact? | Without integrity, an adversary could reorder entries to hide the attack sequence |
| **Provenance** | What was running on a node at time T? | Without integrity, an adversary could insert fake entries showing clean state |

```
Theorem 7.1:    modification detected   ==>  ledger is trustworthy
Corollary 7.1.1: deletion detected      ==>  no entries hidden
Corollary 7.1.2: reordering detected    ==>  temporal ordering preserved

Therefore: forensic queries return accurate, complete, ordered results
```

### 13.5 Global Fleet Monitoring

**Consequence of:** Theorems 6.1 (Deterministic Aggregation) and 6.2 (Hierarchical Tamper Evidence)

```
Theorem 6.2:  modified artifact ANYWHERE in the fleet
              ==>  global_root changes

Therefore:    monitoring ONE 256-bit value detects modifications ANYWHERE

Bandwidth savings:
  Without hierarchy: verify every artifact individually = O(total_artifacts * 32) bytes
  With hierarchy:    verify one global root             = 32 bytes
                     + k cluster roots on change        = O(k * 32) bytes
```

### 13.6 Distributed Auditing

**Consequence of:** Theorem 8.1 (Consistency Soundness) and Corollary 8.1.1

```
Theorem 8.1:  valid consistency proof  ==>  prefix unchanged [w.o.p.]

Therefore:    an auditor who verified up to sequence m
              needs only O(n - m) work to verify extension to sequence n
              (not O(n) work to re-verify everything)

This is the same mechanism as Certificate Transparency (RFC 9162),
applied to infrastructure attestation instead of TLS certificates.
```

### 13.7 Dependency Graph: Mathematics to Engineering

```
    BLAKE3: (P1) Preimage, (P2) Second-Preimage, (P3) Collision, (P4) Determinism
        |
        +--- (Thm 2.1) Combine Non-Commutativity
        |        |
        |        +--- (Def 5.3) Canonical Ordering
        |                 |
        |                 +--- (Thm 5.1) Order-Independent Composition
        |                          |
        |                          +---> Master Signature ---> Gate evaluation
        |
        +--- (Thm 2.2) Domain Separation
        |        |
        |        +--- (Def 3.1) Merkle Trees
        |        |        |
        |        |        +--- (Thm 3.1) Tamper Evidence ---------> inshou, sekiban
        |        |        |
        |        |        +--- (Thm 3.3) Inclusion Proofs --------> Selective disclosure
        |        |        |
        |        |        +--- (Thm 4.1) CertificationArtifact --> sekiban CRD
        |        |                 |
        |        |                 +--- (Cor 4.1.1) Non-Forgery
        |        |                 |
        |        |                 +--- (Cor 4.1.2) Selective Disclosure
        |        |
        |        +--- (Thm 3.2) No Leaf/Internal Confusion
        |
        +--- (Thm 7.1) Hash Chain Integrity ---------> Forensic ledger
        |        |
        |        +--- (Cor 7.1.1) Append-Only --------> No hidden deletions
        |        |
        |        +--- (Cor 7.1.2) Order Preserved -----> Temporal integrity
        |        |
        |        +--- (Thm 8.1) Consistency Proofs ----> Distributed auditing
        |
        +--- (Thm 9.1) Two-Phase Binding -------------> kensa integration
        |        |
        |        +--- (Cor 9.1.1) No Retrofit ---------> Compliance immutability
        |
        +--- (Thm 6.1) Deterministic Aggregation -----> Global fleet root
        |        |
        |        +--- (Thm 6.2) Hierarchical Tamper --> Single-hash fleet check
        |
        +--- (Thm 10.1) Split-Knowledge Security -----> DFC threshold signing
        |
        +--- (Thm 11.1) Security Reduction -----------> Everything reduces to BLAKE3
```

**Reading this graph:** Every arrow from a theorem to an engineering component means: "this component's security guarantee is a mathematical consequence of this theorem." The graph is a DAG rooted at BLAKE3's four properties. Replacing BLAKE3 with any hash function satisfying (P1)-(P4) preserves all guarantees.

---

## Appendix A: Notation Summary

| Symbol | Meaning | First Defined |
|--------|---------|---------------|
| `H` | BLAKE3 hash function (or any function satisfying P1-P4) | Def 1.3 |
| `B_256` | 256-bit hash output space `{0,1}^256` | Sec 1.1 |
| `k` | Security parameter (128 for collisions, 256 for preimages) | Def 1.1 |
| `negl(k)` | Negligible function in `k` | Sec 1.1 |
| `a \|\| b` | Byte string concatenation | Sec 1.1 |
| `H_d(x)` | Domain-separated hash: `H(d \|\| x)` | Def 2.2 |
| `MT(L)` | Domain-separated Merkle tree over leaf sequence `L` | Def 3.1 |
| `root(MT(L))` | Root hash of Merkle tree | Def 3.1 |
| `pi_i` | Inclusion proof for leaf `i` | Def 3.2 |
| `CA` | CertificationArtifact `(a, c, i, r, Pi)` | Def 4.1 |
| `LS` | LayerSignature `(t, h, M)` | Def 5.2 |
| `MS` | MasterSignature `(u, c, s)` | Def 9.1 |
| `GSR` | GlobalStateRoot | Def 6.2 |
| `C` | Forensic hash chain | Def 7.1 |
| `e_i` | Chain entry at index `i` | Def 7.1 |
| `eh_i` | Entry hash for entry `i` | Sec 7.2 |
| `ph_i` | Previous hash for entry `i` | Sec 7.3 |
| `F_a, F_b` | Split-knowledge fragments | Def 10.1 |

## Appendix B: Definition Index

| Definition | Name | Section |
|-----------|------|---------|
| 1.1 | Security Parameter | 1.2 |
| 1.2 | Cryptographic Hash Function | 1.3 |
| 1.3 | BLAKE3 Instantiation | 1.4 |
| 2.1 | Hash Combination Function | 2.1 |
| 2.2 | Domain-Separated Hash | 2.2 |
| 3.1 | Domain-Separated Binary Merkle Tree | 3.1 |
| 3.2 | Merkle Inclusion Proof | 3.4 |
| 3.3 | Verification Algorithm | 3.4 |
| 4.1 | Certification Artifact | 4.1 |
| 5.1 | Infrastructure Layer | 5.1 |
| 5.2 | Layer Signature | 5.1 |
| 5.3 | Canonical Layer Ordering | 5.2 |
| 5.4 | Master Signature Composition | 5.2 |
| 6.1 | Cluster Root | 6.1 |
| 6.2 | Global Root | 6.1 |
| 6.3 | Temporal Chain | 6.4 |
| 7.1 | Forensic Hash Chain | 7.1 |
| 8.1 | Consistency Proof | 8.1 |
| 9.1 | Two-Phase Master Signature | 9.1 |
| 10.1 | XOR Split-Knowledge Signer | 10.1 |
| 10.2 | Distributed Fragment Cryptography | 10.3 |

## Appendix C: Theorem Index

| Theorem | Statement | Section |
|---------|-----------|---------|
| 2.1 | Combine non-commutativity: `H(a\|\|b) != H(b\|\|a)` for `a != b` | 2.1 |
| 2.2 | Domain separation prevents cross-domain collisions | 2.2 |
| 3.1 | Merkle tree tamper evidence: changed leaf changes root | 3.3 |
| 3.2 | Second-preimage resistance: leaf and internal nodes cannot be confused | 3.3 |
| 3.3 | Inclusion proof soundness: valid proof implies authentic leaf | 3.4 |
| 4.1 | CertificationArtifact: simultaneous binding of `(a, c, i)` | 4.3 |
| 5.1 | Order-independent composition: same layers, any order, same root | 5.3 |
| 6.1 | Deterministic global aggregation: independent of reporting order/time | 6.3 |
| 6.2 | Hierarchical tamper evidence: any artifact change changes global root | 6.3 |
| 7.1 | Forensic chain integrity: any modification detectable (with tail caveat) | 7.5 |
| 8.1 | Consistency proof soundness: verified extension implies unchanged prefix | 8.3 |
| 9.1 | Two-phase binding: secure hash commits to infrastructure AND compliance | 9.3 |
| 10.1 | Split-knowledge: one fragment reveals zero information about key | 10.2 |
| 11.1 | Security reduction: attestation forgery implies BLAKE3 collision | 11.1 |
| 11.2 | Ledger forgery: undetected modification implies BLAKE3 break or DFC forgery | 11.2 |

## Appendix D: Corollary Index

| Corollary | Statement | Derived From |
|-----------|-----------|--------------|
| 3.3.1 | Inclusion proof size is `O(log n)` | Thm 3.3 |
| 4.1.1 | Cannot forge composed root without all three inputs | Thm 4.1 |
| 4.1.2 | Selective disclosure: prove one leaf without revealing others | Thm 4.1 |
| 7.1.1 | Append-only: deletion of interior entries is detectable | Thm 7.1 |
| 7.1.2 | Reordering: swapped entries break chain linkage | Thm 7.1 |
| 8.1.1 | Incremental auditing: `O(n - m)` work, not `O(n)` | Thm 8.1 |
| 9.1.1 | Compliance cannot be retrofitted after publication | Thm 9.1 |

## Appendix E: Test Evidence Mapping

Every theorem in this document is verified by automated tests in the tameshi ecosystem. This table maps mathematical claims to their concrete test implementations.

| Claim | Tests | Module | Key Tests |
|-------|------:|--------|-----------|
| Thm 2.1 (non-commutativity) | 4+ | `hash.rs` | `blake3_combine_not_commutative`, proptest `hash_combine_non_commutative` (256 cases) |
| Thm 2.2 (domain separation) | 4 | `merkle.rs` | `domain_separated_leaf_prefix_byte`, `domain_separation_leaf_vs_internal_prefix` |
| Thm 3.1 (tamper evidence) | 256+ | `merkle.rs` | proptest `merkle_tamper_detection` (256 random layer sets, random tamper position) |
| Thm 3.2 (second-preimage) | 2 | `merkle.rs` | `domain_separation_prevents_second_preimage`, `domain_separation_root_differs_from_undifferentiated` |
| Thm 3.3 (proof soundness) | 256+ | `merkle.rs` | proptest `merkle_proof_validity` (256 random trees, every leaf verified) |
| Thm 4.1 (binding) | 287+ | `certification_artifact.rs` | 31 unit + 256 proptest (`certification_artifact_collision_resistance`, `tamper_detection`) |
| Thm 5.1 (order-independence) | 3 | `merkle.rs` | `merkle_root_order_independent`, `compose_merkle_creates_master` |
| Thm 6.1 (global determinism) | 8 | `global.rs` | `compute_global_root_deterministic`, `cluster_roots_deterministic` |
| Thm 6.2 (hierarchical tamper) | 4 | `global.rs` | `modified_artifact_changes_global_root` |
| Thm 7.1 (chain integrity) | 13 | `forensics/ledger.rs` | `chain_detect_tampered_entry`, `chain_1000_entries_integrity` |
| Thm 8.1 (consistency) | 8 | `heartbeat.rs` | `consistency_proof_valid`, `consistency_proof_detects_tamper` |
| Thm 9.1 (two-phase binding) | 4 | `signature.rs` | `master_signature_composition` |
| Thm 10.1 (split-knowledge) | 4 | `signing.rs` | `mock_dfc_wrong_fragment_a_verify_fails`, `mock_dfc_wrong_fragment_b_verify_fails` |
| Thm 11.1 (reduction) | structural | — | Proved by construction; all tamper detection tests (Thms 3.1, 4.1, 6.2, 7.1) serve as witnesses that the reduction holds |
| Thm 11.2 (ledger reduction) | structural | — | Combination of chain integrity tests (Thm 7.1) + signing tests (Thm 10.1) |
