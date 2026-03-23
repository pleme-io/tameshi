# Tameshi: What It Is and Why It Matters

*A plain-language guide for anyone evaluating this technology.*

---

## The One-Sentence Version

Tameshi is a system that **mathematically proves** every binary running on
your infrastructure is exactly what was built, tested, and approved — and
enforces that proof inside the Linux kernel where nothing can bypass it.

---

## The Problem We Solve

Today, every secrets management platform — including the largest ones —
has the same blind spot: **no one can prove that the code running in
production right now is the same code that passed all the tests.**

An attacker who compromises a build pipeline, a container registry, or
a deployment script can substitute a modified binary. Existing tools
(image signing, admission webhooks, CVE scanners) check the binary
*before* it reaches the machine. Once it's on disk and the operating
system runs it, those checks are gone. The kernel doesn't know about
your Cosign signatures. It just executes bytes.

This is the gap. Tameshi closes it.

> **Want to understand the gap in detail?**
> See `docs/grand-unified-specification.md`, Level 1: "The Semantic Gap."

---

## How It Works (The 30-Second Version)

Three things happen, in order:

```
1. ANALYZE     2. ATTEST      3. ENFORCE
   (Ferrite)      (Tameshi)      (Kanshi)
   Go source      Compose a      Kernel checks
   is proved      Merkle root    the hash at
   memory-safe    from 3 inputs  every execve()
```

**Step 1** happens at build time. Ferrite analyzes the Go source code and
produces a receipt called a **Proof of Memory Safety** (PoMS). If the code
has memory bugs, the receipt is not issued and the pipeline stops.

**Step 2** happens at deployment time. Tameshi takes three hashes — the
binary itself, the compliance assessment, and the PoMS — and compresses
them into a single 32-byte fingerprint. That fingerprint is signed and
placed into a kernel map.

**Step 3** happens at runtime. Every time a process tries to execute a
binary (`execve`), the kernel checks: is this binary's fingerprint in the
map? If not, execution is denied. No agent to kill, no config to change.

> **Want to see the full pipeline diagram?**
> See `docs/grand-unified-specification.md`, Level 3: "The Integration Bridge."

---

## What We Know Is True

This is not a prototype. It is not a proof of concept. Every claim below
is backed by passing tests that you can run yourself.

### The code works

| What | Tests | Status |
|------|------:|--------|
| Core Rust library (tameshi) | 1,446 | All passing |
| Go analyzer + runtime (Ferrite) | 372 | All passing |
| Property-based security checks | 39 x 10,000 each | All passing |
| Cross-repo integration tests | 95 | All passing |

*Run it:* `cargo test` in tameshi, `go test ./...` in ferrite.

### The math holds

Every security property in the system is covered by at least one of three
independent verification layers:

| Layer | What It Does | Confidence |
|-------|-------------|------------|
| **Proptest** (390,000 random inputs) | Throws hostile random data at every function. If a single input breaks an invariant, the test fails. | High — any implementation bug that violates a theorem is caught |
| **Kani** (44 exhaustive proofs) | Explores *every possible* execution path. Not random sampling — complete enumeration. | Very high — proves the *absence* of bugs, not just their non-detection |
| **F*** (10 formal proof modules) | Mathematical proofs that hold for ALL inputs of ANY size. The gold standard in computer science. | Absolute — conditional only on BLAKE3 being a good hash function |

*Run it:* `nix run .#verify-all` in tameshi.

> **Skeptical about the verification layers?**
> Each layer is explained in `docs/verification-strategy.md` with exact
> theorem-to-test mappings. Every one of the 15 mathematical theorems
> and 7 corollaries is mapped to a passing test.

### The performance is real

We benchmarked the Ferrite arena allocator against standard Go maps on
an Apple M4 Pro:

| Operation | Standard Go | Ferrite Arena | Improvement |
|-----------|------------|---------------|-------------|
| Cache write (put + read) | 48.5 ns | 37.4 ns | **30% faster** |
| Cache read (steady state) | 48.5 ns | 7.0 ns | **7x faster** |
| Heap allocations per op | 1 | 0 | **Zero GC pressure** |
| GC cycles during 100k reads | varies | 0 | **Eliminated** |

The "zero allocations" claim isn't an estimate. It's a measured fact:
`TestProof_ZeroGC_HotPath` runs 100,000 cache reads and verifies that
exactly 0 heap allocations occurred and 0 GC cycles ran.

*Run it:* `go test -bench=BenchmarkCache -benchmem ./check/` in ferrite.

> **Want to understand why the arena is faster?**
> See `docs/grand-unified-specification.md`, Level 6: "Performance Attestation."

---

## What Each Layer Does

### Ferrite: The Compiler Safety Net

Ferrite is a static analyzer for Go. It reads Go source code (not binaries)
and checks for memory safety violations:

| Violation | What It Catches | How We Know It Works |
|-----------|----------------|---------------------|
| Memory leak | A value is allocated but never freed | 8 testdata packages + 25 E2E corpus entries |
| Double-free | A value is freed twice | testdata a,b,e,f + E2E corpus c03 |
| Use-after-free | A value is used after it was freed | testdata a,b,e,f + E2E corpus c05 |
| Dangling pointer | A borrowed reference outlives its owner | testdata a,b,e + E2E corpus c04 |
| Channel-send move | A value is used after being sent through a channel | `ssa_spec/spec.go` test corpus |
| Goroutine escape | A value is captured in a goroutine and used in the parent | `ssa_goroutine` testdata |

If Ferrite finds zero violations, it produces a **PoMS** — a JSON file
containing cryptographic hashes of the source, AST, and compiled output.
This receipt is the input to tameshi.

> **Want to see Ferrite's analysis rules?**
> See `ferrite/CLAUDE.md` for the full rule table with diagnostics and test coverage.

### Tameshi: The Cryptographic Binding

Tameshi takes three pieces of evidence and compresses them into one hash:

```
Leaf 0: "What was built"         (Nix closure hash or container digest)
Leaf 1: "What compliance says"   (NIST 800-53 / CIS assessment result)
Leaf 2: "What the code proves"   (Ferrite PoMS or infrastructure intent)
                    |
                    v
            composed_root (32 bytes)
```

This is a Merkle tree — the same data structure used in Bitcoin, Git, and
Certificate Transparency. The key property: **changing any single input
changes the output.** If one line of Go code changes, or one Nix dependency
updates, or one compliance control fails, the composed root changes and
the old attestation is invalid.

This property is not just tested. It is **mathematically proved** in
`fstar/Tameshi.Merkle.fst` by structural induction — the proof holds
for all inputs of any size, unconditionally.

> **Want to understand the Merkle tree structure?**
> See `docs/grand-unified-specification.md`, Level 2: "The Data Hierarchy."

### Kanshi: The Kernel Enforcer

Kanshi is an eBPF program that runs inside the Linux kernel. It hooks
the `bprm_check_security` function — the last checkpoint before the
kernel executes any binary.

When a process calls `exec`:
1. The kernel computes the binary's hash
2. Kanshi looks up the hash in the attestation map
3. If the hash is not found or has violations: **denied** (`-EPERM`)
4. If the hash is found with zero violations: **allowed**

There is no daemon to kill. There is no agent to disable. The enforcement
lives at the same privilege level as the filesystem and the scheduler.
A compromised application cannot see, detect, or disable the hook.

> **Want to see the hook source code?**
> See `bpf/kanshi_enforcer.bpf.c` — 191 lines of annotated C.

---

## Where You Might Have Doubts (And What We Can Show You)

### "How do you know the Rust struct matches the C struct?"

The `PomsEntry` struct is shared between Rust (userspace) and C (kernel).
If they disagree on field layout by even one byte, the kernel reads garbage.

We don't rely on manual inspection. Kani's `ffi_safety_proofs` module
creates a `PomsEntry` with **every possible combination of field values**
and proves that Rust and C read identical bytes at identical offsets.
This is not sampling — it is exhaustive.

7 harnesses. 0 failures. Every possible struct layout verified.

*See:* `proofs/kani/src/ffi_safety_proofs.rs`

### "How do you know the eBPF hook won't crash the kernel?"

Kani's `liveness_proofs` module proves that every tameshi algorithm
terminates. The `mutex_chain_no_starvation` harness proves no deadlock
under thread contention. The `bpf_attestation_cycle_terminates` harness
proves the hot path (compose artifact, compute root) is straight-line
code with no loops.

7 liveness harnesses. 0 failures. No infinite loops, no deadlocks.

*See:* `proofs/kani/src/liveness_proofs.rs`

### "How do you know rejected inputs can't corrupt the state?"

F*'s `Tameshi.NonInterference` module proves a precise mathematical
statement: `transition(state, Unsafe) == state`. In English: **processing
a rejected input returns the state completely unchanged.** Not "mostly
unchanged." Identically unchanged. This is proved definitionally — the
F* type checker confirms it without any assumptions.

*See:* `fstar/Tameshi.NonInterference.fst`

### "How do you know the whole pipeline is consistent?"

F*'s `Tameshi.Refinement` module proves the end-to-end contract:

- If Ferrite says "safe" → the kernel authorizes execution (always)
- If the kernel authorizes → Ferrite verified it (no exceptions)
- If Ferrite says "unsafe" → the kernel denies (unconditionally)

All three theorems are proved without `admit()` — meaning no unverified
assumptions. The F* type checker confirmed them computationally.

*See:* `fstar/Tameshi.Refinement.fst`

### "How do you know the signing keys are safe from timing attacks?"

Kani's `crypto_timing_proofs` module proves that the DFC key
reconstruction path (XOR fragments, hash, sign) contains no
data-dependent branches. The hash comparison function processes
all bytes unconditionally — no early exit that could leak information
through timing measurement.

4 harnesses. 0 failures. No timing side channels.

*See:* `proofs/kani/src/crypto_timing_proofs.rs`

### "What if BLAKE3 itself is broken?"

Every proof in the system reduces to one assumption: BLAKE3 is a
good hash function (collision-resistant). If someone finds a way to
produce two different inputs with the same BLAKE3 output, our proofs
break — but so does TLS, SSH, WireGuard, and every cryptocurrency
on Earth. The security of tameshi is exactly as strong as the security
of the internet.

*See:* `docs/grand-unified-specification.md`, Section 5.4: "The Trust Foundation."

---

## Regulatory Alignment

| Framework | What Tameshi Provides |
|-----------|----------------------|
| **CIRCIA 2026** | Tamper-evident audit chain with 72-hour retention. Every binary verification is logged. |
| **FedRAMP High** | SA-11: 3-layer formal verification. SI-7: Merkle attestation of every binary. |
| **SLSA Level 3** | Build provenance via Nix hashing. Source analysis via Ferrite PoMS. |
| **SOC 2 Type II** | Continuous compliance monitoring via HeartbeatChain. |
| **NIST 800-53 Rev 5** | 14 controls mapped: SR-4, SI-7, CM-2/3/6/8, AC-3/6, AU-2/3/6/9/10, SC-12. |

> **Want the full compliance mapping?**
> See `docs/compliance-coverage-comparison.md` (~14,800 controls benchmarked).

---

## The Numbers

| Metric | Value |
|--------|-------|
| Rust tests (tameshi) | 1,446 passing |
| Go tests (Ferrite) | 372 passing |
| Proptest properties | 39 x 10,000 = 390,000 random checks |
| Kani proof harnesses | 44 (exhaustive, not sampled) |
| F* formal proof modules | 10 (unbounded mathematical proofs) |
| Mathematical theorems proved | 15 theorems + 7 corollaries |
| Ecosystem repositories | 9 |
| Infrastructure layer types | 15 |
| Compliance frameworks | CIRCIA, FedRAMP, SLSA, SOC2, NIST |
| Zero failures | across all verification layers |

---

## Where To Go Next

| If you want to... | Read this |
|-------------------|-----------|
| Understand the business case and architecture | `docs/grand-unified-specification.md` |
| See the mathematical theorems and proofs | `docs/mathematical-foundations.md` |
| Understand the verification strategy | `docs/verification-strategy.md` |
| Present to a board or audit committee | `docs/FORMAL_VERIFICATION_SUMMARY.md` |
| Start developing against the API | `docs/quick-start-guide.md` |
| Read the system architecture (code-level) | `docs/tameshi-technical-specification.md` |
| See the compliance comparison | `docs/compliance-coverage-comparison.md` |
| Run the proofs yourself | `nix run .#verify-all` |

---

## Run It Yourself

```bash
git clone https://github.com/pleme-io/tameshi && cd tameshi

cargo test                     # 1,446 Rust tests
nix run .#verify-proptest      # 390,000 random hostile inputs
nix run .#verify-kani          # 44 exhaustive proof harnesses
nix run .#verify-fstar         # 10 mathematical proof modules
nix run .#verify-all           # Everything, in sequence
```

Every claim in this document corresponds to a passing test. Nothing is
taken on faith. The proofs are open source, the tests are deterministic,
and the results are reproducible on any machine with Rust and Nix installed.

---

*Tameshi (試し) — "test" or "proof." The act of putting something
to the trial to determine its true nature.*
