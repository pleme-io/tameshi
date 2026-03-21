# Threat Model and Compliance

## 1. Threat Model Summary

tameshi defends against supply chain injection, post-deployment binary tampering, compliance forgery, and audit trail manipulation. It does not attempt to prove code correctness (Rice's Theorem makes this undecidable). Instead, it mathematically guarantees that the exact code tested and audited is the exact code that executes in production -- and provides tamper-evident evidence that this property held continuously over time.

The security model rests on four pillars:

1. **CertificationArtifact** -- cryptographic binding of provenance, compliance, and intent
2. **Threshold signing** -- non-repudiation via Akeyless DFC (key never assembled)
3. **eBPF LSM enforcement** -- kernel-level binary verification at `execve()`
4. **HeartbeatChain** -- tamper-evident audit trail for regulatory evidence

---

## 2. Attack Surface Analysis

| # | Attack Vector | Defense | Gating Point | Test Evidence |
|:-:|--------------|---------|:------------:|:-------------:|
| 1 | **Supply chain injection** -- modified dependency in build | Nix closure hash changes if any dependency changes; CertificationArtifact root invalidated | inshou | 457 tests |
| 2 | **Binary tampering** -- modified binary on disk post-deploy | BLAKE3 content hash does not match BPF allow map; kernel returns EPERM | kanshi LSM | 135 tests |
| 3 | **Compliance forgery** -- fabricated compliance report | Compliance hash is BLAKE3 of actual kensa assessment; changing it invalidates the CertificationArtifact composed_root | kensa | 546 tests |
| 4 | **Secret exposure** -- Akeyless secrets leaked via attestation | `LiveAkeylessCollector` hashes secret VALUES with gateway+path salt but never stores them; only salted hashes appear in signatures | tameshi collector | 6 tests |
| 5 | **Infrastructure drift** -- config changed without re-attestation | HeartbeatChain provides continuous verification record; gaps detectable by missing sequence numbers | heartbeat | 51+ tests |
| 6 | **Admission bypass** -- deploy without webhook | `ValidatingAdmissionWebhook` with `failurePolicy: Fail`; K8s API server itself enforces the call | sekiban | 417 tests |
| 7 | **Break-glass abuse** -- emergency bypass used maliciously | Every break-glass event is cryptographically signed, scoped, time-bounded, and recorded as `HeartbeatEvent::BreakGlass` | signing + heartbeat | 11 tests |
| 8 | **Signature replay** -- reuse old valid signature for new binary | `GatingPolicy.max_signature_age_secs` rejects stale signatures (default: 1 hour); `FixedClock` injection enables deterministic age testing | gating engine | 4 tests |
| 9 | **Merkle tree manipulation** -- present internal node as leaf | RFC 9162 domain separation: `0x00` leaf prefix, `0x01` internal node prefix; `Blake3Algorithm.concat_and_hash()` enforces at type level | merkle construction | 5 tests |
| 10 | **DFC key theft** -- steal signing key | Production: key never assembled (Akeyless DFC, fragments distributed). Mock: split-knowledge requires both fragments (XOR = one-time pad) | signing architecture | 70 tests |
| 11 | **Audit trail tampering** -- delete/modify heartbeat entries | BLAKE3 hash chain: modifying any field in any entry changes its `entry_hash`, breaking linkage at the next entry; `ConsistencyProof` enables remote verification | heartbeat chain | 12 tests |
| 12 | **Namespace escape** -- execute in wrong namespace to avoid policy | Per-namespace `EnforcementPolicy` in BPF `tameshi_policy_map`; cgroup ID identifies container namespace at kernel level | kanshi policy | 8 tests |
| 13 | **dlopen/JIT injection** -- load malicious shared library | `mmap_file` LSM hook verifies hash at `mmap()` time, not just `execve()` | kanshi eBPF | BPF design |
| 14 | **Binary revocation race** -- execute revoked binary before map update | `tameshi_revocation_list` checked before `tameshi_allow_map`; revocation takes priority in both `verify()` and `verify_by_hash()` | kanshi verifier | 10 tests |

---

## 3. Red Team Audit Results

Five vulnerabilities were identified through adversarial review of the architecture and implementation. All five have been fixed with corresponding regression tests.

### Vulnerability 1: Nix Path Fallback (CRITICAL)

**Description:** Early inshou design allowed a fallback to a less-trusted hash source when the primary Nix store path was inaccessible. An attacker with filesystem access could make the primary path unavailable (e.g., unmount, permission change), forcing fallback to a weaker verification path.

**Exploitation:** Mount namespace manipulation or `chmod` on the Nix store path, forcing inshou to fall back to an unverified secondary source.

**Fix:** Fail-secure design with zero fallback paths. If the primary hash source is unavailable, inshou aborts the rebuild with a hard error. The `App<N,C,P,K,F>` architecture makes every dependency injectable, so there is no hidden fallback logic that could be exploited.

**Regression test:** inshou test suite verifies that unavailable hash sources produce `Err`, not a degraded `Ok`. 457 tests cover all error paths with no fallback behavior.

---

### Vulnerability 2: Inode Reuse (HIGH)

**Description:** `HashVerifier.verify()` uses inode-based lookup for performance. When a file is deleted and a new file is created, the filesystem may assign the same inode number. The verifier would look up the old expected hash for the inode, which does not match the new binary's content, yielding `Mismatch`. However, the initial design did not have a content-hash-only verification path.

**Exploitation:** Delete an attested binary, create a malicious binary at the same path. If the filesystem reuses the inode and the system uses only inode-based lookup, a timing window exists during inode map updates.

**Fix:** `verify_by_hash()` added to `HashVerifier` -- checks the content hash directly against the `allow_set`, bypassing inode lookup entirely. This is the secure path, immune to inode reuse attacks:

```rust
pub fn verify_by_hash(&self, hash: &BpfHash) -> VerifyResult {
    if self.revocation_map.contains(hash) { return VerifyResult::Revoked; }
    if self.allow_set.contains(hash) { return VerifyResult::Allowed; }
    VerifyResult::Unknown
}
```

**Regression tests:**
- `inode_reuse_with_different_hash_detected` -- same inode, different content hash yields `Mismatch`
- `verify_by_hash_allowed` -- content hash in allow set passes regardless of inode
- `verify_by_hash_revoked` -- revoked hash blocked regardless of allow set membership
- `verify_by_hash_revocation_takes_priority` -- hash in both allow and revocation sets is blocked

---

### Vulnerability 3: Helm Values Drift (MEDIUM)

**Description:** The deployed Helm release could drift from the attested chart if Helm values were modified after the chart was rendered and hashed. The rendered chart hash captured the template output at attestation time, but post-attestation value overrides were not detected.

**Exploitation:** `helm upgrade --set` with modified values after the initial attestation, changing runtime behavior without invalidating the signature.

**Fix:** `hash_deployed_manifest()` hashes the actual deployed manifest (via `kubectl get -o json`), not just the rendered template. The `KubernetesCollector` captures the live state. Additionally, sekiban's `changeset` module hashes the diff between old and new objects on UPDATE operations, detecting any mutation.

**Regression test:** `RenderedHelmCollector` tests verify that different `--set` values produce different hashes. `KubernetesCollector` tests verify live manifest hashing. sekiban changeset tests verify mutation detection.

---

### Vulnerability 4: TOCTOU (Time-of-Check-Time-of-Use) (MEDIUM)

**Description:** Time window between sekiban admission verification and actual binary execution. A container image verified at admission could theoretically be replaced before the kubelet pulls it.

**Exploitation:** Compromise the container registry between admission and pull. Replace the image tag with a malicious image.

**Fix:** Three-layer TOCTOU mitigation documented in `sekiban/src/webhook/admission.rs`:

1. **OCI digest enforcement** -- `validate_image_digests()` rejects mutable tags (`nginx:latest`), requiring immutable digest references (`@sha256:abc123`). Images referenced by digest cannot be replaced.
2. **K8s spec immutability** -- Container images cannot be changed after Pod creation. Kubernetes enforces this at the API level.
3. **kanshi LSM hooks** -- Even if a binary is somehow modified on the filesystem after admission, `bprm_check_security` verifies the BLAKE3 content hash at `execve()` time.

**Regression tests:**
- `validate_image_digests_rejects_tag` -- mutable tags produce violations
- `validate_image_digests_accepts_sha256` -- digest references pass
- `validate_image_digests_checks_init_containers` -- init containers checked
- `validate_image_digests_ephemeral_containers` -- ephemeral containers checked
- TOCTOU-specific integration test verifying all three layers work together

---

### Vulnerability 5: eBPF LSM Gap (HIGH)

**Description:** If the Linux kernel does not have `CONFIG_BPF_LSM=y`, kanshi's LSM hooks cannot attach. The daemon would start successfully but provide zero enforcement, creating a false sense of security.

**Exploitation:** Deploy kanshi on a node with a kernel that lacks BPF LSM support. kanshi appears healthy (healthz passes) but cannot intercept `execve()`.

**Fix:** `enforce_or_fail()` in `kanshi/src/bpf_loader.rs` -- if BPF LSM is not available and the policy is `Enforce`, kanshi returns a hard error and refuses to run:

```rust
pub fn enforce_or_fail(lsm_available: bool, policy: EnforcementPolicy) -> Result<(), Error> {
    if policy == EnforcementPolicy::Enforce && !lsm_available {
        Err(Error::Bpf(
            "SECURITY: Enforce mode requires BPF LSM but it is not available. \
             Refusing to run in degraded mode. Either enable CONFIG_BPF_LSM=y \
             in the kernel or switch to Audit mode."
        ))
    } else { Ok(()) }
}
```

`check_lsm_support()` reads `/sys/kernel/security/lsm` to detect BPF LSM availability. On non-Linux platforms, returns `Ok(false)`.

**Regression tests:**
- `enforce_or_fail_denies_without_lsm` -- Enforce + no LSM = hard error containing "SECURITY"
- `enforce_or_fail_allows_audit_without_lsm` -- Audit mode acceptable without LSM
- `enforce_or_fail_allows_with_lsm` -- Enforce + LSM available = OK
- `check_lsm_support_returns_false_on_macos` -- non-Linux platforms correctly report no LSM

---

## 4. NIST SP 800-53 Rev. 5 Control Mapping

| Control ID | Control Name | tameshi Implementation | Component |
|:----------:|-------------|----------------------|:---------:|
| **SR-4** | Provenance | `CertificationArtifact` binds artifact to build origin via `artifact_hash` (Leaf 0). `NixCollector` captures Nix closure. `OciCollector` captures OCI manifest digest. | tameshi |
| **SR-11** | Component Authenticity | `CertificationArtifact.composed_root` = Merkle commitment to provenance + compliance + intent. Signed by `MerkleRootSigner` (DFC threshold). | tameshi |
| **SI-7** | Software, Firmware, and Information Integrity | kanshi eBPF `bprm_check_security` hook verifies BLAKE3 content hash at `execve()` time. `verify_by_hash()` immune to inode reuse. | kanshi |
| **SI-3** | Malicious Code Protection | BPF `tameshi_revocation_list` blocks known-bad hashes. Revocation checked before allow map. tameshi-watch ingests CVE feeds for automatic revocation. | kanshi + tameshi-watch |
| **CM-2** | Baseline Configuration | Nix closure hash captures exact package set. `NixCollector` hashes the full closure via `nix-store --query --requisites`. | tameshi |
| **CM-3** | Configuration Change Control | inshou gates all NixOS/nix-darwin system changes. HeartbeatChain logs every gate decision with verifier identity and timestamp. | inshou + heartbeat |
| **CM-6** | Configuration Settings | `RenderedHelmCollector` hashes rendered Helm chart YAML. `KubernetesCollector` hashes live manifests. Drift between them is detectable. | tameshi |
| **CM-8** | System Component Inventory | Nix closure captures exact package set with versions and hashes. `SdlcChain` tracks 8 pipeline phases. | tameshi |
| **AC-3** | Access Enforcement | BPF `EnforcementPolicy` per namespace. `Enforce` mode: only attested binaries execute. `Audit` mode: log violations. `AllowUnknown`: permit unknown binaries. | kanshi |
| **AC-6** | Least Privilege | In `Enforce` mode, only binaries with hashes in the BPF allow map can execute. All other binaries receive `EPERM`. | kanshi |
| **AU-2** | Event Logging | `HeartbeatChain` records all verification events across all components (sekiban, kensa, inshou, kanshi). 14 event types. | heartbeat |
| **AU-3** | Content of Audit Records | `HeartbeatEntry` includes: sequence, timestamp, verifier identity (component + instance + version), event type, outcome, resource identifier, signature hash. | heartbeat |
| **AU-9** | Protection of Audit Information | BLAKE3 hash chain: each entry's `entry_hash` includes `previous_hash`. Modifying any entry breaks the chain at the next entry. `S3Emitter` for off-host persistence. | heartbeat |
| **SC-12** | Cryptographic Key Establishment and Management | Akeyless DFC threshold signing: key never exists in one piece. `MockDfcSigner` split-knowledge: `key = BLAKE3(fragment_a XOR fragment_b)`. `BreakGlassToken` for emergency bypass with full audit. | signing |

---

## 5. CIRCIA Compliance

The Cyber Incident Reporting for Critical Infrastructure Act requires evidence of continuous monitoring and a 72-hour reporting window for significant cyber incidents.

tameshi provides:

| Requirement | Implementation |
|-------------|---------------|
| Continuous monitoring evidence | `HeartbeatChain` -- append-only, BLAKE3-linked entries recording every verification event |
| 72-hour reporting window | `CirciaReport` -- aggregated evidence over configurable time window (`generate_circia_report(window_hours)`) |
| Tamper-evident records | Hash chain linkage: `entry_hash = BLAKE3(... ∥ previous_hash)`. Modification of any entry detectable |
| Off-host evidence preservation | `S3Emitter` persists chain to S3-compatible storage via `object_store` crate |
| Emergency bypass audit | `BreakGlassToken` events recorded as `HeartbeatEvent::BreakGlass` with cryptographic signing, scope, and expiry |
| Incremental verification | `ConsistencyProof` -- CT-style proof between two chain states (from_seq, to_seq), enabling remote audit without full chain download |

### CirciaReport Structure

```rust
pub struct CirciaReport {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub total_blocked: u64,
    pub blocked_by_reason: BTreeMap<String, u64>,  // NotInAllowMap, HashMismatch, Revoked
    pub blocked_binaries: Vec<BlockedBinarySummary>,
    pub heartbeat_chain_length: u64,
    pub chain_integrity_verified: bool,
}
```

`is_clean()` returns `true` when `total_blocked == 0` and `chain_integrity_verified == true`.

---

## 6. SLSA Level Mapping

| SLSA Level | Requirement | tameshi Coverage | Status |
|:----------:|-------------|-----------------|:------:|
| **Level 1** | Build process documented | Nix flake captures entire build graph. `SdlcChain` records 8 pipeline phases. | Covered |
| **Level 2** | Hosted build service + signed provenance | CI builds on hosted runners. `SignedRoot` with `AkeylessDfcSigner` or `LocalSigner`. | Covered |
| **Level 3** | Hardened build platform + non-falsifiable provenance | Nix hermetic builds (no network, no ambient state). DFC threshold signing (key never assembled). `CertificationArtifact` binds provenance to compliance and intent. | Covered |
| **Level 4** | Two-person review + hermetic, reproducible builds | tameshi does not enforce code review policy (organizational control). Nix builds are hermetic and reproducible. | Partial |

---

## 7. FedRAMP / OSCAL

kensa produces OSCAL (Open Security Controls Assessment Language) 1.1.2 output:

- `compliance/oscal.rs` generates OSCAL-formatted assessment results
- OSCAL output is BLAKE3-hashed into the compliance evidence chain
- The OSCAL hash becomes part of the `CertificationArtifact.control_hash` (Leaf 1)
- FedRAMP boundary documentation can reference the OSCAL output as machine-readable evidence
- `CompliancePlugin` trait's `nist_families()` method maps each domain's controls to NIST 800-53 control families

Assessment results are deterministic: same infrastructure state + same compliance rules = same OSCAL output = same BLAKE3 hash. This enables reproducible compliance verification and cacheable results.

---

## 8. What the System Does NOT Defend Against

| Attack Vector | Why | Mitigation Strategy |
|--------------|-----|---------------------|
| **Vulnerabilities in attested code** | Rice's Theorem: it is undecidable whether arbitrary code is free of vulnerabilities. Attestation proves provenance, not correctness. | Complement with SAST/DAST, fuzzing, and code review. |
| **BLAKE3 cryptanalysis** | If BLAKE3 is broken (preimage or collision attack), the entire hash chain is compromised. | BLAKE3 has a 256-bit security margin based on the well-analyzed BLAKE2 construction. `Sha256Hasher` is available as a FIPS 140-3 fallback. Switching requires only changing the `AttestationHasher` impl. |
| **Runtime behavior post-execution** | kanshi verifies binary integrity at exec time but cannot constrain what the binary does after passing verification. | Complement with eBPF runtime security (Falco, Tetragon) for behavioral monitoring. |
| **Kernel compromise** | If the kernel itself is compromised, eBPF LSM hooks can be bypassed. | Secure Boot + IMA (Integrity Measurement Architecture) + TPM-based attestation for kernel integrity. |
| **Side-channel attacks** | BLAKE3 timing side channels are not analyzed in this system. | Hash equality uses `PartialEq` on `[u8; 32]` byte arrays (constant-time in practice on modern CPUs). |
| **Quantum computing** | BLAKE3's 256-bit output provides 128-bit security against Grover's algorithm. May be insufficient for post-quantum requirements. | Monitor NIST post-quantum standardization. BLAKE3 output size can be extended. |

---

## 9. Test Evidence Summary

All test counts obtained by running the full suite across 9 repositories. Zero failures. Zero flaky tests. Deterministic -- reproduced on independent CI runs.

| Repository | Passing Tests | Key Coverage |
|------------|-------------:|--------------|
| tameshi | 1,178 | BLAKE3 determinism, Merkle composition, CertificationArtifact binding, signing (3 signers), HeartbeatChain integrity, GatingPolicy evaluation, 14 collectors, SDLC chain, IaC attestation |
| kensa | 546 | CompliancePlugin trait, 4 domain plugins, NIST control mapping, OSCAL output, CVE ingestion, two-phase certification |
| inshou | 457 | `App<N,C,P,K,F>` generic architecture, hash verification, gate logic, CLI parsing, fail-secure error paths |
| sekiban | 417 | Admission webhook, SignatureGate/Certification/CompliancePolicy CRDs, gate reconciler, changeset verification, OCI digest enforcement, multi-namespace policies |
| iac-test-runner | 180 | Init/Apply/Verify/Teardown orchestration, 5 platform adapters, phase hash composition, Helm chart |
| tameshi-watch | 144 | 7 CVE sources, dedup pipeline, severity filter, kensa ingestion, kanshi revocation |
| compliance-forge | 137 | Control generation from Pangea resources, TOML specs, structural compliance controls |
| kanshi | 135 | MockBpfLoader, FailableBpfLoader (chaos), CrdWatcher, HashVerifier, PolicyEngine, EventMetricsCollector, CirciaReport, BPF types |
| inspec-rspec | 94 | Parser correctness, control type construction, transpiler determinism, tag preservation, multi-describe blocks |
| **Total** | **3,288** | |

### Property Coverage

| Security Property | Test Count | Verification Method |
|-------------------|:---------:|---------------------|
| BLAKE3 determinism (same input -> same hash) | 55 | Unit tests + 19 proptest properties (256 random cases each) |
| Collision resistance (different inputs -> different hashes) | 30 | Exhaustive single-byte enumeration (256 inputs) + proptest |
| Merkle composition determinism | 30 | Repeated construction, reordering, proptest tamper detection |
| CertificationArtifact binding (3-leaf Merkle) | 109 | Composition, proof paths, tamper detection, proptest roundtrip |
| Threshold signing correctness | 70 | LocalSigner, MockDfcSigner split-knowledge, AkeylessDfcSigner API, BreakGlassToken |
| HeartbeatChain integrity | 51 | Chain linkage, tamper detection, consistency proofs, concurrent access |
| K8s admission gating | 417 | Webhook handler, CRD reconciliation, OCI digest enforcement, changeset verification |
| eBPF enforcement | 135 | BPF map operations, inode reuse detection, `verify_by_hash`, `enforce_or_fail`, policy engine |
| Nix gate fail-secure | 457 | All error paths, no fallback behavior, injectable dependencies |
