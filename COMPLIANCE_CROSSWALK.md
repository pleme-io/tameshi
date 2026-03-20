# Tameshi Compliance Crosswalk

> Complete mapping of Tameshi attestation capabilities to regulatory frameworks,
> vulnerability classes, and industry benchmarks.

**Status:** Living document
**Last Updated:** 2026-03-20
**Classification:** Compliance Artifact — suitable for auditor distribution

---

## 1. NIST SP 800-53 Rev. 5 Control Mapping

### Full Coverage Controls

| Control ID | Control Name | Tameshi Component | Evidence |
|-----------|-------------|------------------|----------|
| **SR-4** | Provenance | tameshi (Nix + BLAKE3) | Mathematical chain of custody from source code to running binary via content-addressed Nix derivations and BLAKE3 Merkle trees |
| **SI-7** | Software/Firmware Integrity | kanshi (eBPF LSM) | Atomic binary verification at `bprm_check_security` — kernel holds binary lock, zero TOCTOU window |
| **SI-7(1)** | Integrity Checks | kanshi + inshou | Startup self-attestation + periodic runtime re-verification |
| **SI-7(5)** | Automated Response to Integrity Violations | sekiban (self-healing) | Automatic rollback to last-known-good Merkle root on tamper detection |
| **SI-7(6)** | Cryptographic Protection | tameshi (BLAKE3) | All integrity checks use BLAKE3 with constant-time comparison (subtle crate) |
| **SI-16** | Memory Protection | kanshi (W^X enforcement) | eBPF `file_mprotect` hook enforces Write XOR Execute at kernel level |
| **CM-2** | Baseline Configuration | tameshi (Helm rendered hash) | Cryptographic snapshot of the full rendered Helm manifest as Merkle leaf |
| **CM-3** | Configuration Change Control | sekiban (admission webhook) | Any config change invalidates the Merkle root — deployment rejected |
| **CM-6** | Configuration Settings | tameshi (config integrity) | All ConfigMaps, env vars, security contexts hashed into Merkle tree |
| **CM-7** | Least Functionality | tameshi (resource limits attestation) | Resource limits and security contexts are attested leaf nodes |
| **CM-8** | System Component Inventory | kanshi (BPF allow map) | Real-time cryptographic inventory of every running binary — live runtime SBOM |
| **CM-14** | Signed Components | tameshi (DFC signing) | Merkle roots signed via Akeyless DFC threshold cryptography |
| **AU-2** | Audit Events | tameshi (heartbeat chain) | Every verification event recorded in append-only BLAKE3-linked chain |
| **AU-3** | Content of Audit Records | tameshi (HeartbeatEntry) | Each entry includes: verifier, event type, result, resource, signature, timestamp, chain hash |
| **AU-4** | Audit Storage Capacity | tameshi (streaming emitters) | Real-time streaming to S3/Akeyless Log Vault — unlimited capacity |
| **AU-8** | Time Stamps | kanshi (monotonic clock) | `bpf_ktime_get_ns()` for tamper-resistant timestamps + NTP drift detection |
| **AU-9** | Protection of Audit Information | tameshi (heartbeat chain) | Chain integrity — any deletion breaks the BLAKE3 link, providing cryptographic proof of tampering |
| **AU-10** | Non-Repudiation | tameshi + Akeyless | Every secret access tied to Merkle proof; every attestation DFC-signed |
| **AC-3** | Access Enforcement | tameshi (contextual binding) | `Hash(Binary + Namespace + ServiceAccount)` — three-factor attestation |
| **AC-6** | Least Privilege | kanshi (ephemeral container guard) | Debug containers require Senior SRE attestation via Akeyless |
| **AC-6(9)** | Auditing Use of Privileged Functions | kanshi (procfs masking) | eBPF blocks privileged writes to /proc, /sys even from root containers |
| **SC-4** | Information in Shared System Resources | kanshi (IPC isolation) | eBPF `ipc_permission` hook blocks IPC between attested and unattested pods |
| **SC-5** | Denial of Service Protection | sekiban (Bloom filter) | Pre-verification rejects 99% of garbage requests in nanoseconds |
| **SC-7** | Boundary Protection | kanshi (eBPF LSM) | Kernel-level boundary prevents unauthorized lateral movement |
| **SC-8** | Transmission Confidentiality | tameshi (mTLS + cert pinning) | All Akeyless API calls use mutual TLS with pinned certificates |
| **SC-13** | Cryptographic Protection | tameshi (BLAKE3 + Ed25519) | BLAKE3 for integrity, Ed25519/DFC for signing, constant-time comparison |
| **SC-23** | Session Authenticity | tameshi (mTLS) | Bidirectional authentication: pod proves identity to Akeyless, Akeyless proves identity to pod |
| **SC-34** | Non-Modifiable Execution Programs | sekiban (self-attestation) | sekiban verifies its own binary hash at startup before registering webhook |
| **SC-39** | Process Isolation | kanshi (W^X + IPC isolation) | Write-XOR-Execute + cross-cgroup IPC blocking |
| **SC-45** | System Time Synchronization | kanshi (NTP integrity) | Monotonic clock for TTL checks; wall clock drift alerting |
| **SC-51** | Hardware-Rooted Integrity | kanshi (TPM 2.0 — Phase 5) | TPM remote attestation verifies node firmware before receiving keys |
| **SA-10** | Developer Configuration Management | inshou + Nix | Content-addressed builds; any input change = different derivation hash |
| **SA-11** | Developer Security Testing | kensa (compliance engine) | Automated NIST/SOC2/PCI/FedRAMP/STIG assessments with hash attestation |
| **IA-2** | Identification and Authentication | Akeyless K8s Auth | Pod identity bound to namespace + service account + binary hash |
| **IA-5** | Authenticator Management | tameshi (cert pinning) | Akeyless CA fingerprint compiled into binary via Nix |
| **IA-7** | Cryptographic Module Authentication | tameshi (DFC signing) | Threshold signing — key never exists in one piece |
| **IR-4** | Incident Handling | sekiban (self-healing) | Auto-rollback on integrity violation with forensic context |
| **IR-5** | Incident Monitoring | kanshi + tameshi (heartbeat) | Real-time verification stream to Grafana/Hubble dashboard |
| **IR-6** | Incident Reporting | tameshi (CIRCIA evidence) | 72-hour reporting chain with cryptographic provenance |
| **CA-2** | Security Assessments | kensa (compliance TTL) | Mandatory re-verification every 30 days against current baseline |
| **CA-7** | Continuous Monitoring | kanshi + heartbeat | Continuous runtime integrity verification via eBPF |

---

## 2. CWE (Common Weakness Enumeration) Coverage

| CWE ID | Weakness Name | Tameshi Defense | Component |
|--------|--------------|-----------------|-----------|
| **CWE-494** | Download of Code Without Integrity Check | Physically impossible — all code must pass Merkle integrity check before execution | kanshi (eBPF) |
| **CWE-367** | Time-of-Check Time-of-Use (TOCTOU) | eBPF LSM hook holds kernel lock during verification — zero TOCTOU window. `fexecve` pattern for FD-based execution | kanshi (LSM) |
| **CWE-693** | Protection Mechanism Failure | W^X enforcement at kernel level — security mechanisms cannot be bypassed in memory | kanshi (mprotect) |
| **CWE-502** | Deserialization of Untrusted Data | Config integrity hashing — deserialized data must match attested Merkle leaf | tameshi (config hash) |
| **CWE-829** | Inclusion of Functionality from Untrusted Control Sphere | Nix content-addressing — all dependencies are hash-verified | inshou + Nix |
| **CWE-912** | Hidden Functionality | Helm rendered hashing — injected sidecars detected by pod spec re-hash | sekiban (reinvocation) |
| **CWE-345** | Insufficient Verification of Data Authenticity | DFC signing — Merkle roots cryptographically signed, cannot be forged | tameshi (DFC) |
| **CWE-353** | Missing Support for Integrity Check | Every binary, config, and secret policy has a BLAKE3 hash in the Merkle tree | tameshi (full coverage) |
| **CWE-250** | Execution with Unnecessary Privileges | procfs/sysfs masking — even privileged containers blocked from host writes | kanshi (LSM) |
| **CWE-269** | Improper Privilege Management | Contextual binding — binary can only run in its attested namespace/SA | tameshi (3-factor) |
| **CWE-732** | Incorrect Permission Assignment | Attestation includes security context (runAsUser, capabilities) — any change breaks Merkle | tameshi (config hash) |
| **CWE-668** | Exposure of Resource to Wrong Sphere | IPC isolation — attested pods cannot share memory with unattested pods | kanshi (IPC hook) |

---

## 3. CAPEC (Common Attack Pattern Enumeration) Coverage

| CAPEC ID | Attack Pattern | Tameshi Defense | Component |
|----------|---------------|-----------------|-----------|
| **CAPEC-437** | Exploitation of Trusted Dependency | Poisoned dependency won't match Nix derivation hash — build rejected | inshou + Nix |
| **CAPEC-185** | Malicious Software Update | Short-lived attestations + version-pinned history — old versions expire, replay blocked | sekiban (TTL) |
| **CAPEC-148** | Content Spoofing | Certificate pinning + mTLS — Akeyless API cannot be spoofed by DNS/MITM | tameshi (cert pin) |
| **CAPEC-94** | Adversary in the Middle | mTLS with pinned Akeyless CA — MITM impossible without DFC key fragments | tameshi (mTLS) |
| **CAPEC-176** | Configuration/Environment Manipulation | Helm rendered hash — any config change breaks Merkle root | tameshi (config) |
| **CAPEC-242** | Code Injection | W^X enforcement — executable memory cannot be written; writable memory cannot be executed | kanshi (W^X) |
| **CAPEC-166** | Force the System to Reset Values | Break-glass mechanism with cryptographic audit — forced resets are fully logged | tameshi (break-glass) |
| **CAPEC-439** | Manipulation During Distribution | OCI digest-only references — mutable tags rejected by sekiban | sekiban (digest check) |
| **CAPEC-153** | Input Data Manipulation | Config integrity — all input data (ConfigMaps, env vars) hashed into Merkle tree | tameshi (config hash) |

---

## 4. 2026 Regulatory "Big Three"

### CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act)

**Requirement:** Report substantial cyber incidents within 72 hours.

**Tameshi Solution:** The heartbeat chain provides "T+0" forensics:
- Every verification event includes: who verified, what was checked, when, result, chain hash
- Streaming to immutable log vault — cannot be erased by attacker
- Break-glass events are Level 1 audit alerts with full provenance
- Heartbeat chain integrity verification proves continuous monitoring

**Evidence Artifacts:**
- `heartbeat.jsonl` — append-only JSONL with BLAKE3 chain linkage
- `HeartbeatChain::verify_integrity()` — cryptographic proof of completeness
- Break-glass token audit trail — signed, timestamped, scoped

### OMB M-26-05 (Risk-Based Assurances)

**Requirement:** Runtime SBOMs for cloud providers. Shift from standardized forms to risk-based assurances.

**Tameshi Solution:** kanshi's BPF allow map IS a live runtime SBOM:
- `tameshi_allow_map` contains every binary hash authorized to run
- Real-time — updated as pods start/stop
- Cryptographically verified — every entry is a BLAKE3 hash
- Exportable as JSON/SPDX/CycloneDX via kanshi admin API

**Evidence Artifacts:**
- BPF map dump → runtime SBOM export
- Prometheus metrics: `tameshi_verification_total` per binary
- Grafana dashboard: "Cluster Integrity Score"

### EU Cyber Resilience Act (CRA)

**Requirement:** Prove "Secure-by-Design" for products sold in the EU.

**Tameshi Solution:**
- **Language safety:** Entire stack is Rust (memory-safe by design)
- **Build reproducibility:** Nix derivations are content-addressed
- **Supply chain security:** BLAKE3 Merkle tree covers all dependencies
- **Vulnerability management:** Global revocation map for zero-day response
- **Update mechanism:** Self-healing rollback on integrity violation

---

## 5. CIS Kubernetes Benchmark Hardening

| CIS Section | Requirement | Tameshi Implementation | Score Impact |
|-------------|-------------|----------------------|-------------|
| **1.2.x** | Secrets Encryption | Akeyless DFC — secrets never stored in etcd or K8s filesystem | Pass (hardest CIS requirement) |
| **4.2.x** | Kubelet Security | kanshi eBPF verifies binaries at kernel level — independent of kubelet | Pass |
| **5.1.x** | RBAC Enforcement | Tameshi contextual binding: `Hash(Binary + Namespace + ServiceAccount)` — RBAC is cryptographic law | Pass |
| **5.2.x** | Pod Security Standards | kanshi enforces "Restricted" profile at kernel level — blocks host networking, privileged escalation | Pass |
| **5.3.x** | Network Policies | kanshi Cilium integration — network identity correlated with attestation state | Pass |
| **5.4.x** | Secrets Management | Akeyless dynamic secrets — policy-path hashing, never plaintext in cluster | Pass |
| **5.7.x** | General Policies | Helm rendered hashing — all pod policies attested in Merkle tree | Pass |

---

## 6. Additional Framework Coverage

### SOC 2 Type II Trust Service Criteria

| Category | Controls Covered | Tameshi Component |
|----------|-----------------|-------------------|
| Security (CC) | CC6.1, CC6.6, CC6.7, CC7.1, CC7.2, CC8.1 | sekiban, kanshi, heartbeat, inshou |
| Availability (A) | A1.1, A1.2 | break-glass, self-healing |
| Processing Integrity (PI) | PI1.1 | BLAKE3 Merkle tree |
| Confidentiality (C) | C1.1 | Akeyless policy-path hashing |

### PCI DSS 4.0

| Requirement | Controls Covered | Tameshi Component |
|-------------|-----------------|-------------------|
| Req 6: Secure Development | 6.2.4, 6.3.2 | Nix content-addressing, BLAKE3 integrity |
| Req 10: Logging | 10.2.1, 10.3.1 | Heartbeat chain, CIRCIA evidence |
| Req 11: Testing | 11.3.1, 11.6.1 | kensa continuous assessment, TTL attestations |
| Req 12: Policy | 12.3.1, 12.8.1 | Compliance dashboard, audit-first mode |

### FedRAMP (Based on NIST 800-53)

| Baseline | Controls Covered | Tameshi Component |
|----------|-----------------|-------------------|
| Low | CM-2, CM-6, SI-7, AU-2, AU-3 | tameshi, sekiban, heartbeat |
| Moderate | + CM-8, SC-7, SC-13, IA-2, IR-6 | + kanshi, Akeyless K8s Auth |
| High | + SC-34, SC-51, SI-16, AU-10 | + self-attestation, TPM, W^X |

### DISA STIG

| Severity | Findings Addressed | Tameshi Component |
|----------|-------------------|-------------------|
| CAT I (Critical) | Binary integrity, unauthorized execution | kanshi eBPF, revocation map |
| CAT II (Medium) | Config drift, audit completeness, secrets | Helm hash, heartbeat, Akeyless |
| CAT III (Low) | Logging format, metric export | heartbeat JSONL, Prometheus |

---

## 7. Compliance Generation

Tameshi can automatically generate compliance artifacts via kensa:

```bash
# Generate NIST 800-53 report
kensa report --framework nist-800-53 --baseline moderate --output nist-report.json

# Generate SOC 2 Type II report
kensa report --framework soc2 --output soc2-report.json

# Generate PCI DSS 4.0 report
kensa report --framework pci-dss --output pci-report.json

# Generate FedRAMP report
kensa report --framework fedramp --baseline high --output fedramp-report.json

# Generate DISA STIG report
kensa report --framework disa-stig --output stig-report.json

# Generate full compliance crosswalk (all frameworks)
kensa report --framework all --output compliance-crosswalk.json
```

Each report includes:
- Framework name and version
- Assessment timestamp
- Control-by-control mapping with evidence
- Tameshi component that satisfies each control
- Current compliance status (pass/fail/partial)
- Heartbeat chain reference for audit trail
