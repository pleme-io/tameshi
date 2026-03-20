# Akeyless Deep Integration Plan

> Definitive mapping of the full Akeyless API surface (604 endpoints, 18 categories)
> to every tameshi security requirement. This document answers: "How do we leverage
> the entire Akeyless product to make tameshi the best security framework possible?"

**Status:** Strategic planning document
**Last Updated:** 2026-03-20
**Classification:** PRIVATE — Internal architecture only

---

## The Integration Thesis

We have identified **30+ security holes** across 9 phases of adversarial analysis.
Akeyless provides **604 API endpoints** across 18 categories. The thesis: for every
hole tameshi needs to fill, there is an Akeyless capability that either solves it
directly or provides the trust anchor for our solution.

Tameshi provides the **integrity plane** (what is running, is it verified).
Akeyless provides the **secrets plane** (who can access what, cryptographic operations).
Together, they form a **closed-loop security architecture** where no single
compromise can break both planes simultaneously.

---

## Part 1: Akeyless API Endpoints → Tameshi Requirements

### Category 1: DFC Signing (8 endpoints)

**Akeyless Endpoints:**
- `create_dfc_key` — Create DFC signing key
- DFC sign/verify operations (8 total)

**Tameshi Requirements Solved:**

| Hole | Phase | How DFC Solves It |
|------|-------|-------------------|
| Root of Trust | 5 | Signing key split into fragments — literally un-stealable |
| Break-Glass tokens | 4 | Emergency bypass tokens signed by DFC — tamper-proof |
| Merkle root signing | 7-8 | Untested→Secure signature chain signed by DFC |
| Key compromise | 9 | No single point of key compromise — fragments distributed |

**Implementation Path:**
```rust
// tameshi/src/signing.rs → AkeylessDfcSigner
// Uses: POST /sign-data-with-classic-key (or DFC-specific endpoint)
// Flow: Merkle root bytes → Akeyless DFC sign → SignedRoot
// Verify: Akeyless DFC verify → bool
```

**Akeyless API calls needed:**
1. `auth` → get token
2. `sign_data_with_classic_key` (with DFC key name) → signature bytes
3. `verify_data_with_classic_key` → verification result

**Gap:** Our current `AkeylessDfcSigner` is a placeholder. Need to wire the actual
`akeyless_api::apis::v2_api::sign_data_with_classic_key` call.

---

### Category 2: Encryption/Decryption (15+ endpoints)

**Akeyless Endpoints:**
- `encrypt_with_key` / `decrypt_with_key`
- `encrypt_batch` / `decrypt_batch`
- Cipher support: AES-GCM, ChaCha20-Poly1305, RSA-OAEP

**Tameshi Requirements Solved:**

| Hole | Phase | How Encryption Solves It |
|------|-------|------------------------|
| Log-Erasure (CIRCIA integrity) | 8 | Heartbeat entries encrypted before storage |
| Zero-Knowledge evidence | 8 | Encrypted audit trail — even storage provider can't read |
| Break-Glass token payload | 4 | Token scope/reason encrypted for confidentiality |

**Implementation Path:**
```rust
// tameshi/src/heartbeat.rs → EncryptedEmitter
// Uses: POST /encrypt (with workspace-scoped key)
// Flow: HeartbeatEntry JSON → Akeyless encrypt → encrypted bytes → storage
// Recovery: encrypted bytes → Akeyless decrypt → original entry
```

**New module needed:** `tameshi/src/heartbeat.rs` — add `AkeylessEncryptedEmitter`
that wraps any inner emitter with Akeyless encryption.

---

### Category 3: HMAC Operations (1 endpoint)

**Akeyless Endpoint:** `hmac`

**Tameshi Requirements Solved:**

| Hole | Phase | How HMAC Solves It |
|------|-------|-------------------|
| Constant-time comparison | 9 | Akeyless HMAC for server-side hash verification |
| Heartbeat chain integrity | 3 | HMAC-based chain linking (alternative to BLAKE3) |

**Implementation Path:**
Server-side HMAC verification for webhook admission — sekiban can ask Akeyless
to compute HMAC(expected_hash, presented_hash) and compare server-side, eliminating
any client-side timing leak.

---

### Category 4: K8s Auth Method (26+ auth endpoints)

**Akeyless Endpoints:**
- `create_auth_method_k8s` / `update_auth_method_k8s`
- `auth` (with K8s JWT token)
- Sub-claims: namespace, service_account, pod_name

**Tameshi Requirements Solved:**

| Hole | Phase | How K8s Auth Solves It |
|------|-------|----------------------|
| Confused Deputy | 9 | Three-factor: binary_hash + namespace + service_account |
| Identity Masquerade | 6 | Pod identity cryptographically bound to Akeyless token |
| Contextual Binding | 9 | Akeyless Access Roles + Sub-Claims = per-binary policies |
| Ephemeral Container | 7 | Debug attestation requires Akeyless-authenticated SRE |

**Implementation Path (CRITICAL):**

The K8s auth method is the **linchpin** of the entire integration. Here's how:

1. **Current state:** Pod authenticates to Akeyless with K8s JWT → gets token
2. **Tameshi enhancement:** The Akeyless Access Role includes a **custom sub-claim**
   for the binary hash:
   ```json
   {
     "access_id": "p-k8s-prod",
     "sub_claims": {
       "namespace": ["production"],
       "service_account": ["auth-service-sa"],
       "tameshi_hash": ["blake3:abc123..."]
     }
   }
   ```
3. **Enforcement:** Akeyless will ONLY issue a token if ALL sub-claims match.
   The pod can't get secrets unless its binary hash, namespace, AND service account
   all match the Access Role configuration.

**Gap analysis:**
- Akeyless K8s auth supports namespace + service_account sub-claims natively
- Custom sub-claims (like `tameshi_hash`) may require Akeyless Gateway configuration
  or a custom auth method wrapper
- Alternative: Use `create_auth_method_cert` with client certificates that embed
  the binary hash in a certificate extension

---

### Category 5: Certificate Management (30+ endpoints)

**Akeyless Endpoints:**
- `create_pki_cert_issuer` / `create_ssh_cert_issuer`
- Certificate renewal, revocation, discovery
- CSR handling, SAN configuration

**Tameshi Requirements Solved:**

| Hole | Phase | How Certs Solve It |
|------|-------|-------------------|
| Akeyless API Spoof (MITM) | 8b | mTLS with Akeyless-issued client certs |
| Certificate pinning | 8b | Akeyless PKI → pinned CA compiled into Nix binary |
| Developer environment attestation | 6 | SSH certs with dev identity → build provenance |
| Ephemeral container auth | 7 | Short-lived SRE certs for debug attestation |

**Implementation Path:**
```rust
// tameshi/src/akeyless_client.rs — mTLS with Akeyless-issued certs
// 1. At build time: Nix fetches Akeyless CA cert → compile into binary
// 2. At runtime: Pod requests client cert from Akeyless PKI
// 3. All API calls use mTLS: client cert (pod identity) + pinned CA (Akeyless identity)
```

**New capability needed:**
- `inshou` — during CI, request a short-lived client certificate from Akeyless PKI
- Certificate includes: binary hash, build timestamp, Git commit SHA
- sekiban verifies the client cert when accepting attestation receipts

---

### Category 6: Dynamic Secrets (60+ endpoints, 27+ backends)

**Akeyless Endpoints:**
- Create/update/delete producers for all 27 backend types
- Get temporary credentials
- Test connections

**Tameshi Requirements Solved:**

| Hole | Phase | How Dynamic Secrets Solve It |
|------|-------|-----------------------------|
| Dynamic Secret Paradox | Spec | Policy-path hashing (path + target + role) |
| Secret rotation breaking attestation | Spec | Value rotates, policy hash stays stable |
| Database credential theft | — | Short-lived, auto-revoked credentials |

**Current Implementation:** Already complete in `tameshi/src/collectors/akeyless.rs`.
The collector hashes the secret PATH and ACCESS CONFIGURATION, not the value.

**Enhancement needed:**
- Add TTL metadata to the attestation: when was the producer last verified?
- Alert if a producer's configuration changes between attestation cycles
- Track which dynamic secret backends are in use for compliance reporting

---

### Category 7: Rotated Secrets (45+ endpoints, 18+ backends)

**Akeyless Endpoints:**
- Create/update/delete rotated secrets for 18 backend types
- Rotate now, get last rotation time, test connection

**Tameshi Requirements Solved:**

| Hole | Phase | How Rotated Secrets Solve It |
|------|-------|-----------------------------|
| Compliance TTL | 6 | Rotation events trigger re-attestation |
| Time-Drift attack | 8 | Rotation timestamp is Akeyless-verified (trusted time source) |
| CIRCIA evidence | Reg | Rotation events are Akeyless audit log entries |

**Enhancement needed:**
- Wire Akeyless rotation events to tameshi heartbeat chain
- When a rotated secret rotates, emit a `SecretRotation` heartbeat event
- This requires Akeyless Event Forwarding (see Category 13)

---

### Category 8: Target Management (125 endpoints, 31+ types)

**Already fully implemented** in `tameshi/src/collectors/akeyless_target.rs` with
all 30 target types. The collector hashes target CONFIGURATION (connection params,
auth method, association metadata).

**Enhancement needed:**
- Periodic re-collection: re-hash target configs on a configurable interval
- Alert on target configuration drift (same target name, different config hash)
- Add target health status to the attestation (is the target reachable?)

---

### Category 9: Log Forwarding (50+ endpoints, 11 destinations)

**Akeyless Endpoints:**
- Create/update/delete log forwarders for: S3, Azure Analytics, Datadog,
  Elasticsearch, Google Chronicle, Logstash, Logz.io, Splunk, Stdout,
  Sumologic, Syslog

**Tameshi Requirements Solved:**

| Hole | Phase | How Log Forwarding Solves It |
|------|-------|-----------------------------|
| Log-Erasure (CIRCIA) | 8 | Heartbeat chain → Akeyless → 11 external destinations |
| Immutable evidence | 8 | S3 with object lock (WORM) via Akeyless forwarder |
| Multi-destination redundancy | 8 | Same event → Splunk + S3 + Datadog simultaneously |

**Implementation Path:**
```yaml
# Akeyless Log Forwarding configuration for tameshi
log_forwarders:
  - type: aws_s3
    bucket: tameshi-evidence
    object_lock: true
    prefix: heartbeat/
  - type: splunk
    hec_endpoint: https://splunk.internal
    index: tameshi_audit
  - type: datadog
    api_key: "***"
    site: datadoghq.com
```

**Critical integration:** Configure Akeyless to forward ALL tameshi-related audit
events (secret accesses, auth events, key operations) to the same destinations
as the heartbeat chain. This creates a **two-source corroborating evidence trail**.

---

### Category 10: Event Forwarding (18 endpoints, 5 channels)

**Akeyless Endpoints:**
- Email, Slack, Teams, ServiceNow, Generic Webhooks

**Tameshi Requirements Solved:**

| Hole | Phase | How Event Forwarding Solves It |
|------|-------|-----------------------------|
| Break-Glass alerts | 4 | Break-glass activation → Slack + PagerDuty immediately |
| Revocation alerts | 7 | Binary revoked → Teams + ServiceNow ticket |
| Compliance degradation | 6 | Re-verification failure → email to security team |

**Implementation Path:**
Configure Akeyless to fire webhook events to a tameshi endpoint when:
- A secret is accessed by an attested binary (positive evidence)
- An auth method is modified (policy change → re-attestation trigger)
- A target configuration changes (drift alert)
- A DFC key is rotated (heartbeat chain records key rotation)

---

### Category 11: Access Control (10+ endpoints)

**Akeyless Endpoints:**
- `create_role` / `update_role` / `delete_role` / `list_roles`
- Role-to-auth-method binding
- Permission assignment

**Tameshi Requirements Solved:**

| Hole | Phase | How Access Control Solves It |
|------|-------|-----------------------------|
| Confused Deputy | 9 | Fine-grained roles per binary+namespace+SA |
| Least Privilege | NIST | Minimum-scope roles for each attestation context |
| IPC Isolation | 9 | Shared secrets only if both pods have matching roles |

**Critical Architecture Decision:**
Every tameshi-attested binary gets its own Akeyless Access Role:
```
Role: tameshi-auth-service-production
  Auth Methods: k8s-prod (namespace=production, sa=auth-service-sa)
  Permissions:
    - /production/db/credentials: read
    - /production/api/external-key: read
  Sub-Claims:
    - tameshi_hash: blake3:abc123...
```

This means: **modifying the binary changes the hash → the role no longer matches
→ the pod can't get secrets → the deployment is effectively blocked at both
the integrity plane (tameshi) AND the secrets plane (Akeyless).**

---

### Category 12: Audit & Compliance (20+ endpoints)

**Akeyless Endpoints:**
- `get_audit_logs` — Full audit trail
- Filtering by user, action, resource, time

**Tameshi Requirements Solved:**

| Requirement | How Audit Solves It |
|-------------|-------------------|
| CIRCIA 72-hour reporting | Akeyless audit + tameshi heartbeat = complete evidence |
| OMB M-26-05 runtime SBOM | Akeyless audit shows which secrets each binary accessed |
| SOC 2 CC7.1 (monitoring) | Real-time audit log monitoring via Akeyless API |
| Non-repudiation (AU-10) | Every secret access logged with caller identity + timestamp |

**Implementation Path:**
```rust
// kensa — pull Akeyless audit logs for compliance assessment
// Uses: GET /get-audit-logs
// Correlate: Akeyless audit events with tameshi heartbeat entries
// Output: Combined compliance report showing both attestation AND access history
```

---

### Category 13: Gateway & Remote Access (60+ endpoints)

**Akeyless Endpoints:**
- Gateway lifecycle, clustering, failover
- RDP/SSH gateway configuration
- Bastion host setup, session recording

**Tameshi Requirements Solved:**

| Hole | Phase | How Gateway/SRA Solves It |
|------|-------|-----------------------------|
| Break-Glass workflow | 4 | SRE authenticates via Akeyless SRA → approval workflow → sign bypass token |
| Ephemeral container | 7 | Debug access via Akeyless SSH cert → session recorded |
| Developer environment | 6 | Dev access via Akeyless SSH gateway → identity tracked |
| Dead Man's Switch | 4 | Gateway clustering → no single point of failure for attestation |

**Critical for availability:**
Akeyless Gateway clustering ensures that tameshi's signing and verification
operations are highly available. If one gateway goes down, the cluster fails over.
This directly addresses the "Dead Man's Switch" hole.

---

## Part 2: Gap Analysis — What's Missing

### Gaps in Current Implementation

| Gap | Current State | What's Needed | Akeyless API |
|-----|--------------|---------------|--------------|
| DFC signing is placeholder | `AkeylessDfcSigner` uses mock | Wire `sign_data_with_classic_key` | Yes (8 endpoints) |
| No mTLS/cert pinning | `reqwest` uses system CAs | Akeyless PKI → compiled CA | Yes (30+ cert endpoints) |
| No K8s auth sub-claims | API key auth only | K8s JWT + custom sub-claims | Yes (K8s auth method) |
| No log forwarding | File emitter only | Akeyless → S3/Splunk/Datadog | Yes (50+ endpoints) |
| No event-driven re-attestation | Periodic polling | Akeyless events → webhook trigger | Yes (18 event endpoints) |
| No encryption at rest for heartbeat | Plain JSON | Akeyless encrypt → encrypted JSONL | Yes (15+ encrypt endpoints) |
| No rotation event correlation | No rotation tracking | Akeyless audit → heartbeat entry | Yes (audit endpoints) |
| No HMAC server-side verify | Client-side comparison | Akeyless HMAC → timing-safe | Yes (1 endpoint) |
| No gateway HA | Single endpoint | Gateway cluster → failover | Yes (60+ gateway endpoints) |

### Gaps in Akeyless (What We Need to Build Ourselves)

| Gap | Why Akeyless Can't Solve It | Our Solution |
|-----|---------------------------|--------------|
| eBPF runtime enforcement | Akeyless is a secrets platform, not a kernel tool | kanshi (eBPF LSM hooks) |
| BLAKE3 Merkle tree | Akeyless uses standard crypto (RSA/ECDSA), not BLAKE3 | tameshi core library |
| Helm rendered hashing | Akeyless doesn't know about Helm charts | tameshi collectors |
| K8s admission webhook | Akeyless doesn't intercept K8s API calls | sekiban |
| Compliance framework mapping | Akeyless has SOC2 cert, doesn't map controls | kensa mapping modules |
| Nix content-addressing | Akeyless doesn't know about Nix | inshou + Nix |
| W^X enforcement | Kernel-level, not Akeyless scope | kanshi eBPF |

---

## Part 3: Regulatory Compliance Roadmap

### CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act)

**Requirement:** Report substantial cyber incidents within 72 hours to CISA.

**What constitutes "substantial":**
- Unauthorized access to information systems
- Compromise of cloud service provider used by the entity
- Denial of service affecting business operations
- Ransomware attacks (24-hour reporting)

**Tameshi + Akeyless coverage:**

| CIRCIA Requirement | Tameshi Component | Akeyless Component |
|-------------------|-------------------|-------------------|
| T+0 forensics data | Heartbeat chain (who verified what, when) | Audit logs (who accessed what secret) |
| Incident timeline | Heartbeat chain entries with monotonic timestamps | Audit log timestamps |
| Scope assessment | kanshi BPF map = real-time affected binary list | Access role = affected secret list |
| Evidence preservation | BLAKE3-linked chain (tamper-evident) | Immutable audit logs |
| Chain of custody | DFC-signed Merkle roots (provenance) | DFC-signed audit entries |
| Report generation | kensa CIRCIA report generator | Akeyless audit log export |

**What's needed to be fully compliant:**
1. Heartbeat chain streaming to immutable storage (S3 with WORM via Akeyless forwarder)
2. Correlated view: tameshi heartbeat + Akeyless audit in single timeline
3. Automated report generation with all required fields (entity info, incident description, affected systems, remediation actions)

### OMB M-22-18 / EO 14028 (Software Supply Chain Security)

**Requirement:** Federal agencies must obtain SBOM and attestation for all software.

**Key mandates:**
- SBOM (Software Bill of Materials) for all software sold to federal government
- Self-attestation form from software producers
- Artifact signing and verification
- Runtime attestation for cloud workloads

**Tameshi + Akeyless coverage:**

| OMB Requirement | Tameshi Component | Akeyless Component |
|-----------------|-------------------|-------------------|
| SBOM generation | kanshi BPF allow map = live SBOM | — |
| Artifact signing | DFC-signed Merkle roots | DFC signing infrastructure |
| Build provenance | Nix derivation hashes (SLSA Level 3+) | — |
| Runtime attestation | kanshi eBPF verification at execve | K8s auth (pod identity) |
| Continuous monitoring | Heartbeat chain + compliance TTL | Audit log stream |

**NIST SSDF (SP 800-218) alignment:**
- PO.1 (Define Security Requirements): kensa compliance policies
- PS.1 (Protect Software): Nix content-addressing + BLAKE3 Merkle
- PW.4 (Review and Audit): heartbeat chain + Akeyless audit
- RV.1 (Identify Vulnerabilities): kanshi revocation map for CVE response

### EU Cyber Resilience Act (CRA)

**Requirement:** Products with digital elements sold in EU must be "secure-by-design."

**Essential cybersecurity requirements:**
- No known exploitable vulnerabilities at time of sale
- Secure default configuration
- Protection against unauthorized access
- Data confidentiality and integrity
- Availability (resist DoS)
- Vulnerability handling process
- Security updates for product lifetime
- SBOM documentation

**Tameshi + Akeyless coverage:**

| CRA Requirement | Tameshi Component | Akeyless Component |
|-----------------|-------------------|-------------------|
| No known vulns | kanshi revocation map (CVE response) | — |
| Secure defaults | Audit-first mode (safe rollout) | — |
| Unauthorized access protection | sekiban webhook + kanshi eBPF | K8s auth + Access Roles |
| Data integrity | BLAKE3 Merkle tree | DFC encryption |
| Availability | Break-glass + CEL fail-safe + gateway HA | Gateway clustering |
| Vulnerability handling | Global revocation (<100ms) | Event forwarding (alerts) |
| Security updates | Self-healing rollback | — |
| SBOM | kanshi BPF map + Nix derivation | — |

**Language safety:** Entire tameshi stack is Rust (memory-safe by design).
This directly satisfies CRA's "secure-by-design" requirement — no buffer overflows,
use-after-free, or memory corruption vulnerabilities possible in safe Rust.

---

## Part 4: Implementation Priority Matrix

### Immediate (Wire existing Akeyless APIs)

| Priority | Item | Effort | Impact | Akeyless API |
|----------|------|--------|--------|-------------|
| P0 | Wire DFC signing in `AkeylessDfcSigner` | Low | Critical | `sign_data_with_classic_key` |
| P0 | Add K8s auth method to `AkeylessClient` | Medium | Critical | `auth` with K8s JWT |
| P1 | mTLS + cert pinning in `AkeylessClient` | Medium | High | `create_pki_cert_issuer` |
| P1 | Configure log forwarding for heartbeat | Low | High | `create_log_forwarding_*` |
| P2 | Server-side HMAC verification | Low | Medium | `hmac` |
| P2 | Heartbeat encryption via Akeyless | Medium | Medium | `encrypt_with_key` |
| P3 | Event-driven re-attestation | Medium | Medium | Event forwarding webhooks |
| P3 | Akeyless audit correlation in kensa | Medium | Medium | `get_audit_logs` |

### Near-term (Build new tameshi capabilities using Akeyless)

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| P1 | Custom sub-claims for binary hash in K8s auth | Medium | Critical |
| P1 | Akeyless Gateway HA for tameshi operations | Low | High |
| P2 | Rotation event → heartbeat chain integration | Medium | Medium |
| P2 | Target config drift detection | Medium | Medium |
| P3 | Combined audit report (Akeyless + tameshi) | High | High |

### Long-term (Requires Akeyless product team coordination)

| Priority | Item | Notes |
|----------|------|-------|
| P2 | Custom sub-claim type for BLAKE3 hash | May need Akeyless feature request |
| P3 | Akeyless Trusted Time Service for NTP validation | Feature availability TBD |
| P3 | DFC fragment distribution across tameshi nodes | Deep integration |

---

## Part 5: The Closed-Loop Architecture

When fully integrated, the architecture creates a **closed loop** where compromising
either tameshi OR Akeyless alone is insufficient to breach the system:

```
Attack: Compromise the binary
  → tameshi: Merkle root changes → sekiban rejects → BLOCKED
  → Akeyless: Binary hash sub-claim fails → no secrets → BLOCKED

Attack: Compromise a secret
  → Akeyless: DFC fragments distributed → can't reconstruct key → BLOCKED
  → tameshi: Secret policy-path hash unchanged → attestation still valid

Attack: Compromise the K8s cluster
  → tameshi: kanshi eBPF blocks unauthorized binaries → BLOCKED
  → Akeyless: K8s auth requires valid JWT + sub-claims → BLOCKED

Attack: Compromise the Akeyless gateway
  → tameshi: mTLS cert pinning → spoofed gateway rejected → BLOCKED
  → Akeyless: Gateway clustering → failover to healthy node → BLOCKED

Attack: Compromise the build pipeline
  → tameshi: Nix derivation hash changes → inshou gate rejects → BLOCKED
  → Akeyless: Dev environment SSH cert required → identity tracked → BLOCKED

Attack: Delete the evidence
  → tameshi: Heartbeat chain break detected → cryptographic proof of deletion
  → Akeyless: Immutable audit logs in 11 external destinations → EVIDENCE PRESERVED

Attack: Insider threat (two-person integrity)
  → tameshi: Break-glass requires DFC-signed token → needs key fragments
  → Akeyless: SRA approval workflow → second SRE must approve → BLOCKED
```

**No single compromise breaks both planes simultaneously.**
This is the "Beautiful Way" — not just security, but **mathematically provable security**.
