# Akeyless Product Integration Map

> How every Akeyless capability strengthens the Tameshi attestation ecosystem.

**Status:** Living document
**Last Updated:** 2026-03-20

---

## Integration Philosophy

Tameshi and Akeyless are not separate systems — they are two halves of one
security architecture. Akeyless provides the **secrets plane** (key management,
authentication, dynamic secrets). Tameshi provides the **integrity plane**
(cryptographic attestation, runtime enforcement, compliance evidence).

When merged correctly, they address **every hole** identified in the adversarial
architecture review.

---

## Akeyless Product → Tameshi Integration Matrix

### 1. DFC (Distributed Fragment Cryptography) → Merkle Root Signing

**Akeyless Capability:** Keys are split into fragments distributed across
infrastructure. No single point can reconstruct the full key.

**Tameshi Integration:** The Merkle root is signed by DFC — the signing key
literally cannot be stolen, even by a compromised node.

**Holes Addressed:**
- Root of Trust (Phase 5) — DFC provides the "un-stealable" signing key
- Break-Glass (Phase 4) — DFC-signed bypass tokens are tamper-proof

**Implementation:** `tameshi/src/signing.rs` → `AkeylessDfcSigner`

---

### 2. K8s Auth Method → Contextual Binding

**Akeyless Capability:** Authenticates pods based on K8s service account,
namespace, and pod identity. Issues short-lived access tokens bound to
the pod's identity.

**Tameshi Integration:** Extends K8s auth with binary hash as an additional
claim. The attestation becomes `Hash(Binary + Namespace + ServiceAccount)`.

**Holes Addressed:**
- Confused Deputy (Phase 9) — secrets only released if the FULL tuple matches
- Identity Masquerade (Phase 6) — binary can only run in its attested context

**Implementation:**
```yaml
# Akeyless K8s Auth Method — extended with tameshi claims
auth_method:
  type: k8s
  access_rules:
    - namespace: "production"
      service_account: "auth-service-sa"
      # NEW: tameshi binary hash claim
      tameshi_hash: "blake3:abc..."
      # Akeyless will ONLY issue a token if ALL three match
```

---

### 3. Dynamic Secrets → Policy-Path Hashing

**Akeyless Capability:** Generates short-lived, automatically-rotating
database credentials, cloud access keys, and API tokens.

**Tameshi Integration:** Hashes the secret POLICY (path + target + role),
not the secret VALUE. The attestation proves the authorization is untampered
while allowing values to rotate freely.

**Holes Addressed:**
- Dynamic Secret Paradox (PROVISIONING_AND_REVOCATION_SPEC.md)
- Policy Drift Detection (Phase 5)

**Already Implemented:** `tameshi/src/collectors/akeyless.rs` and
`tameshi/src/collectors/akeyless_target.rs` (30 target types)

---

### 4. Rotated Secrets → Heartbeat Re-Verification

**Akeyless Capability:** Automatically rotates static secrets (passwords,
API keys, certificates) on a configurable schedule.

**Tameshi Integration:** When a secret rotates, the heartbeat chain records
a `SecretRotation` event. kensa re-verifies that the policy path + target + role
haven't changed (the value rotated, but the policy is stable).

**Holes Addressed:**
- Time-Drift Attestation (Phase 6) — rotation events are timestamped
- CIRCIA Evidence — rotation events are part of the audit chain

---

### 5. Zero-Knowledge Encryption → Log Vault

**Akeyless Capability:** Client-side encryption where Akeyless never sees
the plaintext. Fragments of the encryption key are distributed via DFC.

**Tameshi Integration:** Heartbeat chain entries are encrypted with DFC before
storage. Even if the log vault is compromised, the entries are unreadable
without DFC key fragments from multiple Akeyless infrastructure components.

**Holes Addressed:**
- Log-Erasure (Phase 8) — encrypted, immutable log entries
- CIRCIA Chain Integrity — tamper-proof evidence even against insider threats

---

### 6. Certificate Issuer → mTLS Automation

**Akeyless Capability:** Issues short-lived X.509 certificates for
mutual TLS (mTLS) authentication.

**Tameshi Integration:** Every tameshi component (sekiban, kensa, inshou,
kanshi) authenticates to Akeyless via mTLS with DFC-issued certificates.
Certificate pinning compiled into the binary via Nix.

**Holes Addressed:**
- Akeyless API Spoof / MITM (Phase 8b) — pinned certificates, no system CA trust
- Supply Chain Pre-Commit (Phase 6) — build environment authenticated via mTLS

---

### 7. API Gateway → Admission Control API

**Akeyless Capability:** Centralized API gateway with rate limiting,
audit logging, and access control.

**Tameshi Integration:** sekiban's webhook verification calls route through
the Akeyless API Gateway, which provides:
- Rate limiting (prevents the Bloom Filter DoS attack, Phase 8)
- Audit logging (redundant evidence for CIRCIA)
- Access control (only attested components can query the Merkle root)

**Holes Addressed:**
- Resource Exhaustion / DoS (Phase 8) — API Gateway rate limits
- Akeyless API Spoof (Phase 8b) — Gateway enforces mTLS

---

### 8. SSH Certificate Issuer → Developer Environment Attestation

**Akeyless Capability:** Issues short-lived SSH certificates to developers,
authenticated via their corporate identity (OIDC/SAML).

**Tameshi Integration:** Developer access to the build environment requires
an Akeyless SSH certificate. The certificate includes claims about the
developer's identity, which are recorded in the Merkle tree as part of
the devenv attestation.

**Holes Addressed:**
- Supply Chain Pre-Commit (Phase 6) — developer identity is part of the attestation
- Insider Threat — every commit traceable to an authenticated developer

---

### 9. Universal Identity → Multi-Cluster Federation

**Akeyless Capability:** Single identity platform across clouds, clusters,
and environments. Supports AWS IAM, GCP SA, Azure AD, K8s, LDAP, OIDC.

**Tameshi Integration:** Certification CRDs replicate between clusters using
Akeyless Universal Identity for cross-cluster authentication. Each cluster
verifies the remote certification against its local Akeyless-authenticated
trust anchor.

**Holes Addressed:**
- Multi-Cluster Federation (Sprint 9-10) — Akeyless provides the identity plane
- Cross-cloud attestation — same identity across AWS/GCP/Azure

---

### 10. Audit Logs → CIRCIA Evidence Stream

**Akeyless Capability:** Immutable audit logs of all API operations, secret
accesses, and authentication events.

**Tameshi Integration:** Tameshi's heartbeat chain streams to Akeyless Audit
Logs as a secondary evidence store. The combined log provides:
- Who accessed what secret (Akeyless audit)
- What binary was verified (Tameshi heartbeat)
- When compliance was assessed (kensa heartbeat)
- Full 72-hour CIRCIA evidence chain

---

### 11. Secure Remote Access → Break-Glass Workflow

**Akeyless Capability:** Just-in-time SSH/RDP access with approval workflows,
session recording, and automatic credential rotation.

**Tameshi Integration:** Break-glass token issuance is routed through Akeyless
Secure Remote Access. The SRE must:
1. Authenticate to Akeyless (MFA + corporate identity)
2. Get approval from a second SRE (n-of-m)
3. Receive a short-lived break-glass signing key
4. Sign the bypass token (recorded in Akeyless audit)

**Holes Addressed:**
- Dead Man's Switch / Availability (Phase 4) — controlled bypass with full audit
- Insider Threat — two-person integrity for emergency access

---

### 12. Custom Targets (30 types) → Target Attestation

**Akeyless Capability:** 30 target types including AWS, GCP, Azure, SSH,
databases, certificate stores, Vault, LDAP, and more.

**Tameshi Integration:** Each target's CONFIGURATION (not its secret value)
is hashed into the Merkle tree. The `AkeylessTargetCollector` captures:
- Target type and connection parameters
- Producer associations (dynamic/rotated secret bindings)
- Access role bindings

**Already Implemented:** `tameshi/src/collectors/akeyless_target.rs`
with all 30 target types.

---

## Combined Threat Model Coverage

| Threat | Akeyless Solution | Tameshi Solution | Combined |
|--------|------------------|-----------------|----------|
| Binary tampering | — | BLAKE3 Merkle + kanshi eBPF | Full coverage |
| Secret theft | DFC (un-stealable keys) | Policy-path hashing | Full coverage |
| Config poisoning | — | Helm rendered hash | Full coverage |
| Identity spoofing | K8s Auth + Universal Identity | Contextual binding | Full coverage |
| MITM / API spoof | Certificate Issuer + mTLS | Certificate pinning | Full coverage |
| Log erasure | Immutable Audit Logs | Heartbeat chain | Double coverage |
| Insider threat | MFA + Approval workflows | Two-person break-glass | Full coverage |
| Key compromise | DFC (fragmented keys) | Revocation map | Full coverage |
| Zero-day exploit | — | Global revocation (<100ms) | Full coverage |
| Compliance drift | — | TTL attestations + kensa | Full coverage |
| Cross-cluster | Universal Identity | Federation CRD replication | Full coverage |
| DoS on security | API Gateway rate limiting | Bloom filter pre-verification | Full coverage |
| Developer compromise | SSH Certificate Issuer | Devenv attestation | Full coverage |
| Clock manipulation | Trusted Time Service | Monotonic clock (bpf_ktime) | Full coverage |

---

## Architecture: The Complete Security Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    AKEYLESS PLANE                           │
│                                                             │
│  DFC Signing ─── Certificate Issuer ─── K8s Auth Method    │
│  Dynamic Secrets ─── Rotated Secrets ─── Custom Targets    │
│  API Gateway ─── Audit Logs ─── Secure Remote Access       │
│  Universal Identity ─── Zero-Knowledge Encryption          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                    TAMESHI PLANE                            │
│                                                             │
│  ┌─ THE SHIELD (Admission) ────────────────────────────┐   │
│  │  sekiban webhook ─── CEL fail-safe ─── break-glass  │   │
│  │  inshou gate ─── OCI digest check ─── sidecar guard │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─ THE PULSE (Runtime) ───────────────────────────────┐   │
│  │  kanshi eBPF ─── file_open hooks ─── W^X enforce    │   │
│  │  revocation map ─── procfs masking ─── IPC isolation│   │
│  │  self-healing rollback ─── memory sampling          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─ THE MEMORY (Compliance) ───────────────────────────┐   │
│  │  kensa NIST/SOC2/PCI/FedRAMP ─── heartbeat chain   │   │
│  │  DFC signed roots ─── CIRCIA evidence ─── TTL       │   │
│  │  Hubble dashboard ─── audit-first mode              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## What No Competitor Offers

| Capability | Tameshi+Akeyless | CyberArk | HashiCorp Vault | Sigstore |
|------------|-----------------|----------|----------------|----------|
| BLAKE3 Merkle attestation | Yes | No | No | No (SHA only) |
| eBPF runtime enforcement | Yes | No | No | No |
| DFC threshold signing | Yes (Akeyless) | No | No | No |
| Config integrity (Helm rendered) | Yes | No | No | No |
| Break-glass with audit | Yes | Partial | No | No |
| CIRCIA-compliant evidence chain | Yes | No | No | No |
| Multi-arch attestation | Yes | No | No | Partial |
| Self-healing rollback | Yes | No | No | No |
| W^X kernel enforcement | Yes | No | No | No |
| Policy-path secret hashing | Yes | No | No | No |
| Audit-first rollout mode | Yes | No | No | No |
| Live compliance dashboard | Yes | Partial | Partial | No |
| Nix content-addressed builds | Yes | No | No | No |
| Constant-time hash comparison | Yes | Unknown | Unknown | No |
