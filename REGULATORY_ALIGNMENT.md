# Tameshi Regulatory Alignment: CIRCIA, NIST SSDF, and Zero-Trust Compliance

## Executive Summary

Tameshi transforms Akeyless from a "Secrets Management" platform into a **Cryptographically Verifiable Infrastructure** platform.

Federal cybersecurity mandates — CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act), OMB M-22-18 software attestation requirements, and NIST SSDF (Secure Software Development Framework) — are converging on a single demand: **mathematically provable supply chain integrity, not just signed attestation documents**.

Tameshi delivers this by enforcing a BLAKE3 Merkle-tree hash chain from Nix builds through Akeyless secret provisioning to the Kubernetes admission webhook. The chain is not advisory. It is an admission gate. If the chain breaks, the deployment is rejected at the API level.

This is not a compliance checkbox. It is a mathematical guarantee that the infrastructure state tested and approved by the security team is the exact state that runs in production.

---

## NIST SSDF & OMB Software Attestation Alignment

### The Build-to-Runtime Gap

The OMB M-22-18 memorandum requires software producers to attest conformance with the NIST SSDF. In practice, this means:

1. Generate SBOMs (Software Bill of Materials)
2. Sign build artifacts with SLSA provenance
3. Attest that the development process followed SSDF practices

**The problem:** Standard CI/CD pipelines generate these artifacts at build time, but cannot guarantee that the SBOM matches the running state. Between the CI pipeline and the Kubernetes API call, there is an unguarded gap where:

- Container registries can be compromised
- Helm charts can be modified post-signing
- Kustomize overlays can inject unauthorized manifests
- FluxCD/ArgoCD source refs can be altered
- Akeyless dynamic secrets can be provisioned by tampered logic

SLSA Level 3 attestations prove "this artifact was built by this pipeline." They do NOT prove "this is the artifact currently being deployed to this cluster."

### How Tameshi Closes the Gap

Tameshi extends SLSA attestation into the runtime environment by hashing every layer of the deployment stack into a BLAKE3 Merkle tree and gating the Kubernetes API against the expected root hash:

```
SBOM signed at build time ──┐
                            ├── Standard SLSA L3 (build-time provenance)
Provenance signed by CI ────┘

Tameshi Merkle root ────────── Beyond SLSA L3 (deploy-time verification)
  ├── Nix closure hash         Each layer's content is independently verifiable
  ├── OCI manifest digest      Any change to any layer invalidates the root
  ├── Helm chart provenance    The K8s admission webhook rejects invalid roots
  ├── K8s manifest set hash
  ├── FluxCD reconciliation
  └── Akeyless secret state    Zero-knowledge proof of secret provisioning
```

Federal software attestation becomes **mathematically verifiable** rather than a paper exercise. The attestation is not "we followed SSDF practices" — it is "the cryptographic hash of every infrastructure component matches the hash computed during the security audit."

### SSDF Practice Mapping

| SSDF Practice | Tameshi Implementation |
|---------------|----------------------|
| PO.1 (Define security requirements) | GatingPolicy CRD: required layers, compliance requirement, signature age |
| PS.1 (Protect software from tampering) | BLAKE3 Merkle tree detects any modification to any layer |
| PS.2 (Provide mechanism to verify integrity) | sekiban admission webhook, Merkle inclusion proofs |
| PW.4 (Review/analyze code for vulnerabilities) | kensa compliance engine (NIST 800-53 assessment) |
| PW.6 (Configure compilation/build/packaging to improve security) | Nix hermetic builds, reproducible derivations |
| RV.1 (Identify/confirm vulnerabilities) | kensa native Rust checks + InSpec profiles |

### The Candor Statement

Tameshi proves **integrity and chain of custody**, not **code quality**.

It guarantees: "We are running exactly what we approved." It does NOT guarantee: "What we approved is free of vulnerabilities."

The quality of the security guarantee depends entirely on the rigor of the kensa compliance tests. If the tests are weak, the attested state is weakly audited. Tameshi makes the attestation chain unbreakable, but the security team must ensure the tests at the start of the chain are thorough.

This is the correct architectural boundary. Testing catches bugs. Attestation catches tampering. They are complementary, not redundant.

---

## CIRCIA Alignment: 72-Hour Incident Reporting

### The Incident Response Accelerator

CIRCIA requires critical infrastructure entities to report substantial cyber incidents within 72 hours. In practice, the first 24-48 hours of any breach investigation are consumed by:

1. **Determining scope:** "What systems were affected?"
2. **Establishing baseline:** "What was the known-good state?"
3. **Detecting drift:** "What changed between the baseline and the compromise?"
4. **Verifying supply chain:** "Were any artifacts tampered with?"

These are the most time-consuming and error-prone phases of incident response. Analysts spend hours comparing deployed state against documentation, SBOM records, and CI/CD logs.

### How Tameshi Eliminates Drift as a Variable

Tameshi provides an **immutable, BLAKE3-hashed baseline** of the deployment state and Akeyless secret usage at every deployment. During incident response:

```
Incident detected
  │
  ├── Query sekiban for current SignatureGate status
  │   └── Phase: Verified / Failed / Stale
  │
  ├── If Verified: deployment matches the tested baseline
  │   └── Scope: "infrastructure drift" and "supply chain tampering"
  │       are mathematically eliminated as attack vectors
  │
  ├── If Failed: deployment does NOT match baseline
  │   └── Immediate evidence: tampered component identified
  │       by which layer signature changed
  │
  ├── Merkle proof: isolate exactly WHICH layer was affected
  │   └── O(log n) verification — seconds, not hours
  │
  └── Akeyless attestation: verify secret provisioning integrity
      └── Salted hash proves secret state without revealing values
```

**Time savings:** Eliminating infrastructure drift and supply chain tampering from the triage reduces investigation time by an estimated 8-16 hours for a typical multi-service Kubernetes deployment. For a 72-hour reporting window, this is the difference between "incident reported with root cause" and "incident reported with ongoing investigation."

### Audit Trail for Regulators

The sekiban `Certification` CRD maintains an auditable trail:

- **Gate decisions:** Every allow/deny with timestamp, signature, reason
- **Compliance assessments:** NIST 800-53 control pass/fail results
- **Layer signatures:** Per-layer hashes with collector version and source
- **Master signatures:** Full Merkle root with compliance composition

This trail is queryable via REST, GraphQL, or gRPC API, enabling automated compliance evidence generation for CIRCIA reports.

### The Candor Statement

Tameshi is an **Admission Control** system, not a **Runtime Threat Detection** system.

It prevents unauthorized or tampered artifacts from starting. It does NOT monitor active in-memory exploitation after deployment. A zero-day exploit in application code that does not modify the deployment artifacts will not be detected by Tameshi.

The architectural boundary is deliberate:

| Concern | Tameshi | Runtime Security (Falco/Tetragon/etc.) |
|---------|---------|---------------------------------------|
| Supply chain injection | Detects and blocks | Does not detect |
| Infrastructure drift | Detects and blocks | Detects (slowly) |
| Post-deployment exploitation | Does not detect | Detects and alerts |
| Secret provisioning tampering | Detects and blocks | Does not detect |

Tameshi and runtime security tools are complementary layers in a defense-in-depth architecture. Neither replaces the other.

---

## The Akeyless "Last Mile" Advantage

### The Problem: Dynamic Secret Provisioning

Akeyless Dynamic Secrets are generated at runtime by provisioning logic that creates short-lived credentials (database users, AWS IAM roles, K8s tokens). The provisioning logic runs as part of the deployment pipeline.

If the provisioning logic is tampered with — a modified container image, a mutated Helm chart, an injected sidecar — the attacker gains the ability to:

1. Create credentials with elevated privileges
2. Extend credential lifetimes beyond policy
3. Exfiltrate credentials to external endpoints
4. Modify target configurations to redirect secret provisioning

All of this happens within the authorized provisioning flow. Standard audit logs show normal-looking credential creation events. The tampering is invisible to the secrets management platform because the request appears legitimate.

### How Tameshi Seals the Last Mile

Tameshi proves that the provisioning logic hasn't been tampered with **before it executes**:

```
Nix closure (hermetic build) ─────────────┐
OCI image (immutable manifest) ───────────┤
Helm chart (provenance verified) ─────────┤
K8s manifest set (hash verified) ─────────┤ BLAKE3 Merkle Root
FluxCD state (GitOps reconciled) ─────────┤
Akeyless target config (hash verified) ───┤
Akeyless secret access (salted hash) ─────┘
                                           │
                                           ▼
                              sekiban admission webhook
                              ALLOW only if Merkle root matches
                                           │
                                           ▼
                              Akeyless Dynamic Secret provisioning
                              (guaranteed untampered)
```

The admission webhook verifies the entire stack **before** the provisioning pod starts. If any component has been modified — even a single byte in a base image layer — the pod is rejected and never reaches the Akeyless API.

### Zero-Knowledge Secret Attestation

The Akeyless layer uses two-layer hashing. First, each secret value is salted and hashed at collection time (the raw value is consumed and never stored):

```
per_secret_hash = BLAKE3(gateway_url + ":" + secret_path + ":" + secret_value)
```

Then, the per-secret hashes are bound to the authentication context in a composite attestation hash:

```
attestation_hash = BLAKE3(
    gateway_url + auth_method + gateway_cert_hash + session_hash
    + for each secret: (path + type + per_secret_hash)
)
```

This proves:
1. **Which secrets were accessed** (path is in both hash layers)
2. **The exact value at access time** (value is in the per-secret hash)
3. **Which gateway served the secret** (gateway URL is salt in both layers)
4. **The authentication context** (auth method, TLS cert, session are in the composite)

Without revealing:
- The secret value itself (one-way hash)
- Any information useful for dictionary attacks (gateway+path salt defeats rainbow tables)

For enterprise and federal customers, this means Akeyless can offer a unique guarantee: **the cryptographic proof that the exact secret provisioning logic approved by the security team is the exact logic that ran in production, with zero-knowledge attestation of the secrets it accessed**.

No other secrets management platform provides this level of supply-chain integrity verification.

### Competitive Positioning

| Capability | Akeyless (standard) | Akeyless + Tameshi | HashiCorp Vault | CyberArk |
|-----------|--------------------|--------------------|-----------------|----------|
| Secret rotation | Yes | Yes | Yes | Yes |
| Dynamic secrets | Yes | Yes | Yes | Limited |
| Audit logging | Yes | Yes | Yes | Yes |
| Build provenance (SLSA L3) | Via CI | Via CI | Via CI | Via CI |
| **Deploy-time provenance (beyond SLSA L3)** | No | **Yes** | No | No |
| **K8s admission gating** | No | **Yes** | No | No |
| **Zero-knowledge secret attestation** | No | **Yes** | No | No |
| **Supply chain injection prevention** | No | **Yes** | No | No |
| **CIRCIA baseline evidence** | Partial | **Complete** | Partial | Partial |

*Note: Competitive claims based on publicly documented product capabilities as of March 2026. Vendors may have unreleased or undocumented features not reflected here.*

---

## Summary: What Tameshi Proves and What It Does Not

### Tameshi Proves

- The deployment state matches the audited baseline (cryptographic guarantee)
- No supply chain injection occurred between build and deploy (Merkle integrity)
- Secret provisioning logic was not tampered with (admission gating)
- Secret access is attestable without value disclosure (zero-knowledge hash)
- Infrastructure drift is detectable and blockable (continuous verification)

### Tameshi Does Not Prove

- The code is free of vulnerabilities (undecidable — Rice's Theorem proves that no algorithm can determine non-trivial semantic properties of arbitrary programs, and "vulnerability-free" is such a property)
- The security tests are comprehensive (depends on kensa test quality)
- Runtime behavior is safe after deployment (requires runtime security)
- The BLAKE3 algorithm itself is secure (relies on 256-bit security margin)

### The Net Position

Tameshi sits at the mathematical ceiling of what software systems can guarantee about supply chain integrity. It does not over-promise. It delivers exactly what the cryptography proves, and clearly documents the boundary between attestation and verification.

For federal compliance (CIRCIA, NIST SSDF, OMB M-22-18), this positions Akeyless as the only secrets management platform that can provide **mathematically verifiable deployment integrity** — not just audit logs, not just signed attestations, but cryptographic proof that the approved state is the running state.
