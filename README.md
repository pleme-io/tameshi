# tameshi (試し)

Deterministic integrity attestation library for infrastructure layers.

Provides cryptographic hash computation, Merkle tree composition, and signature verification for every stage of a deployment pipeline — from git commit to running pod.

## What it does

Every provisioning layer (Nix stores, OCI images, Helm charts, Kubernetes manifests) produces a **layer signature**. These compose into a **master signature** via a Merkle tree that gates provisioning at every level.

```text
Collectors → LayerSignatures → Merkle Tree → Master Untested Signature
                                                       +
                                             Compliance Hash
                                                       =
                                             Master Secure Signature
```

## Features

- **BLAKE3 hashing** — fast, deterministic content hashing across all layers
- **Merkle tree composition** — layer signatures compose into a verifiable tree
- **Certification pipeline** — source → build → image → chart → deployment → compliance
- **CI/CD integration** — factory functions for computing attestations at each pipeline stage
- **Kubernetes annotations** — generates `sekiban.pleme.io/signature` annotations for admission webhook gating
- **Layered configuration** — figment-based config (defaults → YAML → env vars)
- **Policy-driven evaluation** — strict production and relaxed staging policy presets
- **Multi-dimensional compliance** — NIST, CIS, STIG, SOC2, PCI-DSS, OWASP, and more

## Usage

```rust
use tameshi::certification::*;
use tameshi::ci;
use tameshi::hash::Blake3Hash;

// Compute attestations at each pipeline stage
let source = ci::source_attestation("github.com/org/repo", "abc123", "refs/heads/main",
    true, Blake3Hash::digest(b"tree"), Blake3Hash::digest(b"lock"), 10, true);

let build = ci::build_attestation("backend", "/nix/store/xxx.drv",
    Blake3Hash::digest(b"closure"), tameshi::compliance::slsa::SlsaLevel::L3,
    true, Blake3Hash::digest(b"sbom"), Blake3Hash::digest(b"vulns"), 0, 0, "nix-build@ci");

// Generate Kubernetes annotations for sekiban webhook
let annotations = ci::sekiban_annotations(
    &Blake3Hash::digest(b"signature"), None, None);
```

## License

MIT
