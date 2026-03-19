# Tameshi Attestation Ecosystem — Akeyless Hackathon Demo

## What is Tameshi?

Tameshi is a deterministic integrity attestation system for infrastructure.
It creates cryptographic proof that your entire deployment pipeline — from source
code to running containers — has not been tampered with.

**Key insight:** By including Akeyless secret access in the attestation chain,
we prove not just WHAT was deployed, but that the secrets powering it came from
a verified, auditable source.

## Architecture

```
Source Code (git hash)
    |
Build (Nix closure hash)
    |
Image (OCI manifest hash)
    |
Chart (Helm chart hash)
    |
Secrets (Akeyless access hash) <-- NEW
    |
Deploy (K8s manifest hash)
    |
+---------------------------+
|  Merkle Tree Composition  |
|  (BLAKE3, deterministic)  |
+------------+--------------+
             |
    Master Signature
             |
    Compliance Check (NIST 800-53)
             |
    Secure Master Signature
             |
+---------------------------+
|  Sekiban Admission Gate   |
|  (K8s ValidatingWebhook)  |
+---------------------------+
```

## Demo Steps

### Step 1: Source Attestation

```bash
# Hash the git tree
git rev-parse HEAD
# -> abc123...

# The commit hash becomes an input to the attestation
```

### Step 2: Build Attestation (inshou)

```bash
# Hash the Nix closure of our service
inshou hash --closure /nix/store/...-my-service
# -> blake3:7f3a...

# This proves the build is deterministic and hermetic
```

### Step 3: Compliance Check (kensa)

```bash
# Run NIST 800-53 compliance checks
kensa run --baseline moderate

# Generate OSCAL assessment results
kensa report --format oscal

# Get the compliance hash
kensa hash
# -> blake3:9b2e...
```

### Step 4: Akeyless Secret Attestation

```bash
# The attestation includes:
# - Which Akeyless gateway was used
# - Authentication method (K8s auth, API key, etc.)
# - BLAKE3 hash of each secret VALUE (not the value itself!)
# - Gateway TLS certificate hash
# - Session hash

# This proves:
# 1. Secrets came from YOUR Akeyless gateway
# 2. The correct secrets were accessed
# 3. No secret substitution attack occurred
```

### Step 5: Deploy with Sekiban Gate

```bash
# Apply the CRDs
kubectl apply -f demo/compliance-policy.yaml
kubectl apply -f demo/signature-gate.yaml
kubectl apply -f demo/certification.yaml

# Try deploying WITHOUT a valid signature -- DENIED
kubectl apply -f demo/unattested-deployment.yaml
# -> Error: admission webhook denied: signature missing

# Deploy WITH a valid signature -- ALLOWED
kubectl apply -f demo/attested-deployment.yaml
# -> deployment.apps/my-service created
```

### Step 6: Tamper Detection

```bash
# Modify one secret in Akeyless
# Re-deploy the same manifest
# Sekiban DENIES because the Akeyless hash changed
# -> "signature mismatch: akeyless layer hash changed"
```

### Step 7: Merkle Proof Verification

```bash
# Generate inclusion proof for the Akeyless layer
# Proves the secret attestation is part of the master signature
# Without revealing other layer hashes
```

## Why Akeyless + Tameshi?

| Without Tameshi | With Tameshi |
|----------------|-------------|
| Secrets accessed at deploy time -- no audit trail in the signature | Akeyless access hashed into master signature |
| Can't prove which gateway provided secrets | Gateway TLS cert hash in attestation |
| Secret substitution attacks possible | Any change to secret values changes the master hash |
| Compliance is a separate, disconnected process | NIST 800-53 controls mapped to attestation dimensions |
| No cryptographic proof of deployment integrity | BLAKE3 Merkle tree with inclusion proofs |

## Components

| Component | Role |
|-----------|------|
| **tameshi** | Core attestation library -- BLAKE3 hashing, Merkle trees, compliance mapping |
| **sekiban** | K8s admission controller -- gates deployments on valid signatures |
| **kensa** | Compliance engine -- NIST 800-53, OSCAL reports, compliance hashing |
| **inshou** | Nix integrity gate -- hashes Nix closures, pre-rebuild verification |

## Demo Manifests

| File | Description |
|------|-------------|
| `signature-gate.yaml` | SignatureGate CRD that defines which layers to verify and which resources to intercept |
| `compliance-policy.yaml` | CompliancePolicy CRD configuring NIST 800-53 moderate baseline with kensa test runner |
| `certification.yaml` | Certification CRD aggregating gates for the production environment |
| `attested-deployment.yaml` | Deployment with valid sekiban attestation annotations -- will be admitted |
| `unattested-deployment.yaml` | Deployment without attestation annotations -- will be denied by the webhook |
