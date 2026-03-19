//! Compliance testing types, OSCAL mapping, and compliance hash computation.
//!
//! The compliance module handles the "second dimension" of integrity attestation:
//! security testing results from NIST/OSCAL/InSpec and other frameworks.
//!
//! **Critical design:** The compliance hash includes not just test results, but also
//! the hashes of the verification packages themselves (InSpec profiles, custom check
//! binaries, OSCAL catalogs). This means:
//!
//! 1. The test framework code is itself attested
//! 2. The control catalogs (NIST 800-53, etc.) are themselves attested
//! 3. Individual test results are attested
//! 4. The composition of (framework hash + catalog hash + results hash) forms the
//!    compliance hash
//! 5. This compliance hash combines with the untested master signature to form the
//!    final secure signature
//!
//! This makes it **impossible** to apply infrastructure that hasn't been verified by
//! known-good, verified testing methods.
//!
//! ## Compliance Dimensions
//!
//! Each compliance source is a "dimension" that contributes to the final hash:
//!
//! | Dimension | Module | Standard |
//! |-----------|--------|----------|
//! | NIST 800-53 assessment | `nist`, `oscal` | NIST SP 800-53 Rev 5 |
//! | CVE/vulnerability scan | `cve` | CVE/NVD/OSV |
//! | SBOM attestation | `sbom` | CycloneDX/SPDX, NTIA |
//! | SLSA provenance | `slsa` | SLSA v1.2, Sigstore, in-toto |
//! | CIS benchmarks | `cis` | CIS Kubernetes/Docker/Linux |
//! | Additional standards | `standards` | DISA STIG, SOC 2, PCI DSS, OWASP, ISO 27001 |
//! | Testing frameworks | `frameworks` | InSpec, OPA, kube-bench, Trivy, etc. |
//! | Unified composition | `dimensions` | All of the above |

pub mod akeyless;
pub mod akeyless_target;
pub mod cis;
pub mod cve;
pub mod dimensions;
pub mod frameworks;
pub mod inspec;
pub mod nist;
pub mod oscal;
pub mod result;
pub mod sbom;
pub mod slsa;
pub mod standards;
