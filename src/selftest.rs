//! Self-attestation for the integrity framework.
//!
//! The tameshi/sekiban/kensa/inshou system must certify itself. This module
//! provides the ability to:
//!
//! 1. Hash the framework binaries (tameshi lib, sekiban, kensa, inshou)
//! 2. Hash the compliance catalogs and test profiles
//! 3. Map the framework's own security properties to NIST 800-53 controls
//! 4. Produce a "framework attestation hash" that's included in every
//!    master signature — proving the tools themselves are known-good
//!
//! ## NIST 800-53 Controls Satisfied by the Framework
//!
//! | Control | Title | How Tameshi Satisfies |
//! |---------|-------|----------------------|
//! | SI-7    | Software Integrity | BLAKE3 hash of all framework binaries |
//! | CM-2    | Baseline Configuration | Master signature = deterministic config baseline |
//! | CM-3    | Configuration Change Control | Gate denies uncertified changes |
//! | AU-2    | Event Logging | Audit trail of all gate decisions |
//! | AU-3    | Content of Audit Records | Full hash chain in audit entries |
//! | CA-2    | Control Assessments | kensa runs automated assessments |
//! | CA-7    | Continuous Monitoring | sekiban continuous certification loop |
//! | SC-13   | Cryptographic Protection | BLAKE3 + Merkle tree composition |
//! | SR-4    | Provenance | Each layer signature tracks input sources |
//! | SR-11   | Component Authenticity | OCI manifest hashing, Nix closure hashing |
//! | SI-10   | Information Input Validation | Admission webhook validates all inputs |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;

/// A framework component that can be self-attested.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkComponent {
    /// Component name (e.g., "tameshi", "sekiban", "kensa", "inshou").
    pub name: String,
    /// Version of the component.
    pub version: String,
    /// BLAKE3 hash of the component binary/library.
    pub binary_hash: Blake3Hash,
    /// Path to the binary (for re-verification).
    pub binary_path: String,
    /// NIST 800-53 controls this component helps satisfy.
    pub satisfies_controls: Vec<String>,
}

/// Complete framework attestation covering all components.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkAttestation {
    /// All framework components.
    pub components: Vec<FrameworkComponent>,
    /// Composite hash of all component hashes.
    pub framework_hash: Blake3Hash,
    /// When this attestation was computed.
    pub computed_at: DateTime<Utc>,
    /// Version of the attestation schema.
    pub schema_version: String,
}

impl FrameworkAttestation {
    /// Verify the framework attestation by recomputing the composite hash.
    pub fn verify(&self) -> bool {
        let recomputed = compute_framework_hash(&self.components);
        recomputed == self.framework_hash
    }

    /// Get all NIST controls satisfied by the framework.
    pub fn satisfied_controls(&self) -> Vec<String> {
        let mut controls: Vec<String> = self
            .components
            .iter()
            .flat_map(|c| c.satisfies_controls.clone())
            .collect();
        controls.sort();
        controls.dedup();
        controls
    }
}

/// Hash a binary file for framework self-attestation.
pub async fn hash_binary(path: &str) -> Result<Blake3Hash> {
    let data = tokio::fs::read(path).await.map_err(|e| {
        TameshiError::CollectorError {
            layer: "self-attestation".to_string(),
            message: format!("failed to read binary {}: {}", path, e),
        }
    })?;
    Ok(Blake3Hash::digest(&data))
}

/// Build the framework attestation by hashing all framework binaries.
pub async fn attest_framework(binary_paths: &[(&str, &str)]) -> Result<FrameworkAttestation> {
    let mut components = Vec::new();

    for (name, path) in binary_paths {
        let hash = hash_binary(path).await?;
        let controls = controls_for_component(name);
        components.push(FrameworkComponent {
            name: name.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            binary_hash: hash,
            binary_path: path.to_string(),
            satisfies_controls: controls,
        });
    }

    // Sort for determinism
    components.sort_by(|a, b| a.name.cmp(&b.name));

    let framework_hash = compute_framework_hash(&components);

    Ok(FrameworkAttestation {
        components,
        framework_hash,
        computed_at: Utc::now(),
        schema_version: "1.0.0".to_string(),
    })
}

/// Compute composite hash from all framework component hashes.
fn compute_framework_hash(components: &[FrameworkComponent]) -> Blake3Hash {
    let mut data = Vec::new();
    for component in components {
        data.extend_from_slice(&component.binary_hash.0);
    }
    Blake3Hash::digest(&data)
}

/// Map a component to the NIST 800-53 controls it satisfies.
fn controls_for_component(name: &str) -> Vec<String> {
    match name {
        "tameshi" => vec![
            "SC-13".to_string(), // Cryptographic Protection (BLAKE3, Merkle)
            "SR-4".to_string(),  // Provenance (input tracking)
            "SI-7".to_string(),  // Software Integrity (hash verification)
            "CM-2".to_string(),  // Baseline Configuration (master signature)
        ],
        "sekiban" => vec![
            "CM-3".to_string(),  // Configuration Change Control (admission webhook)
            "SI-10".to_string(), // Information Input Validation (webhook validation)
            "AU-2".to_string(),  // Event Logging (audit trail)
            "AU-3".to_string(),  // Content of Audit Records (hash chain)
            "CA-7".to_string(),  // Continuous Monitoring (cert reconciler)
            "AC-3".to_string(),  // Access Enforcement (gate denials)
        ],
        "kensa" => vec![
            "CA-2".to_string(), // Control Assessments (compliance testing)
            "CA-7".to_string(), // Continuous Monitoring (scheduled scans)
            "SI-4".to_string(), // System Monitoring (compliance checks)
            "RA-5".to_string(), // Vulnerability Monitoring (security scans)
        ],
        "inshou" => vec![
            "CM-2".to_string(), // Baseline Configuration (Nix profile hashing)
            "CM-3".to_string(), // Configuration Change Control (rebuild gate)
            "SI-7".to_string(), // Software Integrity (closure hashing)
            "SR-11".to_string(), // Component Authenticity (Nix store attestation)
        ],
        _ => vec![],
    }
}

/// NIST 800-53 controls relevant to the attestation framework itself.
///
/// These are the controls we claim our framework satisfies, and the kensa
/// self-test profiles should verify each one.
pub fn framework_nist_controls() -> Vec<FrameworkControlMapping> {
    vec![
        FrameworkControlMapping {
            control_id: "SI-7".to_string(),
            title: "Software, Firmware, and Information Integrity".to_string(),
            how_satisfied: "BLAKE3 hash of all framework binaries, Nix store closures, OCI manifests. Merkle tree composition ensures any change is detected.".to_string(),
            tested_by: vec!["self-attestation-binary-hash".to_string(), "nix-closure-integrity".to_string()],
        },
        FrameworkControlMapping {
            control_id: "CM-2".to_string(),
            title: "Baseline Configuration".to_string(),
            how_satisfied: "Master signature = deterministic hash of all infrastructure layers. Any deviation from baseline is detected by continuous certification.".to_string(),
            tested_by: vec!["master-signature-determinism".to_string(), "baseline-drift-detection".to_string()],
        },
        FrameworkControlMapping {
            control_id: "CM-3".to_string(),
            title: "Configuration Change Control".to_string(),
            how_satisfied: "Sekiban admission webhook gates ALL K8s API operations. Inshou gates Nix rebuilds. Changeset hashing ensures patches are attested.".to_string(),
            tested_by: vec!["admission-webhook-gate".to_string(), "inshou-rebuild-gate".to_string(), "changeset-hash-verification".to_string()],
        },
        FrameworkControlMapping {
            control_id: "AU-2".to_string(),
            title: "Event Logging".to_string(),
            how_satisfied: "Every gate decision is logged to structured tracing, K8s events, and the Certification audit trail.".to_string(),
            tested_by: vec!["audit-trail-completeness".to_string()],
        },
        FrameworkControlMapping {
            control_id: "CA-2".to_string(),
            title: "Control Assessments".to_string(),
            how_satisfied: "Kensa runs automated compliance assessments, maps to NIST controls, and produces OSCAL reports.".to_string(),
            tested_by: vec!["kensa-compliance-run".to_string(), "oscal-report-generation".to_string()],
        },
        FrameworkControlMapping {
            control_id: "CA-7".to_string(),
            title: "Continuous Monitoring".to_string(),
            how_satisfied: "Sekiban cert_reconciler continuously re-verifies environment signatures at configurable intervals.".to_string(),
            tested_by: vec!["continuous-certification-loop".to_string()],
        },
        FrameworkControlMapping {
            control_id: "SC-13".to_string(),
            title: "Cryptographic Protection".to_string(),
            how_satisfied: "BLAKE3 for all hashing, Merkle tree for composition, HMAC-SHA256 for webhook signatures.".to_string(),
            tested_by: vec!["blake3-determinism".to_string(), "merkle-composition".to_string()],
        },
        FrameworkControlMapping {
            control_id: "SR-4".to_string(),
            title: "Provenance".to_string(),
            how_satisfied: "Each LayerSignature tracks all inputs that were hashed, providing full provenance chain.".to_string(),
            tested_by: vec!["input-tracking-completeness".to_string()],
        },
        FrameworkControlMapping {
            control_id: "SR-11".to_string(),
            title: "Component Authenticity".to_string(),
            how_satisfied: "OCI manifest hashing, Helm chart provenance, Nix store closure hashing verify component authenticity.".to_string(),
            tested_by: vec!["oci-manifest-hash".to_string(), "nix-closure-hash".to_string()],
        },
    ]
}

/// Mapping of a NIST control to how the framework satisfies it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkControlMapping {
    /// NIST 800-53 control identifier.
    pub control_id: String,
    /// Control title.
    pub title: String,
    /// How the tameshi framework satisfies this control.
    pub how_satisfied: String,
    /// Test IDs in kensa that verify this claim.
    pub tested_by: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_hash_deterministic() {
        let components = vec![
            FrameworkComponent {
                name: "a".to_string(),
                version: "1.0".to_string(),
                binary_hash: Blake3Hash::digest(b"binary-a"),
                binary_path: "/bin/a".to_string(),
                satisfies_controls: vec![],
            },
            FrameworkComponent {
                name: "b".to_string(),
                version: "1.0".to_string(),
                binary_hash: Blake3Hash::digest(b"binary-b"),
                binary_path: "/bin/b".to_string(),
                satisfies_controls: vec![],
            },
        ];
        let h1 = compute_framework_hash(&components);
        let h2 = compute_framework_hash(&components);
        assert_eq!(h1, h2);
    }

    #[test]
    fn framework_hash_changes_with_binary() {
        let c1 = vec![FrameworkComponent {
            name: "a".to_string(),
            version: "1.0".to_string(),
            binary_hash: Blake3Hash::digest(b"binary-v1"),
            binary_path: "/bin/a".to_string(),
            satisfies_controls: vec![],
        }];
        let c2 = vec![FrameworkComponent {
            name: "a".to_string(),
            version: "1.0".to_string(),
            binary_hash: Blake3Hash::digest(b"binary-v2-modified"),
            binary_path: "/bin/a".to_string(),
            satisfies_controls: vec![],
        }];
        assert_ne!(compute_framework_hash(&c1), compute_framework_hash(&c2));
    }

    #[test]
    fn controls_for_all_components() {
        for name in &["tameshi", "sekiban", "kensa", "inshou"] {
            let controls = controls_for_component(name);
            assert!(!controls.is_empty(), "{} should have controls", name);
        }
    }

    #[test]
    fn framework_nist_controls_non_empty() {
        let mappings = framework_nist_controls();
        assert!(!mappings.is_empty());
        for mapping in &mappings {
            assert!(!mapping.tested_by.is_empty(), "Control {} needs tests", mapping.control_id);
        }
    }

    #[test]
    fn attestation_verify() {
        let components = vec![
            FrameworkComponent {
                name: "tameshi".to_string(),
                version: "0.1.0".to_string(),
                binary_hash: Blake3Hash::digest(b"tameshi-binary"),
                binary_path: "/nix/store/xxx-tameshi".to_string(),
                satisfies_controls: controls_for_component("tameshi"),
            },
        ];
        let framework_hash = compute_framework_hash(&components);
        let attestation = FrameworkAttestation {
            components,
            framework_hash,
            computed_at: Utc::now(),
            schema_version: "1.0.0".to_string(),
        };
        assert!(attestation.verify());
    }
}
