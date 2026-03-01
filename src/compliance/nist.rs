//! NIST SP 800-53 control catalog and baseline mappings.
//!
//! Provides the NIST 800-53 Rev 5 control families, baselines (Low, Moderate, High),
//! and mapping logic from assessment results to specific controls.

use serde::{Deserialize, Serialize};

use crate::compliance::oscal::{Catalog, Control, ControlGroup};
use crate::hash::Blake3Hash;

/// NIST 800-53 baseline levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Baseline {
    Low,
    Moderate,
    High,
}

impl std::fmt::Display for Baseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Baseline::Low => write!(f, "low"),
            Baseline::Moderate => write!(f, "moderate"),
            Baseline::High => write!(f, "high"),
        }
    }
}

/// NIST 800-53 control family identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlFamily {
    AC, // Access Control
    AT, // Awareness and Training
    AU, // Audit and Accountability
    CA, // Assessment, Authorization, and Monitoring
    CM, // Configuration Management
    CP, // Contingency Planning
    IA, // Identification and Authentication
    IR, // Incident Response
    MA, // Maintenance
    MP, // Media Protection
    PE, // Physical and Environmental Protection
    PL, // Planning
    PM, // Program Management
    PS, // Personnel Security
    PT, // PII Processing and Transparency
    RA, // Risk Assessment
    SA, // System and Services Acquisition
    SC, // System and Communications Protection
    SI, // System and Information Integrity
    SR, // Supply Chain Risk Management
}

impl std::fmt::Display for ControlFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A mapping from test/check identifier to NIST 800-53 controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlMapping {
    /// Test/check identifier (e.g., InSpec control ID).
    pub test_id: String,
    /// NIST 800-53 control IDs this test covers.
    pub control_ids: Vec<String>,
    /// Description of what the test verifies.
    pub description: String,
}

/// Build the NIST 800-53 Rev 5 control catalog (abbreviated).
///
/// This returns the catalog structure with control families and their
/// key controls relevant to infrastructure attestation.
pub fn build_catalog() -> Catalog {
    Catalog {
        uuid: uuid::Uuid::new_v4(),
        title: "NIST SP 800-53 Rev 5".to_string(),
        version: "5.0".to_string(),
        groups: vec![
            ControlGroup {
                id: "AC".to_string(),
                title: "Access Control".to_string(),
                controls: vec![
                    control("AC-2", "Account Management"),
                    control("AC-3", "Access Enforcement"),
                    control("AC-4", "Information Flow Enforcement"),
                    control("AC-6", "Least Privilege"),
                    control("AC-7", "Unsuccessful Logon Attempts"),
                    control("AC-17", "Remote Access"),
                ],
            },
            ControlGroup {
                id: "AU".to_string(),
                title: "Audit and Accountability".to_string(),
                controls: vec![
                    control("AU-2", "Event Logging"),
                    control("AU-3", "Content of Audit Records"),
                    control("AU-6", "Audit Record Review, Analysis, and Reporting"),
                    control("AU-12", "Audit Record Generation"),
                ],
            },
            ControlGroup {
                id: "CA".to_string(),
                title: "Assessment, Authorization, and Monitoring".to_string(),
                controls: vec![
                    control("CA-2", "Control Assessments"),
                    control("CA-7", "Continuous Monitoring"),
                    control("CA-8", "Penetration Testing"),
                ],
            },
            ControlGroup {
                id: "CM".to_string(),
                title: "Configuration Management".to_string(),
                controls: vec![
                    control("CM-2", "Baseline Configuration"),
                    control("CM-3", "Configuration Change Control"),
                    control("CM-6", "Configuration Settings"),
                    control("CM-7", "Least Functionality"),
                    control("CM-8", "System Component Inventory"),
                ],
            },
            ControlGroup {
                id: "IA".to_string(),
                title: "Identification and Authentication".to_string(),
                controls: vec![
                    control("IA-2", "Identification and Authentication (Organizational Users)"),
                    control("IA-5", "Authenticator Management"),
                    control("IA-8", "Identification and Authentication (Non-Organizational Users)"),
                ],
            },
            ControlGroup {
                id: "SC".to_string(),
                title: "System and Communications Protection".to_string(),
                controls: vec![
                    control("SC-7", "Boundary Protection"),
                    control("SC-8", "Transmission Confidentiality and Integrity"),
                    control("SC-12", "Cryptographic Key Establishment and Management"),
                    control("SC-13", "Cryptographic Protection"),
                    control("SC-28", "Protection of Information at Rest"),
                ],
            },
            ControlGroup {
                id: "SI".to_string(),
                title: "System and Information Integrity".to_string(),
                controls: vec![
                    control("SI-2", "Flaw Remediation"),
                    control("SI-3", "Malicious Code Protection"),
                    control("SI-4", "System Monitoring"),
                    control("SI-7", "Software, Firmware, and Information Integrity"),
                    control("SI-10", "Information Input Validation"),
                ],
            },
            ControlGroup {
                id: "SR".to_string(),
                title: "Supply Chain Risk Management".to_string(),
                controls: vec![
                    control("SR-3", "Supply Chain Controls and Processes"),
                    control("SR-4", "Provenance"),
                    control("SR-11", "Component Authenticity"),
                ],
            },
        ],
    }
}

/// Get controls for a specific baseline.
pub fn baseline_controls(baseline: &Baseline) -> Vec<String> {
    match baseline {
        Baseline::Low => vec![
            "AC-2", "AC-3", "AC-7", "AC-17", "AU-2", "AU-3", "AU-6", "AU-12", "CA-2", "CA-7",
            "CM-2", "CM-6", "CM-7", "CM-8", "IA-2", "IA-5", "SC-7", "SC-8", "SC-13", "SC-28",
            "SI-2", "SI-3", "SI-4",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        Baseline::Moderate => {
            let mut controls = baseline_controls(&Baseline::Low);
            controls.extend(
                vec!["AC-4", "AC-6", "CA-8", "CM-3", "IA-8", "SC-12", "SI-7", "SI-10", "SR-3", "SR-4", "SR-11"]
                    .into_iter()
                    .map(String::from),
            );
            controls
        }
        Baseline::High => {
            let mut controls = baseline_controls(&Baseline::Moderate);
            // High adds all remaining controls
            controls.extend(
                vec!["AC-4", "SC-12"]
                    .into_iter()
                    .map(String::from),
            );
            controls.sort();
            controls.dedup();
            controls
        }
    }
}

/// Compute a hash of the NIST catalog for a given baseline.
///
/// This hash is included in the compliance hash to attest that the
/// correct control catalog was used for verification.
pub fn baseline_catalog_hash(baseline: &Baseline) -> Blake3Hash {
    let controls = baseline_controls(baseline);
    let canonical = serde_json::to_vec(&controls).unwrap_or_default();
    Blake3Hash::digest(&canonical)
}

fn control(id: &str, title: &str) -> Control {
    Control {
        id: id.to_string(),
        title: title.to_string(),
        description: String::new(),
        enhancements: vec![],
    }
}
