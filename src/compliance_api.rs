//! Central compliance query trait and types.
//!
//! Defines the [`ComplianceQuery`] trait that all tameshi ecosystem repos
//! (sekiban, kensa, inshou) can implement for querying compliance state.
//! Also provides the data types for compliance distance, framework state,
//! certification query status, and dynamic compliance checks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// Current compliance state of the system.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComplianceState {
    /// Overall compliance status.
    pub status: ComplianceStatus,
    /// Distance to full compliance (gap analysis).
    pub distance: ComplianceDistance,
    /// Per-framework compliance states.
    pub frameworks: Vec<FrameworkState>,
    /// When the last assessment was performed.
    pub last_assessed_at: Option<DateTime<Utc>>,
    /// BLAKE3 hash of the compliance evidence.
    pub compliance_hash: Option<Blake3Hash>,
}

/// Overall compliance status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    /// All required controls are satisfied.
    Compliant,
    /// One or more required controls are not satisfied.
    NonCompliant,
    /// Some controls are satisfied, some are not.
    Partial,
    /// Compliance state has not been assessed.
    Unknown,
}

/// Distance to full compliance: how many controls are satisfied vs required.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComplianceDistance {
    /// Total number of controls required by the target baseline.
    pub target_controls: usize,
    /// Number of controls currently satisfied.
    pub satisfied: usize,
    /// Number of controls not yet satisfied (`target_controls - satisfied`).
    pub gap: usize,
    /// Percentage of controls satisfied (0.0..=100.0).
    pub percentage: f64,
}

/// Compliance state for a single framework/baseline.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FrameworkState {
    /// Framework identifier (e.g., "nist-800-53", "cis-k8s").
    pub framework: String,
    /// Baseline level (e.g., "moderate", "level-1").
    pub baseline: String,
    /// Compliance status for this framework.
    pub status: ComplianceStatus,
    /// Total number of controls in this framework baseline.
    pub controls_total: usize,
    /// Number of satisfied controls.
    pub controls_satisfied: usize,
}

/// Status of a certification query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificationQueryStatus {
    /// System is currently certified.
    Certified,
    /// Certification is in progress.
    Pending,
    /// Certification failed.
    Failed,
    /// Certification has expired.
    Expired,
}

/// Definition for a dynamic compliance check.
///
/// Dynamic checks can be registered at runtime to extend compliance
/// coverage beyond the static framework controls.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DynamicComplianceCheck {
    /// Unique check identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this check verifies.
    pub description: String,
    /// The check definition (what to verify).
    pub definition: CheckDefinition,
    /// Framework controls this check satisfies (e.g., "AC-2", "CM-7").
    pub framework_controls: Vec<String>,
    /// When this check was created.
    pub created_at: DateTime<Utc>,
}

/// The type-tagged definition of what a dynamic check verifies.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckDefinition {
    /// Verify that a specific binary hash has been revoked.
    BinaryRevocation {
        /// The BLAKE3 hash of the binary to check.
        binary_hash: Blake3Hash,
    },
    /// Verify that a config file at `path` matches the expected hash.
    ConfigAssertion {
        /// Path to the configuration file.
        path: String,
        /// Expected BLAKE3 hash of the file contents.
        expected_hash: Blake3Hash,
    },
    /// Check whether a CVE affects any of the listed packages.
    CveCheck {
        /// The CVE identifier (e.g., "CVE-2024-1234").
        cve_id: String,
        /// Package names to check against.
        affected_packages: Vec<String>,
    },
    /// Run a custom script and check its exit code.
    Custom {
        /// Script contents to execute.
        script: String,
        /// Expected exit code (0 for success).
        expected_exit_code: i32,
    },
}

/// Central trait for querying compliance state.
///
/// Implementations provide access to the current compliance posture,
/// compliance distance for specific framework baselines, and
/// certification status. All methods are async to support remote
/// data sources (kensa API, database queries, etc.).
pub trait ComplianceQuery: Send + Sync {
    /// Get the current overall compliance state.
    fn state(
        &self,
    ) -> impl std::future::Future<Output = crate::error::Result<ComplianceState>> + Send;

    /// Get the compliance distance for a specific framework and baseline.
    fn distance(
        &self,
        baseline: &str,
        framework: &str,
    ) -> impl std::future::Future<Output = crate::error::Result<ComplianceDistance>> + Send;

    /// Get the current certification status.
    fn certification_status(
        &self,
    ) -> impl std::future::Future<Output = crate::error::Result<CertificationQueryStatus>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // ComplianceState serde roundtrip
    // =========================================================================

    #[test]
    fn compliance_state_serde_roundtrip() {
        let state = ComplianceState {
            status: ComplianceStatus::Partial,
            distance: ComplianceDistance {
                target_controls: 100,
                satisfied: 75,
                gap: 25,
                percentage: 75.0,
            },
            frameworks: vec![FrameworkState {
                framework: "nist-800-53".to_string(),
                baseline: "moderate".to_string(),
                status: ComplianceStatus::Partial,
                controls_total: 100,
                controls_satisfied: 75,
            }],
            last_assessed_at: Some(Utc::now()),
            compliance_hash: Some(Blake3Hash::digest(b"compliance-evidence")),
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ComplianceState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, ComplianceStatus::Partial);
        assert_eq!(deserialized.distance.target_controls, 100);
        assert_eq!(deserialized.distance.satisfied, 75);
        assert_eq!(deserialized.frameworks.len(), 1);
        assert!(deserialized.last_assessed_at.is_some());
        assert!(deserialized.compliance_hash.is_some());
    }

    // =========================================================================
    // ComplianceStatus serde roundtrip
    // =========================================================================

    #[test]
    fn compliance_status_serde_roundtrip() {
        let statuses = vec![
            ComplianceStatus::Compliant,
            ComplianceStatus::NonCompliant,
            ComplianceStatus::Partial,
            ComplianceStatus::Unknown,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: ComplianceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, &deserialized);
        }
    }

    #[test]
    fn compliance_status_snake_case_serialization() {
        let json = serde_json::to_string(&ComplianceStatus::NonCompliant).unwrap();
        assert_eq!(json, "\"non_compliant\"");

        let json = serde_json::to_string(&ComplianceStatus::Compliant).unwrap();
        assert_eq!(json, "\"compliant\"");
    }

    // =========================================================================
    // ComplianceDistance serde roundtrip
    // =========================================================================

    #[test]
    fn compliance_distance_serde_roundtrip() {
        let distance = ComplianceDistance {
            target_controls: 200,
            satisfied: 150,
            gap: 50,
            percentage: 75.0,
        };
        let json = serde_json::to_string(&distance).unwrap();
        let deserialized: ComplianceDistance = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.target_controls, 200);
        assert_eq!(deserialized.satisfied, 150);
        assert_eq!(deserialized.gap, 50);
        assert!((deserialized.percentage - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compliance_distance_percentage_calculation() {
        // Verify the percentage field is consistent with target/satisfied
        let distance = ComplianceDistance {
            target_controls: 80,
            satisfied: 60,
            gap: 20,
            percentage: 75.0,
        };
        let computed_pct = if distance.target_controls == 0 {
            100.0
        } else {
            (distance.satisfied as f64 / distance.target_controls as f64) * 100.0
        };
        assert!(
            (distance.percentage - computed_pct).abs() < f64::EPSILON,
            "Percentage should equal satisfied/target * 100"
        );
    }

    #[test]
    fn compliance_distance_zero_controls() {
        let distance = ComplianceDistance {
            target_controls: 0,
            satisfied: 0,
            gap: 0,
            percentage: 100.0,
        };
        let json = serde_json::to_string(&distance).unwrap();
        let deserialized: ComplianceDistance = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.target_controls, 0);
        assert!((deserialized.percentage - 100.0).abs() < f64::EPSILON);
    }

    // =========================================================================
    // FrameworkState serde roundtrip
    // =========================================================================

    #[test]
    fn framework_state_serde_roundtrip() {
        let fs = FrameworkState {
            framework: "cis-k8s".to_string(),
            baseline: "level-1".to_string(),
            status: ComplianceStatus::Compliant,
            controls_total: 50,
            controls_satisfied: 50,
        };
        let json = serde_json::to_string(&fs).unwrap();
        let deserialized: FrameworkState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.framework, "cis-k8s");
        assert_eq!(deserialized.baseline, "level-1");
        assert_eq!(deserialized.status, ComplianceStatus::Compliant);
        assert_eq!(deserialized.controls_total, 50);
        assert_eq!(deserialized.controls_satisfied, 50);
    }

    // =========================================================================
    // CertificationQueryStatus serde roundtrip
    // =========================================================================

    #[test]
    fn certification_query_status_serde_roundtrip() {
        let statuses = vec![
            CertificationQueryStatus::Certified,
            CertificationQueryStatus::Pending,
            CertificationQueryStatus::Failed,
            CertificationQueryStatus::Expired,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: CertificationQueryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, &deserialized);
        }
    }

    #[test]
    fn certification_query_status_snake_case() {
        let json = serde_json::to_string(&CertificationQueryStatus::Certified).unwrap();
        assert_eq!(json, "\"certified\"");
        let json = serde_json::to_string(&CertificationQueryStatus::Expired).unwrap();
        assert_eq!(json, "\"expired\"");
    }

    // =========================================================================
    // DynamicComplianceCheck serde roundtrip
    // =========================================================================

    #[test]
    fn dynamic_compliance_check_serde_roundtrip() {
        let check = DynamicComplianceCheck {
            id: "check-001".to_string(),
            name: "Binary integrity check".to_string(),
            description: "Verify critical binary hash".to_string(),
            definition: CheckDefinition::BinaryRevocation {
                binary_hash: Blake3Hash::digest(b"malicious-binary"),
            },
            framework_controls: vec!["SI-7".to_string(), "CM-3".to_string()],
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let deserialized: DynamicComplianceCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "check-001");
        assert_eq!(deserialized.framework_controls.len(), 2);
    }

    // =========================================================================
    // CheckDefinition variant serde roundtrips (tag-based serialization)
    // =========================================================================

    #[test]
    fn check_definition_binary_revocation_serde() {
        let def = CheckDefinition::BinaryRevocation {
            binary_hash: Blake3Hash::digest(b"some-binary"),
        };
        let json = serde_json::to_string(&def).unwrap();
        assert!(json.contains("\"type\":\"binary_revocation\""));
        let deserialized: CheckDefinition = serde_json::from_str(&json).unwrap();
        match deserialized {
            CheckDefinition::BinaryRevocation { binary_hash } => {
                assert_eq!(binary_hash, Blake3Hash::digest(b"some-binary"));
            }
            _ => panic!("Expected BinaryRevocation variant"),
        }
    }

    #[test]
    fn check_definition_config_assertion_serde() {
        let def = CheckDefinition::ConfigAssertion {
            path: "/etc/app/config.yaml".to_string(),
            expected_hash: Blake3Hash::digest(b"config-content"),
        };
        let json = serde_json::to_string(&def).unwrap();
        assert!(json.contains("\"type\":\"config_assertion\""));
        let deserialized: CheckDefinition = serde_json::from_str(&json).unwrap();
        match deserialized {
            CheckDefinition::ConfigAssertion { path, expected_hash } => {
                assert_eq!(path, "/etc/app/config.yaml");
                assert_eq!(expected_hash, Blake3Hash::digest(b"config-content"));
            }
            _ => panic!("Expected ConfigAssertion variant"),
        }
    }

    #[test]
    fn check_definition_cve_check_serde() {
        let def = CheckDefinition::CveCheck {
            cve_id: "CVE-2024-1234".to_string(),
            affected_packages: vec!["openssl".to_string(), "libcrypto".to_string()],
        };
        let json = serde_json::to_string(&def).unwrap();
        assert!(json.contains("\"type\":\"cve_check\""));
        let deserialized: CheckDefinition = serde_json::from_str(&json).unwrap();
        match deserialized {
            CheckDefinition::CveCheck {
                cve_id,
                affected_packages,
            } => {
                assert_eq!(cve_id, "CVE-2024-1234");
                assert_eq!(affected_packages.len(), 2);
            }
            _ => panic!("Expected CveCheck variant"),
        }
    }

    #[test]
    fn check_definition_custom_serde() {
        let def = CheckDefinition::Custom {
            script: "#!/bin/bash\nexit 0".to_string(),
            expected_exit_code: 0,
        };
        let json = serde_json::to_string(&def).unwrap();
        assert!(json.contains("\"type\":\"custom\""));
        let deserialized: CheckDefinition = serde_json::from_str(&json).unwrap();
        match deserialized {
            CheckDefinition::Custom {
                script,
                expected_exit_code,
            } => {
                assert!(script.contains("exit 0"));
                assert_eq!(expected_exit_code, 0);
            }
            _ => panic!("Expected Custom variant"),
        }
    }

    // =========================================================================
    // ComplianceState with no optional fields
    // =========================================================================

    #[test]
    fn compliance_state_no_optionals() {
        let state = ComplianceState {
            status: ComplianceStatus::Unknown,
            distance: ComplianceDistance {
                target_controls: 0,
                satisfied: 0,
                gap: 0,
                percentage: 0.0,
            },
            frameworks: vec![],
            last_assessed_at: None,
            compliance_hash: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ComplianceState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, ComplianceStatus::Unknown);
        assert!(deserialized.frameworks.is_empty());
        assert!(deserialized.last_assessed_at.is_none());
        assert!(deserialized.compliance_hash.is_none());
    }
}
