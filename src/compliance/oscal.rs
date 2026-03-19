//! OSCAL (Open Security Controls Assessment Language) types.
//!
//! Implements the core OSCAL data model for assessment results, catalogs,
//! and profiles. Used to map compliance test results to standardized
//! security control frameworks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::hash::Blake3Hash;

/// OSCAL Assessment Result document.
///
/// Represents the results of a security assessment against a set of controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssessmentResult {
    /// Unique identifier for this assessment.
    pub uuid: Uuid,
    /// Title of the assessment.
    pub title: String,
    /// Description of what was assessed.
    pub description: String,
    /// When the assessment was performed.
    pub start: DateTime<Utc>,
    /// When the assessment completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<DateTime<Utc>>,
    /// The assessment activities that were performed.
    pub activities: Vec<AssessmentActivity>,
    /// Individual control assessment results.
    pub results: Vec<ControlResult>,
    /// Metadata about the assessment framework and tools.
    pub assessment_metadata: AssessmentMetadata,
}

/// Metadata about the assessment framework, tools, and their hashes.
///
/// **This is critical for the integrity chain.** By including the hashes of
/// the testing tools and frameworks themselves, we ensure that the compliance
/// verification is performed by known-good, attested code.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssessmentMetadata {
    /// Hash of the assessment framework binary/package.
    pub framework_hash: Blake3Hash,
    /// Hash of the control catalog used (e.g., NIST 800-53 catalog).
    pub catalog_hash: Blake3Hash,
    /// Hashes of individual test profiles/packages.
    pub profile_hashes: Vec<ProfileHash>,
    /// Version of the assessment framework.
    pub framework_version: String,
    /// Name of the assessment framework (e.g., "inspec", "kensa").
    pub framework_name: String,
}

/// Hash of a test profile package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileHash {
    /// Name of the profile (e.g., "nix-store", "kubernetes", "network").
    pub name: String,
    /// BLAKE3 hash of the profile directory/package.
    pub hash: Blake3Hash,
    /// Version of the profile.
    pub version: String,
}

/// An assessment activity (a set of related checks).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssessmentActivity {
    /// Unique identifier.
    pub uuid: Uuid,
    /// Title of the activity.
    pub title: String,
    /// Description.
    pub description: String,
    /// Controls assessed by this activity.
    pub related_controls: Vec<String>,
}

/// Result of assessing a single control.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlResult {
    /// Control identifier (e.g., "AC-2", "SC-7").
    pub control_id: String,
    /// Whether the control is satisfied.
    pub status: ControlStatus,
    /// Human-readable explanation.
    pub description: String,
    /// Individual findings.
    pub findings: Vec<Finding>,
    /// When this control was assessed.
    pub assessed_at: DateTime<Utc>,
}

/// Status of a control assessment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlStatus {
    /// Control is fully satisfied.
    Satisfied,
    /// Control is not satisfied.
    NotSatisfied,
    /// Control assessment is incomplete.
    Other,
}

/// An individual finding from an assessment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier.
    pub uuid: Uuid,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Risk level.
    pub risk: RiskLevel,
    /// Remediation guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Risk level of a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlStatus::Satisfied => write!(f, "satisfied"),
            ControlStatus::NotSatisfied => write!(f, "not_satisfied"),
            ControlStatus::Other => write!(f, "other"),
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "critical"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Info => write!(f, "info"),
        }
    }
}

/// OSCAL Catalog — a collection of security controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Catalog {
    /// Unique identifier.
    pub uuid: Uuid,
    /// Title (e.g., "NIST SP 800-53 Rev 5").
    pub title: String,
    /// Version of the catalog.
    pub version: String,
    /// Control groups.
    pub groups: Vec<ControlGroup>,
}

/// A group of related controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlGroup {
    /// Group identifier (e.g., "AC" for Access Control).
    pub id: String,
    /// Title.
    pub title: String,
    /// Controls in this group.
    pub controls: Vec<Control>,
}

/// A single security control definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Control {
    /// Control identifier (e.g., "AC-2").
    pub id: String,
    /// Title.
    pub title: String,
    /// Description of the control.
    pub description: String,
    /// Control enhancements.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub enhancements: Vec<Control>,
}

/// OSCAL Profile — selects controls from a catalog for a specific baseline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Unique identifier.
    pub uuid: Uuid,
    /// Title (e.g., "Moderate Baseline").
    pub title: String,
    /// Catalog reference.
    pub catalog_ref: String,
    /// Selected control IDs.
    pub selected_controls: Vec<String>,
}

impl AssessmentResult {
    /// Compute BLAKE3 hash of the entire assessment result.
    ///
    /// This includes the assessment metadata (framework + catalog + profile hashes)
    /// to ensure the hash covers both WHAT was tested and HOW it was tested.
    pub fn compute_hash(&self) -> Blake3Hash {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        Blake3Hash::digest(&canonical)
    }

    /// Check if all controls are satisfied.
    pub fn all_satisfied(&self) -> bool {
        self.results
            .iter()
            .all(|r| r.status == ControlStatus::Satisfied)
    }

    /// Count controls by status.
    pub fn status_counts(&self) -> (usize, usize, usize) {
        let satisfied = self
            .results
            .iter()
            .filter(|r| r.status == ControlStatus::Satisfied)
            .count();
        let not_satisfied = self
            .results
            .iter()
            .filter(|r| r.status == ControlStatus::NotSatisfied)
            .count();
        let other = self
            .results
            .iter()
            .filter(|r| r.status == ControlStatus::Other)
            .count();
        (satisfied, not_satisfied, other)
    }
}

impl Catalog {
    /// Compute BLAKE3 hash of the catalog.
    pub fn compute_hash(&self) -> Blake3Hash {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        Blake3Hash::digest(&canonical)
    }

    /// Get total number of controls (including enhancements).
    pub fn control_count(&self) -> usize {
        self.groups.iter().map(|g| count_controls(&g.controls)).sum()
    }
}

fn count_controls(controls: &[Control]) -> usize {
    controls
        .iter()
        .map(|c| 1 + count_controls(&c.enhancements))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_assessment() -> AssessmentResult {
        AssessmentResult {
            uuid: Uuid::new_v4(),
            title: "Test Assessment".to_string(),
            description: "Test".to_string(),
            start: Utc::now(),
            end: Some(Utc::now()),
            activities: vec![AssessmentActivity {
                uuid: Uuid::new_v4(),
                title: "Activity 1".to_string(),
                description: "test activity".to_string(),
                related_controls: vec!["AC-2".to_string()],
            }],
            results: vec![
                ControlResult {
                    control_id: "AC-2".to_string(),
                    status: ControlStatus::Satisfied,
                    description: "passed".to_string(),
                    findings: vec![],
                    assessed_at: Utc::now(),
                },
                ControlResult {
                    control_id: "SC-7".to_string(),
                    status: ControlStatus::NotSatisfied,
                    description: "failed".to_string(),
                    findings: vec![Finding {
                        uuid: Uuid::new_v4(),
                        title: "Open port".to_string(),
                        description: "Port 22 exposed".to_string(),
                        risk: RiskLevel::High,
                        remediation: Some("Close port 22".to_string()),
                    }],
                    assessed_at: Utc::now(),
                },
            ],
            assessment_metadata: AssessmentMetadata {
                framework_hash: Blake3Hash::digest(b"framework"),
                catalog_hash: Blake3Hash::digest(b"catalog"),
                profile_hashes: vec![ProfileHash {
                    name: "test-profile".to_string(),
                    hash: Blake3Hash::digest(b"profile"),
                    version: "1.0".to_string(),
                }],
                framework_version: "1.0".to_string(),
                framework_name: "test".to_string(),
            },
        }
    }

    #[test]
    fn control_status_display() {
        assert_eq!(ControlStatus::Satisfied.to_string(), "satisfied");
        assert_eq!(ControlStatus::NotSatisfied.to_string(), "not_satisfied");
        assert_eq!(ControlStatus::Other.to_string(), "other");
    }

    #[test]
    fn risk_level_display() {
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
        assert_eq!(RiskLevel::High.to_string(), "high");
        assert_eq!(RiskLevel::Info.to_string(), "info");
    }

    #[test]
    fn control_status_serde_roundtrip() {
        for status in &[ControlStatus::Satisfied, ControlStatus::NotSatisfied, ControlStatus::Other] {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: ControlStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, deserialized);
        }
    }

    #[test]
    fn assessment_all_satisfied_false_when_failures() {
        let assessment = make_assessment();
        assert!(!assessment.all_satisfied());
    }

    #[test]
    fn assessment_status_counts() {
        let assessment = make_assessment();
        let (satisfied, not_satisfied, other) = assessment.status_counts();
        assert_eq!(satisfied, 1);
        assert_eq!(not_satisfied, 1);
        assert_eq!(other, 0);
    }

    #[test]
    fn assessment_compute_hash_deterministic() {
        let assessment = make_assessment();
        let h1 = assessment.compute_hash();
        let h2 = assessment.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn assessment_serde_roundtrip() {
        let assessment = make_assessment();
        let json = serde_json::to_string(&assessment).unwrap();
        let deserialized: AssessmentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.title, "Test Assessment");
        assert_eq!(deserialized.results.len(), 2);
    }

    #[test]
    fn catalog_serde_roundtrip() {
        let catalog = Catalog {
            uuid: Uuid::new_v4(),
            title: "Test Catalog".to_string(),
            version: "1.0".to_string(),
            groups: vec![ControlGroup {
                id: "AC".to_string(),
                title: "Access Control".to_string(),
                controls: vec![Control {
                    id: "AC-1".to_string(),
                    title: "Policy".to_string(),
                    description: "test".to_string(),
                    enhancements: vec![],
                }],
            }],
        };
        let json = serde_json::to_string(&catalog).unwrap();
        let deserialized: Catalog = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.title, "Test Catalog");
        assert_eq!(deserialized.control_count(), 1);
    }

    #[test]
    fn catalog_count_includes_enhancements() {
        let catalog = Catalog {
            uuid: Uuid::new_v4(),
            title: "Test".to_string(),
            version: "1.0".to_string(),
            groups: vec![ControlGroup {
                id: "AC".to_string(),
                title: "Access Control".to_string(),
                controls: vec![Control {
                    id: "AC-2".to_string(),
                    title: "Account Management".to_string(),
                    description: "".to_string(),
                    enhancements: vec![
                        Control {
                            id: "AC-2(1)".to_string(),
                            title: "Automated System".to_string(),
                            description: "".to_string(),
                            enhancements: vec![],
                        },
                    ],
                }],
            }],
        };
        assert_eq!(catalog.control_count(), 2);
    }

    #[test]
    fn profile_serde_roundtrip() {
        let profile = Profile {
            uuid: Uuid::new_v4(),
            title: "Moderate Baseline".to_string(),
            catalog_ref: "nist-800-53-rev5".to_string(),
            selected_controls: vec!["AC-2".to_string(), "SC-7".to_string()],
        };
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.title, "Moderate Baseline");
        assert_eq!(deserialized.selected_controls.len(), 2);
    }

    #[test]
    fn finding_serde_roundtrip() {
        let finding = Finding {
            uuid: Uuid::new_v4(),
            title: "Test Finding".to_string(),
            description: "Some issue".to_string(),
            risk: RiskLevel::Medium,
            remediation: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.risk, RiskLevel::Medium);
        assert!(deserialized.remediation.is_none());
    }
}
