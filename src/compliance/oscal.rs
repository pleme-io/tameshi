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
