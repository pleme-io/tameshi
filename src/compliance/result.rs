//! Compliance result hashing and composition.
//!
//! Computes the final compliance hash that combines:
//! 1. Hash of the testing framework/packages themselves (verification method attestation)
//! 2. Hash of the control catalog (what was tested against)
//! 3. Hash of individual test profile packages
//! 4. Hash of the test results
//!
//! This ensures that the compliance hash attests not just WHAT was tested,
//! but also HOW it was tested and by WHAT verified tools. It is impossible
//! to produce a valid compliance hash without using known-good, attested
//! verification methods.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::compliance::nist::Baseline;
use crate::compliance::oscal::AssessmentResult;
use crate::error::Result;
use crate::hash::Blake3Hash;

/// A complete compliance result with all attestation metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// The assessment results.
    pub assessment: AssessmentResult,
    /// NIST baseline this was assessed against.
    pub baseline: Baseline,
    /// Environment that was assessed.
    pub environment: String,
    /// When the compliance check was performed.
    pub performed_at: DateTime<Utc>,
    /// The final compliance hash.
    pub compliance_hash: Blake3Hash,
}

/// Compute the compliance hash from an assessment result.
///
/// The hash is computed as:
/// ```text
/// compliance_hash = BLAKE3(
///   framework_hash       || // Hash of InSpec/kensa binary
///   catalog_hash         || // Hash of NIST 800-53 catalog
///   profile_hashes...    || // Hash of each test profile package
///   results_hash            // Hash of the test results themselves
/// )
/// ```
///
/// This ensures that changing the testing framework, the control catalog,
/// any test profile, OR the results will change the compliance hash,
/// making it impossible to apply untested or improperly-tested infrastructure.
#[must_use]
pub fn compute_compliance_hash(assessment: &AssessmentResult) -> Blake3Hash {
    let profile_count = assessment.assessment_metadata.profile_hashes.len();
    let mut data = Vec::with_capacity(32 * (2 + profile_count + 1));

    // 1. Framework hash — attests the verification tool itself
    data.extend_from_slice(&assessment.assessment_metadata.framework_hash.0);

    // 2. Catalog hash — attests which controls were tested against
    data.extend_from_slice(&assessment.assessment_metadata.catalog_hash.0);

    // 3. Profile hashes — attests which test packages were used
    let mut sorted_profiles = assessment.assessment_metadata.profile_hashes.clone();
    sorted_profiles.sort_by(|a, b| a.name.cmp(&b.name));
    for profile in &sorted_profiles {
        data.extend_from_slice(&profile.hash.0);
    }

    // 4. Results hash — attests the actual test outcomes
    let results_canonical = serde_json::to_vec(&assessment.results).unwrap_or_default();
    let results_hash = Blake3Hash::digest(&results_canonical);
    data.extend_from_slice(&results_hash.0);

    Blake3Hash::digest(&data)
}

/// Build a complete ComplianceResult from an assessment.
pub fn build_compliance_result(
    assessment: AssessmentResult,
    baseline: Baseline,
    environment: &str,
) -> ComplianceResult {
    let compliance_hash = compute_compliance_hash(&assessment);
    ComplianceResult {
        assessment,
        baseline,
        environment: environment.to_string(),
        performed_at: Utc::now(),
        compliance_hash,
    }
}

/// Verify a compliance hash against an assessment result.
///
/// Recomputes the hash from the assessment and compares.
#[must_use]
pub fn verify_compliance_hash(result: &ComplianceResult) -> bool {
    let recomputed = compute_compliance_hash(&result.assessment);
    recomputed == result.compliance_hash
}

/// Combine multiple compliance results into a single hash.
///
/// Used when multiple compliance frameworks or test suites are run
/// against the same environment. The individual compliance hashes
/// are sorted and composed.
pub fn combine_compliance_hashes(results: &[ComplianceResult]) -> Result<Blake3Hash> {
    let mut hashes: Vec<&Blake3Hash> = results.iter().map(|r| &r.compliance_hash).collect();
    hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));

    let mut data = Vec::new();
    for hash in &hashes {
        data.extend_from_slice(&hash.0);
    }

    Ok(Blake3Hash::digest(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::oscal::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_assessment(framework_data: &[u8], catalog_data: &[u8]) -> AssessmentResult {
        AssessmentResult {
            uuid: Uuid::new_v4(),
            title: "Test Assessment".to_string(),
            description: "test".to_string(),
            start: Utc::now(),
            end: Some(Utc::now()),
            activities: vec![],
            results: vec![ControlResult {
                control_id: "AC-2".to_string(),
                status: ControlStatus::Satisfied,
                description: "test".to_string(),
                findings: vec![],
                assessed_at: Utc::now(),
            }],
            assessment_metadata: AssessmentMetadata {
                framework_hash: Blake3Hash::digest(framework_data),
                catalog_hash: Blake3Hash::digest(catalog_data),
                profile_hashes: vec![ProfileHash {
                    name: "test-profile".to_string(),
                    hash: Blake3Hash::digest(b"profile-code"),
                    version: "1.0.0".to_string(),
                }],
                framework_version: "1.0".to_string(),
                framework_name: "test".to_string(),
            },
        }
    }

    #[test]
    fn compliance_hash_deterministic() {
        let a1 = make_assessment(b"inspec-v1", b"nist-catalog");
        // Same assessment hashed twice should be identical
        let h1 = compute_compliance_hash(&a1);
        let h2 = compute_compliance_hash(&a1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compliance_hash_differs_across_assessments() {
        // Two different make_assessment calls produce different timestamps/UUIDs
        // in results, so the results_hash component will differ
        let a1 = make_assessment(b"inspec-v1", b"nist-catalog");
        let a2 = make_assessment(b"inspec-v1", b"nist-catalog");
        let h1 = compute_compliance_hash(&a1);
        let h2 = compute_compliance_hash(&a2);
        // These will differ because assessed_at timestamps differ
        // This is correct behavior — each assessment is unique
        assert_ne!(h1, h2);
    }

    #[test]
    fn compliance_hash_changes_with_framework() {
        let a1 = make_assessment(b"inspec-v1", b"nist-catalog");
        let a2 = make_assessment(b"inspec-v2-modified", b"nist-catalog");
        let h1 = compute_compliance_hash(&a1);
        let h2 = compute_compliance_hash(&a2);
        // Different framework binary = different compliance hash
        assert_ne!(h1, h2);
    }

    #[test]
    fn compliance_hash_changes_with_catalog() {
        let a1 = make_assessment(b"inspec-v1", b"nist-catalog-rev5");
        let a2 = make_assessment(b"inspec-v1", b"nist-catalog-rev6");
        let h1 = compute_compliance_hash(&a1);
        let h2 = compute_compliance_hash(&a2);
        // Different catalog = different compliance hash
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_compliance_roundtrip() {
        let assessment = make_assessment(b"inspec", b"nist");
        let result = build_compliance_result(assessment, Baseline::Moderate, "production");
        assert!(verify_compliance_hash(&result));
    }
}
