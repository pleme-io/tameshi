//! InSpec JSON output parser.
//!
//! Parses InSpec's JSON reporter output format and converts results
//! into tameshi compliance types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compliance::oscal::{
    AssessmentActivity, AssessmentMetadata, AssessmentResult, ControlResult, ControlStatus,
    Finding, ProfileHash, RiskLevel,
};
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;

/// InSpec JSON reporter output (top-level).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecOutput {
    pub platform: Option<InSpecPlatform>,
    pub profiles: Vec<InSpecProfile>,
    pub statistics: Option<InSpecStatistics>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecPlatform {
    pub name: Option<String>,
    pub release: Option<String>,
    pub target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecProfile {
    pub name: String,
    pub version: Option<String>,
    pub title: Option<String>,
    pub controls: Vec<InSpecControl>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecControl {
    pub id: String,
    pub title: Option<String>,
    pub desc: Option<String>,
    pub impact: f64,
    pub results: Vec<InSpecResult>,
    #[serde(default)]
    pub tags: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecResult {
    pub status: String,
    pub code_desc: Option<String>,
    pub message: Option<String>,
    pub skip_message: Option<String>,
    pub run_time: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecStatistics {
    pub duration: Option<f64>,
    pub controls: Option<InSpecControlStats>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecControlStats {
    pub total: Option<u32>,
    pub passed: Option<InSpecPassedFailed>,
    pub skipped: Option<InSpecPassedFailed>,
    pub failed: Option<InSpecPassedFailed>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InSpecPassedFailed {
    pub total: Option<u32>,
}

/// Parse InSpec JSON output into a tameshi AssessmentResult.
pub fn parse_inspec_output(
    json_bytes: &[u8],
    framework_hash: Blake3Hash,
    catalog_hash: Blake3Hash,
) -> Result<AssessmentResult> {
    let output: InSpecOutput = serde_json::from_slice(json_bytes).map_err(|e| {
        TameshiError::ComplianceError(format!("failed to parse InSpec output: {}", e))
    })?;

    let version = output
        .version
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let mut activities = Vec::new();
    let mut results = Vec::new();
    let mut profile_hashes = Vec::new();

    for profile in &output.profiles {
        // Hash the profile itself for attestation
        let profile_json = serde_json::to_vec(profile)?;
        let profile_hash = Blake3Hash::digest(&profile_json);
        profile_hashes.push(ProfileHash {
            name: profile.name.clone(),
            hash: profile_hash,
            version: profile
                .version
                .clone()
                .unwrap_or_else(|| "0.0.0".to_string()),
        });

        let activity_uuid = Uuid::new_v4();
        let mut related_controls = Vec::new();

        for control in &profile.controls {
            related_controls.push(control.id.clone());

            let all_passed = control.results.iter().all(|r| r.status == "passed");
            let any_failed = control.results.iter().any(|r| r.status == "failed");

            let status = if all_passed {
                ControlStatus::Satisfied
            } else if any_failed {
                ControlStatus::NotSatisfied
            } else {
                ControlStatus::Other
            };

            let mut findings = Vec::new();
            for result in &control.results {
                if result.status == "failed" {
                    findings.push(Finding {
                        uuid: Uuid::new_v4(),
                        title: result
                            .code_desc
                            .clone()
                            .unwrap_or_else(|| control.id.clone()),
                        description: result
                            .message
                            .clone()
                            .unwrap_or_else(|| "Check failed".to_string()),
                        risk: impact_to_risk(control.impact),
                        remediation: None,
                    });
                }
            }

            results.push(ControlResult {
                control_id: control.id.clone(),
                status,
                description: control
                    .desc
                    .clone()
                    .unwrap_or_else(|| control.title.clone().unwrap_or_default()),
                findings,
                assessed_at: Utc::now(),
            });
        }

        activities.push(AssessmentActivity {
            uuid: activity_uuid,
            title: profile
                .title
                .clone()
                .unwrap_or_else(|| profile.name.clone()),
            description: format!("InSpec profile: {}", profile.name),
            related_controls,
        });
    }

    Ok(AssessmentResult {
        uuid: Uuid::new_v4(),
        title: "InSpec Compliance Assessment".to_string(),
        description: format!(
            "Automated assessment via InSpec {} with {} profiles",
            version,
            output.profiles.len()
        ),
        start: Utc::now(),
        end: Some(Utc::now()),
        activities,
        results,
        assessment_metadata: AssessmentMetadata {
            framework_hash,
            catalog_hash,
            profile_hashes,
            framework_version: version,
            framework_name: "inspec".to_string(),
        },
    })
}

/// Hash an InSpec profile directory for attestation.
///
/// This hashes the profile code itself, ensuring we know exactly which
/// verification logic was used.
pub async fn hash_inspec_profile(profile_dir: &str) -> Result<Blake3Hash> {
    let mut hasher_data = Vec::new();
    let mut entries = tokio::fs::read_dir(profile_dir).await?;
    let mut files = Vec::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.is_file() {
            if let Ok(data) = tokio::fs::read(&path).await {
                files.push((path.to_string_lossy().to_string(), data));
            }
        }
    }

    // Sort for determinism
    files.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, data) in &files {
        hasher_data.extend_from_slice(&Blake3Hash::digest(data).0);
    }

    Ok(Blake3Hash::digest(&hasher_data))
}

fn impact_to_risk(impact: f64) -> RiskLevel {
    if impact >= 0.9 {
        RiskLevel::Critical
    } else if impact >= 0.7 {
        RiskLevel::High
    } else if impact >= 0.4 {
        RiskLevel::Medium
    } else if impact > 0.0 {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_inspec_output() {
        let json = r#"{
            "profiles": [{
                "name": "test-profile",
                "version": "1.0.0",
                "controls": [{
                    "id": "test-1",
                    "title": "Test Control",
                    "impact": 0.7,
                    "results": [{
                        "status": "passed",
                        "code_desc": "check passed"
                    }]
                }]
            }],
            "version": "5.0.0"
        }"#;

        let framework_hash = Blake3Hash::digest(b"inspec-binary");
        let catalog_hash = Blake3Hash::digest(b"nist-catalog");

        let result = parse_inspec_output(json.as_bytes(), framework_hash, catalog_hash).unwrap();
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].status, ControlStatus::Satisfied);
        assert!(result.all_satisfied());
    }

    #[test]
    fn parse_failed_control() {
        let json = r#"{
            "profiles": [{
                "name": "test-profile",
                "controls": [{
                    "id": "test-1",
                    "impact": 0.9,
                    "results": [{
                        "status": "failed",
                        "code_desc": "expected X got Y",
                        "message": "value mismatch"
                    }]
                }]
            }]
        }"#;

        let result = parse_inspec_output(
            json.as_bytes(),
            Blake3Hash::digest(b"f"),
            Blake3Hash::digest(b"c"),
        )
        .unwrap();
        assert_eq!(result.results[0].status, ControlStatus::NotSatisfied);
        assert_eq!(result.results[0].findings.len(), 1);
        assert_eq!(result.results[0].findings[0].risk, RiskLevel::Critical);
    }

    #[test]
    fn parse_skipped_control_yields_other_status() {
        let json = r#"{
            "profiles": [{
                "name": "skip-profile",
                "controls": [{
                    "id": "skip-1",
                    "impact": 0.5,
                    "results": [{
                        "status": "skipped",
                        "skip_message": "not applicable"
                    }]
                }]
            }]
        }"#;

        let result = parse_inspec_output(
            json.as_bytes(),
            Blake3Hash::digest(b"f"),
            Blake3Hash::digest(b"c"),
        )
        .unwrap();
        assert_eq!(result.results[0].status, ControlStatus::Other);
        assert!(result.results[0].findings.is_empty());
    }

    #[test]
    fn parse_multiple_profiles() {
        let json = r#"{
            "profiles": [
                {
                    "name": "profile-a",
                    "controls": [{
                        "id": "a-1",
                        "impact": 0.7,
                        "results": [{"status": "passed"}]
                    }]
                },
                {
                    "name": "profile-b",
                    "controls": [{
                        "id": "b-1",
                        "impact": 0.5,
                        "results": [{"status": "passed"}]
                    }]
                }
            ],
            "version": "6.0.0"
        }"#;

        let result = parse_inspec_output(
            json.as_bytes(),
            Blake3Hash::digest(b"fw"),
            Blake3Hash::digest(b"cat"),
        )
        .unwrap();
        assert_eq!(result.results.len(), 2);
        assert_eq!(result.activities.len(), 2);
        assert!(result.description.contains("2 profiles"));
        assert!(result.description.contains("6.0.0"));
    }

    #[test]
    fn parse_empty_profiles() {
        let json = r#"{"profiles": []}"#;
        let result = parse_inspec_output(
            json.as_bytes(),
            Blake3Hash::digest(b"fw"),
            Blake3Hash::digest(b"cat"),
        )
        .unwrap();
        assert!(result.results.is_empty());
        assert!(result.activities.is_empty());
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let result = parse_inspec_output(
            b"not json",
            Blake3Hash::digest(b"f"),
            Blake3Hash::digest(b"c"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn impact_to_risk_boundaries() {
        assert_eq!(impact_to_risk(1.0), RiskLevel::Critical);
        assert_eq!(impact_to_risk(0.9), RiskLevel::Critical);
        assert_eq!(impact_to_risk(0.89), RiskLevel::High);
        assert_eq!(impact_to_risk(0.7), RiskLevel::High);
        assert_eq!(impact_to_risk(0.69), RiskLevel::Medium);
        assert_eq!(impact_to_risk(0.4), RiskLevel::Medium);
        assert_eq!(impact_to_risk(0.39), RiskLevel::Low);
        assert_eq!(impact_to_risk(0.01), RiskLevel::Low);
        assert_eq!(impact_to_risk(0.0), RiskLevel::Info);
    }

    #[test]
    fn inspec_output_serde_roundtrip() {
        let output = InSpecOutput {
            platform: Some(InSpecPlatform {
                name: Some("linux".to_string()),
                release: Some("6.1".to_string()),
                target: Some("ssh://host".to_string()),
            }),
            profiles: vec![InSpecProfile {
                name: "test".to_string(),
                version: Some("1.0".to_string()),
                title: Some("Test Profile".to_string()),
                controls: vec![InSpecControl {
                    id: "ctrl-1".to_string(),
                    title: Some("Control 1".to_string()),
                    desc: Some("Description".to_string()),
                    impact: 0.7,
                    results: vec![InSpecResult {
                        status: "passed".to_string(),
                        code_desc: Some("check passed".to_string()),
                        message: None,
                        skip_message: None,
                        run_time: Some(0.123),
                    }],
                    tags: serde_json::json!({"nist": ["AC-2"]}),
                }],
                sha256: Some("abc123".to_string()),
            }],
            statistics: Some(InSpecStatistics {
                duration: Some(1.5),
                controls: Some(InSpecControlStats {
                    total: Some(1),
                    passed: Some(InSpecPassedFailed { total: Some(1) }),
                    skipped: None,
                    failed: Some(InSpecPassedFailed { total: Some(0) }),
                }),
            }),
            version: Some("5.0.0".to_string()),
        };

        let json = serde_json::to_string(&output).unwrap();
        let deserialized: InSpecOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profiles[0].name, "test");
        assert_eq!(deserialized.version, Some("5.0.0".to_string()));
        assert_eq!(
            deserialized.platform.as_ref().unwrap().name,
            Some("linux".to_string())
        );
    }

    #[test]
    fn parse_control_without_optional_fields() {
        let json = r#"{
            "profiles": [{
                "name": "minimal",
                "controls": [{
                    "id": "min-1",
                    "impact": 0.0,
                    "results": [{"status": "passed"}]
                }]
            }]
        }"#;

        let result = parse_inspec_output(
            json.as_bytes(),
            Blake3Hash::digest(b"f"),
            Blake3Hash::digest(b"c"),
        )
        .unwrap();
        assert_eq!(result.results[0].control_id, "min-1");
        // desc is None, so description should come from title (also None) -> empty string
        assert!(result.results[0].description.is_empty());
    }

    #[test]
    fn finding_uses_code_desc_as_title_and_message_as_description() {
        let json = r#"{
            "profiles": [{
                "name": "finding-profile",
                "controls": [{
                    "id": "find-1",
                    "impact": 0.7,
                    "results": [{
                        "status": "failed",
                        "code_desc": "File /etc/passwd should exist",
                        "message": "Expected file to exist but it does not"
                    }]
                }]
            }]
        }"#;

        let result = parse_inspec_output(
            json.as_bytes(),
            Blake3Hash::digest(b"f"),
            Blake3Hash::digest(b"c"),
        )
        .unwrap();
        let finding = &result.results[0].findings[0];
        assert_eq!(finding.title, "File /etc/passwd should exist");
        assert_eq!(
            finding.description,
            "Expected file to exist but it does not"
        );
        assert_eq!(finding.risk, RiskLevel::High);
    }

    #[test]
    fn assessment_metadata_preserved() {
        let fw_hash = Blake3Hash::digest(b"inspec-5.0");
        let cat_hash = Blake3Hash::digest(b"nist-catalog-v5");
        let json = r#"{
            "profiles": [{
                "name": "meta-test",
                "version": "2.0.0",
                "controls": [{"id": "m-1", "impact": 0.5, "results": [{"status": "passed"}]}]
            }],
            "version": "5.22.3"
        }"#;

        let result =
            parse_inspec_output(json.as_bytes(), fw_hash.clone(), cat_hash.clone()).unwrap();
        assert_eq!(result.assessment_metadata.framework_hash, fw_hash);
        assert_eq!(result.assessment_metadata.catalog_hash, cat_hash);
        assert_eq!(result.assessment_metadata.framework_version, "5.22.3");
        assert_eq!(result.assessment_metadata.framework_name, "inspec");
        assert_eq!(result.assessment_metadata.profile_hashes.len(), 1);
        assert_eq!(
            result.assessment_metadata.profile_hashes[0].name,
            "meta-test"
        );
        assert_eq!(
            result.assessment_metadata.profile_hashes[0].version,
            "2.0.0"
        );
    }
}
