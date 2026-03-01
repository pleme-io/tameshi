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
    let output: InSpecOutput =
        serde_json::from_slice(json_bytes).map_err(|e| TameshiError::ComplianceError(
            format!("failed to parse InSpec output: {}", e),
        ))?;

    let version = output.version.clone().unwrap_or_else(|| "unknown".to_string());

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
            version: profile.version.clone().unwrap_or_else(|| "0.0.0".to_string()),
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
}
