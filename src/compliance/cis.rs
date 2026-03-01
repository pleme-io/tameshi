//! CIS (Center for Internet Security) Benchmark integration.
//!
//! CIS Benchmarks provide hardening guidelines for operating systems, cloud
//! platforms, containers, and Kubernetes. Each benchmark is versioned and
//! contains scored/not-scored recommendations organized by topic.
//!
//! ## Supported Benchmarks
//!
//! | Benchmark | Version | Tool | NIST Mapping |
//! |-----------|---------|------|-------------|
//! | CIS Kubernetes Benchmark | 1.9 | kube-bench | CM, AC, SC, AU |
//! | CIS Docker Benchmark | 1.6 | docker-bench-security | CM, SC, AC |
//! | CIS Linux (Debian/Ubuntu) | 2.0 | Lynis, InSpec | CM, AC, SC, AU, IA |
//! | CIS macOS | 4.0 | InSpec | CM, AC, SC |
//! | CIS Helm | N/A | kube-linter, Conftest | CM, SC |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A CIS benchmark assessment result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CisBenchmarkResult {
    /// Which benchmark was assessed.
    pub benchmark: CisBenchmark,
    /// Benchmark version.
    pub version: String,
    /// Tool used for assessment.
    pub tool: String,
    /// Hash of the assessment tool binary.
    pub tool_hash: Blake3Hash,
    /// Hash of the benchmark definition.
    pub benchmark_hash: Blake3Hash,
    /// Individual check results.
    pub checks: Vec<CisCheck>,
    /// Summary.
    pub summary: CisSummary,
    /// When assessed.
    pub assessed_at: DateTime<Utc>,
    /// Target that was assessed.
    pub target: String,
}

/// CIS benchmark identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CisBenchmark {
    KubernetesBenchmark,
    DockerBenchmark,
    LinuxBenchmark,
    MacosBenchmark,
    HelmBenchmark,
    NginxBenchmark,
    PostgresBenchmark,
}

impl std::fmt::Display for CisBenchmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CisBenchmark::KubernetesBenchmark => write!(f, "CIS Kubernetes Benchmark"),
            CisBenchmark::DockerBenchmark => write!(f, "CIS Docker Benchmark"),
            CisBenchmark::LinuxBenchmark => write!(f, "CIS Linux Benchmark"),
            CisBenchmark::MacosBenchmark => write!(f, "CIS macOS Benchmark"),
            CisBenchmark::HelmBenchmark => write!(f, "CIS Helm Best Practices"),
            CisBenchmark::NginxBenchmark => write!(f, "CIS Nginx Benchmark"),
            CisBenchmark::PostgresBenchmark => write!(f, "CIS PostgreSQL Benchmark"),
        }
    }
}

/// A single CIS benchmark check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CisCheck {
    /// Check ID (e.g., "1.1.1", "4.2.3").
    pub id: String,
    /// Check title.
    pub title: String,
    /// Section (e.g., "1.1 Control Plane Components").
    pub section: String,
    /// Whether the check passed.
    pub status: CisCheckStatus,
    /// Whether this is a scored recommendation.
    pub scored: bool,
    /// CIS level (1 = basic, 2 = defense-in-depth).
    pub level: u8,
    /// NIST 800-53 controls this maps to.
    pub nist_controls: Vec<String>,
    /// Remediation guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// CIS check status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CisCheckStatus {
    Pass,
    Fail,
    Warn,
    Info,
    NotApplicable,
}

/// CIS benchmark summary.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CisSummary {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub info: usize,
    pub scored_pass: usize,
    pub scored_fail: usize,
    pub pass_rate: f64,
    pub scored_pass_rate: f64,
}

impl CisSummary {
    pub fn from_checks(checks: &[CisCheck]) -> Self {
        let mut summary = CisSummary::default();
        summary.total = checks.len();
        for c in checks {
            match c.status {
                CisCheckStatus::Pass => {
                    summary.pass += 1;
                    if c.scored { summary.scored_pass += 1; }
                }
                CisCheckStatus::Fail => {
                    summary.fail += 1;
                    if c.scored { summary.scored_fail += 1; }
                }
                CisCheckStatus::Warn => summary.warn += 1,
                CisCheckStatus::Info => summary.info += 1,
                CisCheckStatus::NotApplicable => {}
            }
        }
        if summary.total > 0 {
            summary.pass_rate = summary.pass as f64 / summary.total as f64;
        }
        let scored_total = summary.scored_pass + summary.scored_fail;
        if scored_total > 0 {
            summary.scored_pass_rate = summary.scored_pass as f64 / scored_total as f64;
        }
        summary
    }
}

/// CIS Kubernetes Benchmark sections with NIST mappings.
pub fn kubernetes_benchmark_nist_mappings() -> Vec<CisBenchmarkMapping> {
    vec![
        CisBenchmarkMapping {
            section: "1".to_string(),
            title: "Control Plane Components".to_string(),
            nist_controls: vec!["CM-2".into(), "CM-6".into(), "CM-7".into(), "SC-7".into(), "AC-3".into()],
        },
        CisBenchmarkMapping {
            section: "2".to_string(),
            title: "etcd".to_string(),
            nist_controls: vec!["SC-8".into(), "SC-28".into(), "AC-3".into(), "AU-2".into()],
        },
        CisBenchmarkMapping {
            section: "3".to_string(),
            title: "Control Plane Configuration".to_string(),
            nist_controls: vec!["AC-2".into(), "AC-3".into(), "AC-6".into(), "IA-2".into(), "IA-5".into()],
        },
        CisBenchmarkMapping {
            section: "4".to_string(),
            title: "Worker Nodes".to_string(),
            nist_controls: vec!["CM-2".into(), "CM-6".into(), "SC-7".into(), "AC-3".into()],
        },
        CisBenchmarkMapping {
            section: "5".to_string(),
            title: "Policies".to_string(),
            nist_controls: vec!["AC-3".into(), "AC-6".into(), "CM-7".into(), "SC-7".into(), "SC-8".into()],
        },
    ]
}

/// Mapping from CIS benchmark section to NIST controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CisBenchmarkMapping {
    pub section: String,
    pub title: String,
    pub nist_controls: Vec<String>,
}

/// Compute CIS benchmark hash for the compliance chain.
pub fn compute_cis_hash(result: &CisBenchmarkResult) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&result.tool_hash.0);
    data.extend_from_slice(&result.benchmark_hash.0);

    let checks_canonical = serde_json::to_vec(&result.checks).unwrap_or_default();
    let checks_hash = Blake3Hash::digest(&checks_canonical);
    data.extend_from_slice(&checks_hash.0);

    Blake3Hash::digest(&data)
}

/// CIS benchmark policy — minimum pass rates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CisPolicy {
    /// Minimum scored pass rate (0.0 - 1.0).
    pub min_scored_pass_rate: f64,
    /// Maximum number of scored failures allowed.
    pub max_scored_failures: usize,
    /// Required CIS level (1 or 2).
    pub required_level: u8,
}

impl Default for CisPolicy {
    fn default() -> Self {
        Self {
            min_scored_pass_rate: 0.90,
            max_scored_failures: 5,
            required_level: 1,
        }
    }
}

/// Evaluate a CIS benchmark result against policy.
pub fn evaluate_cis_policy(result: &CisBenchmarkResult, policy: &CisPolicy) -> bool {
    result.summary.scored_pass_rate >= policy.min_scored_pass_rate
        && result.summary.scored_fail <= policy.max_scored_failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_check(id: &str, status: CisCheckStatus, scored: bool) -> CisCheck {
        CisCheck {
            id: id.to_string(),
            title: format!("Check {}", id),
            section: "1.1".to_string(),
            status,
            scored,
            level: 1,
            nist_controls: vec!["CM-2".to_string()],
            remediation: None,
        }
    }

    #[test]
    fn summary_counts() {
        let checks = vec![
            make_check("1.1.1", CisCheckStatus::Pass, true),
            make_check("1.1.2", CisCheckStatus::Pass, true),
            make_check("1.1.3", CisCheckStatus::Fail, true),
            make_check("1.1.4", CisCheckStatus::Warn, false),
        ];
        let summary = CisSummary::from_checks(&checks);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.pass, 2);
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.scored_pass, 2);
        assert_eq!(summary.scored_fail, 1);
    }

    #[test]
    fn cis_hash_deterministic() {
        let result = CisBenchmarkResult {
            benchmark: CisBenchmark::KubernetesBenchmark,
            version: "1.9".to_string(),
            tool: "kube-bench".to_string(),
            tool_hash: Blake3Hash::digest(b"kube-bench-binary"),
            benchmark_hash: Blake3Hash::digest(b"cis-k8s-1.9"),
            checks: vec![make_check("1.1.1", CisCheckStatus::Pass, true)],
            summary: CisSummary::default(),
            assessed_at: Utc::now(),
            target: "plo-cluster".to_string(),
        };
        let h1 = compute_cis_hash(&result);
        let h2 = compute_cis_hash(&result);
        assert_eq!(h1, h2);
    }

    #[test]
    fn policy_evaluation() {
        let checks = vec![
            make_check("1", CisCheckStatus::Pass, true),
            make_check("2", CisCheckStatus::Pass, true),
            make_check("3", CisCheckStatus::Fail, true),
        ];
        let result = CisBenchmarkResult {
            benchmark: CisBenchmark::KubernetesBenchmark,
            version: "1.9".to_string(),
            tool: "kube-bench".to_string(),
            tool_hash: Blake3Hash::digest(b"kb"),
            benchmark_hash: Blake3Hash::digest(b"cis"),
            summary: CisSummary::from_checks(&checks),
            checks,
            assessed_at: Utc::now(),
            target: "test".to_string(),
        };

        // 66% scored pass rate < 90% required
        let strict = CisPolicy::default();
        assert!(!evaluate_cis_policy(&result, &strict));

        // Relaxed policy
        let relaxed = CisPolicy {
            min_scored_pass_rate: 0.5,
            max_scored_failures: 5,
            required_level: 1,
        };
        assert!(evaluate_cis_policy(&result, &relaxed));
    }
}
