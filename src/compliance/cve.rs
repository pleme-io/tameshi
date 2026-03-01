//! CVE/NVD/OSV vulnerability scanning integration.
//!
//! Integrates vulnerability scanning results from tools like Trivy, Grype, and
//! vulnix into the compliance hash chain. Every artifact (OCI image, Nix closure,
//! Helm chart) must be scanned for known vulnerabilities. The scan results —
//! including the vulnerability database version — are hashed into the compliance
//! chain.
//!
//! ## Supported Scanners
//!
//! | Scanner | nixpkgs attr | Target | Database |
//! |---------|-------------|--------|----------|
//! | Trivy | `trivy` | OCI, K8s, IaC, SBOM | NVD, GitHub Advisory, Red Hat |
//! | Grype | `grype` | OCI, SBOM | NVD, GitHub Advisory |
//! | vulnix | `vulnix` | Nix closures | NVD |
//! | OSV-Scanner | `osv-scanner` | Source, SBOM | OSV.dev |
//!
//! ## Hash Chain
//!
//! ```text
//! vuln_hash = BLAKE3(
//!   scanner_binary_hash  || // Attests which scanner was used
//!   db_version_hash      || // Attests which vulnerability DB version
//!   scan_target_hash     || // What was scanned
//!   results_hash            // The actual findings
//! )
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A vulnerability scanning result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnerabilityScan {
    /// Scanner used (trivy, grype, vulnix, osv-scanner).
    pub scanner: VulnerabilityScanner,
    /// Hash of the scanner binary (Nix store path).
    pub scanner_hash: Blake3Hash,
    /// Vulnerability database version/timestamp.
    pub db_version: String,
    /// Hash of the vulnerability database snapshot.
    pub db_hash: Blake3Hash,
    /// What was scanned.
    pub target: ScanTarget,
    /// Hash of the scan target artifact.
    pub target_hash: Blake3Hash,
    /// Vulnerabilities found.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Summary statistics.
    pub summary: VulnSummary,
    /// When the scan was performed.
    pub scanned_at: DateTime<Utc>,
}

/// Supported vulnerability scanners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilityScanner {
    Trivy,
    Grype,
    Vulnix,
    OsvScanner,
}

impl VulnerabilityScanner {
    /// Get the nixpkgs attribute for this scanner.
    pub fn nix_attr(&self) -> &str {
        match self {
            VulnerabilityScanner::Trivy => "trivy",
            VulnerabilityScanner::Grype => "grype",
            VulnerabilityScanner::Vulnix => "vulnix",
            VulnerabilityScanner::OsvScanner => "osv-scanner",
        }
    }
}

impl std::fmt::Display for VulnerabilityScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityScanner::Trivy => write!(f, "trivy"),
            VulnerabilityScanner::Grype => write!(f, "grype"),
            VulnerabilityScanner::Vulnix => write!(f, "vulnix"),
            VulnerabilityScanner::OsvScanner => write!(f, "osv-scanner"),
        }
    }
}

/// What was scanned.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Target type.
    pub target_type: ScanTargetType,
    /// Target identifier (image ref, store path, file path).
    pub identifier: String,
}

/// Types of scan targets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTargetType {
    OciImage,
    NixClosure,
    HelmChart,
    Filesystem,
    Sbom,
    GitRepository,
}

/// A single vulnerability finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE identifier (e.g., "CVE-2024-1234").
    pub cve_id: String,
    /// Severity level.
    pub severity: VulnSeverity,
    /// CVSS v3 score (0.0 - 10.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// Affected package.
    pub package: String,
    /// Installed version.
    pub installed_version: String,
    /// Fixed version (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    /// Short description.
    pub title: String,
    /// Data source (NVD, GitHub Advisory, OSV, etc.).
    pub source: VulnSource,
    /// Whether this CVE has been acknowledged/accepted.
    #[serde(default)]
    pub acknowledged: bool,
}

/// Vulnerability severity levels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VulnSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// Vulnerability data sources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnSource {
    Nvd,
    GithubAdvisory,
    Osv,
    RedHat,
    Debian,
    Alpine,
    Other(String),
}

/// Summary statistics for a vulnerability scan.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VulnSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub fixable: usize,
    pub acknowledged: usize,
}

impl VulnSummary {
    /// Build summary from a list of vulnerabilities.
    pub fn from_vulns(vulns: &[Vulnerability]) -> Self {
        let mut summary = VulnSummary::default();
        summary.total = vulns.len();
        for v in vulns {
            match v.severity {
                VulnSeverity::Critical => summary.critical += 1,
                VulnSeverity::High => summary.high += 1,
                VulnSeverity::Medium => summary.medium += 1,
                VulnSeverity::Low => summary.low += 1,
                VulnSeverity::Unknown => summary.unknown += 1,
            }
            if v.fixed_version.is_some() {
                summary.fixable += 1;
            }
            if v.acknowledged {
                summary.acknowledged += 1;
            }
        }
        summary
    }

    /// Whether the scan passes a given severity threshold.
    pub fn passes_threshold(&self, max_severity: &VulnSeverity) -> bool {
        match max_severity {
            VulnSeverity::Critical => self.critical == 0,
            VulnSeverity::High => self.critical == 0 && self.high == 0,
            VulnSeverity::Medium => {
                self.critical == 0 && self.high == 0 && self.medium == 0
            }
            VulnSeverity::Low => {
                self.critical == 0
                    && self.high == 0
                    && self.medium == 0
                    && self.low == 0
            }
            VulnSeverity::Unknown => self.total == 0,
        }
    }
}

/// Vulnerability scanning policy — what must pass before gating.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnPolicy {
    /// Maximum allowed severity (vulnerabilities above this block).
    pub max_severity: VulnSeverity,
    /// Maximum age of the scan in seconds before it's stale.
    pub max_scan_age_secs: u64,
    /// Required scanners (at least one must have run).
    pub required_scanners: Vec<VulnerabilityScanner>,
    /// Whether acknowledged CVEs are exempt from blocking.
    #[serde(default)]
    pub allow_acknowledged: bool,
}

impl Default for VulnPolicy {
    fn default() -> Self {
        Self {
            max_severity: VulnSeverity::High,
            max_scan_age_secs: 86400, // 24 hours
            required_scanners: vec![VulnerabilityScanner::Trivy],
            allow_acknowledged: true,
        }
    }
}

/// Compute the vulnerability scan hash for inclusion in the compliance chain.
///
/// ```text
/// vuln_hash = BLAKE3(scanner_hash || db_hash || target_hash || results_hash)
/// ```
pub fn compute_vuln_hash(scan: &VulnerabilityScan) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&scan.scanner_hash.0);
    data.extend_from_slice(&scan.db_hash.0);
    data.extend_from_slice(&scan.target_hash.0);

    // Hash the results deterministically
    let results_canonical = serde_json::to_vec(&scan.vulnerabilities).unwrap_or_default();
    let results_hash = Blake3Hash::digest(&results_canonical);
    data.extend_from_slice(&results_hash.0);

    Blake3Hash::digest(&data)
}

/// Combine multiple vulnerability scan hashes (e.g., Trivy + Grype + vulnix).
pub fn combine_vuln_hashes(scans: &[VulnerabilityScan]) -> Blake3Hash {
    let mut hashes: Vec<Blake3Hash> = scans.iter().map(|s| compute_vuln_hash(s)).collect();
    hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));

    let mut data = Vec::new();
    for h in &hashes {
        data.extend_from_slice(&h.0);
    }
    Blake3Hash::digest(&data)
}

/// Check if a vulnerability scan passes the given policy.
pub fn evaluate_vuln_policy(scan: &VulnerabilityScan, policy: &VulnPolicy) -> VulnPolicyResult {
    let mut reasons = Vec::new();

    // Check scan age
    let age = Utc::now()
        .signed_duration_since(scan.scanned_at)
        .num_seconds();
    if age > policy.max_scan_age_secs as i64 {
        reasons.push(format!(
            "Scan is stale: {}s old (max {}s)",
            age, policy.max_scan_age_secs
        ));
    }

    // Filter out acknowledged if policy allows
    let effective_vulns: Vec<&Vulnerability> = if policy.allow_acknowledged {
        scan.vulnerabilities.iter().filter(|v| !v.acknowledged).collect()
    } else {
        scan.vulnerabilities.iter().collect()
    };

    // Check severity threshold
    for v in &effective_vulns {
        if v.severity > policy.max_severity {
            reasons.push(format!(
                "{} ({:?}): {} in {} {}",
                v.cve_id, v.severity, v.title, v.package, v.installed_version
            ));
        }
    }

    VulnPolicyResult {
        passed: reasons.is_empty(),
        violations: reasons,
        scan_hash: compute_vuln_hash(scan),
    }
}

/// Result of evaluating a vulnerability policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnPolicyResult {
    /// Whether the scan passed the policy.
    pub passed: bool,
    /// Reasons for failure (empty if passed).
    pub violations: Vec<String>,
    /// Hash of the scan.
    pub scan_hash: Blake3Hash,
}

/// NIST 800-53 controls satisfied by vulnerability scanning.
pub fn vuln_nist_controls() -> Vec<&'static str> {
    vec![
        "RA-5",  // Vulnerability Monitoring and Scanning
        "SI-2",  // Flaw Remediation
        "SI-3",  // Malicious Code Protection
        "SI-5",  // Security Alerts, Advisories, and Directives
        "SI-7",  // Software, Firmware, and Information Integrity
        "SR-3",  // Supply Chain Controls and Processes
        "SR-4",  // Provenance
        "SR-11", // Component Authenticity
        "CM-8",  // System Component Inventory
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scan(vulns: Vec<Vulnerability>) -> VulnerabilityScan {
        let summary = VulnSummary::from_vulns(&vulns);
        VulnerabilityScan {
            scanner: VulnerabilityScanner::Trivy,
            scanner_hash: Blake3Hash::digest(b"trivy-binary"),
            db_version: "2026-02-28".to_string(),
            db_hash: Blake3Hash::digest(b"nvd-db-snapshot"),
            target: ScanTarget {
                target_type: ScanTargetType::OciImage,
                identifier: "ghcr.io/example-org/myapp:latest".to_string(),
            },
            target_hash: Blake3Hash::digest(b"image-manifest"),
            vulnerabilities: vulns,
            summary,
            scanned_at: Utc::now(),
        }
    }

    fn make_vuln(cve: &str, severity: VulnSeverity) -> Vulnerability {
        Vulnerability {
            cve_id: cve.to_string(),
            severity,
            cvss_score: Some(7.5),
            package: "openssl".to_string(),
            installed_version: "1.1.1".to_string(),
            fixed_version: Some("1.1.1k".to_string()),
            title: "Test vulnerability".to_string(),
            source: VulnSource::Nvd,
            acknowledged: false,
        }
    }

    #[test]
    fn vuln_hash_deterministic() {
        let scan = make_scan(vec![make_vuln("CVE-2024-0001", VulnSeverity::High)]);
        let h1 = compute_vuln_hash(&scan);
        let h2 = compute_vuln_hash(&scan);
        assert_eq!(h1, h2);
    }

    #[test]
    fn vuln_hash_changes_with_findings() {
        let scan1 = make_scan(vec![make_vuln("CVE-2024-0001", VulnSeverity::High)]);
        let scan2 = make_scan(vec![
            make_vuln("CVE-2024-0001", VulnSeverity::High),
            make_vuln("CVE-2024-0002", VulnSeverity::Critical),
        ]);
        assert_ne!(compute_vuln_hash(&scan1), compute_vuln_hash(&scan2));
    }

    #[test]
    fn policy_passes_no_vulns() {
        let scan = make_scan(vec![]);
        let policy = VulnPolicy::default();
        let result = evaluate_vuln_policy(&scan, &policy);
        assert!(result.passed);
    }

    #[test]
    fn policy_fails_critical_vuln() {
        let scan = make_scan(vec![make_vuln("CVE-2024-9999", VulnSeverity::Critical)]);
        let policy = VulnPolicy::default(); // max_severity: High
        let result = evaluate_vuln_policy(&scan, &policy);
        assert!(!result.passed);
    }

    #[test]
    fn policy_allows_acknowledged() {
        let mut vuln = make_vuln("CVE-2024-9999", VulnSeverity::Critical);
        vuln.acknowledged = true;
        let scan = make_scan(vec![vuln]);
        let policy = VulnPolicy {
            allow_acknowledged: true,
            ..Default::default()
        };
        let result = evaluate_vuln_policy(&scan, &policy);
        assert!(result.passed);
    }

    #[test]
    fn summary_counts() {
        let vulns = vec![
            make_vuln("CVE-1", VulnSeverity::Critical),
            make_vuln("CVE-2", VulnSeverity::High),
            make_vuln("CVE-3", VulnSeverity::Medium),
        ];
        let summary = VulnSummary::from_vulns(&vulns);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.fixable, 3); // all have fixed_version
    }
}
