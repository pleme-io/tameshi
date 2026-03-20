//! Proof heartbeat chain — append-only cryptographic audit trail.
//!
//! Every verification event across the tameshi ecosystem (sekiban admission,
//! kensa compliance, inshou gate, kanshi runtime) is recorded as a
//! [`HeartbeatEntry`] in an append-only chain. Each entry includes the hash
//! of the previous entry, forming a BLAKE3-linked chain that proves:
//!
//! 1. **Continuity** — no entries were deleted or reordered
//! 2. **Integrity** — no entries were modified after creation
//! 3. **Completeness** — the full verification history is preserved
//!
//! This chain is the primary CIRCIA evidence artifact, proving continuous
//! integrity verification over the required 72-hour reporting window.
//!
//! # Architecture
//!
//! ```text
//! Entry₀ ──hash──▶ Entry₁ ──hash──▶ Entry₂ ──hash──▶ Entry₃
//!   │                │                │                │
//!   └─ verifier      └─ verifier      └─ verifier      └─ verifier
//!   └─ event         └─ event         └─ event         └─ event
//!   └─ result        └─ result        └─ result        └─ result
//!   └─ prev: 0..0    └─ prev: H(E₀)  └─ prev: H(E₁)  └─ prev: H(E₂)
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A single entry in the proof heartbeat chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// When this verification occurred.
    pub timestamp: DateTime<Utc>,
    /// Which component performed the verification.
    pub verifier: VerifierIdentity,
    /// What kind of verification event this is.
    pub event: HeartbeatEvent,
    /// The outcome of the verification.
    pub result: VerificationOutcome,
    /// Resource identifier (e.g., "prod/Deployment/app").
    pub resource: String,
    /// The signature that was checked.
    pub signature_checked: Blake3Hash,
    /// BLAKE3 hash of this entry's content (excluding entry_hash itself).
    pub entry_hash: Blake3Hash,
    /// BLAKE3 hash of the previous entry (all zeros for the first entry).
    pub previous_hash: Blake3Hash,
}

/// Identity of the component that performed the verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierIdentity {
    /// Component name: "sekiban", "kensa", "inshou", "kanshi".
    pub component: String,
    /// Instance identifier (pod name, hostname, etc.).
    pub instance: String,
    /// Component version.
    pub version: String,
}

impl VerifierIdentity {
    /// Create a new verifier identity.
    #[must_use]
    pub fn new(component: &str, instance: &str, version: &str) -> Self {
        Self {
            component: component.to_string(),
            instance: instance.to_string(),
            version: version.to_string(),
        }
    }
}

/// Types of verification events that produce heartbeat entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatEvent {
    /// sekiban admission webhook decision.
    AdmissionDecision,
    /// sekiban gate reconciler verification.
    GateVerification,
    /// kensa compliance assessment.
    ComplianceAssessment,
    /// kensa certification pipeline.
    Certification,
    /// inshou pre-rebuild gate check.
    GateCheck,
    /// kanshi binary verification at exec.
    BinaryVerification,
    /// kanshi script verification at open.
    ScriptVerification,
    /// Break-glass bypass activation.
    BreakGlass,
    /// Binary revocation event.
    Revocation,
}

impl std::fmt::Display for HeartbeatEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdmissionDecision => write!(f, "admission_decision"),
            Self::GateVerification => write!(f, "gate_verification"),
            Self::ComplianceAssessment => write!(f, "compliance_assessment"),
            Self::Certification => write!(f, "certification"),
            Self::GateCheck => write!(f, "gate_check"),
            Self::BinaryVerification => write!(f, "binary_verification"),
            Self::ScriptVerification => write!(f, "script_verification"),
            Self::BreakGlass => write!(f, "break_glass"),
            Self::Revocation => write!(f, "revocation"),
        }
    }
}

/// Outcome of a verification event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Verification passed — resource is attested.
    Allowed,
    /// Verification failed — resource was denied.
    Denied,
    /// Verification skipped (e.g., no gate applies).
    Skipped,
    /// Error during verification (transient failure).
    Error,
}

impl std::fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Denied => write!(f, "denied"),
            Self::Skipped => write!(f, "skipped"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Append-only heartbeat chain.
///
/// Maintains an ordered sequence of [`HeartbeatEntry`] values linked by
/// BLAKE3 hashes. Each new entry includes the hash of the previous entry,
/// making the chain tamper-evident.
pub struct HeartbeatChain {
    entries: Vec<HeartbeatEntry>,
    next_sequence: u64,
    last_hash: Blake3Hash,
}

impl HeartbeatChain {
    /// Create a new empty heartbeat chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(1024),
            next_sequence: 0,
            last_hash: Blake3Hash::from([0u8; 32]),
        }
    }

    /// Append a new entry to the chain.
    ///
    /// The entry's `sequence`, `entry_hash`, and `previous_hash` are
    /// computed automatically. The caller provides the verification context.
    pub fn append(
        &mut self,
        verifier: VerifierIdentity,
        event: HeartbeatEvent,
        result: VerificationOutcome,
        resource: &str,
        signature_checked: Blake3Hash,
    ) -> &HeartbeatEntry {
        let sequence = self.next_sequence;
        let timestamp = Utc::now();
        let previous_hash = self.last_hash.clone();

        let entry_hash = compute_entry_hash(
            sequence,
            &timestamp,
            &verifier,
            &event,
            &result,
            resource,
            &signature_checked,
            &previous_hash,
        );

        let entry = HeartbeatEntry {
            sequence,
            timestamp,
            verifier,
            event,
            result,
            resource: resource.to_string(),
            signature_checked,
            entry_hash: entry_hash.clone(),
            previous_hash,
        };

        self.last_hash = entry_hash;
        self.next_sequence += 1;
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Returns `true` if every entry's hash matches its content and every
    /// `previous_hash` points to the correct predecessor.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let mut expected_prev = Blake3Hash::from([0u8; 32]);

        for entry in &self.entries {
            // Check previous hash linkage
            if entry.previous_hash != expected_prev {
                return false;
            }

            // Recompute entry hash
            let recomputed = compute_entry_hash(
                entry.sequence,
                &entry.timestamp,
                &entry.verifier,
                &entry.event,
                &entry.result,
                &entry.resource,
                &entry.signature_checked,
                &entry.previous_hash,
            );

            if entry.entry_hash != recomputed {
                return false;
            }

            expected_prev = entry.entry_hash.clone();
        }

        true
    }

    /// Get the number of entries in the chain.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the chain is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the last entry in the chain.
    #[inline]
    #[must_use]
    pub fn last(&self) -> Option<&HeartbeatEntry> {
        self.entries.last()
    }

    /// Get all entries in the chain.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> &[HeartbeatEntry] {
        &self.entries
    }

    /// Get the current chain head hash.
    #[inline]
    #[must_use]
    pub fn head_hash(&self) -> &Blake3Hash {
        &self.last_hash
    }
}

impl Default for HeartbeatChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the BLAKE3 hash of a heartbeat entry's content.
fn compute_entry_hash(
    sequence: u64,
    timestamp: &DateTime<Utc>,
    verifier: &VerifierIdentity,
    event: &HeartbeatEvent,
    result: &VerificationOutcome,
    resource: &str,
    signature_checked: &Blake3Hash,
    previous_hash: &Blake3Hash,
) -> Blake3Hash {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&sequence.to_le_bytes());
    data.extend_from_slice(timestamp.to_rfc3339().as_bytes());
    data.push(0);
    data.extend_from_slice(verifier.component.as_bytes());
    data.push(0);
    data.extend_from_slice(verifier.instance.as_bytes());
    data.push(0);
    data.extend_from_slice(verifier.version.as_bytes());
    data.push(0);
    data.extend_from_slice(event.to_string().as_bytes());
    data.push(0);
    data.extend_from_slice(result.to_string().as_bytes());
    data.push(0);
    data.extend_from_slice(resource.as_bytes());
    data.push(0);
    data.extend_from_slice(&signature_checked.0);
    data.extend_from_slice(&previous_hash.0);
    Blake3Hash::digest(&data)
}

// =============================================================================
// Heartbeat Emitter Trait
// =============================================================================

/// Trait for emitting heartbeat entries to external systems.
///
/// Implementations can send entries to stdout, files, HTTP endpoints,
/// or object storage for CIRCIA evidence collection.
pub trait HeartbeatEmitter: Send + Sync {
    /// Emit a heartbeat entry.
    fn emit(
        &self,
        entry: &HeartbeatEntry,
    ) -> impl std::future::Future<Output = crate::error::Result<()>> + Send;
}

/// No-op emitter — discards all entries. Default until configured.
pub struct NoopEmitter;

impl HeartbeatEmitter for NoopEmitter {
    async fn emit(&self, _entry: &HeartbeatEntry) -> crate::error::Result<()> {
        Ok(())
    }
}

/// Stdout emitter — writes entries as JSON lines to stdout.
pub struct StdoutEmitter;

impl HeartbeatEmitter for StdoutEmitter {
    async fn emit(&self, entry: &HeartbeatEntry) -> crate::error::Result<()> {
        let json = serde_json::to_string(entry)?;
        println!("{json}");
        Ok(())
    }
}

/// File emitter — appends entries as JSON lines to a file.
pub struct FileEmitter {
    path: std::path::PathBuf,
}

impl FileEmitter {
    /// Create a file emitter that writes to the given path.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl HeartbeatEmitter for FileEmitter {
    async fn emit(&self, entry: &HeartbeatEntry) -> crate::error::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut json = serde_json::to_vec(entry)?;
        json.push(b'\n');

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(&json).await?;
        Ok(())
    }
}

/// HTTP emitter — POSTs entries as JSON to a remote endpoint.
pub struct HttpEmitter {
    endpoint: String,
    client: reqwest::Client,
}

impl HttpEmitter {
    /// Create an HTTP emitter that POSTs to the given endpoint.
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

impl HeartbeatEmitter for HttpEmitter {
    async fn emit(&self, entry: &HeartbeatEntry) -> crate::error::Result<()> {
        self.client
            .post(&self.endpoint)
            .json(entry)
            .send()
            .await?;
        Ok(())
    }
}

/// Heartbeat configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Whether heartbeat emission is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Emitter type: "noop", "stdout", "file", "http".
    #[serde(default = "default_emitter_type")]
    pub emitter: String,
    /// File emitter configuration.
    #[serde(default)]
    pub file: FileEmitterConfig,
    /// HTTP emitter configuration.
    #[serde(default)]
    pub http: HttpEmitterConfig,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            emitter: default_emitter_type(),
            file: FileEmitterConfig::default(),
            http: HttpEmitterConfig::default(),
        }
    }
}

fn default_emitter_type() -> String {
    "noop".to_string()
}

/// File emitter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEmitterConfig {
    /// Path to the heartbeat log file.
    #[serde(default = "default_file_path")]
    pub path: String,
    /// Maximum file size in MB before rotation.
    #[serde(default = "default_max_size")]
    pub max_size_mb: u64,
}

impl Default for FileEmitterConfig {
    fn default() -> Self {
        Self {
            path: default_file_path(),
            max_size_mb: default_max_size(),
        }
    }
}

fn default_file_path() -> String {
    "/var/log/tameshi/heartbeat.jsonl".to_string()
}

fn default_max_size() -> u64 {
    100
}

/// HTTP emitter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpEmitterConfig {
    /// HTTP endpoint to POST entries to.
    #[serde(default)]
    pub endpoint: String,
    /// Batch size for HTTP emitter.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Flush interval in milliseconds.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: u64,
}

impl Default for HttpEmitterConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            batch_size: default_batch_size(),
            flush_interval_ms: default_flush_interval(),
        }
    }
}

fn default_batch_size() -> usize {
    100
}

fn default_flush_interval() -> u64 {
    5000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_verifier() -> VerifierIdentity {
        VerifierIdentity::new("sekiban", "sekiban-pod-abc", "0.1.0")
    }

    fn test_signature() -> Blake3Hash {
        Blake3Hash::digest(b"test-signature")
    }

    // =========================================================================
    // HeartbeatChain tests
    // =========================================================================

    #[test]
    fn chain_starts_empty() {
        let chain = HeartbeatChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.last().is_none());
    }

    #[test]
    fn chain_append_increments_sequence() {
        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "default/Deployment/app",
            test_signature(),
        );
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateVerification,
            VerificationOutcome::Allowed,
            "default/Deployment/app",
            test_signature(),
        );

        assert_eq!(chain.len(), 2);
        assert_eq!(chain.entries()[0].sequence, 0);
        assert_eq!(chain.entries()[1].sequence, 1);
    }

    #[test]
    fn chain_links_previous_hashes() {
        let mut chain = HeartbeatChain::new();

        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "ns/Deploy/a",
            test_signature(),
        );
        let first_hash = chain.entries()[0].entry_hash.clone();

        chain.append(
            test_verifier(),
            HeartbeatEvent::GateVerification,
            VerificationOutcome::Denied,
            "ns/Deploy/b",
            test_signature(),
        );

        // Second entry's previous_hash should be first entry's entry_hash
        assert_eq!(chain.entries()[1].previous_hash, first_hash);
    }

    #[test]
    fn chain_first_entry_has_zero_previous() {
        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "system",
            test_signature(),
        );
        assert_eq!(chain.entries()[0].previous_hash, Blake3Hash::from([0u8; 32]));
    }

    #[test]
    fn chain_verify_integrity_empty() {
        let chain = HeartbeatChain::new();
        assert!(chain.verify_integrity());
    }

    #[test]
    fn chain_verify_integrity_valid() {
        let mut chain = HeartbeatChain::new();
        for i in 0..10 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::AdmissionDecision,
                VerificationOutcome::Allowed,
                &format!("resource-{i}"),
                test_signature(),
            );
        }
        assert!(chain.verify_integrity());
    }

    #[test]
    fn chain_detect_tampered_entry() {
        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "ns/Deploy/app",
            test_signature(),
        );
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateVerification,
            VerificationOutcome::Allowed,
            "ns/Deploy/app",
            test_signature(),
        );

        // Tamper with the first entry
        chain.entries[0].resource = "ns/Deploy/EVIL".to_string();

        assert!(!chain.verify_integrity(), "Tampered chain should fail verification");
    }

    #[test]
    fn chain_detect_broken_link() {
        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "a",
            test_signature(),
        );
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateVerification,
            VerificationOutcome::Allowed,
            "b",
            test_signature(),
        );

        // Break the link
        chain.entries[1].previous_hash = Blake3Hash::digest(b"wrong");

        assert!(!chain.verify_integrity(), "Broken link should fail verification");
    }

    #[test]
    fn chain_head_hash_updates() {
        let mut chain = HeartbeatChain::new();
        let initial = chain.head_hash().clone();

        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "x",
            test_signature(),
        );

        assert_ne!(chain.head_hash(), &initial);
    }

    #[test]
    fn chain_deterministic_hashing() {
        // Same inputs at the same timestamp should produce the same hash
        let verifier = test_verifier();
        let sig = test_signature();
        let ts = Utc::now();
        let prev = Blake3Hash::from([0u8; 32]);

        let h1 = compute_entry_hash(
            0, &ts, &verifier, &HeartbeatEvent::GateCheck,
            &VerificationOutcome::Allowed, "res", &sig, &prev,
        );
        let h2 = compute_entry_hash(
            0, &ts, &verifier, &HeartbeatEvent::GateCheck,
            &VerificationOutcome::Allowed, "res", &sig, &prev,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_different_events_different_hashes() {
        let verifier = test_verifier();
        let sig = test_signature();
        let ts = Utc::now();
        let prev = Blake3Hash::from([0u8; 32]);

        let h1 = compute_entry_hash(
            0, &ts, &verifier, &HeartbeatEvent::GateCheck,
            &VerificationOutcome::Allowed, "res", &sig, &prev,
        );
        let h2 = compute_entry_hash(
            0, &ts, &verifier, &HeartbeatEvent::AdmissionDecision,
            &VerificationOutcome::Allowed, "res", &sig, &prev,
        );
        assert_ne!(h1, h2);
    }

    // =========================================================================
    // Serde roundtrip tests
    // =========================================================================

    #[test]
    fn heartbeat_entry_serde_roundtrip() {
        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::ComplianceAssessment,
            VerificationOutcome::Allowed,
            "kensa/assessment/nist",
            test_signature(),
        );

        let entry = chain.last().unwrap();
        let json = serde_json::to_string(entry).unwrap();
        let deserialized: HeartbeatEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, &deserialized);
    }

    #[test]
    fn verifier_identity_serde_roundtrip() {
        let vi = test_verifier();
        let json = serde_json::to_string(&vi).unwrap();
        let deserialized: VerifierIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(vi, deserialized);
    }

    #[test]
    fn heartbeat_event_serde_roundtrip() {
        let events = vec![
            HeartbeatEvent::AdmissionDecision,
            HeartbeatEvent::GateVerification,
            HeartbeatEvent::ComplianceAssessment,
            HeartbeatEvent::Certification,
            HeartbeatEvent::GateCheck,
            HeartbeatEvent::BinaryVerification,
            HeartbeatEvent::ScriptVerification,
            HeartbeatEvent::BreakGlass,
            HeartbeatEvent::Revocation,
        ];
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let deserialized: HeartbeatEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, &deserialized);
        }
    }

    #[test]
    fn verification_outcome_serde_roundtrip() {
        let outcomes = vec![
            VerificationOutcome::Allowed,
            VerificationOutcome::Denied,
            VerificationOutcome::Skipped,
            VerificationOutcome::Error,
        ];
        for outcome in &outcomes {
            let json = serde_json::to_string(outcome).unwrap();
            let deserialized: VerificationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, &deserialized);
        }
    }

    // =========================================================================
    // Display tests
    // =========================================================================

    #[test]
    fn heartbeat_event_display() {
        assert_eq!(HeartbeatEvent::AdmissionDecision.to_string(), "admission_decision");
        assert_eq!(HeartbeatEvent::BreakGlass.to_string(), "break_glass");
        assert_eq!(HeartbeatEvent::Revocation.to_string(), "revocation");
    }

    #[test]
    fn verification_outcome_display() {
        assert_eq!(VerificationOutcome::Allowed.to_string(), "allowed");
        assert_eq!(VerificationOutcome::Denied.to_string(), "denied");
        assert_eq!(VerificationOutcome::Skipped.to_string(), "skipped");
        assert_eq!(VerificationOutcome::Error.to_string(), "error");
    }

    // =========================================================================
    // Emitter tests
    // =========================================================================

    #[tokio::test]
    async fn noop_emitter_succeeds() {
        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "test",
            test_signature(),
        );
        let emitter = NoopEmitter;
        let result = emitter.emit(chain.last().unwrap()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn file_emitter_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat.jsonl");
        let emitter = FileEmitter::new(&path);

        let mut chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "ns/Deploy/app",
            test_signature(),
        );

        emitter.emit(chain.last().unwrap()).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(!content.is_empty());
        // Should be valid JSON
        let _: HeartbeatEntry = serde_json::from_str(content.trim()).unwrap();
    }

    #[tokio::test]
    async fn file_emitter_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat.jsonl");
        let emitter = FileEmitter::new(&path);

        let mut chain = HeartbeatChain::new();
        for i in 0..3 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::GateVerification,
                VerificationOutcome::Allowed,
                &format!("resource-{i}"),
                test_signature(),
            );
            emitter.emit(chain.last().unwrap()).await.unwrap();
        }

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3, "Should have 3 JSONL lines");
    }

    // =========================================================================
    // Config tests
    // =========================================================================

    #[test]
    fn heartbeat_config_defaults() {
        let config = HeartbeatConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.emitter, "noop");
        assert_eq!(config.file.path, "/var/log/tameshi/heartbeat.jsonl");
        assert_eq!(config.file.max_size_mb, 100);
    }

    #[test]
    fn heartbeat_config_serde_roundtrip() {
        let config = HeartbeatConfig {
            enabled: true,
            emitter: "file".to_string(),
            file: FileEmitterConfig {
                path: "/tmp/test.jsonl".to_string(),
                max_size_mb: 50,
            },
            http: HttpEmitterConfig::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HeartbeatConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.enabled);
        assert_eq!(deserialized.emitter, "file");
        assert_eq!(deserialized.file.path, "/tmp/test.jsonl");
    }

    // =========================================================================
    // Large chain tests
    // =========================================================================

    #[test]
    fn chain_1000_entries_integrity() {
        let mut chain = HeartbeatChain::new();
        for i in 0..1000 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::AdmissionDecision,
                if i % 2 == 0 {
                    VerificationOutcome::Allowed
                } else {
                    VerificationOutcome::Denied
                },
                &format!("resource-{i}"),
                Blake3Hash::digest(format!("sig-{i}").as_bytes()),
            );
        }
        assert_eq!(chain.len(), 1000);
        assert!(chain.verify_integrity());
    }

    #[test]
    fn chain_default_is_new() {
        let chain = HeartbeatChain::default();
        assert!(chain.is_empty());
        assert!(chain.verify_integrity());
    }

    // =========================================================================
    // Monotonic sequence test
    // =========================================================================

    #[test]
    fn chain_monotonic_sequence() {
        let mut chain = HeartbeatChain::new();
        for _ in 0..50 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                "test",
                test_signature(),
            );
        }
        for window in chain.entries().windows(2) {
            assert!(window[1].sequence > window[0].sequence);
        }
    }

    // =========================================================================
    // Monotonic timestamps test
    // =========================================================================

    #[test]
    fn chain_monotonic_timestamps() {
        let mut chain = HeartbeatChain::new();
        for _ in 0..10 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                "test",
                test_signature(),
            );
        }
        for window in chain.entries().windows(2) {
            assert!(window[1].timestamp >= window[0].timestamp);
        }
    }
}
