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
use object_store::ObjectStoreExt as _;
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A single entry in the proof heartbeat chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// IaC test infrastructure initialization completed.
    IacTestInit,
    /// IaC test infrastructure applied.
    IacTestApply,
    /// IaC test verification (InSpec) completed.
    IacTestVerify,
    /// IaC test infrastructure teardown completed.
    IacTestTeardown,
    /// Complete IaC test suite finished.
    IacTestSuiteComplete,
    /// AI Threat Intelligence analysis completed.
    AiThreatAnalysis,
    /// Fragment collection request initiated.
    FragmentCollectionRequest,
    /// Fragment collection completed (threshold met or failed).
    FragmentCollectionComplete,
    /// Attestation expired and was revoked.
    AttestationExpired,
    /// Compliance re-verification triggered.
    ComplianceRecheck,
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
            Self::IacTestInit => write!(f, "iac_test_init"),
            Self::IacTestApply => write!(f, "iac_test_apply"),
            Self::IacTestVerify => write!(f, "iac_test_verify"),
            Self::IacTestTeardown => write!(f, "iac_test_teardown"),
            Self::IacTestSuiteComplete => write!(f, "iac_test_suite_complete"),
            Self::AiThreatAnalysis => write!(f, "ai_threat_analysis"),
            Self::FragmentCollectionRequest => write!(f, "fragment_collection_request"),
            Self::FragmentCollectionComplete => write!(f, "fragment_collection_complete"),
            Self::AttestationExpired => write!(f, "attestation_expired"),
            Self::ComplianceRecheck => write!(f, "compliance_recheck"),
        }
    }
}

/// Outcome of a verification event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
///
/// # Thread Safety
///
/// `HeartbeatChain` is thread-safe. Internal state is protected by a
/// `RwLock`, allowing concurrent reads and exclusive writes. All public
/// methods acquire the lock automatically.
pub struct HeartbeatChain {
    inner: std::sync::RwLock<HeartbeatChainInner>,
}

struct HeartbeatChainInner {
    entries: Vec<HeartbeatEntry>,
    next_sequence: u64,
    last_hash: Blake3Hash,
}

impl HeartbeatChain {
    /// Create a new empty heartbeat chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(HeartbeatChainInner {
                entries: Vec::with_capacity(1024),
                next_sequence: 0,
                last_hash: Blake3Hash::from([0u8; 32]),
            }),
        }
    }

    /// Append a new entry to the chain.
    ///
    /// The entry's `sequence`, `entry_hash`, and `previous_hash` are
    /// computed automatically. The caller provides the verification context.
    /// Uses the system clock for timestamping. For deterministic testing,
    /// use [`append_with_clock`](Self::append_with_clock) instead.
    pub fn append(
        &self,
        verifier: VerifierIdentity,
        event: HeartbeatEvent,
        result: VerificationOutcome,
        resource: &str,
        signature_checked: Blake3Hash,
    ) -> HeartbeatEntry {
        self.append_with_clock(
            verifier,
            event,
            result,
            resource,
            signature_checked,
            &crate::traits::SystemClock,
        )
    }

    /// Append a new entry to the chain with an explicit clock (for deterministic testing).
    ///
    /// The entry's `sequence`, `entry_hash`, and `previous_hash` are
    /// computed automatically. The caller provides the verification context
    /// and a [`Clock`](crate::traits::Clock) implementation to control
    /// timestamping.
    pub fn append_with_clock(
        &self,
        verifier: VerifierIdentity,
        event: HeartbeatEvent,
        result: VerificationOutcome,
        resource: &str,
        signature_checked: Blake3Hash,
        clock: &impl crate::traits::Clock,
    ) -> HeartbeatEntry {
        let mut inner = self.inner.write().expect("HeartbeatChain lock poisoned");
        let sequence = inner.next_sequence;
        let timestamp = clock.now();
        let previous_hash = inner.last_hash.clone();

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

        inner.last_hash = entry_hash;
        inner.next_sequence += 1;
        inner.entries.push(entry.clone());
        entry
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Returns `true` if every entry's hash matches its content and every
    /// `previous_hash` points to the correct predecessor.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        let mut expected_prev = Blake3Hash::from([0u8; 32]);

        for entry in &inner.entries {
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
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.entries.len()
    }

    /// Check if the chain is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.entries.is_empty()
    }

    /// Get the last entry in the chain.
    #[inline]
    #[must_use]
    pub fn last(&self) -> Option<HeartbeatEntry> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.entries.last().cloned()
    }

    /// Get all entries in the chain.
    #[inline]
    #[must_use]
    pub fn entries(&self) -> Vec<HeartbeatEntry> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.entries.clone()
    }

    /// Get the current chain head hash.
    #[inline]
    #[must_use]
    pub fn head_hash(&self) -> Blake3Hash {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.last_hash.clone()
    }

    /// Export the entire chain as JSON for CIRCIA evidence.
    #[must_use]
    pub fn export_json(&self) -> crate::error::Result<String> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        serde_json::to_string_pretty(&inner.entries).map_err(|e| e.into())
    }

    /// Export the chain as compact JSONL (one entry per line).
    #[must_use]
    pub fn export_jsonl(&self) -> crate::error::Result<String> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        let mut output = String::new();
        for entry in &inner.entries {
            let line = serde_json::to_string(entry)?;
            output.push_str(&line);
            output.push('\n');
        }
        Ok(output)
    }

    /// Get entries within a time range.
    #[must_use]
    pub fn entries_in_range(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<HeartbeatEntry> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.entries.iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .cloned()
            .collect()
    }

    /// Get entries by event type.
    #[must_use]
    pub fn entries_by_event(&self, event: &HeartbeatEvent) -> Vec<HeartbeatEntry> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        inner.entries.iter()
            .filter(|e| &e.event == event)
            .cloned()
            .collect()
    }

    /// Get the number of allowed vs denied outcomes.
    #[must_use]
    pub fn outcome_counts(&self) -> (usize, usize) {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");
        let allowed = inner.entries.iter().filter(|e| e.result == VerificationOutcome::Allowed).count();
        let denied = inner.entries.iter().filter(|e| e.result == VerificationOutcome::Denied).count();
        (allowed, denied)
    }
}

/// A CT-style consistency proof between two chain states.
///
/// Proves that the chain from `from_seq` to `to_seq` is append-only:
/// no entries were deleted, reordered, or modified. The `proof_nodes`
/// contain the entry hashes at each sequence in the range, and
/// verification recomputes the chain linkage.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsistencyProof {
    /// Starting sequence number (inclusive).
    pub from_seq: u64,
    /// Ending sequence number (inclusive).
    pub to_seq: u64,
    /// Entry hash at `from_seq`.
    pub from_hash: Blake3Hash,
    /// Entry hash at `to_seq`.
    pub to_hash: Blake3Hash,
    /// Entry hashes for each sequence from `from_seq` through `to_seq`.
    pub proof_nodes: Vec<Blake3Hash>,
    /// Whether the proof has been verified server-side.
    #[serde(default)]
    pub verified: bool,
}

impl HeartbeatChain {
    /// Generate a consistency proof that the chain from `from_seq` to `to_seq`
    /// is append-only (no entries were deleted or modified).
    ///
    /// # Errors
    ///
    /// Returns an error if `from_seq > to_seq` or if either sequence number
    /// is beyond the current chain length.
    pub fn consistency_proof(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> crate::error::Result<ConsistencyProof> {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");

        if from_seq > to_seq {
            return Err(crate::error::TameshiError::InvalidInput(format!(
                "from_seq ({from_seq}) must be <= to_seq ({to_seq})"
            )));
        }

        let len = inner.entries.len() as u64;
        if to_seq >= len {
            return Err(crate::error::TameshiError::InvalidInput(format!(
                "to_seq ({to_seq}) is beyond chain length ({len})"
            )));
        }

        let from_idx = from_seq as usize;
        let to_idx = to_seq as usize;

        let proof_nodes: Vec<Blake3Hash> = inner.entries[from_idx..=to_idx]
            .iter()
            .map(|e| e.entry_hash.clone())
            .collect();

        let from_hash = inner.entries[from_idx].entry_hash.clone();
        let to_hash = inner.entries[to_idx].entry_hash.clone();

        Ok(ConsistencyProof {
            from_seq,
            to_seq,
            from_hash,
            to_hash,
            proof_nodes,
            verified: false,
        })
    }

    /// Verify a consistency proof.
    ///
    /// Recomputes the chain linkage from the proof nodes and verifies
    /// that each entry's hash matches its content and links correctly
    /// to the previous entry.
    #[must_use]
    pub fn verify_consistency_proof(&self, proof: &ConsistencyProof) -> bool {
        let inner = self.inner.read().expect("HeartbeatChain lock poisoned");

        if proof.from_seq > proof.to_seq {
            return false;
        }

        let len = inner.entries.len() as u64;
        if proof.to_seq >= len {
            return false;
        }

        let expected_count = (proof.to_seq - proof.from_seq + 1) as usize;
        if proof.proof_nodes.len() != expected_count {
            return false;
        }

        let from_idx = proof.from_seq as usize;
        let to_idx = proof.to_seq as usize;

        // Verify that proof_nodes match the actual entry hashes
        for (i, entry) in inner.entries[from_idx..=to_idx].iter().enumerate() {
            if entry.entry_hash != proof.proof_nodes[i] {
                return false;
            }
        }

        // Verify the chain linkage within the range
        for window in inner.entries[from_idx..=to_idx].windows(2) {
            // Recompute the second entry's hash and check linkage
            let recomputed = compute_entry_hash(
                window[1].sequence,
                &window[1].timestamp,
                &window[1].verifier,
                &window[1].event,
                &window[1].result,
                &window[1].resource,
                &window[1].signature_checked,
                &window[1].previous_hash,
            );
            if recomputed != window[1].entry_hash {
                return false;
            }
            if window[1].previous_hash != window[0].entry_hash {
                return false;
            }
        }

        // Verify the from/to hashes match
        if proof.from_hash != inner.entries[from_idx].entry_hash {
            return false;
        }
        if proof.to_hash != inner.entries[to_idx].entry_hash {
            return false;
        }

        true
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

// =============================================================================
// S3 Log Forwarding
// =============================================================================

/// Configuration for S3-compatible log forwarding.
///
/// **Security:** The `Debug` impl redacts `secret_access_key` to prevent
/// accidental credential leakage in logs or error messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct S3EmitterConfig {
    /// S3-compatible endpoint URL (e.g., `"https://s3.amazonaws.com"`).
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// Key prefix for heartbeat logs (e.g., `"tameshi/heartbeats/"`).
    pub key_prefix: String,
    /// AWS access key ID.
    pub access_key_id: String,
    /// AWS secret access key.
    pub secret_access_key: String,
    /// AWS region.
    pub region: String,
    /// Optional session token for IAM role assumption (IRSA, STS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3EmitterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3EmitterConfig")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("key_prefix", &self.key_prefix)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("region", &self.region)
            .field("session_token", &self.session_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Emits heartbeat chain entries to S3-compatible storage via the
/// [`object_store`] crate, which handles AWS Signature V4 (including
/// session tokens for IRSA/STS) automatically.
pub struct S3Emitter {
    store: Box<dyn object_store::ObjectStore>,
    config: S3EmitterConfig,
}

impl S3Emitter {
    /// Create a new S3 emitter backed by a real `AmazonS3` client.
    ///
    /// # Errors
    ///
    /// Returns an error if the `object_store` S3 builder fails (e.g.,
    /// missing or invalid configuration values).
    pub fn new(config: S3EmitterConfig) -> crate::error::Result<Self> {
        use object_store::aws::AmazonS3Builder;

        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_access_key_id(&config.access_key_id)
            .with_secret_access_key(&config.secret_access_key);

        if !config.endpoint.is_empty() {
            builder = builder
                .with_endpoint(&config.endpoint)
                .with_virtual_hosted_style_request(false); // path-style for MinIO/custom
        }

        if let Some(token) = &config.session_token {
            builder = builder.with_token(token);
        }

        let store = builder.build().map_err(|e| {
            crate::error::TameshiError::CollectorError {
                layer: "s3".to_string(),
                message: format!("failed to build S3 client: {e}"),
            }
        })?;

        Ok(Self {
            store: Box::new(store),
            config,
        })
    }

    /// Create an `S3Emitter` with a custom [`ObjectStore`] backend (for testing).
    #[must_use]
    pub fn with_store(store: Box<dyn object_store::ObjectStore>, config: S3EmitterConfig) -> Self {
        Self { store, config }
    }

    /// Upload the full chain as a JSON file.
    ///
    /// Serializes the chain's entries as pretty-printed JSON and PUTs to
    /// `{key_prefix}chain-{timestamp}.json`.
    /// Returns the S3 object key on success.
    pub async fn upload_chain(
        &self,
        chain: &HeartbeatChain,
    ) -> crate::error::Result<String> {
        let now = Utc::now();
        let key = self.chain_key(&now);
        let body = chain.export_json()?;
        let path = object_store::path::Path::from(key.as_str());

        self.store
            .put(&path, object_store::PutPayload::from(body.into_bytes()))
            .await
            .map_err(|e| crate::error::TameshiError::CollectorError {
                layer: "s3".to_string(),
                message: format!("S3 PUT failed: {e}"),
            })?;

        Ok(key)
    }

    /// Upload a single entry as JSONL.
    ///
    /// Serializes the entry as a single JSON line and PUTs to
    /// `{key_prefix}entries/{sequence:08}.jsonl`.
    /// Returns the S3 object key on success.
    pub async fn upload_entry(
        &self,
        entry: &HeartbeatEntry,
    ) -> crate::error::Result<String> {
        let key = self.entry_key(entry);
        let mut body = serde_json::to_vec(entry)?;
        body.push(b'\n');
        let path = object_store::path::Path::from(key.as_str());

        self.store
            .put(&path, object_store::PutPayload::from_bytes(body.into()))
            .await
            .map_err(|e| crate::error::TameshiError::CollectorError {
                layer: "s3".to_string(),
                message: format!("S3 PUT failed: {e}"),
            })?;

        Ok(key)
    }

    /// Generate the S3 object key for a chain export.
    #[must_use]
    pub fn chain_key(&self, timestamp: &DateTime<Utc>) -> String {
        format!(
            "{}chain-{}.json",
            self.config.key_prefix,
            timestamp.format("%Y%m%dT%H%M%SZ")
        )
    }

    /// Generate the S3 object key for a single entry.
    #[must_use]
    pub fn entry_key(&self, entry: &HeartbeatEntry) -> String {
        format!(
            "{}entries/{:08}.jsonl",
            self.config.key_prefix, entry.sequence
        )
    }
}

impl HeartbeatEmitter for S3Emitter {
    async fn emit(&self, entry: &HeartbeatEntry) -> crate::error::Result<()> {
        self.upload_entry(entry).await?;
        Ok(())
    }
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
        let chain = HeartbeatChain::new();
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
        let chain = HeartbeatChain::new();

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
        let chain = HeartbeatChain::new();
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
        let chain = HeartbeatChain::new();
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
        let chain = HeartbeatChain::new();
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
        chain.inner.write().expect("lock").entries[0].resource = "ns/Deploy/EVIL".to_string();

        assert!(!chain.verify_integrity(), "Tampered chain should fail verification");
    }

    #[test]
    fn chain_detect_broken_link() {
        let chain = HeartbeatChain::new();
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
        chain.inner.write().expect("lock").entries[1].previous_hash = Blake3Hash::digest(b"wrong");

        assert!(!chain.verify_integrity(), "Broken link should fail verification");
    }

    #[test]
    fn chain_head_hash_updates() {
        let chain = HeartbeatChain::new();
        let initial = chain.head_hash();

        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "x",
            test_signature(),
        );

        assert_ne!(chain.head_hash(), initial);
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
        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::ComplianceAssessment,
            VerificationOutcome::Allowed,
            "kensa/assessment/nist",
            test_signature(),
        );

        let entry = chain.last().unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: HeartbeatEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
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
            HeartbeatEvent::IacTestInit,
            HeartbeatEvent::IacTestApply,
            HeartbeatEvent::IacTestVerify,
            HeartbeatEvent::IacTestTeardown,
            HeartbeatEvent::IacTestSuiteComplete,
            HeartbeatEvent::AiThreatAnalysis,
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
        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "test",
            test_signature(),
        );
        let emitter = NoopEmitter;
        let entry = chain.last().unwrap();
        let result = emitter.emit(&entry).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn file_emitter_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat.jsonl");
        let emitter = FileEmitter::new(&path);

        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "ns/Deploy/app",
            test_signature(),
        );

        let entry = chain.last().unwrap();
        emitter.emit(&entry).await.unwrap();

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

        let chain = HeartbeatChain::new();
        for i in 0..3 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::GateVerification,
                VerificationOutcome::Allowed,
                &format!("resource-{i}"),
                test_signature(),
            );
            let entry = chain.last().unwrap();
            emitter.emit(&entry).await.unwrap();
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
        let chain = HeartbeatChain::new();
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
        let chain = HeartbeatChain::new();
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
        let chain = HeartbeatChain::new();
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

    // =========================================================================
    // Export and query method tests
    // =========================================================================

    #[test]
    fn export_json_valid() {
        let chain = HeartbeatChain::new();
        for i in 0..3 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::AdmissionDecision,
                VerificationOutcome::Allowed,
                &format!("resource-{i}"),
                test_signature(),
            );
        }
        let json = chain.export_json().unwrap();
        let parsed: Vec<HeartbeatEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].resource, "resource-0");
        assert_eq!(parsed[2].resource, "resource-2");
    }

    #[test]
    fn export_jsonl_line_count() {
        let chain = HeartbeatChain::new();
        for i in 0..5 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                &format!("res-{i}"),
                test_signature(),
            );
        }
        let jsonl = chain.export_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 5, "JSONL line count should match entry count");
        // Each line should be valid JSON
        for line in &lines {
            let _: HeartbeatEntry = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn entries_in_range_filters() {
        let chain = HeartbeatChain::new();
        // Append a few entries -- timestamps are set to Utc::now() in append()
        let before = Utc::now();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "early",
            test_signature(),
        );
        let mid = Utc::now();
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Denied,
            "late",
            test_signature(),
        );
        let after = Utc::now();

        // Full range should return all
        let all = chain.entries_in_range(before, after);
        assert_eq!(all.len(), 2);

        // Range before any entries
        let none = chain.entries_in_range(
            before - chrono::Duration::hours(2),
            before - chrono::Duration::hours(1),
        );
        assert_eq!(none.len(), 0);

        // Range that includes only entries from mid onward
        let late_entries = chain.entries_in_range(mid, after);
        assert!(late_entries.iter().all(|e| e.resource == "late"));
    }

    #[test]
    fn entries_by_event_filters() {
        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "a",
            test_signature(),
        );
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "b",
            test_signature(),
        );
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Denied,
            "c",
            test_signature(),
        );
        chain.append(
            test_verifier(),
            HeartbeatEvent::Certification,
            VerificationOutcome::Allowed,
            "d",
            test_signature(),
        );

        let admission = chain.entries_by_event(&HeartbeatEvent::AdmissionDecision);
        assert_eq!(admission.len(), 2);
        assert_eq!(admission[0].resource, "a");
        assert_eq!(admission[1].resource, "c");

        let gate = chain.entries_by_event(&HeartbeatEvent::GateCheck);
        assert_eq!(gate.len(), 1);
        assert_eq!(gate[0].resource, "b");

        let cert = chain.entries_by_event(&HeartbeatEvent::Certification);
        assert_eq!(cert.len(), 1);

        let revocation = chain.entries_by_event(&HeartbeatEvent::Revocation);
        assert_eq!(revocation.len(), 0);
    }

    #[test]
    fn outcome_counts_correct() {
        let chain = HeartbeatChain::new();
        // 3 allowed
        for _ in 0..3 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::AdmissionDecision,
                VerificationOutcome::Allowed,
                "ok",
                test_signature(),
            );
        }
        // 2 denied
        for _ in 0..2 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::AdmissionDecision,
                VerificationOutcome::Denied,
                "bad",
                test_signature(),
            );
        }
        // 1 skipped (should not count as allowed or denied)
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Skipped,
            "skip",
            test_signature(),
        );

        let (allowed, denied) = chain.outcome_counts();
        assert_eq!(allowed, 3);
        assert_eq!(denied, 2);
    }

    // =========================================================================
    // ConsistencyProof tests
    // =========================================================================

    fn build_chain(n: usize) -> HeartbeatChain {
        let chain = HeartbeatChain::new();
        for i in 0..n {
            chain.append(
                test_verifier(),
                HeartbeatEvent::AdmissionDecision,
                VerificationOutcome::Allowed,
                &format!("resource-{i}"),
                Blake3Hash::digest(format!("sig-{i}").as_bytes()),
            );
        }
        chain
    }

    #[test]
    fn consistency_proof_valid() {
        let chain = build_chain(10);
        let proof = chain.consistency_proof(2, 7).unwrap();
        assert_eq!(proof.from_seq, 2);
        assert_eq!(proof.to_seq, 7);
        assert_eq!(proof.proof_nodes.len(), 6);
        assert!(chain.verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_full_chain() {
        let chain = build_chain(5);
        let proof = chain.consistency_proof(0, 4).unwrap();
        assert_eq!(proof.proof_nodes.len(), 5);
        assert!(chain.verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_detects_tamper() {
        let chain = build_chain(10);
        let proof = chain.consistency_proof(2, 7).unwrap();

        // Tamper with an entry in the proof range
        chain.inner.write().expect("lock").entries[4].resource = "TAMPERED".to_string();

        assert!(
            !chain.verify_consistency_proof(&proof),
            "Tampered chain should fail consistency proof verification"
        );
    }

    #[test]
    fn consistency_proof_detects_hash_tamper() {
        let chain = build_chain(10);
        let proof = chain.consistency_proof(2, 7).unwrap();

        // Tamper with an entry hash directly
        chain.inner.write().expect("lock").entries[5].entry_hash = Blake3Hash::digest(b"forged-hash");

        assert!(
            !chain.verify_consistency_proof(&proof),
            "Forged entry hash should fail consistency proof verification"
        );
    }

    #[test]
    fn consistency_proof_empty_range() {
        let chain = build_chain(5);
        let proof = chain.consistency_proof(3, 3).unwrap();
        assert_eq!(proof.from_seq, 3);
        assert_eq!(proof.to_seq, 3);
        assert_eq!(proof.proof_nodes.len(), 1);
        assert_eq!(proof.from_hash, proof.to_hash);
        assert!(chain.verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_invalid_range() {
        let chain = build_chain(5);
        let result = chain.consistency_proof(4, 2);
        assert!(
            result.is_err(),
            "from_seq > to_seq should return an error"
        );
    }

    #[test]
    fn consistency_proof_out_of_bounds() {
        let chain = build_chain(5);
        let result = chain.consistency_proof(0, 10);
        assert!(
            result.is_err(),
            "to_seq beyond chain length should return an error"
        );
    }

    #[test]
    fn consistency_proof_serde_roundtrip() {
        let chain = build_chain(5);
        let proof = chain.consistency_proof(1, 3).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ConsistencyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.from_seq, deserialized.from_seq);
        assert_eq!(proof.to_seq, deserialized.to_seq);
        assert_eq!(proof.from_hash, deserialized.from_hash);
        assert_eq!(proof.to_hash, deserialized.to_hash);
        assert_eq!(proof.proof_nodes.len(), deserialized.proof_nodes.len());
        assert!(chain.verify_consistency_proof(&deserialized));
    }

    // =========================================================================
    // S3Emitter tests
    // =========================================================================

    fn test_s3_config() -> S3EmitterConfig {
        S3EmitterConfig {
            endpoint: "https://s3.us-east-1.amazonaws.com".to_string(),
            bucket: "tameshi-heartbeats".to_string(),
            key_prefix: "tameshi/heartbeats/".to_string(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            region: "us-east-1".to_string(),
            session_token: None,
        }
    }

    fn in_memory_emitter() -> (std::sync::Arc<object_store::memory::InMemory>, S3Emitter) {
        let store = std::sync::Arc::new(object_store::memory::InMemory::new());
        let emitter = S3Emitter::with_store(Box::new(std::sync::Arc::clone(&store)), test_s3_config());
        (store, emitter)
    }

    #[test]
    fn s3_emitter_config_serde() {
        let config = test_s3_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: S3EmitterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.endpoint, config.endpoint);
        assert_eq!(deserialized.bucket, config.bucket);
        assert_eq!(deserialized.key_prefix, config.key_prefix);
        assert_eq!(deserialized.access_key_id, config.access_key_id);
        assert_eq!(deserialized.secret_access_key, config.secret_access_key);
        assert_eq!(deserialized.region, config.region);
        assert_eq!(deserialized.session_token, None);
    }

    #[test]
    fn s3_emitter_config_serde_with_session_token() {
        let mut config = test_s3_config();
        config.session_token = Some("FwoGZX...EXAMPLE".to_string());
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: S3EmitterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_token, Some("FwoGZX...EXAMPLE".to_string()));
    }

    #[test]
    fn s3_emitter_config_debug_redacts_secrets() {
        let mut config = test_s3_config();
        config.session_token = Some("secret-token".to_string());
        let debug = format!("{config:?}");
        assert!(!debug.contains("wJalrXUtnFEMI"), "secret_access_key must be redacted");
        assert!(!debug.contains("secret-token"), "session_token must be redacted");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn s3_emitter_chain_key_format() {
        let (_, emitter) = in_memory_emitter();
        let ts = chrono::DateTime::parse_from_rfc3339("2026-03-20T15:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let key = emitter.chain_key(&ts);
        assert_eq!(key, "tameshi/heartbeats/chain-20260320T153000Z.json");
    }

    #[test]
    fn s3_emitter_entry_key_format() {
        let (_, emitter) = in_memory_emitter();
        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "test",
            test_signature(),
        );
        let entry = chain.last().unwrap();
        let key = emitter.entry_key(&entry);
        assert_eq!(key, "tameshi/heartbeats/entries/00000000.jsonl");

        // Append more to get a higher sequence
        for _ in 0..41 {
            chain.append(
                test_verifier(),
                HeartbeatEvent::GateCheck,
                VerificationOutcome::Allowed,
                "test",
                test_signature(),
            );
        }
        let entry42 = chain.last().unwrap();
        assert_eq!(entry42.sequence, 41);
        let key42 = emitter.entry_key(&entry42);
        assert_eq!(key42, "tameshi/heartbeats/entries/00000041.jsonl");
    }

    #[test]
    fn s3_emitter_new_builds_client() {
        let config = test_s3_config();
        let emitter = S3Emitter::new(config.clone()).unwrap();
        // Verify the config is stored correctly.
        assert_eq!(emitter.config.endpoint, config.endpoint);
        assert_eq!(emitter.config.bucket, config.bucket);
        assert_eq!(emitter.config.key_prefix, config.key_prefix);
        assert_eq!(emitter.config.region, config.region);
    }

    #[tokio::test]
    async fn s3_emitter_uploads_chain() {
        let (store, emitter) = in_memory_emitter();
        let chain = HeartbeatChain::new();
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

        let key = emitter.upload_chain(&chain).await.unwrap();
        assert!(key.starts_with("tameshi/heartbeats/chain-"));
        assert!(key.ends_with(".json"));

        // Verify the data was actually written and is valid JSON.
        let path = object_store::path::Path::from(key.as_str());
        let result = store.get(&path).await.unwrap();
        let bytes = result.bytes().await.unwrap();
        let entries: Vec<HeartbeatEntry> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].resource, "ns/Deploy/app");
    }

    #[tokio::test]
    async fn s3_emitter_uploads_entry() {
        let (store, emitter) = in_memory_emitter();
        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::ComplianceAssessment,
            VerificationOutcome::Allowed,
            "kensa/assessment",
            test_signature(),
        );
        let entry = chain.last().unwrap();
        let key = emitter.upload_entry(&entry).await.unwrap();
        assert_eq!(key, "tameshi/heartbeats/entries/00000000.jsonl");

        // Verify the data was actually written.
        let path = object_store::path::Path::from(key.as_str());
        let result = store.get(&path).await.unwrap();
        let bytes = result.bytes().await.unwrap();
        let line = std::str::from_utf8(&bytes).unwrap().trim();
        let deserialized: HeartbeatEntry = serde_json::from_str(line).unwrap();
        assert_eq!(deserialized.resource, "kensa/assessment");
        assert_eq!(deserialized.sequence, 0);
    }

    #[tokio::test]
    async fn s3_emitter_emit_trait() {
        let (store, emitter) = in_memory_emitter();
        let chain = HeartbeatChain::new();
        chain.append(
            test_verifier(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "emit-test",
            test_signature(),
        );
        let entry = chain.last().unwrap();

        // Use the HeartbeatEmitter trait method.
        emitter.emit(&entry).await.unwrap();

        // Verify via store.
        let path = object_store::path::Path::from("tameshi/heartbeats/entries/00000000.jsonl");
        let result = store.get(&path).await.unwrap();
        let bytes = result.bytes().await.unwrap();
        assert!(!bytes.is_empty());
    }

    // =========================================================================
    // Clock injection tests (Gap 1 + Gap 6)
    // =========================================================================

    #[test]
    fn append_with_clock_uses_fixed_timestamp() {
        use crate::traits::FixedClock;

        let fixed_time = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let clock = FixedClock::new(fixed_time);

        let chain = HeartbeatChain::new();
        let entry = chain.append_with_clock(
            test_verifier(),
            HeartbeatEvent::AdmissionDecision,
            VerificationOutcome::Allowed,
            "clock-test",
            test_signature(),
            &clock,
        );

        assert_eq!(entry.timestamp, fixed_time, "Entry must use the injected clock timestamp");
    }

    #[test]
    fn append_with_clock_deterministic_same_clock_same_hash() {
        use crate::traits::FixedClock;

        let fixed_time = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let clock = FixedClock::new(fixed_time);
        let verifier = test_verifier();
        let sig = test_signature();

        // Build two independent chains with the same fixed clock
        let chain1 = HeartbeatChain::new();
        let entry1 = chain1.append_with_clock(
            verifier.clone(),
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "deterministic-resource",
            sig.clone(),
            &clock,
        );

        let chain2 = HeartbeatChain::new();
        let entry2 = chain2.append_with_clock(
            verifier,
            HeartbeatEvent::GateCheck,
            VerificationOutcome::Allowed,
            "deterministic-resource",
            sig,
            &clock,
        );

        assert_eq!(
            entry1.entry_hash, entry2.entry_hash,
            "Same inputs + same clock must produce identical entry hashes"
        );
        assert_eq!(entry1.timestamp, entry2.timestamp);
    }

    #[test]
    fn append_backward_compat_still_works() {
        // Existing append() method (uses SystemClock internally) must still work.
        let chain = HeartbeatChain::new();
        let entry = chain.append(
            test_verifier(),
            HeartbeatEvent::ComplianceAssessment,
            VerificationOutcome::Allowed,
            "backward-compat",
            test_signature(),
        );

        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.resource, "backward-compat");
        assert!(chain.verify_integrity());
    }
}
