//! AI Threat Intelligence — zero-day detection from Merkle-structured provenance.
//!
//! This module contains transport-agnostic types and traits for the AI Threat
//! Intelligence service. The AI analyzes Nix derivation dependency graphs
//! against structural fingerprints of known breaches to detect zero-day
//! threats before admission.
//!
//! # Architecture
//!
//! ```text
//! AnalyzeProvenanceRequest  ──▶  AiThreatClient  ──▶  AnalyzeProvenanceResponse
//!   (artifact + Nix graph)         (trait)             (decision + evidence)
//! ```
//!
//! # Implementations
//!
//! - [`MockAiThreatClient`] — configurable responses with call counting
//! - [`FailableAiThreatClient`] — wraps mock, injects failures for chaos testing
//! - [`HttpAiThreatClient`] — real `reqwest` client (URL construction only in tests)
//! - [`DemoAiThreatClient`] — demo theater: ALLOW by default, DENY after heist trigger

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// AI gate verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AiDecision {
    /// Provenance verified — no threat indicators.
    Allow,
    /// Provenance blocked — structural similarity to known breach.
    Deny,
    /// Elevated anomaly — manual review recommended.
    Warn,
}

/// Recommended operator action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Continue with deployment.
    Proceed,
    /// Isolate the artifact for analysis.
    Quarantine,
    /// Manual investigation required.
    Investigate,
    /// Block deployment immediately.
    Block,
}

/// Request urgency level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    /// Synchronous — must respond within 500ms.
    Admission,
    /// Asynchronous — best-effort analysis.
    Background,
}

/// Model health status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelHealthStatus {
    /// Model loaded and serving.
    Ready,
    /// Model is retraining — may have degraded accuracy.
    Retraining,
    /// Model performance degraded.
    Degraded,
    /// Model not available.
    Unavailable,
}

/// Operator feedback label for model retraining.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackLabel {
    /// Correctly identified a threat.
    TruePositive,
    /// Incorrectly flagged as a threat.
    FalsePositive,
    /// Correctly identified as safe.
    TrueNegative,
    /// Missed a real threat.
    FalseNegative,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Request to analyze a binary's cryptographic provenance.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnalyzeProvenanceRequest {
    /// BLAKE3 hash of the Nix store closure or OCI manifest.
    pub artifact_hash: String,
    /// BLAKE3 hash of the kensa compliance assessment.
    pub control_hash: String,
    /// BLAKE3 hash of Pangea synthesis output.
    pub intent_hash: String,
    /// 3-leaf Merkle root with RFC 9162 domain separation.
    pub composed_root: String,
    /// Nix closure metadata — the structural signal.
    pub nix_derivation_graph: NixDerivationGraph,
    /// Where this binary is being deployed.
    pub deployment_context: AiDeploymentContext,
    /// Caller identity (e.g., "sekiban-webhook", "inshou").
    pub requesting_component: String,
    /// Request urgency level.
    pub urgency: Urgency,
}

/// Nix derivation graph metadata for structural analysis.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NixDerivationGraph {
    /// Nix store path of the top-level derivation.
    pub store_path: String,
    /// Immediate Nix store dependencies.
    pub direct_dependencies: Vec<String>,
    /// Total closure size.
    pub transitive_dependency_count: u32,
    /// BLAKE3 hash of the sorted closure.
    pub closure_hash: String,
    /// BLAKE3 hash of all build-time inputs.
    pub build_inputs_hash: String,
}

/// Deployment context for the AI analysis request.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AiDeploymentContext {
    /// Target cluster ID.
    pub cluster: String,
    /// Target K8s namespace.
    pub namespace: String,
    /// Specific node (if known at admission time).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// OCI image reference (must be `@sha256:` digest).
    pub image_ref: String,
}

/// Operator feedback on a previous analysis for model retraining.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnalysisFeedback {
    /// BLAKE3 hash of the analysis being labeled.
    pub analysis_hash: String,
    /// Operator's assessment of the analysis.
    pub label: FeedbackLabel,
    /// Operator identity.
    pub operator_id: String,
    /// Free text justification.
    pub justification: String,
    /// Optional link to an external change management system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_request_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response from the AI provenance analysis.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnalyzeProvenanceResponse {
    /// Gate verdict.
    pub decision: AiDecision,
    /// Model confidence in the decision (0.0–1.0).
    pub confidence: f64,
    /// Detailed analysis metrics.
    pub analysis: AnalysisDetail,
    /// Threat intelligence results.
    pub threat_intelligence: ThreatIntelligence,
    /// Human-readable explanation (present for DENY and WARN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Cryptographic evidence for audit trail.
    pub evidence: AnalysisEvidence,
}

/// Detailed structural analysis metrics.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnalysisDetail {
    /// Cosine similarity to the nearest known breach graph embedding.
    pub structural_similarity_to_known_breaches: f64,
    /// Isolation Forest anomaly score (>0.8 = highly anomalous).
    pub dependency_graph_anomaly_score: f64,
    /// Distance from the learned baseline for this application.
    pub drift_from_baseline: f64,
    /// Number of transitive dependencies never seen in any prior attestation.
    pub novel_dependency_count: u32,
    /// Dependencies contributing most to the anomaly score.
    pub flagged_dependencies: Vec<String>,
}

/// Threat intelligence results from breach pattern matching.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreatIntelligence {
    /// Known breach patterns matched.
    pub matched_patterns: Vec<MatchedPattern>,
    /// Breach ID of the closest structural match, or None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nearest_breach_id: Option<String>,
    /// Similarity score to the nearest breach.
    pub nearest_breach_similarity: f64,
    /// Recommended operator action.
    pub recommended_action: RecommendedAction,
}

/// A matched breach pattern.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MatchedPattern {
    /// Tameshi breach pattern identifier.
    pub pattern_id: String,
    /// Structural similarity score.
    pub similarity: f64,
    /// Human-readable description of the breach pattern.
    pub description: String,
    /// Dependency pattern that triggered the match.
    pub affected_dependency_pattern: String,
    /// When this pattern was first observed (ISO 8601).
    pub first_observed: String,
}

/// Cryptographic evidence for audit trail linkage.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnalysisEvidence {
    /// BLAKE3 hash of the full analysis payload.
    pub analysis_hash: String,
    /// Model version that produced this analysis.
    pub model_version: String,
    /// Timestamp of analysis completion (ISO 8601).
    pub analyzed_at: String,
    /// Wall-clock inference time in milliseconds.
    pub inference_time_ms: u64,
}

/// Current model status and health.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStatus {
    /// Model version identifier.
    pub model_version: String,
    /// Current health status.
    pub status: ModelHealthStatus,
    /// Training data window.
    pub training_data: TrainingData,
    /// Performance metrics.
    pub performance: ModelPerformance,
    /// When the model was last retrained (ISO 8601).
    pub last_retrained: String,
    /// Next scheduled retraining (ISO 8601), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retrain_scheduled: Option<String>,
}

/// Training data window metadata.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingData {
    /// Start of the training data window (ISO 8601).
    pub window_start: String,
    /// End of the training data window (ISO 8601).
    pub window_end: String,
    /// Number of `CertificationArtifact` entries used for training.
    pub total_attestations_trained: u64,
    /// Number of known breach structural fingerprints in the model.
    pub breach_patterns_loaded: u32,
    /// Number of clusters covered by training data.
    pub clusters_covered: u32,
}

/// Model performance metrics.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelPerformance {
    /// Mean inference latency over the last 24 hours.
    pub avg_inference_ms: u64,
    /// 99th percentile inference latency.
    pub p99_inference_ms: u64,
    /// Total analyses performed in the last 24 hours.
    pub total_analyses_24h: u64,
    /// Number of DENY decisions in the last 24 hours.
    pub deny_count_24h: u64,
    /// Number of WARN decisions in the last 24 hours.
    pub warn_count_24h: u64,
}

/// Acknowledgment of operator feedback submission.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedbackAck {
    /// Unique feedback identifier.
    pub feedback_id: String,
    /// Analysis hash that was labeled.
    pub analysis_hash: String,
    /// The label that was applied.
    pub label: FeedbackLabel,
    /// When the feedback was recorded (ISO 8601).
    pub recorded_at: String,
    /// Whether this feedback will affect the next retraining cycle.
    pub will_affect_retrain: bool,
    /// Next scheduled retraining (ISO 8601), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retrain: Option<String>,
}

/// Summary for embedding in `CryptographicReceipt` and `DeploymentContext`.
///
/// A compact representation of the AI analysis result, suitable for inclusion
/// in attestation artifacts without the full analysis payload.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AiAnalysisSummary {
    /// Gate verdict.
    pub decision: AiDecision,
    /// Model confidence in the decision.
    pub confidence: f64,
    /// Structural similarity to known breaches.
    pub structural_similarity: f64,
    /// Dependency graph anomaly score.
    pub anomaly_score: f64,
    /// Nearest breach ID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nearest_breach_id: Option<String>,
    /// Similarity to the nearest breach.
    pub nearest_breach_similarity: f64,
    /// BLAKE3 hash of the full analysis.
    pub analysis_hash: String,
    /// Model version that produced the analysis.
    pub model_version: String,
}

impl AiAnalysisSummary {
    /// Create a summary from a full provenance response.
    #[must_use]
    pub fn from_response(response: &AnalyzeProvenanceResponse) -> Self {
        Self {
            decision: response.decision.clone(),
            confidence: response.confidence,
            structural_similarity: response.analysis.structural_similarity_to_known_breaches,
            anomaly_score: response.analysis.dependency_graph_anomaly_score,
            nearest_breach_id: response.threat_intelligence.nearest_breach_id.clone(),
            nearest_breach_similarity: response.threat_intelligence.nearest_breach_similarity,
            analysis_hash: response.evidence.analysis_hash.clone(),
            model_version: response.evidence.model_version.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the AI Threat Intelligence service.
#[derive(Debug, thiserror::Error)]
pub enum AiThreatError {
    /// The AI service did not respond within the timeout budget.
    #[error("AI service timeout after {0}ms")]
    Timeout(u64),
    /// The AI service is not reachable or not ready.
    #[error("AI service unavailable: {0}")]
    Unavailable(String),
    /// The request was malformed or missing required fields.
    #[error("AI request invalid: {0}")]
    InvalidRequest(String),
    /// The response could not be processed.
    #[error("AI response unprocessable: {0}")]
    Unprocessable(String),
    /// Generic service error.
    #[error("AI service error: {0}")]
    ServiceError(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Client interface for the AI Threat Intelligence service.
///
/// Implementations:
/// - [`MockAiThreatClient`] — configurable responses for testing
/// - [`FailableAiThreatClient`] — chaos testing wrapper
/// - [`HttpAiThreatClient`] — real HTTP client
/// - [`DemoAiThreatClient`] — demo theater client
pub trait AiThreatClient: Send + Sync {
    /// Analyze a binary's provenance for zero-day threat indicators.
    fn analyze_provenance(
        &self,
        request: &AnalyzeProvenanceRequest,
    ) -> impl std::future::Future<Output = Result<AnalyzeProvenanceResponse, AiThreatError>> + Send;

    /// Get the current model status.
    fn model_status(
        &self,
    ) -> impl std::future::Future<Output = Result<ModelStatus, AiThreatError>> + Send;

    /// Submit operator feedback on a previous analysis.
    fn submit_feedback(
        &self,
        feedback: &AnalysisFeedback,
    ) -> impl std::future::Future<Output = Result<FeedbackAck, AiThreatError>> + Send;
}

// ---------------------------------------------------------------------------
// Helpers — default responses
// ---------------------------------------------------------------------------

fn default_allow_response() -> AnalyzeProvenanceResponse {
    AnalyzeProvenanceResponse {
        decision: AiDecision::Allow,
        confidence: 0.98,
        analysis: AnalysisDetail {
            structural_similarity_to_known_breaches: 0.02,
            dependency_graph_anomaly_score: 0.01,
            drift_from_baseline: 0.03,
            novel_dependency_count: 0,
            flagged_dependencies: vec![],
        },
        threat_intelligence: ThreatIntelligence {
            matched_patterns: vec![],
            nearest_breach_id: None,
            nearest_breach_similarity: 0.0,
            recommended_action: RecommendedAction::Proceed,
        },
        reason: None,
        evidence: AnalysisEvidence {
            analysis_hash:
                "blake3:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                    .to_string(),
            model_version: "tameshi-ai-v0.1.0".to_string(),
            analyzed_at: "2026-03-22T14:00:00Z".to_string(),
            inference_time_ms: 7,
        },
    }
}

fn default_deny_response() -> AnalyzeProvenanceResponse {
    AnalyzeProvenanceResponse {
        decision: AiDecision::Deny,
        confidence: 0.96,
        analysis: AnalysisDetail {
            structural_similarity_to_known_breaches: 0.942,
            dependency_graph_anomaly_score: 0.87,
            drift_from_baseline: 0.71,
            novel_dependency_count: 3,
            flagged_dependencies: vec![
                "/nix/store/xxx-fastdds-2.14.0".to_string(),
                "/nix/store/yyy-foonathan-memory-0.7.3".to_string(),
                "/nix/store/zzz-asio-1.28.0".to_string(),
            ],
        },
        threat_intelligence: ThreatIntelligence {
            matched_patterns: vec![MatchedPattern {
                pattern_id: "TAMESHI-BREACH-2025-ROS2-DDS".to_string(),
                similarity: 0.942,
                description: "ROS2 DDS middleware vulnerability chain — memory corruption via malformed RTPS packets in Fast-DDS, exploitable through transitive dependency on foonathan-memory allocator".to_string(),
                affected_dependency_pattern: "fastdds-2.x + foonathan-memory-0.7.x".to_string(),
                first_observed: "2025-09-14T00:00:00Z".to_string(),
            }],
            nearest_breach_id: Some("TAMESHI-BREACH-2025-ROS2-DDS".to_string()),
            nearest_breach_similarity: 0.942,
            recommended_action: RecommendedAction::Block,
        },
        reason: Some("Dependency graph structural analysis detected 94.2% similarity to breach pattern TAMESHI-BREACH-2025-ROS2-DDS.".to_string()),
        evidence: AnalysisEvidence {
            analysis_hash: "blake3:f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1"
                .to_string(),
            model_version: "tameshi-ai-v0.1.0".to_string(),
            analyzed_at: "2026-03-22T14:02:31Z".to_string(),
            inference_time_ms: 23,
        },
    }
}

fn default_warn_response() -> AnalyzeProvenanceResponse {
    AnalyzeProvenanceResponse {
        decision: AiDecision::Warn,
        confidence: 0.73,
        analysis: AnalysisDetail {
            structural_similarity_to_known_breaches: 0.31,
            dependency_graph_anomaly_score: 0.64,
            drift_from_baseline: 0.52,
            novel_dependency_count: 8,
            flagged_dependencies: vec![
                "/nix/store/aaa-new-crypto-lib-0.1.0".to_string(),
                "/nix/store/bbb-experimental-allocator-2.0.0".to_string(),
            ],
        },
        threat_intelligence: ThreatIntelligence {
            matched_patterns: vec![],
            nearest_breach_id: Some("TAMESHI-BREACH-2025-LOG4SHELL-VARIANT".to_string()),
            nearest_breach_similarity: 0.31,
            recommended_action: RecommendedAction::Investigate,
        },
        reason: Some("Dependency graph contains 8 novel transitive dependencies not seen in any prior attestation for this application.".to_string()),
        evidence: AnalysisEvidence {
            analysis_hash: "blake3:1122334455667788990011223344556677889900112233445566778899001122"
                .to_string(),
            model_version: "tameshi-ai-v0.1.0".to_string(),
            analyzed_at: "2026-03-22T14:05:12Z".to_string(),
            inference_time_ms: 19,
        },
    }
}

fn default_model_status() -> ModelStatus {
    ModelStatus {
        model_version: "tameshi-ai-v0.1.0".to_string(),
        status: ModelHealthStatus::Ready,
        training_data: TrainingData {
            window_start: "2025-09-22T00:00:00Z".to_string(),
            window_end: "2026-03-22T00:00:00Z".to_string(),
            total_attestations_trained: 1_284_000,
            breach_patterns_loaded: 47,
            clusters_covered: 12,
        },
        performance: ModelPerformance {
            avg_inference_ms: 8,
            p99_inference_ms: 45,
            total_analyses_24h: 14_200,
            deny_count_24h: 0,
            warn_count_24h: 3,
        },
        last_retrained: "2026-03-21T02:00:00Z".to_string(),
        next_retrain_scheduled: Some("2026-03-28T02:00:00Z".to_string()),
    }
}

fn default_feedback_ack(feedback: &AnalysisFeedback) -> FeedbackAck {
    FeedbackAck {
        feedback_id: "fb-2026-03-22-001".to_string(),
        analysis_hash: feedback.analysis_hash.clone(),
        label: feedback.label.clone(),
        recorded_at: "2026-03-22T11:00:00Z".to_string(),
        will_affect_retrain: true,
        next_retrain: Some("2026-03-28T02:00:00Z".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Implementation 1: MockAiThreatClient
// ---------------------------------------------------------------------------

/// Mock AI Threat Intelligence client with configurable responses and call counting.
///
/// By default returns ALLOW with 0.98 confidence. Use builder methods to
/// configure the response for each endpoint.
pub struct MockAiThreatClient {
    response: std::sync::RwLock<AnalyzeProvenanceResponse>,
    model_status_response: std::sync::RwLock<ModelStatus>,
    analyze_count: AtomicU64,
    status_count: AtomicU64,
    feedback_count: AtomicU64,
}

impl MockAiThreatClient {
    /// Create a new mock client with default ALLOW response.
    #[must_use]
    pub fn new() -> Self {
        Self {
            response: std::sync::RwLock::new(default_allow_response()),
            model_status_response: std::sync::RwLock::new(default_model_status()),
            analyze_count: AtomicU64::new(0),
            status_count: AtomicU64::new(0),
            feedback_count: AtomicU64::new(0),
        }
    }

    /// Configure the decision returned by `analyze_provenance`.
    #[must_use]
    pub fn with_decision(self, decision: AiDecision) -> Self {
        {
            let mut resp = self.response.write().expect("lock poisoned");
            resp.decision = decision;
        }
        self
    }

    /// Configure the full response returned by `analyze_provenance`.
    #[must_use]
    pub fn with_response(self, response: AnalyzeProvenanceResponse) -> Self {
        {
            let mut resp = self.response.write().expect("lock poisoned");
            *resp = response;
        }
        self
    }

    /// Configure the model status response.
    #[must_use]
    pub fn with_model_status(self, status: ModelStatus) -> Self {
        {
            let mut s = self.model_status_response.write().expect("lock poisoned");
            *s = status;
        }
        self
    }

    /// Number of times `analyze_provenance` was called.
    #[must_use]
    pub fn analyze_call_count(&self) -> u64 {
        self.analyze_count.load(Ordering::Relaxed)
    }

    /// Number of times `model_status` was called.
    #[must_use]
    pub fn status_call_count(&self) -> u64 {
        self.status_count.load(Ordering::Relaxed)
    }

    /// Number of times `submit_feedback` was called.
    #[must_use]
    pub fn feedback_call_count(&self) -> u64 {
        self.feedback_count.load(Ordering::Relaxed)
    }
}

impl Default for MockAiThreatClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AiThreatClient for MockAiThreatClient {
    async fn analyze_provenance(
        &self,
        _request: &AnalyzeProvenanceRequest,
    ) -> Result<AnalyzeProvenanceResponse, AiThreatError> {
        self.analyze_count.fetch_add(1, Ordering::Relaxed);
        let resp = self.response.read().expect("lock poisoned");
        Ok(resp.clone())
    }

    async fn model_status(&self) -> Result<ModelStatus, AiThreatError> {
        self.status_count.fetch_add(1, Ordering::Relaxed);
        let status = self.model_status_response.read().expect("lock poisoned");
        Ok(status.clone())
    }

    async fn submit_feedback(
        &self,
        feedback: &AnalysisFeedback,
    ) -> Result<FeedbackAck, AiThreatError> {
        self.feedback_count.fetch_add(1, Ordering::Relaxed);
        Ok(default_feedback_ack(feedback))
    }
}

// ---------------------------------------------------------------------------
// Implementation 2: FailableAiThreatClient
// ---------------------------------------------------------------------------

/// Failure modes for the [`FailableAiThreatClient`].
#[derive(Clone, Debug)]
pub enum AiFailMode {
    /// Simulate network timeout.
    Timeout(u64),
    /// Simulate service unavailable.
    Unavailable,
    /// Simulate corrupted response (returns garbage confidence).
    Corrupted,
    /// Simulate authentication failure.
    AuthFailure,
    /// Simulate rate limiting.
    RateLimited,
}

/// An AI threat client that wraps a [`MockAiThreatClient`] and injects
/// deterministic failures for chaos testing.
///
/// When no `fail_mode` is set, it delegates to the inner mock.
///
/// # Examples
///
/// ```rust
/// use tameshi::ai_threat::{FailableAiThreatClient, AiFailMode, AiThreatClient};
///
/// # tokio_test::block_on(async {
/// let client = FailableAiThreatClient::new().with_timeout(500);
/// let result = client.model_status().await;
/// assert!(result.is_err());
/// # });
/// ```
pub struct FailableAiThreatClient {
    inner: MockAiThreatClient,
    fail_mode: Option<AiFailMode>,
}

impl FailableAiThreatClient {
    /// Create a new failable client with no failure mode (passes through).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MockAiThreatClient::new(),
            fail_mode: None,
        }
    }

    /// Configure to simulate a network timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.fail_mode = Some(AiFailMode::Timeout(timeout_ms));
        self
    }

    /// Configure to simulate service unavailable.
    #[must_use]
    pub fn with_unavailable(mut self) -> Self {
        self.fail_mode = Some(AiFailMode::Unavailable);
        self
    }

    /// Configure to simulate corrupted response.
    #[must_use]
    pub fn with_corrupted(mut self) -> Self {
        self.fail_mode = Some(AiFailMode::Corrupted);
        self
    }

    /// Configure to simulate authentication failure.
    #[must_use]
    pub fn with_auth_failure(mut self) -> Self {
        self.fail_mode = Some(AiFailMode::AuthFailure);
        self
    }

    /// Configure to simulate rate limiting.
    #[must_use]
    pub fn with_rate_limited(mut self) -> Self {
        self.fail_mode = Some(AiFailMode::RateLimited);
        self
    }
}

impl Default for FailableAiThreatClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AiThreatClient for FailableAiThreatClient {
    async fn analyze_provenance(
        &self,
        request: &AnalyzeProvenanceRequest,
    ) -> Result<AnalyzeProvenanceResponse, AiThreatError> {
        match &self.fail_mode {
            Some(AiFailMode::Timeout(ms)) => Err(AiThreatError::Timeout(*ms)),
            Some(AiFailMode::Unavailable) => {
                Err(AiThreatError::Unavailable("service down".to_string()))
            }
            Some(AiFailMode::Corrupted) => Err(AiThreatError::Unprocessable(
                "corrupted response".to_string(),
            )),
            Some(AiFailMode::AuthFailure) => Err(AiThreatError::ServiceError(
                "authentication failed".to_string(),
            )),
            Some(AiFailMode::RateLimited) => {
                Err(AiThreatError::ServiceError("rate limited".to_string()))
            }
            None => self.inner.analyze_provenance(request).await,
        }
    }

    async fn model_status(&self) -> Result<ModelStatus, AiThreatError> {
        match &self.fail_mode {
            Some(AiFailMode::Timeout(ms)) => Err(AiThreatError::Timeout(*ms)),
            Some(AiFailMode::Unavailable) => {
                Err(AiThreatError::Unavailable("service down".to_string()))
            }
            Some(AiFailMode::Corrupted) => Err(AiThreatError::Unprocessable(
                "corrupted response".to_string(),
            )),
            Some(AiFailMode::AuthFailure) => Err(AiThreatError::ServiceError(
                "authentication failed".to_string(),
            )),
            Some(AiFailMode::RateLimited) => {
                Err(AiThreatError::ServiceError("rate limited".to_string()))
            }
            None => self.inner.model_status().await,
        }
    }

    async fn submit_feedback(
        &self,
        feedback: &AnalysisFeedback,
    ) -> Result<FeedbackAck, AiThreatError> {
        match &self.fail_mode {
            Some(AiFailMode::Timeout(ms)) => Err(AiThreatError::Timeout(*ms)),
            Some(AiFailMode::Unavailable) => {
                Err(AiThreatError::Unavailable("service down".to_string()))
            }
            Some(AiFailMode::Corrupted) => Err(AiThreatError::Unprocessable(
                "corrupted response".to_string(),
            )),
            Some(AiFailMode::AuthFailure) => Err(AiThreatError::ServiceError(
                "authentication failed".to_string(),
            )),
            Some(AiFailMode::RateLimited) => {
                Err(AiThreatError::ServiceError("rate limited".to_string()))
            }
            None => self.inner.submit_feedback(feedback).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation 3: HttpAiThreatClient
// ---------------------------------------------------------------------------

/// Real HTTP client for the AI Threat Intelligence service.
///
/// Constructs URLs from a base endpoint and sends JSON requests via `reqwest`.
/// In production, this connects to the tameshi AI inference server.
pub struct HttpAiThreatClient {
    base_url: String,
    client: reqwest::Client,
}

impl HttpAiThreatClient {
    /// Create a new HTTP client targeting the given base URL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tameshi::ai_threat::HttpAiThreatClient;
    ///
    /// let client = HttpAiThreatClient::new("http://localhost:9090");
    /// assert_eq!(client.analyze_url(), "http://localhost:9090/api/v1/ai/analyze-provenance");
    /// ```
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// URL for the analyze-provenance endpoint.
    #[must_use]
    pub fn analyze_url(&self) -> String {
        format!("{}/api/v1/ai/analyze-provenance", self.base_url)
    }

    /// URL for the model-status endpoint.
    #[must_use]
    pub fn status_url(&self) -> String {
        format!("{}/api/v1/ai/model-status", self.base_url)
    }

    /// URL for the feedback endpoint.
    #[must_use]
    pub fn feedback_url(&self) -> String {
        format!("{}/api/v1/ai/feedback", self.base_url)
    }
}

impl AiThreatClient for HttpAiThreatClient {
    async fn analyze_provenance(
        &self,
        request: &AnalyzeProvenanceRequest,
    ) -> Result<AnalyzeProvenanceResponse, AiThreatError> {
        let resp = self
            .client
            .post(&self.analyze_url())
            .json(request)
            .send()
            .await
            .map_err(|e| AiThreatError::Unavailable(e.to_string()))?;

        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| AiThreatError::Unprocessable(e.to_string()))
        } else {
            Err(AiThreatError::ServiceError(format!(
                "HTTP {}",
                resp.status()
            )))
        }
    }

    async fn model_status(&self) -> Result<ModelStatus, AiThreatError> {
        let resp = self
            .client
            .get(&self.status_url())
            .send()
            .await
            .map_err(|e| AiThreatError::Unavailable(e.to_string()))?;

        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| AiThreatError::Unprocessable(e.to_string()))
        } else {
            Err(AiThreatError::ServiceError(format!(
                "HTTP {}",
                resp.status()
            )))
        }
    }

    async fn submit_feedback(
        &self,
        feedback: &AnalysisFeedback,
    ) -> Result<FeedbackAck, AiThreatError> {
        let resp = self
            .client
            .post(&self.feedback_url())
            .json(feedback)
            .send()
            .await
            .map_err(|e| AiThreatError::Unavailable(e.to_string()))?;

        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| AiThreatError::Unprocessable(e.to_string()))
        } else {
            Err(AiThreatError::ServiceError(format!(
                "HTTP {}",
                resp.status()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation 4: DemoAiThreatClient
// ---------------------------------------------------------------------------

/// Demo theater client — ALLOW by default, DENY after `trigger_heist()`.
///
/// Designed for live demonstrations of the AI Threat Intelligence gate.
/// The heist mode returns a DENY response with the ROS2 DDS breach pattern.
///
/// # Examples
///
/// ```rust
/// use tameshi::ai_threat::{DemoAiThreatClient, AiThreatClient, AiDecision};
///
/// # tokio_test::block_on(async {
/// let client = DemoAiThreatClient::new();
/// // Normal mode: ALLOW
/// let req = tameshi::ai_threat::test_helpers::sample_request();
/// let resp = client.analyze_provenance(&req).await.unwrap();
/// assert_eq!(resp.decision, AiDecision::Allow);
///
/// // Trigger heist: DENY
/// client.trigger_heist();
/// let resp = client.analyze_provenance(&req).await.unwrap();
/// assert_eq!(resp.decision, AiDecision::Deny);
///
/// // Reset: back to ALLOW
/// client.reset();
/// let resp = client.analyze_provenance(&req).await.unwrap();
/// assert_eq!(resp.decision, AiDecision::Allow);
/// # });
/// ```
pub struct DemoAiThreatClient {
    heist_active: AtomicBool,
}

impl DemoAiThreatClient {
    /// Create a new demo client in normal (ALLOW) mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heist_active: AtomicBool::new(false),
        }
    }

    /// Activate heist mode — subsequent analyses return DENY with ROS2 DDS pattern.
    pub fn trigger_heist(&self) {
        self.heist_active.store(true, Ordering::Release);
    }

    /// Reset to normal mode — subsequent analyses return ALLOW.
    pub fn reset(&self) {
        self.heist_active.store(false, Ordering::Release);
    }

    /// Whether heist mode is currently active.
    #[must_use]
    pub fn is_heist_active(&self) -> bool {
        self.heist_active.load(Ordering::Acquire)
    }
}

impl Default for DemoAiThreatClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AiThreatClient for DemoAiThreatClient {
    async fn analyze_provenance(
        &self,
        _request: &AnalyzeProvenanceRequest,
    ) -> Result<AnalyzeProvenanceResponse, AiThreatError> {
        if self.heist_active.load(Ordering::Acquire) {
            Ok(default_deny_response())
        } else {
            Ok(default_allow_response())
        }
    }

    async fn model_status(&self) -> Result<ModelStatus, AiThreatError> {
        Ok(default_model_status())
    }

    async fn submit_feedback(
        &self,
        feedback: &AnalysisFeedback,
    ) -> Result<FeedbackAck, AiThreatError> {
        Ok(default_feedback_ack(feedback))
    }
}

// ---------------------------------------------------------------------------
// Test helpers (public for doc-tests and downstream crates)
// ---------------------------------------------------------------------------

/// Test helper utilities for constructing sample requests and responses.
pub mod test_helpers {
    use super::*;

    /// Build a sample `AnalyzeProvenanceRequest` for testing.
    #[must_use]
    pub fn sample_request() -> AnalyzeProvenanceRequest {
        AnalyzeProvenanceRequest {
            artifact_hash:
                "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
                    .to_string(),
            control_hash: "blake3:8c4f7e2d1a3b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"
                .to_string(),
            intent_hash: "blake3:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
                .to_string(),
            composed_root:
                "blake3:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    .to_string(),
            nix_derivation_graph: NixDerivationGraph {
                store_path: "/nix/store/abc123-myapp-1.0.0".to_string(),
                direct_dependencies: vec![
                    "/nix/store/def456-openssl-3.3.1".to_string(),
                    "/nix/store/ghi789-glibc-2.39".to_string(),
                    "/nix/store/jkl012-libcurl-8.7.1".to_string(),
                ],
                transitive_dependency_count: 147,
                closure_hash:
                    "blake3:7f2e1d4c5b6a8907f2e1d4c5b6a89070a1b2c3d4e5f60708a1b2c3d4e5f60708"
                        .to_string(),
                build_inputs_hash:
                    "blake3:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                        .to_string(),
            },
            deployment_context: AiDeploymentContext {
                cluster: "plo-us-east".to_string(),
                namespace: "production".to_string(),
                node: Some("node-04".to_string()),
                image_ref: "ghcr.io/pleme-io/myapp@sha256:abc123def456789".to_string(),
            },
            requesting_component: "sekiban-webhook".to_string(),
            urgency: Urgency::Admission,
        }
    }

    /// Build a sample ALLOW response (Response A from the API doc).
    #[must_use]
    pub fn response_a() -> AnalyzeProvenanceResponse {
        default_allow_response()
    }

    /// Build a sample DENY response (Response B from the API doc).
    #[must_use]
    pub fn response_b() -> AnalyzeProvenanceResponse {
        default_deny_response()
    }

    /// Build a sample WARN response (Response C from the API doc).
    #[must_use]
    pub fn response_c() -> AnalyzeProvenanceResponse {
        default_warn_response()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // Enum serde roundtrips (5)
    // =====================================================================

    #[test]
    fn ai_decision_serde_roundtrip() {
        for decision in [AiDecision::Allow, AiDecision::Deny, AiDecision::Warn] {
            let json = serde_json::to_string(&decision).unwrap();
            let deser: AiDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, deser);
        }
        // Verify SCREAMING_SNAKE_CASE format.
        assert_eq!(
            serde_json::to_string(&AiDecision::Allow).unwrap(),
            "\"ALLOW\""
        );
        assert_eq!(
            serde_json::to_string(&AiDecision::Deny).unwrap(),
            "\"DENY\""
        );
        assert_eq!(
            serde_json::to_string(&AiDecision::Warn).unwrap(),
            "\"WARN\""
        );
    }

    #[test]
    fn recommended_action_serde_roundtrip() {
        for action in [
            RecommendedAction::Proceed,
            RecommendedAction::Quarantine,
            RecommendedAction::Investigate,
            RecommendedAction::Block,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let deser: RecommendedAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, deser);
        }
        assert_eq!(
            serde_json::to_string(&RecommendedAction::Proceed).unwrap(),
            "\"proceed\""
        );
    }

    #[test]
    fn urgency_serde_roundtrip() {
        for urgency in [Urgency::Admission, Urgency::Background] {
            let json = serde_json::to_string(&urgency).unwrap();
            let deser: Urgency = serde_json::from_str(&json).unwrap();
            assert_eq!(urgency, deser);
        }
        assert_eq!(
            serde_json::to_string(&Urgency::Admission).unwrap(),
            "\"admission\""
        );
        assert_eq!(
            serde_json::to_string(&Urgency::Background).unwrap(),
            "\"background\""
        );
    }

    #[test]
    fn model_health_status_serde_roundtrip() {
        for status in [
            ModelHealthStatus::Ready,
            ModelHealthStatus::Retraining,
            ModelHealthStatus::Degraded,
            ModelHealthStatus::Unavailable,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deser: ModelHealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deser);
        }
        assert_eq!(
            serde_json::to_string(&ModelHealthStatus::Ready).unwrap(),
            "\"ready\""
        );
    }

    #[test]
    fn feedback_label_serde_roundtrip() {
        for label in [
            FeedbackLabel::TruePositive,
            FeedbackLabel::FalsePositive,
            FeedbackLabel::TrueNegative,
            FeedbackLabel::FalseNegative,
        ] {
            let json = serde_json::to_string(&label).unwrap();
            let deser: FeedbackLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(label, deser);
        }
        assert_eq!(
            serde_json::to_string(&FeedbackLabel::FalsePositive).unwrap(),
            "\"false_positive\""
        );
    }

    // =====================================================================
    // Struct serde roundtrips (10)
    // =====================================================================

    #[test]
    fn nix_derivation_graph_serde_roundtrip() {
        let graph = NixDerivationGraph {
            store_path: "/nix/store/abc-app-1.0.0".to_string(),
            direct_dependencies: vec!["/nix/store/def-openssl-3.3.1".to_string()],
            transitive_dependency_count: 42,
            closure_hash: "blake3:abcd".to_string(),
            build_inputs_hash: "blake3:1234".to_string(),
        };
        let json = serde_json::to_string(&graph).unwrap();
        let deser: NixDerivationGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.store_path, graph.store_path);
        assert_eq!(deser.transitive_dependency_count, 42);
    }

    #[test]
    fn ai_deployment_context_serde_roundtrip() {
        let ctx = AiDeploymentContext {
            cluster: "plo".to_string(),
            namespace: "prod".to_string(),
            node: Some("node-1".to_string()),
            image_ref: "ghcr.io/app@sha256:abc".to_string(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let deser: AiDeploymentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.cluster, "plo");
        assert_eq!(deser.node, Some("node-1".to_string()));
    }

    #[test]
    fn ai_deployment_context_none_node_skipped() {
        let ctx = AiDeploymentContext {
            cluster: "plo".to_string(),
            namespace: "prod".to_string(),
            node: None,
            image_ref: "ghcr.io/app@sha256:abc".to_string(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("node"));
    }

    #[test]
    fn analyze_provenance_request_serde_roundtrip() {
        let req = test_helpers::sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let deser: AnalyzeProvenanceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.artifact_hash, req.artifact_hash);
        assert_eq!(deser.urgency, Urgency::Admission);
    }

    #[test]
    fn analysis_detail_serde_roundtrip() {
        let detail = AnalysisDetail {
            structural_similarity_to_known_breaches: 0.42,
            dependency_graph_anomaly_score: 0.33,
            drift_from_baseline: 0.15,
            novel_dependency_count: 2,
            flagged_dependencies: vec!["/nix/store/foo".to_string()],
        };
        let json = serde_json::to_string(&detail).unwrap();
        let deser: AnalysisDetail = serde_json::from_str(&json).unwrap();
        assert!((deser.structural_similarity_to_known_breaches - 0.42).abs() < f64::EPSILON);
        assert_eq!(deser.novel_dependency_count, 2);
    }

    #[test]
    fn matched_pattern_serde_roundtrip() {
        let pattern = MatchedPattern {
            pattern_id: "TAMESHI-BREACH-2025-ROS2-DDS".to_string(),
            similarity: 0.942,
            description: "ROS2 DDS breach".to_string(),
            affected_dependency_pattern: "fastdds-2.x".to_string(),
            first_observed: "2025-09-14T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let deser: MatchedPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pattern_id, "TAMESHI-BREACH-2025-ROS2-DDS");
    }

    #[test]
    fn analysis_evidence_serde_roundtrip() {
        let evidence = AnalysisEvidence {
            analysis_hash: "blake3:abc123".to_string(),
            model_version: "v0.1.0".to_string(),
            analyzed_at: "2026-03-22T14:00:00Z".to_string(),
            inference_time_ms: 12,
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let deser: AnalysisEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.inference_time_ms, 12);
    }

    #[test]
    fn model_status_serde_roundtrip() {
        let status = default_model_status();
        let json = serde_json::to_string(&status).unwrap();
        let deser: ModelStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.model_version, "tameshi-ai-v0.1.0");
        assert_eq!(deser.status, ModelHealthStatus::Ready);
        assert_eq!(deser.training_data.breach_patterns_loaded, 47);
    }

    #[test]
    fn feedback_ack_serde_roundtrip() {
        let ack = FeedbackAck {
            feedback_id: "fb-001".to_string(),
            analysis_hash: "blake3:abc".to_string(),
            label: FeedbackLabel::FalsePositive,
            recorded_at: "2026-03-22T11:00:00Z".to_string(),
            will_affect_retrain: true,
            next_retrain: Some("2026-03-28T02:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&ack).unwrap();
        let deser: FeedbackAck = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.feedback_id, "fb-001");
        assert!(deser.will_affect_retrain);
    }

    #[test]
    fn analysis_feedback_serde_roundtrip() {
        let feedback = AnalysisFeedback {
            analysis_hash: "blake3:abc".to_string(),
            label: FeedbackLabel::TruePositive,
            operator_id: "operator@pleme.io".to_string(),
            justification: "Confirmed threat".to_string(),
            change_request_ref: None,
        };
        let json = serde_json::to_string(&feedback).unwrap();
        let deser: AnalysisFeedback = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.label, FeedbackLabel::TruePositive);
        assert!(!json.contains("change_request_ref"));
    }

    // =====================================================================
    // Mock response deserialization from API doc JSON (3)
    // =====================================================================

    #[test]
    fn response_a_clean_binary_allow() {
        let json = r#"{
            "decision": "ALLOW",
            "confidence": 0.98,
            "analysis": {
                "structural_similarity_to_known_breaches": 0.02,
                "dependency_graph_anomaly_score": 0.01,
                "drift_from_baseline": 0.03,
                "novel_dependency_count": 0,
                "flagged_dependencies": []
            },
            "threat_intelligence": {
                "matched_patterns": [],
                "nearest_breach_id": null,
                "nearest_breach_similarity": 0.0,
                "recommended_action": "proceed"
            },
            "evidence": {
                "analysis_hash": "blake3:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "model_version": "tameshi-ai-v0.1.0",
                "analyzed_at": "2026-03-22T14:00:00Z",
                "inference_time_ms": 7
            }
        }"#;
        let resp: AnalyzeProvenanceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, AiDecision::Allow);
        assert!((resp.confidence - 0.98).abs() < f64::EPSILON);
        assert!(resp.threat_intelligence.matched_patterns.is_empty());
        assert_eq!(
            resp.threat_intelligence.recommended_action,
            RecommendedAction::Proceed
        );
    }

    #[test]
    fn response_b_zero_day_deny() {
        let json = r#"{
            "decision": "DENY",
            "confidence": 0.96,
            "analysis": {
                "structural_similarity_to_known_breaches": 0.942,
                "dependency_graph_anomaly_score": 0.87,
                "drift_from_baseline": 0.71,
                "novel_dependency_count": 3,
                "flagged_dependencies": [
                    "/nix/store/xxx-fastdds-2.14.0",
                    "/nix/store/yyy-foonathan-memory-0.7.3",
                    "/nix/store/zzz-asio-1.28.0"
                ]
            },
            "threat_intelligence": {
                "matched_patterns": [
                    {
                        "pattern_id": "TAMESHI-BREACH-2025-ROS2-DDS",
                        "similarity": 0.942,
                        "description": "ROS2 DDS middleware vulnerability chain",
                        "affected_dependency_pattern": "fastdds-2.x + foonathan-memory-0.7.x",
                        "first_observed": "2025-09-14T00:00:00Z"
                    }
                ],
                "nearest_breach_id": "TAMESHI-BREACH-2025-ROS2-DDS",
                "nearest_breach_similarity": 0.942,
                "recommended_action": "block"
            },
            "reason": "Zero-day structural match",
            "evidence": {
                "analysis_hash": "blake3:f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1",
                "model_version": "tameshi-ai-v0.1.0",
                "analyzed_at": "2026-03-22T14:02:31Z",
                "inference_time_ms": 23
            }
        }"#;
        let resp: AnalyzeProvenanceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, AiDecision::Deny);
        assert_eq!(resp.analysis.flagged_dependencies.len(), 3);
        assert_eq!(resp.threat_intelligence.matched_patterns.len(), 1);
        assert_eq!(
            resp.threat_intelligence.matched_patterns[0].pattern_id,
            "TAMESHI-BREACH-2025-ROS2-DDS"
        );
        assert_eq!(
            resp.threat_intelligence.recommended_action,
            RecommendedAction::Block
        );
        assert!(resp.reason.is_some());
    }

    #[test]
    fn response_c_elevated_anomaly_warn() {
        let json = r#"{
            "decision": "WARN",
            "confidence": 0.73,
            "analysis": {
                "structural_similarity_to_known_breaches": 0.31,
                "dependency_graph_anomaly_score": 0.64,
                "drift_from_baseline": 0.52,
                "novel_dependency_count": 8,
                "flagged_dependencies": [
                    "/nix/store/aaa-new-crypto-lib-0.1.0",
                    "/nix/store/bbb-experimental-allocator-2.0.0"
                ]
            },
            "threat_intelligence": {
                "matched_patterns": [],
                "nearest_breach_id": "TAMESHI-BREACH-2025-LOG4SHELL-VARIANT",
                "nearest_breach_similarity": 0.31,
                "recommended_action": "investigate"
            },
            "reason": "8 novel transitive dependencies",
            "evidence": {
                "analysis_hash": "blake3:1122334455667788990011223344556677889900112233445566778899001122",
                "model_version": "tameshi-ai-v0.1.0",
                "analyzed_at": "2026-03-22T14:05:12Z",
                "inference_time_ms": 19
            }
        }"#;
        let resp: AnalyzeProvenanceResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, AiDecision::Warn);
        assert!((resp.confidence - 0.73).abs() < f64::EPSILON);
        assert_eq!(resp.analysis.novel_dependency_count, 8);
        assert_eq!(
            resp.threat_intelligence.recommended_action,
            RecommendedAction::Investigate
        );
    }

    // =====================================================================
    // AiThreatError display messages (5)
    // =====================================================================

    #[test]
    fn error_timeout_display() {
        let err = AiThreatError::Timeout(500);
        assert_eq!(err.to_string(), "AI service timeout after 500ms");
    }

    #[test]
    fn error_unavailable_display() {
        let err = AiThreatError::Unavailable("connection refused".to_string());
        assert_eq!(
            err.to_string(),
            "AI service unavailable: connection refused"
        );
    }

    #[test]
    fn error_invalid_request_display() {
        let err = AiThreatError::InvalidRequest("missing artifact_hash".to_string());
        assert_eq!(err.to_string(), "AI request invalid: missing artifact_hash");
    }

    #[test]
    fn error_unprocessable_display() {
        let err = AiThreatError::Unprocessable("bad json".to_string());
        assert_eq!(err.to_string(), "AI response unprocessable: bad json");
    }

    #[test]
    fn error_service_error_display() {
        let err = AiThreatError::ServiceError("internal error".to_string());
        assert_eq!(err.to_string(), "AI service error: internal error");
    }

    // =====================================================================
    // MockAiThreatClient (10)
    // =====================================================================

    #[tokio::test]
    async fn mock_default_returns_allow() {
        let client = MockAiThreatClient::new();
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Allow);
        assert!((resp.confidence - 0.98).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn mock_with_decision_deny() {
        let client = MockAiThreatClient::new().with_decision(AiDecision::Deny);
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Deny);
    }

    #[tokio::test]
    async fn mock_with_decision_warn() {
        let client = MockAiThreatClient::new().with_decision(AiDecision::Warn);
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Warn);
    }

    #[tokio::test]
    async fn mock_with_full_response() {
        let custom_resp = default_deny_response();
        let client = MockAiThreatClient::new().with_response(custom_resp.clone());
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Deny);
        assert!((resp.confidence - 0.96).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn mock_analyze_call_count() {
        let client = MockAiThreatClient::new();
        assert_eq!(client.analyze_call_count(), 0);
        let req = test_helpers::sample_request();
        client.analyze_provenance(&req).await.unwrap();
        assert_eq!(client.analyze_call_count(), 1);
        client.analyze_provenance(&req).await.unwrap();
        assert_eq!(client.analyze_call_count(), 2);
    }

    #[tokio::test]
    async fn mock_status_call_count() {
        let client = MockAiThreatClient::new();
        assert_eq!(client.status_call_count(), 0);
        client.model_status().await.unwrap();
        assert_eq!(client.status_call_count(), 1);
    }

    #[tokio::test]
    async fn mock_feedback_call_count() {
        let client = MockAiThreatClient::new();
        assert_eq!(client.feedback_call_count(), 0);
        let feedback = AnalysisFeedback {
            analysis_hash: "blake3:abc".to_string(),
            label: FeedbackLabel::FalsePositive,
            operator_id: "op@pleme.io".to_string(),
            justification: "authorized".to_string(),
            change_request_ref: Some("CR-001".to_string()),
        };
        client.submit_feedback(&feedback).await.unwrap();
        assert_eq!(client.feedback_call_count(), 1);
    }

    #[tokio::test]
    async fn mock_model_status_returns_ready() {
        let client = MockAiThreatClient::new();
        let status = client.model_status().await.unwrap();
        assert_eq!(status.status, ModelHealthStatus::Ready);
        assert_eq!(status.model_version, "tameshi-ai-v0.1.0");
    }

    #[tokio::test]
    async fn mock_submit_feedback_returns_ack() {
        let client = MockAiThreatClient::new();
        let feedback = AnalysisFeedback {
            analysis_hash: "blake3:xyz".to_string(),
            label: FeedbackLabel::TrueNegative,
            operator_id: "op@pleme.io".to_string(),
            justification: "verified safe".to_string(),
            change_request_ref: None,
        };
        let ack = client.submit_feedback(&feedback).await.unwrap();
        assert_eq!(ack.analysis_hash, "blake3:xyz");
        assert_eq!(ack.label, FeedbackLabel::TrueNegative);
        assert!(ack.will_affect_retrain);
    }

    #[tokio::test]
    async fn mock_thread_safe_concurrent_access() {
        use std::sync::Arc;
        let client = Arc::new(MockAiThreatClient::new());
        let req = test_helpers::sample_request();

        let mut handles = vec![];
        for _ in 0..10 {
            let c = Arc::clone(&client);
            let r = req.clone();
            handles.push(tokio::spawn(async move {
                c.analyze_provenance(&r).await.unwrap()
            }));
        }
        for h in handles {
            let resp = h.await.unwrap();
            assert_eq!(resp.decision, AiDecision::Allow);
        }
        assert_eq!(client.analyze_call_count(), 10);
    }

    // =====================================================================
    // FailableAiThreatClient (5)
    // =====================================================================

    #[tokio::test]
    async fn failable_timeout() {
        let client = FailableAiThreatClient::new().with_timeout(500);
        let req = test_helpers::sample_request();
        let err = client.analyze_provenance(&req).await.unwrap_err();
        assert!(matches!(err, AiThreatError::Timeout(500)));
        assert!(err.to_string().contains("500ms"));
    }

    #[tokio::test]
    async fn failable_unavailable() {
        let client = FailableAiThreatClient::new().with_unavailable();
        let err = client.model_status().await.unwrap_err();
        assert!(matches!(err, AiThreatError::Unavailable(_)));
    }

    #[tokio::test]
    async fn failable_corrupted() {
        let client = FailableAiThreatClient::new().with_corrupted();
        let req = test_helpers::sample_request();
        let err = client.analyze_provenance(&req).await.unwrap_err();
        assert!(matches!(err, AiThreatError::Unprocessable(_)));
    }

    #[tokio::test]
    async fn failable_auth_failure() {
        let client = FailableAiThreatClient::new().with_auth_failure();
        let feedback = AnalysisFeedback {
            analysis_hash: "blake3:abc".to_string(),
            label: FeedbackLabel::FalsePositive,
            operator_id: "op@pleme.io".to_string(),
            justification: "test".to_string(),
            change_request_ref: None,
        };
        let err = client.submit_feedback(&feedback).await.unwrap_err();
        assert!(matches!(err, AiThreatError::ServiceError(_)));
        assert!(err.to_string().contains("authentication"));
    }

    #[tokio::test]
    async fn failable_rate_limited() {
        let client = FailableAiThreatClient::new().with_rate_limited();
        let req = test_helpers::sample_request();
        let err = client.analyze_provenance(&req).await.unwrap_err();
        assert!(matches!(err, AiThreatError::ServiceError(_)));
        assert!(err.to_string().contains("rate limited"));
    }

    // =====================================================================
    // HttpAiThreatClient URL construction (3)
    // =====================================================================

    #[test]
    fn http_client_analyze_url() {
        let client = HttpAiThreatClient::new("http://localhost:9090");
        assert_eq!(
            client.analyze_url(),
            "http://localhost:9090/api/v1/ai/analyze-provenance"
        );
    }

    #[test]
    fn http_client_status_url() {
        let client = HttpAiThreatClient::new("http://localhost:9090/");
        assert_eq!(
            client.status_url(),
            "http://localhost:9090/api/v1/ai/model-status"
        );
    }

    #[test]
    fn http_client_feedback_url() {
        let client = HttpAiThreatClient::new("https://ai.tameshi.io");
        assert_eq!(
            client.feedback_url(),
            "https://ai.tameshi.io/api/v1/ai/feedback"
        );
    }

    // =====================================================================
    // DemoAiThreatClient (6)
    // =====================================================================

    #[tokio::test]
    async fn demo_default_returns_allow() {
        let client = DemoAiThreatClient::new();
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Allow);
    }

    #[tokio::test]
    async fn demo_heist_returns_deny() {
        let client = DemoAiThreatClient::new();
        client.trigger_heist();
        assert!(client.is_heist_active());
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Deny);
        assert!(
            (resp.analysis.structural_similarity_to_known_breaches - 0.942).abs() < f64::EPSILON
        );
    }

    #[tokio::test]
    async fn demo_reset_returns_allow() {
        let client = DemoAiThreatClient::new();
        client.trigger_heist();
        client.reset();
        assert!(!client.is_heist_active());
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Allow);
    }

    #[tokio::test]
    async fn demo_heist_includes_ros2_dds_pattern() {
        let client = DemoAiThreatClient::new();
        client.trigger_heist();
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.threat_intelligence.matched_patterns.len(), 1);
        let pattern = &resp.threat_intelligence.matched_patterns[0];
        assert_eq!(pattern.pattern_id, "TAMESHI-BREACH-2025-ROS2-DDS");
        assert!((pattern.similarity - 0.942).abs() < f64::EPSILON);
        assert!(pattern.description.contains("ROS2 DDS"));
    }

    #[tokio::test]
    async fn demo_model_status_always_ready() {
        let client = DemoAiThreatClient::new();
        let status = client.model_status().await.unwrap();
        assert_eq!(status.status, ModelHealthStatus::Ready);
    }

    #[tokio::test]
    async fn demo_feedback_returns_ack() {
        let client = DemoAiThreatClient::new();
        let feedback = AnalysisFeedback {
            analysis_hash: "blake3:abc".to_string(),
            label: FeedbackLabel::FalseNegative,
            operator_id: "op@pleme.io".to_string(),
            justification: "missed threat".to_string(),
            change_request_ref: None,
        };
        let ack = client.submit_feedback(&feedback).await.unwrap();
        assert_eq!(ack.label, FeedbackLabel::FalseNegative);
    }

    // =====================================================================
    // AiAnalysisSummary (2)
    // =====================================================================

    #[test]
    fn ai_analysis_summary_from_allow_response() {
        let resp = test_helpers::response_a();
        let summary = AiAnalysisSummary::from_response(&resp);
        assert_eq!(summary.decision, AiDecision::Allow);
        assert!((summary.confidence - 0.98).abs() < f64::EPSILON);
        assert!((summary.structural_similarity - 0.02).abs() < f64::EPSILON);
        assert!((summary.anomaly_score - 0.01).abs() < f64::EPSILON);
        assert!(summary.nearest_breach_id.is_none());
        assert_eq!(summary.model_version, "tameshi-ai-v0.1.0");
    }

    #[test]
    fn ai_analysis_summary_from_deny_response() {
        let resp = test_helpers::response_b();
        let summary = AiAnalysisSummary::from_response(&resp);
        assert_eq!(summary.decision, AiDecision::Deny);
        assert!((summary.confidence - 0.96).abs() < f64::EPSILON);
        assert_eq!(
            summary.nearest_breach_id.as_deref(),
            Some("TAMESHI-BREACH-2025-ROS2-DDS")
        );
        assert!((summary.nearest_breach_similarity - 0.942).abs() < f64::EPSILON);
    }

    // =====================================================================
    // AiAnalysisSummary serde roundtrip (1)
    // =====================================================================

    #[test]
    fn ai_analysis_summary_serde_roundtrip() {
        let resp = test_helpers::response_b();
        let summary = AiAnalysisSummary::from_response(&resp);
        let json = serde_json::to_string(&summary).unwrap();
        let deser: AiAnalysisSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.decision, AiDecision::Deny);
        assert_eq!(deser.analysis_hash, summary.analysis_hash);
    }

    // =====================================================================
    // Integration: analyze -> sign -> gate (3)
    // =====================================================================

    #[tokio::test]
    async fn integration_allow_does_not_block() {
        let client = MockAiThreatClient::new();
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        // ALLOW decision should not block deployment.
        assert_eq!(resp.decision, AiDecision::Allow);
        // Evidence hash is present for heartbeat recording.
        assert!(!resp.evidence.analysis_hash.is_empty());
        assert!(!resp.evidence.model_version.is_empty());
    }

    #[tokio::test]
    async fn integration_deny_blocks_with_evidence() {
        let client = MockAiThreatClient::new().with_response(default_deny_response());
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Deny);
        // DENY must include evidence for audit trail.
        assert!(!resp.evidence.analysis_hash.is_empty());
        assert!(resp.reason.is_some());
        // Summary should preserve the deny decision.
        let summary = AiAnalysisSummary::from_response(&resp);
        assert_eq!(summary.decision, AiDecision::Deny);
    }

    #[tokio::test]
    async fn integration_failable_degrades_gracefully() {
        // When AI is unavailable, the system should get an error but not panic.
        let client = FailableAiThreatClient::new().with_unavailable();
        let req = test_helpers::sample_request();
        let result = client.analyze_provenance(&req).await;
        assert!(result.is_err());
        // The error should be actionable.
        let err = result.unwrap_err();
        assert!(matches!(err, AiThreatError::Unavailable(_)));
    }

    // =====================================================================
    // Schema generation (1)
    // =====================================================================

    #[test]
    fn schema_generation_does_not_panic() {
        // Ensure all types with schemars::JsonSchema can generate schemas.
        let _ = schemars::schema_for!(AiDecision);
        let _ = schemars::schema_for!(RecommendedAction);
        let _ = schemars::schema_for!(Urgency);
        let _ = schemars::schema_for!(ModelHealthStatus);
        let _ = schemars::schema_for!(FeedbackLabel);
        let _ = schemars::schema_for!(AnalyzeProvenanceRequest);
        let _ = schemars::schema_for!(AnalyzeProvenanceResponse);
        let _ = schemars::schema_for!(AnalysisDetail);
        let _ = schemars::schema_for!(ThreatIntelligence);
        let _ = schemars::schema_for!(MatchedPattern);
        let _ = schemars::schema_for!(AnalysisEvidence);
        let _ = schemars::schema_for!(ModelStatus);
        let _ = schemars::schema_for!(TrainingData);
        let _ = schemars::schema_for!(ModelPerformance);
        let _ = schemars::schema_for!(FeedbackAck);
        let _ = schemars::schema_for!(AiAnalysisSummary);
        let _ = schemars::schema_for!(NixDerivationGraph);
        let _ = schemars::schema_for!(AiDeploymentContext);
        let _ = schemars::schema_for!(AnalysisFeedback);
    }

    // =====================================================================
    // Failable no-failure passthrough (1)
    // =====================================================================

    #[tokio::test]
    async fn failable_no_mode_passes_through() {
        let client = FailableAiThreatClient::new();
        let req = test_helpers::sample_request();
        let resp = client.analyze_provenance(&req).await.unwrap();
        assert_eq!(resp.decision, AiDecision::Allow);
    }

    // =====================================================================
    // Default impls (2)
    // =====================================================================

    #[test]
    fn mock_default_impl() {
        let client = MockAiThreatClient::default();
        assert_eq!(client.analyze_call_count(), 0);
    }

    #[test]
    fn failable_default_impl() {
        let _client = FailableAiThreatClient::default();
    }

    #[test]
    fn demo_default_impl() {
        let client = DemoAiThreatClient::default();
        assert!(!client.is_heist_active());
    }

    // =====================================================================
    // Threat intelligence response details (2)
    // =====================================================================

    #[test]
    fn threat_intelligence_serde_roundtrip() {
        let ti = ThreatIntelligence {
            matched_patterns: vec![MatchedPattern {
                pattern_id: "TEST-001".to_string(),
                similarity: 0.85,
                description: "test pattern".to_string(),
                affected_dependency_pattern: "lib-1.x".to_string(),
                first_observed: "2026-01-01T00:00:00Z".to_string(),
            }],
            nearest_breach_id: Some("TEST-001".to_string()),
            nearest_breach_similarity: 0.85,
            recommended_action: RecommendedAction::Quarantine,
        };
        let json = serde_json::to_string(&ti).unwrap();
        let deser: ThreatIntelligence = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.matched_patterns.len(), 1);
        assert_eq!(deser.recommended_action, RecommendedAction::Quarantine);
    }

    #[test]
    fn training_data_serde_roundtrip() {
        let td = TrainingData {
            window_start: "2025-01-01T00:00:00Z".to_string(),
            window_end: "2026-01-01T00:00:00Z".to_string(),
            total_attestations_trained: 1_000_000,
            breach_patterns_loaded: 30,
            clusters_covered: 5,
        };
        let json = serde_json::to_string(&td).unwrap();
        let deser: TrainingData = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.total_attestations_trained, 1_000_000);
    }

    #[test]
    fn model_performance_serde_roundtrip() {
        let mp = ModelPerformance {
            avg_inference_ms: 10,
            p99_inference_ms: 50,
            total_analyses_24h: 10_000,
            deny_count_24h: 2,
            warn_count_24h: 5,
        };
        let json = serde_json::to_string(&mp).unwrap();
        let deser: ModelPerformance = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.p99_inference_ms, 50);
    }

    // =====================================================================
    // Full provenance response serde roundtrip (1)
    // =====================================================================

    #[test]
    fn full_provenance_response_serde_roundtrip() {
        let resp = default_deny_response();
        let json = serde_json::to_string(&resp).unwrap();
        let deser: AnalyzeProvenanceResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.decision, resp.decision);
        assert!((deser.confidence - resp.confidence).abs() < f64::EPSILON);
        assert_eq!(
            deser.threat_intelligence.matched_patterns.len(),
            resp.threat_intelligence.matched_patterns.len()
        );
    }

    // =====================================================================
    // Mock with custom model status (1)
    // =====================================================================

    #[tokio::test]
    async fn mock_with_custom_model_status() {
        let mut custom_status = default_model_status();
        custom_status.status = ModelHealthStatus::Retraining;
        custom_status.model_version = "tameshi-ai-v0.2.0".to_string();
        let client = MockAiThreatClient::new().with_model_status(custom_status);
        let status = client.model_status().await.unwrap();
        assert_eq!(status.status, ModelHealthStatus::Retraining);
        assert_eq!(status.model_version, "tameshi-ai-v0.2.0");
    }
}
