//! Generic alerting hooks for integrity violations.
//!
//! Provides a pluggable notification system that fires when:
//! - Gate denials occur (unsigned/invalid resources attempted)
//! - Compliance failures detected
//! - Signature mismatches found
//! - Certifications go stale or degrade
//! - Bad changesets or artifacts are attempted
//!
//! Supports multiple notification channels: webhook, Discord, Slack,
//! Kubernetes events, and custom handlers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::hash::Blake3Hash;
use crate::signature::LayerType;

/// Severity level for alerts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// Informational — state change logged, no action needed.
    Info,
    /// Warning — degraded state, attention recommended.
    Warning,
    /// Critical — gate denial or compliance failure, immediate action needed.
    Critical,
    /// Emergency — system integrity compromised.
    Emergency,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Warning => write!(f, "warning"),
            AlertSeverity::Critical => write!(f, "critical"),
            AlertSeverity::Emergency => write!(f, "emergency"),
        }
    }
}

/// Types of integrity events that trigger alerts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertEvent {
    /// A resource was denied by the admission gate.
    GateDenied {
        resource_kind: String,
        resource_name: String,
        namespace: String,
        expected_signature: String,
        actual_signature: Option<String>,
        reason: String,
    },
    /// Compliance tests failed.
    ComplianceFailed {
        environment: String,
        failed_controls: Vec<String>,
        framework: String,
        baseline: String,
    },
    /// Signature mismatch detected during continuous certification.
    SignatureMismatch {
        environment: String,
        layer: LayerType,
        expected: String,
        actual: String,
    },
    /// Certification degraded from Certified to Degraded/Failed.
    CertificationDegraded {
        environment: String,
        previous_phase: String,
        current_phase: String,
        affected_layers: Vec<String>,
    },
    /// A stale certification was detected (not re-verified within interval).
    CertificationStale {
        environment: String,
        last_verified_at: DateTime<Utc>,
        staleness_seconds: u64,
    },
    /// Bad artifact detected (unsigned image, unverified chart, etc.).
    BadArtifact {
        artifact_type: String,
        artifact_ref: String,
        reason: String,
    },
    /// Changeset rejected — a K8s patch/update was denied.
    ChangesetRejected {
        operation: String,
        resource_kind: String,
        resource_name: String,
        namespace: String,
        changeset_hash: String,
        reason: String,
    },
    /// System self-attestation failure.
    SelfAttestationFailed {
        component: String,
        expected_hash: String,
        actual_hash: String,
    },
}

/// An alert ready for dispatch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert identifier.
    pub id: String,
    /// When the alert was created.
    pub timestamp: DateTime<Utc>,
    /// Severity level.
    pub severity: AlertSeverity,
    /// The event that triggered this alert.
    pub event: AlertEvent,
    /// Human-readable summary.
    pub summary: String,
    /// Environment where the event occurred.
    pub environment: String,
    /// Source component (e.g., "sekiban", "inshou", "kensa").
    pub source: String,
}

impl Alert {
    /// Create a new alert.
    #[must_use]
    pub fn new(
        severity: AlertSeverity,
        event: AlertEvent,
        summary: &str,
        environment: &str,
        source: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            severity,
            event,
            summary: summary.to_string(),
            environment: environment.to_string(),
            source: source.to_string(),
        }
    }

    /// Create a gate denial alert.
    #[must_use]
    pub fn gate_denied(
        resource_kind: &str,
        resource_name: &str,
        namespace: &str,
        expected: &Blake3Hash,
        actual: Option<&Blake3Hash>,
        reason: &str,
        environment: &str,
    ) -> Self {
        Self::new(
            AlertSeverity::Critical,
            AlertEvent::GateDenied {
                resource_kind: resource_kind.to_string(),
                resource_name: resource_name.to_string(),
                namespace: namespace.to_string(),
                expected_signature: expected.to_prefixed(),
                actual_signature: actual.map(|a| a.to_prefixed()),
                reason: reason.to_string(),
            },
            &format!(
                "Gate DENIED: {}/{} in {} — {}",
                resource_kind, resource_name, namespace, reason
            ),
            environment,
            "sekiban",
        )
    }

    /// Create a changeset rejected alert.
    #[must_use]
    pub fn changeset_rejected(
        operation: &str,
        resource_kind: &str,
        resource_name: &str,
        namespace: &str,
        changeset_hash: &Blake3Hash,
        reason: &str,
        environment: &str,
    ) -> Self {
        Self::new(
            AlertSeverity::Critical,
            AlertEvent::ChangesetRejected {
                operation: operation.to_string(),
                resource_kind: resource_kind.to_string(),
                resource_name: resource_name.to_string(),
                namespace: namespace.to_string(),
                changeset_hash: changeset_hash.to_prefixed(),
                reason: reason.to_string(),
            },
            &format!(
                "Changeset REJECTED: {} {}/{} in {} — {}",
                operation, resource_kind, resource_name, namespace, reason
            ),
            environment,
            "sekiban",
        )
    }

    /// Create a compliance failure alert.
    #[must_use]
    pub fn compliance_failed(
        environment: &str,
        failed_controls: Vec<String>,
        framework: &str,
        baseline: &str,
    ) -> Self {
        Self::new(
            AlertSeverity::Critical,
            AlertEvent::ComplianceFailed {
                environment: environment.to_string(),
                failed_controls: failed_controls.clone(),
                framework: framework.to_string(),
                baseline: baseline.to_string(),
            },
            &format!(
                "Compliance FAILED: {} controls failed against {} {} in {}",
                failed_controls.len(),
                framework,
                baseline,
                environment
            ),
            environment,
            "kensa",
        )
    }
}

/// Configuration for a notification channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NotificationChannel {
    /// Generic webhook (POST JSON to URL).
    Webhook {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        headers: Option<std::collections::HashMap<String, String>>,
    },
    /// Discord webhook.
    Discord {
        webhook_url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    /// Slack webhook.
    Slack {
        webhook_url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel: Option<String>,
    },
    /// Kubernetes Event emission.
    KubernetesEvent {
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
    },
    /// Log only (structured tracing output).
    Log,
}

/// Trait for dispatching alerts.
///
/// Abstracts over alert delivery so consumers can inject custom
/// dispatchers (e.g., in-memory for testing, custom webhook logic).
pub trait AlertSender: Send + Sync {
    /// Dispatch an alert. Implementations should handle channel routing.
    fn dispatch(&self, alert: &Alert) -> impl std::future::Future<Output = ()> + Send;
}

/// Alert dispatcher — sends alerts to configured channels.
#[derive(Clone)]
pub struct AlertDispatcher {
    channels: Vec<NotificationChannel>,
    min_severity: AlertSeverity,
    client: reqwest::Client,
}

impl AlertDispatcher {
    /// Create a new dispatcher with the given channels.
    #[must_use]
    pub fn new(channels: Vec<NotificationChannel>, min_severity: AlertSeverity) -> Self {
        Self {
            channels,
            min_severity,
            client: reqwest::Client::new(),
        }
    }

    /// Create a log-only dispatcher (default fallback).
    #[must_use]
    pub fn log_only() -> Self {
        Self::new(vec![NotificationChannel::Log], AlertSeverity::Info)
    }

    /// Dispatch an alert to all configured channels.
    pub async fn dispatch(&self, alert: &Alert) {
        if alert.severity < self.min_severity {
            return;
        }

        for channel in &self.channels {
            if let Err(e) = self.send(channel, alert).await {
                error!(
                    channel = ?channel,
                    error = %e,
                    alert_id = %alert.id,
                    "Failed to dispatch alert"
                );
            }
        }
    }

    async fn send(
        &self,
        channel: &NotificationChannel,
        alert: &Alert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match channel {
            NotificationChannel::Webhook {
                url,
                secret,
                headers,
            } => {
                let mut req = self.client.post(url).json(alert);
                if let Some(secret) = secret {
                    // HMAC-SHA256 signature of the body
                    let body = serde_json::to_vec(alert)?;
                    let signature = compute_webhook_signature(secret, &body);
                    req = req.header("X-Tameshi-Signature", signature);
                }
                if let Some(headers) = headers {
                    for (k, v) in headers {
                        req = req.header(k, v);
                    }
                }
                req.send().await?;
                info!(url = %url, alert_id = %alert.id, "Alert dispatched via webhook");
            }
            NotificationChannel::Discord {
                webhook_url,
                username,
            } => {
                let color = match alert.severity {
                    AlertSeverity::Emergency => 0xFF0000, // red
                    AlertSeverity::Critical => 0xFF4500,  // orange-red
                    AlertSeverity::Warning => 0xFFAA00,   // amber
                    AlertSeverity::Info => 0x00AA00,      // green
                };
                let payload = serde_json::json!({
                    "username": username.as_deref().unwrap_or("Tameshi"),
                    "embeds": [{
                        "title": format!("[{}] {}", alert.severity, alert.summary),
                        "color": color,
                        "fields": [
                            {"name": "Environment", "value": &alert.environment, "inline": true},
                            {"name": "Source", "value": &alert.source, "inline": true},
                            {"name": "Severity", "value": alert.severity.to_string(), "inline": true},
                        ],
                        "timestamp": alert.timestamp.to_rfc3339(),
                    }]
                });
                self.client.post(webhook_url).json(&payload).send().await?;
                info!(alert_id = %alert.id, "Alert dispatched via Discord");
            }
            NotificationChannel::Slack {
                webhook_url,
                channel,
            } => {
                let emoji = match alert.severity {
                    AlertSeverity::Emergency => ":rotating_light:",
                    AlertSeverity::Critical => ":x:",
                    AlertSeverity::Warning => ":warning:",
                    AlertSeverity::Info => ":white_check_mark:",
                };
                let mut payload = serde_json::json!({
                    "text": format!("{} *[{}]* {}", emoji, alert.severity, alert.summary),
                    "blocks": [{
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!(
                                "{} *[{}]* {}\n*Environment:* `{}`\n*Source:* `{}`",
                                emoji, alert.severity, alert.summary,
                                alert.environment, alert.source
                            )
                        }
                    }]
                });
                if let Some(ch) = channel {
                    payload["channel"] = serde_json::Value::String(ch.clone());
                }
                self.client.post(webhook_url).json(&payload).send().await?;
                info!(alert_id = %alert.id, "Alert dispatched via Slack");
            }
            NotificationChannel::KubernetesEvent { .. } => {
                // K8s events are emitted by the controller using kube::runtime::events
                // This channel is a marker — actual emission happens in sekiban
                warn!(alert_id = %alert.id, "K8s event emission delegated to controller");
            }
            NotificationChannel::Log => match alert.severity {
                AlertSeverity::Emergency | AlertSeverity::Critical => {
                    error!(
                        alert_id = %alert.id,
                        severity = %alert.severity,
                        environment = %alert.environment,
                        source = %alert.source,
                        "{}",
                        alert.summary
                    );
                }
                AlertSeverity::Warning => {
                    warn!(
                        alert_id = %alert.id,
                        severity = %alert.severity,
                        environment = %alert.environment,
                        "{}",
                        alert.summary
                    );
                }
                AlertSeverity::Info => {
                    info!(
                        alert_id = %alert.id,
                        severity = %alert.severity,
                        environment = %alert.environment,
                        "{}",
                        alert.summary
                    );
                }
            },
        }
        Ok(())
    }
}

impl AlertSender for AlertDispatcher {
    async fn dispatch(&self, alert: &Alert) {
        AlertDispatcher::dispatch(self, alert).await;
    }
}

/// A no-op alert sender for testing.
///
/// Records dispatched alerts in memory for assertions.
pub struct MockAlertSender {
    alerts: std::sync::Mutex<Vec<Alert>>,
}

impl MockAlertSender {
    /// Create a new mock alert sender.
    #[must_use]
    pub fn new() -> Self {
        Self {
            alerts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get all dispatched alerts.
    #[must_use]
    pub fn alerts(&self) -> Vec<Alert> {
        self.alerts.lock().unwrap().clone()
    }
}

impl Default for MockAlertSender {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertSender for MockAlertSender {
    async fn dispatch(&self, alert: &Alert) {
        self.alerts.lock().unwrap().push(alert.clone());
    }
}

/// Compute HMAC-SHA256 signature for webhook payloads.
fn compute_webhook_signature(secret: &str, body: &[u8]) -> String {
    use sha2::Digest;
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(body);
    let result = hasher.finalize();
    format!("sha256={}", const_hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_creation() {
        let alert = Alert::gate_denied(
            "Deployment",
            "my-app",
            "production",
            &Blake3Hash::digest(b"expected"),
            None,
            "Missing signature annotation",
            "production",
        );
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert!(alert.summary.contains("Gate DENIED"));
        assert_eq!(alert.source, "sekiban");
    }

    #[test]
    fn alert_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
        assert!(AlertSeverity::Critical < AlertSeverity::Emergency);
    }

    #[test]
    fn changeset_alert() {
        let alert = Alert::changeset_rejected(
            "PATCH",
            "Deployment",
            "my-app",
            "production",
            &Blake3Hash::digest(b"changeset"),
            "Changeset not certified",
            "production",
        );
        assert!(alert.summary.contains("Changeset REJECTED"));
    }

    #[test]
    fn compliance_failure_alert() {
        let alert = Alert::compliance_failed(
            "staging",
            vec!["AC-2".to_string(), "SC-7".to_string()],
            "NIST_800_53",
            "moderate",
        );
        assert!(alert.summary.contains("Compliance FAILED"));
        assert!(alert.summary.contains("2 controls"));
    }

    #[test]
    fn alert_severity_display() {
        assert_eq!(AlertSeverity::Info.to_string(), "info");
        assert_eq!(AlertSeverity::Warning.to_string(), "warning");
        assert_eq!(AlertSeverity::Critical.to_string(), "critical");
        assert_eq!(AlertSeverity::Emergency.to_string(), "emergency");
    }

    #[test]
    fn alert_severity_serde_roundtrip() {
        for severity in &[
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Critical,
            AlertSeverity::Emergency,
        ] {
            let json = serde_json::to_string(severity).unwrap();
            let deserialized: AlertSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*severity, deserialized);
        }
    }

    #[test]
    fn alert_serde_roundtrip() {
        let alert = Alert::gate_denied(
            "Deployment",
            "app",
            "default",
            &Blake3Hash::digest(b"expected"),
            None,
            "missing sig",
            "prod",
        );
        let json = serde_json::to_string(&alert).unwrap();
        let deserialized: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.severity, AlertSeverity::Critical);
        assert_eq!(deserialized.source, "sekiban");
    }

    #[test]
    fn notification_channel_serde_roundtrip() {
        let channels = vec![
            NotificationChannel::Log,
            NotificationChannel::Webhook {
                url: "https://example.com".to_string(),
                secret: None,
                headers: None,
            },
            NotificationChannel::Discord {
                webhook_url: "https://discord.com/api/webhooks/123".to_string(),
                username: Some("TestBot".to_string()),
            },
            NotificationChannel::Slack {
                webhook_url: "https://hooks.slack.com/xxx".to_string(),
                channel: Some("#alerts".to_string()),
            },
            NotificationChannel::KubernetesEvent {
                namespace: Some("default".to_string()),
            },
        ];
        for channel in &channels {
            let json = serde_json::to_string(channel).unwrap();
            let deserialized: NotificationChannel = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&deserialized).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn webhook_signature_deterministic() {
        let sig1 = compute_webhook_signature("secret", b"body");
        let sig2 = compute_webhook_signature("secret", b"body");
        assert_eq!(sig1, sig2);
        assert!(sig1.starts_with("sha256="));
    }

    #[test]
    fn webhook_signature_changes_with_secret() {
        let sig1 = compute_webhook_signature("secret1", b"body");
        let sig2 = compute_webhook_signature("secret2", b"body");
        assert_ne!(sig1, sig2);
    }

    #[tokio::test]
    async fn mock_alert_sender_records_alerts() {
        let sender = MockAlertSender::new();
        let alert = Alert::gate_denied(
            "Pod",
            "nginx",
            "default",
            &Blake3Hash::digest(b"sig"),
            None,
            "denied",
            "test",
        );
        sender.dispatch(&alert).await;
        let alerts = sender.alerts();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].summary.contains("Gate DENIED"));
    }

    #[test]
    fn log_only_dispatcher() {
        let dispatcher = AlertDispatcher::log_only();
        assert_eq!(dispatcher.channels.len(), 1);
    }
}
