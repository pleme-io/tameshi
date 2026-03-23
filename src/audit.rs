//! Enterprise audit pipeline for kanshi eBPF events.
//!
//! Receives raw `AuditEvent` structs from the kernel ring buffer,
//! enriches them into `EnterpriseSiemAlert` JSON payloads for
//! Splunk, Datadog, or vault audit logs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::bpf_loader::AuditEvent;
use crate::hash::Blake3Hash;

/// MITRE ATT&CK tactic mapping for execution denial events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MitreTactic {
    /// TA0002 — Execution: adversary trying to run code.
    #[serde(rename = "TA0002")]
    Execution,
    /// TA0003 — Persistence: adversary trying to maintain foothold.
    #[serde(rename = "TA0003")]
    Persistence,
    /// TA0004 — Privilege Escalation: adversary trying to gain higher permissions.
    #[serde(rename = "TA0004")]
    PrivilegeEscalation,
    /// TA0005 — Defense Evasion: adversary trying to avoid detection.
    #[serde(rename = "TA0005")]
    DefenseEvasion,
}

/// Reason the execution was denied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DenialReason {
    /// No PoMS receipt found for this binary.
    #[serde(rename = "MISSING_POMS_RECEIPT")]
    MissingPomsReceipt,
    /// PoMS receipt exists but has memory safety violations.
    #[serde(rename = "MEMORY_VIOLATIONS_DETECTED")]
    MemoryViolationsDetected,
}

/// Enterprise SIEM alert produced from a raw kernel audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnterpriseSiemAlert {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: String,
    pub reason: DenialReason,
    pub binary_hash: String,
    pub pid: u32,
    pub uid: u32,
    pub mitre_tactic: MitreTactic,
    pub mitre_technique: String,
    pub source: String,
    pub action_taken: String,
    pub ferrite_version: String,
}

/// Convert a raw kernel `AuditEvent` into an enterprise SIEM alert.
pub fn enrich_audit_event(event: &AuditEvent, reason: DenialReason) -> EnterpriseSiemAlert {
    let hash = Blake3Hash(event.hash);

    let (tactic, technique) = match &reason {
        DenialReason::MissingPomsReceipt => (
            MitreTactic::Execution,
            "T1204 — Unattested Binary Execution".into(),
        ),
        DenialReason::MemoryViolationsDetected => (
            MitreTactic::DefenseEvasion,
            "T1055 — Memory-Unsafe Binary Execution".into(),
        ),
    };

    EnterpriseSiemAlert {
        timestamp: Utc::now(),
        event_type: "EXECUTION_DENIED".into(),
        severity: "CRITICAL".into(),
        reason,
        binary_hash: hash.to_hex(),
        pid: event.pid,
        uid: event.uid,
        mitre_tactic: tactic,
        mitre_technique: technique,
        source: "kanshi-ebpf-enforcer".into(),
        action_taken: "PROCESS_KILLED".into(),
        ferrite_version: "0.1.0".into(),
    }
}

/// Format an alert as pretty-printed JSON for SIEM ingestion.
pub fn format_siem_json(alert: &EnterpriseSiemAlert) -> String {
    serde_json::to_string_pretty(alert).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_denied_event() -> AuditEvent {
        AuditEvent {
            pid: 31337,
            uid: 1000,
            hash: Blake3Hash::digest(b"unattested-gateway-binary").0,
            denied: 1,
        }
    }

    #[test]
    fn enrich_missing_poms() {
        let event = mock_denied_event();
        let alert = enrich_audit_event(&event, DenialReason::MissingPomsReceipt);

        assert_eq!(alert.event_type, "EXECUTION_DENIED");
        assert_eq!(alert.severity, "CRITICAL");
        assert_eq!(alert.reason, DenialReason::MissingPomsReceipt);
        assert_eq!(alert.pid, 31337);
        assert_eq!(alert.uid, 1000);
        assert_eq!(alert.mitre_tactic, MitreTactic::Execution);
        assert_eq!(alert.action_taken, "PROCESS_KILLED");
        assert!(!alert.binary_hash.is_empty());
    }

    #[test]
    fn enrich_memory_violations() {
        let event = mock_denied_event();
        let alert = enrich_audit_event(&event, DenialReason::MemoryViolationsDetected);

        assert_eq!(alert.reason, DenialReason::MemoryViolationsDetected);
        assert_eq!(alert.mitre_tactic, MitreTactic::DefenseEvasion);
        assert!(alert.mitre_technique.contains("T1055"));
    }

    #[test]
    fn siem_json_format() {
        let event = mock_denied_event();
        let alert = enrich_audit_event(&event, DenialReason::MissingPomsReceipt);
        let json = format_siem_json(&alert);

        assert!(json.contains("EXECUTION_DENIED"));
        assert!(json.contains("MISSING_POMS_RECEIPT"));
        assert!(json.contains("31337"));
        assert!(json.contains("TA0002"));
        assert!(json.contains("kanshi-ebpf-enforcer"));
    }

    #[test]
    fn siem_json_parses_back() {
        let event = mock_denied_event();
        let alert = enrich_audit_event(&event, DenialReason::MissingPomsReceipt);
        let json = format_siem_json(&alert);

        let parsed: EnterpriseSiemAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, alert.pid);
        assert_eq!(parsed.reason, alert.reason);
        assert_eq!(parsed.binary_hash, alert.binary_hash);
    }

    #[test]
    fn hash_is_hex_encoded() {
        let event = mock_denied_event();
        let alert = enrich_audit_event(&event, DenialReason::MissingPomsReceipt);
        // BLAKE3 hex is 64 chars.
        assert_eq!(alert.binary_hash.len(), 64);
        assert!(alert.binary_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn print_sample_siem_alert() {
        let event = AuditEvent {
            pid: 8472,
            uid: 0,
            hash: Blake3Hash::digest(b"compromised-gateway-v2.3.1").0,
            denied: 1,
        };
        let alert = enrich_audit_event(&event, DenialReason::MissingPomsReceipt);
        let json = format_siem_json(&alert);
        // This test's log output is the CISO demo slide content.
        eprintln!("\n=== KANSHI SIEM ALERT (Sample for Executive Demo) ===\n{json}\n===\n");
    }
}
