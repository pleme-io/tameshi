use crate::api::types::*;
use std::fmt::Write;

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

pub fn format_get_audit_trail(data: &Vec<AuditEntry>) -> String {
    format!("{:#?}", data)
}

pub fn format_list_certifications(data: &Vec<CertificationSummary>) -> String {
    format!("{:#?}", data)
}

pub fn format_get_certification(data: &Certification) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Name: {}", data.name);
    let _ = writeln!(out, "Namespace: {}", data.namespace);
    let _ = writeln!(out, "Spec: {}", data.spec);
    let _ = writeln!(out, "Status: {}", data.status);
    out
}

pub fn format_certify_product(data: &ApiResponseCertifyResponse) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Data: {}", data.data);
    out
}

pub fn format_get_compliance_hash(data: &ApiResponseHashResponse) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Data: {}", data.data);
    out
}

pub fn format_get_compliance_report(data: &serde_json::Value) -> String {
    format!("{:#?}", data)
}

pub fn format_list_compliance_results(data: &ApiResponseResultSummaryList) -> String {
    if data.data.is_empty() {
        return "No results found.".into();
    }
    let mut out = format!("{} results:\n", data.data.len());
    for item in &data.data {
        let _ = writeln!(out, "  {} | {} | {} | {}", item.all_satisfied, item.baseline, item.compliance_hash, item.environment);
    }
    out
}

pub fn format_get_compliance_result(data: &ComplianceResult) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "All Satisfied: {}", data.all_satisfied);
    let _ = writeln!(out, "Assessment Result: {}", data.assessment_result);
    let _ = writeln!(out, "Baseline: {}", data.baseline);
    let _ = writeln!(out, "Catalog Hash: {}", data.catalog_hash);
    let _ = writeln!(out, "Compliance Hash: {}", data.compliance_hash);
    let _ = writeln!(out, "Computed At: {}", data.computed_at);
    let _ = writeln!(out, "Environment: {}", data.environment);
    let _ = writeln!(out, "Framework Hash: {}", data.framework_hash);
    let _ = writeln!(out, "Id: {}", data.id);
    out
}

pub fn format_run_compliance_assessment(data: &ApiResponseRunResponse) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Data: {}", data.data);
    out
}

pub fn format_list_gates(data: &Vec<GateSummary>) -> String {
    format!("{:#?}", data)
}

pub fn format_get_gate(data: &SignatureGate) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Name: {}", data.name);
    let _ = writeln!(out, "Namespace: {}", data.namespace);
    let _ = writeln!(out, "Spec: {}", data.spec);
    let _ = writeln!(out, "Status: {}", data.status);
    out
}

pub fn format_verify_gate(data: &GateVerifyResult) -> String {
    let mut out = String::with_capacity(512);
    if let Some(ref v) = data.current_signature {
        let _ = writeln!(out, "Current Signature: {v}");
    }
    if let Some(ref v) = data.expected_signature {
        let _ = writeln!(out, "Expected Signature: {v}");
    }
    if let Some(ref v) = data.layer_statuses {
        let _ = writeln!(out, "Layer Statuses: {v}");
    }
    let _ = writeln!(out, "Name: {}", data.name);
    let _ = writeln!(out, "Phase: {}", data.phase);
    let _ = writeln!(out, "Verified: {}", data.verified);
    out
}

pub fn format_compute_signature(data: &ComputeSignatureResponse) -> String {
    if data.layers.is_empty() {
        return "No results found.".into();
    }
    let mut out = format!("{} results:\n", data.layers.len());
    for item in &data.layers {
        let _ = writeln!(out, "  {}", item);
    }
    out
}

