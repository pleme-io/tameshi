//! Akeyless secret management compliance dimension.
//!
//! Provides attestation types for Akeyless secret management integration,
//! recording which secrets were accessed, how authentication was performed,
//! and computing a deterministic compliance hash from these records.
//!
//! **Important:** Only the *hashes* of secret values are stored, never the
//! secret values themselves.

use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// Attestation for Akeyless secret management integration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AkeylessSecretAttestation {
    /// Akeyless Gateway URL.
    pub gateway_url: String,
    /// Authentication method used.
    pub auth_method: AkeylessAuthMethod,
    /// Secrets accessed during the attestation window.
    pub secrets_accessed: Vec<AkeylessSecretAccess>,
    /// Hash of the gateway's TLS certificate.
    pub gateway_certificate_hash: Blake3Hash,
    /// Hash of the authentication session.
    pub session_hash: Blake3Hash,
}

/// Akeyless authentication methods.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AkeylessAuthMethod {
    /// API key authentication.
    ApiKey,
    /// AWS IAM authentication.
    AwsIam,
    /// Azure AD authentication.
    AzureAd,
    /// GCP GCE authentication.
    GcpGce,
    /// Kubernetes authentication.
    K8s,
    /// SAML authentication.
    Saml,
    /// OIDC authentication.
    Oidc,
    /// Certificate authentication.
    Certificate,
    /// Universal identity authentication.
    Universal,
}

impl std::fmt::Display for AkeylessAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "api_key"),
            Self::AwsIam => write!(f, "aws_iam"),
            Self::AzureAd => write!(f, "azure_ad"),
            Self::GcpGce => write!(f, "gcp_gce"),
            Self::K8s => write!(f, "k8s"),
            Self::Saml => write!(f, "saml"),
            Self::Oidc => write!(f, "oidc"),
            Self::Certificate => write!(f, "certificate"),
            Self::Universal => write!(f, "universal"),
        }
    }
}

/// Record of a secret access event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AkeylessSecretAccess {
    /// Secret path in Akeyless.
    pub path: String,
    /// Type of secret.
    pub secret_type: AkeylessSecretType,
    /// Hash of the secret value (NOT the value itself).
    pub value_hash: Blake3Hash,
    /// When the secret was accessed.
    pub accessed_at: chrono::DateTime<chrono::Utc>,
    /// Version of the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

/// Types of Akeyless secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AkeylessSecretType {
    /// Static secret.
    Static,
    /// Dynamic AWS IAM secret.
    DynamicAwsIam,
    /// Dynamic GCP secret.
    DynamicGcp,
    /// Dynamic Azure secret.
    DynamicAzure,
    /// Dynamic Kubernetes secret.
    DynamicK8s,
    /// Dynamic database secret.
    DynamicDatabase,
    /// Dynamic custom secret.
    DynamicCustom,
    /// Rotated secret.
    RotatedSecret,
    /// SSH certificate.
    SshCertificate,
    /// PKI certificate.
    PkiCertificate,
}

impl std::fmt::Display for AkeylessSecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "static"),
            Self::DynamicAwsIam => write!(f, "dynamic_aws_iam"),
            Self::DynamicGcp => write!(f, "dynamic_gcp"),
            Self::DynamicAzure => write!(f, "dynamic_azure"),
            Self::DynamicK8s => write!(f, "dynamic_k8s"),
            Self::DynamicDatabase => write!(f, "dynamic_database"),
            Self::DynamicCustom => write!(f, "dynamic_custom"),
            Self::RotatedSecret => write!(f, "rotated_secret"),
            Self::SshCertificate => write!(f, "ssh_certificate"),
            Self::PkiCertificate => write!(f, "pki_certificate"),
        }
    }
}

/// Compute a deterministic compliance hash for the Akeyless attestation.
///
/// The hash covers the gateway URL, auth method, certificate hash, session hash,
/// and each secret access record (path, type, value hash).
#[must_use]
pub fn compute_akeyless_hash(attestation: &AkeylessSecretAttestation) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(attestation.gateway_url.as_bytes());
    data.extend_from_slice(attestation.auth_method.to_string().as_bytes());
    data.extend_from_slice(attestation.gateway_certificate_hash.as_ref());
    data.extend_from_slice(attestation.session_hash.as_ref());
    for access in &attestation.secrets_accessed {
        data.extend_from_slice(access.path.as_bytes());
        data.extend_from_slice(access.secret_type.to_string().as_bytes());
        data.extend_from_slice(access.value_hash.as_ref());
    }
    Blake3Hash::digest(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attestation() -> AkeylessSecretAttestation {
        AkeylessSecretAttestation {
            gateway_url: "https://gw.akeyless.example.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            secrets_accessed: vec![AkeylessSecretAccess {
                path: "/production/db/password".to_string(),
                secret_type: AkeylessSecretType::Static,
                value_hash: Blake3Hash::digest(b"secret-value"),
                accessed_at: chrono::Utc::now(),
                version: Some(1),
            }],
            gateway_certificate_hash: Blake3Hash::digest(b"tls-cert"),
            session_hash: Blake3Hash::digest(b"session-data"),
        }
    }

    #[test]
    fn akeyless_hash_deterministic() {
        let attestation = sample_attestation();
        let h1 = compute_akeyless_hash(&attestation);
        let h2 = compute_akeyless_hash(&attestation);
        assert_eq!(h1, h2);
    }

    #[test]
    fn akeyless_hash_different_for_different_gateways() {
        let mut a1 = sample_attestation();
        let a2 = sample_attestation();
        a1.gateway_url = "https://other-gw.akeyless.example.com".to_string();
        assert_ne!(compute_akeyless_hash(&a1), compute_akeyless_hash(&a2));
    }

    #[test]
    fn akeyless_hash_different_for_different_secrets() {
        let a1 = sample_attestation();
        let mut a2 = sample_attestation();
        a2.secrets_accessed[0].path = "/production/db/other".to_string();
        assert_ne!(compute_akeyless_hash(&a1), compute_akeyless_hash(&a2));
    }

    #[test]
    fn akeyless_serde_roundtrip() {
        let attestation = sample_attestation();
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: AkeylessSecretAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, deserialized);
    }
}
