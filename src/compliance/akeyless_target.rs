//! Akeyless target attestation compliance dimension.
//!
//! Provides attestation types for Akeyless target infrastructure,
//! recording which targets were configured, how they connect to backends,
//! and computing a deterministic compliance hash from these records.
//!
//! **Important:** Only the *hashes* of target configuration and credentials
//! are stored, never the actual values themselves.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::compliance::akeyless::AkeylessSecretType;
use crate::hash::Blake3Hash;

/// Akeyless target types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AkeylessTargetType {
    /// Database target.
    Database,
    /// AWS target.
    Aws,
    /// Azure target.
    Azure,
    /// GCP target.
    Gcp,
    /// Kubernetes target.
    Kubernetes,
    /// EKS target.
    Eks,
    /// GKE target.
    Gke,
    /// SSH target.
    Ssh,
    /// HashiCorp Vault target.
    HashiVault,
    /// RabbitMQ target.
    RabbitMq,
    /// Artifactory target.
    Artifactory,
    /// GitHub target.
    GitHub,
    /// GitLab target.
    GitLab,
    /// DockerHub target.
    DockerHub,
    /// Salesforce target.
    Salesforce,
    /// LDAP target.
    Ldap,
    /// Web target.
    Web,
    /// Windows target.
    Windows,
    /// Let's Encrypt target.
    LetsEncrypt,
    /// ZeroSSL target.
    ZeroSsl,
    /// GoDaddy target.
    GoDaddy,
    /// Sectigo target.
    Sectigo,
    /// GlobalSign target.
    GlobalSign,
    /// GlobalSign Atlas target.
    GlobalSignAtlas,
    /// Ping target.
    Ping,
    /// OpenAI target.
    OpenAi,
    /// Gemini target.
    Gemini,
    /// Splunk target.
    Splunk,
    /// Linked target.
    Linked,
    /// Custom target.
    Custom,
}

impl fmt::Display for AkeylessTargetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => write!(f, "database"),
            Self::Aws => write!(f, "aws"),
            Self::Azure => write!(f, "azure"),
            Self::Gcp => write!(f, "gcp"),
            Self::Kubernetes => write!(f, "kubernetes"),
            Self::Eks => write!(f, "eks"),
            Self::Gke => write!(f, "gke"),
            Self::Ssh => write!(f, "ssh"),
            Self::HashiVault => write!(f, "hashi_vault"),
            Self::RabbitMq => write!(f, "rabbit_mq"),
            Self::Artifactory => write!(f, "artifactory"),
            Self::GitHub => write!(f, "git_hub"),
            Self::GitLab => write!(f, "git_lab"),
            Self::DockerHub => write!(f, "docker_hub"),
            Self::Salesforce => write!(f, "salesforce"),
            Self::Ldap => write!(f, "ldap"),
            Self::Web => write!(f, "web"),
            Self::Windows => write!(f, "windows"),
            Self::LetsEncrypt => write!(f, "lets_encrypt"),
            Self::ZeroSsl => write!(f, "zero_ssl"),
            Self::GoDaddy => write!(f, "go_daddy"),
            Self::Sectigo => write!(f, "sectigo"),
            Self::GlobalSign => write!(f, "global_sign"),
            Self::GlobalSignAtlas => write!(f, "global_sign_atlas"),
            Self::Ping => write!(f, "ping"),
            Self::OpenAi => write!(f, "open_ai"),
            Self::Gemini => write!(f, "gemini"),
            Self::Splunk => write!(f, "splunk"),
            Self::Linked => write!(f, "linked"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for AkeylessTargetType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "database" => Ok(Self::Database),
            "aws" => Ok(Self::Aws),
            "azure" => Ok(Self::Azure),
            "gcp" => Ok(Self::Gcp),
            "kubernetes" => Ok(Self::Kubernetes),
            "eks" => Ok(Self::Eks),
            "gke" => Ok(Self::Gke),
            "ssh" => Ok(Self::Ssh),
            "hashi_vault" | "hashivault" => Ok(Self::HashiVault),
            "rabbit_mq" | "rabbitmq" => Ok(Self::RabbitMq),
            "artifactory" => Ok(Self::Artifactory),
            "git_hub" | "github" => Ok(Self::GitHub),
            "git_lab" | "gitlab" => Ok(Self::GitLab),
            "docker_hub" | "dockerhub" => Ok(Self::DockerHub),
            "salesforce" => Ok(Self::Salesforce),
            "ldap" => Ok(Self::Ldap),
            "web" => Ok(Self::Web),
            "windows" => Ok(Self::Windows),
            "lets_encrypt" | "letsencrypt" => Ok(Self::LetsEncrypt),
            "zero_ssl" | "zerossl" => Ok(Self::ZeroSsl),
            "go_daddy" | "godaddy" => Ok(Self::GoDaddy),
            "sectigo" => Ok(Self::Sectigo),
            "global_sign" | "globalsign" => Ok(Self::GlobalSign),
            "global_sign_atlas" | "globalsignatlas" => Ok(Self::GlobalSignAtlas),
            "ping" => Ok(Self::Ping),
            "open_ai" | "openai" => Ok(Self::OpenAi),
            "gemini" => Ok(Self::Gemini),
            "splunk" => Ok(Self::Splunk),
            "linked" => Ok(Self::Linked),
            "custom" => Ok(Self::Custom),
            other => Err(format!("unknown target type: '{other}'")),
        }
    }
}

/// Association between a target and a dynamic secret producer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProducerAssociation {
    /// Name of the producer (dynamic secret).
    pub producer_name: String,
    /// Type of secret the producer generates.
    pub producer_type: AkeylessSecretType,
    /// User TTL for the produced credentials.
    pub user_ttl: String,
    /// Target association ID (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_assoc_id: Option<String>,
}

/// Attestation for an Akeyless target's infrastructure configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AkeylessTargetAttestation {
    /// Name of the target in Akeyless.
    pub target_name: String,
    /// Type of target.
    pub target_type: AkeylessTargetType,
    /// Hash of the target configuration (connection details, parameters).
    pub target_config_hash: Blake3Hash,
    /// Hash of the target credentials.
    pub target_credential_hash: Blake3Hash,
    /// Hash of the backend endpoint URL/address.
    pub backend_endpoint_hash: Blake3Hash,
    /// Hash of the backend TLS certificate (if TLS is configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_tls_cert_hash: Option<Blake3Hash>,
    /// Whether TLS certificate verification is enabled for the backend.
    pub backend_tls_verified: bool,
    /// Dynamic secret producers associated with this target.
    pub associated_producers: Vec<ProducerAssociation>,
    /// When the attestation was created.
    pub attested_at: chrono::DateTime<chrono::Utc>,
}

/// Compute a deterministic compliance hash for a single target attestation.
///
/// The hash covers the target name, type, config hash, credential hash,
/// backend endpoint hash, TLS cert hash, TLS verification status, and
/// each associated producer (sorted by name for determinism).
#[must_use]
pub fn compute_target_attestation_hash(attestation: &AkeylessTargetAttestation) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(attestation.target_name.as_bytes());
    data.extend_from_slice(attestation.target_type.to_string().as_bytes());
    data.extend_from_slice(attestation.target_config_hash.as_ref());
    data.extend_from_slice(attestation.target_credential_hash.as_ref());
    data.extend_from_slice(attestation.backend_endpoint_hash.as_ref());
    if let Some(ref tls_hash) = attestation.backend_tls_cert_hash {
        data.extend_from_slice(tls_hash.as_ref());
    }
    data.extend_from_slice(if attestation.backend_tls_verified {
        b"tls:verified"
    } else {
        b"tls:unverified"
    });

    // Sort producers by name for determinism.
    let mut sorted_producers = attestation.associated_producers.clone();
    sorted_producers.sort_by(|a, b| a.producer_name.cmp(&b.producer_name));
    for producer in &sorted_producers {
        data.extend_from_slice(producer.producer_name.as_bytes());
        data.extend_from_slice(producer.producer_type.to_string().as_bytes());
        data.extend_from_slice(producer.user_ttl.as_bytes());
    }

    Blake3Hash::digest(&data)
}

/// Compute a deterministic hash over multiple target attestations.
///
/// Targets are sorted by name before hashing to ensure order-independence.
#[must_use]
pub fn compute_multi_target_hash(attestations: &[AkeylessTargetAttestation]) -> Blake3Hash {
    let mut sorted = attestations.to_vec();
    sorted.sort_by(|a, b| a.target_name.cmp(&b.target_name));

    let mut data = Vec::new();
    for att in &sorted {
        let h = compute_target_attestation_hash(att);
        data.extend_from_slice(h.as_ref());
    }
    Blake3Hash::digest(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_target_attestation() -> AkeylessTargetAttestation {
        AkeylessTargetAttestation {
            target_name: "/targets/prod/database".to_string(),
            target_type: AkeylessTargetType::Database,
            target_config_hash: Blake3Hash::digest(b"db-config"),
            target_credential_hash: Blake3Hash::digest(b"db-creds"),
            backend_endpoint_hash: Blake3Hash::digest(b"db.prod.internal:5432"),
            backend_tls_cert_hash: Some(Blake3Hash::digest(b"tls-cert-data")),
            backend_tls_verified: true,
            associated_producers: vec![ProducerAssociation {
                producer_name: "/producers/db-dynamic".to_string(),
                producer_type: AkeylessSecretType::DynamicDatabase,
                user_ttl: "1h".to_string(),
                target_assoc_id: Some("assoc-123".to_string()),
            }],
            attested_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn target_attestation_hash_deterministic() {
        let att = sample_target_attestation();
        let h1 = compute_target_attestation_hash(&att);
        let h2 = compute_target_attestation_hash(&att);
        assert_eq!(h1, h2);
    }

    #[test]
    fn target_attestation_hash_different_for_different_targets() {
        let att1 = sample_target_attestation();
        let mut att2 = sample_target_attestation();
        att2.target_name = "/targets/prod/other-db".to_string();
        assert_ne!(
            compute_target_attestation_hash(&att1),
            compute_target_attestation_hash(&att2)
        );
    }

    #[test]
    fn target_attestation_hash_sensitive_to_endpoint() {
        let att1 = sample_target_attestation();
        let mut att2 = sample_target_attestation();
        att2.backend_endpoint_hash = Blake3Hash::digest(b"db.staging.internal:5432");
        assert_ne!(
            compute_target_attestation_hash(&att1),
            compute_target_attestation_hash(&att2)
        );
    }

    #[test]
    fn target_attestation_hash_sensitive_to_tls_cert() {
        let att1 = sample_target_attestation();
        let mut att2 = sample_target_attestation();
        att2.backend_tls_cert_hash = Some(Blake3Hash::digest(b"new-tls-cert"));
        assert_ne!(
            compute_target_attestation_hash(&att1),
            compute_target_attestation_hash(&att2)
        );
    }

    #[test]
    fn target_attestation_serde_roundtrip() {
        let att = sample_target_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: AkeylessTargetAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn target_type_display_roundtrip() {
        let types = vec![
            AkeylessTargetType::Database,
            AkeylessTargetType::Aws,
            AkeylessTargetType::Azure,
            AkeylessTargetType::Gcp,
            AkeylessTargetType::Kubernetes,
            AkeylessTargetType::Eks,
            AkeylessTargetType::Gke,
            AkeylessTargetType::Ssh,
            AkeylessTargetType::HashiVault,
            AkeylessTargetType::RabbitMq,
            AkeylessTargetType::Artifactory,
            AkeylessTargetType::GitHub,
            AkeylessTargetType::GitLab,
            AkeylessTargetType::DockerHub,
            AkeylessTargetType::Salesforce,
            AkeylessTargetType::Ldap,
            AkeylessTargetType::Web,
            AkeylessTargetType::Windows,
            AkeylessTargetType::LetsEncrypt,
            AkeylessTargetType::ZeroSsl,
            AkeylessTargetType::GoDaddy,
            AkeylessTargetType::Sectigo,
            AkeylessTargetType::GlobalSign,
            AkeylessTargetType::GlobalSignAtlas,
            AkeylessTargetType::Ping,
            AkeylessTargetType::OpenAi,
            AkeylessTargetType::Gemini,
            AkeylessTargetType::Splunk,
            AkeylessTargetType::Linked,
            AkeylessTargetType::Custom,
        ];
        for tt in types {
            let s = tt.to_string();
            let parsed: AkeylessTargetType = s.parse().unwrap();
            assert_eq!(tt, parsed);
        }
    }

    #[test]
    fn multi_target_hash_deterministic() {
        let att1 = sample_target_attestation();
        let mut att2 = sample_target_attestation();
        att2.target_name = "/targets/prod/api-gateway".to_string();
        att2.target_type = AkeylessTargetType::Web;

        let h1 = compute_multi_target_hash(&[att1.clone(), att2.clone()]);
        let h2 = compute_multi_target_hash(&[att1, att2]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn multi_target_hash_order_independent() {
        let att1 = sample_target_attestation();
        let mut att2 = sample_target_attestation();
        att2.target_name = "/targets/prod/api-gateway".to_string();
        att2.target_type = AkeylessTargetType::Web;

        let h_forward = compute_multi_target_hash(&[att1.clone(), att2.clone()]);
        let h_reverse = compute_multi_target_hash(&[att2, att1]);
        assert_eq!(h_forward, h_reverse);
    }

    #[test]
    fn producer_association_sorting_is_deterministic() {
        let mut att1 = sample_target_attestation();
        att1.associated_producers = vec![
            ProducerAssociation {
                producer_name: "/producers/z-producer".to_string(),
                producer_type: AkeylessSecretType::DynamicDatabase,
                user_ttl: "2h".to_string(),
                target_assoc_id: None,
            },
            ProducerAssociation {
                producer_name: "/producers/a-producer".to_string(),
                producer_type: AkeylessSecretType::DynamicCustom,
                user_ttl: "30m".to_string(),
                target_assoc_id: None,
            },
        ];

        let mut att2 = att1.clone();
        att2.associated_producers.reverse();

        assert_eq!(
            compute_target_attestation_hash(&att1),
            compute_target_attestation_hash(&att2)
        );
    }

    #[test]
    fn target_type_from_str_invalid() {
        let result = "nonexistent_type".parse::<AkeylessTargetType>();
        assert!(result.is_err());
    }
}
