//! Agent certificates collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's TLS certificate chain
//! fingerprints. Follows the Ferrite collector pattern for struct-based
//! attestation.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Certificate usage purpose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateUsage {
    /// Server TLS certificate.
    ServerTls,
    /// Client mTLS certificate.
    ClientMtls,
    /// Platform API certificate (WhatsApp, Telegram, etc.).
    PlatformApi,
    /// Internal service mesh certificate.
    ServiceMesh,
}

/// A certificate entry in the attestation chain.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CertificateEntry {
    /// Human-readable name for this certificate.
    pub name: String,
    /// SHA-256 fingerprint of the certificate (DER-encoded).
    pub fingerprint_sha256: String,
    /// Certificate usage purpose.
    pub usage: CertificateUsage,
    /// Subject common name (CN).
    pub subject_cn: String,
    /// Issuer common name (CN).
    pub issuer_cn: String,
    /// Not-before date (RFC 3339).
    pub not_before: String,
    /// Not-after date (RFC 3339).
    pub not_after: String,
}

/// Configuration for agent certificates collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCertificatesConfig {
    /// Certificate entries to attest.
    pub certificates: Vec<CertificateEntry>,
    /// Agent name for metadata.
    pub agent_name: String,
}

/// Collector that produces a [`LayerSignature`] from TLS certificate chains.
#[derive(Debug)]
pub struct AgentCertificatesCollector {
    config: AgentCertificatesConfig,
}

impl AgentCertificatesCollector {
    /// Create a new agent certificates collector.
    #[must_use]
    pub fn new(config: AgentCertificatesConfig) -> Self {
        Self { config }
    }
}

impl LayerCollector for AgentCertificatesCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let mut inputs = Vec::new();

        for cert in &self.config.certificates {
            let cert_canonical = serde_json::to_string(cert).unwrap_or_default();
            inputs.push(InputHash {
                name: format!("cert:{}", cert.name),
                hash: Blake3Hash::digest(cert_canonical.as_bytes()),
                size_bytes: Some(cert_canonical.len() as u64),
            });
        }

        // Compute composite hash from sorted inputs
        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher_data = Vec::with_capacity(sorted.len() * 32);
        for input in &sorted {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let composite = if hasher_data.is_empty() {
            Blake3Hash::digest(b"empty-certificates")
        } else {
            Blake3Hash::digest(&hasher_data)
        };

        Ok(LayerSignature {
            layer: LayerType::AgentCertificates,
            hash: composite,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.config.agent_name.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::AgentCertificates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(name: &str, usage: CertificateUsage) -> CertificateEntry {
        CertificateEntry {
            name: name.into(),
            fingerprint_sha256: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99".into(),
            usage,
            subject_cn: format!("{name}.openclaw.io"),
            issuer_cn: "OpenClaw Internal CA".into(),
            not_before: "2025-01-01T00:00:00Z".into(),
            not_after: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn make_config() -> AgentCertificatesConfig {
        AgentCertificatesConfig {
            certificates: vec![
                make_cert("api-server", CertificateUsage::ServerTls),
                make_cert("whatsapp-gateway", CertificateUsage::PlatformApi),
                make_cert("service-mesh", CertificateUsage::ServiceMesh),
            ],
            agent_name: "openclaw".into(),
        }
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = AgentCertificatesCollector::new(make_config());
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentCertificates);
        assert_eq!(sig.inputs.len(), 3);
        assert!(sig.inputs.iter().any(|i| i.name == "cert:api-server"));
        assert!(sig.inputs.iter().any(|i| i.name == "cert:whatsapp-gateway"));
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let c1 = AgentCertificatesCollector::new(make_config());
        let c2 = AgentCertificatesCollector::new(make_config());
        let s1 = c1.collect().await.unwrap();
        let s2 = c2.collect().await.unwrap();
        assert_eq!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_empty_certs_produces_signature() {
        let config = AgentCertificatesConfig {
            certificates: vec![],
            agent_name: "openclaw".into(),
        };
        let collector = AgentCertificatesCollector::new(config);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::AgentCertificates);
        assert!(sig.inputs.is_empty());
    }

    #[tokio::test]
    async fn collect_hash_changes_on_cert_change() {
        let c1 = AgentCertificatesCollector::new(make_config());
        let s1 = c1.collect().await.unwrap();

        let mut config2 = make_config();
        config2
            .certificates
            .push(make_cert("new-cert", CertificateUsage::ClientMtls));
        let c2 = AgentCertificatesCollector::new(config2);
        let s2 = c2.collect().await.unwrap();

        assert_ne!(s1.hash, s2.hash);
    }

    #[test]
    fn layer_type_is_agent_certificates() {
        let collector = AgentCertificatesCollector::new(make_config());
        assert_eq!(collector.layer_type(), LayerType::AgentCertificates);
    }

    #[test]
    fn certificate_usage_serde_roundtrip() {
        for usage in &[
            CertificateUsage::ServerTls,
            CertificateUsage::ClientMtls,
            CertificateUsage::PlatformApi,
            CertificateUsage::ServiceMesh,
        ] {
            let json = serde_json::to_string(usage).unwrap();
            let parsed: CertificateUsage = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, usage);
        }
    }

    #[test]
    fn certificate_entry_serde_roundtrip() {
        let cert = make_cert("test-cert", CertificateUsage::ServerTls);
        let json = serde_json::to_string(&cert).unwrap();
        let deserialized: CertificateEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test-cert");
        assert_eq!(deserialized.subject_cn, "test-cert.openclaw.io");
    }
}
