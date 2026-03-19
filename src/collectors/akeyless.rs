//! Akeyless secret management collector.
//!
//! Produces a [`LayerSignature`] from an [`AkeylessSecretAttestation`],
//! recording which secrets were accessed and computing a deterministic
//! hash for the Akeyless compliance dimension.

use crate::compliance::akeyless::{AkeylessSecretAttestation, compute_akeyless_hash};
use crate::error::Result;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Collector for Akeyless secret management attestation.
///
/// Takes a pre-built [`AkeylessSecretAttestation`] and produces a
/// [`LayerSignature`] with hashes of all accessed secrets.
pub struct AkeylessCollector {
    /// The attestation data to collect from.
    pub attestation: AkeylessSecretAttestation,
}

impl AkeylessCollector {
    /// Create a new Akeyless collector from an attestation.
    #[must_use]
    pub fn new(attestation: AkeylessSecretAttestation) -> Self {
        Self { attestation }
    }
}

impl LayerCollector for AkeylessCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let hash = compute_akeyless_hash(&self.attestation);
        let inputs: Vec<InputHash> = self
            .attestation
            .secrets_accessed
            .iter()
            .map(|s| InputHash {
                name: s.path.clone(),
                hash: s.value_hash.clone(),
                size_bytes: None,
            })
            .collect();

        Ok(LayerSignature {
            layer: self.layer_type(),
            hash,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").to_string(),
                source: format!("akeyless:{}", self.attestation.gateway_url),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::Akeyless
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::akeyless::{
        AkeylessAuthMethod, AkeylessSecretAccess, AkeylessSecretType,
    };
    use crate::hash::Blake3Hash;

    fn sample_attestation() -> AkeylessSecretAttestation {
        AkeylessSecretAttestation {
            gateway_url: "https://gw.akeyless.example.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            secrets_accessed: vec![
                AkeylessSecretAccess {
                    path: "/production/db/password".to_string(),
                    secret_type: AkeylessSecretType::Static,
                    value_hash: Blake3Hash::digest(b"secret-value-1"),
                    accessed_at: chrono::Utc::now(),
                    version: Some(1),
                },
                AkeylessSecretAccess {
                    path: "/production/api/key".to_string(),
                    secret_type: AkeylessSecretType::RotatedSecret,
                    value_hash: Blake3Hash::digest(b"secret-value-2"),
                    accessed_at: chrono::Utc::now(),
                    version: Some(3),
                },
            ],
            gateway_certificate_hash: Blake3Hash::digest(b"tls-cert"),
            session_hash: Blake3Hash::digest(b"session-data"),
        }
    }

    #[tokio::test]
    async fn akeyless_collector_produces_signature() {
        let attestation = sample_attestation();
        let collector = AkeylessCollector::new(attestation);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::Akeyless);
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "/production/db/password");
        assert_eq!(sig.inputs[1].name, "/production/api/key");
        assert!(sig.metadata.source.starts_with("akeyless:"));
    }

    #[tokio::test]
    async fn akeyless_collector_deterministic() {
        let attestation = sample_attestation();
        let collector = AkeylessCollector::new(attestation);
        let sig1 = collector.collect().await.unwrap();
        let sig2 = collector.collect().await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[test]
    fn akeyless_collector_layer_type() {
        let attestation = sample_attestation();
        let collector = AkeylessCollector::new(attestation);
        assert_eq!(collector.layer_type(), LayerType::Akeyless);
    }
}
