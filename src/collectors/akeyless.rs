//! Akeyless secret management collector.
//!
//! Produces a [`LayerSignature`] from an [`AkeylessSecretAttestation`],
//! recording which secrets were accessed and computing a deterministic
//! hash for the Akeyless compliance dimension.
//!
//! Two collector variants are provided:
//!
//! - [`AkeylessCollector`] — takes a pre-built attestation (simple/offline).
//! - [`LiveAkeylessCollector`] — uses an [`AkeylessClient`] to authenticate
//!   and fetch secrets from a live gateway.

use crate::akeyless_client::AkeylessClient;
use crate::compliance::akeyless::{AkeylessSecretAttestation, compute_akeyless_hash};
use crate::error::{Result, TameshiError};
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

// ---------------------------------------------------------------------------
// LiveAkeylessCollector
// ---------------------------------------------------------------------------

/// Collector that uses a live [`AkeylessClient`] to build attestations.
///
/// Authenticates to the gateway, fetches and hashes the specified secrets,
/// and produces a [`LayerSignature`] from the result.
pub struct LiveAkeylessCollector<C: AkeylessClient> {
    client: C,
    secret_paths: Vec<String>,
}

impl<C: AkeylessClient> LiveAkeylessCollector<C> {
    /// Create a new live collector targeting the given secret paths.
    #[must_use]
    pub fn new(client: C, secret_paths: Vec<String>) -> Self {
        Self {
            client,
            secret_paths,
        }
    }
}

impl<C: AkeylessClient> LayerCollector for LiveAkeylessCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let attestation = self
            .client
            .build_attestation(&self.secret_paths)
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "akeyless".to_string(),
                message: format!("{e}"),
            })?;

        let hash = compute_akeyless_hash(&attestation);
        let inputs: Vec<InputHash> = attestation
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
                source: format!("akeyless:{}", attestation.gateway_url),
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

    // -----------------------------------------------------------------------
    // LiveAkeylessCollector tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn live_collector_produces_valid_layer_signature() {
        use crate::akeyless_client::MockAkeylessClient;

        let client = MockAkeylessClient::new();
        let collector = LiveAkeylessCollector::new(client, vec!["/mock/secret".to_string()]);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::Akeyless);
        assert!(sig.metadata.source.starts_with("akeyless:"));
        assert!(!sig.inputs.is_empty());
    }

    #[test]
    fn live_collector_layer_type() {
        use crate::akeyless_client::MockAkeylessClient;

        let client = MockAkeylessClient::new();
        let collector = LiveAkeylessCollector::new(client, vec!["/mock/secret".to_string()]);
        assert_eq!(collector.layer_type(), LayerType::Akeyless);
    }

    #[tokio::test]
    async fn live_collector_different_secrets_produce_different_hashes() {
        use crate::akeyless_client::MockAkeylessClient;

        let att1 = AkeylessSecretAttestation {
            gateway_url: "https://gw.example.com".to_string(),
            auth_method: AkeylessAuthMethod::ApiKey,
            secrets_accessed: vec![AkeylessSecretAccess {
                path: "/secret/a".to_string(),
                secret_type: AkeylessSecretType::Static,
                value_hash: Blake3Hash::digest(b"value-a"),
                accessed_at: chrono::Utc::now(),
                version: None,
            }],
            gateway_certificate_hash: Blake3Hash::digest(b"cert"),
            session_hash: Blake3Hash::digest(b"session"),
        };
        let att2 = AkeylessSecretAttestation {
            gateway_url: "https://gw.example.com".to_string(),
            auth_method: AkeylessAuthMethod::ApiKey,
            secrets_accessed: vec![AkeylessSecretAccess {
                path: "/secret/b".to_string(),
                secret_type: AkeylessSecretType::Static,
                value_hash: Blake3Hash::digest(b"value-b"),
                accessed_at: chrono::Utc::now(),
                version: None,
            }],
            gateway_certificate_hash: Blake3Hash::digest(b"cert"),
            session_hash: Blake3Hash::digest(b"session"),
        };

        let c1 = MockAkeylessClient::with_attestation(att1);
        let c2 = MockAkeylessClient::with_attestation(att2);

        let col1 = LiveAkeylessCollector::new(c1, vec!["/secret/a".to_string()]);
        let col2 = LiveAkeylessCollector::new(c2, vec!["/secret/b".to_string()]);

        let sig1 = col1.collect().await.unwrap();
        let sig2 = col2.collect().await.unwrap();

        assert_ne!(sig1.hash, sig2.hash);
    }
}
