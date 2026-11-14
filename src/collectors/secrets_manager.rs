//! Secrets-manager secret management collector.
//!
//! Produces a [`LayerSignature`] from an [`SecretAttestation`],
//! recording which secrets were accessed and computing a deterministic
//! hash for the secrets-manager compliance dimension.
//!
//! Two collector variants are provided:
//!
//! - [`SecretsManagerCollector`] — takes a pre-built attestation (simple/offline).
//! - [`LiveSecretsManagerCollector`] — uses an [`SecretsManagerClient`] to authenticate
//!   and fetch secrets from a live gateway.

use crate::secrets_client::SecretsManagerClient;
use crate::compliance::secrets::{SecretAttestation, compute_secret_hash};
use crate::error::{Result, TameshiError};
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Collector for secrets-manager secret management attestation.
///
/// Takes a pre-built [`SecretAttestation`] and produces a
/// [`LayerSignature`] with hashes of all accessed secrets.
pub struct SecretsManagerCollector {
    /// The attestation data to collect from.
    pub attestation: SecretAttestation,
}

impl SecretsManagerCollector {
    /// Create a new secrets-manager collector from an attestation.
    #[must_use]
    pub fn new(attestation: SecretAttestation) -> Self {
        Self { attestation }
    }
}

impl LayerCollector for SecretsManagerCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let hash = compute_secret_hash(&self.attestation);
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
                source: format!("secrets_manager:{}", self.attestation.gateway_url),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::SecretsManager
    }
}

// ---------------------------------------------------------------------------
// LiveSecretsManagerCollector
// ---------------------------------------------------------------------------

/// Collector that uses a live [`SecretsManagerClient`] to build attestations.
///
/// Authenticates to the gateway, fetches and hashes the specified secrets,
/// and produces a [`LayerSignature`] from the result.
pub struct LiveSecretsManagerCollector<C: SecretsManagerClient> {
    client: C,
    secret_paths: Vec<String>,
}

impl<C: SecretsManagerClient> LiveSecretsManagerCollector<C> {
    /// Create a new live collector targeting the given secret paths.
    #[must_use]
    pub fn new(client: C, secret_paths: Vec<String>) -> Self {
        Self {
            client,
            secret_paths,
        }
    }
}

impl<C: SecretsManagerClient> LayerCollector for LiveSecretsManagerCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let attestation = self
            .client
            .build_attestation(&self.secret_paths)
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "secrets_manager".to_string(),
                message: format!("{e}"),
            })?;

        let hash = compute_secret_hash(&attestation);
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
                source: format!("secrets_manager:{}", attestation.gateway_url),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::SecretsManager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::secrets::{
        SecretAuthMethod, SecretAccess, SecretKind,
    };
    use crate::hash::Blake3Hash;

    fn sample_attestation() -> SecretAttestation {
        SecretAttestation {
            gateway_url: "https://gw.secrets.example.com".to_string(),
            auth_method: SecretAuthMethod::K8s,
            secrets_accessed: vec![
                SecretAccess {
                    path: "/production/db/password".to_string(),
                    secret_type: SecretKind::Static,
                    value_hash: Blake3Hash::digest(b"secret-value-1"),
                    accessed_at: chrono::Utc::now(),
                    version: Some(1),
                },
                SecretAccess {
                    path: "/production/api/key".to_string(),
                    secret_type: SecretKind::RotatedSecret,
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
    async fn secrets_manager_collector_produces_signature() {
        let attestation = sample_attestation();
        let collector = SecretsManagerCollector::new(attestation);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::SecretsManager);
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "/production/db/password");
        assert_eq!(sig.inputs[1].name, "/production/api/key");
        assert!(sig.metadata.source.starts_with("secrets_manager:"));
    }

    #[tokio::test]
    async fn secrets_manager_collector_deterministic() {
        let attestation = sample_attestation();
        let collector = SecretsManagerCollector::new(attestation);
        let sig1 = collector.collect().await.unwrap();
        let sig2 = collector.collect().await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[test]
    fn secrets_manager_collector_layer_type() {
        let attestation = sample_attestation();
        let collector = SecretsManagerCollector::new(attestation);
        assert_eq!(collector.layer_type(), LayerType::SecretsManager);
    }

    // -----------------------------------------------------------------------
    // LiveSecretsManagerCollector tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn live_collector_produces_valid_layer_signature() {
        use crate::secrets_client::MockSecretsManagerClient;

        let client = MockSecretsManagerClient::new();
        let collector = LiveSecretsManagerCollector::new(client, vec!["/mock/secret".to_string()]);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::SecretsManager);
        assert!(sig.metadata.source.starts_with("secrets_manager:"));
        assert!(!sig.inputs.is_empty());
    }

    #[test]
    fn live_collector_layer_type() {
        use crate::secrets_client::MockSecretsManagerClient;

        let client = MockSecretsManagerClient::new();
        let collector = LiveSecretsManagerCollector::new(client, vec!["/mock/secret".to_string()]);
        assert_eq!(collector.layer_type(), LayerType::SecretsManager);
    }

    #[tokio::test]
    async fn live_collector_different_secrets_produce_different_hashes() {
        use crate::secrets_client::MockSecretsManagerClient;

        let att1 = SecretAttestation {
            gateway_url: "https://gw.example.com".to_string(),
            auth_method: SecretAuthMethod::ApiKey,
            secrets_accessed: vec![SecretAccess {
                path: "/secret/a".to_string(),
                secret_type: SecretKind::Static,
                value_hash: Blake3Hash::digest(b"value-a"),
                accessed_at: chrono::Utc::now(),
                version: None,
            }],
            gateway_certificate_hash: Blake3Hash::digest(b"cert"),
            session_hash: Blake3Hash::digest(b"session"),
        };
        let att2 = SecretAttestation {
            gateway_url: "https://gw.example.com".to_string(),
            auth_method: SecretAuthMethod::ApiKey,
            secrets_accessed: vec![SecretAccess {
                path: "/secret/b".to_string(),
                secret_type: SecretKind::Static,
                value_hash: Blake3Hash::digest(b"value-b"),
                accessed_at: chrono::Utc::now(),
                version: None,
            }],
            gateway_certificate_hash: Blake3Hash::digest(b"cert"),
            session_hash: Blake3Hash::digest(b"session"),
        };

        let c1 = MockSecretsManagerClient::with_attestation(att1);
        let c2 = MockSecretsManagerClient::with_attestation(att2);

        let col1 = LiveSecretsManagerCollector::new(c1, vec!["/secret/a".to_string()]);
        let col2 = LiveSecretsManagerCollector::new(c2, vec!["/secret/b".to_string()]);

        let sig1 = col1.collect().await.unwrap();
        let sig2 = col2.collect().await.unwrap();

        assert_ne!(sig1.hash, sig2.hash);
    }
}
