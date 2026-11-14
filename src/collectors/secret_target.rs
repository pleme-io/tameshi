//! Secrets-manager target attestation collector.
//!
//! Produces a [`LayerSignature`] from [`SecretTargetAttestation`] records,
//! recording which targets were configured and computing a deterministic
//! hash for the secrets-manager target compliance dimension.
//!
//! Two collector variants are provided:
//!
//! - [`SecretTargetCollector`] — takes pre-built attestations (simple/offline).
//! - [`LiveSecretTargetCollector`] — uses an [`SecretsManagerClient`] to fetch
//!   target details from a live gateway.

use crate::secrets_client::SecretsManagerClient;
use crate::compliance::secret_target::{
    SecretTargetAttestation, compute_multi_target_hash, compute_target_attestation_hash,
};
use crate::error::{Result, TameshiError};
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};

use super::traits::LayerCollector;

/// Collector for secrets-manager target attestation.
///
/// Takes pre-built [`SecretTargetAttestation`] records and produces a
/// [`LayerSignature`] with hashes of all target configurations.
pub struct SecretTargetCollector {
    /// The target attestation data to collect from.
    pub attestations: Vec<SecretTargetAttestation>,
}

impl SecretTargetCollector {
    /// Create a new secrets-manager target collector from attestations.
    #[must_use]
    pub fn new(attestations: Vec<SecretTargetAttestation>) -> Self {
        Self { attestations }
    }
}

impl LayerCollector for SecretTargetCollector {
    async fn collect(&self) -> Result<LayerSignature> {
        let hash = compute_multi_target_hash(&self.attestations);
        let inputs: Vec<InputHash> = self
            .attestations
            .iter()
            .map(|a| InputHash {
                name: a.target_name.clone(),
                hash: compute_target_attestation_hash(a),
                size_bytes: None,
            })
            .collect();

        Ok(LayerSignature {
            layer: self.layer_type(),
            hash,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").to_string(),
                source: "secrets-targets".to_string(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::SecretTarget
    }
}

// ---------------------------------------------------------------------------
// LiveSecretTargetCollector
// ---------------------------------------------------------------------------

/// Collector that uses a live [`SecretsManagerClient`] to build target attestations.
///
/// Authenticates to the gateway, fetches target details, and produces a
/// [`LayerSignature`] from the result.
pub struct LiveSecretTargetCollector<C: SecretsManagerClient> {
    client: C,
    target_names: Vec<String>,
}

impl<C: SecretsManagerClient> LiveSecretTargetCollector<C> {
    /// Create a new live target collector for the given target names.
    #[must_use]
    pub fn new(client: C, target_names: Vec<String>) -> Self {
        Self {
            client,
            target_names,
        }
    }
}

impl<C: SecretsManagerClient> LayerCollector for LiveSecretTargetCollector<C> {
    async fn collect(&self) -> Result<LayerSignature> {
        let attestations = self
            .client
            .build_target_attestation(&self.target_names)
            .await
            .map_err(|e| TameshiError::CollectorError {
                layer: "secret_target".to_string(),
                message: format!("{e}"),
            })?;

        let hash = compute_multi_target_hash(&attestations);
        let inputs: Vec<InputHash> = attestations
            .iter()
            .map(|a| InputHash {
                name: a.target_name.clone(),
                hash: compute_target_attestation_hash(a),
                size_bytes: None,
            })
            .collect();

        Ok(LayerSignature {
            layer: self.layer_type(),
            hash,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").to_string(),
                source: "secrets-targets".to_string(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::SecretTarget
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::secrets::SecretKind;
    use crate::compliance::secret_target::{SecretTargetType, ProducerAssociation};
    use crate::hash::Blake3Hash;

    fn sample_target_attestations() -> Vec<SecretTargetAttestation> {
        vec![
            SecretTargetAttestation {
                target_name: "/targets/prod/database".to_string(),
                target_type: SecretTargetType::Database,
                target_config_hash: Blake3Hash::digest(b"db-config"),
                target_credential_hash: Blake3Hash::digest(b"db-creds"),
                backend_endpoint_hash: Blake3Hash::digest(b"db.prod.internal:5432"),
                backend_tls_cert_hash: Some(Blake3Hash::digest(b"tls-cert")),
                backend_tls_verified: true,
                associated_producers: vec![ProducerAssociation {
                    producer_name: "/producers/db-dynamic".to_string(),
                    producer_type: SecretKind::DynamicDatabase,
                    user_ttl: "1h".to_string(),
                    target_assoc_id: Some("assoc-123".to_string()),
                }],
                attested_at: chrono::Utc::now(),
            },
            SecretTargetAttestation {
                target_name: "/targets/prod/api-gateway".to_string(),
                target_type: SecretTargetType::Web,
                target_config_hash: Blake3Hash::digest(b"web-config"),
                target_credential_hash: Blake3Hash::digest(b"web-creds"),
                backend_endpoint_hash: Blake3Hash::digest(b"api.prod.internal:443"),
                backend_tls_cert_hash: Some(Blake3Hash::digest(b"web-tls-cert")),
                backend_tls_verified: true,
                associated_producers: vec![],
                attested_at: chrono::Utc::now(),
            },
        ]
    }

    #[tokio::test]
    async fn target_collector_produces_signature() {
        let atts = sample_target_attestations();
        let collector = SecretTargetCollector::new(atts);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::SecretTarget);
        assert_eq!(sig.inputs.len(), 2);
        assert_eq!(sig.inputs[0].name, "/targets/prod/database");
        assert_eq!(sig.inputs[1].name, "/targets/prod/api-gateway");
    }

    #[tokio::test]
    async fn target_collector_deterministic() {
        let atts = sample_target_attestations();
        let collector = SecretTargetCollector::new(atts);
        let sig1 = collector.collect().await.unwrap();
        let sig2 = collector.collect().await.unwrap();
        assert_eq!(sig1.hash, sig2.hash);
    }

    #[test]
    fn target_collector_layer_type() {
        let atts = sample_target_attestations();
        let collector = SecretTargetCollector::new(atts);
        assert_eq!(collector.layer_type(), LayerType::SecretTarget);
    }

    #[tokio::test]
    async fn live_target_collector_produces_signature() {
        use crate::secrets_client::MockSecretsManagerClient;

        let atts = sample_target_attestations();
        let client = MockSecretsManagerClient::new().with_target_attestations(atts);
        let collector =
            LiveSecretTargetCollector::new(client, vec!["/targets/prod/database".to_string()]);
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::SecretTarget);
        assert!(!sig.inputs.is_empty());
    }

    #[test]
    fn live_target_collector_layer_type() {
        use crate::secrets_client::MockSecretsManagerClient;

        let client = MockSecretsManagerClient::new();
        let collector =
            LiveSecretTargetCollector::new(client, vec!["/targets/prod/database".to_string()]);
        assert_eq!(collector.layer_type(), LayerType::SecretTarget);
    }
}
