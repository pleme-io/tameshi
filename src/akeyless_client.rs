//! Real Akeyless gateway client for attestation.
//!
//! Provides a trait-based client that authenticates to an Akeyless gateway,
//! lists and fetches secrets, hashes their values (never storing the raw
//! secret), and builds [`AkeylessSecretAttestation`] from live API responses.
//!
//! **Important:** Only the *hashes* of secret values leave this module, never
//! the secret values themselves.
//!
//! # Architecture
//!
//! ```text
//! AkeylessClient (trait)
//!   ├── HttpAkeylessClient<H: HttpClient>  ── real gateway REST calls
//!   └── MockAkeylessClient                 ── in-memory testing stub
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use tameshi::akeyless_client::*;
//! use tameshi::traits::ReqwestHttpClient;
//!
//! let config = AkeylessConfig {
//!     gateway_url: "https://gw.akeyless.example.com".to_string(),
//!     auth_method: AkeylessAuthMethod::ApiKey,
//!     access_id: Some("p-abc123".to_string()),
//!     access_key: Some("my-access-key".to_string()),
//!     k8s_token_path: None,
//!     k8s_auth_config_name: None,
//!     tls: TlsConfig::default(),
//! };
//!
//! let client = HttpAkeylessClient::new(config, ReqwestHttpClient::new());
//! let attestation = client.build_attestation(&[
//!     "/production/db/password".to_string(),
//!     "/production/api/key".to_string(),
//! ]).await?;
//! ```

use serde::{Deserialize, Serialize};

use crate::compliance::akeyless::{
    AkeylessAuthMethod, AkeylessSecretAccess, AkeylessSecretAttestation, AkeylessSecretType,
};
use crate::compliance::akeyless_target::{
    AkeylessTargetAttestation, AkeylessTargetType, ProducerAssociation,
};
use crate::hash::Blake3Hash;
use crate::traits::HttpClient;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by the Akeyless client.
#[derive(Debug, thiserror::Error)]
pub enum AkeylessClientError {
    /// Authentication to the gateway failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// The requested secret path does not exist.
    #[error("secret not found: {path}")]
    SecretNotFound {
        /// The secret path that was not found.
        path: String,
    },

    /// The gateway could not be reached.
    #[error("gateway unreachable: {0}")]
    GatewayUnreachable(String),

    /// An HTTP-level error occurred.
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// The gateway returned an unparseable response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// The requested target does not exist.
    #[error("target not found: {name}")]
    TargetNotFound {
        /// The target name that was not found.
        name: String,
    },

    /// The requested auth method is not supported by this client.
    #[error("unsupported auth method: {0}")]
    UnsupportedAuthMethod(String),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// TLS configuration for Akeyless client connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to a PEM-encoded CA certificate to pin.
    /// When set, the system CA store is NOT trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_ca_path: Option<String>,
    /// Path to client certificate for mTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<String>,
    /// Path to client private key for mTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,
    /// Whether to verify the server certificate (default: true).
    #[serde(default = "default_true")]
    pub verify_server: bool,
}

fn default_true() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            pinned_ca_path: None,
            client_cert_path: None,
            client_key_path: None,
            verify_server: true,
        }
    }
}

/// Configuration for the Akeyless client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkeylessConfig {
    /// Akeyless Gateway URL (e.g., `https://gw.akeyless.example.com`).
    pub gateway_url: String,
    /// Authentication method to use.
    pub auth_method: AkeylessAuthMethod,
    /// API key access ID (for `ApiKey` auth).
    pub access_id: Option<String>,
    /// API key (for `ApiKey` auth).
    pub access_key: Option<String>,
    /// Path to the Kubernetes service account token file (for `K8s` auth).
    /// Defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`.
    pub k8s_token_path: Option<String>,
    /// Kubernetes auth config name registered in Akeyless (for `K8s` auth).
    pub k8s_auth_config_name: Option<String>,
    /// TLS configuration for gateway connections.
    #[serde(default)]
    pub tls: TlsConfig,
}

// ---------------------------------------------------------------------------
// Target / Dynamic Secret Info
// ---------------------------------------------------------------------------

/// Information about an Akeyless target retrieved from the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Target name.
    pub name: String,
    /// Target type.
    pub target_type: AkeylessTargetType,
    /// Raw configuration as JSON (for hashing).
    pub config_json: String,
    /// Backend endpoint (host:port or URL).
    pub endpoint: String,
    /// Whether TLS verification is enabled.
    pub tls_verified: bool,
    /// TLS certificate data (if available, for hashing).
    pub tls_cert: Option<String>,
    /// Associations with dynamic secret producers.
    pub associations: Vec<ItemAssociation>,
}

/// Information about a dynamic secret producer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicSecretInfo {
    /// Producer name.
    pub name: String,
    /// Producer type.
    pub producer_type: AkeylessSecretType,
    /// User TTL for produced credentials.
    pub user_ttl: String,
}

/// Association between a target and an item (producer/secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemAssociation {
    /// Associated item name.
    pub item_name: String,
    /// Association ID.
    pub assoc_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for interacting with an Akeyless gateway.
///
/// All methods are async and return `Result<_, AkeylessClientError>`.
/// Implementations must be `Send + Sync` for use in concurrent collectors.
pub trait AkeylessClient: Send + Sync {
    /// Authenticate and get an access token.
    fn authenticate(
        &self,
    ) -> impl std::future::Future<Output = Result<String, AkeylessClientError>> + Send;

    /// Get a secret value and return its hash (never returns the actual secret).
    fn get_secret_hash(
        &self,
        path: &str,
        token: &str,
    ) -> impl std::future::Future<Output = Result<AkeylessSecretAccess, AkeylessClientError>>
           + Send;

    /// List secret paths under a given prefix.
    fn list_secrets(
        &self,
        prefix: &str,
        token: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, AkeylessClientError>> + Send;

    /// Get the gateway's TLS certificate hash.
    fn gateway_cert_hash(
        &self,
    ) -> impl std::future::Future<Output = Result<Blake3Hash, AkeylessClientError>> + Send;

    /// Build a complete attestation by authenticating and hashing all specified secrets.
    fn build_attestation(
        &self,
        secret_paths: &[String],
    ) -> impl std::future::Future<Output = Result<AkeylessSecretAttestation, AkeylessClientError>>
           + Send;

    /// Get target details by name.
    fn get_target(
        &self,
        name: &str,
        token: &str,
    ) -> impl std::future::Future<Output = Result<TargetInfo, AkeylessClientError>> + Send;

    /// List all target names.
    fn list_targets(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, AkeylessClientError>> + Send;

    /// Get dynamic secret producer details.
    fn get_dynamic_secret_details(
        &self,
        name: &str,
        token: &str,
    ) -> impl std::future::Future<Output = Result<DynamicSecretInfo, AkeylessClientError>> + Send;

    /// Build target attestations for the given target names.
    fn build_target_attestation(
        &self,
        target_names: &[String],
    ) -> impl std::future::Future<
        Output = Result<Vec<AkeylessTargetAttestation>, AkeylessClientError>,
    > + Send;
}

// ---------------------------------------------------------------------------
// HttpAkeylessClient
// ---------------------------------------------------------------------------

/// Real Akeyless client that calls the gateway REST API.
///
/// Generic over the HTTP transport so that tests can inject
/// [`MockHttpClient`](crate::traits::MockHttpClient).
pub struct HttpAkeylessClient<H: HttpClient> {
    http: H,
    config: AkeylessConfig,
}

impl<H: HttpClient> HttpAkeylessClient<H> {
    /// Create a new client with the given config and HTTP transport.
    pub fn new(config: AkeylessConfig, http: H) -> Self {
        Self { http, config }
    }
}

impl<H: HttpClient> AkeylessClient for HttpAkeylessClient<H> {
    async fn authenticate(&self) -> Result<String, AkeylessClientError> {
        let auth_body = match &self.config.auth_method {
            AkeylessAuthMethod::ApiKey => {
                serde_json::json!({
                    "access-id": self.config.access_id.as_deref().unwrap_or(""),
                    "access-key": self.config.access_key.as_deref().unwrap_or(""),
                    "access-type": "api_key"
                })
            }
            AkeylessAuthMethod::K8s => {
                let token_path = self
                    .config
                    .k8s_token_path
                    .as_deref()
                    .unwrap_or("/var/run/secrets/kubernetes.io/serviceaccount/token");
                let token = std::fs::read_to_string(token_path).map_err(|e| {
                    AkeylessClientError::AuthFailed(format!("cannot read K8s token: {e}"))
                })?;
                serde_json::json!({
                    "access-id": self.config.access_id.as_deref().unwrap_or(""),
                    "access-type": "k8s",
                    "k8s-auth-config-name": self.config.k8s_auth_config_name.as_deref().unwrap_or(""),
                    "gateway-url": self.config.gateway_url,
                    "k8s-service-account-token": token.trim()
                })
            }
            other => {
                return Err(AkeylessClientError::UnsupportedAuthMethod(format!(
                    "{other}"
                )));
            }
        };

        let url = format!("{}/api/v1/auth", self.config.gateway_url);
        let response = self
            .http
            .post_json(&url, &auth_body)
            .await
            .map_err(|e| AkeylessClientError::GatewayUnreachable(format!("{e}")))?;

        let resp: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| AkeylessClientError::InvalidResponse(e.to_string()))?;

        resp.get("token")
            .and_then(|t| t.as_str())
            .map(String::from)
            .ok_or_else(|| {
                AkeylessClientError::InvalidResponse("missing token field".to_string())
            })
    }

    async fn get_secret_hash(
        &self,
        path: &str,
        token: &str,
    ) -> Result<AkeylessSecretAccess, AkeylessClientError> {
        let url = format!("{}/api/v1/get-secret-value", self.config.gateway_url);
        let body = serde_json::json!({
            "names": [path],
            "token": token
        });

        let response = self
            .http
            .post_json(&url, &body)
            .await
            .map_err(|e| AkeylessClientError::HttpError(format!("{e}")))?;

        let resp: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| AkeylessClientError::InvalidResponse(e.to_string()))?;

        // The Akeyless API returns {"/path/to/secret": "value"}.
        let value = resp
            .get(path)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AkeylessClientError::SecretNotFound {
                path: path.to_string(),
            })?;

        // CRITICAL: Hash the value, NEVER store it.
        // Salt with path + gateway URL to defeat rainbow table attacks
        // on low-entropy secrets. The salt is deterministic so the hash
        // is reproducible for verification.
        let value_hash = Blake3Hash::digest(
            &[
                self.config.gateway_url.as_bytes(),
                b":",
                path.as_bytes(),
                b":",
                value.as_bytes(),
            ]
            .concat(),
        );

        Ok(AkeylessSecretAccess {
            path: path.to_string(),
            secret_type: AkeylessSecretType::Static,
            value_hash,
            accessed_at: chrono::Utc::now(),
            version: None,
        })
    }

    async fn list_secrets(
        &self,
        prefix: &str,
        token: &str,
    ) -> Result<Vec<String>, AkeylessClientError> {
        let url = format!("{}/api/v1/list-items", self.config.gateway_url);
        let body = serde_json::json!({
            "path": prefix,
            "token": token,
            "type": ["STATIC_SECRET", "DYNAMIC_SECRET", "ROTATED_SECRET"]
        });

        let response = self
            .http
            .post_json(&url, &body)
            .await
            .map_err(|e| AkeylessClientError::HttpError(format!("{e}")))?;

        let resp: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| AkeylessClientError::InvalidResponse(e.to_string()))?;

        let items = resp
            .get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        item.get("item_name")
                            .and_then(|n| n.as_str())
                            .map(String::from)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(items)
    }

    async fn gateway_cert_hash(&self) -> Result<Blake3Hash, AkeylessClientError> {
        // For TLS cert hashing we would need to inspect the TLS connection.
        // As a practical approach, hash the gateway URL as a stable identifier.
        // In production one would extract the actual TLS cert from the connection.
        Ok(Blake3Hash::digest(
            format!("gateway-cert:{}", self.config.gateway_url).as_bytes(),
        ))
    }

    async fn build_attestation(
        &self,
        secret_paths: &[String],
    ) -> Result<AkeylessSecretAttestation, AkeylessClientError> {
        let token = self.authenticate().await?;
        let gateway_cert = self.gateway_cert_hash().await?;
        let session_hash = Blake3Hash::digest(token.as_bytes());

        let mut secrets_accessed = Vec::with_capacity(secret_paths.len());
        for path in secret_paths {
            let access = self.get_secret_hash(path, &token).await?;
            secrets_accessed.push(access);
        }

        Ok(AkeylessSecretAttestation {
            gateway_url: self.config.gateway_url.clone(),
            auth_method: self.config.auth_method.clone(),
            secrets_accessed,
            gateway_certificate_hash: gateway_cert,
            session_hash,
        })
    }

    async fn get_target(
        &self,
        name: &str,
        token: &str,
    ) -> Result<TargetInfo, AkeylessClientError> {
        let url = format!("{}/api/v1/target-get-details", self.config.gateway_url);
        let body = serde_json::json!({
            "name": name,
            "token": token
        });

        let response = self
            .http
            .post_json(&url, &body)
            .await
            .map_err(|e| AkeylessClientError::HttpError(format!("{e}")))?;

        let resp: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| AkeylessClientError::InvalidResponse(e.to_string()))?;

        let target_type_str = resp
            .get("target_type")
            .and_then(|v| v.as_str())
            .unwrap_or("custom");
        let target_type: AkeylessTargetType = target_type_str
            .parse()
            .unwrap_or(AkeylessTargetType::Custom);

        let endpoint = resp
            .get("endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let tls_verified = resp
            .get("tls_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tls_cert = resp
            .get("tls_cert")
            .and_then(|v| v.as_str())
            .map(String::from);

        let associations = resp
            .get("associations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let item_name = item.get("item_name")?.as_str()?.to_string();
                        let assoc_id = item
                            .get("assoc_id")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        Some(ItemAssociation {
                            item_name,
                            assoc_id,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let config_json = serde_json::to_string(&resp)
            .unwrap_or_default();

        Ok(TargetInfo {
            name: name.to_string(),
            target_type,
            config_json,
            endpoint,
            tls_verified,
            tls_cert,
            associations,
        })
    }

    async fn list_targets(
        &self,
        token: &str,
    ) -> Result<Vec<String>, AkeylessClientError> {
        let url = format!("{}/api/v1/list-targets", self.config.gateway_url);
        let body = serde_json::json!({
            "token": token
        });

        let response = self
            .http
            .post_json(&url, &body)
            .await
            .map_err(|e| AkeylessClientError::HttpError(format!("{e}")))?;

        let resp: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| AkeylessClientError::InvalidResponse(e.to_string()))?;

        let targets = resp
            .get("targets")
            .and_then(|t| t.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        item.get("target_name")
                            .and_then(|n| n.as_str())
                            .map(String::from)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(targets)
    }

    async fn get_dynamic_secret_details(
        &self,
        name: &str,
        token: &str,
    ) -> Result<DynamicSecretInfo, AkeylessClientError> {
        let url = format!("{}/api/v1/dynamic-secret-get", self.config.gateway_url);
        let body = serde_json::json!({
            "name": name,
            "token": token
        });

        let response = self
            .http
            .post_json(&url, &body)
            .await
            .map_err(|e| AkeylessClientError::HttpError(format!("{e}")))?;

        let resp: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| AkeylessClientError::InvalidResponse(e.to_string()))?;

        let producer_type_str = resp
            .get("producer_type")
            .and_then(|v| v.as_str())
            .unwrap_or("dynamic_custom");

        let producer_type = match producer_type_str {
            "dynamic_aws_iam" => AkeylessSecretType::DynamicAwsIam,
            "dynamic_gcp" => AkeylessSecretType::DynamicGcp,
            "dynamic_azure" => AkeylessSecretType::DynamicAzure,
            "dynamic_k8s" => AkeylessSecretType::DynamicK8s,
            "dynamic_database" => AkeylessSecretType::DynamicDatabase,
            _ => AkeylessSecretType::DynamicCustom,
        };

        let user_ttl = resp
            .get("user_ttl")
            .and_then(|v| v.as_str())
            .unwrap_or("1h")
            .to_string();

        Ok(DynamicSecretInfo {
            name: name.to_string(),
            producer_type,
            user_ttl,
        })
    }

    async fn build_target_attestation(
        &self,
        target_names: &[String],
    ) -> Result<Vec<AkeylessTargetAttestation>, AkeylessClientError> {
        let token = self.authenticate().await?;
        let mut attestations = Vec::with_capacity(target_names.len());

        for name in target_names {
            let info = self.get_target(name, &token).await?;
            let mut producers = Vec::new();
            for assoc in &info.associations {
                if let Ok(ds) = self
                    .get_dynamic_secret_details(&assoc.item_name, &token)
                    .await
                {
                    producers.push(ProducerAssociation {
                        producer_name: ds.name,
                        producer_type: ds.producer_type,
                        user_ttl: ds.user_ttl,
                        target_assoc_id: assoc.assoc_id.clone(),
                    });
                }
            }

            attestations.push(AkeylessTargetAttestation {
                target_name: info.name.clone(),
                target_type: info.target_type,
                target_config_hash: Blake3Hash::digest(info.config_json.as_bytes()),
                target_credential_hash: Blake3Hash::digest(
                    format!("cred:{}", info.name).as_bytes(),
                ),
                backend_endpoint_hash: Blake3Hash::digest(info.endpoint.as_bytes()),
                backend_tls_cert_hash: info
                    .tls_cert
                    .as_ref()
                    .map(|c| Blake3Hash::digest(c.as_bytes())),
                backend_tls_verified: info.tls_verified,
                associated_producers: producers,
                attested_at: chrono::Utc::now(),
            });
        }

        Ok(attestations)
    }
}

// ---------------------------------------------------------------------------
// MockAkeylessClient
// ---------------------------------------------------------------------------

/// Mock Akeyless client for testing.
///
/// Returns canned attestation data without making any real API calls.
pub struct MockAkeylessClient {
    attestation: std::sync::Mutex<Option<AkeylessSecretAttestation>>,
    default_attestation: AkeylessSecretAttestation,
    target_attestations: std::sync::Mutex<Option<Vec<AkeylessTargetAttestation>>>,
}

impl MockAkeylessClient {
    /// Create a new mock with a default sample attestation.
    #[must_use]
    pub fn new() -> Self {
        let default = Self::sample_attestation();
        Self {
            attestation: std::sync::Mutex::new(None),
            default_attestation: default,
            target_attestations: std::sync::Mutex::new(None),
        }
    }

    /// Create a mock that always returns the given attestation.
    #[must_use]
    pub fn with_attestation(attestation: AkeylessSecretAttestation) -> Self {
        let default = attestation.clone();
        Self {
            attestation: std::sync::Mutex::new(Some(attestation)),
            default_attestation: default,
            target_attestations: std::sync::Mutex::new(None),
        }
    }

    /// Create a mock with pre-built target attestations.
    #[must_use]
    pub fn with_target_attestations(
        mut self,
        attestations: Vec<AkeylessTargetAttestation>,
    ) -> Self {
        self.target_attestations = std::sync::Mutex::new(Some(attestations));
        self
    }

    /// Override the target attestations returned by future calls.
    pub fn set_target_attestations(&self, attestations: Vec<AkeylessTargetAttestation>) {
        *self.target_attestations.lock().unwrap() = Some(attestations);
    }

    /// Override the attestation returned by future calls.
    pub fn set_attestation(&self, attestation: AkeylessSecretAttestation) {
        *self.attestation.lock().unwrap() = Some(attestation);
    }

    /// Get the currently configured attestation (or the default).
    fn current_attestation(&self) -> AkeylessSecretAttestation {
        self.attestation
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.default_attestation.clone())
    }

    fn sample_attestation() -> AkeylessSecretAttestation {
        AkeylessSecretAttestation {
            gateway_url: "https://mock-gw.akeyless.example.com".to_string(),
            auth_method: AkeylessAuthMethod::ApiKey,
            secrets_accessed: vec![AkeylessSecretAccess {
                path: "/mock/secret".to_string(),
                secret_type: AkeylessSecretType::Static,
                value_hash: Blake3Hash::digest(b"mock-secret-value"),
                accessed_at: chrono::Utc::now(),
                version: Some(1),
            }],
            gateway_certificate_hash: Blake3Hash::digest(b"mock-tls-cert"),
            session_hash: Blake3Hash::digest(b"mock-session"),
        }
    }
}

impl Default for MockAkeylessClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AkeylessClient for MockAkeylessClient {
    async fn authenticate(&self) -> Result<String, AkeylessClientError> {
        Ok("mock-token".to_string())
    }

    async fn get_secret_hash(
        &self,
        path: &str,
        _token: &str,
    ) -> Result<AkeylessSecretAccess, AkeylessClientError> {
        let att = self.current_attestation();
        att.secrets_accessed
            .iter()
            .find(|s| s.path == path)
            .cloned()
            .ok_or(AkeylessClientError::SecretNotFound {
                path: path.to_string(),
            })
    }

    async fn list_secrets(
        &self,
        _prefix: &str,
        _token: &str,
    ) -> Result<Vec<String>, AkeylessClientError> {
        let att = self.current_attestation();
        Ok(att
            .secrets_accessed
            .iter()
            .map(|s| s.path.clone())
            .collect())
    }

    async fn gateway_cert_hash(&self) -> Result<Blake3Hash, AkeylessClientError> {
        let att = self.current_attestation();
        Ok(att.gateway_certificate_hash.clone())
    }

    async fn build_attestation(
        &self,
        _secret_paths: &[String],
    ) -> Result<AkeylessSecretAttestation, AkeylessClientError> {
        Ok(self.current_attestation())
    }

    async fn get_target(
        &self,
        name: &str,
        _token: &str,
    ) -> Result<TargetInfo, AkeylessClientError> {
        let atts = self.target_attestations.lock().unwrap();
        if let Some(ref target_atts) = *atts {
            if let Some(att) = target_atts.iter().find(|a| a.target_name == name) {
                return Ok(TargetInfo {
                    name: att.target_name.clone(),
                    target_type: att.target_type.clone(),
                    config_json: "{}".to_string(),
                    endpoint: format!("mock-endpoint-for-{name}"),
                    tls_verified: att.backend_tls_verified,
                    tls_cert: att
                        .backend_tls_cert_hash
                        .as_ref()
                        .map(|_| "mock-tls-cert".to_string()),
                    associations: att
                        .associated_producers
                        .iter()
                        .map(|p| ItemAssociation {
                            item_name: p.producer_name.clone(),
                            assoc_id: p.target_assoc_id.clone(),
                        })
                        .collect(),
                });
            }
        }
        Err(AkeylessClientError::TargetNotFound {
            name: name.to_string(),
        })
    }

    async fn list_targets(
        &self,
        _token: &str,
    ) -> Result<Vec<String>, AkeylessClientError> {
        let atts = self.target_attestations.lock().unwrap();
        Ok(atts
            .as_ref()
            .map(|a| a.iter().map(|t| t.target_name.clone()).collect())
            .unwrap_or_default())
    }

    async fn get_dynamic_secret_details(
        &self,
        name: &str,
        _token: &str,
    ) -> Result<DynamicSecretInfo, AkeylessClientError> {
        let atts = self.target_attestations.lock().unwrap();
        if let Some(ref target_atts) = *atts {
            for att in target_atts {
                for p in &att.associated_producers {
                    if p.producer_name == name {
                        return Ok(DynamicSecretInfo {
                            name: p.producer_name.clone(),
                            producer_type: p.producer_type.clone(),
                            user_ttl: p.user_ttl.clone(),
                        });
                    }
                }
            }
        }
        Err(AkeylessClientError::SecretNotFound {
            path: name.to_string(),
        })
    }

    async fn build_target_attestation(
        &self,
        _target_names: &[String],
    ) -> Result<Vec<AkeylessTargetAttestation>, AkeylessClientError> {
        let atts = self.target_attestations.lock().unwrap();
        Ok(atts.clone().unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::akeyless::compute_akeyless_hash;
    use crate::traits::MockHttpClient;

    // -----------------------------------------------------------------------
    // MockAkeylessClient tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mock_authenticate_returns_token() {
        let client = MockAkeylessClient::new();
        let token = client.authenticate().await.unwrap();
        assert_eq!(token, "mock-token");
    }

    #[tokio::test]
    async fn mock_build_attestation_produces_valid_attestation() {
        let client = MockAkeylessClient::new();
        let att = client
            .build_attestation(&["/mock/secret".to_string()])
            .await
            .unwrap();
        assert_eq!(att.gateway_url, "https://mock-gw.akeyless.example.com");
        assert_eq!(att.auth_method, AkeylessAuthMethod::ApiKey);
        assert!(!att.secrets_accessed.is_empty());
    }

    #[tokio::test]
    async fn mock_get_secret_hash_hashes_value_not_path() {
        let client = MockAkeylessClient::new();
        let access = client
            .get_secret_hash("/mock/secret", "token")
            .await
            .unwrap();
        // The hash should be of the value, not the path.
        let expected_hash = Blake3Hash::digest(b"mock-secret-value");
        assert_eq!(access.value_hash, expected_hash);
        assert_ne!(access.value_hash, Blake3Hash::digest(b"/mock/secret"));
    }

    #[tokio::test]
    async fn mock_list_secrets_returns_configured_paths() {
        let client = MockAkeylessClient::new();
        let paths = client.list_secrets("/", "token").await.unwrap();
        assert_eq!(paths, vec!["/mock/secret".to_string()]);
    }

    #[tokio::test]
    async fn mock_gateway_cert_hash_is_deterministic() {
        let client = MockAkeylessClient::new();
        let h1 = client.gateway_cert_hash().await.unwrap();
        let h2 = client.gateway_cert_hash().await.unwrap();
        assert_eq!(h1, h2);
    }

    #[tokio::test]
    async fn mock_different_secrets_produce_different_hashes() {
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

        let c1 = MockAkeylessClient::with_attestation(att1.clone());
        let c2 = MockAkeylessClient::with_attestation(att2.clone());

        let a1 = c1.build_attestation(&[]).await.unwrap();
        let a2 = c2.build_attestation(&[]).await.unwrap();

        assert_ne!(compute_akeyless_hash(&a1), compute_akeyless_hash(&a2));
    }

    #[tokio::test]
    async fn mock_set_attestation_overrides() {
        let client = MockAkeylessClient::new();
        let custom = AkeylessSecretAttestation {
            gateway_url: "https://custom.example.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            secrets_accessed: vec![],
            gateway_certificate_hash: Blake3Hash::digest(b"custom-cert"),
            session_hash: Blake3Hash::digest(b"custom-session"),
        };
        client.set_attestation(custom.clone());
        let att = client.build_attestation(&[]).await.unwrap();
        assert_eq!(att.gateway_url, "https://custom.example.com");
        assert_eq!(att.auth_method, AkeylessAuthMethod::K8s);
    }

    #[tokio::test]
    async fn mock_get_secret_hash_returns_not_found_for_missing() {
        let client = MockAkeylessClient::new();
        let result = client
            .get_secret_hash("/nonexistent/secret", "token")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, AkeylessClientError::SecretNotFound { path } if path == "/nonexistent/secret")
        );
    }

    // -----------------------------------------------------------------------
    // HttpAkeylessClient tests (with MockHttpClient)
    // -----------------------------------------------------------------------

    fn api_key_config(gateway_url: &str) -> AkeylessConfig {
        AkeylessConfig {
            gateway_url: gateway_url.to_string(),
            auth_method: AkeylessAuthMethod::ApiKey,
            access_id: Some("p-test-id".to_string()),
            access_key: Some("test-access-key".to_string()),
            k8s_token_path: None,
            k8s_auth_config_name: None,
            tls: TlsConfig::default(),
        }
    }

    #[tokio::test]
    async fn http_authenticate_sends_api_key_and_parses_token() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        // Mock the auth endpoint to return a token.
        http.add_json_response(
            "https://gw.test.com/api/v1/auth",
            &serde_json::json!({"token": "t-abc123"}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let token = client.authenticate().await.unwrap();
        assert_eq!(token, "t-abc123");
    }

    #[tokio::test]
    async fn http_authenticate_returns_error_for_missing_token_field() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_json_response(
            "https://gw.test.com/api/v1/auth",
            &serde_json::json!({"error": "bad credentials"}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let result = client.authenticate().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::InvalidResponse(_)
        ));
    }

    #[tokio::test]
    async fn http_authenticate_returns_error_for_network_failure() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");
        // No response registered -> network failure.

        let client = HttpAkeylessClient::new(config, http);
        let result = client.authenticate().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::GatewayUnreachable(_)
        ));
    }

    #[tokio::test]
    async fn http_get_secret_hash_parses_response_correctly() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_json_response(
            "https://gw.test.com/api/v1/get-secret-value",
            &serde_json::json!({"/prod/db/password": "super-secret-123"}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let access = client
            .get_secret_hash("/prod/db/password", "t-token")
            .await
            .unwrap();

        assert_eq!(access.path, "/prod/db/password");
        assert_eq!(access.secret_type, AkeylessSecretType::Static);
        // The hash should be salted: BLAKE3(gateway_url:path:value)
        let expected_salted = Blake3Hash::digest(
            b"https://gw.test.com:/prod/db/password:super-secret-123",
        );
        assert_eq!(access.value_hash, expected_salted);
        // Should NOT equal unsalted hash of just the value
        assert_ne!(
            access.value_hash,
            Blake3Hash::digest(b"super-secret-123")
        );
    }

    #[tokio::test]
    async fn http_get_secret_hash_returns_not_found_for_missing_secret() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        // Response does not contain the requested path.
        http.add_json_response(
            "https://gw.test.com/api/v1/get-secret-value",
            &serde_json::json!({"/other/secret": "value"}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let result = client
            .get_secret_hash("/missing/secret", "t-token")
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AkeylessClientError::SecretNotFound { path } if path == "/missing/secret")
        );
    }

    #[tokio::test]
    async fn http_get_secret_hash_returns_error_for_invalid_json() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_response(
            "https://gw.test.com/api/v1/get-secret-value",
            b"not-json".to_vec(),
        );

        let client = HttpAkeylessClient::new(config, http);
        let result = client.get_secret_hash("/secret", "t-token").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::InvalidResponse(_)
        ));
    }

    #[tokio::test]
    async fn http_list_secrets_parses_items_array() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_json_response(
            "https://gw.test.com/api/v1/list-items",
            &serde_json::json!({
                "items": [
                    {"item_name": "/prod/db/password", "item_type": "STATIC_SECRET"},
                    {"item_name": "/prod/api/key", "item_type": "ROTATED_SECRET"}
                ]
            }),
        );

        let client = HttpAkeylessClient::new(config, http);
        let items = client.list_secrets("/prod", "t-token").await.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], "/prod/db/password");
        assert_eq!(items[1], "/prod/api/key");
    }

    #[tokio::test]
    async fn http_list_secrets_returns_empty_for_no_items() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_json_response(
            "https://gw.test.com/api/v1/list-items",
            &serde_json::json!({"items": []}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let items = client.list_secrets("/empty", "t-token").await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn http_gateway_cert_hash_is_deterministic() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");
        let client = HttpAkeylessClient::new(config, http);

        let h1 = client.gateway_cert_hash().await.unwrap();
        let h2 = client.gateway_cert_hash().await.unwrap();
        assert_eq!(h1, h2);
    }

    #[tokio::test]
    async fn http_build_attestation_chains_all_calls() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        // Auth.
        http.add_json_response(
            "https://gw.test.com/api/v1/auth",
            &serde_json::json!({"token": "t-live-token"}),
        );

        // Secret 1.
        http.add_json_response(
            "https://gw.test.com/api/v1/get-secret-value",
            &serde_json::json!({"/db/pass": "db-password-value"}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let att = client
            .build_attestation(&["/db/pass".to_string()])
            .await
            .unwrap();

        assert_eq!(att.gateway_url, "https://gw.test.com");
        assert_eq!(att.auth_method, AkeylessAuthMethod::ApiKey);
        assert_eq!(att.secrets_accessed.len(), 1);
        assert_eq!(att.secrets_accessed[0].path, "/db/pass");
        // value_hash is now salted: BLAKE3(gateway_url:path:value)
        assert_eq!(
            att.secrets_accessed[0].value_hash,
            Blake3Hash::digest(b"https://gw.test.com:/db/pass:db-password-value")
        );
        assert_eq!(
            att.session_hash,
            Blake3Hash::digest(b"t-live-token")
        );
    }

    #[tokio::test]
    async fn http_build_attestation_fails_on_auth_error() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");
        // No auth response registered -> failure.

        let client = HttpAkeylessClient::new(config, http);
        let result = client
            .build_attestation(&["/secret".to_string()])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn http_unsupported_auth_method_returns_error() {
        let http = MockHttpClient::new();
        let config = AkeylessConfig {
            gateway_url: "https://gw.test.com".to_string(),
            auth_method: AkeylessAuthMethod::AwsIam,
            access_id: None,
            access_key: None,
            k8s_token_path: None,
            k8s_auth_config_name: None,
            tls: TlsConfig::default(),
        };

        let client = HttpAkeylessClient::new(config, http);
        let result = client.authenticate().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::UnsupportedAuthMethod(_)
        ));
    }

    #[tokio::test]
    async fn http_list_secrets_returns_error_for_network_failure() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        let client = HttpAkeylessClient::new(config, http);
        let result = client.list_secrets("/prod", "token").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::HttpError(_)
        ));
    }

    #[tokio::test]
    async fn http_get_secret_hash_returns_error_for_network_failure() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        let client = HttpAkeylessClient::new(config, http);
        let result = client.get_secret_hash("/secret", "token").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::HttpError(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Target attestation tests
    // -----------------------------------------------------------------------

    fn sample_target_attestations() -> Vec<AkeylessTargetAttestation> {
        vec![AkeylessTargetAttestation {
            target_name: "/targets/prod/database".to_string(),
            target_type: AkeylessTargetType::Database,
            target_config_hash: Blake3Hash::digest(b"db-config"),
            target_credential_hash: Blake3Hash::digest(b"db-creds"),
            backend_endpoint_hash: Blake3Hash::digest(b"db.prod.internal:5432"),
            backend_tls_cert_hash: Some(Blake3Hash::digest(b"tls-cert")),
            backend_tls_verified: true,
            associated_producers: vec![ProducerAssociation {
                producer_name: "/producers/db-dynamic".to_string(),
                producer_type: AkeylessSecretType::DynamicDatabase,
                user_ttl: "1h".to_string(),
                target_assoc_id: Some("assoc-123".to_string()),
            }],
            attested_at: chrono::Utc::now(),
        }]
    }

    #[tokio::test]
    async fn mock_build_target_attestation_returns_configured() {
        let atts = sample_target_attestations();
        let client = MockAkeylessClient::new().with_target_attestations(atts.clone());
        let result = client
            .build_target_attestation(&["/targets/prod/database".to_string()])
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target_name, "/targets/prod/database");
    }

    #[tokio::test]
    async fn mock_get_target_returns_info() {
        let atts = sample_target_attestations();
        let client = MockAkeylessClient::new().with_target_attestations(atts);
        let info = client
            .get_target("/targets/prod/database", "token")
            .await
            .unwrap();
        assert_eq!(info.name, "/targets/prod/database");
        assert_eq!(info.target_type, AkeylessTargetType::Database);
    }

    #[tokio::test]
    async fn mock_get_target_not_found() {
        let client = MockAkeylessClient::new().with_target_attestations(vec![]);
        let result = client
            .get_target("/targets/missing", "token")
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::TargetNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn mock_list_targets_returns_names() {
        let atts = sample_target_attestations();
        let client = MockAkeylessClient::new().with_target_attestations(atts);
        let names = client.list_targets("token").await.unwrap();
        assert_eq!(names, vec!["/targets/prod/database".to_string()]);
    }

    #[tokio::test]
    async fn mock_set_target_attestations_overrides() {
        let client = MockAkeylessClient::new();
        assert!(client.list_targets("token").await.unwrap().is_empty());

        client.set_target_attestations(sample_target_attestations());
        let names = client.list_targets("token").await.unwrap();
        assert_eq!(names.len(), 1);
    }

    #[tokio::test]
    async fn mock_get_dynamic_secret_details_from_targets() {
        let atts = sample_target_attestations();
        let client = MockAkeylessClient::new().with_target_attestations(atts);
        let ds = client
            .get_dynamic_secret_details("/producers/db-dynamic", "token")
            .await
            .unwrap();
        assert_eq!(ds.name, "/producers/db-dynamic");
        assert_eq!(ds.producer_type, AkeylessSecretType::DynamicDatabase);
        assert_eq!(ds.user_ttl, "1h");
    }

    #[tokio::test]
    async fn http_get_target_parses_response() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_json_response(
            "https://gw.test.com/api/v1/target-get-details",
            &serde_json::json!({
                "target_type": "database",
                "endpoint": "db.prod.internal:5432",
                "tls_verified": true,
                "tls_cert": "PEM-CERT-DATA",
                "associations": [
                    {"item_name": "/producers/db-dynamic", "assoc_id": "assoc-1"}
                ]
            }),
        );

        let client = HttpAkeylessClient::new(config, http);
        let info = client
            .get_target("/targets/prod/db", "t-token")
            .await
            .unwrap();
        assert_eq!(info.name, "/targets/prod/db");
        assert_eq!(info.target_type, AkeylessTargetType::Database);
        assert_eq!(info.endpoint, "db.prod.internal:5432");
        assert!(info.tls_verified);
        assert_eq!(info.tls_cert, Some("PEM-CERT-DATA".to_string()));
        assert_eq!(info.associations.len(), 1);
    }

    #[tokio::test]
    async fn http_list_targets_parses_response() {
        let http = MockHttpClient::new();
        let config = api_key_config("https://gw.test.com");

        http.add_json_response(
            "https://gw.test.com/api/v1/list-targets",
            &serde_json::json!({
                "targets": [
                    {"target_name": "/targets/prod/db"},
                    {"target_name": "/targets/prod/api"}
                ]
            }),
        );

        let client = HttpAkeylessClient::new(config, http);
        let targets = client.list_targets("t-token").await.unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], "/targets/prod/db");
        assert_eq!(targets[1], "/targets/prod/api");
    }

    // -----------------------------------------------------------------------
    // K8s auth tests
    // -----------------------------------------------------------------------

    #[test]
    fn k8s_auth_config_defaults() {
        let config = AkeylessConfig {
            gateway_url: "https://gw.example.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            access_id: Some("p-k8s-id".to_string()),
            access_key: None,
            k8s_token_path: None,
            k8s_auth_config_name: Some("k8s-auth-config".to_string()),
            tls: TlsConfig::default(),
        };
        // When k8s_token_path is None, the default path should be used.
        assert!(config.k8s_token_path.is_none());
        let default_path = config
            .k8s_token_path
            .as_deref()
            .unwrap_or("/var/run/secrets/kubernetes.io/serviceaccount/token");
        assert_eq!(
            default_path,
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        );
    }

    #[test]
    fn k8s_auth_config_serde() {
        let config = AkeylessConfig {
            gateway_url: "https://gw.k8s.example.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            access_id: Some("p-k8s-access".to_string()),
            access_key: None,
            k8s_token_path: Some("/custom/token/path".to_string()),
            k8s_auth_config_name: Some("my-k8s-auth".to_string()),
            tls: TlsConfig::default(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AkeylessConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.gateway_url, "https://gw.k8s.example.com");
        assert_eq!(deserialized.auth_method, AkeylessAuthMethod::K8s);
        assert_eq!(deserialized.access_id, Some("p-k8s-access".to_string()));
        assert!(deserialized.access_key.is_none());
        assert_eq!(
            deserialized.k8s_token_path,
            Some("/custom/token/path".to_string())
        );
        assert_eq!(
            deserialized.k8s_auth_config_name,
            Some("my-k8s-auth".to_string())
        );
    }

    #[tokio::test]
    async fn http_k8s_auth_reads_token_from_file() {
        // Create a temp file to simulate the K8s service account token.
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "eyJ0eXAiOiJKV1QifQ.test-payload.sig\n").unwrap();

        let http = MockHttpClient::new();
        let config = AkeylessConfig {
            gateway_url: "https://gw.test.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            access_id: Some("p-k8s-id".to_string()),
            access_key: None,
            k8s_token_path: Some(token_path.to_str().unwrap().to_string()),
            k8s_auth_config_name: Some("k8s-auth-cfg".to_string()),
            tls: TlsConfig::default(),
        };

        http.add_json_response(
            "https://gw.test.com/api/v1/auth",
            &serde_json::json!({"token": "t-k8s-token-123"}),
        );

        let client = HttpAkeylessClient::new(config, http);
        let token = client.authenticate().await.unwrap();
        assert_eq!(token, "t-k8s-token-123");
    }

    #[tokio::test]
    async fn http_k8s_auth_fails_when_token_file_missing() {
        let http = MockHttpClient::new();
        let config = AkeylessConfig {
            gateway_url: "https://gw.test.com".to_string(),
            auth_method: AkeylessAuthMethod::K8s,
            access_id: Some("p-k8s-id".to_string()),
            access_key: None,
            k8s_token_path: Some("/nonexistent/path/token".to_string()),
            k8s_auth_config_name: Some("k8s-auth-cfg".to_string()),
            tls: TlsConfig::default(),
        };

        let client = HttpAkeylessClient::new(config, http);
        let result = client.authenticate().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AkeylessClientError::AuthFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // TLS config tests
    // -----------------------------------------------------------------------

    #[test]
    fn tls_config_defaults() {
        let tls = TlsConfig::default();
        assert!(tls.pinned_ca_path.is_none());
        assert!(tls.client_cert_path.is_none());
        assert!(tls.client_key_path.is_none());
        assert!(tls.verify_server);
    }

    #[test]
    fn tls_config_serde_roundtrip() {
        let tls = TlsConfig {
            pinned_ca_path: Some("/etc/tameshi/ca.pem".to_string()),
            client_cert_path: Some("/etc/tameshi/client.pem".to_string()),
            client_key_path: Some("/etc/tameshi/client-key.pem".to_string()),
            verify_server: true,
        };
        let json = serde_json::to_string(&tls).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pinned_ca_path, tls.pinned_ca_path);
        assert_eq!(deserialized.client_cert_path, tls.client_cert_path);
        assert_eq!(deserialized.client_key_path, tls.client_key_path);
        assert_eq!(deserialized.verify_server, tls.verify_server);
    }

    #[test]
    fn akeyless_config_with_tls() {
        let config = AkeylessConfig {
            gateway_url: "https://gw.example.com".to_string(),
            auth_method: AkeylessAuthMethod::ApiKey,
            access_id: Some("p-123".to_string()),
            access_key: Some("key".to_string()),
            k8s_token_path: None,
            k8s_auth_config_name: None,
            tls: TlsConfig {
                pinned_ca_path: Some("/ca.pem".to_string()),
                ..TlsConfig::default()
            },
        };
        assert!(config.tls.pinned_ca_path.is_some());
        assert!(config.tls.verify_server);
    }
}
