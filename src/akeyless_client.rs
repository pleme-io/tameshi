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

    /// The requested auth method is not supported by this client.
    #[error("unsupported auth method: {0}")]
    UnsupportedAuthMethod(String),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

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
        let value_hash = Blake3Hash::digest(value.as_bytes());

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
}

impl MockAkeylessClient {
    /// Create a new mock with a default sample attestation.
    #[must_use]
    pub fn new() -> Self {
        let default = Self::sample_attestation();
        Self {
            attestation: std::sync::Mutex::new(None),
            default_attestation: default,
        }
    }

    /// Create a mock that always returns the given attestation.
    #[must_use]
    pub fn with_attestation(attestation: AkeylessSecretAttestation) -> Self {
        let default = attestation.clone();
        Self {
            attestation: std::sync::Mutex::new(Some(attestation)),
            default_attestation: default,
        }
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
        // The hash should be of the value, not the path.
        assert_eq!(
            access.value_hash,
            Blake3Hash::digest(b"super-secret-123")
        );
        assert_ne!(
            access.value_hash,
            Blake3Hash::digest(b"/prod/db/password")
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
        assert_eq!(
            att.secrets_accessed[0].value_hash,
            Blake3Hash::digest(b"db-password-value")
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
}
