//! Mock Akeyless gateway for deterministic, offline testing.
//!
//! Starts an in-process axum HTTP server that mimics the Akeyless REST API.
//! Responses are deterministic and configurable for test scenarios.
//!
//! # Supported Endpoints
//!
//! | Endpoint | Description |
//! |----------|-------------|
//! | `POST /auth` | Returns a fixed mock token |
//! | `POST /get-secret-value` | Returns configurable secret values |
//! | `POST /sign-data-with-classic-key` | Returns a deterministic BLAKE3 signature |
//! | `POST /verify-data-with-classic-key` | Verifies against the mock signature |
//! | `POST /list-items` | Returns configurable secret paths |
//! | `POST /describe-item` | Returns item metadata |
//! | `POST /get-target-details` | Returns target configuration |
//! | `POST /hmac` | Returns HMAC of provided data |
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() {
//! use tameshi::testing::akeyless_mock::MockAkeylessGateway;
//!
//! let mock = MockAkeylessGateway::builder()
//!     .with_secret("/production/db/password", "mock-password-123")
//!     .with_secret("/production/api/key", "mock-api-key")
//!     .with_target("db-target", "mysql", "db.example.com:3306")
//!     .with_signing_key("test-dfc-key")
//!     .build()
//!     .await;
//!
//! let url = mock.url(); // e.g., "http://127.0.0.1:PORT"
//! // Use url in AkeylessConfig for testing
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::hash::Blake3Hash;

// ---------------------------------------------------------------------------
// Mock State
// ---------------------------------------------------------------------------

/// Internal state shared across all mock handler threads.
#[derive(Debug, Clone)]
struct MockState {
    /// The fixed auth token returned by `/auth`.
    token: String,
    /// Map of secret path -> secret value.
    secrets: HashMap<String, String>,
    /// Map of target name -> (target_type, endpoint).
    targets: HashMap<String, TargetEntry>,
    /// Signing keys registered for DFC operations.
    signing_keys: Vec<String>,
    /// HMAC key seed (deterministic).
    hmac_seed: [u8; 32],
}

/// A mock target entry.
#[derive(Debug, Clone)]
struct TargetEntry {
    target_type: String,
    endpoint: String,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`MockAkeylessGateway`].
///
/// Configure mock responses before starting the server.
#[derive(Debug, Clone)]
pub struct MockAkeylessGatewayBuilder {
    token: String,
    secrets: HashMap<String, String>,
    targets: HashMap<String, TargetEntry>,
    signing_keys: Vec<String>,
    hmac_seed: [u8; 32],
}

impl Default for MockAkeylessGatewayBuilder {
    fn default() -> Self {
        Self {
            token: "mock-akeyless-token-00000000".to_string(),
            secrets: HashMap::new(),
            targets: HashMap::new(),
            signing_keys: Vec::new(),
            hmac_seed: [42u8; 32],
        }
    }
}

impl MockAkeylessGatewayBuilder {
    /// Register a secret at the given path with the given value.
    #[must_use]
    pub fn with_secret(mut self, path: &str, value: &str) -> Self {
        self.secrets.insert(path.to_string(), value.to_string());
        self
    }

    /// Register a target with name, type, and endpoint.
    #[must_use]
    pub fn with_target(mut self, name: &str, target_type: &str, endpoint: &str) -> Self {
        self.targets.insert(
            name.to_string(),
            TargetEntry {
                target_type: target_type.to_string(),
                endpoint: endpoint.to_string(),
            },
        );
        self
    }

    /// Register a signing key name for DFC operations.
    #[must_use]
    pub fn with_signing_key(mut self, key_name: &str) -> Self {
        self.signing_keys.push(key_name.to_string());
        self
    }

    /// Override the default auth token.
    #[must_use]
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = token.to_string();
        self
    }

    /// Override the HMAC seed (default: `[42u8; 32]`).
    #[must_use]
    pub fn with_hmac_seed(mut self, seed: [u8; 32]) -> Self {
        self.hmac_seed = seed;
        self
    }

    /// Build and start the mock server.
    ///
    /// Binds to `127.0.0.1:0` for an OS-assigned ephemeral port.
    pub async fn build(self) -> MockAkeylessGateway {
        let state = Arc::new(Mutex::new(MockState {
            token: self.token,
            secrets: self.secrets,
            targets: self.targets,
            signing_keys: self.signing_keys,
            hmac_seed: self.hmac_seed,
        }));

        let app = Router::new()
            .route("/auth", post(handle_auth))
            .route("/get-secret-value", post(handle_get_secret_value))
            .route(
                "/sign-data-with-classic-key",
                post(handle_sign_data),
            )
            .route(
                "/verify-data-with-classic-key",
                post(handle_verify_data),
            )
            .route("/list-items", post(handle_list_items))
            .route("/describe-item", post(handle_describe_item))
            .route("/get-target-details", post(handle_get_target_details))
            .route("/hmac", post(handle_hmac))
            .fallback(handle_fallback)
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock server");
        let addr = listener.local_addr().expect("failed to get local addr");
        let url = format!("http://127.0.0.1:{}", addr.port());

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock server failed");
        });

        MockAkeylessGateway {
            url,
            _handle: handle,
            state,
        }
    }
}

// ---------------------------------------------------------------------------
// MockAkeylessGateway
// ---------------------------------------------------------------------------

/// Mock Akeyless gateway for testing.
///
/// Starts an in-process HTTP server that mimics the Akeyless API.
/// Responses are deterministic and configurable for test scenarios.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() {
/// use tameshi::testing::akeyless_mock::MockAkeylessGateway;
///
/// let mock = MockAkeylessGateway::builder()
///     .with_secret("/production/db/password", "mock-password-123")
///     .with_secret("/production/api/key", "mock-api-key")
///     .with_target("db-target", "mysql", "db.example.com:3306")
///     .with_signing_key("test-dfc-key")
///     .build()
///     .await;
///
/// let url = mock.url(); // e.g., "http://127.0.0.1:PORT"
/// // Use url in AkeylessConfig for testing
/// # }
/// ```
pub struct MockAkeylessGateway {
    url: String,
    #[allow(dead_code)]
    _handle: tokio::task::JoinHandle<()>,
    state: Arc<Mutex<MockState>>,
}

impl MockAkeylessGateway {
    /// Create a new builder.
    #[must_use]
    pub fn builder() -> MockAkeylessGatewayBuilder {
        MockAkeylessGatewayBuilder::default()
    }

    /// The base URL of the mock server (e.g., `http://127.0.0.1:12345`).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Dynamically add a secret at runtime.
    pub async fn add_secret(&self, path: &str, value: &str) {
        let mut state = self.state.lock().await;
        state.secrets.insert(path.to_string(), value.to_string());
    }

    /// Dynamically add a target at runtime.
    pub async fn add_target(&self, name: &str, target_type: &str, endpoint: &str) {
        let mut state = self.state.lock().await;
        state.targets.insert(
            name.to_string(),
            TargetEntry {
                target_type: target_type.to_string(),
                endpoint: endpoint.to_string(),
            },
        );
    }

    /// Get the current number of registered secrets.
    pub async fn secret_count(&self) -> usize {
        self.state.lock().await.secrets.len()
    }

    /// Get the current number of registered targets.
    pub async fn target_count(&self) -> usize {
        self.state.lock().await.targets.len()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

type AppState = Arc<Mutex<MockState>>;

/// `POST /auth` -- always returns a mock token.
async fn handle_auth(State(state): State<AppState>, Json(_body): Json<Value>) -> impl IntoResponse {
    let st = state.lock().await;
    Json(json!({ "token": st.token }))
}

/// `POST /get-secret-value` -- returns the configured secret value.
async fn handle_get_secret_value(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let name = body
        .get("names")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .or_else(|| body.get("name").and_then(Value::as_str))
        .unwrap_or("");

    let st = state.lock().await;
    if let Some(value) = st.secrets.get(name) {
        (
            StatusCode::OK,
            Json(json!({ name: value })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("secret not found: {name}")
            })),
        )
    }
}

/// `POST /sign-data-with-classic-key` -- deterministic BLAKE3 signature.
///
/// Uses BLAKE3 keyed hash: `H(key_name_bytes || data_bytes)` for determinism.
async fn handle_sign_data(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let key_name = body
        .get("key-name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let data_hex = body.get("data").and_then(Value::as_str).unwrap_or("");

    let st = state.lock().await;
    if !st.signing_keys.contains(&key_name.to_string()) && !st.signing_keys.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("key not found: {key_name}")
            })),
        );
    }

    let data_bytes = const_hex::decode(data_hex).unwrap_or_default();
    let sig = mock_sign(key_name.as_bytes(), &data_bytes);
    let sig_hex = const_hex::encode(sig);

    (StatusCode::OK, Json(json!({ "result": sig_hex })))
}

/// `POST /verify-data-with-classic-key` -- verify against mock signature.
async fn handle_verify_data(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let key_name = body
        .get("key-name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let data_hex = body.get("data").and_then(Value::as_str).unwrap_or("");
    let sig_hex = body
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or("");

    let st = state.lock().await;
    if !st.signing_keys.contains(&key_name.to_string()) && !st.signing_keys.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("key not found: {key_name}")
            })),
        );
    }

    let data_bytes = const_hex::decode(data_hex).unwrap_or_default();
    let expected_sig = mock_sign(key_name.as_bytes(), &data_bytes);
    let provided_sig = const_hex::decode(sig_hex).unwrap_or_default();

    let valid = expected_sig == provided_sig.as_slice();
    (StatusCode::OK, Json(json!({ "result": valid })))
}

/// `POST /list-items` -- returns configured secret paths matching an optional prefix.
async fn handle_list_items(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let path = body.get("path").and_then(Value::as_str).unwrap_or("/");

    let st = state.lock().await;
    let items: Vec<Value> = st
        .secrets
        .keys()
        .filter(|k| k.starts_with(path))
        .map(|k| {
            json!({
                "item_name": k,
                "item_type": "STATIC_SECRET",
                "item_size": 0,
            })
        })
        .collect();

    Json(json!({ "items": items }))
}

/// `POST /describe-item` -- returns item metadata.
async fn handle_describe_item(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let name = body.get("name").and_then(Value::as_str).unwrap_or("");

    let st = state.lock().await;
    if st.secrets.contains_key(name) {
        (
            StatusCode::OK,
            Json(json!({
                "item_name": name,
                "item_type": "STATIC_SECRET",
                "item_metadata": "mock-metadata",
                "item_general_info": {
                    "certs_expiration_date_in_unix_time": 0,
                },
                "item_targets_assoc": [],
                "item_versions_info": {
                    "1": {
                        "status": "Active",
                        "creation_date": "2026-01-01T00:00:00Z"
                    }
                },
                "protection_key_name": "default-protection-key",
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("item not found: {name}")
            })),
        )
    }
}

/// `POST /get-target-details` -- returns target configuration.
async fn handle_get_target_details(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let name = body.get("name").and_then(Value::as_str).unwrap_or("");

    let st = state.lock().await;
    if let Some(target) = st.targets.get(name) {
        (
            StatusCode::OK,
            Json(json!({
                "value": {
                    "name": name,
                    "target_type": target.target_type,
                    "target_details": {
                        "host": target.endpoint,
                    },
                    "with_customer_fragment": false,
                    "protection_key_name": "default-protection-key",
                    "target_items_assoc": [],
                },
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("target not found: {name}")
            })),
        )
    }
}

/// `POST /hmac` -- returns a deterministic HMAC of the provided data.
async fn handle_hmac(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let key_name = body
        .get("key-name")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let data_hex = body.get("data").and_then(Value::as_str).unwrap_or("");

    let st = state.lock().await;
    let data_bytes = const_hex::decode(data_hex).unwrap_or_default();

    // Deterministic HMAC: H(hmac_seed || key_name || data)
    let mut input = Vec::with_capacity(32 + key_name.len() + data_bytes.len());
    input.extend_from_slice(&st.hmac_seed);
    input.extend_from_slice(key_name.as_bytes());
    input.extend_from_slice(&data_bytes);
    let hmac = Blake3Hash::digest(&input);
    let hmac_hex = const_hex::encode(hmac.0);

    Json(json!({ "result": hmac_hex }))
}

/// Fallback handler for unknown routes.
async fn handle_fallback() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "unknown endpoint"
        })),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic mock signature: BLAKE3(`key_name || data`).
fn mock_sign(key_name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(key_name.len() + data.len());
    input.extend_from_slice(key_name);
    input.extend_from_slice(data);
    let hash = Blake3Hash::digest(&input);
    hash.0.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a reqwest client for testing.
    fn http_client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[tokio::test]
    async fn mock_auth_returns_token() {
        let mock = MockAkeylessGateway::builder()
            .with_token("test-token-42")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/auth", mock.url()))
            .json(&json!({
                "access-id": "p-123",
                "access-key": "key",
                "access-type": "api_key",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["token"], "test-token-42");
    }

    #[tokio::test]
    async fn mock_get_secret_value() {
        let mock = MockAkeylessGateway::builder()
            .with_secret("/prod/db/password", "s3cret!")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/get-secret-value", mock.url()))
            .json(&json!({
                "names": ["/prod/db/password"],
                "token": "mock-token",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["/prod/db/password"], "s3cret!");
    }

    #[tokio::test]
    async fn mock_get_secret_value_not_found() {
        let mock = MockAkeylessGateway::builder().build().await;

        let resp = http_client()
            .post(format!("{}/get-secret-value", mock.url()))
            .json(&json!({
                "names": ["/nonexistent"],
                "token": "mock-token",
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn mock_sign_and_verify() {
        let mock = MockAkeylessGateway::builder()
            .with_signing_key("test-dfc-key")
            .build()
            .await;

        let data = Blake3Hash::digest(b"merkle-root");
        let data_hex = const_hex::encode(data.0);

        // Sign
        let sign_resp: Value = http_client()
            .post(format!("{}/sign-data-with-classic-key", mock.url()))
            .json(&json!({
                "key-name": "test-dfc-key",
                "data": data_hex,
                "token": "mock-token",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let sig_hex = sign_resp["result"].as_str().unwrap();
        assert!(!sig_hex.is_empty());

        // Verify (valid)
        let verify_resp: Value = http_client()
            .post(format!("{}/verify-data-with-classic-key", mock.url()))
            .json(&json!({
                "key-name": "test-dfc-key",
                "data": data_hex,
                "signature": sig_hex,
                "token": "mock-token",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(verify_resp["result"], true);

        // Verify (tampered data)
        let tampered_hex = const_hex::encode(Blake3Hash::digest(b"tampered").0);
        let verify_bad: Value = http_client()
            .post(format!("{}/verify-data-with-classic-key", mock.url()))
            .json(&json!({
                "key-name": "test-dfc-key",
                "data": tampered_hex,
                "signature": sig_hex,
                "token": "mock-token",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(verify_bad["result"], false);
    }

    #[tokio::test]
    async fn mock_sign_deterministic() {
        let mock = MockAkeylessGateway::builder()
            .with_signing_key("det-key")
            .build()
            .await;

        let data_hex = const_hex::encode(Blake3Hash::digest(b"same-data").0);

        let resp1: Value = http_client()
            .post(format!("{}/sign-data-with-classic-key", mock.url()))
            .json(&json!({ "key-name": "det-key", "data": data_hex, "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let resp2: Value = http_client()
            .post(format!("{}/sign-data-with-classic-key", mock.url()))
            .json(&json!({ "key-name": "det-key", "data": data_hex, "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp1["result"], resp2["result"]);
    }

    #[tokio::test]
    async fn mock_list_items() {
        let mock = MockAkeylessGateway::builder()
            .with_secret("/prod/db/password", "pw1")
            .with_secret("/prod/api/key", "key1")
            .with_secret("/staging/db/password", "pw2")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/list-items", mock.url()))
            .json(&json!({ "path": "/prod/", "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let items = resp["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        let names: Vec<&str> = items
            .iter()
            .map(|i| i["item_name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"/prod/db/password"));
        assert!(names.contains(&"/prod/api/key"));
    }

    #[tokio::test]
    async fn mock_describe_item() {
        let mock = MockAkeylessGateway::builder()
            .with_secret("/prod/secret", "val")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/describe-item", mock.url()))
            .json(&json!({ "name": "/prod/secret", "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["item_name"], "/prod/secret");
        assert_eq!(resp["item_type"], "STATIC_SECRET");
    }

    #[tokio::test]
    async fn mock_describe_item_not_found() {
        let mock = MockAkeylessGateway::builder().build().await;

        let resp = http_client()
            .post(format!("{}/describe-item", mock.url()))
            .json(&json!({ "name": "/nope", "token": "t" }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn mock_get_target_details() {
        let mock = MockAkeylessGateway::builder()
            .with_target("db-target", "mysql", "db.example.com:3306")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/get-target-details", mock.url()))
            .json(&json!({ "name": "db-target", "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let target = &resp["value"];
        assert_eq!(target["name"], "db-target");
        assert_eq!(target["target_type"], "mysql");
        assert_eq!(target["target_details"]["host"], "db.example.com:3306");
    }

    #[tokio::test]
    async fn mock_get_target_details_not_found() {
        let mock = MockAkeylessGateway::builder().build().await;

        let resp = http_client()
            .post(format!("{}/get-target-details", mock.url()))
            .json(&json!({ "name": "nope", "token": "t" }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn mock_hmac() {
        let mock = MockAkeylessGateway::builder().build().await;

        let data_hex = const_hex::encode(b"some data to hmac");

        let resp: Value = http_client()
            .post(format!("{}/hmac", mock.url()))
            .json(&json!({
                "key-name": "hmac-key",
                "data": data_hex,
                "token": "t",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let result = resp["result"].as_str().unwrap();
        assert_eq!(result.len(), 64); // 32 bytes hex-encoded

        // Deterministic: same input -> same output
        let resp2: Value = http_client()
            .post(format!("{}/hmac", mock.url()))
            .json(&json!({
                "key-name": "hmac-key",
                "data": data_hex,
                "token": "t",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["result"], resp2["result"]);
    }

    #[tokio::test]
    async fn mock_unknown_endpoint_returns_404() {
        let mock = MockAkeylessGateway::builder().build().await;

        let resp = http_client()
            .post(format!("{}/totally-unknown", mock.url()))
            .json(&json!({}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "unknown endpoint");
    }

    #[tokio::test]
    async fn mock_builder_with_multiple_secrets() {
        let mock = MockAkeylessGateway::builder()
            .with_secret("/a", "val-a")
            .with_secret("/b", "val-b")
            .with_secret("/c", "val-c")
            .build()
            .await;

        assert_eq!(mock.secret_count().await, 3);

        for (path, expected) in [("/a", "val-a"), ("/b", "val-b"), ("/c", "val-c")] {
            let resp: Value = http_client()
                .post(format!("{}/get-secret-value", mock.url()))
                .json(&json!({ "names": [path], "token": "t" }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(resp[path], expected);
        }
    }

    #[tokio::test]
    async fn mock_dynamic_add_secret() {
        let mock = MockAkeylessGateway::builder().build().await;

        assert_eq!(mock.secret_count().await, 0);

        mock.add_secret("/dynamic/secret", "dynamic-value").await;

        assert_eq!(mock.secret_count().await, 1);

        let resp: Value = http_client()
            .post(format!("{}/get-secret-value", mock.url()))
            .json(&json!({ "names": ["/dynamic/secret"], "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["/dynamic/secret"], "dynamic-value");
    }

    #[tokio::test]
    async fn mock_dynamic_add_target() {
        let mock = MockAkeylessGateway::builder().build().await;

        assert_eq!(mock.target_count().await, 0);

        mock.add_target("dyn-target", "postgres", "pg.local:5432")
            .await;

        assert_eq!(mock.target_count().await, 1);

        let resp: Value = http_client()
            .post(format!("{}/get-target-details", mock.url()))
            .json(&json!({ "name": "dyn-target", "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["value"]["target_type"], "postgres");
    }

    #[tokio::test]
    async fn mock_sign_unknown_key_returns_error() {
        let mock = MockAkeylessGateway::builder()
            .with_signing_key("only-this-key")
            .build()
            .await;

        let resp = http_client()
            .post(format!("{}/sign-data-with-classic-key", mock.url()))
            .json(&json!({
                "key-name": "wrong-key",
                "data": "aa",
                "token": "t",
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn mock_get_secret_with_name_field() {
        let mock = MockAkeylessGateway::builder()
            .with_secret("/alt/path", "alt-value")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/get-secret-value", mock.url()))
            .json(&json!({ "name": "/alt/path", "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["/alt/path"], "alt-value");
    }

    #[tokio::test]
    async fn mock_list_items_all() {
        let mock = MockAkeylessGateway::builder()
            .with_secret("/a/1", "v1")
            .with_secret("/b/2", "v2")
            .build()
            .await;

        let resp: Value = http_client()
            .post(format!("{}/list-items", mock.url()))
            .json(&json!({ "path": "/", "token": "t" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["items"].as_array().unwrap().len(), 2);
    }
}
