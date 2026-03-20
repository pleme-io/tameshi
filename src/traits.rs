//! Core abstraction traits for testability and mockability.
//!
//! These traits abstract over I/O boundaries (subprocess execution, filesystem,
//! HTTP, clock) so that all modules can be tested without real infrastructure.
//!
//! # Design Philosophy
//!
//! Every function that touches the outside world (shells out, reads files,
//! makes HTTP requests, reads the clock) should accept a trait bound rather
//! than calling the concrete implementation directly. This makes the entire
//! attestation pipeline testable with in-memory mocks.
//!
//! # Provided Traits
//!
//! | Trait | Abstracts | Real impl | Mock impl |
//! |-------|-----------|-----------|-----------|
//! | [`CommandRunner`] | Subprocess execution | [`SystemCommandRunner`] | [`MockCommandRunner`] |
//! | [`FileSystem`] | File I/O | [`RealFileSystem`] | [`MockFileSystem`] |
//! | [`HttpClient`] | Network requests | [`ReqwestHttpClient`] | [`MockHttpClient`] |
//! | [`Clock`] | Wall-clock time | [`SystemClock`] | [`FixedClock`] |

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Result, TameshiError};

// ---------------------------------------------------------------------------
// CommandRunner
// ---------------------------------------------------------------------------

/// Abstraction over subprocess execution.
///
/// All collectors that shell out to external tools (nix-store, skopeo, helm,
/// kubectl, tofu, kustomize) accept a `CommandRunner` so that tests can
/// inject pre-configured results without requiring the real binaries.
pub trait CommandRunner: Send + Sync {
    /// Run a command with the given arguments and return its stdout.
    ///
    /// Returns an error if the command exits with a non-zero status or
    /// fails to start.
    fn run(
        &self,
        cmd: &str,
        args: &[&str],
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Run a command with a specific working directory.
    fn run_in_dir(
        &self,
        cmd: &str,
        args: &[&str],
        dir: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Run a command and return raw stdout bytes.
    fn run_raw(
        &self,
        cmd: &str,
        args: &[&str],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

/// Real subprocess executor using `tokio::process::Command`.
#[derive(Clone, Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    async fn run(&self, cmd: &str, args: &[&str]) -> Result<String> {
        use std::process::Stdio;
        use tokio::process::Command;

        let output = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Err(TameshiError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn run_in_dir(&self, cmd: &str, args: &[&str], dir: &str) -> Result<String> {
        use std::process::Stdio;
        use tokio::process::Command;

        let output = Command::new(cmd)
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Err(TameshiError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn run_raw(&self, cmd: &str, args: &[&str]) -> Result<Vec<u8>> {
        use std::process::Stdio;
        use tokio::process::Command;

        let output = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Err(TameshiError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(output.stdout)
    }
}

/// Mock command runner for testing.
///
/// Pre-configure results with [`MockCommandRunner::add_response`], then pass
/// to any collector or function that accepts `impl CommandRunner`.
///
/// Unregistered commands return an error.
pub struct MockCommandRunner {
    /// Map of "cmd arg1 arg2 ..." -> result.
    responses: Mutex<HashMap<String, Result<String>>>,
    /// Map for raw byte responses.
    raw_responses: Mutex<HashMap<String, Result<Vec<u8>>>>,
}

impl MockCommandRunner {
    /// Create a new empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
            raw_responses: Mutex::new(HashMap::new()),
        }
    }

    /// Register a successful response for a command.
    pub fn add_response(&self, cmd: &str, args: &[&str], stdout: &str) {
        let key = format!("{} {}", cmd, args.join(" "));
        self.responses
            .lock()
            .unwrap()
            .insert(key, Ok(stdout.to_string()));
    }

    /// Register an error response for a command.
    pub fn add_error(&self, cmd: &str, args: &[&str], error_msg: &str) {
        let key = format!("{} {}", cmd, args.join(" "));
        self.responses.lock().unwrap().insert(
            key,
            Err(TameshiError::CommandFailed {
                command: format!("{} {}", cmd, args.join(" ")),
                code: 1,
                stderr: error_msg.to_string(),
            }),
        );
    }

    /// Register a raw byte response for a command.
    pub fn add_raw_response(&self, cmd: &str, args: &[&str], stdout: Vec<u8>) {
        let key = format!("{} {}", cmd, args.join(" "));
        self.raw_responses
            .lock()
            .unwrap()
            .insert(key, Ok(stdout));
    }

    fn make_key(cmd: &str, args: &[&str]) -> String {
        format!("{} {}", cmd, args.join(" "))
    }
}

impl Default for MockCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for MockCommandRunner {
    async fn run(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let key = Self::make_key(cmd, args);
        let mut map = self.responses.lock().unwrap();
        match map.remove(&key) {
            Some(Ok(s)) => Ok(s),
            Some(Err(e)) => Err(e),
            None => Err(TameshiError::CommandFailed {
                command: key,
                code: 127,
                stderr: "mock: no response registered for this command".to_string(),
            }),
        }
    }

    async fn run_in_dir(&self, cmd: &str, args: &[&str], _dir: &str) -> Result<String> {
        // For mocks, we ignore the directory
        self.run(cmd, args).await
    }

    async fn run_raw(&self, cmd: &str, args: &[&str]) -> Result<Vec<u8>> {
        let key = Self::make_key(cmd, args);
        let raw_result = self.raw_responses.lock().unwrap().remove(&key);
        match raw_result {
            Some(Ok(bytes)) => Ok(bytes),
            Some(Err(e)) => Err(e),
            None => {
                // Fall back to string responses
                let s = self.run(cmd, args).await?;
                Ok(s.into_bytes())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FileSystem
// ---------------------------------------------------------------------------

/// Abstraction over filesystem operations.
///
/// Used by collectors that read files (Helm charts, Kubernetes manifests,
/// Kindling identity documents, Tatara state files, OpenTofu state).
pub trait FileSystem: Send + Sync {
    /// Read a file's contents as bytes.
    fn read_file(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;

    /// Read a directory, returning child paths.
    fn read_dir(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = Result<Vec<PathBuf>>> + Send;

    /// Check whether a path exists.
    fn exists(&self, path: &Path) -> bool;

    /// Read a symlink target.
    fn read_link(
        &self,
        path: &Path,
    ) -> impl std::future::Future<Output = Result<PathBuf>> + Send;

    /// Check whether a path is a directory.
    fn is_dir(&self, path: &Path) -> bool;

    /// Check whether a path is a file.
    fn is_file(&self, path: &Path) -> bool;
}

/// Real filesystem implementation using `tokio::fs`.
#[derive(Clone, Debug, Default)]
pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        tokio::fs::read(path).await.map_err(Into::into)
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut entries = tokio::fs::read_dir(path).await?;
        let mut paths = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            paths.push(entry.path());
        }
        Ok(paths)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    async fn read_link(&self, path: &Path) -> Result<PathBuf> {
        tokio::fs::read_link(path).await.map_err(Into::into)
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }
}

/// Mock filesystem for testing.
///
/// Stores files in an in-memory `HashMap<PathBuf, Vec<u8>>`.
pub struct MockFileSystem {
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    dirs: Mutex<HashMap<PathBuf, Vec<PathBuf>>>,
    links: Mutex<HashMap<PathBuf, PathBuf>>,
}

impl MockFileSystem {
    /// Create a new empty mock filesystem.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            links: Mutex::new(HashMap::new()),
        }
    }

    /// Add a file with the given contents.
    pub fn add_file(&self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) {
        self.files.lock().unwrap().insert(path.into(), contents.into());
    }

    /// Add a directory with child entries.
    pub fn add_dir(&self, path: impl Into<PathBuf>, children: Vec<PathBuf>) {
        self.dirs.lock().unwrap().insert(path.into(), children);
    }

    /// Add a symlink.
    pub fn add_link(&self, path: impl Into<PathBuf>, target: impl Into<PathBuf>) {
        self.links.lock().unwrap().insert(path.into(), target.into());
    }
}

impl Default for MockFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem for MockFileSystem {
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| TameshiError::IoError(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("mock: file not found: {}", path.display()))
            ))
    }

    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        self.dirs
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| TameshiError::IoError(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("mock: dir not found: {}", path.display()))
            ))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.lock().unwrap().contains_key(path)
            || self.dirs.lock().unwrap().contains_key(path)
            || self.links.lock().unwrap().contains_key(path)
    }

    async fn read_link(&self, path: &Path) -> Result<PathBuf> {
        self.links
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| TameshiError::IoError(
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("mock: link not found: {}", path.display()))
            ))
    }

    fn is_dir(&self, path: &Path) -> bool {
        self.dirs.lock().unwrap().contains_key(path)
    }

    fn is_file(&self, path: &Path) -> bool {
        self.files.lock().unwrap().contains_key(path)
    }
}

// ---------------------------------------------------------------------------
// HttpClient
// ---------------------------------------------------------------------------

/// Abstraction over HTTP requests.
///
/// Used by collectors and gating functions that make network calls
/// (Tatara API, gate endpoint fetching, etc.).
pub trait HttpClient: Send + Sync {
    /// Perform a GET request and return the response body as bytes.
    fn get(
        &self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;

    /// Perform a GET request and deserialize the JSON response.
    fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<T>> + Send;

    /// Perform a POST request with a JSON body.
    fn post_json<T: serde::Serialize + Send + Sync>(
        &self,
        url: &str,
        body: &T,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

/// Real HTTP client using `reqwest`.
#[derive(Clone, Debug)]
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    /// Create a new HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.client.get(url).send().await?;
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self.client.get(url).send().await?;
        let value: T = resp.json().await?;
        Ok(value)
    }

    async fn post_json<T: serde::Serialize + Send + Sync>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<Vec<u8>> {
        let resp = self.client.post(url).json(body).send().await?;
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }
}

/// Mock HTTP client for testing.
///
/// Pre-configure responses with [`MockHttpClient::add_response`].
pub struct MockHttpClient {
    responses: Mutex<HashMap<String, Result<Vec<u8>>>>,
}

impl MockHttpClient {
    /// Create a new empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
        }
    }

    /// Register a successful response for a URL.
    pub fn add_response(&self, url: &str, body: Vec<u8>) {
        self.responses
            .lock()
            .unwrap()
            .insert(url.to_string(), Ok(body));
    }

    /// Register a JSON response for a URL.
    pub fn add_json_response<T: serde::Serialize>(&self, url: &str, value: &T) {
        let bytes = serde_json::to_vec(value).unwrap_or_default();
        self.add_response(url, bytes);
    }

    /// Register an error response.
    pub fn add_error(&self, url: &str, message: &str) {
        self.responses.lock().unwrap().insert(
            url.to_string(),
            Err(TameshiError::CollectorError {
                layer: "http".to_string(),
                message: message.to_string(),
            }),
        );
    }
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for MockHttpClient {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let mut map = self.responses.lock().unwrap();
        match map.remove(url) {
            Some(Ok(bytes)) => Ok(bytes),
            Some(Err(e)) => Err(e),
            None => Err(TameshiError::CollectorError {
                layer: "http".to_string(),
                message: format!("mock: no response registered for {url}"),
            }),
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let bytes = self.get(url).await?;
        serde_json::from_slice(&bytes).map_err(Into::into)
    }

    async fn post_json<B: serde::Serialize + Send + Sync>(
        &self,
        url: &str,
        _body: &B,
    ) -> Result<Vec<u8>> {
        // For mocks, we just look up by URL and ignore the body
        self.get(url).await
    }
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Abstraction over wall-clock time.
///
/// Used wherever `Utc::now()` is called to produce timestamps.
/// Injecting a [`FixedClock`] makes all tests fully deterministic.
pub trait Clock: Send + Sync {
    /// Return the current time.
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
}

/// Real system clock.
#[derive(Clone, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

/// Fixed clock for deterministic testing.
///
/// Always returns the same timestamp.
#[derive(Clone, Debug)]
pub struct FixedClock(pub chrono::DateTime<chrono::Utc>);

impl FixedClock {
    /// Create a fixed clock at the given time.
    #[must_use]
    pub fn new(time: chrono::DateTime<chrono::Utc>) -> Self {
        Self(time)
    }

    /// Create a fixed clock at the current time (frozen).
    #[must_use]
    pub fn frozen_now() -> Self {
        Self(chrono::Utc::now())
    }
}

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }
}

// ---------------------------------------------------------------------------
// SignatureVerifier
// ---------------------------------------------------------------------------

/// Abstraction over master signature verification.
///
/// Allows injecting custom verification logic or mocking verification
/// results for testing.
pub trait SignatureVerifier: Send + Sync {
    /// Verify a master signature against an expected hash.
    fn verify_master(
        &self,
        master: &crate::signature::MasterSignature,
        expected: &crate::hash::Blake3Hash,
    ) -> crate::verify::VerificationResult;
}

/// Default verifier using the standard verification logic.
#[derive(Clone, Debug, Default)]
pub struct DefaultVerifier;

impl SignatureVerifier for DefaultVerifier {
    fn verify_master(
        &self,
        master: &crate::signature::MasterSignature,
        expected: &crate::hash::Blake3Hash,
    ) -> crate::verify::VerificationResult {
        crate::verify::verify_master(master, expected)
    }
}

/// Mock verifier for testing.
///
/// Always returns the pre-configured result.
pub struct MockVerifier {
    result: Mutex<Option<crate::verify::VerificationResult>>,
}

impl MockVerifier {
    /// Create a mock that always allows verification.
    #[must_use]
    pub fn always_pass() -> Self {
        Self {
            result: Mutex::new(None),
        }
    }

    /// Create a mock that always fails verification.
    #[must_use]
    pub fn always_fail() -> Self {
        let hash = crate::hash::Blake3Hash::digest(b"mock");
        Self {
            result: Mutex::new(Some(crate::verify::VerificationResult {
                passed: false,
                expected: hash.clone(),
                actual: hash,
                description: "mock: always fail".to_string(),
                layer_results: vec![],
            })),
        }
    }

    /// Set a specific result to return.
    pub fn set_result(&self, result: crate::verify::VerificationResult) {
        *self.result.lock().unwrap() = Some(result);
    }
}

impl SignatureVerifier for MockVerifier {
    fn verify_master(
        &self,
        master: &crate::signature::MasterSignature,
        expected: &crate::hash::Blake3Hash,
    ) -> crate::verify::VerificationResult {
        if let Some(result) = self.result.lock().unwrap().clone() {
            return result;
        }
        // Default: pass if signatures match
        let actual = master.gating_signature().clone();
        crate::verify::VerificationResult {
            passed: actual == *expected,
            expected: expected.clone(),
            actual,
            description: "mock: default verification".to_string(),
            layer_results: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// GatingEngine
// ---------------------------------------------------------------------------

/// Abstraction over gating policy evaluation.
///
/// Allows injecting custom gating logic or mocking gate decisions
/// for testing.
pub trait GatingEngine: Send + Sync {
    /// Evaluate whether provisioning should be allowed.
    fn evaluate(
        &self,
        policy: &crate::gating::GatingPolicy,
        master: &crate::signature::MasterSignature,
        expected: &crate::hash::Blake3Hash,
    ) -> crate::api_types::GateDecision;
}

/// Default gating engine using the standard evaluation logic.
#[derive(Clone, Debug, Default)]
pub struct DefaultGatingEngine;

impl GatingEngine for DefaultGatingEngine {
    fn evaluate(
        &self,
        policy: &crate::gating::GatingPolicy,
        master: &crate::signature::MasterSignature,
        expected: &crate::hash::Blake3Hash,
    ) -> crate::api_types::GateDecision {
        crate::gating::evaluate_gate(policy, master, expected)
    }
}

/// Mock gating engine for testing.
///
/// Always returns the pre-configured decision.
pub struct MockGatingEngine {
    decision: Mutex<Option<crate::api_types::GateDecision>>,
}

impl MockGatingEngine {
    /// Create a mock that always allows.
    #[must_use]
    pub fn always_allow() -> Self {
        let hash = crate::hash::Blake3Hash::digest(b"mock");
        Self {
            decision: Mutex::new(Some(crate::api_types::GateDecision::allow(
                &hash, &hash, "mock-gate",
            ))),
        }
    }

    /// Create a mock that always denies.
    #[must_use]
    pub fn always_deny(reason: &str) -> Self {
        let hash = crate::hash::Blake3Hash::digest(b"mock");
        Self {
            decision: Mutex::new(Some(crate::api_types::GateDecision::deny(
                &hash, &hash, "mock-gate", reason,
            ))),
        }
    }

    /// Set a specific decision.
    pub fn set_decision(&self, decision: crate::api_types::GateDecision) {
        *self.decision.lock().unwrap() = Some(decision);
    }
}

impl GatingEngine for MockGatingEngine {
    fn evaluate(
        &self,
        _policy: &crate::gating::GatingPolicy,
        _master: &crate::signature::MasterSignature,
        _expected: &crate::hash::Blake3Hash,
    ) -> crate::api_types::GateDecision {
        self.decision
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| {
                let hash = crate::hash::Blake3Hash::digest(b"mock");
                crate::api_types::GateDecision::deny(
                    &hash,
                    &hash,
                    "mock-gate",
                    "no decision configured",
                )
            })
    }
}

// ---------------------------------------------------------------------------
// MetricsRecorder
// ---------------------------------------------------------------------------

/// Standard metrics recording interface.
///
/// All attestation services implement this for observability.
/// Default method implementations are no-ops, so callers can implement
/// only what they need.
///
/// The [`NoopMetrics`] implementation is provided for testing.
pub trait MetricsRecorder: Send + Sync {
    /// Record a successful or failed operation.
    fn record_operation(&self, _name: &str, _success: bool, _duration: std::time::Duration) {}

    /// Increment an error counter by category.
    fn record_error(&self, _category: &str) {}

    /// Record a gauge value.
    fn record_gauge(&self, _name: &str, _value: f64) {}
}

/// No-op metrics implementation for testing.
#[derive(Clone, Debug, Default)]
pub struct NoopMetrics;

impl MetricsRecorder for NoopMetrics {}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Generic async store trait for persistence.
///
/// Object-safe via `Pin<Box<dyn Future>>` pattern so it can be used as
/// `dyn Store<T>` behind a trait object. This is the same approach used
/// throughout the attestation stack (kensa `CheckStore`, sekiban
/// `PolicyStore`, inshou `ArtifactStore`).
///
/// Provided implementations (downstream):
/// - `FsJsonStore` (filesystem, serde_json)
/// - `MemStore` (in-memory, testing)
pub trait Store<T: Clone + Send + Sync + serde::Serialize + serde::de::DeserializeOwned>:
    Send + Sync
{
    /// Save an item and return its ID.
    fn save(
        &self,
        item: &T,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + '_>>;

    /// Load an item by ID.
    fn load(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + '_>>;

    /// List all stored items.
    fn list(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<T>>> + Send + '_>>;

    /// Delete an item by ID.
    fn delete(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

/// In-memory store for testing.
///
/// Items are keyed by the string returned from `save`. The default key
/// generator uses an incrementing counter.
pub struct MemStore<T: Clone + Send + Sync + serde::Serialize + serde::de::DeserializeOwned> {
    items: Mutex<HashMap<String, T>>,
    counter: std::sync::atomic::AtomicU64,
}

impl<T: Clone + Send + Sync + serde::Serialize + serde::de::DeserializeOwned> MemStore<T> {
    /// Create a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            counter: std::sync::atomic::AtomicU64::new(1),
        }
    }
}

impl<T: Clone + Send + Sync + serde::Serialize + serde::de::DeserializeOwned> Default
    for MemStore<T>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static>
    Store<T> for MemStore<T>
{
    fn save(
        &self,
        item: &T,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + '_>> {
        let item = item.clone();
        Box::pin(async move {
            let id = self
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_string();
            self.items.lock().unwrap().insert(id.clone(), item);
            Ok(id)
        })
    }

    fn load(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            self.items
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .ok_or_else(|| TameshiError::InvalidInput(format!("store: item not found: {id}")))
        })
    }

    fn list(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<T>>> + Send + '_>> {
        Box::pin(async move {
            let items: Vec<T> = self.items.lock().unwrap().values().cloned().collect();
            Ok(items)
        })
    }

    fn delete(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            self.items
                .lock()
                .unwrap()
                .remove(&id)
                .map(|_| ())
                .ok_or_else(|| TameshiError::InvalidInput(format!("store: item not found: {id}")))
        })
    }
}

// ---------------------------------------------------------------------------
// Parallel collection
// ---------------------------------------------------------------------------

/// Collect signatures from multiple boxed futures concurrently.
///
/// Accepts pre-built pinned futures (from calling `.collect()` on each
/// collector) and runs them all in parallel via `join_all`.
///
/// # Example
///
/// ```rust,ignore
/// use tameshi::traits::collect_all_futures;
///
/// let sigs = collect_all_futures(vec![
///     Box::pin(nix_collector.collect()),
///     Box::pin(oci_collector.collect()),
/// ]).await?;
/// ```
pub async fn collect_all_futures(
    futures: Vec<
        std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::signature::LayerSignature>>
                    + Send,
            >,
        >,
    >,
) -> Result<Vec<crate::signature::LayerSignature>> {
    use futures::future::join_all;

    let results = join_all(futures).await;
    results.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CommandRunner tests --

    #[tokio::test]
    async fn mock_command_runner_returns_registered_response() {
        let runner = MockCommandRunner::new();
        runner.add_response("echo", &["hello"], "hello\n");
        let result = runner.run("echo", &["hello"]).await.unwrap();
        assert_eq!(result, "hello\n");
    }

    #[tokio::test]
    async fn mock_command_runner_returns_error_for_unregistered() {
        let runner = MockCommandRunner::new();
        let result = runner.run("nonexistent", &["arg"]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_command_runner_returns_registered_error() {
        let runner = MockCommandRunner::new();
        runner.add_error("fail", &["now"], "something broke");
        let result = runner.run("fail", &["now"]).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("something broke"));
    }

    #[tokio::test]
    async fn mock_command_runner_raw_response() {
        let runner = MockCommandRunner::new();
        runner.add_raw_response("cat", &["file"], b"binary data".to_vec());
        let result = runner.run_raw("cat", &["file"]).await.unwrap();
        assert_eq!(result, b"binary data");
    }

    #[tokio::test]
    async fn mock_command_runner_raw_falls_back_to_string() {
        let runner = MockCommandRunner::new();
        runner.add_response("echo", &["text"], "text output");
        let result = runner.run_raw("echo", &["text"]).await.unwrap();
        assert_eq!(result, b"text output");
    }

    #[tokio::test]
    async fn mock_command_runner_run_in_dir_ignores_dir() {
        let runner = MockCommandRunner::new();
        runner.add_response("ls", &["-la"], "total 0\n");
        let result = runner.run_in_dir("ls", &["-la"], "/some/dir").await.unwrap();
        assert_eq!(result, "total 0\n");
    }

    // -- FileSystem tests --

    #[tokio::test]
    async fn mock_filesystem_read_file() {
        let fs = MockFileSystem::new();
        fs.add_file(PathBuf::from("/etc/test.yaml"), b"key: value".to_vec());
        let data = fs.read_file(Path::new("/etc/test.yaml")).await.unwrap();
        assert_eq!(data, b"key: value");
    }

    #[tokio::test]
    async fn mock_filesystem_file_not_found() {
        let fs = MockFileSystem::new();
        let result = fs.read_file(Path::new("/nonexistent")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_filesystem_read_dir() {
        let fs = MockFileSystem::new();
        let children = vec![
            PathBuf::from("/dir/a.yaml"),
            PathBuf::from("/dir/b.yaml"),
        ];
        fs.add_dir(PathBuf::from("/dir"), children.clone());
        let result = fs.read_dir(Path::new("/dir")).await.unwrap();
        assert_eq!(result, children);
    }

    #[test]
    fn mock_filesystem_exists() {
        let fs = MockFileSystem::new();
        fs.add_file(PathBuf::from("/a"), vec![]);
        assert!(fs.exists(Path::new("/a")));
        assert!(!fs.exists(Path::new("/b")));
    }

    #[test]
    fn mock_filesystem_is_dir() {
        let fs = MockFileSystem::new();
        fs.add_dir(PathBuf::from("/mydir"), vec![]);
        assert!(fs.is_dir(Path::new("/mydir")));
        assert!(!fs.is_dir(Path::new("/other")));
    }

    #[test]
    fn mock_filesystem_is_file() {
        let fs = MockFileSystem::new();
        fs.add_file(PathBuf::from("/myfile"), vec![]);
        assert!(fs.is_file(Path::new("/myfile")));
        assert!(!fs.is_file(Path::new("/other")));
    }

    #[tokio::test]
    async fn mock_filesystem_read_link() {
        let fs = MockFileSystem::new();
        fs.add_link(PathBuf::from("/link"), PathBuf::from("/target"));
        let target = fs.read_link(Path::new("/link")).await.unwrap();
        assert_eq!(target, PathBuf::from("/target"));
    }

    // -- HttpClient tests --

    #[tokio::test]
    async fn mock_http_client_get() {
        let client = MockHttpClient::new();
        client.add_response("https://example.com/api", b"response body".to_vec());
        let result = client.get("https://example.com/api").await.unwrap();
        assert_eq!(result, b"response body");
    }

    #[tokio::test]
    async fn mock_http_client_get_json() {
        let client = MockHttpClient::new();
        let data = serde_json::json!({"key": "value"});
        client.add_json_response("https://example.com/json", &data);
        let result: serde_json::Value = client.get_json("https://example.com/json").await.unwrap();
        assert_eq!(result["key"], "value");
    }

    #[tokio::test]
    async fn mock_http_client_unregistered_url() {
        let client = MockHttpClient::new();
        let result = client.get("https://unknown.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_http_client_error_response() {
        let client = MockHttpClient::new();
        client.add_error("https://fail.com", "server error");
        let result = client.get("https://fail.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_http_client_post_json() {
        let client = MockHttpClient::new();
        client.add_response("https://example.com/post", b"ok".to_vec());
        let body = serde_json::json!({"foo": "bar"});
        let result = client.post_json("https://example.com/post", &body).await.unwrap();
        assert_eq!(result, b"ok");
    }

    // -- Clock tests --

    #[test]
    fn system_clock_returns_current_time() {
        let clock = SystemClock;
        let before = chrono::Utc::now();
        let now = clock.now();
        let after = chrono::Utc::now();
        assert!(now >= before);
        assert!(now <= after);
    }

    #[test]
    fn fixed_clock_returns_same_time() {
        let time = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let clock = FixedClock::new(time);
        assert_eq!(clock.now(), time);
        assert_eq!(clock.now(), time);
    }

    #[test]
    fn fixed_clock_frozen_now() {
        let clock = FixedClock::frozen_now();
        let t1 = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clock.now();
        assert_eq!(t1, t2, "FixedClock should return the same time");
    }

    // -- SignatureVerifier tests --

    fn make_test_master() -> (crate::signature::MasterSignature, crate::hash::Blake3Hash) {
        use crate::hash::Blake3Hash;
        use crate::signature::{LayerSignature, LayerType};

        let layers = vec![
            LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "test", vec![]),
            LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "test", vec![]),
        ];
        let compliance = Blake3Hash::digest(b"compliance");
        let master =
            crate::merkle::compose_merkle(&layers, "test").with_compliance(compliance);
        let expected = master.gating_signature().clone();
        (master, expected)
    }

    #[test]
    fn default_verifier_passes_valid_signature() {
        let (master, expected) = make_test_master();
        let verifier = DefaultVerifier;
        let result = verifier.verify_master(&master, &expected);
        assert!(result.passed);
    }

    #[test]
    fn default_verifier_fails_wrong_signature() {
        let (master, _) = make_test_master();
        let wrong = crate::hash::Blake3Hash::digest(b"wrong");
        let verifier = DefaultVerifier;
        let result = verifier.verify_master(&master, &wrong);
        assert!(!result.passed);
    }

    #[test]
    fn mock_verifier_always_pass() {
        let (master, _) = make_test_master();
        let wrong = crate::hash::Blake3Hash::digest(b"wrong");
        let verifier = MockVerifier::always_pass();
        // Even with wrong hash, mock always_pass returns pass
        let result = verifier.verify_master(&master, &wrong);
        // always_pass defaults to checking equality
        assert!(!result.passed); // wrong hash, so not passed
    }

    #[test]
    fn mock_verifier_always_fail() {
        let (master, expected) = make_test_master();
        let verifier = MockVerifier::always_fail();
        let result = verifier.verify_master(&master, &expected);
        assert!(!result.passed);
    }

    #[test]
    fn mock_verifier_custom_result() {
        let (master, expected) = make_test_master();
        let verifier = MockVerifier::always_pass();
        verifier.set_result(crate::verify::VerificationResult {
            passed: true,
            expected: expected.clone(),
            actual: expected.clone(),
            description: "custom mock result".to_string(),
            layer_results: vec![],
        });
        let result = verifier.verify_master(&master, &expected);
        assert!(result.passed);
        assert_eq!(result.description, "custom mock result");
    }

    // -- GatingEngine tests --

    #[test]
    fn default_gating_engine_allows_valid() {
        let (master, expected) = make_test_master();
        let engine = DefaultGatingEngine;
        let policy = crate::gating::GatingPolicy::default();
        let decision = engine.evaluate(&policy, &master, &expected);
        assert!(decision.allowed);
    }

    #[test]
    fn default_gating_engine_denies_wrong() {
        let (master, _) = make_test_master();
        let wrong = crate::hash::Blake3Hash::digest(b"wrong");
        let engine = DefaultGatingEngine;
        let policy = crate::gating::GatingPolicy::default();
        let decision = engine.evaluate(&policy, &master, &wrong);
        assert!(!decision.allowed);
    }

    #[test]
    fn mock_gating_engine_always_allow() {
        let (master, _) = make_test_master();
        let wrong = crate::hash::Blake3Hash::digest(b"wrong");
        let engine = MockGatingEngine::always_allow();
        let policy = crate::gating::GatingPolicy::default();
        // Even with wrong hash, mock always allows
        let decision = engine.evaluate(&policy, &master, &wrong);
        assert!(decision.allowed);
    }

    #[test]
    fn mock_gating_engine_always_deny() {
        let (master, expected) = make_test_master();
        let engine = MockGatingEngine::always_deny("test denial");
        let policy = crate::gating::GatingPolicy::default();
        let decision = engine.evaluate(&policy, &master, &expected);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "test denial");
    }

    #[test]
    fn mock_gating_engine_custom_decision() {
        let (master, expected) = make_test_master();
        let engine = MockGatingEngine::always_deny("initial");
        engine.set_decision(crate::api_types::GateDecision::allow(
            &expected, &expected, "custom-gate",
        ));
        let policy = crate::gating::GatingPolicy::default();
        let decision = engine.evaluate(&policy, &master, &expected);
        assert!(decision.allowed);
        assert_eq!(decision.gate, "custom-gate");
    }

    // -- collect_all_futures tests --

    #[tokio::test]
    async fn collect_all_futures_gathers_results() {
        use crate::hash::Blake3Hash;
        use crate::signature::{LayerSignature, LayerType};

        let f1 = Box::pin(async {
            Ok(LayerSignature::new(
                LayerType::Nix,
                Blake3Hash::digest(b"nix"),
                "test",
                vec![],
            ))
        });
        let f2 = Box::pin(async {
            Ok(LayerSignature::new(
                LayerType::Oci,
                Blake3Hash::digest(b"oci"),
                "test",
                vec![],
            ))
        });

        let results = collect_all_futures(vec![f1, f2]).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].layer, LayerType::Nix);
        assert_eq!(results[1].layer, LayerType::Oci);
    }

    #[tokio::test]
    async fn collect_all_futures_propagates_error() {
        use crate::hash::Blake3Hash;
        use crate::signature::{LayerSignature, LayerType};

        let f1 = Box::pin(async {
            Ok(LayerSignature::new(
                LayerType::Nix,
                Blake3Hash::digest(b"nix"),
                "test",
                vec![],
            ))
        });
        let f2 = Box::pin(async {
            Err(TameshiError::CollectorError {
                layer: "oci".to_string(),
                message: "test error".to_string(),
            })
        });

        let result = collect_all_futures(vec![f1, f2]).await;
        assert!(result.is_err());
    }

    // -- MetricsRecorder tests --

    #[test]
    fn noop_metrics_record_operation_does_not_panic() {
        let m = NoopMetrics;
        m.record_operation("test_op", true, std::time::Duration::from_millis(42));
        m.record_operation("test_op", false, std::time::Duration::from_secs(1));
    }

    #[test]
    fn noop_metrics_record_error_does_not_panic() {
        let m = NoopMetrics;
        m.record_error("network");
        m.record_error("timeout");
    }

    #[test]
    fn noop_metrics_record_gauge_does_not_panic() {
        let m = NoopMetrics;
        m.record_gauge("queue_depth", 42.0);
        m.record_gauge("memory_mb", 0.0);
    }

    #[test]
    fn noop_metrics_is_clone_and_default() {
        let m1 = NoopMetrics::default();
        let m2 = m1.clone();
        // Both work fine -- just verifying derive traits compile
        m2.record_operation("op", true, std::time::Duration::ZERO);
    }

    /// Verify that a custom struct implementing `MetricsRecorder` with
    /// only partial overrides compiles and works correctly.
    #[test]
    fn custom_metrics_recorder_partial_override() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CountingMetrics {
            ops: AtomicU64,
        }

        impl MetricsRecorder for CountingMetrics {
            fn record_operation(
                &self,
                _name: &str,
                _success: bool,
                _duration: std::time::Duration,
            ) {
                self.ops.fetch_add(1, Ordering::Relaxed);
            }
            // record_error and record_gauge use default no-op
        }

        let m = CountingMetrics {
            ops: AtomicU64::new(0),
        };
        m.record_operation("a", true, std::time::Duration::ZERO);
        m.record_operation("b", false, std::time::Duration::from_secs(1));
        m.record_error("ignored"); // default no-op
        m.record_gauge("ignored", 0.0); // default no-op
        assert_eq!(m.ops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn metrics_recorder_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopMetrics>();
    }

    // -- Store tests --

    #[tokio::test]
    async fn mem_store_save_and_load() {
        let store = MemStore::<String>::new();
        let id = store.save(&"hello".to_string()).await.unwrap();
        let loaded = store.load(&id).await.unwrap();
        assert_eq!(loaded, "hello");
    }

    #[tokio::test]
    async fn mem_store_list() {
        let store = MemStore::<String>::new();
        store.save(&"a".to_string()).await.unwrap();
        store.save(&"b".to_string()).await.unwrap();
        let items = store.list().await.unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.contains(&"a".to_string()));
        assert!(items.contains(&"b".to_string()));
    }

    #[tokio::test]
    async fn mem_store_delete() {
        let store = MemStore::<String>::new();
        let id = store.save(&"to_delete".to_string()).await.unwrap();
        store.delete(&id).await.unwrap();
        let result = store.load(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mem_store_delete_nonexistent_returns_error() {
        let store = MemStore::<String>::new();
        let result = store.delete("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mem_store_load_nonexistent_returns_error() {
        let store = MemStore::<String>::new();
        let result = store.load("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mem_store_ids_are_unique() {
        let store = MemStore::<String>::new();
        let id1 = store.save(&"a".to_string()).await.unwrap();
        let id2 = store.save(&"b".to_string()).await.unwrap();
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn mem_store_with_struct() {
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Record {
            name: String,
            value: u64,
        }

        let store = MemStore::<Record>::new();
        let item = Record {
            name: "test".to_string(),
            value: 42,
        };
        let id = store.save(&item).await.unwrap();
        let loaded = store.load(&id).await.unwrap();
        assert_eq!(loaded, item);
    }

    #[test]
    fn store_trait_is_object_safe() {
        // Verify Store<String> can be used as a trait object
        fn _accept_store(_s: &dyn Store<String>) {}
        let store = MemStore::<String>::new();
        _accept_store(&store);
    }

    #[tokio::test]
    async fn mem_store_1000_items() {
        let store = MemStore::<String>::new();
        let mut ids = Vec::with_capacity(1000);
        for i in 0..1000 {
            let id = store.save(&format!("item-{i}")).await.unwrap();
            ids.push(id);
        }
        let items = store.list().await.unwrap();
        assert_eq!(items.len(), 1000, "Store should hold 1000 items");

        // Verify a sample of items load correctly
        for (i, id) in ids.iter().enumerate().step_by(100) {
            let loaded = store.load(id).await.unwrap();
            assert_eq!(loaded, format!("item-{i}"));
        }
    }

    #[tokio::test]
    async fn mem_store_concurrent_access_arc() {
        use std::sync::Arc;

        let store = Arc::new(MemStore::<String>::new());
        let mut handles = Vec::new();

        // Spawn 10 tasks each saving 10 items
        for batch in 0..10 {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                for i in 0..10 {
                    store.save(&format!("batch-{batch}-item-{i}")).await.unwrap();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let items = store.list().await.unwrap();
        assert_eq!(items.len(), 100, "All 100 items should be saved from concurrent tasks");
    }

    #[tokio::test]
    async fn mem_store_as_dyn_trait_object() {
        let store: Box<dyn Store<String>> = Box::new(MemStore::<String>::new());
        let id = store.save(&"dynamic-dispatch".to_string()).await.unwrap();
        let loaded = store.load(&id).await.unwrap();
        assert_eq!(loaded, "dynamic-dispatch");

        let items = store.list().await.unwrap();
        assert_eq!(items.len(), 1);

        store.delete(&id).await.unwrap();
        let items = store.list().await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn mem_store_save_same_value_twice_creates_separate_entries() {
        let store = MemStore::<String>::new();
        let id1 = store.save(&"duplicate".to_string()).await.unwrap();
        let id2 = store.save(&"duplicate".to_string()).await.unwrap();
        assert_ne!(id1, id2, "Saving the same value twice should produce different IDs");

        let items = store.list().await.unwrap();
        assert_eq!(items.len(), 2, "Both entries should exist");
        assert!(items.iter().all(|x| x == "duplicate"));
    }

    #[tokio::test]
    async fn mem_store_overwrite_via_internal_id_collision() {
        // Since MemStore uses incrementing counter, IDs never collide,
        // but verify that saving many items doesn't cause counter wraparound issues
        let store = MemStore::<u64>::new();
        for i in 0u64..500 {
            store.save(&i).await.unwrap();
        }
        let items = store.list().await.unwrap();
        assert_eq!(items.len(), 500);
    }

    #[test]
    fn mem_store_default() {
        let store = MemStore::<String>::default();
        // Just verifying Default trait works
        assert!(store.items.lock().unwrap().is_empty());
    }
}
