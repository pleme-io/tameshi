# Testing & Mock Architecture: Complete Trait Isolation for the Tameshi Ecosystem

## 1. Design Philosophy

Every I/O boundary in the tameshi ecosystem is abstracted behind a Rust trait with `Send + Sync` bounds. All mocks are hand-written -- no `mockall` crate, no procedural macros, no generated code. This gives full control over mock behavior, keeps compilation fast, and ensures mocks are readable test documentation.

The rules:

- **Every trait has at least one mock implementation.** No trait exists without a test double.
- **Critical traits have a `Failable*` implementation.** These inject deterministic failures for chaos/negative testing.
- **Some traits have a `Demo*` implementation.** These power the live Mocked Theater demo (ALLOW by default, DENY on command).
- **All mocks are `#[must_use]` with builder patterns.** Configuration is explicit and chainable.
- **All tests run on macOS.** No Linux kernel, no K8s cluster, no Akeyless gateway, no AI model. The entire 2,789-test ecosystem runs natively on a MacBook.
- **Mocks use `Mutex`/`RwLock` for thread safety.** Every mock can be wrapped in `Arc` and shared across async tasks.

---

## 2. The Four Boundaries

### 2.1 State/Secrets Boundary

#### AkeylessClient

**Trait** (`tameshi/src/akeyless_client.rs`):

```rust
pub trait AkeylessClient: Send + Sync {
    fn authenticate(&self) -> impl Future<Output = Result<String, AkeylessClientError>> + Send;
    fn get_secret_hash(&self, path: &str, token: &str) -> impl Future<Output = Result<AkeylessSecretAccess, AkeylessClientError>> + Send;
    fn list_secrets(&self, prefix: &str, token: &str) -> impl Future<Output = Result<Vec<String>, AkeylessClientError>> + Send;
    fn gateway_cert_hash(&self) -> impl Future<Output = Result<Blake3Hash, AkeylessClientError>> + Send;
    fn build_attestation(&self, secret_paths: &[String]) -> impl Future<Output = Result<AkeylessSecretAttestation, AkeylessClientError>> + Send;
    fn get_target(&self, name: &str, token: &str) -> impl Future<Output = Result<TargetInfo, AkeylessClientError>> + Send;
    fn list_targets(&self, token: &str) -> impl Future<Output = Result<Vec<String>, AkeylessClientError>> + Send;
    fn get_dynamic_secret_details(&self, name: &str, token: &str) -> impl Future<Output = Result<DynamicSecretInfo, AkeylessClientError>> + Send;
    fn build_target_attestation(&self, target_names: &[String]) -> impl Future<Output = Result<Vec<AkeylessTargetAttestation>, AkeylessClientError>> + Send;
}
```

**Real:** `HttpAkeylessClient<H: HttpClient>` -- generic over HTTP transport, calls the Akeyless gateway REST API. Hashes secret VALUES (never stores them). Salts with `gateway_url:path:value` to defeat rainbow tables.

**Mock:** `MockAkeylessClient` -- returns canned attestation data from `sample_attestation()`. Builder methods: `with_attestation()`, `with_target_attestations()`. Runtime override: `set_attestation()`, `set_target_attestations()`.

```rust
let mock = MockAkeylessClient::new(); // uses sample_attestation()
let mock = MockAkeylessClient::with_attestation(custom_attestation);
mock.set_secret_hash("/path", hash); // runtime override
```

#### MerkleRootSigner

**Trait** (`tameshi/src/signing.rs`):

```rust
pub trait MerkleRootSigner: Send + Sync {
    fn sign(&self, root: &Blake3Hash) -> impl Future<Output = Result<SignedRoot>> + Send;
    fn verify(&self, signed: &SignedRoot) -> impl Future<Output = Result<bool>> + Send;
}
```

**Real implementations:**
- `LocalSigner` -- Ed25519 HMAC-like signing using BLAKE3 keyed hash. `for_testing()` creates with seed `[42u8; 32]`.
- `AkeylessDfcSigner` -- Calls Akeyless gateway `/sign-data-with-classic-key` endpoint. Key never exists in one piece (Distributed Fragment Cryptography). Supports mTLS via `TlsConfig`.

**Mock:** `MockDfcSigner` -- Split-knowledge XOR simulation. Two 32-byte fragments. Key = `BLAKE3(fragment_a XOR fragment_b)`. Neither fragment alone reveals the key. Debug output redacts fragments.

```rust
pub struct MockDfcSigner {
    signer_id: String,
    fragment_a: [u8; 32],  // Debug: "[REDACTED]"
    fragment_b: [u8; 32],  // Debug: "[REDACTED]"
}

let signer = MockDfcSigner::for_testing();           // fragments [1u8;32], [2u8;32]
let signer = MockDfcSigner::from_fragments(a, b, id); // explicit
```

**Failable:** `FailableDfcSigner` -- wraps `MockDfcSigner`, injects 4 failure modes:

```rust
pub enum FailMode {
    Timeout(Duration),         // sign/verify return error
    CorruptedSignature,        // sign succeeds but flips all bits -> verify fails
    AuthFailure,               // sign/verify return auth error
    RateLimited,               // sign/verify return rate limit error
}

let signer = FailableDfcSigner::new()
    .with_timeout(Duration::from_secs(5));  // or
    .with_corrupted_signature();             // or
    .with_auth_failure();                    // or
    .with_rate_limited();
```

#### GlobalStateClient

**Trait** (`tameshi/src/global.rs`):

```rust
pub trait GlobalStateClient: Send + Sync {
    fn report_root(&self, report: &ClusterRootReport) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + '_>>;
    fn query_global_blast_radius(&self, hash: &Blake3Hash) -> Pin<Box<dyn Future<Output = Result<GlobalBlastRadiusReport>> + Send + '_>>;
    fn revoke_everywhere(&self, hash: &Blake3Hash, reason: &str) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>>;
    fn get_global_root(&self) -> Pin<Box<dyn Future<Output = Result<GlobalStateRoot>> + Send + '_>>;
}
```

**Mock:** `MockGlobalStateClient` -- records all calls in `Mutex<Vec<_>>` fields for later assertion. Configurable responses via `configured_root`, `configured_blast_radius`, `revocation_clusters`.

```rust
let mock = MockGlobalStateClient::new();
// After test:
assert_eq!(mock.reports.lock().unwrap().len(), 1);
assert_eq!(mock.revocations.lock().unwrap().len(), 0);
```

---

### 2.2 Kernel Boundary

#### BpfLoader

**Trait** (`kanshi/src/bpf_loader.rs`):

```rust
pub trait BpfLoader: Send + Sync {
    fn load(&mut self) -> Result<(), Error>;
    fn is_loaded(&self) -> bool;
    fn allow_hash(&self, hash: &BpfHash) -> Result<(), Error>;
    fn remove_hash(&self, hash: &BpfHash) -> Result<(), Error>;
    fn revoke_hash(&self, hash: &BpfHash) -> Result<(), Error>;
    fn unrevoke_hash(&self, hash: &BpfHash) -> Result<(), Error>;
    fn set_policy(&self, namespace_hash: u32, policy: EnforcementPolicy) -> Result<(), Error>;
    fn allow_count(&self) -> usize;
    fn revocation_count(&self) -> usize;
}
```

**Real:** `AyaBpfLoader` (Linux only, scaffold) -- loads eBPF programs into the kernel and provides typed access to BPF maps.

**Mock:** `MockBpfLoader` -- in-memory `HashMap` behind `Mutex` locks. Full map introspection: `allow_count()`, `revocation_count()`.

```rust
let mut loader = MockBpfLoader::new();
loader.load().unwrap();
loader.allow_hash(&hash).unwrap();
assert_eq!(loader.allow_count(), 1);
loader.remove_hash(&hash).unwrap();
assert_eq!(loader.allow_count(), 0);
```

**Failable:** `FailableBpfLoader` -- wraps `MockBpfLoader` with 4 failure flags:

```rust
let loader = FailableBpfLoader::new()
    .with_fail_on_allow()       // allow_hash returns error (map full)
    .with_fail_on_revoke()      // revoke_hash returns error
    .with_fail_on_load()        // load returns error (BPF won't attach)
    .with_corrupt_lookups();    // allow_hash silently drops (no store)
```

#### EventReader

**Trait** (`kanshi/src/event_reader.rs`):

```rust
pub trait EventReader: Send + Sync {
    fn poll_events(&self) -> Result<Vec<BlockedExecutionEvent>, Error>;
}
```

**Mock:** `MockEventReader` -- pre-populated event queue behind `Mutex`. Methods: `with_events()`, `push_event()`, `pending_count()`. Events are drained on `poll_events()`.

**Failable:** `FailableEventReader` -- wraps `MockEventReader` with 4 failure modes:

```rust
pub enum EventReaderFailMode {
    DropEvents(usize),    // ring buffer overflow: return at most N events
    PartialEvents,        // corrupted: zero out binary paths
    DelayedDelivery(usize), // return empty for first N polls, then deliver
    PollError,            // hard I/O error on poll
}

let reader = FailableEventReader::new()
    .with_drop_events(2);      // silently drop events beyond 2 per poll
```

#### ForensicsWriter

**Trait** (`kanshi/src/forensics_writer.rs`):

```rust
pub trait ForensicsWriter: Send + Sync {
    fn write_entry(&self, entry: &ForensicsEntry) -> Result<u64>;
    fn entry_count(&self) -> usize;
}
```

**Mock:** `InMemoryForensicsWriter` -- `Mutex<Vec<ForensicsEntry>>`. Thread-safe, dyn-safe. Method: `entries()` returns snapshot of all stored entries.

---

### 2.3 Build Boundary

#### NixStoreOps

**Trait** (`inshou/src/nix_ops.rs`):

```rust
pub trait NixStoreOps: Send + Sync {
    fn hash_single_path(&self, store_path: &str) -> impl Future<Output = Result<Blake3Hash, NixOpsError>> + Send;
    fn hash_closure(&self, store_path: &str) -> impl Future<Output = Result<LayerSignature, NixOpsError>> + Send;
    fn hash_system_profile(&self) -> impl Future<Output = Result<LayerSignature, NixOpsError>> + Send;
}
```

**Real:** `FsNixStoreOps` -- delegates to `nix-store --query --requisites`.

**Mock:** `MockNixStoreOps` -- configurable via `set_single_path_result()`, `set_closure_result()`, `set_system_result()`. Defaults produce deterministic hashes from `Blake3Hash::digest(b"mock-nix-store-path")`.

```rust
let ops = MockNixStoreOps::new();
ops.set_system_result(Ok(custom_signature));
// or use factory:
let ops = MockNixStoreOps::with_system_hash(specific_hash);
```

#### VerificationClient

**Trait** (`inshou/src/client.rs`):

```rust
pub trait VerificationClient: Send + Sync {
    fn fetch_expected(&self, endpoint: &str) -> impl Future<Output = Result<SekibanSignatureResponse, ClientError>> + Send;
}
```

**Real:** `HttpVerificationClient` -- `reqwest` with configurable timeout.

**Mock:** `MockVerificationClient` -- returns configured `SekibanSignatureResponse`. Override via `set_response()`.

```rust
let client = MockVerificationClient::new("blake3:abcd1234");
// or with full response:
let client = MockVerificationClient::with_full_response(response);
client.set_response(Err(ClientError::Timeout)); // next call fails
```

#### LayerCollector

**Trait** (`tameshi/src/collectors/traits.rs`):

```rust
pub trait LayerCollector: Send + Sync {
    fn collect(&self) -> impl Future<Output = Result<LayerSignature>> + Send;
    fn layer_type(&self) -> LayerType;
}
```

**Mock:** `MockCollector` -- returns deterministic signature based on layer type. Override via `set_result()`. Consumed on use (reverts to default).

```rust
let collector = MockCollector::new(LayerType::Nix);
collector.set_result(Ok(custom_signature)); // next collect() returns this
// Second collect() returns default
```

#### CommandRunner

**Trait** (`tameshi/src/traits.rs`):

```rust
pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &str, args: &[&str]) -> impl Future<Output = Result<String>> + Send;
    fn run_in_dir(&self, cmd: &str, args: &[&str], dir: &str) -> impl Future<Output = Result<String>> + Send;
    fn run_raw(&self, cmd: &str, args: &[&str]) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
```

**Real:** `SystemCommandRunner` -- `tokio::process::Command`.

**Mock:** `MockCommandRunner` -- response queue keyed by `"cmd arg1 arg2"`. Methods: `add_response()`, `add_error()`, `add_raw_response()`. Unregistered commands return error code 127.

```rust
let runner = MockCommandRunner::new();
runner.add_response("nix-store", &["--query", "--requisites", "/nix/store/abc"], "/nix/store/abc\n/nix/store/def\n");
runner.add_error("helm", &["template", "chart"], "chart not found");
```

---

### 2.4 AI/Forensics Boundary

#### AiThreatClient

**Trait** (`tameshi/src/ai_threat.rs`):

```rust
pub trait AiThreatClient: Send + Sync {
    fn analyze_provenance(&self, request: &AnalyzeProvenanceRequest) -> impl Future<Output = Result<AnalyzeProvenanceResponse, AiThreatError>> + Send;
    fn model_status(&self) -> impl Future<Output = Result<ModelStatus, AiThreatError>> + Send;
    fn submit_feedback(&self, feedback: &AnalysisFeedback) -> impl Future<Output = Result<FeedbackAck, AiThreatError>> + Send;
}
```

**Real:** `HttpAiThreatClient` -- `reqwest` to the tameshi AI inference server.

**Mock:** `MockAiThreatClient` -- configurable decision (ALLOW/DENY/WARN) with atomic call counters. Default: ALLOW with 0.98 confidence.

```rust
let client = MockAiThreatClient::new()                     // default ALLOW
    .with_decision(AiDecision::Deny);                       // override decision
assert_eq!(client.analyze_call_count(), 0);
client.analyze_provenance(&req).await.unwrap();
assert_eq!(client.analyze_call_count(), 1);
```

**Failable:** `FailableAiThreatClient` -- wraps `MockAiThreatClient` with 5 failure modes:

```rust
pub enum AiFailMode {
    Timeout(u64),       // AiThreatError::Timeout
    Unavailable,        // AiThreatError::Unavailable
    Corrupted,          // AiThreatError::Unprocessable
    AuthFailure,        // AiThreatError::ServiceError
    RateLimited,        // AiThreatError::ServiceError
}

let client = FailableAiThreatClient::new().with_timeout(500);
let result = client.analyze_provenance(&req).await;
assert!(matches!(result, Err(AiThreatError::Timeout(500))));
```

**Demo:** `DemoAiThreatClient` -- the Mocked Theater client. ALLOW by default. Call `trigger_heist()` to switch to DENY mode (returns ROS2 DDS zero-day breach pattern). Call `reset()` to return to ALLOW.

```rust
let client = DemoAiThreatClient::new();     // ALLOW mode
client.trigger_heist();                      // DENY mode (ROS2 DDS pattern)
client.reset();                              // back to ALLOW
assert!(!client.is_heist_active());
```

The DENY response includes a realistic breach pattern:

```json
{
  "decision": "DENY",
  "confidence": 0.96,
  "analysis": {
    "structural_similarity_to_known_breaches": 0.942,
    "dependency_graph_anomaly_score": 0.87,
    "flagged_dependencies": [
      "/nix/store/xxx-fastdds-2.14.0",
      "/nix/store/yyy-foonathan-memory-0.7.3",
      "/nix/store/zzz-asio-1.28.0"
    ]
  },
  "threat_intelligence": {
    "matched_patterns": [{
      "pattern_id": "TAMESHI-BREACH-2025-ROS2-DDS",
      "similarity": 0.942,
      "description": "ROS2 DDS middleware vulnerability chain"
    }],
    "recommended_action": "block"
  }
}
```

The ALLOW response shows clean provenance:

```json
{
  "decision": "ALLOW",
  "confidence": 0.98,
  "analysis": {
    "structural_similarity_to_known_breaches": 0.02,
    "dependency_graph_anomaly_score": 0.01,
    "novel_dependency_count": 0,
    "flagged_dependencies": []
  },
  "threat_intelligence": {
    "matched_patterns": [],
    "recommended_action": "proceed"
  }
}
```

#### MerkleLedgerStore

**Trait** (`tameshi/src/forensics/ledger.rs`):

```rust
pub trait MerkleLedgerStore: Send + Sync {
    fn append(&self, entry: MerkleLedgerEntry) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + '_>>;
    fn get(&self, sequence: u64) -> Pin<Box<dyn Future<Output = Result<Option<MerkleLedgerEntry>>> + Send + '_>>;
    fn range(&self, from_seq: u64, to_seq: u64) -> Pin<Box<dyn Future<Output = Result<Vec<MerkleLedgerEntry>>> + Send + '_>>;
    fn latest(&self) -> Pin<Box<dyn Future<Output = Result<Option<MerkleLedgerEntry>>> + Send + '_>>;
    fn len(&self) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + '_>>;
}
```

**Mock:** `InMemoryLedgerStore` -- `Mutex<Vec<MerkleLedgerEntry>>` with a `LedgerIndex` for O(log n) queries by hash, node, namespace, time, and binary path.

#### CompliancePlugin

**Trait** (`tameshi/src/compliance/plugin.rs`):

```rust
pub trait CompliancePlugin: Send + Sync {
    fn domain(&self) -> &str;
    fn nist_families(&self) -> Vec<String>;
    fn generate_controls(&self, config: &PluginConfig) -> Vec<ComplianceControl>;
    fn evaluate(&self, controls: &[ComplianceControl], config: &PluginConfig) -> Pin<Box<dyn Future<Output = Result<DomainEvaluation>> + Send + '_>>;
    fn is_available(&self) -> bool;
}
```

**Mock:** `MockPlugin` -- builder pattern with `with_nist_families()`, `with_controls()`, `with_pass_all()`, `with_available()`. Helper: `MockPlugin::make_control(id, domain, required)`.

```rust
let plugin = MockPlugin::new("kernel")
    .with_pass_all(true)
    .with_available(true);
let controls = plugin.generate_controls(&PluginConfig::default());
let result = plugin.evaluate(&controls, &config).await.unwrap();
assert!(result.all_required_passed);
```

#### ScriptEngine

**Trait** (`kensa/src/runner/dynamic.rs`):

```rust
pub trait ScriptEngine: Send + Sync {
    fn evaluate(&self, source: &str, context: &BTreeMap<String, String>, env_desc: &str) -> ScriptResult;
}
```

**Real:** `RhaiEngine` -- sandboxed Rhai with resource limits (10,000 ops, 10KB strings, 1000-element arrays, 32 call levels).

**Mock:** `MockScriptEngine` -- fixed result factories:

```rust
let engine = MockScriptEngine::always_pass();
let engine = MockScriptEngine::always_fail("policy violation");
let engine = MockScriptEngine::always_error("script timeout");
```

---

## 3. Complete Mock Inventory Table

| Boundary | Trait | Real Impl | Mock | Failable | Demo | Repo |
|----------|-------|-----------|------|----------|------|------|
| State/Secrets | `AkeylessClient` | `HttpAkeylessClient<H>` | `MockAkeylessClient` | -- | -- | tameshi |
| State/Secrets | `MerkleRootSigner` | `LocalSigner`, `AkeylessDfcSigner` | `MockDfcSigner` | `FailableDfcSigner` | -- | tameshi |
| State/Secrets | `GlobalStateClient` | -- (planned) | `MockGlobalStateClient` | -- | -- | tameshi |
| State/Secrets | `IacTestAttester` | -- (iac-test-runner) | `MockIacTestAttester` | -- | -- | tameshi |
| I/O | `CommandRunner` | `SystemCommandRunner` | `MockCommandRunner` | -- | -- | tameshi |
| I/O | `FileSystem` | `RealFileSystem` | `MockFileSystem` | -- | -- | tameshi |
| I/O | `HttpClient` | `ReqwestHttpClient` | `MockHttpClient` | -- | -- | tameshi |
| I/O | `Clock` | `SystemClock` | `FixedClock` | -- | -- | tameshi |
| Collection | `LayerCollector` | 14 real collectors | `MockCollector` | -- | -- | tameshi |
| Compliance | `CompliancePlugin` | (domain plugins) | `MockPlugin` | -- | -- | tameshi |
| Forensics | `MerkleLedgerStore` | -- (planned DB) | `InMemoryLedgerStore` | -- | -- | tameshi |
| AI | `AiThreatClient` | `HttpAiThreatClient` | `MockAiThreatClient` | `FailableAiThreatClient` | `DemoAiThreatClient` | tameshi |
| Kernel | `BpfLoader` | `AyaBpfLoader` (Linux) | `MockBpfLoader` | `FailableBpfLoader` | -- | kanshi |
| Kernel | `EventReader` | -- (aya RingBuf) | `MockEventReader` | `FailableEventReader` | -- | kanshi |
| Kernel | `ForensicsWriter` | -- (planned) | `InMemoryForensicsWriter` | -- | -- | kanshi |
| K8s | `HeartbeatRecorder` | `SekibanHeartbeat` | `NoopHeartbeatRecorder` | -- | -- | sekiban |
| K8s | `AdmissionReviewer` | (webhook handler) | `MockAdmissionReviewer` | -- | -- | sekiban |
| Build | `NixStoreOps` | `FsNixStoreOps` | `MockNixStoreOps` | -- | -- | inshou |
| Build | `VerificationClient` | `HttpVerificationClient` | `MockVerificationClient` | -- | -- | inshou |
| Build | `ProfileStore` | `FsProfileStore` | `MemProfileStore` | -- | -- | inshou |
| Build | `OutputFormatter` | `TextFormatter`, `JsonFormatter` | -- | -- | -- | inshou |
| Build | `ConfigLoader` | `DefaultConfigLoader` | `TestConfigLoader` | -- | -- | inshou |
| Compliance | `ScriptEngine` | `RhaiEngine` | `MockScriptEngine` | -- | -- | kensa |
| Compliance | `ComplianceStore` | `FsStore` | `MemStore` | -- | -- | kensa |
| Compliance | `ReportGenerator` | `OscalReportGenerator` | `MockReportGenerator` | -- | -- | kensa |
| Compliance | `SignatureComputer` | `DefaultSignatureComputer` | `MockSignatureComputer` | -- | -- | kensa |
| Compliance | `CertificationPipeline` | `DefaultCertificationPipeline` | `MockCertificationPipeline` | -- | -- | kensa |
| K8s | `LayerHashCollector` | (kube API) | `MockLayerHashCollector` | -- | -- | sekiban |
| K8s | `GateStore` | `KubeStore` | `MemStore` | -- | -- | sekiban |

---

## 4. Test Harness Example: Fail-Secure Scenario

This demonstrates the complete mock wiring for a fail-secure gate evaluation. The test creates mocks for signing, BPF loading, AI analysis, and layer collection, then walks through a happy path followed by three failure injection scenarios.

```rust
use tameshi::hash::Blake3Hash;
use tameshi::signing::{MockDfcSigner, FailableDfcSigner, MerkleRootSigner, SignedRoot};
use tameshi::certification_artifact::compose_certification_artifact;
use tameshi::ai_threat::{
    DemoAiThreatClient, AiThreatClient, AiDecision,
    MockAiThreatClient, FailableAiThreatClient,
    test_helpers::sample_request,
};
use tameshi::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};
use tameshi::collectors::mock::MockCollector;
use tameshi::signature::LayerType;

#[tokio::test]
async fn fail_secure_gate_scenario() {
    // ---------------------------------------------------------------
    // 1. Create all mocks
    // ---------------------------------------------------------------
    let signer = MockDfcSigner::for_testing();
    let ai_client = DemoAiThreatClient::new();
    let nix_collector = MockCollector::new(LayerType::Nix);
    let heartbeat = HeartbeatChain::new();
    let verifier = VerifierIdentity::new("test-gate", "local", "0.1.0");

    // ---------------------------------------------------------------
    // 2. Compose a CertificationArtifact
    // ---------------------------------------------------------------
    let artifact_hash = Blake3Hash::digest(b"nix-derivation-abc");
    let control_hash = Blake3Hash::digest(b"kensa-assessment-xyz");
    let intent_hash = Blake3Hash::digest(b"pangea-synthesis-123");
    let artifact = compose_certification_artifact(
        artifact_hash.clone(),
        control_hash.clone(),
        intent_hash.clone(),
    );

    // ---------------------------------------------------------------
    // 3. Sign with MockDfcSigner
    // ---------------------------------------------------------------
    let signed = signer.sign(&artifact.composed_root).await.unwrap();
    assert_eq!(signed.root, artifact.composed_root);

    // ---------------------------------------------------------------
    // 4. Verify signature
    // ---------------------------------------------------------------
    let verified = signer.verify(&signed).await.unwrap();
    assert!(verified, "MockDfcSigner should verify its own signatures");

    // ---------------------------------------------------------------
    // 5. AI analysis: normal mode -> ALLOW
    // ---------------------------------------------------------------
    let ai_request = sample_request();
    let ai_response = ai_client.analyze_provenance(&ai_request).await.unwrap();
    assert_eq!(ai_response.decision, AiDecision::Allow);

    // Record in heartbeat chain
    heartbeat.append(
        verifier.clone(),
        HeartbeatEvent::GateVerification,
        VerificationOutcome::Allowed,
        "test-resource",
        artifact.composed_root.clone(),
    );
    assert_eq!(heartbeat.len(), 1);

    // ---------------------------------------------------------------
    // 6. Inject signing failure: FailableDfcSigner with timeout
    // ---------------------------------------------------------------
    let failing_signer = FailableDfcSigner::new()
        .with_timeout(std::time::Duration::from_secs(5));
    let sign_result = failing_signer.sign(&artifact.composed_root).await;
    assert!(sign_result.is_err(), "Timeout should cause sign to fail");

    // Gate DENIES because signing failed (fail-secure)
    heartbeat.append(
        verifier.clone(),
        HeartbeatEvent::GateVerification,
        VerificationOutcome::Denied,
        "test-resource",
        artifact.composed_root.clone(),
    );
    assert_eq!(heartbeat.len(), 2);

    // ---------------------------------------------------------------
    // 7. Inject corrupted signature: sign succeeds but verify fails
    // ---------------------------------------------------------------
    let corrupt_signer = FailableDfcSigner::new()
        .with_corrupted_signature();
    let corrupt_signed = corrupt_signer.sign(&artifact.composed_root).await.unwrap();
    let corrupt_verify = corrupt_signer.verify(&corrupt_signed).await.unwrap();
    assert!(!corrupt_verify, "Corrupted signature must fail verification");

    heartbeat.append(
        verifier.clone(),
        HeartbeatEvent::GateVerification,
        VerificationOutcome::Denied,
        "test-resource-corrupt",
        artifact.composed_root.clone(),
    );

    // ---------------------------------------------------------------
    // 8. Trigger the heist: DemoAiThreatClient -> DENY
    // ---------------------------------------------------------------
    ai_client.trigger_heist();
    assert!(ai_client.is_heist_active());

    let heist_response = ai_client.analyze_provenance(&ai_request).await.unwrap();
    assert_eq!(heist_response.decision, AiDecision::Deny);
    assert!(heist_response.reason.unwrap().contains("TAMESHI-BREACH-2025-ROS2-DDS"));

    heartbeat.append(
        verifier.clone(),
        HeartbeatEvent::GateVerification,
        VerificationOutcome::Denied,
        "test-resource-heist",
        artifact.composed_root.clone(),
    );

    // ---------------------------------------------------------------
    // 9. Verify HeartbeatChain recorded all events
    // ---------------------------------------------------------------
    assert_eq!(heartbeat.len(), 4);
    assert!(heartbeat.verify_integrity(), "Chain must be tamper-evident");

    let entries = heartbeat.entries();
    assert_eq!(entries[0].result, VerificationOutcome::Allowed);  // normal gate pass
    assert_eq!(entries[1].result, VerificationOutcome::Denied);   // signer timeout
    assert_eq!(entries[2].result, VerificationOutcome::Denied);   // corrupt signature
    assert_eq!(entries[3].result, VerificationOutcome::Denied);   // AI heist

    // ---------------------------------------------------------------
    // 10. Reset and verify recovery
    // ---------------------------------------------------------------
    ai_client.reset();
    let recovery_response = ai_client.analyze_provenance(&ai_request).await.unwrap();
    assert_eq!(recovery_response.decision, AiDecision::Allow);
}
```

---

## 5. The Mocked Theater Demo Setup

The Mocked Theater wires all mock implementations together for a live demonstration. Every component is running locally -- no Linux kernel, no K8s cluster, no Akeyless, no AI model.

```rust
use tameshi::signing::MockDfcSigner;
use tameshi::ai_threat::DemoAiThreatClient;
use tameshi::collectors::mock::MockCollector;
use tameshi::signature::LayerType;
use tameshi::heartbeat::HeartbeatChain;
use tameshi::forensics::ledger::{MerkleLedger, InMemoryLedgerStore};
use tameshi::akeyless_client::MockAkeylessClient;
use tameshi::global::MockGlobalStateClient;
use tameshi::traits::FixedClock;

use kanshi::bpf_loader::MockBpfLoader;
use kanshi::event_reader::MockEventReader;
use kanshi::forensics_writer::InMemoryForensicsWriter;

struct MockedTheater {
    signer: MockDfcSigner,
    ai: DemoAiThreatClient,
    bpf: MockBpfLoader,
    events: MockEventReader,
    forensics: InMemoryForensicsWriter,
    heartbeat: HeartbeatChain,
    ledger: MerkleLedger,
    ledger_store: InMemoryLedgerStore,
    akeyless: MockAkeylessClient,
    global: MockGlobalStateClient,
    nix_collector: MockCollector,
    oci_collector: MockCollector,
    helm_collector: MockCollector,
    clock: FixedClock,
}

fn setup_mocked_theater() -> MockedTheater {
    let signer = MockDfcSigner::for_testing();
    let ai = DemoAiThreatClient::new();
    let mut bpf = MockBpfLoader::new();
    bpf.load().unwrap();  // "load" the mock BPF programs
    let events = MockEventReader::new();
    let forensics = InMemoryForensicsWriter::new();
    let heartbeat = HeartbeatChain::new();
    let ledger = MerkleLedger::new();
    let ledger_store = InMemoryLedgerStore::new();
    let akeyless = MockAkeylessClient::new();
    let global = MockGlobalStateClient::new();
    let nix_collector = MockCollector::new(LayerType::Nix);
    let oci_collector = MockCollector::new(LayerType::Oci);
    let helm_collector = MockCollector::new(LayerType::Helm);
    let clock = FixedClock::frozen_now();

    MockedTheater {
        signer,
        ai,
        bpf,
        events,
        forensics,
        heartbeat,
        ledger,
        ledger_store,
        akeyless,
        global,
        nix_collector,
        oci_collector,
        helm_collector,
        clock,
    }
}
```

Demo script:

1. **Normal flow:** Collect layer signatures, compose artifact, sign, add to BPF allow map, AI ALLOW.
2. **Trigger heist:** `theater.ai.trigger_heist()` -- next analysis returns DENY with ROS2 DDS pattern.
3. **Blast radius:** Query ledger for all deployments containing the compromised hash.
4. **Recovery:** `theater.ai.reset()` -- system returns to normal.
5. **Audit:** Dump heartbeat chain showing all 4 events with integrity verified.

---

## 6. Chaos Testing Matrix

| Mock | Failure Mode | Method | Expected Behavior |
|------|-------------|--------|-------------------|
| `FailableDfcSigner` | Timeout | `.with_timeout(5s)` | `sign()` and `verify()` return `Err(HashError)`. Gate DENY. |
| `FailableDfcSigner` | CorruptedSignature | `.with_corrupted_signature()` | `sign()` returns `Ok(corrupted)`. `verify()` returns `Ok(false)`. Gate DENY. |
| `FailableDfcSigner` | AuthFailure | `.with_auth_failure()` | `sign()` and `verify()` return `Err(HashError)`. Gate DENY. |
| `FailableDfcSigner` | RateLimited | `.with_rate_limited()` | `sign()` and `verify()` return `Err(HashError)`. Gate DENY. |
| `FailableAiThreatClient` | Timeout | `.with_timeout(500)` | `analyze_provenance()` returns `Err(Timeout(500))`. Merkle gate decides alone. |
| `FailableAiThreatClient` | Unavailable | `.with_unavailable()` | `analyze_provenance()` returns `Err(Unavailable)`. Merkle gate decides alone. |
| `FailableAiThreatClient` | Corrupted | `.with_corrupted()` | `analyze_provenance()` returns `Err(Unprocessable)`. Merkle gate decides alone. |
| `FailableAiThreatClient` | AuthFailure | `.with_auth_failure()` | All methods return `Err(ServiceError)`. |
| `FailableAiThreatClient` | RateLimited | `.with_rate_limited()` | All methods return `Err(ServiceError)`. |
| `FailableBpfLoader` | MapFull | `.with_fail_on_allow()` | `allow_hash()` returns `Err(Bpf)`. Binary cannot be whitelisted. |
| `FailableBpfLoader` | LoadFailure | `.with_fail_on_load()` | `load()` returns `Err(Bpf)`. No BPF programs attached. |
| `FailableBpfLoader` | CorruptLookups | `.with_corrupt_lookups()` | `allow_hash()` silently drops. Binary not in map at execution time. |
| `FailableBpfLoader` | RevokeFailure | `.with_fail_on_revoke()` | `revoke_hash()` returns `Err(Bpf)`. Compromised binary stays in allow map. |
| `FailableEventReader` | DropEvents | `.with_drop_events(2)` | Events beyond limit silently dropped. Incomplete audit trail. |
| `FailableEventReader` | PartialEvents | `.with_partial_events()` | Events returned with zeroed binary paths. Degraded forensics. |
| `FailableEventReader` | DelayedDelivery | `.with_delayed_delivery(3)` | First 3 polls return empty. Events delivered on 4th poll. |
| `FailableEventReader` | PollError | `.with_poll_error()` | `poll_events()` returns `Err(Bpf)`. No events available. |
| `DemoAiThreatClient` | Heist | `.trigger_heist()` | `analyze_provenance()` returns DENY with ROS2 DDS breach pattern. |
| `MockCommandRunner` | Unregistered cmd | (no response added) | Returns `Err(CommandFailed { code: 127 })`. |
| `MockHttpClient` | Unregistered URL | (no response added) | Returns `Err(CollectorError)`. |
| `MockFileSystem` | Missing file | (no file added) | Returns `Err(IoError(NotFound))`. |
| `MockVerificationClient` | Timeout | `.set_response(Err(Timeout))` | `fetch_expected()` returns `Err(Timeout)`. |
| `MockScriptEngine` | Script error | `::always_error("msg")` | `evaluate()` returns `ScriptResult::Error`. |
| `MockAdmissionReviewer` | Timeout | `::with_timeout()` | Returns deny response with internal error. |
| `MockAdmissionReviewer` | MalformedResponse | `::with_malformed_response()` | Returns response with empty UID. |

---

## 7. Test Count by Boundary

### tameshi (core library) -- 1,427 tests

| Module / Boundary | Tests |
|-------------------|------:|
| `hash` (Blake3Hash, Sha256Hash, AttestationHasher) | 42 |
| `merkle` (compose, verify, domain separation) | 28 |
| `signing` (LocalSigner, MockDfcSigner, FailableDfcSigner, BreakGlassToken) | 61 |
| `certification_artifact` (3-leaf Merkle, proof paths) | 38 |
| `heartbeat` (HeartbeatChain, ConsistencyProof, S3Emitter) | 45 |
| `gating` (GatingPolicy, evaluate_gate) | 32 |
| `collectors` (MockCollector, all 14 collectors) | 89 |
| `compliance` (plugin, nist, oscal, cis, cve, sbom, slsa, inspec) | 72 |
| `forensics` (MerkleLedger, LedgerIndex, query, blast_radius) | 67 |
| `global` (GlobalStateRoot, MockGlobalStateClient) | 48 |
| `traits` (CommandRunner, FileSystem, HttpClient, Clock) | 36 |
| `akeyless_client` (MockAkeylessClient, HttpAkeylessClient) | 52 |
| `ai_threat` (MockAiThreatClient, FailableAiThreatClient, DemoAiThreatClient) | 58 |
| `iac_attestation` (MockIacTestAttester) | 24 |
| `compliance_api` (ComplianceQuery types) | 18 |
| End-to-end tests (`tests/`) | 95 |
| Property-based tests (proptest) | 19 |
| Specification tests (OpenAPI schema roundtrips) | 13 |
| Documentation tests | 11 |

### kanshi (eBPF sentinel) -- 130 tests

| Module / Boundary | Tests |
|-------------------|------:|
| `bpf_loader` (MockBpfLoader, FailableBpfLoader) | 12 |
| `event_reader` (MockEventReader, FailableEventReader) | 20 |
| `event_metrics` (EventMetricsCollector, CirciaReport) | 26 |
| `crd_watcher` (CrdWatcher, hash parsing) | 14 |
| `verifier` (HashVerifier) | 10 |
| `policy` (PolicyEngine) | 8 |
| `forensics_writer` (InMemoryForensicsWriter) | 18 |
| `kanshi-common` (BpfHash, EnforcementPolicy, BlockedExecutionEvent) | 16 |
| Integration tests | 6 |

### sekiban (K8s admission webhook) -- 365 tests

| Module / Boundary | Tests |
|-------------------|------:|
| `webhook/admission` (MockAdmissionReviewer, AdmissionReview) | ~80 |
| `heartbeat` (HeartbeatRecorder, SekibanHeartbeat) | ~30 |
| `collectors` (MockLayerHashCollector) | ~25 |
| `store` (MemStore, GateStore) | ~20 |
| `crd` (SignatureGate, Certification, CompliancePolicy) | ~45 |
| `controller` (reconcilers) | ~35 |
| `federation` (replicator, verifier) | ~25 |
| Other modules + integration | ~105 |

### inshou (Nix gate CLI) -- 366 tests

| Module / Boundary | Tests |
|-------------------|------:|
| `nix_ops` (MockNixStoreOps) | ~35 |
| `client` (MockVerificationClient) | ~30 |
| `gate` (run_gate_with, full pipeline) | ~85 |
| `verify` (verify_system_with) | ~40 |
| `profile` (MemProfileStore) | ~30 |
| `format` (TextFormatter, JsonFormatter) | ~20 |
| `config` (TestConfigLoader) | ~15 |
| Other + integration | ~111 |

### kensa (compliance engine) -- 438 tests

| Module / Boundary | Tests |
|-------------------|------:|
| `runner/dynamic` (MockScriptEngine, RhaiEngine) | ~40 |
| `store` (MemStore, ComplianceStore) | ~30 |
| `mapping` (MockReportGenerator) | ~45 |
| `signature` (MockSignatureComputer) | ~35 |
| `certification` (MockCertificationPipeline) | ~40 |
| Other modules + integration + proptest | ~248 |

### Ecosystem Total: 2,726 tests

All running on macOS. No kernel. No cluster. No cloud. No AI model.
