use crate::api::types::*;
use crate::error::{TameshiMcpError, Result};

/// HTTP client for the tameshi-mcp API.
///
/// Deterministic integrity attestation and compliance verification for infrastructure.

Tameshi unifies two complementary services:

- **sekiban** -- Kubernetes integrity gating via deterministic BLAKE3 signature
  verification across infrastructure layers (Nix, OCI, Helm, Tofu, etc.).
- **kensa** -- Compliance engine that runs NIST/OSCAL assessments and drives a
  multi-stage product certification pipeline.

Together they provide a cryptographically verifiable chain from source code
through build, image, chart, deployment, and compliance -- producing a single
certification hash that attests the entire stack.

#[derive(Debug, Clone)]
pub struct TameshiMcpClient {
    inner: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl TameshiMcpClient {
    /// Create a new client.
    pub fn new(base_url: &str, api_key: &str) -> Result<Self> {
        let inner = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("pleme-io/tameshi_mcp 0.1.0")
            .build()
            .map_err(TameshiMcpError::Request)?;

        Ok(Self {
            inner,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .inner
            .get(&self.url(path))
            
            .send()
            .await
            .map_err(TameshiMcpError::Request)?;
        Self::handle_response(resp).await
    }

    async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .inner
            .post(&self.url(path))
            
            .json(body)
            .send()
            .await
            .map_err(TameshiMcpError::Request)?;
        Self::handle_response(resp).await
    }

    async fn post_empty<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .inner
            .post(&self.url(path))
            
            .send()
            .await
            .map_err(TameshiMcpError::Request)?;
        Self::handle_response(resp).await
    }

    async fn put<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .inner
            .put(&self.url(path))
            
            .json(body)
            .send()
            .await
            .map_err(TameshiMcpError::Request)?;
        Self::handle_response(resp).await
    }

    async fn patch<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .inner
            .patch(&self.url(path))
            
            .json(body)
            .send()
            .await
            .map_err(TameshiMcpError::Request)?;
        Self::handle_response(resp).await
    }

    async fn delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .inner
            .delete(&self.url(path))
            
            .send()
            .await
            .map_err(TameshiMcpError::Request)?;
        Self::handle_response(resp).await
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T> {
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(TameshiMcpError::Api { status, body });
        }
        let text = resp.text().await.map_err(TameshiMcpError::Request)?;
        serde_json::from_str(&text).map_err(TameshiMcpError::Json)
    }

    // -- Public API methods --

    /// GET /api/v1/audit/{environment}
    ///
    /// Get audit trail for environment
    pub async fn get_audit_trail(
        &self,
        environment: &str,
    ) -> Result<Vec<AuditEntry>> {
        self.get(&format!("/api/v1/audit/{environment}")).await
    }

    /// GET /api/v1/certifications
    ///
    /// List all certifications
    pub async fn list_certifications(
        &self,
    ) -> Result<Vec<CertificationSummary>> {
        self.get("/api/v1/certifications").await
    }

    /// GET /api/v1/certifications/{name}
    ///
    /// Get certification by name
    pub async fn get_certification(
        &self,
        name: &str,
    ) -> Result<Certification> {
        self.get(&format!("/api/v1/certifications/{name}")).await
    }

    /// POST /api/v1/compliance/certify
    ///
    /// Certify a product
    pub async fn certify_product(
        &self,
        req: &CertifyRequest,
    ) -> Result<ApiResponseCertifyResponse> {
        self.post("/api/v1/compliance/certify", req).await
    }

    /// GET /api/v1/compliance/hash
    ///
    /// Get latest compliance hash
    pub async fn get_compliance_hash(
        &self,
    ) -> Result<ApiResponseHashResponse> {
        self.get("/api/v1/compliance/hash").await
    }

    /// GET /api/v1/compliance/report
    ///
    /// Generate compliance report
    pub async fn get_compliance_report(
        &self,
        format: Option<Format>,
    ) -> Result<serde_json::Value> {
        let mut path = format!("/api/v1/compliance/report");
        if let Some(ref v) = format {
            path.push_str(&format!("?format={}", urlencoding::encode(&v.to_string())));
        }
        self.get(&path).await
    }

    /// GET /api/v1/compliance/results
    ///
    /// List compliance results
    pub async fn list_compliance_results(
        &self,
    ) -> Result<ApiResponseResultSummaryList> {
        self.get("/api/v1/compliance/results").await
    }

    /// GET /api/v1/compliance/results/{id}
    ///
    /// Get compliance result by ID
    pub async fn get_compliance_result(
        &self,
        id: &str,
    ) -> Result<ComplianceResult> {
        self.get(&format!("/api/v1/compliance/results/{id}")).await
    }

    /// POST /api/v1/compliance/run
    ///
    /// Run compliance assessment
    pub async fn run_compliance_assessment(
        &self,
    ) -> Result<ApiResponseRunResponse> {
        self.post_empty("/api/v1/compliance/run").await
    }

    /// GET /api/v1/gates
    ///
    /// List all signature gates
    pub async fn list_gates(
        &self,
    ) -> Result<Vec<GateSummary>> {
        self.get("/api/v1/gates").await
    }

    /// GET /api/v1/gates/{name}
    ///
    /// Get a signature gate by name
    pub async fn get_gate(
        &self,
        name: &str,
    ) -> Result<SignatureGate> {
        self.get(&format!("/api/v1/gates/{name}")).await
    }

    /// GET /api/v1/gates/{name}/verify
    ///
    /// Verify a signature gate
    pub async fn verify_gate(
        &self,
        name: &str,
    ) -> Result<GateVerifyResult> {
        self.get(&format!("/api/v1/gates/{name}/verify")).await
    }

    /// POST /api/v1/signatures/compute
    ///
    /// Compute a signature
    pub async fn compute_signature(
        &self,
        req: &ComputeSignatureRequest,
    ) -> Result<ComputeSignatureResponse> {
        self.post("/api/v1/signatures/compute", req).await
    }

    /// GET /healthz
    ///
    /// Liveness probe
    pub async fn healthz(
        &self,
    ) -> Result<serde_json::Value> {
        self.get("/healthz").await
    }

    /// GET /readyz
    ///
    /// Readiness probe
    pub async fn readyz(
        &self,
    ) -> Result<serde_json::Value> {
        self.get("/readyz").await
    }

}
