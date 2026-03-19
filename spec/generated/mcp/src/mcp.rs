use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;

use crate::auth;
use crate::client::TameshiMcpClient;
use crate::config::TameshiMcpConfig;
use crate::format;

// -- MCP tool input types --
//
// Each struct maps to an operation from the API spec. Field descriptions
// are preserved for schemars -> MCP tool schema generation.

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetAuditTrailInput {
    #[schemars(description = "Environment name (e.g. plo, zek)")]
    environment: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetCertificationInput {
    #[schemars(description = "Name of the Certification resource")]
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CertifyProductInput {
    #[schemars(description = "Build attestations for each service")]
    builds: Vec<BuildAttestation>,
    #[schemars(description = "Helm chart attestations")]
    charts: Vec<ChartAttestation>,
    #[schemars(description = "Kubernetes cluster name")]
    cluster: String,
    deployment: DeploymentAttestation,
    #[schemars(description = "Target environment (e.g. plo, zek)")]
    environment: String,
    #[schemars(description = "Container image attestations")]
    images: Vec<ImageAttestation>,
    #[schemars(description = "Name of the CertificationPolicy to evaluate against")]
    policy: Option<String>,
    #[schemars(description = "Product name being certified")]
    product: String,
    source: SourceAttestation,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetComplianceReportInput {
    #[schemars(description = "Report output format")]
    format: Option<Format>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetComplianceResultInput {
    #[schemars(description = "Unique identifier of the compliance result")]
    id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetGateInput {
    #[schemars(description = "Name of the SignatureGate resource")]
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct VerifyGateInput {
    #[schemars(description = "Name of the SignatureGate resource to verify")]
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ComputeSignatureInput {
    #[schemars(description = "Target environment name")]
    environment: String,
    #[schemars(description = "Infrastructure layers to include in the computation")]
    layers: Vec<LayerType>,
}

// -- MCP Server --

#[derive(Debug, Clone)]
struct TameshiMcpMcp {
    client: TameshiMcpClient,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl TameshiMcpMcp {
    fn new() -> Result<Self, String> {
        let config = TameshiMcpConfig::load();
        let api_key = auth::resolve_api_key(None, &config).map_err(|e| e.to_string())?;
        let client =
            TameshiMcpClient::new(&config.api_url, &api_key).map_err(|e| e.to_string())?;

        Ok(Self {
            client,
            tool_router: Self::tool_router(),
        })
    }

    #[tool(description = "Get audit trail for environment")]
    async fn get_audit_trail(&self, Parameters(input): Parameters<GetAuditTrailInput>) -> String {
        match self.client.get_audit_trail(&input.environment).await {
            Ok(result) => format::format_get_audit_trail(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List all certifications")]
    async fn list_certifications(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.list_certifications().await {
            Ok(result) => format::format_list_certifications(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get certification by name")]
    async fn get_certification(&self, Parameters(input): Parameters<GetCertificationInput>) -> String {
        match self.client.get_certification(&input.name).await {
            Ok(result) => format::format_get_certification(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Certify a product")]
    async fn certify_product(&self, Parameters(input): Parameters<CertifyProductInput>) -> String {
        let req = crate::api::types::CertifyRequest {
            builds: input.builds.clone(),
            charts: input.charts.clone(),
            cluster: input.cluster.clone(),
            deployment: input.deployment.clone(),
            environment: input.environment.clone(),
            images: input.images.clone(),
            policy: input.policy.clone(),
            product: input.product.clone(),
            source: input.source.clone(),
        };
        match self.client.certify_product(&req).await {
            Ok(result) => format::format_certify_product(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get latest compliance hash")]
    async fn get_compliance_hash(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.get_compliance_hash().await {
            Ok(result) => format::format_get_compliance_hash(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Generate compliance report")]
    async fn get_compliance_report(&self, Parameters(input): Parameters<GetComplianceReportInput>) -> String {
        match self.client.get_compliance_report(input.format.as_deref()).await {
            Ok(result) => format::format_get_compliance_report(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List compliance results")]
    async fn list_compliance_results(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.list_compliance_results().await {
            Ok(result) => format::format_list_compliance_results(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get compliance result by ID")]
    async fn get_compliance_result(&self, Parameters(input): Parameters<GetComplianceResultInput>) -> String {
        match self.client.get_compliance_result(&input.id).await {
            Ok(result) => format::format_get_compliance_result(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Run compliance assessment")]
    async fn run_compliance_assessment(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.run_compliance_assessment().await {
            Ok(result) => format::format_run_compliance_assessment(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List all signature gates")]
    async fn list_gates(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.list_gates().await {
            Ok(result) => format::format_list_gates(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get a signature gate by name")]
    async fn get_gate(&self, Parameters(input): Parameters<GetGateInput>) -> String {
        match self.client.get_gate(&input.name).await {
            Ok(result) => format::format_get_gate(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Verify a signature gate")]
    async fn verify_gate(&self, Parameters(input): Parameters<VerifyGateInput>) -> String {
        match self.client.verify_gate(&input.name).await {
            Ok(result) => format::format_verify_gate(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Compute a signature")]
    async fn compute_signature(&self, Parameters(input): Parameters<ComputeSignatureInput>) -> String {
        let req = crate::api::types::ComputeSignatureRequest {
            environment: input.environment.clone(),
            layers: input.layers.clone(),
        };
        match self.client.compute_signature(&req).await {
            Ok(result) => format::format_compute_signature(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Liveness probe")]
    async fn healthz(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.healthz().await {
            Ok(result) => format::format_healthz(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Readiness probe")]
    async fn readyz(&self, Parameters(_): Parameters<serde_json::Value>) -> String {
        match self.client.readyz().await {
            Ok(result) => format::format_readyz(&result),
            Err(e) => format!("Error: {e}"),
        }
    }

}

#[tool_handler]
impl ServerHandler for TameshiMcpMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Deterministic integrity attestation and compliance verification for infrastructure.  Tameshi unifies two complementary services:  - **sekiban** -- Kubernetes integrity gating via deterministic BLAKE3 signature   verification across infrastructure layers (Nix, OCI, Helm, Tofu, etc.). - **kensa** -- Compliance engine that runs NIST/OSCAL assessments and drives a   multi-stage product certification pipeline.  Together they provide a cryptographically verifiable chain from source code through build, image, chart, deployment, and compliance -- producing a single certification hash that attests the entire stack. "
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// -- Entry point --

pub async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let server = TameshiMcpMcp::new()?.serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
