use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum TameshiMcpError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("API returned {status}: {body}")]
    Api { status: u16, body: String },

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("API key not found -- set --api-key, TAMESHI_MCP_API_KEY, or create {path}")]
    NoApiKey { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, TameshiMcpError>;
