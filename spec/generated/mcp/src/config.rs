use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct TameshiMcpConfig {
    pub api_url: String,
    pub api_key_file: PathBuf,
}

impl Default for TameshiMcpConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Self {
            api_url: "http://localhost:8080".into(),
            api_key_file: PathBuf::from(&home).join(".config/tameshi_mcp/api-key"),
        }
    }
}

impl TameshiMcpConfig {
    pub fn load() -> Self {
        // Priority:
        // 1. TAMESHI_MCP_CONFIG env (set by Nix HM module for MCP server context)
        // 2. XDG_CONFIG_HOME/tameshi_mcp/tameshi_mcp.yaml
        // 3. ~/.config/tameshi_mcp/tameshi_mcp.yaml
        // 4. Defaults

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());

        let candidates: Vec<PathBuf> = [
            // Nix module sets this for MCP server processes that lack user env
            std::env::var("TAMESHI_MCP_CONFIG").map(PathBuf::from).ok(),
            std::env::var("XDG_CONFIG_HOME")
                .map(|x| PathBuf::from(x).join("tameshi_mcp/tameshi_mcp.yaml"))
                .ok(),
            Some(PathBuf::from(&home).join(".config/tameshi_mcp/tameshi_mcp.yaml")),
        ]
        .into_iter()
        .flatten()
        .collect();

        for candidate in &candidates {
            if candidate.exists() {
                if let Ok(content) = std::fs::read_to_string(candidate) {
                    match serde_yaml_ng::from_str::<Self>(&content) {
                        Ok(config) => return config,
                        Err(e) => {
                            tracing::warn!("failed to parse {}: {e}", candidate.display());
                        }
                    }
                }
            }
        }

        Self::default()
    }
}
