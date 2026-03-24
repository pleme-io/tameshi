//! Agent MCP servers collector.
//!
//! Computes a [`LayerSignature`] for an AI agent's MCP (Model Context Protocol)
//! server configurations and binaries. Follows the agent_skills collector pattern
//! for directory-based traversal.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType, SignatureMetadata};
use crate::traits::FileSystem;

use super::traits::LayerCollector;

/// Transport protocol for an MCP server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    /// Standard I/O transport.
    Stdio,
    /// Server-Sent Events over HTTP.
    Sse(String),
    /// Streamable HTTP transport.
    StreamableHttp(String),
}

/// Attestation record for a single MCP server.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct McpServerAttestation {
    /// Server name identifier.
    pub server_name: String,
    /// BLAKE3 hash of the server configuration.
    pub config_hash: Blake3Hash,
    /// BLAKE3 hash of the server binary (if local).
    pub binary_hash: Option<Blake3Hash>,
    /// Transport protocol.
    pub transport: McpTransport,
    /// Tools exposed by this server.
    pub tool_names: Vec<String>,
}

/// Configuration for agent MCP servers collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMcpServersConfig {
    /// Directory containing MCP server configurations.
    pub servers_dir: String,
    /// Optional registry manifest listing all configured servers.
    pub registry_path: Option<String>,
}

/// Collector that produces a [`LayerSignature`] from MCP server configurations.
#[derive(Debug)]
pub struct AgentMcpServersCollector<F: FileSystem = crate::traits::MockFileSystem> {
    config: AgentMcpServersConfig,
    fs: F,
}

impl<F: FileSystem> AgentMcpServersCollector<F> {
    /// Create a new MCP servers collector.
    #[must_use]
    pub fn new(config: AgentMcpServersConfig, fs: F) -> Self {
        Self { config, fs }
    }
}

impl<F: FileSystem + Send + Sync> LayerCollector for AgentMcpServersCollector<F> {
    async fn collect(&self) -> Result<LayerSignature> {
        let mut inputs = Vec::new();

        // If a registry manifest exists, hash it for the overall structure
        if let Some(ref registry_path) = self.config.registry_path {
            let rpath = Path::new(registry_path);
            if let Ok(registry_content) = self.fs.read_file(rpath).await {
                inputs.push(InputHash {
                    name: "registry".into(),
                    hash: Blake3Hash::digest(&registry_content),
                    size_bytes: Some(registry_content.len() as u64),
                });
            }
        }

        // List and hash all server config files in the servers directory
        let servers_path = Path::new(&self.config.servers_dir);
        let entries = self.fs.read_dir(servers_path).await.map_err(|e| {
            crate::error::TameshiError::InvalidInput(format!(
                "failed to list MCP servers directory '{}': {e}",
                self.config.servers_dir
            ))
        })?;

        let mut sorted_entries = entries;
        sorted_entries.sort();

        for entry in &sorted_entries {
            let name = entry
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if let Ok(content) = self.fs.read_file(entry).await {
                inputs.push(InputHash {
                    name: format!("mcp_server:{name}"),
                    hash: Blake3Hash::digest(&content),
                    size_bytes: Some(content.len() as u64),
                });
            }
        }

        // Compute composite hash from sorted inputs
        let mut sorted = inputs.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher_data = Vec::with_capacity(sorted.len() * 32);
        for input in &sorted {
            hasher_data.extend_from_slice(&input.hash.0);
        }
        let composite = if hasher_data.is_empty() {
            Blake3Hash::digest(b"empty-mcp-servers")
        } else {
            Blake3Hash::digest(&hasher_data)
        };

        Ok(LayerSignature {
            layer: LayerType::AgentMcpServers,
            hash: composite,
            metadata: SignatureMetadata {
                computed_at: chrono::Utc::now(),
                collector_version: env!("CARGO_PKG_VERSION").into(),
                source: self.config.servers_dir.clone(),
                environment: None,
            },
            inputs,
        })
    }

    fn layer_type(&self) -> LayerType {
        LayerType::AgentMcpServers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockFileSystem;
    use std::path::PathBuf;

    fn make_config() -> AgentMcpServersConfig {
        AgentMcpServersConfig {
            servers_dir: "/opt/openclaw/mcp-servers".into(),
            registry_path: Some("/opt/openclaw/mcp-servers/registry.json".into()),
        }
    }

    fn make_fs() -> MockFileSystem {
        let fs = MockFileSystem::new();
        fs.add_file(
            "/opt/openclaw/mcp-servers/registry.json",
            b"{\"servers\": [\"zoekt\", \"codesearch\"]}",
        );
        fs.add_dir(
            "/opt/openclaw/mcp-servers",
            vec![
                PathBuf::from("/opt/openclaw/mcp-servers/registry.json"),
                PathBuf::from("/opt/openclaw/mcp-servers/zoekt.json"),
                PathBuf::from("/opt/openclaw/mcp-servers/codesearch.json"),
            ],
        );
        fs.add_file(
            "/opt/openclaw/mcp-servers/zoekt.json",
            b"{\"name\":\"zoekt\",\"transport\":\"stdio\",\"command\":\"zoekt-mcp\"}",
        );
        fs.add_file(
            "/opt/openclaw/mcp-servers/codesearch.json",
            b"{\"name\":\"codesearch\",\"transport\":\"stdio\",\"command\":\"codesearch\"}",
        );
        fs
    }

    #[tokio::test]
    async fn collect_produces_signature() {
        let collector = AgentMcpServersCollector::new(make_config(), make_fs());
        let sig = collector.collect().await.unwrap();

        assert_eq!(sig.layer, LayerType::AgentMcpServers);
        assert!(sig.inputs.len() >= 3);
        assert!(sig.inputs.iter().any(|i| i.name == "registry"));
    }

    #[tokio::test]
    async fn collect_hash_deterministic() {
        let c1 = AgentMcpServersCollector::new(make_config(), make_fs());
        let c2 = AgentMcpServersCollector::new(make_config(), make_fs());
        let s1 = c1.collect().await.unwrap();
        let s2 = c2.collect().await.unwrap();
        assert_eq!(s1.hash, s2.hash);
    }

    #[tokio::test]
    async fn collect_empty_dir_produces_signature() {
        let fs = MockFileSystem::new();
        fs.add_dir("/opt/openclaw/mcp-servers", vec![]);
        let config = AgentMcpServersConfig {
            servers_dir: "/opt/openclaw/mcp-servers".into(),
            registry_path: None,
        };
        let collector = AgentMcpServersCollector::new(config, fs);
        let sig = collector.collect().await.unwrap();
        assert_eq!(sig.layer, LayerType::AgentMcpServers);
        assert!(sig.inputs.is_empty());
    }

    #[test]
    fn layer_type_is_agent_mcp_servers() {
        let fs = MockFileSystem::new();
        let collector = AgentMcpServersCollector::new(make_config(), fs);
        assert_eq!(collector.layer_type(), LayerType::AgentMcpServers);
    }

    #[test]
    fn mcp_transport_serde_roundtrip() {
        let transports = vec![
            McpTransport::Stdio,
            McpTransport::Sse("http://localhost:8080".into()),
            McpTransport::StreamableHttp("http://localhost:9090/mcp".into()),
        ];
        for transport in &transports {
            let json = serde_json::to_string(transport).unwrap();
            let parsed: McpTransport = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, transport);
        }
    }

    #[test]
    fn mcp_server_attestation_serde_roundtrip() {
        let att = McpServerAttestation {
            server_name: "zoekt".into(),
            config_hash: Blake3Hash::digest(b"zoekt-config"),
            binary_hash: Some(Blake3Hash::digest(b"zoekt-binary")),
            transport: McpTransport::Stdio,
            tool_names: vec!["search".into(), "list_repos".into()],
        };
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: McpServerAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.server_name, "zoekt");
        assert_eq!(deserialized.config_hash, att.config_hash);
    }
}
