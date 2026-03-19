use clap::Parser;
use std::process::ExitCode;

mod api;
mod auth;
mod client;
mod config;
mod error;
mod format;
mod mcp;

use config::TameshiMcpConfig;

#[derive(Parser)]
#[command(name = "tameshi_mcp", about = "Deterministic integrity attestation and compliance verification for infrastructure.

Tameshi unifies two complementary services:

- **sekiban** -- Kubernetes integrity gating via deterministic BLAKE3 signature
  verification across infrastructure layers (Nix, OCI, Helm, Tofu, etc.).
- **kensa** -- Compliance engine that runs NIST/OSCAL assessments and drives a
  multi-stage product certification pipeline.

Together they provide a cryptographically verifiable chain from source code
through build, image, chart, deployment, and compliance -- producing a single
certification hash that attests the entire stack.
")]
struct Cli {
    /// Run in MCP server mode (default when no subcommand given)
    #[command(subcommand)]
    command: Option<Command>,

    /// API key (overrides env and config file)
    #[arg(long)]
    api_key: Option<String>,

    /// API base URL (overrides config)
    #[arg(long)]
    api_url: Option<String>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run the MCP server on stdio
    Serve,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // No subcommand or explicit serve -> MCP server mode (stdio)
    match cli.command {
        None | Some(Command::Serve) => {
            init_tracing(true);
            if let Err(e) = mcp::run().await {
                eprintln!("MCP server error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

fn init_tracing(json: bool) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    if json {
        fmt().json().with_env_filter(filter).with_writer(std::io::stderr).init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}
