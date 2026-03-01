//! Nix store closure collector.
//!
//! Computes BLAKE3 hashes of Nix store closures by querying `nix-store --query
//! --requisites` and hashing each store path in sorted order.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::{InputHash, LayerSignature, LayerType};

use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// Hash a Nix store closure.
///
/// Runs `nix-store --query --requisites <path>` to get all transitive
/// dependencies, hashes each path's content, sorts, and computes the
/// composite hash via sorted concatenation.
pub async fn hash_closure(store_path: &str) -> Result<LayerSignature> {
    let output = Command::new("nix-store")
        .args(["--query", "--requisites", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("nix-store --query --requisites {}", store_path),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut paths: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    paths.sort();

    debug!(path_count = paths.len(), "Hashing Nix closure");

    let mut inputs = Vec::with_capacity(paths.len());
    for path in &paths {
        let hash = hash_store_path(path).await?;
        inputs.push(InputHash {
            name: path.to_string(),
            hash,
            size_bytes: None,
        });
    }

    let composite = compute_composite_hash(&inputs);
    Ok(LayerSignature::new(
        LayerType::Nix,
        composite,
        store_path,
        inputs,
    ))
}

/// Hash the current system profile.
///
/// On NixOS: `/run/current-system`
/// On nix-darwin: `/run/current-system` or the current profile link
pub async fn hash_system_profile() -> Result<LayerSignature> {
    let profile_path = if cfg!(target_os = "macos") {
        "/run/current-system".to_string()
    } else {
        "/run/current-system".to_string()
    };

    // Resolve the symlink to get the actual store path
    let resolved = tokio::fs::read_link(&profile_path).await.map_err(|e| {
        TameshiError::CollectorError {
            layer: "nix".to_string(),
            message: format!("failed to resolve system profile at {}: {}", profile_path, e),
        }
    })?;

    hash_closure(resolved.to_string_lossy().as_ref()).await
}

/// Hash a specific flake output.
///
/// Runs `nix build <flake_ref> --no-link --print-out-paths` and then
/// hashes the resulting store closure.
pub async fn hash_flake_output(flake_ref: &str) -> Result<LayerSignature> {
    let output = Command::new("nix")
        .args(["build", flake_ref, "--no-link", "--print-out-paths"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(TameshiError::CommandFailed {
            command: format!("nix build {}", flake_ref),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let store_path = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();

    if store_path.is_empty() {
        return Err(TameshiError::CollectorError {
            layer: "nix".to_string(),
            message: format!("nix build {} produced no output paths", flake_ref),
        });
    }

    hash_closure(&store_path).await
}

/// Hash a single Nix store path using `nix-store --dump`.
///
/// This produces the NAR (Nix Archive) serialization of the path,
/// which is the canonical content representation.
async fn hash_store_path(path: &str) -> Result<Blake3Hash> {
    let output = Command::new("nix-store")
        .args(["--dump", path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        // Fall back to hashing the path string if we can't dump
        // (e.g., path doesn't exist locally but is in the closure query)
        debug!(path = path, "nix-store --dump failed, hashing path string");
        return Ok(Blake3Hash::digest(path.as_bytes()));
    }

    Ok(Blake3Hash::digest(&output.stdout))
}

/// Compute composite hash from sorted input hashes.
fn compute_composite_hash(inputs: &[InputHash]) -> Blake3Hash {
    if inputs.is_empty() {
        return Blake3Hash::digest(b"empty-nix-closure");
    }
    let mut data = Vec::new();
    for input in inputs {
        data.extend_from_slice(&input.hash.0);
    }
    Blake3Hash::digest(&data)
}
