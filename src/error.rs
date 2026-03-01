//! Error types for tameshi operations.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TameshiError {
    #[error("hash computation failed: {0}")]
    HashError(String),

    #[error("collector error for layer {layer}: {message}")]
    CollectorError { layer: String, message: String },

    #[error("verification failed: expected {expected}, got {actual}")]
    VerificationFailed { expected: String, actual: String },

    #[error("merkle tree construction failed: {0}")]
    MerkleError(String),

    #[error("compliance error: {0}")]
    ComplianceError(String),

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("command execution failed: {command} exited with {code}: {stderr}")]
    CommandFailed {
        command: String,
        code: i32,
        stderr: String,
    },

    #[error("http request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, TameshiError>;
