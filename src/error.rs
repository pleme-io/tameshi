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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = TameshiError::HashError("bad hash".to_string());
        assert!(err.to_string().contains("bad hash"));

        let err = TameshiError::CollectorError {
            layer: "nix".to_string(),
            message: "failed".to_string(),
        };
        assert!(err.to_string().contains("nix"));
        assert!(err.to_string().contains("failed"));

        let err = TameshiError::CommandFailed {
            command: "nix-store".to_string(),
            code: 1,
            stderr: "error output".to_string(),
        };
        assert!(err.to_string().contains("nix-store"));
        assert!(err.to_string().contains("error output"));

        let err = TameshiError::InvalidInput("bad input".to_string());
        assert!(err.to_string().contains("bad input"));

        let err = TameshiError::ConfigError("missing field".to_string());
        assert!(err.to_string().contains("missing field"));

        let err = TameshiError::MerkleError("tree failed".to_string());
        assert!(err.to_string().contains("tree failed"));

        let err = TameshiError::ComplianceError("compliance issue".to_string());
        assert!(err.to_string().contains("compliance issue"));

        let err = TameshiError::VerificationFailed {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        };
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("def"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let tameshi_err: TameshiError = io_err.into();
        assert!(matches!(tameshi_err, TameshiError::IoError(_)));
    }

    #[test]
    fn serde_error_conversion() {
        let bad_json = "not json";
        let serde_err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let tameshi_err: TameshiError = serde_err.into();
        assert!(matches!(tameshi_err, TameshiError::SerializationError(_)));
    }
}
