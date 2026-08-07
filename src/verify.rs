//! Signature verification logic.
//!
//! Provides functions to verify layer signatures, master signatures,
//! and perform full attestation checks including compliance.

use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::signature::MasterSignature;

/// Result of a verification check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    /// Whether verification passed.
    pub passed: bool,
    /// The expected hash.
    pub expected: Blake3Hash,
    /// The actual computed hash.
    pub actual: Blake3Hash,
    /// Human-readable description of what was verified.
    pub description: String,
    /// Per-layer verification results (if applicable).
    pub layer_results: Vec<LayerVerification>,
}

/// Verification status for a single layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerVerification {
    /// Layer name.
    pub layer: String,
    /// Whether this layer's hash matches.
    pub passed: bool,
    /// Expected hash.
    pub expected: Blake3Hash,
    /// Actual hash.
    pub actual: Blake3Hash,
}

/// Verify a master signature against an expected hash.
///
/// Checks:
/// 1. Untested signature matches Merkle root recomputation
/// 2. If compliance is present, secure signature is valid
/// 3. Gating signature matches expected
#[inline]
#[must_use]
pub fn verify_master(master: &MasterSignature, expected: &Blake3Hash) -> VerificationResult {
    let actual = master.gating_signature().clone();
    let untested_valid = master.verify_untested();

    let secure_valid = if master.is_fully_attested() {
        master.verify_secure()
    } else {
        true // No compliance to verify
    };

    let passed = untested_valid && secure_valid && actual == *expected;

    VerificationResult {
        passed,
        expected: expected.clone(),
        actual: actual.clone(),
        description: format!(
            "Master signature verification for environment '{}': untested={}, secure={}, match={}",
            master.environment,
            untested_valid,
            secure_valid,
            actual == *expected
        ),
        layer_results: vec![],
    }
}

/// Verify that a master signature's untested hash matches the expected value.
#[inline]
pub fn verify_untested(master: &MasterSignature, expected: &Blake3Hash) -> Result<()> {
    if master.untested != *expected {
        return Err(TameshiError::VerificationFailed {
            expected: expected.to_hex(),
            actual: master.untested.to_hex(),
        });
    }
    if !master.verify_untested() {
        return Err(TameshiError::VerificationFailed {
            expected: "valid merkle root".to_string(),
            actual: "merkle root recomputation mismatch".to_string(),
        });
    }
    Ok(())
}

/// Verify the full secure signature (untested + compliance).
#[inline]
pub fn verify_secure(master: &MasterSignature, expected: &Blake3Hash) -> Result<()> {
    let gating = master.gating_signature();
    if *gating != *expected {
        return Err(TameshiError::VerificationFailed {
            expected: expected.to_hex(),
            actual: gating.to_hex(),
        });
    }
    if !master.verify_untested() {
        return Err(TameshiError::VerificationFailed {
            expected: "valid merkle root".to_string(),
            actual: "merkle root recomputation mismatch".to_string(),
        });
    }
    if master.is_fully_attested() && !master.verify_secure() {
        return Err(TameshiError::VerificationFailed {
            expected: "valid secure composition".to_string(),
            actual: "secure signature recomputation mismatch".to_string(),
        });
    }
    Ok(())
}

/// Verify that a prefixed signature string matches the master.
#[inline]
pub fn verify_prefixed(master: &MasterSignature, prefixed: &str) -> Result<()> {
    let expected = Blake3Hash::from_prefixed(prefixed).map_err(|e| {
        TameshiError::InvalidInput(format!("invalid prefixed hash '{}': {}", prefixed, e))
    })?;
    verify_secure(master, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::signature::{LayerSignature, LayerType};

    fn make_layer(layer: LayerType, data: &[u8]) -> LayerSignature {
        LayerSignature::new(layer, Blake3Hash::digest(data), "test", vec![])
    }

    #[test]
    fn verify_master_pass() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        let master = merkle::compose_merkle(&layers, "test");
        let expected = master.gating_signature().clone();
        let result = verify_master(&master, &expected);
        assert!(result.passed);
    }

    #[test]
    fn verify_master_fail_wrong_hash() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let wrong = Blake3Hash::digest(b"wrong");
        let result = verify_master(&master, &wrong);
        assert!(!result.passed);
    }

    #[test]
    fn verify_untested_ok() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let expected = master.untested.clone();
        assert!(verify_untested(&master, &expected).is_ok());
    }

    #[test]
    fn verify_secure_with_compliance() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        let compliance = Blake3Hash::digest(b"compliance-passed");
        let master = merkle::compose_merkle(&layers, "prod").with_compliance(compliance);
        let expected = master.gating_signature().clone();
        assert!(verify_secure(&master, &expected).is_ok());
    }

    #[test]
    fn verify_prefixed_roundtrip() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let prefixed = master.gating_signature_prefixed();
        assert!(verify_prefixed(&master, &prefixed).is_ok());
    }

    #[test]
    fn verify_prefixed_invalid_format() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let result = verify_prefixed(&master, "not-a-valid-hash");
        assert!(result.is_err());
    }

    #[test]
    fn verify_untested_wrong_hash() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let wrong = Blake3Hash::digest(b"wrong");
        let result = verify_untested(&master, &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn verify_secure_wrong_hash() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
        ];
        let compliance = Blake3Hash::digest(b"compliance");
        let master = merkle::compose_merkle(&layers, "prod").with_compliance(compliance);
        let wrong = Blake3Hash::digest(b"wrong-secure");
        let result = verify_secure(&master, &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn verify_master_description_contains_environment() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "my-env");
        let expected = master.gating_signature().clone();
        let result = verify_master(&master, &expected);
        assert!(result.description.contains("my-env"));
    }

    #[test]
    fn verification_result_equality() {
        let h1 = Blake3Hash::digest(b"a");
        let h2 = Blake3Hash::digest(b"a");
        let r1 = VerificationResult {
            passed: true,
            expected: h1.clone(),
            actual: h1.clone(),
            description: "test".to_string(),
            layer_results: vec![],
        };
        let r2 = VerificationResult {
            passed: true,
            expected: h2.clone(),
            actual: h2,
            description: "test".to_string(),
            layer_results: vec![],
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn verify_master_without_compliance_uses_untested() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix-data"),
            make_layer(LayerType::Oci, b"oci-data"),
        ];
        let master = merkle::compose_merkle(&layers, "staging");
        assert!(!master.is_fully_attested());
        let expected = master.gating_signature().clone();
        assert_eq!(
            expected, master.untested,
            "without compliance, gating = untested"
        );
        let result = verify_master(&master, &expected);
        assert!(result.passed);
    }

    #[test]
    fn verify_secure_without_compliance_still_passes() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "dev");
        let expected = master.gating_signature().clone();
        assert!(verify_secure(&master, &expected).is_ok());
    }

    #[test]
    fn verify_untested_mismatch_error_message() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let wrong = Blake3Hash::digest(b"wrong");
        let err = verify_untested(&master, &wrong).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected") || msg.contains("got") || msg.contains("verification"),
            "error should describe the mismatch: {}",
            msg
        );
    }

    #[test]
    fn verify_secure_wrong_hash_error_message() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let compliance = Blake3Hash::digest(b"compliance");
        let master = merkle::compose_merkle(&layers, "prod").with_compliance(compliance);
        let wrong = Blake3Hash::digest(b"wrong");
        let err = verify_secure(&master, &wrong).unwrap_err();
        assert!(
            err.to_string().contains(wrong.to_hex().as_str())
                || err.to_string().contains("expected")
        );
    }

    #[test]
    fn verify_prefixed_wrong_hash_value() {
        let layers = vec![make_layer(LayerType::Nix, b"nix")];
        let master = merkle::compose_merkle(&layers, "test");
        let wrong_prefixed = format!("blake3:{}", Blake3Hash::digest(b"wrong").to_hex());
        let result = verify_prefixed(&master, &wrong_prefixed);
        assert!(result.is_err());
    }

    #[test]
    fn verify_master_with_compliance_both_checked() {
        let layers = vec![
            make_layer(LayerType::Nix, b"nix"),
            make_layer(LayerType::Oci, b"oci"),
            make_layer(LayerType::Helm, b"helm"),
        ];
        let compliance = Blake3Hash::digest(b"compliance-hash");
        let master = merkle::compose_merkle(&layers, "prod").with_compliance(compliance);
        assert!(master.is_fully_attested());
        let expected = master.gating_signature().clone();
        let result = verify_master(&master, &expected);
        assert!(result.passed);
        assert!(result.description.contains("prod"));
    }

    #[test]
    fn layer_verification_equality() {
        let h = Blake3Hash::digest(b"test");
        let lv1 = LayerVerification {
            layer: "nix".to_string(),
            passed: true,
            expected: h.clone(),
            actual: h.clone(),
        };
        let lv2 = LayerVerification {
            layer: "nix".to_string(),
            passed: true,
            expected: h.clone(),
            actual: h,
        };
        assert_eq!(lv1, lv2);
    }

    #[test]
    fn verification_result_clone() {
        let h = Blake3Hash::digest(b"clone-test");
        let result = VerificationResult {
            passed: true,
            expected: h.clone(),
            actual: h,
            description: "clone test".to_string(),
            layer_results: vec![],
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }
}
