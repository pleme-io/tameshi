//! Content canonicalization for deterministic hashing.
//!
//! When hashing infrastructure content (YAML manifests, JSON state files, HCL configs),
//! non-semantic differences like key ordering, whitespace, and comments can produce
//! different hashes for logically identical content. This module provides canonicalization
//! strategies to normalize content before hashing.
//!
//! # Modes
//!
//! - **Strict**: Byte-for-byte hashing. No normalization. Use for binary content or
//!   when exact reproduction is required (Nix store paths, OCI layers).
//! - **Logical**: Parse → normalize → serialize. Strips comments, sorts keys,
//!   normalizes whitespace. Use for configuration files where semantic equality matters.
//!
//! # Example
//!
//! ```rust
//! use tameshi::canonicalize::{CanonicalMode, Canonicalizer, YamlCanonicalizer, JsonCanonicalizer};
//!
//! let yaml1 = b"b: 2\na: 1\n# comment\n";
//! let yaml2 = b"a: 1\nb: 2\n";
//!
//! let c = YamlCanonicalizer;
//!
//! // Logical mode: same content regardless of key order or comments
//! let out1 = c.canonicalize(yaml1, CanonicalMode::Logical);
//! let out2 = c.canonicalize(yaml2, CanonicalMode::Logical);
//! assert_eq!(out1, out2);
//!
//! // Strict mode: byte-for-byte, so different
//! let s1 = c.canonicalize(yaml1, CanonicalMode::Strict);
//! let s2 = c.canonicalize(yaml2, CanonicalMode::Strict);
//! assert_ne!(s1, s2);
//! ```

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Canonicalization mode for content hashing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CanonicalMode {
    /// Byte-for-byte hashing. No normalization applied.
    /// Use for binary content, Nix store paths, OCI layers.
    #[default]
    Strict,
    /// Parse → normalize → serialize. Strips comments, sorts keys,
    /// normalizes whitespace. Use for YAML/JSON/HCL configuration.
    Logical,
}

impl std::fmt::Display for CanonicalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Logical => write!(f, "logical"),
        }
    }
}

impl std::str::FromStr for CanonicalMode {
    type Err = crate::error::TameshiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "logical" => Ok(Self::Logical),
            other => Err(crate::error::TameshiError::InvalidInput(format!(
                "unknown canonical mode: '{other}' (expected 'strict' or 'logical')"
            ))),
        }
    }
}

/// Trait for content canonicalization before hashing.
///
/// Implementations know how to parse and normalize specific content formats
/// (YAML, JSON, HCL, etc.) into a canonical byte representation.
pub trait Canonicalizer: Send + Sync {
    /// Canonicalize content according to the specified mode.
    ///
    /// - `Strict`: returns the content unchanged (identity passthrough)
    /// - `Logical`: parses, normalizes, and re-serializes the content
    ///
    /// On parse failure in Logical mode, falls back to Strict (raw bytes).
    fn canonicalize<'a>(&self, content: &'a [u8], mode: CanonicalMode) -> Cow<'a, [u8]>;

    /// The content format this canonicalizer handles (for logging/diagnostics).
    fn format_name(&self) -> &str;
}

/// YAML canonicalizer — sorts keys, strips comments, normalizes whitespace.
///
/// Uses `serde_yaml_ng` to parse YAML into a `serde_json::Value` (which
/// normalizes types), then serializes as sorted-key JSON for determinism.
pub struct YamlCanonicalizer;

impl Canonicalizer for YamlCanonicalizer {
    fn canonicalize<'a>(&self, content: &'a [u8], mode: CanonicalMode) -> Cow<'a, [u8]> {
        match mode {
            CanonicalMode::Strict => Cow::Borrowed(content),
            CanonicalMode::Logical => {
                let Ok(content_str) = std::str::from_utf8(content) else {
                    return Cow::Borrowed(content);
                };
                let Ok(value) = serde_yaml_ng::from_str::<serde_json::Value>(content_str) else {
                    return Cow::Borrowed(content);
                };
                let normalized = normalize_json_value(&value);
                Cow::Owned(serde_json::to_vec(&normalized).unwrap_or_else(|_| content.to_vec()))
            }
        }
    }

    #[inline]
    fn format_name(&self) -> &str {
        "yaml"
    }
}

/// JSON canonicalizer — sorts keys, normalizes whitespace.
///
/// Parses JSON, recursively sorts all object keys via `BTreeMap`, and
/// re-serializes without extra whitespace.
pub struct JsonCanonicalizer;

impl Canonicalizer for JsonCanonicalizer {
    fn canonicalize<'a>(&self, content: &'a [u8], mode: CanonicalMode) -> Cow<'a, [u8]> {
        match mode {
            CanonicalMode::Strict => Cow::Borrowed(content),
            CanonicalMode::Logical => {
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(content) else {
                    return Cow::Borrowed(content);
                };
                let normalized = normalize_json_value(&value);
                Cow::Owned(serde_json::to_vec(&normalized).unwrap_or_else(|_| content.to_vec()))
            }
        }
    }

    #[inline]
    fn format_name(&self) -> &str {
        "json"
    }
}

/// HCL canonicalizer — parses HCL, converts to sorted JSON representation.
///
/// Since HCL is a superset of JSON in structure, we parse it and convert
/// to canonical JSON for deterministic hashing. Falls back to strict mode
/// if parsing fails (e.g., complex HCL expressions).
///
/// Note: This performs best-effort canonicalization. Complex HCL features
/// (functions, conditionals, dynamic blocks) may not parse correctly and
/// will fall back to strict byte-for-byte hashing.
pub struct HclCanonicalizer;

impl Canonicalizer for HclCanonicalizer {
    fn canonicalize<'a>(&self, content: &'a [u8], mode: CanonicalMode) -> Cow<'a, [u8]> {
        match mode {
            CanonicalMode::Strict => Cow::Borrowed(content),
            CanonicalMode::Logical => {
                // HCL files are often valid JSON (terraform state files)
                // Try JSON first, then fall back to raw content
                let Ok(content_str) = std::str::from_utf8(content) else {
                    return Cow::Borrowed(content);
                };
                // Try JSON parse first (Tofu state files are JSON)
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(content_str) {
                    let normalized = normalize_json_value(&value);
                    return Cow::Owned(serde_json::to_vec(&normalized)
                        .unwrap_or_else(|_| content.to_vec()));
                }
                // For actual HCL (.tf files), we hash raw content since
                // HCL parsing requires the hcl-rs crate which is optional.
                // The plan uses `tofu show -json` which outputs JSON anyway.
                Cow::Borrowed(content)
            }
        }
    }

    #[inline]
    fn format_name(&self) -> &str {
        "hcl"
    }
}

/// Raw canonicalizer — identity passthrough in all modes.
///
/// Use for content that is already canonical (Nix store paths, OCI layers)
/// or binary content that cannot be parsed.
pub struct RawCanonicalizer;

impl Canonicalizer for RawCanonicalizer {
    fn canonicalize<'a>(&self, content: &'a [u8], _mode: CanonicalMode) -> Cow<'a, [u8]> {
        Cow::Borrowed(content)
    }

    #[inline]
    fn format_name(&self) -> &str {
        "raw"
    }
}

/// Normalize a JSON value by recursively sorting all object keys.
///
/// This is the core canonicalization function shared by YAML, JSON, and HCL
/// canonicalizers. It ensures deterministic serialization regardless of the
/// original key ordering.
fn normalize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), normalize_json_value(v)))
                .collect();
            serde_json::to_value(sorted).unwrap_or_default()
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(normalize_json_value).collect())
        }
        other => other.clone(),
    }
}

/// Select the appropriate canonicalizer for a given content type.
///
/// Returns a boxed canonicalizer based on the content type hint.
/// Falls back to `RawCanonicalizer` for unknown types.
#[must_use]
pub fn canonicalizer_for(content_type: &str) -> Box<dyn Canonicalizer> {
    match content_type.to_lowercase().as_str() {
        "yaml" | "yml" => Box::new(YamlCanonicalizer),
        "json" => Box::new(JsonCanonicalizer),
        "hcl" | "tf" => Box::new(HclCanonicalizer),
        _ => Box::new(RawCanonicalizer),
    }
}

/// Canonicalize content and compute its BLAKE3 hash.
///
/// Convenience function that combines canonicalization and hashing.
#[must_use]
pub fn canonical_hash(
    content: &[u8],
    mode: CanonicalMode,
    canonicalizer: &dyn Canonicalizer,
) -> crate::hash::Blake3Hash {
    let canonical = canonicalizer.canonicalize(content, mode);
    crate::hash::Blake3Hash::digest(canonical.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Blake3Hash;

    // =========================================================================
    // CanonicalMode tests
    // =========================================================================

    #[test]
    fn canonical_mode_default_is_strict() {
        assert_eq!(CanonicalMode::default(), CanonicalMode::Strict);
    }

    #[test]
    fn canonical_mode_display() {
        assert_eq!(CanonicalMode::Strict.to_string(), "strict");
        assert_eq!(CanonicalMode::Logical.to_string(), "logical");
    }

    #[test]
    fn canonical_mode_from_str() {
        assert_eq!("strict".parse::<CanonicalMode>().unwrap(), CanonicalMode::Strict);
        assert_eq!("logical".parse::<CanonicalMode>().unwrap(), CanonicalMode::Logical);
        assert_eq!("STRICT".parse::<CanonicalMode>().unwrap(), CanonicalMode::Strict);
        assert_eq!("Logical".parse::<CanonicalMode>().unwrap(), CanonicalMode::Logical);
        assert!("invalid".parse::<CanonicalMode>().is_err());
    }

    #[test]
    fn canonical_mode_serde_roundtrip() {
        let modes = [CanonicalMode::Strict, CanonicalMode::Logical];
        for mode in &modes {
            let json = serde_json::to_string(mode).unwrap();
            let deserialized: CanonicalMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, &deserialized);
        }
    }

    // =========================================================================
    // YAML canonicalizer tests
    // =========================================================================

    #[test]
    fn yaml_strict_preserves_bytes() {
        let content = b"b: 2\na: 1\n# comment\n";
        let result = YamlCanonicalizer.canonicalize(content, CanonicalMode::Strict);
        assert_eq!(&*result, content);
    }

    #[test]
    fn yaml_logical_sorts_keys() {
        let yaml1 = b"b: 2\na: 1\n";
        let yaml2 = b"a: 1\nb: 2\n";
        let c1 = YamlCanonicalizer.canonicalize(yaml1, CanonicalMode::Logical);
        let c2 = YamlCanonicalizer.canonicalize(yaml2, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Key reordering should produce same canonical form");
    }

    #[test]
    fn yaml_logical_strips_comments() {
        let with_comment = b"a: 1\n# this is a comment\nb: 2\n";
        let without_comment = b"a: 1\nb: 2\n";
        let c1 = YamlCanonicalizer.canonicalize(with_comment, CanonicalMode::Logical);
        let c2 = YamlCanonicalizer.canonicalize(without_comment, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Comments should be stripped in logical mode");
    }

    #[test]
    fn yaml_logical_normalizes_whitespace() {
        let yaml1 = b"a:   1\nb:    2\n";
        let yaml2 = b"a: 1\nb: 2\n";
        let c1 = YamlCanonicalizer.canonicalize(yaml1, CanonicalMode::Logical);
        let c2 = YamlCanonicalizer.canonicalize(yaml2, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Extra whitespace should be normalized");
    }

    #[test]
    fn yaml_logical_nested_keys_sorted() {
        let yaml1 = b"z:\n  b: 2\n  a: 1\na:\n  d: 4\n  c: 3\n";
        let yaml2 = b"a:\n  c: 3\n  d: 4\nz:\n  a: 1\n  b: 2\n";
        let c1 = YamlCanonicalizer.canonicalize(yaml1, CanonicalMode::Logical);
        let c2 = YamlCanonicalizer.canonicalize(yaml2, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Nested keys should be recursively sorted");
    }

    #[test]
    fn yaml_logical_fallback_on_invalid() {
        let invalid = b"not: valid: yaml: [[[";
        let result = YamlCanonicalizer.canonicalize(invalid, CanonicalMode::Logical);
        assert_eq!(&*result, invalid, "Invalid YAML should fallback to strict");
    }

    #[test]
    fn yaml_logical_binary_fallback() {
        let binary = &[0xFF, 0xFE, 0x00, 0x01];
        let result = YamlCanonicalizer.canonicalize(binary, CanonicalMode::Logical);
        assert_eq!(&*result, binary, "Binary content should fallback to strict");
    }

    #[test]
    fn yaml_format_name() {
        assert_eq!(YamlCanonicalizer.format_name(), "yaml");
    }

    // =========================================================================
    // JSON canonicalizer tests
    // =========================================================================

    #[test]
    fn json_strict_preserves_bytes() {
        let content = b"{\"b\":2,\"a\":1}";
        let result = JsonCanonicalizer.canonicalize(content, CanonicalMode::Strict);
        assert_eq!(&*result, content);
    }

    #[test]
    fn json_logical_sorts_keys() {
        let json1 = b"{\"b\":2,\"a\":1}";
        let json2 = b"{\"a\":1,\"b\":2}";
        let c1 = JsonCanonicalizer.canonicalize(json1, CanonicalMode::Logical);
        let c2 = JsonCanonicalizer.canonicalize(json2, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Key reordering should produce same canonical form");
    }

    #[test]
    fn json_logical_normalizes_whitespace() {
        let compact = b"{\"a\":1,\"b\":2}";
        let pretty = b"{\n  \"a\": 1,\n  \"b\": 2\n}";
        let c1 = JsonCanonicalizer.canonicalize(compact, CanonicalMode::Logical);
        let c2 = JsonCanonicalizer.canonicalize(pretty, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Whitespace should be normalized");
    }

    #[test]
    fn json_logical_nested_objects() {
        let json1 = b"{\"z\":{\"b\":2,\"a\":1},\"a\":{\"d\":4,\"c\":3}}";
        let json2 = b"{\"a\":{\"c\":3,\"d\":4},\"z\":{\"a\":1,\"b\":2}}";
        let c1 = JsonCanonicalizer.canonicalize(json1, CanonicalMode::Logical);
        let c2 = JsonCanonicalizer.canonicalize(json2, CanonicalMode::Logical);
        assert_eq!(c1, c2, "Nested objects should be recursively sorted");
    }

    #[test]
    fn json_logical_preserves_arrays() {
        let json = b"[3,1,2]";
        let result = JsonCanonicalizer.canonicalize(json, CanonicalMode::Logical);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed, serde_json::json!([3, 1, 2]), "Arrays should preserve order");
    }

    #[test]
    fn json_logical_fallback_on_invalid() {
        let invalid = b"not json at all";
        let result = JsonCanonicalizer.canonicalize(invalid, CanonicalMode::Logical);
        assert_eq!(&*result, invalid, "Invalid JSON should fallback to strict");
    }

    #[test]
    fn json_format_name() {
        assert_eq!(JsonCanonicalizer.format_name(), "json");
    }

    // =========================================================================
    // HCL canonicalizer tests
    // =========================================================================

    #[test]
    fn hcl_strict_preserves_bytes() {
        let content = b"resource \"aws_instance\" \"main\" {}";
        let result = HclCanonicalizer.canonicalize(content, CanonicalMode::Strict);
        assert_eq!(&*result, content);
    }

    #[test]
    fn hcl_logical_json_state_file() {
        // Tofu state files are JSON — HCL canonicalizer should handle them
        let state1 = b"{\"version\":4,\"resources\":[]}";
        let state2 = b"{\"resources\":[],\"version\":4}";
        let c1 = HclCanonicalizer.canonicalize(state1, CanonicalMode::Logical);
        let c2 = HclCanonicalizer.canonicalize(state2, CanonicalMode::Logical);
        assert_eq!(c1, c2, "JSON state files should be canonicalized");
    }

    #[test]
    fn hcl_logical_non_json_fallback() {
        // Pure HCL (non-JSON) falls back to raw
        let hcl = b"resource \"aws_instance\" \"main\" {\n  ami = \"abc\"\n}";
        let result = HclCanonicalizer.canonicalize(hcl, CanonicalMode::Logical);
        assert_eq!(&*result, hcl, "Non-JSON HCL should fallback to strict");
    }

    #[test]
    fn hcl_format_name() {
        assert_eq!(HclCanonicalizer.format_name(), "hcl");
    }

    // =========================================================================
    // Raw canonicalizer tests
    // =========================================================================

    #[test]
    fn raw_always_preserves_bytes() {
        let content = b"anything \xff\xfe goes here";
        let strict = RawCanonicalizer.canonicalize(content, CanonicalMode::Strict);
        let logical = RawCanonicalizer.canonicalize(content, CanonicalMode::Logical);
        assert_eq!(&*strict, content);
        assert_eq!(&*logical, content);
    }

    #[test]
    fn raw_format_name() {
        assert_eq!(RawCanonicalizer.format_name(), "raw");
    }

    // =========================================================================
    // canonicalizer_for factory tests
    // =========================================================================

    #[test]
    fn factory_selects_correct_canonicalizer() {
        assert_eq!(canonicalizer_for("yaml").format_name(), "yaml");
        assert_eq!(canonicalizer_for("yml").format_name(), "yaml");
        assert_eq!(canonicalizer_for("json").format_name(), "json");
        assert_eq!(canonicalizer_for("hcl").format_name(), "hcl");
        assert_eq!(canonicalizer_for("tf").format_name(), "hcl");
        assert_eq!(canonicalizer_for("unknown").format_name(), "raw");
        assert_eq!(canonicalizer_for("YAML").format_name(), "yaml");
        assert_eq!(canonicalizer_for("JSON").format_name(), "json");
    }

    // =========================================================================
    // canonical_hash convenience function
    // =========================================================================

    #[test]
    fn canonical_hash_yaml_logical() {
        let yaml1 = b"b: 2\na: 1\n";
        let yaml2 = b"a: 1\nb: 2\n";
        let h1 = canonical_hash(yaml1, CanonicalMode::Logical, &YamlCanonicalizer);
        let h2 = canonical_hash(yaml2, CanonicalMode::Logical, &YamlCanonicalizer);
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_hash_yaml_strict_differs() {
        let yaml1 = b"b: 2\na: 1\n";
        let yaml2 = b"a: 1\nb: 2\n";
        let h1 = canonical_hash(yaml1, CanonicalMode::Strict, &YamlCanonicalizer);
        let h2 = canonical_hash(yaml2, CanonicalMode::Strict, &YamlCanonicalizer);
        assert_ne!(h1, h2, "Strict mode should hash raw bytes differently");
    }

    // =========================================================================
    // Hash determinism across canonicalizers
    // =========================================================================

    #[test]
    fn yaml_and_json_same_content_same_hash() {
        // YAML `a: 1\nb: 2` and JSON `{"a":1,"b":2}` should produce same canonical form
        let yaml = b"a: 1\nb: 2\n";
        let json = b"{\"a\":1,\"b\":2}";
        let h_yaml = canonical_hash(yaml, CanonicalMode::Logical, &YamlCanonicalizer);
        let h_json = canonical_hash(json, CanonicalMode::Logical, &JsonCanonicalizer);
        assert_eq!(h_yaml, h_json, "Same content in YAML/JSON should hash identically");
    }

    // =========================================================================
    // K8s manifest canonicalization (Hole 2 mitigation)
    // =========================================================================

    #[test]
    fn k8s_manifest_reordering_same_hash() {
        let manifest1 = br#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: myapp:v1
"#;
        let manifest2 = br#"kind: Deployment
apiVersion: apps/v1
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:v1
  replicas: 3
metadata:
  name: app
"#;
        let h1 = canonical_hash(manifest1, CanonicalMode::Logical, &YamlCanonicalizer);
        let h2 = canonical_hash(manifest2, CanonicalMode::Logical, &YamlCanonicalizer);
        assert_eq!(h1, h2, "K8s manifests with reordered keys should hash identically");
    }

    #[test]
    fn k8s_manifest_changed_value_different_hash() {
        let manifest1 = b"apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 3\n";
        let manifest2 = b"apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 5\n";
        let h1 = canonical_hash(manifest1, CanonicalMode::Logical, &YamlCanonicalizer);
        let h2 = canonical_hash(manifest2, CanonicalMode::Logical, &YamlCanonicalizer);
        assert_ne!(h1, h2, "Changed values must produce different hashes");
    }

    #[test]
    fn k8s_manifest_added_volume_different_hash() {
        let manifest1 = b"spec:\n  containers:\n  - name: app\n";
        let manifest2 = b"spec:\n  containers:\n  - name: app\n  volumes:\n  - name: evil\n    hostPath:\n      path: /etc/shadow\n";
        let h1 = canonical_hash(manifest1, CanonicalMode::Logical, &YamlCanonicalizer);
        let h2 = canonical_hash(manifest2, CanonicalMode::Logical, &YamlCanonicalizer);
        assert_ne!(h1, h2, "Added malicious volume must change the hash");
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn empty_content() {
        let h1 = canonical_hash(b"", CanonicalMode::Strict, &RawCanonicalizer);
        let h2 = canonical_hash(b"", CanonicalMode::Logical, &RawCanonicalizer);
        assert_eq!(h1, h2, "Empty content should hash the same in both modes");
    }

    #[test]
    fn yaml_null_document() {
        let yaml = b"---\n";
        let result = YamlCanonicalizer.canonicalize(yaml, CanonicalMode::Logical);
        // Should produce valid canonical output (null)
        assert!(!result.is_empty());
    }

    #[test]
    fn json_number_types_preserved() {
        let json = b"{\"int\":42,\"float\":3.14,\"neg\":-1}";
        let result = JsonCanonicalizer.canonicalize(json, CanonicalMode::Logical);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["int"], 42);
        assert_eq!(parsed["neg"], -1);
    }

    #[test]
    fn json_unicode_preserved() {
        let json = "{\"key\":\"\\u4e16\\u754c\"}".as_bytes();
        let result = JsonCanonicalizer.canonicalize(json, CanonicalMode::Logical);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["key"], "\u{4e16}\u{754c}");
    }

    #[test]
    fn deeply_nested_yaml() {
        let yaml = b"a:\n  b:\n    c:\n      d:\n        e:\n          f: deep\n";
        let result = YamlCanonicalizer.canonicalize(yaml, CanonicalMode::Logical);
        assert!(!result.is_empty());
        let hash1 = Blake3Hash::digest(&result);
        let result2 = YamlCanonicalizer.canonicalize(yaml, CanonicalMode::Logical);
        let hash2 = Blake3Hash::digest(&result2);
        assert_eq!(hash1, hash2, "Deep nesting should hash deterministically");
    }

    #[test]
    fn yaml_with_anchors() {
        // YAML anchors/aliases should be resolved by the parser
        let yaml = b"defaults: &defaults\n  a: 1\n  b: 2\nproduction:\n  <<: *defaults\n  c: 3\n";
        let result = YamlCanonicalizer.canonicalize(yaml, CanonicalMode::Logical);
        // Should not panic, and should produce deterministic output
        assert!(!result.is_empty());
    }

    #[test]
    fn canonical_mode_clone_eq() {
        let a = CanonicalMode::Strict;
        let b = a;
        assert_eq!(a, b);
        let c = CanonicalMode::Logical;
        assert_ne!(a, c);
    }

    #[test]
    fn canonical_mode_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CanonicalMode::Strict);
        set.insert(CanonicalMode::Logical);
        set.insert(CanonicalMode::Strict); // duplicate
        assert_eq!(set.len(), 2);
    }
}
