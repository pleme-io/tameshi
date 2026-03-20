//! Validates that Rust types match the OpenAPI spec schemas.
//!
//! This test generates JSON Schema from Rust types via schemars, then
//! compares key structural properties against the OpenAPI spec. Any drift
//! between code and spec is caught at test time.

use schemars::schema_for;

/// Load the OpenAPI spec and return the components/schemas mapping.
fn load_spec_schemas() -> serde_yaml_ng::Value {
    let spec_yaml =
        std::fs::read_to_string("spec/openapi.yaml").expect("failed to read spec/openapi.yaml");
    let spec: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&spec_yaml).expect("failed to parse spec YAML");
    spec["components"]["schemas"].clone()
}

/// Validate that required fields declared in the OpenAPI spec exist in the Rust type's
/// generated JSON Schema, and vice versa. Accounts for snake_case (Rust) vs camelCase (spec).
fn validate_type_fields<T: schemars::JsonSchema>(
    spec_schemas: &serde_yaml_ng::Value,
    spec_name: &str,
) {
    let rust_schema = schema_for!(T);
    let rust_json = serde_json::to_value(&rust_schema).unwrap();

    let spec_schema = &spec_schemas[spec_name];
    assert!(
        !spec_schema.is_null(),
        "Schema '{spec_name}' not found in OpenAPI spec -- add it to spec/openapi.yaml"
    );

    // Collect Rust property names from the generated JSON Schema.
    // schemars respects serde rename_all, so these will already be in the
    // serialized form (snake_case for most tameshi types).
    let rust_props = collect_rust_properties(&rust_json);

    // Check that all required fields in the spec exist in the Rust schema.
    if let Some(required) = spec_schema["required"].as_sequence() {
        for field in required {
            let spec_field = field.as_str().unwrap();
            // Try the spec field name directly (if Rust uses camelCase rename)
            // and also the snake_case conversion.
            let snake = to_snake_case(spec_field);
            let spec_str = spec_field.to_string();
            assert!(
                rust_props.contains(&spec_str) || rust_props.contains(&snake),
                "Required field '{spec_field}' (or '{snake}') from spec schema '{spec_name}' \
                 not found in Rust type {}\n\
                 Rust properties: {rust_props:?}",
                std::any::type_name::<T>()
            );
        }
    }

    // Check that Rust type's required fields exist in the spec.
    if let Some(rust_required) = rust_json.get("required").and_then(|r| r.as_array()) {
        let spec_props = &spec_schema["properties"];
        for field in rust_required {
            let rust_field = field.as_str().unwrap();
            let camel = to_camel_case(rust_field);
            assert!(
                !spec_props[rust_field].is_null() || !spec_props[&camel].is_null(),
                "Rust required field '{rust_field}' (or '{camel}') in {} \
                 not found in spec schema '{spec_name}' -- update spec/openapi.yaml\n\
                 Spec properties: {:?}",
                std::any::type_name::<T>(),
                collect_spec_properties(spec_props),
            );
        }
    }
}

/// Collect property names from a schemars-generated JSON Schema value.
/// Handles both top-level `properties` and `$ref`-based definitions.
fn collect_rust_properties(schema: &serde_json::Value) -> Vec<String> {
    let mut props = Vec::new();
    if let Some(obj) = schema.get("properties").and_then(|p| p.as_object()) {
        for key in obj.keys() {
            props.push(key.clone());
        }
    }
    props
}

/// Collect property names from an OpenAPI spec schema's properties mapping.
fn collect_spec_properties(props: &serde_yaml_ng::Value) -> Vec<String> {
    let mut result = Vec::new();
    if let Some(map) = props.as_mapping() {
        for key in map.keys() {
            if let Some(s) = key.as_str() {
                result.push(s.to_string());
            }
        }
    }
    result
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.extend(c.to_lowercase());
    }
    result
}

fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;
    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Heartbeat types
// ---------------------------------------------------------------------------

#[test]
fn heartbeat_entry_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::heartbeat::HeartbeatEntry>(&schemas, "HeartbeatEntry");
}

#[test]
fn verifier_identity_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::heartbeat::VerifierIdentity>(&schemas, "VerifierIdentity");
}

#[test]
fn consistency_proof_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::heartbeat::ConsistencyProof>(&schemas, "ConsistencyProof");
}

// ---------------------------------------------------------------------------
// Signing types
// ---------------------------------------------------------------------------

#[test]
fn signed_root_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::signing::SignedRoot>(&schemas, "SignedRoot");
}

// ---------------------------------------------------------------------------
// Compliance types
// ---------------------------------------------------------------------------

#[test]
fn compliance_distance_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::compliance_api::ComplianceDistance>(
        &schemas,
        "ComplianceDistance",
    );
}

// ---------------------------------------------------------------------------
// Signature types
// ---------------------------------------------------------------------------

#[test]
fn input_hash_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::signature::InputHash>(&schemas, "InputHash");
}

#[test]
fn master_signature_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::signature::MasterSignature>(&schemas, "MasterSignature");
}

#[test]
fn layer_signature_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::signature::LayerSignature>(&schemas, "LayerSignature");
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

#[test]
fn gate_decision_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::api_types::GateDecision>(&schemas, "GateDecision");
}

#[test]
fn audit_entry_matches_spec() {
    let schemas = load_spec_schemas();
    validate_type_fields::<tameshi::api_types::AuditEntry>(&schemas, "AuditEntry");
}

// ---------------------------------------------------------------------------
// Enum variant coverage -- ensure Rust enum variants match spec enum values
// ---------------------------------------------------------------------------

#[test]
fn layer_type_enum_matches_spec() {
    let schemas = load_spec_schemas();
    let spec_enum = &schemas["LayerType"]["enum"];
    let spec_variants: Vec<&str> = spec_enum
        .as_sequence()
        .expect("LayerType should have enum in spec")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    // Generate the schemars schema for LayerType and extract its enum values.
    let rust_schema = schema_for!(tameshi::signature::LayerType);
    let rust_json = serde_json::to_value(&rust_schema).unwrap();

    // schemars generates oneOf for tagged enums; for simple string enums with
    // rename_all it generates a top-level "enum" array.
    let rust_variants = extract_enum_variants(&rust_json);

    for spec_variant in &spec_variants {
        assert!(
            rust_variants.contains(&spec_variant.to_string()),
            "Spec LayerType variant '{spec_variant}' not found in Rust enum.\n\
             Rust variants: {rust_variants:?}"
        );
    }
}

#[test]
fn heartbeat_event_enum_matches_spec() {
    let schemas = load_spec_schemas();
    let spec_enum = &schemas["HeartbeatEvent"]["enum"];
    let spec_variants: Vec<&str> = spec_enum
        .as_sequence()
        .expect("HeartbeatEvent should have enum in spec")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let rust_schema = schema_for!(tameshi::heartbeat::HeartbeatEvent);
    let rust_json = serde_json::to_value(&rust_schema).unwrap();
    let rust_variants = extract_enum_variants(&rust_json);

    for spec_variant in &spec_variants {
        assert!(
            rust_variants.contains(&spec_variant.to_string()),
            "Spec HeartbeatEvent variant '{spec_variant}' not found in Rust enum.\n\
             Rust variants: {rust_variants:?}"
        );
    }
}

#[test]
fn verification_outcome_enum_matches_spec() {
    let schemas = load_spec_schemas();
    let spec_enum = &schemas["VerificationOutcome"]["enum"];
    let spec_variants: Vec<&str> = spec_enum
        .as_sequence()
        .expect("VerificationOutcome should have enum in spec")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let rust_schema = schema_for!(tameshi::heartbeat::VerificationOutcome);
    let rust_json = serde_json::to_value(&rust_schema).unwrap();
    let rust_variants = extract_enum_variants(&rust_json);

    for spec_variant in &spec_variants {
        assert!(
            rust_variants.contains(&spec_variant.to_string()),
            "Spec VerificationOutcome variant '{spec_variant}' not found in Rust enum.\n\
             Rust variants: {rust_variants:?}"
        );
    }
}

/// Extract enum string variants from a schemars-generated JSON Schema.
/// Handles both flat `{"enum": [...]}` and `{"oneOf": [{"enum": [...]}, ...]}` layouts.
fn extract_enum_variants(schema: &serde_json::Value) -> Vec<String> {
    let mut variants = Vec::new();

    // Flat enum: {"enum": ["a", "b", "c"]}
    if let Some(arr) = schema.get("enum").and_then(|e| e.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                variants.push(s.to_string());
            }
        }
    }

    // oneOf layout: {"oneOf": [{"enum": ["variant"]}, ...]}
    if let Some(one_of) = schema.get("oneOf").and_then(|o| o.as_array()) {
        for item in one_of {
            if let Some(arr) = item.get("enum").and_then(|e| e.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        variants.push(s.to_string());
                    }
                }
            }
            // Also check nested properties for tagged variants
            if let Some(props) = item.get("properties") {
                if let Some(type_field) = props.get("type") {
                    if let Some(arr) = type_field.get("enum").and_then(|e| e.as_array()) {
                        for v in arr {
                            if let Some(s) = v.as_str() {
                                variants.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    variants
}
