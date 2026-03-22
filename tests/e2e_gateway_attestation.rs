//! E2E Gateway Attestation Crucible.
//!
//! Proves acceptance of safe code and rejection of leaky code
//! through the Go->Rust PoMS pipeline.

use tameshi::collectors::ferrite::{FerriteCollector, PomsArtifact, PomsAnalysis, PomsHashes, PomsTarget};
use tameshi::collectors::traits::LayerCollector;
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compute_merkle_root;
use tameshi::signature::LayerType;
use tameshi::signing::{LocalSigner, MerkleRootSigner};

fn safe_gateway_poms() -> PomsArtifact {
    PomsArtifact {
        version: "1.0.0".into(),
        tool: "ferrite-check".into(),
        tool_version: "0.1.0".into(),
        target: PomsTarget { module: "gateway-shim".into() },
        analysis: PomsAnalysis {
            allocations_tracked: 1,
            violations_detected: 0,
            rules_enforced: vec!["linear_typing".into(), "temporal_safety".into()],
        },
        hashes: PomsHashes {
            algorithm: "SHA-256".into(),
            source_hash: "a1b2c3".into(),
            ast_hash: "d4e5f6".into(),
            program_hash: "789abc".into(),
        },
    }
}

fn leaky_gateway_poms() -> PomsArtifact {
    PomsArtifact {
        version: "1.0.0".into(),
        tool: "ferrite-check".into(),
        tool_version: "0.1.0".into(),
        target: PomsTarget { module: "gateway-shim".into() },
        analysis: PomsAnalysis {
            allocations_tracked: 1,
            violations_detected: 1,
            rules_enforced: vec!["linear_typing".into()],
        },
        hashes: PomsHashes {
            algorithm: "SHA-256".into(),
            source_hash: "deadbeef".into(),
            ..Default::default()
        },
    }
}

// Phase A: Safe Gateway -> Accepted

#[tokio::test]
async fn phase_a_safe_produces_signature() {
    let sig = FerriteCollector::new(safe_gateway_poms()).collect().await.unwrap();
    assert_eq!(sig.layer, LayerType::FerritePoms);
    assert_eq!(sig.inputs.len(), 3);
}

#[tokio::test]
async fn phase_a_composes_into_merkle() {
    let ferrite = FerriteCollector::new(safe_gateway_poms()).collect().await.unwrap();
    let nix = tameshi::signature::LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "nix", vec![]);
    let oci = tameshi::signature::LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "oci", vec![]);
    let root = compute_merkle_root(&[nix, oci, ferrite]);
    assert_ne!(root, Blake3Hash::digest(b""));
}

#[tokio::test]
async fn phase_a_root_is_signable() {
    let sig = FerriteCollector::new(safe_gateway_poms()).collect().await.unwrap();
    let root = compute_merkle_root(&[sig]);
    let signer = LocalSigner::for_testing();
    let signed = signer.sign(&root).await.unwrap();
    assert!(signer.verify(&signed).await.unwrap());
}

#[tokio::test]
async fn phase_a_deterministic() {
    let s1 = FerriteCollector::new(safe_gateway_poms()).collect().await.unwrap();
    let s2 = FerriteCollector::new(safe_gateway_poms()).collect().await.unwrap();
    assert_eq!(s1.hash, s2.hash);
}

#[tokio::test]
async fn phase_a_json_contract() {
    let json = serde_json::to_vec(&safe_gateway_poms()).unwrap();
    let sig = FerriteCollector::from_json(&json).unwrap().collect().await.unwrap();
    assert_eq!(sig.layer, LayerType::FerritePoms);
}

// Phase B: Leaky Gateway -> REJECTED

#[tokio::test]
async fn phase_b_rejected() {
    let json = serde_json::to_vec(&leaky_gateway_poms()).unwrap();
    let result = FerriteCollector::from_json(&json);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("violation"));
}

#[tokio::test]
async fn phase_b_never_enters_tree() {
    let json = serde_json::to_vec(&leaky_gateway_poms()).unwrap();
    assert!(FerriteCollector::from_json(&json).is_err());
}

#[tokio::test]
async fn phase_b_multi_violations() {
    let mut p = leaky_gateway_poms();
    p.analysis.violations_detected = 5;
    let json = serde_json::to_vec(&p).unwrap();
    assert!(FerriteCollector::from_json(&json).unwrap_err().to_string().contains("5 violations"));
}

// Phase C: Tamper Detection

#[tokio::test]
async fn phase_c_tamper_changes_root() {
    let genuine = FerriteCollector::new(safe_gateway_poms()).collect().await.unwrap();
    let mut tp = safe_gateway_poms();
    tp.hashes.source_hash = "TAMPERED".into();
    let tampered = FerriteCollector::new(tp).collect().await.unwrap();
    assert_ne!(genuine.hash, tampered.hash);
    assert_ne!(compute_merkle_root(&[genuine]), compute_merkle_root(&[tampered]));
}

#[tokio::test]
async fn phase_c_bit_flip() {
    let json = serde_json::to_vec(&safe_gateway_poms()).unwrap();
    let genuine = FerriteCollector::from_json(&json).unwrap().collect().await.unwrap().hash;
    let mut bad = json.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0xFF;
    match FerriteCollector::from_json(&bad) {
        Err(_) => {}
        Ok(c) => assert_ne!(genuine, c.collect().await.unwrap().hash),
    }
}
