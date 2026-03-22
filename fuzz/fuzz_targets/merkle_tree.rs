#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::hash::Blake3Hash;
use tameshi::merkle::{build_merkle_tree, compute_merkle_root, merkle_proof, verify_proof};
use tameshi::signature::{LayerSignature, LayerType};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Use first byte as layer count (0-255), rest as hash data
    let count = (data[0] as usize) % 64; // cap at 64 layers
    let types = [
        LayerType::Nix,
        LayerType::Oci,
        LayerType::Helm,
        LayerType::Tofu,
        LayerType::Kubernetes,
        LayerType::Kindling,
        LayerType::Tatara,
        LayerType::FluxCD,
        LayerType::ArgoCD,
        LayerType::Akeyless,
        LayerType::AkeylessTarget,
    ];

    let layers: Vec<LayerSignature> = (0..count)
        .map(|i| {
            let hash_data = if i + 1 < data.len() {
                &data[i + 1..std::cmp::min(i + 33, data.len())]
            } else {
                &[i as u8]
            };
            LayerSignature::new(
                types[i % types.len()].clone(),
                Blake3Hash::digest(hash_data),
                "fuzz",
                vec![],
            )
        })
        .collect();

    // Should never panic
    let root = compute_merkle_root(&layers);

    // Determinism check
    let root2 = compute_merkle_root(&layers);
    assert_eq!(root, root2);

    // Build tree should not panic
    let _ = build_merkle_tree(&layers);

    // Proof gen/verify should not panic
    for i in 0..layers.len() {
        if let Some(proof_hashes) = merkle_proof(&layers, i) {
            let mut sorted = layers.clone();
            sorted.sort_by(|a, b| a.layer.cmp(&b.layer));
            if i < sorted.len() {
                let _ = verify_proof(&proof_hashes, &root, &sorted[i], i, sorted.len());
            }
        }
    }
});
