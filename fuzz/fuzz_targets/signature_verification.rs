#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};

fuzz_target!(|data: &[u8]| {
    // Try to deserialize as MasterSignature - should not panic
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<MasterSignature>(s);
    }

    // Create valid signatures and verify - should not panic
    if data.len() >= 4 {
        let layer_count = (data[0] as usize % 11) + 1;
        let types = [
            LayerType::Nix,
            LayerType::Oci,
            LayerType::Helm,
            LayerType::Tofu,
            LayerType::Kubernetes,
        ];

        let layers: Vec<LayerSignature> = (0..layer_count)
            .map(|i| {
                let d = if i + 1 < data.len() {
                    &data[i + 1..]
                } else {
                    &[0u8]
                };
                LayerSignature::new(
                    types[i % types.len()].clone(),
                    Blake3Hash::digest(d),
                    "fuzz",
                    vec![],
                )
            })
            .collect();

        let master = compose_merkle(&layers, "fuzz");
        let _ = master.verify_untested();
        let _ = master.verify_secure();
        let _ = master.is_fully_attested();
        let _ = master.gating_signature();

        // With compliance
        let compliance = Blake3Hash::digest(&data[1..]);
        let secure = master.with_compliance(compliance);
        let _ = secure.verify_untested();
        let _ = secure.verify_secure();
    }
});
