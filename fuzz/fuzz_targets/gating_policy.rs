#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::gating::{evaluate_gate, GatingPolicy};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{LayerSignature, LayerType};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Create a master signature
    let layers = vec![
        LayerSignature::new(
            LayerType::Nix,
            Blake3Hash::digest(&data[..data.len() / 2]),
            "fuzz",
            vec![],
        ),
        LayerSignature::new(
            LayerType::Oci,
            Blake3Hash::digest(&data[data.len() / 2..]),
            "fuzz",
            vec![],
        ),
    ];
    let compliance = Blake3Hash::digest(b"compliance");
    let master = compose_merkle(&layers, "fuzz").with_compliance(compliance);

    // Create various policies from fuzz data
    let policy = GatingPolicy {
        name: "fuzz-policy".to_string(),
        required_layers: if data[0] & 1 != 0 {
            vec!["nix".to_string()]
        } else {
            vec![]
        },
        require_compliance: data[0] & 2 != 0,
        max_signature_age_secs: if data[0] & 4 != 0 {
            Some(u64::from(data[1]) * 60)
        } else {
            None
        },
        fail_open: data[0] & 8 != 0,
        require_certification_artifacts: data[0] & 32 != 0,
    };

    // Expected sig - sometimes correct, sometimes wrong
    let expected = if data[0] & 16 != 0 {
        master.gating_signature().clone()
    } else {
        Blake3Hash::digest(data)
    };

    // evaluate_gate should never panic
    let decision = evaluate_gate(&policy, &master, &expected);
    // Decision should always have a reason
    assert!(!decision.reason.is_empty());
});
