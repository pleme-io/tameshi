#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::api_types::GateDecision;
use tameshi::gating::GatingPolicy;
use tameshi::hash::Blake3Hash;
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try deserializing various types - should never panic
        let _ = serde_json::from_str::<Blake3Hash>(s);
        let _ = serde_json::from_str::<LayerSignature>(s);
        let _ = serde_json::from_str::<MasterSignature>(s);
        let _ = serde_json::from_str::<GatingPolicy>(s);
        let _ = serde_json::from_str::<GateDecision>(s);
        let _ = serde_json::from_str::<LayerType>(s);
    }
});
