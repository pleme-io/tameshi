#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::compliance::dimensions::{
    AttestationBuilder, ComplianceAttestation, ComplianceDimension, ComplianceDimensionPolicy,
    DimensionType,
};
use tameshi::hash::Blake3Hash;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Try deserializing compliance types from fuzz data - should never panic
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ComplianceAttestation>(s);
        let _ = serde_json::from_str::<ComplianceDimension>(s);
        let _ = serde_json::from_str::<ComplianceDimensionPolicy>(s);
        let _ = serde_json::from_str::<DimensionType>(s);
    }

    // Build attestations from fuzz data - should never panic
    let dimension_count = (data[0] as usize) % 16;
    let dimension_types = [
        DimensionType::NistAssessment,
        DimensionType::VulnerabilityScan,
        DimensionType::Sbom,
        DimensionType::SlsaProvenance,
        DimensionType::CosignSignature,
        DimensionType::InTotoAttestation,
        DimensionType::CisBenchmark,
        DimensionType::DisaStig,
        DimensionType::Soc2,
        DimensionType::PciDss,
        DimensionType::OwaspAsvs,
        DimensionType::Iso27001,
        DimensionType::FedRamp,
        DimensionType::CsaStar,
        DimensionType::FrameworkSelfAttestation,
        DimensionType::AkeylessTargetVerification,
    ];

    // Use the builder with self-attestation dimensions driven by fuzz data
    let mut builder = AttestationBuilder::new("fuzz-env", "fuzz-artifact", "fuzz-policy");
    for i in 0..dimension_count {
        let hash_seed = if i + 1 < data.len() {
            &data[i + 1..std::cmp::min(i + 33, data.len())]
        } else {
            &[i as u8]
        };
        let hash = Blake3Hash::digest(hash_seed);
        let dim_idx = if i + 1 < data.len() {
            data[i + 1] as usize % dimension_types.len()
        } else {
            i % dimension_types.len()
        };
        let summary = format!("fuzz dimension {} type {:?}", i, dimension_types[dim_idx]);
        builder = builder.with_self_attestation(hash, &summary);
    }

    // build() should never panic
    let attestation = builder.build();

    // Verify properties that should always hold
    assert_eq!(attestation.environment, "fuzz-env");
    assert_eq!(attestation.artifact, "fuzz-artifact");
    assert_eq!(attestation.policy_name, "fuzz-policy");

    // Compliance hash should be deterministic for same inputs
    // (we can't easily re-build due to timestamps, but the hash itself must be 32 bytes)
    assert_eq!(attestation.compliance_hash.0.len(), 32);

    // Serde roundtrip of the attestation should not panic
    if let Ok(json) = serde_json::to_string(&attestation) {
        let _ = serde_json::from_str::<ComplianceAttestation>(&json);
    }
});
