#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::changeset::{
    certify_changeset, hash_changeset, verify_changeset, Operation, ResourceId,
};
use tameshi::hash::Blake3Hash;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let op = match data[0] % 4 {
        0 => Operation::Create,
        1 => Operation::Update,
        2 => Operation::Patch,
        _ => Operation::Delete,
    };

    let resource = ResourceId {
        group: "apps".to_string(),
        version: "v1".to_string(),
        kind: "Deployment".to_string(),
        namespace: "default".to_string(),
        name: String::from_utf8_lossy(&data[1..std::cmp::min(data.len(), 32)]).to_string(),
    };

    let content = &data[1..];

    // hash_changeset should never panic
    let _ = hash_changeset(&op, &resource, content);

    // certify and verify roundtrip
    let before = Blake3Hash::digest(&data[..data.len() / 2]);
    let after = Blake3Hash::digest(&data[data.len() / 2..]);
    let env_sig = Blake3Hash::digest(b"env");
    let compliance_sig = Blake3Hash::digest(b"compliance");

    let certified = certify_changeset(
        op,
        resource,
        content,
        Some(&before),
        Some(&after),
        &env_sig,
        Some(&compliance_sig),
        "fuzzer",
    );
    let _ = verify_changeset(&certified);
});
