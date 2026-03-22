#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::hash::{blake3_hex, blake3_str, Blake3Hash};

fuzz_target!(|data: &[u8]| {
    // digest should never panic and always return 32 bytes
    let h = Blake3Hash::digest(data);
    assert_eq!(h.0.len(), 32);

    // Deterministic
    let h2 = Blake3Hash::digest(data);
    assert_eq!(h, h2);

    // Hex roundtrip
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    let h3 = Blake3Hash::from_hex(&hex).unwrap();
    assert_eq!(h, h3);

    // Prefixed roundtrip
    let prefixed = h.to_prefixed();
    let h4 = Blake3Hash::from_prefixed(&prefixed).unwrap();
    assert_eq!(h, h4);

    // blake3_hex should not panic
    let _ = blake3_hex(data);

    // blake3_str should not panic on valid UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = blake3_str(s);
    }

    // Combine should not panic
    if data.len() >= 2 {
        let mid = data.len() / 2;
        let a = Blake3Hash::digest(&data[..mid]);
        let b = Blake3Hash::digest(&data[mid..]);
        let _ = Blake3Hash::combine(&a, &b);
    }
});
