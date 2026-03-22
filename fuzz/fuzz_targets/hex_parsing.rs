#![no_main]
use libfuzzer_sys::fuzz_target;
use tameshi::hash::Blake3Hash;

fuzz_target!(|data: &[u8]| {
    // Try parsing as hex - should never panic
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Blake3Hash::from_hex(s);
        let _ = Blake3Hash::from_prefixed(s);
        let _ = s.parse::<Blake3Hash>();
    }
});
