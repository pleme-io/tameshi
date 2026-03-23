//! FFI memory-layout safety proofs.
//!
//! Verifies that the `#[repr(C)]` boundary between Rust and C is
//! correct: field offsets, alignment, padding, and total size match
//! what the C-based BPF hook expects.
//!
//! This is critical because the eBPF verifier in the kernel reads
//! `struct poms_entry` as raw bytes. If the Rust layout differs from
//! the C layout by even one byte of padding, the kernel reads garbage
//! — a silent, catastrophic failure invisible to unit tests.
//!
//! Kani exhaustively verifies these properties for ALL possible field
//! values, not just sample inputs.

/// BLAKE3 hash size (models the real 32-byte BLAKE3 output).
/// We use 4-byte hashes for Kani tractability; the layout properties
/// scale identically to 32 bytes (repr(C) is size-independent).
const HASH_SIZE: usize = 4;

/// PomsEntry as seen by Rust — must match `struct poms_entry` in C.
///
/// C layout (with 4-byte hashes for Kani):
/// ```c
/// struct poms_entry {
///     uint8_t binary_hash[4];   // offset 0, size 4
///     uint8_t poms_hash[4];     // offset 4, size 4
///     uint64_t attested_at;     // offset 8, size 8
///     uint32_t pid;             // offset 16, size 4
///     uint32_t violations;      // offset 20, size 4
/// };                            // total: 24 bytes
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(kani), allow(dead_code))]
struct PomsEntry {
    binary_hash: [u8; HASH_SIZE],
    poms_hash: [u8; HASH_SIZE],
    attested_at: u64,
    pid: u32,
    violations: u32,
}

/// KanshiConfig as seen by Rust — must match `struct kanshi_config` in C.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(kani), allow(dead_code))]
struct KanshiConfig {
    enforce: u32,
    log_allowed: u32,
}

/// AuditEvent as seen by Rust — must match `struct audit_event` in C.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(kani), allow(dead_code))]
struct AuditEvent {
    pid: u32,
    uid: u32,
    hash: [u8; HASH_SIZE],
    denied: u8,
}

/// Write a PomsEntry to a byte buffer the way Rust would (memcpy of repr(C)),
/// then read it back field-by-field the way C would (fixed offsets).
/// If Rust and C agree, the values must match.
#[cfg_attr(not(kani), allow(dead_code))]
fn roundtrip_poms_entry(entry: &PomsEntry) -> PomsEntry {
    let size = std::mem::size_of::<PomsEntry>();
    let mut buf = vec![0u8; size];

    // Rust writes the struct as raw bytes (this is what libbpf-rs does)
    unsafe {
        std::ptr::copy_nonoverlapping(
            (entry as *const PomsEntry).cast::<u8>(),
            buf.as_mut_ptr(),
            size,
        );
    }

    // C reads from fixed offsets (this is what the BPF hook does)
    let mut binary_hash = [0u8; HASH_SIZE];
    binary_hash.copy_from_slice(&buf[0..HASH_SIZE]);

    let mut poms_hash = [0u8; HASH_SIZE];
    poms_hash.copy_from_slice(&buf[HASH_SIZE..2 * HASH_SIZE]);

    let attested_at_offset = 2 * HASH_SIZE;
    let attested_at = u64::from_le_bytes(
        buf[attested_at_offset..attested_at_offset + 8]
            .try_into()
            .unwrap(),
    );

    let pid_offset = attested_at_offset + 8;
    let pid = u32::from_le_bytes(buf[pid_offset..pid_offset + 4].try_into().unwrap());

    let violations_offset = pid_offset + 4;
    let violations = u32::from_le_bytes(
        buf[violations_offset..violations_offset + 4]
            .try_into()
            .unwrap(),
    );

    PomsEntry {
        binary_hash,
        poms_hash,
        attested_at,
        pid,
        violations,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove: PomsEntry size matches the C struct size.
    ///
    /// With 4-byte hashes: 4 + 4 + 8 + 4 + 4 = 24 bytes.
    /// Any padding inserted by the Rust compiler would increase this,
    /// breaking the C layout contract.
    #[kani::proof]
    fn poms_entry_size_is_correct() {
        let expected_size = 2 * HASH_SIZE + 8 + 4 + 4; // hashes + u64 + u32 + u32
        assert_eq!(
            std::mem::size_of::<PomsEntry>(),
            expected_size,
            "PomsEntry size must match C struct"
        );
    }

    /// Prove: PomsEntry alignment matches C expectations.
    ///
    /// The u64 field requires 8-byte alignment. repr(C) guarantees
    /// the struct alignment is the maximum of its fields' alignments.
    #[kani::proof]
    fn poms_entry_alignment_is_correct() {
        assert_eq!(
            std::mem::align_of::<PomsEntry>(),
            8,
            "PomsEntry alignment must be 8 (u64 field)"
        );
    }

    /// Prove: Rust-to-C roundtrip preserves all field values.
    ///
    /// For ANY symbolic PomsEntry, writing it as raw bytes (Rust side)
    /// and reading it back at fixed C offsets produces identical values.
    /// This proves zero undefined behavior at the FFI boundary.
    #[kani::proof]
    #[kani::unwind(2)]
    fn poms_entry_roundtrip_preserves_values() {
        let entry = PomsEntry {
            binary_hash: kani::any(),
            poms_hash: kani::any(),
            attested_at: kani::any(),
            pid: kani::any(),
            violations: kani::any(),
        };

        let recovered = roundtrip_poms_entry(&entry);

        assert_eq!(
            entry.binary_hash, recovered.binary_hash,
            "binary_hash must survive roundtrip"
        );
        assert_eq!(
            entry.poms_hash, recovered.poms_hash,
            "poms_hash must survive roundtrip"
        );
        assert_eq!(
            entry.attested_at, recovered.attested_at,
            "attested_at must survive roundtrip"
        );
        assert_eq!(entry.pid, recovered.pid, "pid must survive roundtrip");
        assert_eq!(
            entry.violations, recovered.violations,
            "violations must survive roundtrip"
        );
    }

    /// Prove: The violations field at its exact C offset is readable.
    ///
    /// The BPF hook reads `entry->violations` at a fixed offset to
    /// decide allow/deny. This proves Rust writes it at the same offset.
    #[kani::proof]
    fn violations_field_at_correct_offset() {
        let violations: u32 = kani::any();
        let entry = PomsEntry {
            binary_hash: [0; HASH_SIZE],
            poms_hash: [0; HASH_SIZE],
            attested_at: 0,
            pid: 0,
            violations,
        };

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&entry as *const PomsEntry).cast::<u8>(),
                std::mem::size_of::<PomsEntry>(),
            )
        };

        // violations is at offset: 2*HASH_SIZE + 8 + 4 = 20
        let offset = 2 * HASH_SIZE + 8 + 4;
        let read_back = u32::from_le_bytes(
            bytes[offset..offset + 4].try_into().unwrap(),
        );

        assert_eq!(
            violations, read_back,
            "violations must be at the correct C offset"
        );
    }

    /// Prove: KanshiConfig size and layout match C.
    #[kani::proof]
    fn kanshi_config_layout() {
        assert_eq!(std::mem::size_of::<KanshiConfig>(), 8);
        assert_eq!(std::mem::align_of::<KanshiConfig>(), 4);

        let config = KanshiConfig {
            enforce: kani::any(),
            log_allowed: kani::any(),
        };

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&config as *const KanshiConfig).cast::<u8>(),
                8,
            )
        };

        let enforce = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let log_allowed = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

        assert_eq!(enforce, config.enforce);
        assert_eq!(log_allowed, config.log_allowed);
    }

    /// Prove: A safe PoMS (violations == 0) written to the map
    /// is readable as authorized by the C-side BPF hook.
    ///
    /// This is the FFI-level refinement: Rust writes a safe entry,
    /// C reads it and finds violations == 0 → ALLOW.
    #[kani::proof]
    #[kani::unwind(2)]
    fn safe_poms_is_authorized_at_ffi_boundary() {
        let binary: Hash = kani::any();
        let poms: Hash = kani::any();

        // Rust side: attest a safe binary (violations = 0)
        let entry = PomsEntry {
            binary_hash: binary,
            poms_hash: poms,
            attested_at: kani::any(),
            pid: kani::any(),
            violations: 0, // SAFE
        };

        // C side: read the violations field at its fixed offset
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&entry as *const PomsEntry).cast::<u8>(),
                std::mem::size_of::<PomsEntry>(),
            )
        };

        let violations_offset = 2 * HASH_SIZE + 8 + 4;
        let c_violations = u32::from_le_bytes(
            bytes[violations_offset..violations_offset + 4]
                .try_into()
                .unwrap(),
        );

        // The C hook checks: if (entry->violations == 0) { ALLOW; }
        assert_eq!(c_violations, 0, "C must read violations == 0 for safe PoMS");
    }

    /// Prove: An unsafe PoMS (violations > 0) is denied at the FFI boundary.
    #[kani::proof]
    #[kani::unwind(2)]
    fn unsafe_poms_is_denied_at_ffi_boundary() {
        let violations: u32 = kani::any();
        kani::assume(violations > 0);

        let entry = PomsEntry {
            binary_hash: kani::any(),
            poms_hash: kani::any(),
            attested_at: kani::any(),
            pid: kani::any(),
            violations,
        };

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&entry as *const PomsEntry).cast::<u8>(),
                std::mem::size_of::<PomsEntry>(),
            )
        };

        let violations_offset = 2 * HASH_SIZE + 8 + 4;
        let c_violations = u32::from_le_bytes(
            bytes[violations_offset..violations_offset + 4]
                .try_into()
                .unwrap(),
        );

        assert_ne!(c_violations, 0, "C must read violations > 0 for unsafe PoMS");
    }
}
