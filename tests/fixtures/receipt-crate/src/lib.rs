//! The target `lib.wrapTest` attests in tameshi's receipt checks.

/// Whether `n` is even.
#[must_use]
pub fn is_even(n: u64) -> bool {
    n % 2 == 0
}
