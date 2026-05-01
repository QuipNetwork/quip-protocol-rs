//! Shared fixed-point aliases and helpers.

/// Fixed-point scale factor used throughout the crate.
///
/// A value of `1000` means all floating-point quantities from the Python
/// reference are represented in milli-precision.
pub const MILLI_SCALE: i64 = 1_000;

/// Fixed-point milli-precision energy value.
pub type MilliEnergy = i64;
/// Fixed-point milli-precision local field or coupling value.
pub type MilliValue = i32;
/// Fixed-point milli-precision diversity score.
pub type MilliDiversity = u32;

pub(crate) fn round_div_u64(numerator: u64, denominator: u64) -> u64 {
    debug_assert!(denominator > 0);
    (numerator + (denominator / 2)) / denominator
}
