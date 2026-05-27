//! Error types for structural and arithmetic validation failures.

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Errors returned by deterministic validation helpers in this crate.
pub enum ValidationError {
    /// The caller supplied an empty node list where at least one node is
    /// required.
    #[cfg_attr(feature = "std", error("node set must not be empty"))]
    EmptyNodes,
    /// The caller supplied no candidate `h` values for model generation.
    #[cfg_attr(feature = "std", error("allowed h-values must not be empty"))]
    EmptyFieldValues,
    /// An `AllowedValueSpec` is empty or has inverted bounds (`max < min`).
    #[cfg_attr(feature = "std", error("allowed value spec is empty or inverted"))]
    EmptyAllowedValues,
    /// The encoded value falls outside the spec's representable range.
    #[cfg_attr(
        feature = "std",
        error("encoded value {raw} is not a valid representation under this spec")
    )]
    InvalidEncodedValue { raw: u32 },
    /// The spec requires more bits per value than the protocol supports.
    #[cfg_attr(
        feature = "std",
        error("encoding requires {bits} bits per value, exceeds protocol maximum")
    )]
    EncodingTooWide { bits: u8 },
    /// A packed solution payload's byte count does not match the bit-width
    /// implied by the spec and the expected spin count.
    #[cfg_attr(
        feature = "std",
        error("packed solution length mismatch: expected {expected} bytes, got {actual}")
    )]
    PackedSolutionLengthMismatch { expected: usize, actual: usize },
    /// A solution length does not match the expected number of spins.
    #[cfg_attr(
        feature = "std",
        error("solution length mismatch: expected {expected}, got {actual}")
    )]
    SolutionLengthMismatch { expected: usize, actual: usize },
    /// The local-field vector does not match the node count.
    #[cfg_attr(
        feature = "std",
        error("field length mismatch: expected {expected}, got {actual}")
    )]
    FieldLengthMismatch { expected: usize, actual: usize },
    /// The edge list and coupling vector have different lengths.
    #[cfg_attr(
        feature = "std",
        error("edge/weight length mismatch: {edges} edges, {weights} weights")
    )]
    EdgeWeightLengthMismatch { edges: usize, weights: usize },
    /// A spin value is outside the allowed Ising alphabet `{-1, +1}`.
    #[cfg_attr(feature = "std", error("invalid spin at index {index}: {value}"))]
    InvalidSpinValue { index: usize, value: i8 },
    /// A node identifier appears more than once in a node list.
    #[cfg_attr(feature = "std", error("duplicate node id {node}"))]
    DuplicateNode { node: u32 },
    /// An edge references a node that is not present in the node list.
    #[cfg_attr(feature = "std", error("edge references unknown node {node}"))]
    UnknownNodeInEdge { node: u32 },
    /// An intermediate fixed-point computation overflowed.
    #[cfg_attr(feature = "std", error("arithmetic overflow"))]
    ArithmeticOverflow,
}

#[cfg(not(feature = "std"))]
impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNodes => write!(f, "node set must not be empty"),
            Self::EmptyFieldValues => write!(f, "allowed h-values must not be empty"),
            Self::EmptyAllowedValues => write!(f, "allowed value spec is empty or inverted"),
            Self::InvalidEncodedValue { raw } => {
                write!(
                    f,
                    "encoded value {raw} is not a valid representation under this spec"
                )
            }
            Self::EncodingTooWide { bits } => write!(
                f,
                "encoding requires {bits} bits per value, exceeds protocol maximum"
            ),
            Self::PackedSolutionLengthMismatch { expected, actual } => write!(
                f,
                "packed solution length mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::SolutionLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "solution length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::FieldLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "field length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::EdgeWeightLengthMismatch { edges, weights } => {
                write!(
                    f,
                    "edge/weight length mismatch: {edges} edges, {weights} weights"
                )
            }
            Self::InvalidSpinValue { index, value } => {
                write!(f, "invalid spin at index {index}: {value}")
            }
            Self::DuplicateNode { node } => write!(f, "duplicate node id {node}"),
            Self::UnknownNodeInEdge { node } => write!(f, "edge references unknown node {node}"),
            Self::ArithmeticOverflow => write!(f, "arithmetic overflow"),
        }
    }
}
