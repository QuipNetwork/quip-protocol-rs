//! Concrete hybrid signature suite definitions.
//!
//! Each submodule in this directory defines one fully assembled hybrid suite:
//! wrapper types, serialization layout, suite label, and a
//! [`crate::HybridSignatureScheme`] implementation.

pub mod ed25519_mldsa44;
pub mod sr25519_mldsa44;

/// Default version byte used in the domain-separated hybrid message format.
pub const DEFAULT_HYBRID_SIGNATURE_VERSION: u8 = 0x01;

/// Compile-time metadata for a concrete hybrid signature suite.
pub trait FixedHybridSuite {
    /// Domain-separation label for the suite, including the trailing NUL byte
    /// required by the current specification.
    const LABEL: &'static [u8];

    /// Version byte prepended to the domain-separated message.
    const VERSION: u8 = DEFAULT_HYBRID_SIGNATURE_VERSION;
}
