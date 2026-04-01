pub mod ed25519_mldsa44;
pub mod sr25519_mldsa44;

pub const DEFAULT_HYBRID_SIGNATURE_VERSION: u8 = 0x01;

/// Compile-time metadata for a concrete hybrid signature suite.
pub trait FixedHybridSuite {
    const LABEL: &'static [u8];
    const VERSION: u8 = DEFAULT_HYBRID_SIGNATURE_VERSION;
}
