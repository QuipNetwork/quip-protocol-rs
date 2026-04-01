//! Error types shared by the hybrid signature crate.

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Errors returned while parsing or deriving hybrid key and signature types.
pub enum HybridSignatureError {
    /// A serialized value had the wrong fixed length.
    #[cfg_attr(
        feature = "std",
        error("invalid length: expected {expected}, got {actual}")
    )]
    InvalidLength {
        /// Expected serialized length in bytes.
        expected: usize,
        /// Actual serialized length in bytes.
        actual: usize,
    },
    /// A master seed had the wrong length.
    #[cfg_attr(
        feature = "std",
        error("invalid seed length: expected {expected}, got {actual}")
    )]
    InvalidSeedLength {
        /// Expected master-seed length in bytes.
        expected: usize,
        /// Actual master-seed length in bytes.
        actual: usize,
    },
    /// A public key failed decoding or semantic validation.
    #[cfg_attr(feature = "std", error("invalid public key"))]
    InvalidPublicKey,
    /// A secret key failed decoding or semantic validation.
    #[cfg_attr(feature = "std", error("invalid secret key"))]
    InvalidSecretKey,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for HybridSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, got {actual}")
            }
            Self::InvalidSeedLength { expected, actual } => {
                write!(f, "invalid seed length: expected {expected}, got {actual}")
            }
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSecretKey => write!(f, "invalid secret key"),
        }
    }
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, HybridSignatureError>;
