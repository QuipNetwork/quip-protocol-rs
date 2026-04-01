#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HybridSignatureError {
    #[cfg_attr(
        feature = "std",
        error("invalid length: expected {expected}, got {actual}")
    )]
    InvalidLength { expected: usize, actual: usize },
    #[cfg_attr(
        feature = "std",
        error("invalid seed length: expected {expected}, got {actual}")
    )]
    InvalidSeedLength { expected: usize, actual: usize },
    #[cfg_attr(feature = "std", error("invalid public key"))]
    InvalidPublicKey,
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

pub type Result<T> = core::result::Result<T, HybridSignatureError>;
