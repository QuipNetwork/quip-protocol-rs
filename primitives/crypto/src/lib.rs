#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod domain;
pub mod sr25519_mldsa44;

pub use sr25519_mldsa44::{HybridPublicKey, HybridSecretKey, HybridSignature, Sr25519MlDsa44};

use rand_core::CryptoRngCore;
use zeroize::Zeroize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HybridSignatureError {
    InvalidLength { expected: usize, actual: usize },
    InvalidSeedLength { expected: usize, actual: usize },
    InvalidPublicKey,
    InvalidSecretKey,
}

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

#[cfg(feature = "std")]
impl std::error::Error for HybridSignatureError {}

/// Common interface for hybrid signature constructions.
///
/// Signing has two modes:
/// - `sign` — hedged: adds fresh randomness where the scheme supports it (default).
/// - `sign_deterministic` — deterministic from a network-derived nonce (consensus use).
///
/// Verification has two modes:
/// - `verify` — works for signatures produced by either signing function.
/// - `verify_deterministic` — additionally checks the nonce where it is embedded
///   in the signature (Falcon-512 hybrids). For ML-DSA-44 hybrids this is equivalent
///   to `verify`.
pub trait HybridSignatureScheme {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey: Zeroize;
    type Signature: AsRef<[u8]>;

    fn public_key_len() -> usize;
    fn secret_key_len() -> usize;
    fn signature_max_len() -> usize;

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey);
    fn from_seed_slice(
        seed: &[u8],
    ) -> Result<(Self::SecretKey, Self::PublicKey), HybridSignatureError>;
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, HybridSignatureError>;
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey, HybridSignatureError>;
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, HybridSignatureError>;
    fn public(sk: &Self::SecretKey) -> Self::PublicKey;

    /// Hedged signing. Safe for all use cases.
    fn sign(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Self::Signature;

    /// Deterministic signing with a network-derived nonce.
    ///
    /// `nonce` MUST be unique per `(key, msg)` pair — typically
    /// `H(state_root || block_number || msg)`.
    fn sign_deterministic(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        nonce: &[u8],
    ) -> Self::Signature;

    /// Standard verification. Works for signatures from both signing functions.
    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool;

    /// Verification with nonce check.
    ///
    /// For Falcon-512 hybrids: extracts the nonce embedded in the PQ component
    /// and compares it to `expected_nonce`.
    /// For ML-DSA-44 hybrids: equivalent to `verify` (nonce is not embedded).
    fn verify_deterministic(
        pk: &Self::PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &Self::Signature,
        expected_nonce: &[u8],
    ) -> bool;
}
