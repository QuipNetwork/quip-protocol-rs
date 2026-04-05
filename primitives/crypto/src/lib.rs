//! Hybrid signature primitives for the Quip protocol.
//!
//! This crate currently provides fixed-size hybrid signature suites that pair a
//! classical signature algorithm with ML-DSA-44:
//! - [`Ed25519MlDsa44`]
//! - [`Sr25519MlDsa44`]
//!
//! Internally, the crate is organized into a few layers:
//! - [`classical`] and [`pq`] adapt concrete component algorithms into a common
//!   byte-oriented interface
//! - [`fixed`] contains the reusable engine for fixed-size hybrid suites
//! - [`suite`] contains concrete suite definitions, labels, and wrapper types
//! - [`substrate`] contains Substrate-facing wrappers for selected suites
//! - [`seed`] and [`domain`] provide shared seed-expansion and message-binding
//!   helpers
//!
//! The public API is centered around [`HybridSignatureScheme`], which exposes
//! generation, serialization, signing, and verification for a concrete hybrid
//! suite.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod classical;
mod domain;
mod error;
mod fixed;
mod pq;
mod seed;
#[cfg(feature = "std")]
pub mod substrate;
pub mod suite;

pub use error::{HybridSignatureError, Result};
pub use suite::ed25519_mldsa44::Ed25519MlDsa44;
pub use suite::ed25519_mldsa44::{
    PublicKey as Ed25519MlDsa44PublicKey, SecretKey as Ed25519MlDsa44SecretKey,
    Signature as Ed25519MlDsa44Signature,
};
pub use suite::sr25519_mldsa44::Sr25519MlDsa44;
pub use suite::sr25519_mldsa44::{
    PublicKey as Sr25519MlDsa44PublicKey, SecretKey as Sr25519MlDsa44SecretKey,
    Signature as Sr25519MlDsa44Signature,
};

use rand_core::CryptoRngCore;
use zeroize::Zeroize;

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
    /// Serialized public-key type for the suite.
    type PublicKey: AsRef<[u8]> + Clone;
    /// Serialized secret-key type for the suite.
    type SecretKey: Zeroize;
    /// Serialized signature type for the suite.
    type Signature: AsRef<[u8]>;

    /// Returns the serialized public-key length in bytes.
    fn public_key_len() -> usize;
    /// Returns the serialized secret-key length in bytes.
    fn secret_key_len() -> usize;
    /// Returns the maximum serialized signature length in bytes.
    fn signature_max_len() -> usize;

    /// Generates a fresh keypair.
    fn generate(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey);

    /// Derives a deterministic keypair from a 32-byte master seed.
    fn from_seed_slice(seed: &[u8]) -> Result<(Self::SecretKey, Self::PublicKey)>;

    /// Parses and validates a serialized public key.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey>;

    /// Parses and validates a serialized secret key.
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey>;

    /// Parses and validates a serialized signature.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature>;

    /// Derives the public key from a secret key.
    fn public(sk: &Self::SecretKey) -> Self::PublicKey;

    /// Hedged signing. Safe for all use cases.
    ///
    /// `ctx` is an optional application-specific context that is folded into
    /// the domain-separated message before the component signatures are
    /// produced.
    fn sign(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Self::Signature;

    /// Deterministic signing with a network-derived nonce.
    ///
    /// `ctx` is an optional application-specific context that is folded into
    /// the domain-separated message before signing.
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
    ///
    /// `ctx` must exactly match the context used during signing.
    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool;

    /// Verification with nonce check.
    ///
    /// `ctx` must exactly match the context used during signing.
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

/// Common interface for hybrid VRF constructions.
///
/// This trait is intentionally smaller than the eventual BABE crypto interface.
/// It captures the minimum operations needed to build BABE-facing helpers and
/// proof types around a concrete hybrid VRF implementation:
/// - derive the consensus-facing hybrid VRF output from an input
/// - produce a hybrid VRF proof
/// - derive bytes from the hybrid output
/// - verify a proof against a public key
pub trait HybridVrf {
    /// Public-key type used to verify VRF proofs.
    type PublicKey;
    /// VRF input type.
    type VrfInput;
    /// VRF signing data type.
    type VrfSignData;
    /// Consensus-facing VRF output type.
    type VrfOutput;
    /// VRF proof / signature type.
    type VrfSignature;

    /// Derives the consensus-facing hybrid VRF output for the given input.
    fn vrf_output(&self, input: &Self::VrfInput) -> Self::VrfOutput;

    /// Produces a hybrid VRF proof for the given sign data.
    fn vrf_sign(&self, data: &Self::VrfSignData) -> Self::VrfSignature;

    /// Expands the hybrid VRF output into `N` bytes for protocol use.
    fn make_bytes<const N: usize>(&self, context: &[u8], input: &Self::VrfInput) -> [u8; N]
    where
        [u8; N]: Default;

    /// Verifies a hybrid VRF proof.
    fn vrf_verify(
        public: &Self::PublicKey,
        data: &Self::VrfSignData,
        signature: &Self::VrfSignature,
    ) -> bool;
}
