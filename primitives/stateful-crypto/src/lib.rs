//! # sp-stateful-crypto
//!
//! Stateful signature primitives for Quip Protocol.
//!
//! Provides the [`StatefulSignature`] trait and a [`WotsPlus`] implementation.
//! The trait models hash-based, one-time-signature (OTS) schemes where each
//! key usage advances an on-chain state index that is enforced by the identity
//! registry pallet.
//!
//! ## Cryptographic agility
//!
//! The trait is intentionally scheme-agnostic so that SQISign (or any future
//! post-quantum primitive) can be added as a second `impl` without touching the
//! registry or transaction-validation logic.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod wots_plus;

pub use wots_plus::WotsPlus;

use codec::{Decode, Encode};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that a [`StatefulSignature`] implementation may return.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SignatureError {
    /// No OTS keys remain in the current state.
    #[cfg_attr(
        feature = "std",
        error("all one-time signature keys have been exhausted")
    )]
    KeysExhausted,

    /// The provided signature bytes are malformed.
    #[cfg_attr(
        feature = "std",
        error("signature is malformed or has an incorrect length")
    )]
    MalformedSignature,

    /// The provided public key bytes are malformed.
    #[cfg_attr(
        feature = "std",
        error("public key is malformed or has an incorrect length")
    )]
    MalformedPublicKey,

    /// Signature verification failed (wrong key, message, or index).
    #[cfg_attr(feature = "std", error("signature verification failed"))]
    VerificationFailed,
}

// ── Core trait ────────────────────────────────────────────────────────────────

/// A stateful, hash-based signature scheme.
///
/// Each call to [`sign`](StatefulSignature::sign) consumes exactly one OTS key
/// and increments the index stored in `State`.  The corresponding
/// [`verify`](StatefulSignature::verify) call takes the expected index so that
/// the identity registry can enforce strict ordering and prevent replay.
pub trait StatefulSignature: Sized {
    /// The public counterpart of a keypair (e.g. a Merkle root over OTS keys).
    type PublicKey: AsRef<[u8]> + Clone + Encode + Decode;

    /// A single signature together with any authentication data needed for
    /// verification (e.g. a Merkle auth-path for WOTS+).
    type Signature: AsRef<[u8]> + Clone + Encode + Decode;

    /// The secret material used to derive OTS signing keys.
    type SecretKey;

    /// Mutable per-identity state kept off-chain by the signer.
    ///
    /// Must be `Encode + Decode` so the runtime can persist a compact summary
    /// (the current index) on-chain while the full state lives with the wallet.
    type State: Encode + Decode + Clone;

    /// Generate a fresh keypair and its initial state.
    ///
    /// The caller is responsible for persisting `SecretKey` and `State`
    /// securely; losing either makes the identity unusable.
    fn generate() -> (Self::SecretKey, Self::PublicKey, Self::State);

    /// Sign `message` using the next unused OTS key, advancing `state`.
    ///
    /// Returns an error if no keys remain (`state` is exhausted).
    fn sign(
        secret: &Self::SecretKey,
        state: &mut Self::State,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError>;

    /// Verify `signature` over `message` using `public` at OTS position `state_index`.
    ///
    /// `state_index` must match the value tracked by the on-chain identity
    /// registry at the time the transaction is validated.
    fn verify(
        public: &Self::PublicKey,
        signature: &Self::Signature,
        message: &[u8],
        state_index: u64,
    ) -> bool;

    /// Read the current OTS index from `state`.
    fn current_index(state: &Self::State) -> u64;

    /// Return `true` if `state` has at least one unused OTS key.
    fn has_remaining_keys(state: &Self::State) -> bool;

    /// Total number of OTS keys available in `state` (tree capacity).
    fn total_keys(state: &Self::State) -> u64;
}
