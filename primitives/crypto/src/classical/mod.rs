//! Classical signature backends used by the hybrid suites.
//!
//! This module provides two things:
//! - concrete algorithm adapters in [`ed25519`] and [`sr25519`]
//! - a small internal trait, [`ClassicalSignatureAlgorithm`], used by the
//!   generic fixed-size hybrid engine
//!
//! The hybrid layer signs a domain-separated message (`msg_prime`) and treats
//! each classical backend as an implementation detail behind byte-oriented
//! helpers. Each backend is therefore responsible for:
//! - key generation from a 32-byte component seed
//! - validating serialized public keys
//! - deriving a public key from serialized secret key bytes
//! - hedged signing
//! - deterministic signing
//! - verification
//!
//! The two supported algorithms intentionally differ in signing semantics:
//! - [`Ed25519`] uses native deterministic Ed25519 signing and currently ignores
//!   both the caller-provided RNG and deterministic nonce.
//! - [`Sr25519`] supports both hedged signing with external randomness and a
//!   deterministic mode that derives an internal RNG stream from
//!   `H(secret || nonce || msg_prime)`.

use rand_core::CryptoRngCore;

use crate::seed::MASTER_SEED_LEN;

pub mod ed25519;
pub mod sr25519;

/// Byte-oriented interface implemented by classical algorithms inside the
/// hybrid signature engine.
///
/// This trait is internal to the crate's composition logic. It keeps the
/// generic hybrid layer independent from concrete key types by expressing all
/// operations in terms of fixed-size byte arrays plus signing and verification
/// primitives over the already domain-separated message `msg_prime`.
pub trait ClassicalSignatureAlgorithm {
    /// Serialized public key representation.
    type PublicKeyBytes: AsRef<[u8]>;
    /// Serialized secret key representation.
    type SecretKeyBytes: AsRef<[u8]>;
    /// Serialized signature representation.
    type SignatureBytes: AsRef<[u8]>;

    /// Deterministically derives a classical keypair from a 32-byte component
    /// seed produced by the hybrid seed-expansion logic.
    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);

    /// Validates a serialized public key.
    ///
    /// Implementations return `false` on length mismatch or decoding failure.
    fn validate_public_key(public: &[u8]) -> bool;

    /// Derives a public key from serialized secret key bytes.
    ///
    /// Callers are expected to pass a correctly sized secret key slice.
    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes;

    /// Produces a hedged signature over the already domain-separated message.
    ///
    /// Backends may interpret the RNG differently. In particular, the current
    /// ed25519 backend ignores it and remains fully deterministic.
    fn sign<R: CryptoRngCore>(secret: &[u8], msg_prime: &[u8], rng: &mut R)
        -> Self::SignatureBytes;

    /// Produces a deterministic signature over the already domain-separated
    /// message using a caller-supplied nonce.
    ///
    /// Backends are free to define their own nonce handling. The current
    /// ed25519 backend ignores `nonce`, while sr25519 mixes it into an
    /// internally derived RNG stream.
    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes;

    /// Verifies a signature against a serialized public key and domain-separated
    /// message.
    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool;
}

/// Marker type for the sr25519 classical backend.
pub struct Sr25519;

impl ClassicalSignatureAlgorithm for Sr25519 {
    type PublicKeyBytes = [u8; sr25519::PUBLIC_KEY_LEN];
    type SecretKeyBytes = [u8; sr25519::SECRET_KEY_LEN];
    type SignatureBytes = [u8; sr25519::SIGNATURE_LEN];

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        sr25519::from_seed(seed)
    }

    fn validate_public_key(public: &[u8]) -> bool {
        let public: &[u8; sr25519::PUBLIC_KEY_LEN] = match public.try_into() {
            Ok(public) => public,
            Err(_) => return false,
        };
        sr25519::validate_public_key(public)
    }

    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes {
        let secret: &[u8; sr25519::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid sr25519 secret key length");
        sr25519::public_key_from_secret(secret)
    }

    fn sign<R: CryptoRngCore>(
        secret: &[u8],
        msg_prime: &[u8],
        rng: &mut R,
    ) -> Self::SignatureBytes {
        let secret: &[u8; sr25519::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid sr25519 secret key length");
        sr25519::sign(secret, msg_prime, rng)
    }

    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes {
        let secret: &[u8; sr25519::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid sr25519 secret key length");
        sr25519::sign_deterministic(secret, msg_prime, nonce)
    }

    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool {
        let public: &[u8; sr25519::PUBLIC_KEY_LEN] = match public.try_into() {
            Ok(public) => public,
            Err(_) => return false,
        };
        let signature: &[u8; sr25519::SIGNATURE_LEN] = match signature.try_into() {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        sr25519::verify(public, msg_prime, signature)
    }
}

/// Marker type for the ed25519 classical backend.
pub struct Ed25519;

impl ClassicalSignatureAlgorithm for Ed25519 {
    type PublicKeyBytes = [u8; ed25519::PUBLIC_KEY_LEN];
    type SecretKeyBytes = [u8; ed25519::SECRET_KEY_LEN];
    type SignatureBytes = [u8; ed25519::SIGNATURE_LEN];

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        ed25519::from_seed(seed)
    }

    fn validate_public_key(public: &[u8]) -> bool {
        let public: &[u8; ed25519::PUBLIC_KEY_LEN] = match public.try_into() {
            Ok(public) => public,
            Err(_) => return false,
        };
        ed25519::validate_public_key(public)
    }

    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes {
        let secret: &[u8; ed25519::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid ed25519 secret key length");
        ed25519::public_key_from_secret(secret)
    }

    fn sign<R: CryptoRngCore>(
        secret: &[u8],
        msg_prime: &[u8],
        rng: &mut R,
    ) -> Self::SignatureBytes {
        let secret: &[u8; ed25519::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid ed25519 secret key length");
        ed25519::sign(secret, msg_prime, rng)
    }

    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes {
        let secret: &[u8; ed25519::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid ed25519 secret key length");
        ed25519::sign_deterministic(secret, msg_prime, nonce)
    }

    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool {
        let public: &[u8; ed25519::PUBLIC_KEY_LEN] = match public.try_into() {
            Ok(public) => public,
            Err(_) => return false,
        };
        let signature: &[u8; ed25519::SIGNATURE_LEN] = match signature.try_into() {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        ed25519::verify(public, msg_prime, signature)
    }
}
