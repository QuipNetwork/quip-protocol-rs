//! Post-quantum signature backends used by the hybrid suites.
//!
//! Like [`crate::classical`], this module adapts concrete algorithms into a
//! byte-oriented interface consumed by the generic hybrid engine. The current
//! crate only exposes a fixed-size ML-DSA-44 backend, but the abstraction is
//! intentionally written so additional fixed-size PQ schemes can be added later.

use rand_core::CryptoRngCore;

use crate::seed::MASTER_SEED_LEN;

pub mod mldsa44;

/// Byte-oriented interface implemented by fixed-size PQ signature algorithms.
///
/// The hybrid layer signs an already domain-separated message `msg_prime` and
/// treats each PQ backend as a source of fixed-size serialized keys and
/// signatures.
pub trait FixedPqSignatureAlgorithm {
    /// Serialized public key representation.
    type PublicKeyBytes: AsRef<[u8]>;
    /// Serialized secret key representation.
    type SecretKeyBytes: AsRef<[u8]>;
    /// Serialized signature representation.
    type SignatureBytes: AsRef<[u8]>;

    /// Generates a fresh PQ keypair.
    fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);

    /// Derives a deterministic PQ keypair from a 32-byte component seed.
    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);

    /// Validates a serialized public key.
    fn validate_public_key(public: &[u8]) -> bool;

    /// Derives the public key from serialized secret-key bytes.
    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes;

    /// Produces a hedged PQ signature over the already domain-separated
    /// message.
    fn sign<R: CryptoRngCore>(secret: &[u8], msg_prime: &[u8], rng: &mut R)
        -> Self::SignatureBytes;

    /// Produces a deterministic PQ signature over the already domain-separated
    /// message.
    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes;

    /// Verifies a PQ signature over the already domain-separated message.
    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool;
}

/// Marker type for the ML-DSA-44 backend.
pub struct MlDsa44;

impl FixedPqSignatureAlgorithm for MlDsa44 {
    type PublicKeyBytes = [u8; mldsa44::PUBLIC_KEY_LEN];
    type SecretKeyBytes = [u8; mldsa44::SECRET_KEY_LEN];
    type SignatureBytes = [u8; mldsa44::SIGNATURE_LEN];

    fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        mldsa44::generate(rng)
    }

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        mldsa44::from_seed(seed)
    }

    fn validate_public_key(public: &[u8]) -> bool {
        let public: &[u8; mldsa44::PUBLIC_KEY_LEN] = match public.try_into() {
            Ok(public) => public,
            Err(_) => return false,
        };
        mldsa44::validate_public_key(public)
    }

    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes {
        let secret: &[u8; mldsa44::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid ML-DSA-44 secret key length");
        mldsa44::public_key_from_secret(secret)
    }

    fn sign<R: CryptoRngCore>(
        secret: &[u8],
        msg_prime: &[u8],
        rng: &mut R,
    ) -> Self::SignatureBytes {
        let secret: &[u8; mldsa44::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid ML-DSA-44 secret key length");
        mldsa44::sign(secret, msg_prime, rng)
    }

    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes {
        let _ = nonce;
        let secret: &[u8; mldsa44::SECRET_KEY_LEN] = secret
            .try_into()
            .expect("invalid ML-DSA-44 secret key length");
        mldsa44::sign_deterministic(secret, msg_prime)
    }

    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool {
        let public: &[u8; mldsa44::PUBLIC_KEY_LEN] = match public.try_into() {
            Ok(public) => public,
            Err(_) => return false,
        };
        let signature: &[u8; mldsa44::SIGNATURE_LEN] = match signature.try_into() {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        mldsa44::verify(public, msg_prime, signature)
    }
}
