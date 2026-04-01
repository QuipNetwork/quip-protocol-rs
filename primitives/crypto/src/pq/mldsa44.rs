//! ML-DSA-44 backend used by the hybrid signature engine.
//!
//! This backend uses the `fips204` crate's ML-DSA-44 implementation and exposes
//! it in the byte-oriented form expected by the hybrid layer.
//!
//! Encodings are fixed-size:
//! - seed: 32 bytes
//! - public key: 1312 bytes
//! - secret key: 2560 bytes
//! - signature: 2420 bytes
//!
//! The deterministic signing path intentionally ignores the external nonce and
//! relies on the backend's deterministic API instead.

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier as _};
use rand_core::CryptoRngCore;

/// Length in bytes of an ML-DSA-44 seed.
pub const SEED_LEN: usize = 32;
/// Length in bytes of a serialized ML-DSA-44 public key.
pub const PUBLIC_KEY_LEN: usize = 1312;
/// Length in bytes of a serialized ML-DSA-44 secret key.
pub const SECRET_KEY_LEN: usize = 2560;
/// Length in bytes of a serialized ML-DSA-44 signature.
pub const SIGNATURE_LEN: usize = 2420;

/// Generates a fresh ML-DSA-44 keypair.
pub fn generate(rng: &mut impl CryptoRngCore) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let (public, secret) =
        ml_dsa_44::KG::try_keygen_with_rng(rng).expect("ML-DSA-44 keygen failed");
    (public.into_bytes(), secret.into_bytes())
}

/// Derives an ML-DSA-44 keypair from a 32-byte seed.
pub fn from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let (public, secret) = ml_dsa_44::KG::keygen_from_seed(seed);
    (public.into_bytes(), secret.into_bytes())
}

/// Validates a serialized ML-DSA-44 public key.
pub fn validate_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    ml_dsa_44::PublicKey::try_from_bytes(*bytes).is_ok()
}

/// Validates a serialized ML-DSA-44 secret key.
pub fn validate_secret_key(bytes: &[u8; SECRET_KEY_LEN]) -> bool {
    ml_dsa_44::PrivateKey::try_from_bytes(*bytes).is_ok()
}

/// Derives the ML-DSA-44 public key from a serialized secret key.
pub fn public_key_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let secret =
        ml_dsa_44::PrivateKey::try_from_bytes(*secret).expect("stored ML-DSA-44 key is valid");
    secret.get_public_key().into_bytes()
}

/// Produces a hedged ML-DSA-44 signature over the already domain-separated
/// message.
pub fn sign(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    rng: &mut impl CryptoRngCore,
) -> [u8; SIGNATURE_LEN] {
    let secret =
        ml_dsa_44::PrivateKey::try_from_bytes(*secret).expect("stored ML-DSA-44 key is valid");
    secret
        .try_sign_with_rng(rng, msg_prime, b"")
        .expect("ML-DSA-44 hedged signing failed")
}

/// Produces a deterministic ML-DSA-44 signature over the already
/// domain-separated message.
///
/// The deterministic path intentionally uses a fixed seed and ignores the
/// external hybrid nonce because ML-DSA-44 is treated as natively deterministic
/// in this crate's API.
pub fn sign_deterministic(secret: &[u8; SECRET_KEY_LEN], msg_prime: &[u8]) -> [u8; SIGNATURE_LEN] {
    let secret =
        ml_dsa_44::PrivateKey::try_from_bytes(*secret).expect("stored ML-DSA-44 key is valid");
    secret
        .try_sign_with_seed(&[0u8; 32], msg_prime, b"")
        .expect("ML-DSA-44 deterministic signing failed")
}

/// Verifies an ML-DSA-44 signature over the already domain-separated message.
pub fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    msg_prime: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    match ml_dsa_44::PublicKey::try_from_bytes(*public) {
        Ok(public) => public.verify(msg_prime, signature, b""),
        Err(_) => false,
    }
}
