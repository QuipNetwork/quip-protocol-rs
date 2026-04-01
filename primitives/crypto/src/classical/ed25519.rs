//! ed25519 backend used by the hybrid signature engine.
//!
//! Key encoding matches the hybrid specification:
//! - seed: 32 bytes
//! - public key: 32 bytes
//! - secret key: 64 bytes encoded as `seed || public`
//! - signature: 64 bytes
//!
//! Signing uses `ed25519-zebra` directly. At the moment both `sign()` and
//! `sign_deterministic()` are intentionally equivalent: they perform standard
//! deterministic Ed25519 signing over the already domain-separated message and
//! ignore the caller-supplied RNG and nonce.

use core::convert::TryFrom;

use ed25519_zebra::{Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use rand_core::CryptoRngCore;

/// Length in bytes of an ed25519 seed.
pub const SEED_LEN: usize = 32;
/// Length in bytes of a serialized ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of a serialized ed25519 secret key (`seed || public`).
pub const SECRET_KEY_LEN: usize = 64;
/// Length in bytes of an ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Derives an ed25519 keypair from a 32-byte seed.
///
/// Returns the public key plus the 64-byte secret key encoding used by this
/// crate: `seed || public`.
pub fn from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let signing_key = SigningKey::from(*seed);
    let public: [u8; PUBLIC_KEY_LEN] = VerificationKeyBytes::from(&signing_key).into();

    let mut secret = [0u8; SECRET_KEY_LEN];
    secret[..SEED_LEN].copy_from_slice(seed);
    secret[SEED_LEN..].copy_from_slice(&public);

    (public, secret)
}

/// Validates a serialized ed25519 public key.
pub fn validate_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    VerificationKey::try_from(*bytes).is_ok()
}

/// Validates a serialized ed25519 secret key in `seed || public` form.
///
/// Validation recomputes the public key from the seed and checks that it
/// matches the appended public key bytes.
pub fn validate_secret_key(bytes: &[u8; SECRET_KEY_LEN]) -> bool {
    let seed: &[u8; SEED_LEN] = bytes[..SEED_LEN].try_into().expect("seed length");
    let public: &[u8; PUBLIC_KEY_LEN] = bytes[SEED_LEN..].try_into().expect("public key length");

    let signing_key = SigningKey::from(*seed);
    let expected_public: [u8; PUBLIC_KEY_LEN] = VerificationKeyBytes::from(&signing_key).into();

    expected_public == *public && validate_public_key(public)
}

/// Derives the ed25519 public key from a serialized secret key.
pub fn public_key_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let seed: &[u8; SEED_LEN] = secret[..SEED_LEN].try_into().expect("seed length");
    let signing_key = SigningKey::from(*seed);
    VerificationKeyBytes::from(&signing_key).into()
}

/// Signs `msg_prime` using native deterministic Ed25519.
///
/// The RNG parameter is currently ignored so that this backend can satisfy the
/// shared hybrid API without changing Ed25519 behavior.
pub fn sign(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    _rng: &mut impl CryptoRngCore,
) -> [u8; SIGNATURE_LEN] {
    sign_deterministic(secret, msg_prime, &[])
}

/// Signs `msg_prime` using native deterministic Ed25519.
///
/// The nonce is currently ignored. This preserves the agreed API shape for all
/// hybrid suites while keeping the ed25519 backend simple and predictable.
pub fn sign_deterministic(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    _nonce: &[u8],
) -> [u8; SIGNATURE_LEN] {
    let seed: &[u8; SEED_LEN] = secret[..SEED_LEN].try_into().expect("seed length");
    let signing_key = SigningKey::from(*seed);
    signing_key.sign(msg_prime).to_bytes()
}

/// Verifies an ed25519 signature over the already domain-separated message.
pub fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    msg_prime: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let public = match VerificationKey::try_from(*public) {
        Ok(public) => public,
        Err(_) => return false,
    };
    let signature = match Signature::try_from(signature.as_slice()) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    public.verify(&signature, msg_prime).is_ok()
}
