use core::convert::TryFrom;

use ed25519_zebra::{Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use rand_core::CryptoRngCore;

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 64;

pub fn from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let signing_key = SigningKey::from(*seed);
    let public: [u8; PUBLIC_KEY_LEN] = VerificationKeyBytes::from(&signing_key).into();

    let mut secret = [0u8; SECRET_KEY_LEN];
    secret[..SEED_LEN].copy_from_slice(seed);
    secret[SEED_LEN..].copy_from_slice(&public);

    (public, secret)
}

pub fn validate_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    VerificationKey::try_from(*bytes).is_ok()
}

pub fn validate_secret_key(bytes: &[u8; SECRET_KEY_LEN]) -> bool {
    let seed: &[u8; SEED_LEN] = bytes[..SEED_LEN].try_into().expect("seed length");
    let public: &[u8; PUBLIC_KEY_LEN] = bytes[SEED_LEN..].try_into().expect("public key length");

    let signing_key = SigningKey::from(*seed);
    let expected_public: [u8; PUBLIC_KEY_LEN] = VerificationKeyBytes::from(&signing_key).into();

    expected_public == *public && validate_public_key(public)
}

pub fn public_key_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let seed: &[u8; SEED_LEN] = secret[..SEED_LEN].try_into().expect("seed length");
    let signing_key = SigningKey::from(*seed);
    VerificationKeyBytes::from(&signing_key).into()
}

pub fn sign(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    _rng: &mut impl CryptoRngCore,
) -> [u8; SIGNATURE_LEN] {
    sign_deterministic(secret, msg_prime, &[])
}

pub fn sign_deterministic(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    _nonce: &[u8],
) -> [u8; SIGNATURE_LEN] {
    let seed: &[u8; SEED_LEN] = secret[..SEED_LEN].try_into().expect("seed length");
    let signing_key = SigningKey::from(*seed);
    signing_key.sign(msg_prime).to_bytes()
}

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
