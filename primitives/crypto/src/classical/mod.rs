use rand_core::CryptoRngCore;

use crate::suite::MASTER_SEED_LEN;

pub mod sr25519;

pub trait ClassicalSignatureAlgorithm {
    type PublicKeyBytes: AsRef<[u8]>;
    type SecretKeyBytes: AsRef<[u8]>;
    type SignatureBytes: AsRef<[u8]>;

    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);
    fn validate_public_key(bytes: &[u8]) -> bool;
    fn validate_secret_key(bytes: &[u8]) -> bool;
    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes;
    fn sign<R: CryptoRngCore>(secret: &[u8], msg_prime: &[u8], rng: &mut R)
        -> Self::SignatureBytes;
    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes;
    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool;
}

pub struct Sr25519;

impl ClassicalSignatureAlgorithm for Sr25519 {
    type PublicKeyBytes = [u8; sr25519::PUBLIC_KEY_LEN];
    type SecretKeyBytes = [u8; sr25519::SECRET_KEY_LEN];
    type SignatureBytes = [u8; sr25519::SIGNATURE_LEN];

    const PUBLIC_KEY_LEN: usize = sr25519::PUBLIC_KEY_LEN;
    const SECRET_KEY_LEN: usize = sr25519::SECRET_KEY_LEN;
    const SIGNATURE_LEN: usize = sr25519::SIGNATURE_LEN;

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        sr25519::from_seed(seed)
    }

    fn validate_public_key(bytes: &[u8]) -> bool {
        match bytes.try_into() {
            Ok(bytes) => sr25519::validate_public_key(bytes),
            Err(_) => false,
        }
    }

    fn validate_secret_key(bytes: &[u8]) -> bool {
        match bytes.try_into() {
            Ok(bytes) => sr25519::validate_secret_key(bytes),
            Err(_) => false,
        }
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
