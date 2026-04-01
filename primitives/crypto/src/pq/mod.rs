use rand_core::CryptoRngCore;

use crate::suite::MASTER_SEED_LEN;

pub mod mldsa44;

pub trait FixedPqSignatureAlgorithm {
    type PublicKeyBytes: AsRef<[u8]>;
    type SecretKeyBytes: AsRef<[u8]>;
    type SignatureBytes: AsRef<[u8]>;

    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;

    fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);
    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);
    fn validate_public_key(bytes: &[u8]) -> bool;
    fn validate_secret_key(bytes: &[u8]) -> bool;
    fn public_key_from_secret(secret: &[u8]) -> Self::PublicKeyBytes;
    fn sign<R: CryptoRngCore>(secret: &[u8], msg_prime: &[u8], rng: &mut R)
        -> Self::SignatureBytes;
    fn sign_deterministic(secret: &[u8], msg_prime: &[u8], nonce: &[u8]) -> Self::SignatureBytes;
    fn verify(public: &[u8], msg_prime: &[u8], signature: &[u8]) -> bool;
}

pub struct MlDsa44;

impl FixedPqSignatureAlgorithm for MlDsa44 {
    type PublicKeyBytes = [u8; mldsa44::PUBLIC_KEY_LEN];
    type SecretKeyBytes = [u8; mldsa44::SECRET_KEY_LEN];
    type SignatureBytes = [u8; mldsa44::SIGNATURE_LEN];

    const PUBLIC_KEY_LEN: usize = mldsa44::PUBLIC_KEY_LEN;
    const SECRET_KEY_LEN: usize = mldsa44::SECRET_KEY_LEN;
    const SIGNATURE_LEN: usize = mldsa44::SIGNATURE_LEN;

    fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        mldsa44::generate(rng)
    }

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        mldsa44::from_seed(seed)
    }

    fn validate_public_key(bytes: &[u8]) -> bool {
        match bytes.try_into() {
            Ok(bytes) => mldsa44::validate_public_key(bytes),
            Err(_) => false,
        }
    }

    fn validate_secret_key(bytes: &[u8]) -> bool {
        match bytes.try_into() {
            Ok(bytes) => mldsa44::validate_secret_key(bytes),
            Err(_) => false,
        }
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
