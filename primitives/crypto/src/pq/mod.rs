use rand_core::CryptoRngCore;

use crate::suite::MASTER_SEED_LEN;

pub mod mldsa44;

pub trait FixedPqSignatureAlgorithm {
    type PublicKeyBytes: AsRef<[u8]>;
    type SecretKeyBytes: AsRef<[u8]>;
    type SignatureBytes: AsRef<[u8]>;

    fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);
    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes);
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

    fn generate<R: CryptoRngCore>(rng: &mut R) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        mldsa44::generate(rng)
    }

    fn from_seed(seed: &[u8; MASTER_SEED_LEN]) -> (Self::PublicKeyBytes, Self::SecretKeyBytes) {
        mldsa44::from_seed(seed)
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
