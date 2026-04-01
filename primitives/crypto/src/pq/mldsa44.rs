use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier as _};
use rand_core::CryptoRngCore;

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 1312;
pub const SECRET_KEY_LEN: usize = 2560;
pub const SIGNATURE_LEN: usize = 2420;

pub fn generate(rng: &mut impl CryptoRngCore) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let (public, secret) =
        ml_dsa_44::KG::try_keygen_with_rng(rng).expect("ML-DSA-44 keygen failed");
    (public.into_bytes(), secret.into_bytes())
}

pub fn from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let (public, secret) = ml_dsa_44::KG::keygen_from_seed(seed);
    (public.into_bytes(), secret.into_bytes())
}

pub fn validate_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    ml_dsa_44::PublicKey::try_from_bytes(*bytes).is_ok()
}

pub fn validate_secret_key(bytes: &[u8; SECRET_KEY_LEN]) -> bool {
    ml_dsa_44::PrivateKey::try_from_bytes(*bytes).is_ok()
}

pub fn public_key_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let secret =
        ml_dsa_44::PrivateKey::try_from_bytes(*secret).expect("stored ML-DSA-44 key is valid");
    secret.get_public_key().into_bytes()
}

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

pub fn sign_deterministic(secret: &[u8; SECRET_KEY_LEN], msg_prime: &[u8]) -> [u8; SIGNATURE_LEN] {
    let secret =
        ml_dsa_44::PrivateKey::try_from_bytes(*secret).expect("stored ML-DSA-44 key is valid");
    secret
        .try_sign_with_seed(&[0u8; 32], msg_prime, b"")
        .expect("ML-DSA-44 deterministic signing failed")
}

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
