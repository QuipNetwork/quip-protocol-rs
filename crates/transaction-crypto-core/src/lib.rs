#![cfg_attr(not(feature = "std"), no_std)]

//! Pure transaction/account identity helpers for Quip's hybrid signer.
//!
//! This crate is intentionally bytes-oriented:
//! - it derives compact 32-byte account ids from hybrid public bytes
//! - it signs raw payload bytes with the H3 suite
//! - it encodes/decodes the runtime signature envelope as raw bytes
//!
//! It does not depend on runtime traits, `sp_core`, or `sp_io`.

extern crate alloc;

use alloc::vec::Vec;

use bip39::{Language, Mnemonic};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use codec::{Decode, DecodeWithMemTracking, Encode};
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier as _};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SR_PUBLIC_LEN: usize = 32;
const SR_SECRET_LEN: usize = 64;
const SR_SIGNATURE_LEN: usize = 64;

const ML_DSA_PUBLIC_LEN: usize = 1312;
const ML_DSA_SECRET_LEN: usize = 2560;
const ML_DSA_SIGNATURE_LEN: usize = 2420;

const MASTER_SEED_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"hybrid-sig";
const HKDF_CLASSICAL_INFO: &[u8] = b"classical";
const HKDF_PQ_INFO: &[u8] = b"pq";
const H3_LABEL: &[u8] = b"hybrid-sr25519-mldsa44-v1\0";
const H3_VERSION: u8 = 1;
const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";

/// Serialized H3 public-key length in bytes.
pub const HYBRID_PUBLIC_LEN: usize = SR_PUBLIC_LEN + ML_DSA_PUBLIC_LEN;
/// Serialized H3 signature length in bytes.
pub const HYBRID_SIGNATURE_LEN: usize = SR_SIGNATURE_LEN + ML_DSA_SIGNATURE_LEN;
/// Serialized H3 secret-key length in bytes.
pub const HYBRID_SECRET_LEN: usize = SR_SECRET_LEN + ML_DSA_SECRET_LEN;
/// Fixed length of derived Quip account ids.
pub const ACCOUNT_ID_LEN: usize = 32;

/// Domain separator for account-id derivation from the hybrid public key.
pub const ACCOUNT_ID_DOMAIN: &[u8] = b"quip-account-v1";

/// Error returned by byte-level hybrid transaction crypto helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HybridTxCryptoError {
    InvalidLength { expected: usize, actual: usize },
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSeed,
    SigningFailed,
    /// The BIP39 phrase was not a valid English mnemonic.
    InvalidMnemonic,
    /// The secret URI contained `/`-prefixed derivation junctions, which the
    /// browser signer intentionally does not support.
    UnsupportedDerivationPath,
}

pub type HybridResult<T> = core::result::Result<T, HybridTxCryptoError>;

/// Bytes-level transaction signature envelope.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Encode, Decode, DecodeWithMemTracking)]
pub struct HybridTxSignatureBytes {
    pub public: [u8; HYBRID_PUBLIC_LEN],
    pub signature: [u8; HYBRID_SIGNATURE_LEN],
}

impl HybridTxSignatureBytes {
    /// Creates a bytes-level envelope after validating the input lengths and encodings.
    pub fn new(public: &[u8], signature: &[u8]) -> HybridResult<Self> {
        let public = public_from_bytes(public)?;
        let signature = signature_from_bytes(signature)?;

        Ok(Self { public, signature })
    }

    /// Returns the derived compact account id for the embedded public key.
    pub fn derived_account_id(&self) -> [u8; ACCOUNT_ID_LEN] {
        account_id_from_public_bytes(&self.public)
    }

    /// Verifies the embedded signature against the provided raw message bytes.
    pub fn verify(&self, message: &[u8]) -> bool {
        verify_h3(&self.public, message, b"", &self.signature)
    }

    /// SCALE-encodes the bytes-level envelope.
    pub fn encode_envelope(&self) -> Vec<u8> {
        self.encode()
    }

    /// Decodes a SCALE-encoded bytes-level envelope.
    pub fn decode_envelope(bytes: &[u8]) -> HybridResult<Self> {
        let decoded =
            Self::decode(&mut &bytes[..]).map_err(|_| HybridTxCryptoError::InvalidLength {
                expected: HYBRID_PUBLIC_LEN + HYBRID_SIGNATURE_LEN,
                actual: bytes.len(),
            })?;
        Self::new(&decoded.public, &decoded.signature)
    }
}

/// Derives the compact Quip account id from serialized H3 public bytes.
pub fn account_id_from_public_bytes(public: &[u8]) -> [u8; ACCOUNT_ID_LEN] {
    let mut hasher = Blake2bVar::new(ACCOUNT_ID_LEN).expect("32-byte Blake2 output is valid");
    hasher.update(ACCOUNT_ID_DOMAIN);
    hasher.update(public);

    let mut out = [0u8; ACCOUNT_ID_LEN];
    hasher
        .finalize_variable(&mut out)
        .expect("output length matches buffer");
    out
}

/// Derives serialized H3 public bytes from a 32-byte H3 master seed.
pub fn public_key_from_seed(seed: &[u8]) -> HybridResult<[u8; HYBRID_PUBLIC_LEN]> {
    let (_, public) = keypair_from_seed(seed)?;
    Ok(public)
}

/// Derives the 32-byte H3 master seed from a limited secret URI.
///
/// This mirrors the supported subset of substrate's `Pair::from_string`:
///
/// - a `0x`-prefixed 64-digit hex string is used directly as the master seed;
/// - otherwise the input is an English BIP39 phrase, optionally followed by
///   `///<password>`.
///
/// Derivation junctions (`//hard`, `/soft`) and the leading-`/` dev-phrase
/// shortcut are intentionally **not** supported: a `/` outside the `///`
/// password separator is rejected rather than silently ignored, so an imported
/// account can never derive to an address the runtime would not recognize.
pub fn master_seed_from_secret_uri(uri: &str) -> HybridResult<[u8; MASTER_SEED_LEN]> {
    let (phrase, password) = match uri.split_once("///") {
        Some((phrase, password)) => (phrase, Some(password)),
        None => (uri, None),
    };
    let phrase = phrase.trim();

    if let Some(hex) = phrase.strip_prefix("0x").or_else(|| phrase.strip_prefix("0X")) {
        return decode_seed_hex(hex);
    }

    if phrase.contains('/') {
        return Err(HybridTxCryptoError::UnsupportedDerivationPath);
    }

    master_seed_from_mnemonic(phrase, password)
}

/// Derives the 32-byte H3 master seed from an English BIP39 phrase.
///
/// This matches substrate's `Pair::from_phrase`: the mnemonic entropy is run
/// through `substrate_bip39::seed_from_entropy` (PBKDF2-HMAC-SHA512, salt
/// `"mnemonic" || password`, 2048 rounds) and the first 32 bytes of the 64-byte
/// output are taken as the master seed.
pub fn master_seed_from_mnemonic(
    phrase: &str,
    password: Option<&str>,
) -> HybridResult<[u8; MASTER_SEED_LEN]> {
    // `parse_in_normalized` expects already-NFKD input and, unlike `parse_in`,
    // does not pull in `unicode-normalization`. English BIP39 words are
    // lowercase ASCII (always NFKD) and NFKD never changes case, so this yields
    // the same entropy as substrate's `parse_in` for every valid English
    // mnemonic.
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| HybridTxCryptoError::InvalidMnemonic)?;
    let (entropy, entropy_len) = mnemonic.to_entropy_array();

    let mut big_seed = substrate_bip39::seed_from_entropy(&entropy[..entropy_len], password.unwrap_or(""))
        .map_err(|_| HybridTxCryptoError::InvalidMnemonic)?;

    let mut seed = [0u8; MASTER_SEED_LEN];
    seed.copy_from_slice(&big_seed[..MASTER_SEED_LEN]);
    big_seed.zeroize();

    Ok(seed)
}

/// Decodes a 64-digit hex string into a 32-byte master seed.
fn decode_seed_hex(hex: &str) -> HybridResult<[u8; MASTER_SEED_LEN]> {
    if hex.len() != MASTER_SEED_LEN * 2 {
        return Err(HybridTxCryptoError::InvalidSeed);
    }

    let mut seed = [0u8; MASTER_SEED_LEN];
    for (index, byte) in seed.iter_mut().enumerate() {
        let hi = hex_digit(hex.as_bytes()[index * 2])?;
        let lo = hex_digit(hex.as_bytes()[index * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }

    Ok(seed)
}

fn hex_digit(ch: u8) -> HybridResult<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(HybridTxCryptoError::InvalidSeed),
    }
}

/// Signs raw payload bytes with a 32-byte H3 master seed and returns the bytes-level envelope.
pub fn sign_payload_from_seed(seed: &[u8], payload: &[u8]) -> HybridResult<HybridTxSignatureBytes> {
    let (secret, public) = keypair_from_seed(seed)?;
    sign_payload_from_secret(&secret, &public, payload)
}

/// Signs raw payload bytes with expanded H3 secret bytes and matching public bytes.
pub fn sign_payload_from_secret(
    secret: &[u8],
    public: &[u8],
    payload: &[u8],
) -> HybridResult<HybridTxSignatureBytes> {
    let secret = secret_from_bytes(secret)?;
    let public = public_from_bytes(public)?;
    let signature = sign_h3_deterministic(&secret, payload, b"", b"")?;

    HybridTxSignatureBytes::new(&public, &signature)
}

fn keypair_from_seed(
    seed: &[u8],
) -> HybridResult<([u8; HYBRID_SECRET_LEN], [u8; HYBRID_PUBLIC_LEN])> {
    let mut classical_seed = [0u8; MASTER_SEED_LEN];
    let mut pq_seed = [0u8; MASTER_SEED_LEN];
    derive_component_seeds(seed, &mut classical_seed, &mut pq_seed)?;

    let (sr_public, sr_secret) = sr25519_from_seed(&classical_seed)?;
    let (ml_public, ml_secret) = ml_dsa_from_seed(&pq_seed);

    classical_seed.zeroize();
    pq_seed.zeroize();

    let mut secret = [0u8; HYBRID_SECRET_LEN];
    secret[..SR_SECRET_LEN].copy_from_slice(&sr_secret);
    secret[SR_SECRET_LEN..].copy_from_slice(&ml_secret);

    let mut public = [0u8; HYBRID_PUBLIC_LEN];
    public[..SR_PUBLIC_LEN].copy_from_slice(&sr_public);
    public[SR_PUBLIC_LEN..].copy_from_slice(&ml_public);

    Ok((secret, public))
}

fn derive_component_seeds(
    seed: &[u8],
    classical_seed: &mut [u8; MASTER_SEED_LEN],
    pq_seed: &mut [u8; MASTER_SEED_LEN],
) -> HybridResult<()> {
    if seed.len() != MASTER_SEED_LEN {
        return Err(HybridTxCryptoError::InvalidLength {
            expected: MASTER_SEED_LEN,
            actual: seed.len(),
        });
    }

    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    hkdf.expand(HKDF_CLASSICAL_INFO, classical_seed)
        .map_err(|_| HybridTxCryptoError::InvalidSeed)?;
    hkdf.expand(HKDF_PQ_INFO, pq_seed)
        .map_err(|_| HybridTxCryptoError::InvalidSeed)?;
    Ok(())
}

fn sr25519_from_seed(
    seed: &[u8; MASTER_SEED_LEN],
) -> HybridResult<([u8; SR_PUBLIC_LEN], [u8; SR_SECRET_LEN])> {
    let keypair = MiniSecretKey::from_bytes(seed)
        .map_err(|_| HybridTxCryptoError::InvalidSeed)?
        .expand_to_keypair(ExpansionMode::Ed25519);

    Ok((keypair.public.to_bytes(), keypair.secret.to_bytes()))
}

fn ml_dsa_from_seed(
    seed: &[u8; MASTER_SEED_LEN],
) -> ([u8; ML_DSA_PUBLIC_LEN], [u8; ML_DSA_SECRET_LEN]) {
    let (public, secret) = ml_dsa_44::KG::keygen_from_seed(seed);
    (public.into_bytes(), secret.into_bytes())
}

fn public_from_bytes(bytes: &[u8]) -> HybridResult<[u8; HYBRID_PUBLIC_LEN]> {
    if bytes.len() != HYBRID_PUBLIC_LEN {
        return Err(HybridTxCryptoError::InvalidLength {
            expected: HYBRID_PUBLIC_LEN,
            actual: bytes.len(),
        });
    }

    let mut public = [0u8; HYBRID_PUBLIC_LEN];
    public.copy_from_slice(bytes);

    if schnorrkel::PublicKey::from_bytes(&public[..SR_PUBLIC_LEN]).is_err() {
        return Err(HybridTxCryptoError::InvalidPublicKey);
    }

    let ml_public: [u8; ML_DSA_PUBLIC_LEN] = public[SR_PUBLIC_LEN..]
        .try_into()
        .expect("ML-DSA public slice length is fixed");
    if ml_dsa_44::PublicKey::try_from_bytes(ml_public).is_err() {
        return Err(HybridTxCryptoError::InvalidPublicKey);
    }

    Ok(public)
}

fn secret_from_bytes(bytes: &[u8]) -> HybridResult<[u8; HYBRID_SECRET_LEN]> {
    if bytes.len() != HYBRID_SECRET_LEN {
        return Err(HybridTxCryptoError::InvalidLength {
            expected: HYBRID_SECRET_LEN,
            actual: bytes.len(),
        });
    }

    let mut secret = [0u8; HYBRID_SECRET_LEN];
    secret.copy_from_slice(bytes);

    if schnorrkel::SecretKey::from_bytes(&secret[..SR_SECRET_LEN]).is_err() {
        secret.zeroize();
        return Err(HybridTxCryptoError::InvalidSecretKey);
    }

    let ml_secret: [u8; ML_DSA_SECRET_LEN] = secret[SR_SECRET_LEN..]
        .try_into()
        .expect("ML-DSA secret slice length is fixed");
    if ml_dsa_44::PrivateKey::try_from_bytes(ml_secret).is_err() {
        secret.zeroize();
        return Err(HybridTxCryptoError::InvalidSecretKey);
    }

    Ok(secret)
}

fn signature_from_bytes(bytes: &[u8]) -> HybridResult<[u8; HYBRID_SIGNATURE_LEN]> {
    if bytes.len() != HYBRID_SIGNATURE_LEN {
        return Err(HybridTxCryptoError::InvalidLength {
            expected: HYBRID_SIGNATURE_LEN,
            actual: bytes.len(),
        });
    }

    let mut signature = [0u8; HYBRID_SIGNATURE_LEN];
    signature.copy_from_slice(bytes);
    Ok(signature)
}

fn sign_h3_deterministic(
    secret: &[u8; HYBRID_SECRET_LEN],
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
) -> HybridResult<[u8; HYBRID_SIGNATURE_LEN]> {
    let msg_prime = prepare_message(msg, ctx);
    let sr_secret: &[u8; SR_SECRET_LEN] = secret[..SR_SECRET_LEN]
        .try_into()
        .expect("sr25519 secret slice length is fixed");
    let ml_secret: &[u8; ML_DSA_SECRET_LEN] = secret[SR_SECRET_LEN..]
        .try_into()
        .expect("ML-DSA secret slice length is fixed");

    let sr_signature = sr25519_sign_deterministic(sr_secret, &msg_prime, nonce)?;
    let ml_signature = ml_dsa_sign_deterministic(ml_secret, &msg_prime)?;

    let mut signature = [0u8; HYBRID_SIGNATURE_LEN];
    signature[..SR_SIGNATURE_LEN].copy_from_slice(&sr_signature);
    signature[SR_SIGNATURE_LEN..].copy_from_slice(&ml_signature);
    Ok(signature)
}

fn verify_h3(
    public: &[u8; HYBRID_PUBLIC_LEN],
    msg: &[u8],
    ctx: &[u8],
    signature: &[u8; HYBRID_SIGNATURE_LEN],
) -> bool {
    let msg_prime = prepare_message(msg, ctx);
    let sr_public: &[u8; SR_PUBLIC_LEN] = public[..SR_PUBLIC_LEN]
        .try_into()
        .expect("sr25519 public slice length is fixed");
    let ml_public: &[u8; ML_DSA_PUBLIC_LEN] = public[SR_PUBLIC_LEN..]
        .try_into()
        .expect("ML-DSA public slice length is fixed");
    let sr_signature: &[u8; SR_SIGNATURE_LEN] = signature[..SR_SIGNATURE_LEN]
        .try_into()
        .expect("sr25519 signature slice length is fixed");
    let ml_signature: &[u8; ML_DSA_SIGNATURE_LEN] = signature[SR_SIGNATURE_LEN..]
        .try_into()
        .expect("ML-DSA signature slice length is fixed");

    sr25519_verify(sr_public, &msg_prime, sr_signature)
        && ml_dsa_verify(ml_public, &msg_prime, ml_signature)
}

fn prepare_message(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    assert!(ctx.len() <= 255, "ctx must be at most 255 bytes");
    let mut out = Vec::with_capacity(1 + H3_LABEL.len() + 1 + ctx.len() + msg.len());
    out.push(H3_VERSION);
    out.extend_from_slice(H3_LABEL);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(msg);
    out
}

fn sr25519_sign_deterministic(
    secret: &[u8; SR_SECRET_LEN],
    msg_prime: &[u8],
    nonce: &[u8],
) -> HybridResult<[u8; SR_SIGNATURE_LEN]> {
    let rng_seed = Zeroizing::new(blake2_256_secret_parts(&[
        secret.as_ref(),
        nonce,
        msg_prime,
    ]));
    let secret = schnorrkel::SecretKey::from_bytes(secret)
        .map_err(|_| HybridTxCryptoError::InvalidSecretKey)?;
    let keypair = Zeroizing::new(secret.to_keypair());
    let mut det_rng = Blake2Rng::new(*rng_seed);
    let transcript = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(SUBSTRATE_SIGNING_CONTEXT).bytes(msg_prime),
        &mut det_rng,
    );
    Ok(keypair.sign(transcript).to_bytes())
}

fn sr25519_verify(
    public: &[u8; SR_PUBLIC_LEN],
    msg_prime: &[u8],
    signature: &[u8; SR_SIGNATURE_LEN],
) -> bool {
    let Ok(public) = schnorrkel::PublicKey::from_bytes(public) else {
        return false;
    };
    let Ok(signature) = schnorrkel::Signature::from_bytes(signature) else {
        return false;
    };

    public
        .verify_simple(SUBSTRATE_SIGNING_CONTEXT, msg_prime, &signature)
        .is_ok()
}

fn ml_dsa_sign_deterministic(
    secret: &[u8; ML_DSA_SECRET_LEN],
    msg_prime: &[u8],
) -> HybridResult<[u8; ML_DSA_SIGNATURE_LEN]> {
    let secret = ml_dsa_44::PrivateKey::try_from_bytes(*secret)
        .map_err(|_| HybridTxCryptoError::InvalidSecretKey)?;
    secret
        .try_sign_with_seed(&[0u8; MASTER_SEED_LEN], msg_prime, b"")
        .map_err(|_| HybridTxCryptoError::SigningFailed)
}

fn ml_dsa_verify(
    public: &[u8; ML_DSA_PUBLIC_LEN],
    msg_prime: &[u8],
    signature: &[u8; ML_DSA_SIGNATURE_LEN],
) -> bool {
    match ml_dsa_44::PublicKey::try_from_bytes(*public) {
        Ok(public) => public.verify(msg_prime, signature, b""),
        Err(_) => false,
    }
}

fn blake2_256_secret_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2b output is valid");
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output length matches buffer");
    out
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Blake2Rng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl Blake2Rng {
    fn new(seed: [u8; 32]) -> Self {
        let buf = blake2_256_seed_counter(&seed, 0);
        Blake2Rng {
            seed,
            counter: 0,
            buf,
            pos: 0,
        }
    }
}

impl RngCore for Blake2Rng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            if self.pos >= 32 {
                self.counter += 1;
                self.buf = blake2_256_seed_counter(&self.seed, self.counter);
                self.pos = 0;
            }

            let take = core::cmp::min(32 - self.pos, dest.len() - offset);
            dest[offset..offset + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Blake2Rng {}

fn blake2_256_seed_counter(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&counter.to_le_bytes());

    let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2b output is valid");
    hasher.update(&input);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output length matches buffer");
    input.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_domain_is_pinned() {
        assert_eq!(ACCOUNT_ID_DOMAIN, b"quip-account-v1");
    }

    #[test]
    fn same_public_key_derives_same_account_id() {
        let public = public_key_from_seed(&[1u8; 32]).unwrap();
        let first = account_id_from_public_bytes(public.as_ref());
        let second = account_id_from_public_bytes(public.as_ref());

        assert_eq!(first, second);
    }

    #[test]
    fn different_public_keys_derive_different_account_ids() {
        let alice = public_key_from_seed(&[1u8; 32]).unwrap();
        let bob = public_key_from_seed(&[2u8; 32]).unwrap();

        assert_ne!(
            account_id_from_public_bytes(alice.as_ref()),
            account_id_from_public_bytes(bob.as_ref())
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let envelope = sign_payload_from_seed(&[7u8; 32], b"quip-message").unwrap();
        assert!(envelope.verify(b"quip-message"));
        assert!(!envelope.verify(b"wrong-message"));
    }

    #[test]
    fn public_key_from_seed_matches_signed_envelope_public() {
        let public = public_key_from_seed(&[7u8; 32]).unwrap();
        let envelope = sign_payload_from_seed(&[7u8; 32], b"quip-message").unwrap();

        assert_eq!(public, envelope.public);
    }

    #[test]
    fn envelope_round_trips_through_scale() {
        let envelope = sign_payload_from_seed(&[9u8; 32], b"quip-message").unwrap();
        let encoded = envelope.encode_envelope();
        let decoded = HybridTxSignatureBytes::decode_envelope(&encoded).unwrap();

        assert_eq!(decoded, envelope);
        assert!(decoded.verify(b"quip-message"));
    }

    #[test]
    fn envelope_decode_rejects_empty_bytes() {
        assert!(HybridTxSignatureBytes::decode_envelope(&[]).is_err());
    }

    #[test]
    fn tampered_signature_rejects() {
        let mut envelope = sign_payload_from_seed(&[11u8; 32], b"quip-message").unwrap();
        envelope.signature[envelope.signature.len() / 2] ^= 0xFF;

        assert!(!envelope.verify(b"quip-message"));
    }

    #[test]
    fn wrong_seed_length_rejects() {
        assert!(public_key_from_seed(&[1u8; 31]).is_err());
    }

    // Standard BIP39 test vector phrase.
    const TEST_PHRASE: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn mnemonic_seed_is_deterministic() {
        let first = master_seed_from_mnemonic(TEST_PHRASE, None).unwrap();
        let second = master_seed_from_mnemonic(TEST_PHRASE, None).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn mnemonic_password_changes_seed() {
        let no_password = master_seed_from_mnemonic(TEST_PHRASE, None).unwrap();
        let with_password = master_seed_from_mnemonic(TEST_PHRASE, Some("hunter2")).unwrap();

        assert_ne!(no_password, with_password);
    }

    #[test]
    fn secret_uri_password_matches_explicit_password() {
        let split = master_seed_from_secret_uri(&alloc::format!("{TEST_PHRASE}///hunter2")).unwrap();
        let explicit = master_seed_from_mnemonic(TEST_PHRASE, Some("hunter2")).unwrap();

        assert_eq!(split, explicit);
    }

    #[test]
    fn secret_uri_accepts_hex_seed() {
        let seed = master_seed_from_secret_uri(
            "0x0707070707070707070707070707070707070707070707070707070707070707",
        )
        .unwrap();

        assert_eq!(seed, [7u8; MASTER_SEED_LEN]);
    }

    #[test]
    fn secret_uri_rejects_derivation_junctions() {
        assert_eq!(
            master_seed_from_secret_uri(&alloc::format!("{TEST_PHRASE}//0")),
            Err(HybridTxCryptoError::UnsupportedDerivationPath)
        );
    }

    #[test]
    fn secret_uri_rejects_invalid_phrase() {
        assert_eq!(
            master_seed_from_secret_uri("not a real mnemonic phrase at all"),
            Err(HybridTxCryptoError::InvalidMnemonic)
        );
    }

    #[test]
    fn mnemonic_seed_signs_and_verifies() {
        let seed = master_seed_from_mnemonic(TEST_PHRASE, None).unwrap();
        let envelope = sign_payload_from_seed(&seed, b"quip-message").unwrap();

        assert!(envelope.verify(b"quip-message"));
    }
}
