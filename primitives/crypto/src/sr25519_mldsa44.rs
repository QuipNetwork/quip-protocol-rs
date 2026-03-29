//! H3: sr25519 + ML-DSA-44 hybrid signature scheme.
//!
//! Composite sizes:
//!   Public key : 32  (sr25519)  + 1312 (ML-DSA-44) = 1344 bytes
//!   Signature  : 64  (sr25519)  + 2420 (ML-DSA-44) = 2484 bytes (fixed)
//!
//! Signature byte layout:
//!   [0  .. 64)   sr25519 signature
//!   [64 .. 2484) ML-DSA-44 signature
//!
//! Domain label: `hybrid-sr25519-mldsa44-v1`

use alloc::vec::Vec;

use crate::domain::prepare_message;
use crate::HybridSignatureScheme;

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier as _};
use rand_core::CryptoRngCore;
use sp_core::{sr25519, Pair};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION: u8 = 0x01;
const LABEL: &[u8] = b"hybrid-sr25519-mldsa44-v1";

const SR_PK_LEN: usize = 32;
const SR_SIG_LEN: usize = 64;

const ML_PK_LEN: usize = 1312;
const ML_SK_LEN: usize = 2560;
const ML_SIG_LEN: usize = 2420;

pub const HYBRID_PK_LEN: usize = SR_PK_LEN + ML_PK_LEN; // 1344
pub const HYBRID_SIG_LEN: usize = SR_SIG_LEN + ML_SIG_LEN; // 2484

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Composite public key: `sr25519_pk (32B) || ml_dsa_pk (1312B)`.
#[derive(Clone)]
pub struct HybridPublicKey([u8; HYBRID_PK_LEN]);

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for HybridPublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Composite secret key. Zeroized on drop — no `Clone`.
///
/// Stores the 32-byte sr25519 seed (to reconstruct `sp_core::sr25519::Pair`
/// on demand) plus ML-DSA-44 private and public key bytes.
/// `ml_dsa_pk` is cached so that `public()` is cheap.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    sr25519_seed: [u8; SR_PK_LEN],
    ml_dsa_sk: [u8; ML_SK_LEN],
    ml_dsa_pk: [u8; ML_PK_LEN],
}

/// Composite signature: `sr25519_sig (64B) || ml_dsa_sig (2420B)`.
#[derive(Clone)]
pub struct HybridSignature([u8; HYBRID_SIG_LEN]);

impl AsRef<[u8]> for HybridSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Zero-sized type implementing [`HybridSignatureScheme`] for H3.
pub struct Sr25519MlDsa44;

impl HybridSignatureScheme for Sr25519MlDsa44 {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type Signature = HybridSignature;

    /// Generate a fresh hybrid key pair from the provided RNG.
    fn generate(rng: &mut impl CryptoRngCore) -> (HybridSecretKey, HybridPublicKey) {
        // sr25519: seed from RNG for no_std compatibility
        let mut sr25519_seed = [0u8; 32];
        rng.fill_bytes(&mut sr25519_seed);
        let sr_pair = sr25519::Pair::from_seed_slice(&sr25519_seed)
            .expect("32-byte seed is always valid for sr25519");

        // ML-DSA-44
        let (ml_pk, ml_sk) =
            ml_dsa_44::KG::try_keygen_with_rng(rng).expect("ML-DSA-44 keygen failed");

        let ml_pk_bytes = ml_pk.into_bytes();
        let ml_sk_bytes = ml_sk.into_bytes();

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(sr_pair.public().as_array_ref());
        pk_bytes[SR_PK_LEN..].copy_from_slice(&ml_pk_bytes);

        let sk = HybridSecretKey {
            sr25519_seed,
            ml_dsa_sk: ml_sk_bytes,
            ml_dsa_pk: ml_pk_bytes,
        };

        (sk, HybridPublicKey(pk_bytes))
    }

    fn public(sk: &HybridSecretKey) -> HybridPublicKey {
        let sr_pair =
            sr25519::Pair::from_seed_slice(&sk.sr25519_seed).expect("stored sr25519 seed is valid");

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(sr_pair.public().as_array_ref());
        pk_bytes[SR_PK_LEN..].copy_from_slice(&sk.ml_dsa_pk);

        HybridPublicKey(pk_bytes)
    }

    /// Hedged signing.
    ///
    /// sr25519: injects the caller-provided RNG into schnorrkel's signing
    /// transcript to avoid relying on OS randomness. ML-DSA-44:
    /// `try_sign_with_rng` adds fresh randomness for hedged security.
    ///
    /// Both components sign `M' = VERSION || LABEL || ctx || msg`.
    fn sign(sk: &HybridSecretKey, msg: &[u8], rng: &mut impl CryptoRngCore) -> HybridSignature {
        let msg_prime = prepare_message(VERSION, LABEL, msg, &[]);

        let sr_sig = sr25519_sign_hedged(&sk.sr25519_seed, &msg_prime, rng);

        let ml_sk = ml_dsa_44::PrivateKey::try_from_bytes(sk.ml_dsa_sk)
            .expect("stored ML-DSA-44 key is valid");
        let ml_sig = ml_sk
            .try_sign_with_rng(rng, &msg_prime, b"")
            .expect("ML-DSA-44 hedged signing failed");

        build_signature(&sr_sig, &ml_sig)
    }

    /// Deterministic signing with a network-derived nonce.
    ///
    /// Delegates to [`sr25519_sign_det`] and [`mldsa44_sign_det`].
    fn sign_deterministic(sk: &HybridSecretKey, msg: &[u8], nonce: &[u8]) -> HybridSignature {
        let msg_prime = prepare_message(VERSION, LABEL, msg, &[]);
        let sr_sig = sr25519_sign_det(&sk.sr25519_seed, &msg_prime, nonce);
        // ML-DSA rnd = H(ml_dsa_sk || nonce || msg') — bound to the ML-DSA-44
        // key, not the sr25519 seed.
        let ml_rnd = blake2_256_secret_parts(&[sk.ml_dsa_sk.as_ref(), nonce, msg_prime.as_slice()]);
        let ml_sig = mldsa44_sign_det(&sk.ml_dsa_sk, &msg_prime, &ml_rnd);
        build_signature(&sr_sig, &ml_sig)
    }

    /// Standard verification. Works for signatures from both `sign` and
    /// `sign_deterministic`. Both components must pass.
    fn verify(pk: &HybridPublicKey, msg: &[u8], sig: &HybridSignature) -> bool {
        let msg_prime = prepare_message(VERSION, LABEL, msg, &[]);
        verify_internal(pk, &msg_prime, sig)
    }

    /// Verification with nonce check.
    ///
    /// For ML-DSA-44 hybrids: equivalent to `verify` — ML-DSA-44 does not
    /// embed a nonce in the signature, so there is nothing to check.
    /// (Nonce verification applies to Falcon-512 hybrids where the 40-byte
    /// nonce `r` is visible in the PQ signature component.)
    fn verify_deterministic(
        pk: &HybridPublicKey,
        msg: &[u8],
        sig: &HybridSignature,
        _expected_nonce: &[u8],
    ) -> bool {
        let msg_prime = prepare_message(VERSION, LABEL, msg, &[]);
        verify_internal(pk, &msg_prime, sig)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Counter-mode Blake2-256 PRNG used to drive `attach_rng` in
/// `sign_deterministic`.  Seeded from `H(sk_seed || nonce || msg')`.
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

impl rand_core::RngCore for Blake2Rng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
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

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Blake2Rng {}

fn blake2_256_seed_counter(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&counter.to_le_bytes());
    let hash = sp_core::hashing::blake2_256(&input);
    input.zeroize();
    hash
}

fn blake2_256_secret_parts(parts: &[&[u8]]) -> [u8; 32] {
    let total_len: usize = parts.iter().map(|part| part.len()).sum();
    let mut input = Zeroizing::new(Vec::with_capacity(total_len));
    for part in parts {
        input.extend_from_slice(part);
    }
    sp_core::hashing::blake2_256(input.as_slice())
}

fn sr25519_keypair_from_seed(seed: &[u8; 32]) -> schnorrkel::Keypair {
    let mini = schnorrkel::MiniSecretKey::from_bytes(seed).expect("valid sr25519 seed");
    mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519)
}

fn sr25519_sign_hedged(
    seed: &[u8; 32],
    msg_prime: &[u8],
    rng: &mut impl CryptoRngCore,
) -> sr25519::Signature {
    let keypair = sr25519_keypair_from_seed(seed);
    let t = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(b"substrate").bytes(msg_prime),
        rng,
    );
    sr25519::Signature::from_raw(keypair.sign(t).to_bytes())
}

/// sr25519 deterministic signing helper.
///
/// Derives Schnorr nonce `r` from `H(seed || nonce || msg_prime)` by seeding
/// `Blake2Rng` and feeding it to `schnorrkel::context::attach_rng`.  This
/// replaces schnorrkel's default `getrandom` call so the output is fully
/// determined by `(seed, nonce, msg_prime)`.
fn sr25519_sign_det(seed: &[u8; 32], msg_prime: &[u8], nonce: &[u8]) -> sr25519::Signature {
    let rng_seed = blake2_256_secret_parts(&[seed.as_ref(), nonce, msg_prime]);
    let keypair = sr25519_keypair_from_seed(seed);
    let mut det_rng = Blake2Rng::new(rng_seed);
    let t = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(b"substrate").bytes(msg_prime),
        &mut det_rng,
    );
    sr25519::Signature::from_raw(keypair.sign(t).to_bytes())
}

/// ML-DSA-44 deterministic signing helper.
///
/// Uses `try_sign_with_seed` (FIPS 204 §5.2 deterministic variant) so the
/// output is fully determined by `(ml_dsa_sk, msg_prime, rnd)` without calling
/// any system RNG.  `rnd` is the 32-byte randomness value that FIPS 204 calls
/// `rnd`; for deterministic signing derive it as `H(sk_seed || nonce || msg')`.
fn mldsa44_sign_det(
    ml_dsa_sk: &[u8; ML_SK_LEN],
    msg_prime: &[u8],
    rnd: &[u8; 32],
) -> [u8; ML_SIG_LEN] {
    let ml_sk =
        ml_dsa_44::PrivateKey::try_from_bytes(*ml_dsa_sk).expect("stored ML-DSA-44 key is valid");
    ml_sk
        .try_sign_with_seed(rnd, msg_prime, b"")
        .expect("ML-DSA-44 deterministic signing failed")
}

fn build_signature(sr_sig: &sr25519::Signature, ml_sig: &[u8; ML_SIG_LEN]) -> HybridSignature {
    let mut sig = [0u8; HYBRID_SIG_LEN];
    sig[..SR_SIG_LEN].copy_from_slice(sr_sig.as_ref());
    sig[SR_SIG_LEN..].copy_from_slice(ml_sig);
    HybridSignature(sig)
}

/// Verify both components against `msg_prime`. Both must pass.
fn verify_internal(pk: &HybridPublicKey, msg_prime: &[u8], sig: &HybridSignature) -> bool {
    let sr_pk = sr25519::Public::from_raw(pk.0[..SR_PK_LEN].try_into().expect("pk is 1344 bytes"));
    let ml_pk_bytes: &[u8; ML_PK_LEN] = pk.0[SR_PK_LEN..]
        .try_into()
        .expect("ml_pk slice is 1312 bytes");

    let sr_sig_bytes: &[u8; SR_SIG_LEN] =
        sig.0[..SR_SIG_LEN].try_into().expect("sig is 2484 bytes");
    let ml_sig_bytes: &[u8; ML_SIG_LEN] = sig.0[SR_SIG_LEN..]
        .try_into()
        .expect("ml_sig slice is 2420 bytes");

    let sr_sig = sr25519::Signature::from_raw(*sr_sig_bytes);
    let sr_ok = sr25519::Pair::verify(&sr_sig, msg_prime, &sr_pk);

    // Check both legs before returning — do not short-circuit on sr_ok
    let ml_ok = match ml_dsa_44::PublicKey::try_from_bytes(*ml_pk_bytes) {
        Ok(ml_pk) => ml_pk.verify(msg_prime, ml_sig_bytes, b""),
        Err(_) => false,
    };

    sr_ok && ml_ok
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn keygen() -> (HybridSecretKey, HybridPublicKey) {
        Sr25519MlDsa44::generate(&mut OsRng)
    }

    #[test]
    fn hedged_sign_verify_roundtrip() {
        let (sk, pk) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"hello quip", &mut OsRng);
        assert!(Sr25519MlDsa44::verify(&pk, b"hello quip", &sig));
    }

    #[test]
    fn deterministic_sign_verify_roundtrip() {
        let (sk, pk) = keygen();
        let nonce = b"H(state_root||block||msg)";
        let sig = Sr25519MlDsa44::sign_deterministic(&sk, b"hello quip", nonce);
        assert!(Sr25519MlDsa44::verify(&pk, b"hello quip", &sig));
    }

    #[test]
    fn deterministic_is_deterministic() {
        let (sk, _) = keygen();
        let nonce = b"same-nonce";
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", nonce);
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", nonce);
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn deterministic_different_nonce_gives_different_sig() {
        let (sk, _) = keygen();
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"nonce-1");
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"nonce-2");
        assert_ne!(sig1.0, sig2.0);
    }

    #[test]
    fn verify_accepts_hedged_and_deterministic() {
        let (sk, pk) = keygen();
        let hedged = Sr25519MlDsa44::sign(&sk, b"msg", &mut OsRng);
        let det = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"nonce");
        assert!(Sr25519MlDsa44::verify(&pk, b"msg", &hedged));
        assert!(Sr25519MlDsa44::verify(&pk, b"msg", &det));
    }

    #[test]
    fn verify_deterministic_is_equivalent_to_verify() {
        // For ML-DSA-44 hybrids verify_deterministic == verify (no nonce in signature).
        let (sk, pk) = keygen();
        let sig = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"nonce");
        assert!(Sr25519MlDsa44::verify_deterministic(
            &pk,
            b"msg",
            &sig,
            b"any-nonce"
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = keygen();
        let (_, wrong_pk) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"hello", &mut OsRng);
        assert!(!Sr25519MlDsa44::verify(&wrong_pk, b"hello", &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let (sk, pk) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"hello", &mut OsRng);
        assert!(!Sr25519MlDsa44::verify(&pk, b"world", &sig));
    }

    #[test]
    fn signature_is_correct_length() {
        let (sk, _) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"test", &mut OsRng);
        assert_eq!(sig.as_ref().len(), HYBRID_SIG_LEN);
    }

    #[test]
    fn public_key_is_correct_length() {
        let (_, pk) = keygen();
        assert_eq!(pk.as_ref().len(), HYBRID_PK_LEN);
    }

    #[test]
    fn public_from_sk_matches_keygen_pk() {
        let (sk, pk) = keygen();
        let derived_pk = Sr25519MlDsa44::public(&sk);
        assert_eq!(pk.0, derived_pk.0);
    }

    // --- component-level determinism tests -----------------------------------

    #[test]
    fn sr25519_component_is_deterministic() {
        let (sk, _) = keygen();
        let msg_prime = prepare_message(VERSION, LABEL, b"msg", &[]);
        let sig1 = sr25519_sign_det(&sk.sr25519_seed, &msg_prime, b"nonce");
        let sig2 = sr25519_sign_det(&sk.sr25519_seed, &msg_prime, b"nonce");
        let b1: &[u8] = sig1.as_ref();
        let b2: &[u8] = sig2.as_ref();
        assert_eq!(b1, b2, "sr25519 component is not deterministic");
    }

    #[test]
    fn mldsa44_component_is_deterministic() {
        let (sk, _) = keygen();
        let msg_prime = prepare_message(VERSION, LABEL, b"msg", &[]);
        let rnd = [42u8; 32];
        let sig1 = mldsa44_sign_det(&sk.ml_dsa_sk, &msg_prime, &rnd);
        let sig2 = mldsa44_sign_det(&sk.ml_dsa_sk, &msg_prime, &rnd);
        assert_eq!(sig1, sig2, "ML-DSA-44 component is not deterministic");
    }
}
