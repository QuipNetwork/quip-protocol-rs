//! H3: sr25519 + ML-DSA-44 hybrid signature scheme.
//!
//! Composite sizes:
//!   Public key : 32  (sr25519)  + 1312 (ML-DSA-44) = 1344 bytes
//!   Secret key : 64  (sr25519)  + 2560 (ML-DSA-44) = 2624 bytes
//!   Signature  : 64  (sr25519)  + 2420 (ML-DSA-44) = 2484 bytes (fixed)
//!
//! Signature byte layout:
//!   [0  .. 64)   sr25519 signature
//!   [64 .. 2484) ML-DSA-44 signature
//!
//! Domain label: `hybrid-sr25519-mldsa44-v1`

use crate::domain::prepare_message;
use crate::suite::{derive_component_seeds, FixedHybridSuite, MASTER_SEED_LEN};
use crate::{HybridSignatureError, HybridSignatureScheme};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier as _};
use rand_core::CryptoRngCore;
use sp_core::{sr25519, Pair};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SR_PK_LEN: usize = 32;
const SR_SK_LEN: usize = 64;
const SR_SIG_LEN: usize = 64;

const ML_PK_LEN: usize = 1312;
const ML_SK_LEN: usize = 2560;
const ML_SIG_LEN: usize = 2420;

pub const HYBRID_PK_LEN: usize = SR_PK_LEN + ML_PK_LEN; // 1344
pub const HYBRID_SK_LEN: usize = SR_SK_LEN + ML_SK_LEN; // 2624
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

impl HybridPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignatureError> {
        if bytes.len() != HYBRID_PK_LEN {
            return Err(HybridSignatureError::InvalidLength {
                expected: HYBRID_PK_LEN,
                actual: bytes.len(),
            });
        }

        let mut out = [0u8; HYBRID_PK_LEN];
        out.copy_from_slice(bytes);

        let sr_bytes: &[u8; SR_PK_LEN] = out[..SR_PK_LEN].try_into().expect("sr25519 pk length");
        let ml_bytes: &[u8; ML_PK_LEN] = out[SR_PK_LEN..].try_into().expect("ML-DSA pk length");

        if schnorrkel::PublicKey::from_bytes(sr_bytes).is_err() {
            return Err(HybridSignatureError::InvalidPublicKey);
        }
        if ml_dsa_44::PublicKey::try_from_bytes(*ml_bytes).is_err() {
            return Err(HybridSignatureError::InvalidPublicKey);
        }

        Ok(Self(out))
    }

    pub fn to_bytes(&self) -> [u8; HYBRID_PK_LEN] {
        self.0
    }
}

/// Composite secret key. Zeroized on drop — no `Clone`.
///
/// Stores the 64-byte sr25519 secret key plus ML-DSA-44 private key bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    sr25519_secret: [u8; SR_SK_LEN],
    ml_dsa_sk: [u8; ML_SK_LEN],
}

impl HybridSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignatureError> {
        if bytes.len() != HYBRID_SK_LEN {
            return Err(HybridSignatureError::InvalidLength {
                expected: HYBRID_SK_LEN,
                actual: bytes.len(),
            });
        }

        let mut sr25519_secret = [0u8; SR_SK_LEN];
        sr25519_secret.copy_from_slice(&bytes[..SR_SK_LEN]);
        if sr25519::Pair::from_seed_slice(&sr25519_secret).is_err() {
            sr25519_secret.zeroize();
            return Err(HybridSignatureError::InvalidSecretKey);
        }

        let mut ml_dsa_sk = [0u8; ML_SK_LEN];
        ml_dsa_sk.copy_from_slice(&bytes[SR_SK_LEN..]);
        if ml_dsa_44::PrivateKey::try_from_bytes(ml_dsa_sk).is_err() {
            sr25519_secret.zeroize();
            ml_dsa_sk.zeroize();
            return Err(HybridSignatureError::InvalidSecretKey);
        }

        Ok(Self {
            sr25519_secret,
            ml_dsa_sk,
        })
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; HYBRID_SK_LEN]> {
        let mut out = Zeroizing::new([0u8; HYBRID_SK_LEN]);
        out[..SR_SK_LEN].copy_from_slice(&self.sr25519_secret);
        out[SR_SK_LEN..].copy_from_slice(&self.ml_dsa_sk);
        out
    }
}

/// Composite signature: `sr25519_sig (64B) || ml_dsa_sig (2420B)`.
#[derive(Clone)]
pub struct HybridSignature([u8; HYBRID_SIG_LEN]);

impl AsRef<[u8]> for HybridSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl HybridSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignatureError> {
        if bytes.len() != HYBRID_SIG_LEN {
            return Err(HybridSignatureError::InvalidLength {
                expected: HYBRID_SIG_LEN,
                actual: bytes.len(),
            });
        }

        let mut out = [0u8; HYBRID_SIG_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub fn to_bytes(&self) -> [u8; HYBRID_SIG_LEN] {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Zero-sized type implementing [`HybridSignatureScheme`] for H3.
pub struct Sr25519MlDsa44;

impl FixedHybridSuite for Sr25519MlDsa44 {
    const LABEL: &'static [u8] = b"hybrid-sr25519-mldsa44-v1\0";
}

impl HybridSignatureScheme for Sr25519MlDsa44 {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type Signature = HybridSignature;

    fn public_key_len() -> usize {
        HYBRID_PK_LEN
    }

    fn secret_key_len() -> usize {
        HYBRID_SK_LEN
    }

    fn signature_max_len() -> usize {
        HYBRID_SIG_LEN
    }

    /// Generate a fresh hybrid key pair from the provided RNG.
    fn generate(rng: &mut impl CryptoRngCore) -> (HybridSecretKey, HybridPublicKey) {
        // sr25519: seed from RNG for no_std compatibility
        let mut sr25519_seed = [0u8; MASTER_SEED_LEN];
        rng.fill_bytes(&mut sr25519_seed);
        let sr_pair = sr25519::Pair::from_seed_slice(&sr25519_seed)
            .expect("32-byte seed is always valid for sr25519");
        let sr25519_secret: [u8; SR_SK_LEN] = sr_pair
            .to_raw_vec()
            .try_into()
            .expect("sp_core sr25519 secret key is always 64 bytes");

        // ML-DSA-44
        let (ml_pk, ml_sk) =
            ml_dsa_44::KG::try_keygen_with_rng(rng).expect("ML-DSA-44 keygen failed");

        let ml_pk_bytes = ml_pk.into_bytes();
        let ml_sk_bytes = ml_sk.into_bytes();

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(sr_pair.public().as_array_ref());
        pk_bytes[SR_PK_LEN..].copy_from_slice(&ml_pk_bytes);

        let sk = HybridSecretKey {
            sr25519_secret,
            ml_dsa_sk: ml_sk_bytes,
        };

        (sk, HybridPublicKey(pk_bytes))
    }

    fn from_seed_slice(
        seed: &[u8],
    ) -> Result<(HybridSecretKey, HybridPublicKey), HybridSignatureError> {
        let mut classical_seed = [0u8; MASTER_SEED_LEN];
        let mut pq_seed = [0u8; MASTER_SEED_LEN];
        derive_component_seeds(seed, &mut classical_seed, &mut pq_seed)?;

        let sr_pair = sr25519::Pair::from_seed_slice(&classical_seed)
            .expect("HKDF yields valid sr25519 seed");
        let sr25519_secret: [u8; SR_SK_LEN] = sr_pair
            .to_raw_vec()
            .try_into()
            .expect("sp_core sr25519 secret key is always 64 bytes");

        let (ml_pk, ml_sk) = ml_dsa_44::KG::keygen_from_seed(&pq_seed);
        let ml_pk_bytes = ml_pk.into_bytes();
        let ml_sk_bytes = ml_sk.into_bytes();

        classical_seed.zeroize();
        pq_seed.zeroize();

        let sk = HybridSecretKey {
            sr25519_secret,
            ml_dsa_sk: ml_sk_bytes,
        };

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(sr_pair.public().as_array_ref());
        pk_bytes[SR_PK_LEN..].copy_from_slice(&ml_pk_bytes);

        Ok((sk, HybridPublicKey(pk_bytes)))
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<HybridPublicKey, HybridSignatureError> {
        HybridPublicKey::from_bytes(bytes)
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<HybridSecretKey, HybridSignatureError> {
        HybridSecretKey::from_bytes(bytes)
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<HybridSignature, HybridSignatureError> {
        HybridSignature::from_bytes(bytes)
    }

    fn public(sk: &HybridSecretKey) -> HybridPublicKey {
        let sr_pair = sr25519::Pair::from_seed_slice(&sk.sr25519_secret)
            .expect("stored sr25519 secret key is valid");
        let ml_sk = ml_dsa_44::PrivateKey::try_from_bytes(sk.ml_dsa_sk)
            .expect("stored ML-DSA-44 key is valid");
        let ml_pk = ml_sk.get_public_key().into_bytes();

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(sr_pair.public().as_array_ref());
        pk_bytes[SR_PK_LEN..].copy_from_slice(&ml_pk);

        HybridPublicKey(pk_bytes)
    }

    /// Hedged signing.
    ///
    /// sr25519: injects the caller-provided RNG into schnorrkel's signing
    /// transcript to avoid relying on OS randomness. ML-DSA-44:
    /// `try_sign_with_rng` adds fresh randomness for hedged security.
    ///
    /// Both components sign `M' = VERSION || LABEL || ctx || msg`.
    fn sign(
        sk: &HybridSecretKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> HybridSignature {
        let msg_prime = prepare_message(
            <Self as FixedHybridSuite>::VERSION,
            <Self as FixedHybridSuite>::LABEL,
            msg,
            ctx,
        );

        let sr_sig = sr25519_sign_hedged(&sk.sr25519_secret, &msg_prime, rng);

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
    fn sign_deterministic(
        sk: &HybridSecretKey,
        msg: &[u8],
        ctx: &[u8],
        nonce: &[u8],
    ) -> HybridSignature {
        let msg_prime = prepare_message(
            <Self as FixedHybridSuite>::VERSION,
            <Self as FixedHybridSuite>::LABEL,
            msg,
            ctx,
        );
        let sr_sig = sr25519_sign_det(&sk.sr25519_secret, &msg_prime, nonce);
        // H3 follows the spec's ML-DSA deterministic mode: the network nonce is
        // ignored and the PQ leg is derived from the key and message only.
        let ml_sig = mldsa44_sign_det(&sk.ml_dsa_sk, &msg_prime);
        build_signature(&sr_sig, &ml_sig)
    }

    /// Standard verification. Works for signatures from both `sign` and
    /// `sign_deterministic`. Both components must pass.
    fn verify(pk: &HybridPublicKey, msg: &[u8], ctx: &[u8], sig: &HybridSignature) -> bool {
        let msg_prime = prepare_message(
            <Self as FixedHybridSuite>::VERSION,
            <Self as FixedHybridSuite>::LABEL,
            msg,
            ctx,
        );
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
        ctx: &[u8],
        sig: &HybridSignature,
        _expected_nonce: &[u8],
    ) -> bool {
        let msg_prime = prepare_message(
            <Self as FixedHybridSuite>::VERSION,
            <Self as FixedHybridSuite>::LABEL,
            msg,
            ctx,
        );
        verify_internal(pk, &msg_prime, sig)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Counter-mode Blake2-256 PRNG used to drive `attach_rng` in
/// `sign_deterministic`.  Seeded from `H(sk || nonce || msg')`.
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

fn sr25519_keypair_from_secret(secret: &[u8; SR_SK_LEN]) -> schnorrkel::Keypair {
    schnorrkel::SecretKey::from_bytes(secret)
        .expect("valid sr25519 secret key")
        .to_keypair()
}

// Signing context for `schnorrkel::context::attach_rng` to mainaint the compatibility with substrate
// wrapper in sp_core.
const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";

fn sr25519_sign_hedged(
    secret: &[u8; SR_SK_LEN],
    msg_prime: &[u8],
    rng: &mut impl CryptoRngCore,
) -> sr25519::Signature {
    let keypair = sr25519_keypair_from_secret(secret);
    let t = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(SUBSTRATE_SIGNING_CONTEXT).bytes(msg_prime),
        rng,
    );
    sr25519::Signature::from_raw(keypair.sign(t).to_bytes())
}

/// sr25519 deterministic signing helper.
///
/// Derives Schnorr nonce `r` from `H(sk || nonce || msg_prime)` by seeding
/// `Blake2Rng` and feeding it to `schnorrkel::context::attach_rng`.  This
/// replaces schnorrkel's default `getrandom` call so the output is fully
/// determined by `(sk, nonce, msg_prime)`.
fn sr25519_sign_det(
    secret: &[u8; SR_SK_LEN],
    msg_prime: &[u8],
    nonce: &[u8],
) -> sr25519::Signature {
    let rng_seed = blake2_256_secret_parts(&[secret.as_ref(), nonce, msg_prime]);
    let keypair = sr25519_keypair_from_secret(secret);
    let mut det_rng = Blake2Rng::new(rng_seed);
    let t = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(SUBSTRATE_SIGNING_CONTEXT).bytes(msg_prime),
        &mut det_rng,
    );
    sr25519::Signature::from_raw(keypair.sign(t).to_bytes())
}

/// ML-DSA-44 deterministic signing helper.
///
/// Uses `try_sign_with_seed` with the all-zero seed from the FIPS 204
/// deterministic variant, so the output depends only on `(ml_dsa_sk,
/// msg_prime)` and not on the external network nonce.
fn mldsa44_sign_det(ml_dsa_sk: &[u8; ML_SK_LEN], msg_prime: &[u8]) -> [u8; ML_SIG_LEN] {
    let ml_sk =
        ml_dsa_44::PrivateKey::try_from_bytes(*ml_dsa_sk).expect("stored ML-DSA-44 key is valid");
    // Note that the context is always empty as it's already included in `msg_prime`.
    ml_sk
        .try_sign_with_seed(&[0u8; 32], msg_prime, b"")
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
        let sig = Sr25519MlDsa44::sign(&sk, b"hello quip", b"", &mut OsRng);
        assert!(Sr25519MlDsa44::verify(&pk, b"hello quip", b"", &sig));
    }

    #[test]
    fn deterministic_sign_verify_roundtrip() {
        let (sk, pk) = keygen();
        let nonce = b"H(state_root||block||msg)";
        let sig = Sr25519MlDsa44::sign_deterministic(&sk, b"hello quip", b"", nonce);
        assert!(Sr25519MlDsa44::verify(&pk, b"hello quip", b"", &sig));
    }

    #[test]
    fn deterministic_is_deterministic() {
        let (sk, _) = keygen();
        let nonce = b"same-nonce";
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", nonce);
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", nonce);
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn deterministic_different_nonce_gives_different_sig() {
        let (sk, _) = keygen();
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce-1");
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce-2");
        assert_ne!(sig1.0, sig2.0);
    }

    #[test]
    fn verify_accepts_hedged_and_deterministic() {
        let (sk, pk) = keygen();
        let hedged = Sr25519MlDsa44::sign(&sk, b"msg", b"", &mut OsRng);
        let det = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce");
        assert!(Sr25519MlDsa44::verify(&pk, b"msg", b"", &hedged));
        assert!(Sr25519MlDsa44::verify(&pk, b"msg", b"", &det));
    }

    #[test]
    fn verify_deterministic_is_equivalent_to_verify() {
        // For ML-DSA-44 hybrids verify_deterministic == verify (no nonce in signature).
        let (sk, pk) = keygen();
        let sig = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce");
        assert!(Sr25519MlDsa44::verify_deterministic(
            &pk,
            b"msg",
            b"",
            &sig,
            b"any-nonce"
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = keygen();
        let (_, wrong_pk) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"hello", b"", &mut OsRng);
        assert!(!Sr25519MlDsa44::verify(&wrong_pk, b"hello", b"", &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let (sk, pk) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"hello", b"", &mut OsRng);
        assert!(!Sr25519MlDsa44::verify(&pk, b"world", b"", &sig));
    }

    #[test]
    fn wrong_context_fails() {
        let (sk, pk) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"hello", b"ctx-a", &mut OsRng);
        assert!(!Sr25519MlDsa44::verify(&pk, b"hello", b"ctx-b", &sig));
    }

    #[test]
    fn signature_is_correct_length() {
        let (sk, _) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"test", b"", &mut OsRng);
        assert_eq!(sig.as_ref().len(), HYBRID_SIG_LEN);
        assert_eq!(Sr25519MlDsa44::signature_max_len(), HYBRID_SIG_LEN);
    }

    #[test]
    fn public_key_is_correct_length() {
        let (_, pk) = keygen();
        assert_eq!(pk.as_ref().len(), HYBRID_PK_LEN);
        assert_eq!(Sr25519MlDsa44::public_key_len(), HYBRID_PK_LEN);
    }

    #[test]
    fn secret_key_is_correct_length() {
        let (sk, _) = keygen();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_SK_LEN);
        assert_eq!(Sr25519MlDsa44::secret_key_len(), HYBRID_SK_LEN);
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
        let msg_prime = prepare_message(
            <Sr25519MlDsa44 as FixedHybridSuite>::VERSION,
            <Sr25519MlDsa44 as FixedHybridSuite>::LABEL,
            b"msg",
            &[],
        );
        let sig1 = sr25519_sign_det(&sk.sr25519_secret, &msg_prime, b"nonce");
        let sig2 = sr25519_sign_det(&sk.sr25519_secret, &msg_prime, b"nonce");
        let b1: &[u8] = sig1.as_ref();
        let b2: &[u8] = sig2.as_ref();
        assert_eq!(b1, b2, "sr25519 component is not deterministic");
    }

    #[test]
    fn mldsa44_component_is_deterministic() {
        let (sk, _) = keygen();
        let msg_prime = prepare_message(
            <Sr25519MlDsa44 as FixedHybridSuite>::VERSION,
            <Sr25519MlDsa44 as FixedHybridSuite>::LABEL,
            b"msg",
            &[],
        );
        let sig1 = mldsa44_sign_det(&sk.ml_dsa_sk, &msg_prime);
        let sig2 = mldsa44_sign_det(&sk.ml_dsa_sk, &msg_prime);
        assert_eq!(sig1, sig2, "ML-DSA-44 component is not deterministic");
    }

    #[test]
    fn deterministic_nonce_only_changes_sr25519_component() {
        let (sk, _) = keygen();
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce-1");
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce-2");

        assert_ne!(&sig1.0[..SR_SIG_LEN], &sig2.0[..SR_SIG_LEN]);
        assert_eq!(&sig1.0[SR_SIG_LEN..], &sig2.0[SR_SIG_LEN..]);
    }

    #[test]
    fn context_changes_signature() {
        let (sk, _) = keygen();
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"ctx-a", b"nonce");
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"ctx-b", b"nonce");
        assert_ne!(sig1.0, sig2.0);
    }

    #[test]
    fn from_seed_slice_is_deterministic() {
        let seed = [7u8; MASTER_SEED_LEN];
        let (sk1, pk1) = Sr25519MlDsa44::from_seed_slice(&seed).unwrap();
        let (sk2, pk2) = Sr25519MlDsa44::from_seed_slice(&seed).unwrap();

        let sk1_bytes = sk1.to_bytes();
        let sk2_bytes = sk2.to_bytes();

        assert_eq!(&*sk1_bytes, &*sk2_bytes);
        assert_eq!(pk1.0, pk2.0);
        assert_eq!(pk1.0, Sr25519MlDsa44::public(&sk1).0);
    }

    #[test]
    fn from_seed_slice_rejects_wrong_length() {
        assert!(matches!(
            Sr25519MlDsa44::from_seed_slice(b"too-short"),
            Err(HybridSignatureError::InvalidSeedLength {
                expected: MASTER_SEED_LEN,
                actual,
            }) if actual == b"too-short".len()
        ));
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let (_, pk) = keygen();
        let decoded = HybridPublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk.0, decoded.0);
    }

    #[test]
    fn secret_key_bytes_roundtrip() {
        let (sk, pk) = keygen();
        let sk_bytes = sk.to_bytes();
        let decoded = HybridSecretKey::from_bytes(sk_bytes.as_ref()).unwrap();
        let decoded_bytes = decoded.to_bytes();

        assert_eq!(&*sk_bytes, &*decoded_bytes);
        assert_eq!(pk.0, Sr25519MlDsa44::public(&decoded).0);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let (sk, _) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"msg", b"", &mut OsRng);
        let decoded = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig.0, decoded.0);
    }
}
