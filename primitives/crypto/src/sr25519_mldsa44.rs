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

use crate::classical::sr25519 as classical_sr25519;
use crate::domain::prepare_message;
use crate::pq::mldsa44 as pq_mldsa44;
use crate::suite::{derive_component_seeds, FixedHybridSuite, MASTER_SEED_LEN};
use crate::{HybridSignatureError, HybridSignatureScheme};

use rand_core::CryptoRngCore;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SR_PK_LEN: usize = classical_sr25519::PUBLIC_KEY_LEN;
const SR_SK_LEN: usize = classical_sr25519::SECRET_KEY_LEN;
const SR_SIG_LEN: usize = classical_sr25519::SIGNATURE_LEN;

const ML_PK_LEN: usize = pq_mldsa44::PUBLIC_KEY_LEN;
const ML_SK_LEN: usize = pq_mldsa44::SECRET_KEY_LEN;
const ML_SIG_LEN: usize = pq_mldsa44::SIGNATURE_LEN;

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

        if !classical_sr25519::validate_public_key(sr_bytes) {
            return Err(HybridSignatureError::InvalidPublicKey);
        }
        if !pq_mldsa44::validate_public_key(ml_bytes) {
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
        if !classical_sr25519::validate_secret_key(&sr25519_secret) {
            sr25519_secret.zeroize();
            return Err(HybridSignatureError::InvalidSecretKey);
        }

        let mut ml_dsa_sk = [0u8; ML_SK_LEN];
        ml_dsa_sk.copy_from_slice(&bytes[SR_SK_LEN..]);
        if !pq_mldsa44::validate_secret_key(&ml_dsa_sk) {
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
        let mut sr25519_seed = [0u8; MASTER_SEED_LEN];
        rng.fill_bytes(&mut sr25519_seed);
        let (sr_pk_bytes, sr25519_secret) = classical_sr25519::from_seed(&sr25519_seed);
        let (ml_pk_bytes, ml_sk_bytes) = pq_mldsa44::generate(rng);

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(&sr_pk_bytes);
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

        let (sr_pk_bytes, sr25519_secret) = classical_sr25519::from_seed(&classical_seed);
        let (ml_pk_bytes, ml_sk_bytes) = pq_mldsa44::from_seed(&pq_seed);

        classical_seed.zeroize();
        pq_seed.zeroize();

        let sk = HybridSecretKey {
            sr25519_secret,
            ml_dsa_sk: ml_sk_bytes,
        };

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(&sr_pk_bytes);
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
        let sr_pk = classical_sr25519::public_key_from_secret(&sk.sr25519_secret);
        let ml_pk = pq_mldsa44::public_key_from_secret(&sk.ml_dsa_sk);

        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(&sr_pk);
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

        let sr_sig = classical_sr25519::sign(&sk.sr25519_secret, &msg_prime, rng);
        let ml_sig = pq_mldsa44::sign(&sk.ml_dsa_sk, &msg_prime, rng);

        build_signature(&sr_sig, &ml_sig)
    }

    /// Deterministic signing with a network-derived nonce.
    ///
    /// Delegates to the classical sr25519 and PQ ML-DSA-44 deterministic signers.
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
        let sr_sig = classical_sr25519::sign_deterministic(&sk.sr25519_secret, &msg_prime, nonce);
        // H3 follows the spec's ML-DSA deterministic mode: the network nonce is
        // ignored and the PQ leg is derived from the key and message only.
        let ml_sig = pq_mldsa44::sign_deterministic(&sk.ml_dsa_sk, &msg_prime);
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

fn build_signature(sr_sig: &[u8; SR_SIG_LEN], ml_sig: &[u8; ML_SIG_LEN]) -> HybridSignature {
    let mut sig = [0u8; HYBRID_SIG_LEN];
    sig[..SR_SIG_LEN].copy_from_slice(sr_sig);
    sig[SR_SIG_LEN..].copy_from_slice(ml_sig);
    HybridSignature(sig)
}

/// Verify both components against `msg_prime`. Both must pass.
fn verify_internal(pk: &HybridPublicKey, msg_prime: &[u8], sig: &HybridSignature) -> bool {
    let sr_pk_bytes: &[u8; SR_PK_LEN] = pk.0[..SR_PK_LEN].try_into().expect("pk is 1344 bytes");
    let ml_pk_bytes: &[u8; ML_PK_LEN] = pk.0[SR_PK_LEN..]
        .try_into()
        .expect("ml_pk slice is 1312 bytes");

    let sr_sig_bytes: &[u8; SR_SIG_LEN] =
        sig.0[..SR_SIG_LEN].try_into().expect("sig is 2484 bytes");
    let ml_sig_bytes: &[u8; ML_SIG_LEN] = sig.0[SR_SIG_LEN..]
        .try_into()
        .expect("ml_sig slice is 2420 bytes");

    // Check both legs before returning — do not short-circuit on sr_ok
    let sr_ok = classical_sr25519::verify(sr_pk_bytes, msg_prime, sr_sig_bytes);
    let ml_ok = pq_mldsa44::verify(ml_pk_bytes, msg_prime, ml_sig_bytes);

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
        let sig1 = classical_sr25519::sign_deterministic(&sk.sr25519_secret, &msg_prime, b"nonce");
        let sig2 = classical_sr25519::sign_deterministic(&sk.sr25519_secret, &msg_prime, b"nonce");
        assert_eq!(sig1, sig2, "sr25519 component is not deterministic");
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
        let sig1 = pq_mldsa44::sign_deterministic(&sk.ml_dsa_sk, &msg_prime);
        let sig2 = pq_mldsa44::sign_deterministic(&sk.ml_dsa_sk, &msg_prime);
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
