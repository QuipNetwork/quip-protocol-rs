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

use crate::classical::{sr25519 as classical_sr25519, ClassicalSignatureAlgorithm, Sr25519};
use crate::fixed::{
    self, CompositePublicKey, CompositeSignature, FixedHybridComponents, FixedHybridEncoding,
    FixedPublicKey, FixedSignature,
};
use crate::pq::{mldsa44 as pq_mldsa44, FixedPqSignatureAlgorithm, MlDsa44};
use crate::suite::FixedHybridSuite;
use crate::{HybridSignatureError, HybridSignatureScheme, Result};

use rand_core::CryptoRngCore;
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

/// Length in bytes of an H3 public key.
pub const HYBRID_PK_LEN: usize = SR_PK_LEN + ML_PK_LEN; // 1344
/// Length in bytes of an H3 secret key.
pub const HYBRID_SK_LEN: usize = SR_SK_LEN + ML_SK_LEN; // 2624
/// Length in bytes of an H3 signature.
pub const HYBRID_SIG_LEN: usize = SR_SIG_LEN + ML_SIG_LEN; // 2484

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Composite public key: `sr25519_pk (32B) || ml_dsa_pk (1312B)`.
pub type PublicKey = FixedPublicKey<Sr25519MlDsa44, HYBRID_PK_LEN, SR_PK_LEN>;

/// Composite secret key. Zeroized on drop — no `Clone`.
///
/// Stores the 64-byte sr25519 secret key plus ML-DSA-44 private key bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    sr25519_secret: [u8; SR_SK_LEN],
    ml_dsa_sk: [u8; ML_SK_LEN],
}

impl SecretKey {
    /// Parses and validates a serialized H3 secret key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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

    /// Serializes the secret key into `sr25519_sk || ml_dsa_sk`.
    ///
    /// The returned buffer is wrapped in [`Zeroizing`] because it contains
    /// secret material.
    pub fn to_bytes(&self) -> Zeroizing<[u8; HYBRID_SK_LEN]> {
        let mut out = Zeroizing::new([0u8; HYBRID_SK_LEN]);
        out[..SR_SK_LEN].copy_from_slice(&self.sr25519_secret);
        out[SR_SK_LEN..].copy_from_slice(&self.ml_dsa_sk);
        out
    }
}

/// Composite signature: `sr25519_sig (64B) || ml_dsa_sig (2420B)`.
pub type Signature = FixedSignature<Sr25519MlDsa44, HYBRID_SIG_LEN, SR_SIG_LEN>;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Zero-sized type implementing [`HybridSignatureScheme`] for H3.
pub struct Sr25519MlDsa44;

impl FixedHybridSuite for Sr25519MlDsa44 {
    const LABEL: &'static [u8] = b"hybrid-sr25519-mldsa44-v1\0";
}

impl FixedHybridComponents for Sr25519MlDsa44 {
    type Classical = Sr25519;
    type Pq = MlDsa44;
}

impl FixedHybridEncoding for Sr25519MlDsa44 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    const SECRET_KEY_LEN: usize = HYBRID_SK_LEN;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey> {
        PublicKey::from_bytes(bytes)
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey> {
        SecretKey::from_bytes(bytes)
    }

    /// Builds the suite secret key from serialized component secret keys.
    fn compose_secret_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SecretKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SecretKeyBytes,
    ) -> Self::SecretKey {
        let mut sr25519_secret = [0u8; SR_SK_LEN];
        sr25519_secret.copy_from_slice(classical.as_ref());

        let mut ml_dsa_sk = [0u8; ML_SK_LEN];
        ml_dsa_sk.copy_from_slice(pq.as_ref());

        SecretKey {
            sr25519_secret,
            ml_dsa_sk,
        }
    }

    /// Splits the suite secret key into classical and PQ serialized components.
    fn split_secret_key(sk: &Self::SecretKey) -> (&[u8], &[u8]) {
        (&sk.sr25519_secret, &sk.ml_dsa_sk)
    }
}

impl HybridSignatureScheme for Sr25519MlDsa44 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn public_key_len() -> usize {
        <Self::PublicKey as CompositePublicKey>::LEN
    }

    fn secret_key_len() -> usize {
        <Self as FixedHybridEncoding>::SECRET_KEY_LEN
    }

    fn signature_max_len() -> usize {
        <Self::Signature as CompositeSignature>::LEN
    }

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey) {
        fixed::generate::<Self>(rng)
    }

    fn from_seed_slice(seed: &[u8]) -> Result<(Self::SecretKey, Self::PublicKey)> {
        fixed::from_seed_slice::<Self>(seed)
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey> {
        <Self as FixedHybridEncoding>::public_key_from_bytes(bytes)
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey> {
        <Self as FixedHybridEncoding>::secret_key_from_bytes(bytes)
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        <Self as FixedHybridEncoding>::signature_from_bytes(bytes)
    }

    fn public(sk: &Self::SecretKey) -> Self::PublicKey {
        fixed::public::<Self>(sk)
    }

    fn sign(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Self::Signature {
        fixed::sign::<Self>(sk, msg, ctx, rng)
    }

    fn sign_deterministic(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        nonce: &[u8],
    ) -> Self::Signature {
        fixed::sign_deterministic::<Self>(sk, msg, ctx, nonce)
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool {
        fixed::verify::<Self>(pk, msg, ctx, sig)
    }

    fn verify_deterministic(
        pk: &Self::PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &Self::Signature,
        _expected_nonce: &[u8],
    ) -> bool {
        Self::verify(pk, msg, ctx, sig)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::prepare_message;
    use crate::seed::MASTER_SEED_LEN;
    use crate::HybridSignatureScheme;
    use rand_core::OsRng;

    fn keygen() -> (SecretKey, PublicKey) {
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
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn deterministic_different_nonce_gives_different_sig() {
        let (sk, _) = keygen();
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce-1");
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"", b"nonce-2");
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
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
        assert_eq!(pk.to_bytes(), derived_pk.to_bytes());
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
        let sig1_bytes = sig1.to_bytes();
        let sig2_bytes = sig2.to_bytes();

        assert_ne!(&sig1_bytes[..SR_SIG_LEN], &sig2_bytes[..SR_SIG_LEN]);
        assert_eq!(&sig1_bytes[SR_SIG_LEN..], &sig2_bytes[SR_SIG_LEN..]);
    }

    #[test]
    fn context_changes_signature() {
        let (sk, _) = keygen();
        let sig1 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"ctx-a", b"nonce");
        let sig2 = Sr25519MlDsa44::sign_deterministic(&sk, b"msg", b"ctx-b", b"nonce");
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn from_seed_slice_is_deterministic() {
        let seed = [7u8; MASTER_SEED_LEN];
        let (sk1, pk1) = Sr25519MlDsa44::from_seed_slice(&seed).unwrap();
        let (sk2, pk2) = Sr25519MlDsa44::from_seed_slice(&seed).unwrap();

        let sk1_bytes = sk1.to_bytes();
        let sk2_bytes = sk2.to_bytes();

        assert_eq!(&*sk1_bytes, &*sk2_bytes);
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
        assert_eq!(pk1.to_bytes(), Sr25519MlDsa44::public(&sk1).to_bytes());
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
        let decoded = PublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn secret_key_bytes_roundtrip() {
        let (sk, pk) = keygen();
        let sk_bytes = sk.to_bytes();
        let decoded = SecretKey::from_bytes(sk_bytes.as_ref()).unwrap();
        let decoded_bytes = decoded.to_bytes();

        assert_eq!(&*sk_bytes, &*decoded_bytes);
        assert_eq!(pk.to_bytes(), Sr25519MlDsa44::public(&decoded).to_bytes());
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let (sk, _) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"msg", b"", &mut OsRng);
        let decoded = Signature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }
}
