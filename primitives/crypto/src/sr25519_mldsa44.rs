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
use crate::fixed::FixedHybridEncoding;
use crate::pq::{mldsa44 as pq_mldsa44, FixedPqSignatureAlgorithm, MlDsa44};
use crate::suite::FixedHybridSuite;
use crate::HybridSignatureError;

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
pub struct PublicKey([u8; HYBRID_PK_LEN]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PublicKey {
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
pub struct SecretKey {
    sr25519_secret: [u8; SR_SK_LEN],
    ml_dsa_sk: [u8; ML_SK_LEN],
}

impl SecretKey {
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
pub struct Signature([u8; HYBRID_SIG_LEN]);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
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

impl FixedHybridEncoding for Sr25519MlDsa44 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;
    type Classical = Sr25519;
    type Pq = MlDsa44;

    const PUBLIC_KEY_LEN: usize = HYBRID_PK_LEN;
    const SECRET_KEY_LEN: usize = HYBRID_SK_LEN;
    const SIGNATURE_LEN: usize = HYBRID_SIG_LEN;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, HybridSignatureError> {
        PublicKey::from_bytes(bytes)
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey, HybridSignatureError> {
        SecretKey::from_bytes(bytes)
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, HybridSignatureError> {
        Signature::from_bytes(bytes)
    }

    fn compose_public_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::PublicKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::PublicKeyBytes,
    ) -> Self::PublicKey {
        let mut pk_bytes = [0u8; HYBRID_PK_LEN];
        pk_bytes[..SR_PK_LEN].copy_from_slice(classical.as_ref());
        pk_bytes[SR_PK_LEN..].copy_from_slice(pq.as_ref());
        PublicKey(pk_bytes)
    }

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

    fn compose_signature(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SignatureBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SignatureBytes,
    ) -> Self::Signature {
        let mut sig = [0u8; HYBRID_SIG_LEN];
        sig[..SR_SIG_LEN].copy_from_slice(classical.as_ref());
        sig[SR_SIG_LEN..].copy_from_slice(pq.as_ref());
        Signature(sig)
    }

    fn split_public_key(pk: &Self::PublicKey) -> (&[u8], &[u8]) {
        (&pk.0[..SR_PK_LEN], &pk.0[SR_PK_LEN..])
    }

    fn split_secret_key(sk: &Self::SecretKey) -> (&[u8], &[u8]) {
        (&sk.sr25519_secret, &sk.ml_dsa_sk)
    }

    fn split_signature(sig: &Self::Signature) -> (&[u8], &[u8]) {
        (&sig.0[..SR_SIG_LEN], &sig.0[SR_SIG_LEN..])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::prepare_message;
    use crate::suite::MASTER_SEED_LEN;
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
        let decoded = PublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk.0, decoded.0);
    }

    #[test]
    fn secret_key_bytes_roundtrip() {
        let (sk, pk) = keygen();
        let sk_bytes = sk.to_bytes();
        let decoded = SecretKey::from_bytes(sk_bytes.as_ref()).unwrap();
        let decoded_bytes = decoded.to_bytes();

        assert_eq!(&*sk_bytes, &*decoded_bytes);
        assert_eq!(pk.0, Sr25519MlDsa44::public(&decoded).0);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let (sk, _) = keygen();
        let sig = Sr25519MlDsa44::sign(&sk, b"msg", b"", &mut OsRng);
        let decoded = Signature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig.0, decoded.0);
    }
}
