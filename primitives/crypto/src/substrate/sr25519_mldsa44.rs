//! Substrate-facing wrapper for the H3 `sr25519 + ML-DSA-44` suite.
//!
//! This module exposes `sp_core`-style `Public`, `Signature`, and `Pair`
//! types so the H3 suite can later be wrapped with
//! `sp_application_crypto::app_crypto!`.
//!
//! Scope of this first phase:
//! - stable Substrate-compatible public key and signature types
//! - a `Pair` backed by the suite's 32-byte master seed
//! - proof that `app_crypto!` can wrap the module
//!
//! Intentional omissions:
//! - no keystore / `RuntimePublic` integration yet
//! - no BABE-specific VRF types here yet

use alloc::vec::Vec;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::crypto::{
    CryptoType, CryptoTypeId, Derive, DeriveError, DeriveJunction, PublicBytes, SecretStringError,
    SignatureBytes,
};
use sp_core::proof_of_possession::NonAggregatable;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::seed::MASTER_SEED_LEN;
use crate::suite::sr25519_mldsa44::{
    PublicKey as HybridPublicKey, SecretKey as HybridSecretKey, Signature as HybridSignature,
    Sr25519MlDsa44, HYBRID_PK_LEN, HYBRID_SIG_LEN,
};
use crate::HybridSignatureScheme;

/// Unique identifier for the H3 hybrid crypto scheme.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"h344");

#[doc(hidden)]
pub struct HybridPublicTag;
#[doc(hidden)]
pub struct HybridSignatureTag;

type InnerPublic = PublicBytes<HYBRID_PK_LEN, HybridPublicTag>;
type InnerSignature = SignatureBytes<HYBRID_SIG_LEN, HybridSignatureTag>;

/// Substrate-style encoded H3 public key.
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    DecodeWithMemTracking,
    MaxEncodedLen,
    TypeInfo,
)]
pub struct Public(InnerPublic);

impl CryptoType for Public {
    type Pair = Pair;
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Public {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl sp_core::crypto::ByteArray for Public {
    const LEN: usize = <InnerPublic as sp_core::crypto::ByteArray>::LEN;
}

impl Derive for Public {}
impl sp_core::crypto::Public for Public {}

impl core::fmt::Debug for Public {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Public").field(&self.as_ref()).finish()
    }
}

impl<'a> TryFrom<&'a [u8]> for Public {
    type Error = ();

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        InnerPublic::try_from(data).map(Self)
    }
}

impl From<HybridPublicKey> for Public {
    fn from(public: HybridPublicKey) -> Self {
        Self(InnerPublic::from(public.to_bytes()))
    }
}

impl TryFrom<Public> for HybridPublicKey {
    type Error = ();

    fn try_from(public: Public) -> Result<Self, Self::Error> {
        HybridPublicKey::from_bytes(public.as_ref()).map_err(|_| ())
    }
}

/// Substrate-style encoded H3 signature.
#[derive(Clone, Eq, PartialEq, Hash, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct Signature(InnerSignature);

impl CryptoType for Signature {
    type Pair = Pair;
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl sp_core::crypto::ByteArray for Signature {
    const LEN: usize = <InnerSignature as sp_core::crypto::ByteArray>::LEN;
}

impl sp_core::crypto::Signature for Signature {}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Signature").field(&self.as_ref()).finish()
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = ();

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        InnerSignature::try_from(data).map(Self)
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = ();

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&data[..])
    }
}

impl From<HybridSignature> for Signature {
    fn from(signature: HybridSignature) -> Self {
        Self(InnerSignature::from(signature.to_bytes()))
    }
}

impl TryFrom<Signature> for HybridSignature {
    type Error = ();

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        HybridSignature::from_bytes(signature.as_ref()).map_err(|_| ())
    }
}

/// Proof of possession is the same as a normal signature for this
/// non-aggregatable scheme.
pub type ProofOfPossession = Signature;

/// Hybrid keypair backed by the 32-byte suite master seed.
///
/// The pair stores only the master seed and a cached public key. The expanded
/// suite secret key is reconstructed on demand for signing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Pair {
    seed: [u8; MASTER_SEED_LEN],
    #[zeroize(skip)]
    public: Public,
}

impl CryptoType for Pair {
    type Pair = Self;
}

impl NonAggregatable for Pair {}

impl Pair {
    fn from_master_seed(seed: [u8; MASTER_SEED_LEN]) -> Result<Self, SecretStringError> {
        let (_secret, public) =
            Sr25519MlDsa44::from_seed_slice(&seed).map_err(|_| SecretStringError::InvalidSeed)?;

        Ok(Self {
            seed,
            public: public.into(),
        })
    }

    fn expanded_secret(&self) -> HybridSecretKey {
        Sr25519MlDsa44::from_seed_slice(&self.seed)
            .expect("pair seed is validated on construction; qed")
            .0
    }
}

impl sp_core::crypto::Pair for Pair {
    type Public = Public;
    type Seed = [u8; MASTER_SEED_LEN];
    type Signature = Signature;
    type ProofOfPossession = ProofOfPossession;

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        seed: Option<Self::Seed>,
    ) -> Result<(Self, Option<Self::Seed>), DeriveError> {
        let base_seed = seed.unwrap_or(self.seed);
        let sr25519_pair = sp_core::sr25519::Pair::from_seed(&base_seed);
        let (_derived_pair, derived_seed) = sr25519_pair.derive(path, Some(base_seed))?;
        let derived_seed = derived_seed.ok_or(DeriveError::SoftKeyInPath)?;
        let pair = Self::from_master_seed(derived_seed).map_err(|_| DeriveError::SoftKeyInPath)?;
        Ok((pair, Some(derived_seed)))
    }

    fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError> {
        if seed.len() != MASTER_SEED_LEN {
            return Err(SecretStringError::InvalidSeedLength);
        }

        let mut owned_seed = [0u8; MASTER_SEED_LEN];
        owned_seed.copy_from_slice(seed);
        Self::from_master_seed(owned_seed)
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let secret = self.expanded_secret();
        Sr25519MlDsa44::sign_deterministic(&secret, message, b"", b"").into()
    }

    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool {
        let Ok(public) = HybridPublicKey::from_bytes(pubkey.as_ref()) else {
            return false;
        };
        let Ok(signature) = HybridSignature::from_bytes(sig.as_ref()) else {
            return false;
        };

        Sr25519MlDsa44::verify(&public, message.as_ref(), b"", &signature)
    }

    fn public(&self) -> Self::Public {
        self.public.clone()
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::sr25519_mldsa44::Sr25519MlDsa44;

    use sp_core::crypto::Pair as _;

    mod app {
        use crate::substrate::sr25519_mldsa44 as hybrid;
        use sp_application_crypto::{app_crypto, key_types::BABE};

        app_crypto!(hybrid, BABE);
    }

    #[test]
    fn public_and_signature_roundtrip_to_suite_types() {
        let seed = [7u8; MASTER_SEED_LEN];
        let (secret, public) = Sr25519MlDsa44::from_seed_slice(&seed).unwrap();
        let signature = Sr25519MlDsa44::sign_deterministic(&secret, b"hello", b"", b"");

        let wrapped_public: Public = public.clone().into();
        let wrapped_signature: Signature = signature.clone().into();

        let decoded_public = HybridPublicKey::try_from(wrapped_public).unwrap();
        let decoded_signature = HybridSignature::try_from(wrapped_signature).unwrap();

        assert_eq!(decoded_public.as_ref(), public.as_ref());
        assert_eq!(decoded_signature.as_ref(), signature.as_ref());
    }

    #[test]
    fn pair_sign_and_verify_matches_suite_verification() {
        let seed = [9u8; MASTER_SEED_LEN];
        let pair = Pair::from_seed(&seed);
        let signature = pair.sign(b"hello babe");

        assert!(Pair::verify(&signature, b"hello babe", &pair.public()));
        assert!(!Pair::verify(&signature, b"wrong", &pair.public()));
    }

    #[test]
    fn app_crypto_can_wrap_the_hybrid_types() {
        let seed = [11u8; MASTER_SEED_LEN];
        let pair = Pair::from_seed(&seed);
        let signature: app::Signature = pair.sign(b"quip").into();
        let public: app::Public = pair.public().into();

        assert!(app::Pair::verify(&signature, b"quip", &public));
    }

    #[test]
    fn hard_suri_derivation_is_supported() {
        let pair = Pair::from_string("//Alice", None).unwrap();
        let pair_again = Pair::from_string("//Alice", None).unwrap();

        assert_eq!(pair.public().as_ref(), pair_again.public().as_ref());
    }
}
