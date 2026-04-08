//! Substrate-facing wrapper for the H1 `ed25519 + ML-DSA-44` suite.
//!
//! Unlike the H3 wrapper used for BABE, this module only needs the shared
//! Substrate/app-crypto signature surface:
//! - `Public`
//! - `Signature`
//! - `Pair`
//! - proof of possession
//!
//! GRANDPA does not need VRF support, so this module is intentionally thin and
//! reuses the generic wrapper core in [`crate::substrate::signature`].

use sp_core::crypto::{CryptoTypeId, DeriveError, DeriveJunction};
use sp_core::ed25519;
use sp_core::Pair as _;

use crate::seed::MASTER_SEED_LEN;
use crate::substrate::signature::{
    Pair as SignaturePair, Public as SignaturePublic, Signature as SignatureWrapper,
    SubstrateSignatureScheme,
};
use crate::suite::ed25519_mldsa44::{Ed25519MlDsa44, HYBRID_PK_LEN, HYBRID_SIG_LEN};

/// Unique identifier for the H1 hybrid crypto scheme.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"h144");

/// Shared Substrate-signature wrapper marker for H1.
#[doc(hidden)]
pub struct SubstrateH1;

impl SubstrateSignatureScheme for SubstrateH1 {
    type Suite = Ed25519MlDsa44;
    const CRYPTO_ID: CryptoTypeId = CRYPTO_ID;

    fn derive_seed<Iter: Iterator<Item = DeriveJunction>>(
        seed: [u8; MASTER_SEED_LEN],
        path: Iter,
    ) -> Result<[u8; MASTER_SEED_LEN], DeriveError> {
        let ed25519_pair = ed25519::Pair::from_seed(&seed);
        let (_derived_pair, derived_seed) = ed25519_pair.derive(path, Some(seed))?;
        derived_seed.ok_or(DeriveError::SoftKeyInPath)
    }
}

/// Substrate-style encoded H1 public key.
pub type Public = SignaturePublic<SubstrateH1, HYBRID_PK_LEN, HYBRID_SIG_LEN>;

/// Substrate-style encoded H1 signature.
pub type Signature = SignatureWrapper<SubstrateH1, HYBRID_PK_LEN, HYBRID_SIG_LEN>;

/// Proof of possession is the same as a normal signature for this
/// non-aggregatable scheme.
pub type ProofOfPossession = Signature;

/// Hybrid keypair backed by the 32-byte suite master seed.
pub type Pair = SignaturePair<SubstrateH1, HYBRID_PK_LEN, HYBRID_SIG_LEN>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::ed25519_mldsa44::Ed25519MlDsa44;
    use crate::HybridSignatureScheme;

    mod app {
        use crate::substrate::ed25519_mldsa44 as hybrid;
        use sp_application_crypto::{app_crypto, key_types::GRANDPA};

        app_crypto!(hybrid, GRANDPA);
    }

    #[test]
    fn public_and_signature_roundtrip_to_suite_types() {
        let seed = [5u8; MASTER_SEED_LEN];
        let (secret, public) = Ed25519MlDsa44::from_seed_slice(&seed).unwrap();
        let signature = Ed25519MlDsa44::sign_deterministic(&secret, b"hello", b"", b"");

        let wrapped_public = Public::from_suite_public(public.clone());
        let wrapped_signature = Signature::from_suite_signature(signature.clone());

        let decoded_public = wrapped_public.to_suite_public().unwrap();
        let decoded_signature = wrapped_signature.to_suite_signature().unwrap();

        assert_eq!(decoded_public.as_ref(), public.as_ref());
        assert_eq!(decoded_signature.as_ref(), signature.as_ref());
    }

    #[test]
    fn pair_sign_and_verify_matches_suite_verification() {
        let seed = [9u8; MASTER_SEED_LEN];
        let pair = Pair::from_seed(&seed);
        let signature = pair.sign(b"hello grandpa");

        assert!(Pair::verify(&signature, b"hello grandpa", &pair.public()));
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
