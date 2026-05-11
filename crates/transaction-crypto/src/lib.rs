#![cfg_attr(not(feature = "std"), no_std)]

//! Transaction/account identity glue for Quip's hybrid runtime signer.
//!
//! This crate is intentionally small and policy-focused:
//! - it fixes the transaction signing scheme to H3 (`sr25519 + ML-DSA-44`)
//! - it derives compact 32-byte account ids from the hybrid public key
//! - it defines the transaction signature envelope that carries both:
//!   - the hybrid public key
//!   - the hybrid signature bytes
//!
//! It does not depend on FRAME or runtime code.
//!
//! # Security model
//!
//! Account ids are derived from the hybrid public key via
//! `blake2_256(ACCOUNT_ID_DOMAIN || hybrid_public_bytes)`. This relies on
//! blake2_256 collision resistance (~2^-128 birthday bound) to ensure two
//! distinct hybrid public keys cannot map to the same 32-byte [`AccountId32`].
//! A collision would credit the wrong owner on a verified signature — a
//! catastrophic silent failure the runtime cannot detect.
//!
//! Two invariants make this load-bearing assumption safe in this code:
//!
//! 1. [`ACCOUNT_ID_DOMAIN`] is a fixed byte string. Pinned by the
//!    `account_id_domain_is_pinned` test so a typo is caught at test time.
//! 2. [`HybridPublic`] has a fixed serialized length. This is what makes the
//!    unprefixed `domain || pubkey` concatenation unambiguous — see the
//!    comment on [`account_id_from_public`].
//!
//! Any refactor that truncates, projects, or otherwise reduces the entropy
//! of the hybrid public key input *will* silently weaken account-id collision
//! resistance. Do not change [`account_id_from_public`] without preserving
//! the property that the full pubkey bytes feed the hash.

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use quip_crypto_primitives::substrate::sr25519_mldsa44;
use scale_info::TypeInfo;
use sp_core::Pair as _;
use sp_runtime::{
    traits::{IdentifyAccount, Lazy, Verify},
    AccountId32,
};

/// Hybrid H3 public key used for transaction signing.
pub type HybridPublic = sr25519_mldsa44::Public;

/// Hybrid H3 signature bytes used for transaction signing.
pub type HybridSignatureBytes = sr25519_mldsa44::Signature;

/// Hybrid H3 pair used for transaction signing.
pub type HybridPair = sr25519_mldsa44::Pair;

/// Compact account id used by the runtime for transaction signers.
pub type DerivedAccountId = AccountId32;

/// Domain separator for account-id derivation from the hybrid public key.
///
/// The trailing version (`v1`) is part of the domain string, not a runtime
/// field — changing this constant re-keys every existing account, which is
/// why `account_id_domain_is_pinned` asserts its exact value.
pub const ACCOUNT_ID_DOMAIN: &[u8] = b"quip-account-v1";

/// Derives the compact runtime account id from the H3 hybrid public key.
///
/// The mapping is: `blake2_256(ACCOUNT_ID_DOMAIN || hybrid_public_bytes)`.
///
/// The domain separator is *not* length-prefixed; this is unambiguous only
/// because [`HybridPublic`] has a fixed serialized length. See the crate-level
/// security note for why this invariant is load-bearing.
///
/// The `Vec` allocation is bounded (one allocation, no reallocation) and is
/// negligible next to the ML-DSA-44 verification that follows on every signed
/// extrinsic. A stack-buffer alternative would require either a const
/// pubkey-length at this layer of the type stack (not currently available
/// from `quip-crypto-primitives`) or a streaming hasher (would force a
/// host-hashing-module change tracked separately).
pub fn account_id_from_public(public: &HybridPublic) -> DerivedAccountId {
    let pub_bytes = public.as_ref();
    let mut input = Vec::with_capacity(ACCOUNT_ID_DOMAIN.len() + pub_bytes.len());
    input.extend_from_slice(ACCOUNT_ID_DOMAIN);
    input.extend_from_slice(pub_bytes);
    DerivedAccountId::new(sp_io::hashing::blake2_256(&input))
}

/// Signer identity wrapper for runtime transaction verification.
///
/// This newtype exists so the runtime can implement `IdentifyAccount` locally
/// while still using the underlying hybrid public key wrapper.
#[derive(
    Clone,
    Debug,
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
pub struct HybridTxPublic(pub HybridPublic);

impl From<HybridPublic> for HybridTxPublic {
    fn from(public: HybridPublic) -> Self {
        Self(public)
    }
}

impl From<HybridTxPublic> for HybridPublic {
    fn from(public: HybridTxPublic) -> Self {
        public.0
    }
}

impl AsRef<HybridPublic> for HybridTxPublic {
    fn as_ref(&self) -> &HybridPublic {
        &self.0
    }
}

impl IdentifyAccount for HybridTxPublic {
    type AccountId = DerivedAccountId;

    fn into_account(self) -> Self::AccountId {
        account_id_from_public(&self.0)
    }
}

/// Runtime transaction signature envelope.
///
/// Carries the full hybrid public key alongside the hybrid signature so
/// runtime verification can:
/// 1. verify the embedded public key derives the claimed `AccountId`
/// 2. verify the hybrid signature under the embedded public key
///
/// The two fields are *not* validated against each other at construction.
/// [`Verify::verify`] is the only path that establishes the relationship;
/// [`Self::new`] and the [`Decode`] path produce envelopes whose fields may
/// be unrelated until `verify` succeeds.
///
/// `MaxEncodedLen` is intentionally not derived because [`HybridSignatureBytes`]
/// (`sr25519_mldsa44::Signature`) does not yet implement it upstream, even
/// though its size is known at compile time via const generics. Add the
/// derive once the upstream gap is closed.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct HybridTxSignature {
    pub public: HybridPublic,
    pub signature: HybridSignatureBytes,
}

impl HybridTxSignature {
    /// Builds the envelope from explicit parts without validating that
    /// `signature` is a real signature under `public`.
    ///
    /// Use [`Self::sign`] to produce an envelope whose parts are guaranteed
    /// to be consistent; reserve `new` for deserialization shims and tests.
    pub fn new(public: HybridPublic, signature: HybridSignatureBytes) -> Self {
        Self { public, signature }
    }

    /// Signs the message with the given hybrid H3 pair and returns the full
    /// transaction signature envelope.
    #[cfg(feature = "std")]
    pub fn sign(pair: &HybridPair, message: &[u8]) -> Self {
        Self {
            public: pair.public(),
            signature: pair.sign(message),
        }
    }

    /// Returns the derived compact account id for the embedded public key.
    pub fn derived_account_id(&self) -> DerivedAccountId {
        account_id_from_public(&self.public)
    }
}

impl Verify for HybridTxSignature {
    type Signer = HybridTxPublic;

    fn verify<L: Lazy<[u8]>>(
        &self,
        mut msg: L,
        signer: &<Self::Signer as IdentifyAccount>::AccountId,
    ) -> bool {
        if self.derived_account_id() != *signer {
            return false;
        }

        HybridPair::verify(&self.signature, msg.get(), &self.public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_public_key_derives_same_account_id() {
        let pair = HybridPair::from_string("//Alice", None).unwrap();
        let first = account_id_from_public(&pair.public());
        let second = account_id_from_public(&pair.public());

        assert_eq!(first, second);
    }

    #[test]
    fn different_public_keys_derive_different_account_ids() {
        let alice = HybridPair::from_string("//Alice", None).unwrap();
        let bob = HybridPair::from_string("//Bob", None).unwrap();

        assert_ne!(
            account_id_from_public(&alice.public()),
            account_id_from_public(&bob.public())
        );
    }

    #[test]
    fn hybrid_tx_signature_verifies_for_matching_account() {
        let pair = HybridPair::from_string("//Alice", None).unwrap();
        let account_id = account_id_from_public(&pair.public());
        let signature = HybridTxSignature::sign(&pair, b"quip-message");

        assert!(signature.verify(&b"quip-message"[..], &account_id));
    }

    #[test]
    fn hybrid_tx_signature_rejects_wrong_account() {
        let pair = HybridPair::from_string("//Alice", None).unwrap();
        let wrong_pair = HybridPair::from_string("//Bob", None).unwrap();
        let wrong_account = account_id_from_public(&wrong_pair.public());
        let signature = HybridTxSignature::sign(&pair, b"quip-message");

        assert!(!signature.verify(&b"quip-message"[..], &wrong_account));
    }

    #[test]
    fn hybrid_tx_signature_rejects_wrong_message() {
        let pair = HybridPair::from_string("//Alice", None).unwrap();
        let account_id = account_id_from_public(&pair.public());
        let signature = HybridTxSignature::sign(&pair, b"quip-message");

        assert!(!signature.verify(&b"wrong-message"[..], &account_id));
    }

    #[test]
    fn account_id_domain_is_pinned() {
        // Changing this string re-keys every account at genesis. If that's
        // really the intent, bump the version segment ("v1" -> "v2") in
        // lockstep with the migration plan.
        assert_eq!(ACCOUNT_ID_DOMAIN, b"quip-account-v1");
    }
}
