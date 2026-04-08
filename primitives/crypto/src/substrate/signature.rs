//! Shared Substrate-facing wrapper core for fixed-size hybrid signature suites.
//!
//! This module contains the reusable `sp_core`/`sp_application_crypto`
//! integration for hybrid suites that only need normal public-key and signature
//! functionality:
//! - `Public`
//! - `Signature`
//! - `Pair`
//! - `RuntimePublic`
//! - proof-of-possession helpers
//!
//! BABE-specific VRF types and helpers stay in the concrete H3 wrapper.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_application_crypto::RuntimePublic;
use sp_core::crypto::{
    ByteArray, CryptoType, CryptoTypeId, Derive, DeriveError, DeriveJunction, PublicBytes,
    SecretStringError, SignatureBytes,
};
use sp_core::proof_of_possession::{NonAggregatable, ProofOfPossessionVerifier};
use sp_core::Pair as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::seed::MASTER_SEED_LEN;
use crate::HybridSignatureScheme;

/// Wrapper-specific behavior needed by the shared Substrate glue.
pub trait SubstrateSignatureScheme {
    /// Hybrid suite exposed through this wrapper.
    type Suite: HybridSignatureScheme;

    /// Substrate crypto identifier for the wrapped scheme.
    const CRYPTO_ID: CryptoTypeId;

    /// Applies Substrate derivation semantics to the 32-byte master seed.
    fn derive_seed<Iter: Iterator<Item = DeriveJunction>>(
        seed: [u8; MASTER_SEED_LEN],
        path: Iter,
    ) -> Result<[u8; MASTER_SEED_LEN], DeriveError>;
}

#[doc(hidden)]
pub struct PublicTag<W>(PhantomData<fn() -> W>);

#[doc(hidden)]
pub struct SignatureTag<W>(PhantomData<fn() -> W>);

type InnerPublic<W, const LEN: usize> = PublicBytes<LEN, PublicTag<W>>;
type InnerSignature<W, const LEN: usize> = SignatureBytes<LEN, SignatureTag<W>>;

/// Generic Substrate-style encoded hybrid public key.
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo)]
#[scale_info(skip_type_params(W))]
pub struct Public<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize>(
    InnerPublic<W, PUBLIC_LEN>,
);

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Clone
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> PartialEq
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Eq
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> PartialOrd
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Ord
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> core::hash::Hash
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> CryptoType
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    type Pair = Pair<W, PUBLIC_LEN, SIGNATURE_LEN>;
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> AsRef<[u8]>
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> AsMut<[u8]>
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> sp_core::crypto::ByteArray
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    const LEN: usize = <InnerPublic<W, PUBLIC_LEN> as sp_core::crypto::ByteArray>::LEN;
}

impl<'a, W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> TryFrom<&'a [u8]>
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    type Error = ();

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        InnerPublic::<W, PUBLIC_LEN>::try_from(data).map(Self)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Derive
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> sp_core::crypto::Public
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> fmt::Debug
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Public").field(&self.as_ref()).finish()
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Public<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    /// Wraps a validated suite public key into the Substrate-facing type.
    pub fn from_suite_public(public: <W::Suite as HybridSignatureScheme>::PublicKey) -> Self {
        let mut bytes = [0u8; PUBLIC_LEN];
        bytes.copy_from_slice(public.as_ref());
        Self(InnerPublic::from(bytes))
    }

    /// Parses the wrapper bytes back into the suite public key type.
    pub fn to_suite_public(&self) -> Result<<W::Suite as HybridSignatureScheme>::PublicKey, ()> {
        W::Suite::public_key_from_bytes(self.as_ref()).map_err(|_| ())
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> RuntimePublic
    for Public<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    type Signature = Signature<W, PUBLIC_LEN, SIGNATURE_LEN>;
    type ProofOfPossession = Signature<W, PUBLIC_LEN, SIGNATURE_LEN>;

    fn all(key_type: sp_application_crypto::KeyTypeId) -> alloc::vec::Vec<Self> {
        sp_io::crypto::crypto_public_keys(key_type, W::CRYPTO_ID.0)
            .into_iter()
            .filter_map(|public| <Self as ByteArray>::from_slice(&public).ok())
            .collect()
    }

    fn generate_pair(
        key_type: sp_application_crypto::KeyTypeId,
        seed: Option<alloc::vec::Vec<u8>>,
    ) -> Self {
        let public = sp_io::crypto::crypto_generate(key_type, W::CRYPTO_ID.0, seed);
        <Self as ByteArray>::from_slice(&public)
            .expect("crypto host returned a valid hybrid public key")
    }

    fn sign<M: AsRef<[u8]>>(
        &self,
        key_type: sp_application_crypto::KeyTypeId,
        msg: &M,
    ) -> Option<Self::Signature> {
        sp_io::crypto::crypto_sign_with(key_type, W::CRYPTO_ID.0, self.as_ref(), msg.as_ref())
            .and_then(|signature| <Self::Signature as ByteArray>::from_slice(&signature).ok())
    }

    fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
        Pair::<W, PUBLIC_LEN, SIGNATURE_LEN>::verify(signature, msg, self)
    }

    fn generate_proof_of_possession(
        &mut self,
        key_type: sp_application_crypto::KeyTypeId,
        owner: &[u8],
    ) -> Option<Self::ProofOfPossession> {
        let statement =
            <Pair<W, PUBLIC_LEN, SIGNATURE_LEN> as NonAggregatable>::proof_of_possession_statement(
                owner,
            );
        sp_io::crypto::crypto_sign_with(key_type, W::CRYPTO_ID.0, self.as_ref(), &statement)
            .and_then(|signature| <Self::Signature as ByteArray>::from_slice(&signature).ok())
    }

    fn verify_proof_of_possession(&self, owner: &[u8], pop: &Self::ProofOfPossession) -> bool {
        Pair::<W, PUBLIC_LEN, SIGNATURE_LEN>::verify_proof_of_possession(owner, pop, self)
    }

    fn to_raw_vec(&self) -> alloc::vec::Vec<u8> {
        sp_core::crypto::ByteArray::to_raw_vec(self)
    }
}

/// Generic Substrate-style encoded hybrid signature.
#[derive(Encode, Decode, DecodeWithMemTracking, TypeInfo)]
#[scale_info(skip_type_params(W))]
pub struct Signature<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize>(
    InnerSignature<W, SIGNATURE_LEN>,
);

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Clone
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> PartialEq
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Eq
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> core::hash::Hash
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> CryptoType
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    type Pair = Pair<W, PUBLIC_LEN, SIGNATURE_LEN>;
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> AsRef<[u8]>
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> AsMut<[u8]>
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> sp_core::crypto::ByteArray
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    const LEN: usize = <InnerSignature<W, SIGNATURE_LEN> as sp_core::crypto::ByteArray>::LEN;
}

impl<'a, W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> TryFrom<&'a [u8]>
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    type Error = ();

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        InnerSignature::<W, SIGNATURE_LEN>::try_from(data).map(Self)
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> sp_core::crypto::Signature
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> fmt::Debug
    for Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.as_ref()).finish()
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Signature<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    /// Wraps a validated suite signature into the Substrate-facing type.
    pub fn from_suite_signature(signature: <W::Suite as HybridSignatureScheme>::Signature) -> Self {
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(signature.as_ref());
        Self(InnerSignature::from(bytes))
    }

    /// Parses the wrapper bytes back into the suite signature type.
    pub fn to_suite_signature(&self) -> Result<<W::Suite as HybridSignatureScheme>::Signature, ()> {
        W::Suite::signature_from_bytes(self.as_ref()).map_err(|_| ())
    }
}

/// Generic hybrid keypair backed by the suite master seed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pair<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize>
where
    W: SubstrateSignatureScheme,
{
    seed: [u8; MASTER_SEED_LEN],
    #[zeroize(skip)]
    public: Public<W, PUBLIC_LEN, SIGNATURE_LEN>,
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Clone
    for Pair<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            public: self.public.clone(),
        }
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> CryptoType
    for Pair<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    type Pair = Self;
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> NonAggregatable
    for Pair<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> Pair<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    /// Constructs the pair from a validated master seed.
    pub(crate) fn from_master_seed(seed: [u8; MASTER_SEED_LEN]) -> Result<Self, SecretStringError> {
        let (_secret, public) =
            W::Suite::from_seed_slice(&seed).map_err(|_| SecretStringError::InvalidSeed)?;

        Ok(Self {
            seed,
            public: Public::from_suite_public(public),
        })
    }

    /// Re-expands the cached master seed into the suite secret key.
    #[cfg(any(feature = "std", feature = "full_crypto"))]
    pub(crate) fn expanded_secret(&self) -> <W::Suite as HybridSignatureScheme>::SecretKey {
        W::Suite::from_seed_slice(&self.seed)
            .expect("pair seed is validated on construction; qed")
            .0
    }
}

impl<W, const PUBLIC_LEN: usize, const SIGNATURE_LEN: usize> sp_core::crypto::Pair
    for Pair<W, PUBLIC_LEN, SIGNATURE_LEN>
where
    W: SubstrateSignatureScheme,
{
    type Public = Public<W, PUBLIC_LEN, SIGNATURE_LEN>;
    type Seed = [u8; MASTER_SEED_LEN];
    type Signature = Signature<W, PUBLIC_LEN, SIGNATURE_LEN>;
    type ProofOfPossession = Signature<W, PUBLIC_LEN, SIGNATURE_LEN>;

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        seed: Option<Self::Seed>,
    ) -> Result<(Self, Option<Self::Seed>), DeriveError> {
        let base_seed = seed.unwrap_or(self.seed);
        let derived_seed = W::derive_seed(base_seed, path)?;
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

    #[cfg(any(feature = "std", feature = "full_crypto"))]
    fn sign(&self, message: &[u8]) -> Self::Signature {
        let secret = self.expanded_secret();
        Signature::from_suite_signature(W::Suite::sign_deterministic(&secret, message, b"", b""))
    }

    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool {
        let Ok(public) = pubkey.to_suite_public() else {
            return false;
        };
        let Ok(signature) = sig.to_suite_signature() else {
            return false;
        };

        W::Suite::verify(&public, message.as_ref(), b"", &signature)
    }

    fn public(&self) -> Self::Public {
        self.public.clone()
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed.to_vec()
    }
}
