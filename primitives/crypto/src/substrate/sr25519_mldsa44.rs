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
//! Phase 2 adds:
//! - BABE-oriented hybrid VRF input/output/proof types
//! - `sp_core::crypto::VrfSecret` / `VrfPublic` implementations
//! - BABE transcript helpers matching upstream slot/epoch/randomness layout
//!
//! Intentional omissions:
//! - no keystore integration yet
//! - no `app_crypto!` forwarding for hybrid VRF methods yet

use alloc::vec::Vec;
use core::fmt;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use hkdf::Hkdf;
use scale_info::TypeInfo;
use sha2::{Digest, Sha256};
use sp_core::crypto::{
    CryptoType, CryptoTypeId, Derive, DeriveError, DeriveJunction, PublicBytes, SecretStringError,
    SignatureBytes, VrfCrypto, VrfPublic,
};
#[cfg(any(feature = "std", feature = "full_crypto"))]
use sp_core::crypto::VrfSecret;
use sp_core::proof_of_possession::NonAggregatable;
use sp_core::sr25519;
#[cfg(any(feature = "std", feature = "full_crypto"))]
use sp_core::Pair as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(any(feature = "std", feature = "full_crypto"))]
use crate::fixed::FixedHybridEncoding;
use crate::pq::mldsa44 as pq_mldsa44;
use crate::seed::MASTER_SEED_LEN;
use crate::suite::sr25519_mldsa44::{
    PublicKey as HybridPublicKey, Signature as HybridSignature, Sr25519MlDsa44, HYBRID_PK_LEN,
    HYBRID_SIG_LEN,
};
#[cfg(any(feature = "std", feature = "full_crypto"))]
use crate::suite::sr25519_mldsa44::SecretKey as HybridSecretKey;
use crate::HybridSignatureScheme;
#[cfg(any(feature = "std", feature = "full_crypto"))]
use crate::HybridVrf;

/// Unique identifier for the H3 hybrid crypto scheme.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"h344");

const HYBRID_VRF_LABEL: &[u8] = b"hybrid-vrf";
/// Length in bytes of the consensus-facing hybrid VRF output.
pub const VRF_OUTPUT_LENGTH: usize = 32;

const SR25519_PUBLIC_KEY_LEN: usize = 32;
const PQ_PUBLIC_KEY_LEN: usize = pq_mldsa44::PUBLIC_KEY_LEN;
#[cfg(any(feature = "std", feature = "full_crypto"))]
const PQ_SECRET_KEY_LEN: usize = pq_mldsa44::SECRET_KEY_LEN;
const PQ_SIGNATURE_LEN: usize = pq_mldsa44::SIGNATURE_LEN;

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

impl Public {
    fn split_components(&self) -> ([u8; SR25519_PUBLIC_KEY_LEN], [u8; PQ_PUBLIC_KEY_LEN]) {
        let bytes = self.as_ref();

        let mut classical = [0u8; SR25519_PUBLIC_KEY_LEN];
        classical.copy_from_slice(&bytes[..SR25519_PUBLIC_KEY_LEN]);

        let mut pq = [0u8; PQ_PUBLIC_KEY_LEN];
        pq.copy_from_slice(&bytes[SR25519_PUBLIC_KEY_LEN..]);

        (classical, pq)
    }

    /// Recomputes the hybrid output from a proof after verifying it.
    pub fn vrf_output(&self, data: &VrfSignData, signature: &VrfSignature) -> Option<VrfOutput> {
        self.vrf_verify(data, signature).then(|| signature.output())
    }

    /// Derives protocol bytes from a verified hybrid VRF proof.
    pub fn make_bytes<const N: usize>(
        &self,
        context: &[u8],
        data: &VrfSignData,
        signature: &VrfSignature,
    ) -> Option<[u8; N]>
    where
        [u8; N]: Default,
    {
        self.vrf_output(data, signature)
            .map(|output| output.make_bytes(context))
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

/// BABE-facing hybrid VRF input.
///
/// The underlying sr25519 transcript is paired with a canonical byte encoding
/// of the logical input so the PQ binding can sign stable bytes rather than an
/// opaque Merlin transcript object.
#[derive(Clone)]
pub struct VrfInput {
    sr25519: sr25519::vrf::VrfInput,
    binding_input: Vec<u8>,
}

impl VrfInput {
    /// Builds a hybrid VRF input from an sr25519 transcript plus a canonical
    /// byte encoding of the same logical input.
    pub fn new(sr25519: sr25519::vrf::VrfInput, binding_input: Vec<u8>) -> Self {
        Self {
            sr25519,
            binding_input,
        }
    }

    /// Returns the canonical byte encoding used for PQ binding.
    pub fn binding_input(&self) -> &[u8] {
        &self.binding_input
    }

    /// Clones the underlying sr25519 transcript.
    pub fn clone_sr25519(&self) -> sr25519::vrf::VrfInput {
        self.sr25519.clone()
    }
}

/// Hybrid VRF signing data.
#[derive(Clone)]
pub struct VrfSignData {
    input: VrfInput,
}

impl From<VrfInput> for VrfSignData {
    fn from(input: VrfInput) -> Self {
        Self { input }
    }
}

impl AsRef<VrfInput> for VrfSignData {
    fn as_ref(&self) -> &VrfInput {
        &self.input
    }
}

impl VrfSignData {
    /// Builds sign data from a hybrid VRF input.
    pub fn new(input: VrfInput) -> Self {
        input.into()
    }

    /// Returns the wrapped hybrid VRF input.
    pub fn input(&self) -> &VrfInput {
        &self.input
    }

    /// Clones the underlying sr25519 signing data.
    pub fn clone_sr25519(&self) -> sr25519::vrf::VrfSignData {
        self.input.sr25519.clone().into_sign_data()
    }
}

/// Consensus-facing hybrid VRF output.
///
/// This is the 32-byte `hybrid_output = H(vrf_output || pq_sig)` value that
/// BABE should eventually consume for leader election, `make_bytes`, and epoch
/// randomness.
#[derive(
    Clone, Eq, PartialEq, Hash, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct VrfOutput([u8; VRF_OUTPUT_LENGTH]);

impl AsRef<[u8]> for VrfOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for VrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VrfOutput").field(&self.as_ref()).finish()
    }
}

impl VrfOutput {
    fn from_parts(
        pre_output: &sr25519::vrf::VrfPreOutput,
        pq_signature: &[u8; PQ_SIGNATURE_LEN],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pre_output.0.as_bytes());
        hasher.update(pq_signature);

        let digest = hasher.finalize();
        let mut out = [0u8; VRF_OUTPUT_LENGTH];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Expands the hybrid output into `N` bytes using HKDF-SHA256.
    pub fn make_bytes<const N: usize>(&self, context: &[u8]) -> [u8; N]
    where
        [u8; N]: Default,
    {
        let hkdf = Hkdf::<Sha256>::from_prk(&self.0)
            .expect("32-byte hybrid output is a valid HKDF pseudo-random key");
        let mut out = [0u8; N];
        hkdf.expand(context, &mut out)
            .expect("HKDF output length is valid");
        out
    }
}

/// Hybrid H3 VRF proof.
///
/// This keeps the native sr25519 VRF proof material intact and adds the
/// ML-DSA-44 binding signature over `H(\"hybrid-vrf\" || input || vrf_output)`.
#[derive(Clone, Eq, PartialEq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct VrfSignature {
    /// Native sr25519 VRF proof material.
    pub sr25519: sr25519::vrf::VrfSignature,
    /// ML-DSA-44 binding signature over the canonical input/output hash.
    pub pq_signature: [u8; PQ_SIGNATURE_LEN],
}

impl fmt::Debug for VrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VrfSignature")
            .field("sr25519", &self.sr25519)
            .field("pq_signature", &self.pq_signature.as_slice())
            .finish()
    }
}

impl VrfSignature {
    /// Returns the consensus-facing hybrid output bound to this proof.
    pub fn output(&self) -> VrfOutput {
        VrfOutput::from_parts(&self.sr25519.pre_output, &self.pq_signature)
    }
}

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

    #[cfg(any(feature = "std", feature = "full_crypto"))]
    fn expanded_secret(&self) -> HybridSecretKey {
        Sr25519MlDsa44::from_seed_slice(&self.seed)
            .expect("pair seed is validated on construction; qed")
            .0
    }

    #[cfg(any(feature = "std", feature = "full_crypto"))]
    fn sr25519_pair(secret: &HybridSecretKey) -> sr25519::Pair {
        let (classical, _) = <Sr25519MlDsa44 as FixedHybridEncoding>::split_secret_key(secret);
        sr25519::Pair::from_seed_slice(classical)
            .expect("stored H3 secret key contains a valid sr25519 secret")
    }

    #[cfg(any(feature = "std", feature = "full_crypto"))]
    fn pq_secret_bytes(secret: &HybridSecretKey) -> &[u8; PQ_SECRET_KEY_LEN] {
        let (_, pq) = <Sr25519MlDsa44 as FixedHybridEncoding>::split_secret_key(secret);
        pq.try_into()
            .expect("stored H3 secret key contains a fixed-size ML-DSA secret")
    }

    #[cfg(any(feature = "std", feature = "full_crypto"))]
    fn pq_binding_signature(
        input: &VrfInput,
        pre_output: &sr25519::vrf::VrfPreOutput,
        pq_secret: &[u8; PQ_SECRET_KEY_LEN],
    ) -> [u8; PQ_SIGNATURE_LEN] {
        let message = binding_message(input, pre_output);
        pq_mldsa44::sign_deterministic(pq_secret, &message)
    }

    /// Computes the consensus-facing hybrid VRF output for a BABE input.
    #[cfg(any(feature = "std", feature = "full_crypto"))]
    pub fn vrf_output(&self, input: &VrfInput) -> VrfOutput {
        let secret = self.expanded_secret();
        let pq_secret = Self::pq_secret_bytes(&secret);
        let sr25519_pre_output = Self::sr25519_pair(&secret).vrf_pre_output(&input.clone_sr25519());
        let pq_signature = Self::pq_binding_signature(input, &sr25519_pre_output, pq_secret);
        VrfOutput::from_parts(&sr25519_pre_output, &pq_signature)
    }

    /// Expands the hybrid VRF output into protocol bytes.
    #[cfg(any(feature = "std", feature = "full_crypto"))]
    pub fn make_bytes<const N: usize>(&self, context: &[u8], input: &VrfInput) -> [u8; N]
    where
        [u8; N]: Default,
    {
        self.vrf_output(input).make_bytes(context)
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

    #[cfg(any(feature = "std", feature = "full_crypto"))]
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

impl VrfCrypto for Pair {
    type VrfInput = VrfInput;
    type VrfPreOutput = VrfOutput;
    type VrfSignData = VrfSignData;
    type VrfSignature = VrfSignature;
}

#[cfg(any(feature = "std", feature = "full_crypto"))]
impl VrfSecret for Pair {
    fn vrf_pre_output(&self, data: &Self::VrfInput) -> Self::VrfPreOutput {
        self.vrf_output(data)
    }

    fn vrf_sign(&self, data: &Self::VrfSignData) -> Self::VrfSignature {
        let secret = self.expanded_secret();
        let pq_secret = Self::pq_secret_bytes(&secret);
        let sr25519 = Self::sr25519_pair(&secret).vrf_sign(&data.clone_sr25519());
        let pq_signature = Self::pq_binding_signature(data.input(), &sr25519.pre_output, pq_secret);

        VrfSignature {
            sr25519,
            pq_signature,
        }
    }
}

impl VrfCrypto for Public {
    type VrfInput = VrfInput;
    type VrfPreOutput = VrfOutput;
    type VrfSignData = VrfSignData;
    type VrfSignature = VrfSignature;
}

impl VrfPublic for Public {
    fn vrf_verify(&self, data: &Self::VrfSignData, signature: &Self::VrfSignature) -> bool {
        let (classical, pq) = self.split_components();
        let classical = sr25519::Public::from_raw(classical);

        if !classical.vrf_verify(&data.clone_sr25519(), &signature.sr25519) {
            return false;
        }

        let message = binding_message(data.input(), &signature.sr25519.pre_output);
        pq_mldsa44::verify(&pq, &message, &signature.pq_signature)
    }
}

#[cfg(any(feature = "std", feature = "full_crypto"))]
impl HybridVrf for Pair {
    type PublicKey = Public;
    type VrfInput = VrfInput;
    type VrfSignData = VrfSignData;
    type VrfOutput = VrfOutput;
    type VrfSignature = VrfSignature;

    fn vrf_output(&self, input: &Self::VrfInput) -> Self::VrfOutput {
        self.vrf_output(input)
    }

    fn vrf_sign(&self, data: &Self::VrfSignData) -> Self::VrfSignature {
        <Self as VrfSecret>::vrf_sign(self, data)
    }

    fn make_bytes<const N: usize>(&self, context: &[u8], input: &Self::VrfInput) -> [u8; N]
    where
        [u8; N]: Default,
    {
        self.make_bytes(context, input)
    }

    fn vrf_verify(
        public: &Self::PublicKey,
        data: &Self::VrfSignData,
        signature: &Self::VrfSignature,
    ) -> bool {
        public.vrf_verify(data, signature)
    }
}

/// BABE-facing transcript helpers for the hybrid H3 wrapper.
pub mod babe {
    use super::{VrfInput, VrfSignData};
    use alloc::vec::Vec;

    /// VRF context used for BABE per-slot randomness generation.
    pub const RANDOMNESS_VRF_CONTEXT: &[u8] = b"BabeVRFInOutContext";
    /// Length in bytes of BABE randomness.
    pub const RANDOMNESS_LENGTH: usize = 32;
    /// BABE randomness type.
    pub type Randomness = [u8; RANDOMNESS_LENGTH];

    const BABE_ENGINE_ID: &[u8] = b"BABE";

    /// Builds the BABE transcript plus canonical binding bytes from the
    /// upstream `(randomness, slot, epoch)` tuple.
    pub fn make_vrf_transcript(randomness: &Randomness, slot: u64, epoch: u64) -> VrfInput {
        let slot_bytes = slot.to_le_bytes();
        let epoch_bytes = epoch.to_le_bytes();

        let transcript = sp_core::sr25519::vrf::VrfInput::new(
            BABE_ENGINE_ID,
            &[
                (b"slot number", &slot_bytes),
                (b"current epoch", &epoch_bytes),
                (b"chain randomness", randomness),
            ],
        );

        let mut binding_input = Vec::with_capacity(4 + 8 + 8 + RANDOMNESS_LENGTH);
        binding_input.extend_from_slice(BABE_ENGINE_ID);
        binding_input.extend_from_slice(&slot_bytes);
        binding_input.extend_from_slice(&epoch_bytes);
        binding_input.extend_from_slice(randomness);

        VrfInput::new(transcript, binding_input)
    }

    /// Builds hybrid VRF signing data matching BABE's slot/epoch/randomness
    /// transcript shape.
    pub fn make_vrf_sign_data(randomness: &Randomness, slot: u64, epoch: u64) -> VrfSignData {
        make_vrf_transcript(randomness, slot, epoch).into()
    }
}

fn binding_message(
    input: &VrfInput,
    pre_output: &sr25519::vrf::VrfPreOutput,
) -> [u8; VRF_OUTPUT_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(HYBRID_VRF_LABEL);
    hasher.update(input.binding_input());
    hasher.update(pre_output.0.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; VRF_OUTPUT_LENGTH];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::sr25519_mldsa44::Sr25519MlDsa44;
    use sp_core::crypto::{VrfPublic, VrfSecret};

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

    #[test]
    fn hybrid_vrf_roundtrip_works() {
        let seed = [13u8; MASTER_SEED_LEN];
        let pair = Pair::from_seed(&seed);
        let public = pair.public();
        let randomness = [5u8; babe::RANDOMNESS_LENGTH];
        let sign_data = babe::make_vrf_sign_data(&randomness, 7, 11);

        let signature = VrfSecret::vrf_sign(&pair, &sign_data);

        assert!(VrfPublic::vrf_verify(&public, &sign_data, &signature));
        assert_eq!(
            pair.make_bytes::<32>(babe::RANDOMNESS_VRF_CONTEXT, sign_data.input()),
            public
                .make_bytes::<32>(babe::RANDOMNESS_VRF_CONTEXT, &sign_data, &signature)
                .unwrap(),
        );
    }

    #[test]
    fn hybrid_vrf_rejects_tampered_pq_binding() {
        let seed = [17u8; MASTER_SEED_LEN];
        let pair = Pair::from_seed(&seed);
        let public = pair.public();
        let randomness = [9u8; babe::RANDOMNESS_LENGTH];
        let sign_data = babe::make_vrf_sign_data(&randomness, 3, 19);
        let mut signature = VrfSecret::vrf_sign(&pair, &sign_data);

        signature.pq_signature[0] ^= 0x01;

        assert!(!VrfPublic::vrf_verify(&public, &sign_data, &signature));
        assert!(public
            .make_bytes::<32>(babe::RANDOMNESS_VRF_CONTEXT, &sign_data, &signature)
            .is_none());
    }

    #[test]
    fn hybrid_vrf_output_matches_signed_proof_output() {
        let seed = [19u8; MASTER_SEED_LEN];
        let pair = Pair::from_seed(&seed);
        let randomness = [3u8; babe::RANDOMNESS_LENGTH];
        let input = babe::make_vrf_transcript(&randomness, 21, 2);
        let sign_data = VrfSignData::new(input.clone());

        let output = pair.vrf_output(&input);
        let signature = VrfSecret::vrf_sign(&pair, &sign_data);

        assert_eq!(output.as_ref(), signature.output().as_ref());
    }

    #[test]
    fn babe_transcript_helper_matches_upstream_sr25519_shape() {
        let seed = [23u8; MASTER_SEED_LEN];
        let pair = sr25519::Pair::from_seed(&seed);
        let randomness = [7u8; babe::RANDOMNESS_LENGTH];
        let slot = 42u64;
        let epoch = 6u64;

        let upstream = sp_consensus_babe::make_vrf_sign_data(
            &randomness,
            sp_consensus_babe::Slot::from(slot),
            epoch,
        );
        let hybrid = babe::make_vrf_sign_data(&randomness, slot, epoch);

        let upstream_signature = pair.vrf_sign(&upstream);
        let hybrid_signature = pair.vrf_sign(&hybrid.clone_sr25519());

        assert_eq!(upstream_signature.pre_output, hybrid_signature.pre_output);
        assert!(pair.public().vrf_verify(&upstream, &upstream_signature));
        assert!(pair
            .public()
            .vrf_verify(&hybrid.clone_sr25519(), &hybrid_signature));
    }
}
