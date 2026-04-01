//! Shared engine for fixed-size hybrid signature suites.
//!
//! This module factors out the common composition logic for suites whose
//! classical and PQ components both have fixed-size serialized encodings. It
//! owns:
//! - generic fixed-size public-key and signature wrappers
//! - suite traits describing how component algorithms are combined
//! - shared generate / derive / sign / verify flows
//!
//! Concrete suites in [`crate::suite`] provide the suite label, choose a
//! classical backend, choose a PQ backend, and define the secret-key wrapper.

use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::classical::ClassicalSignatureAlgorithm;
use crate::domain::prepare_message;
use crate::pq::FixedPqSignatureAlgorithm;
use crate::seed::{derive_component_seeds, MASTER_SEED_LEN};
use crate::suite::FixedHybridSuite;
use crate::{HybridSignatureError, Result};

/// Trait implemented by composite public-key wrappers.
///
/// The fixed hybrid engine only needs to concatenate component bytes, split
/// them back out, and know the total serialized length.
pub trait CompositePublicKey: AsRef<[u8]> + Clone + Sized {
    /// Serialized length in bytes.
    const LEN: usize;

    /// Builds a composite public key from classical and PQ public-key bytes.
    fn from_parts(classical: &[u8], pq: &[u8]) -> Self;

    /// Splits a composite public key into classical and PQ byte slices.
    fn split(&self) -> (&[u8], &[u8]);
}

/// Trait implemented by composite signature wrappers.
pub trait CompositeSignature: AsRef<[u8]> + Sized {
    /// Serialized length in bytes.
    const LEN: usize;

    /// Builds a composite signature from classical and PQ signature bytes.
    fn from_parts(classical: &[u8], pq: &[u8]) -> Self;

    /// Splits a composite signature into classical and PQ byte slices.
    fn split(&self) -> (&[u8], &[u8]);

    /// Parses a serialized composite signature.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// Minimal suite metadata needed by the generic public-key wrapper.
///
/// This is deliberately smaller than [`FixedHybridEncoding`] so a public-key
/// type can depend only on component algorithm choices and suite metadata,
/// without depending on secret-key composition.
pub trait FixedHybridComponents: FixedHybridSuite {
    /// Classical component algorithm.
    type Classical: ClassicalSignatureAlgorithm;
    /// Post-quantum component algorithm.
    type Pq: FixedPqSignatureAlgorithm;
}

// Merges classical and PQ component bytes.
fn merge_parts<const TOTAL_LEN: usize, const LEFT_LEN: usize>(
    classical: &[u8],
    pq: &[u8],
) -> [u8; TOTAL_LEN] {
    debug_assert_eq!(classical.len(), LEFT_LEN);
    debug_assert_eq!(pq.len(), TOTAL_LEN - LEFT_LEN);

    let mut bytes = [0u8; TOTAL_LEN];
    bytes[..LEFT_LEN].copy_from_slice(classical);
    bytes[LEFT_LEN..].copy_from_slice(pq);
    bytes
}

/// Generic fixed-size composite public key.
///
/// `TOTAL_LEN` is the total serialized length and `LEFT_LEN` is the classical
/// component length. The PQ component occupies the remaining suffix.
pub struct FixedPublicKey<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> {
    bytes: [u8; TOTAL_LEN],
    marker: PhantomData<fn() -> S>,
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> Clone
    for FixedPublicKey<S, TOTAL_LEN, LEFT_LEN>
{
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            marker: PhantomData,
        }
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> AsRef<[u8]>
    for FixedPublicKey<S, TOTAL_LEN, LEFT_LEN>
{
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> ConstantTimeEq
    for FixedPublicKey<S, TOTAL_LEN, LEFT_LEN>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> FixedPublicKey<S, TOTAL_LEN, LEFT_LEN>
where
    S: FixedHybridComponents,
{
    /// Parses and validates a serialized composite public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TOTAL_LEN {
            return Err(HybridSignatureError::InvalidLength {
                expected: TOTAL_LEN,
                actual: bytes.len(),
            });
        }

        let mut out = [0u8; TOTAL_LEN];
        out.copy_from_slice(bytes);

        if !<S::Classical as ClassicalSignatureAlgorithm>::validate_public_key(&out[..LEFT_LEN]) {
            return Err(HybridSignatureError::InvalidPublicKey);
        }
        if !<S::Pq as FixedPqSignatureAlgorithm>::validate_public_key(&out[LEFT_LEN..]) {
            return Err(HybridSignatureError::InvalidPublicKey);
        }

        Ok(Self::from_array(out))
    }

    pub fn to_bytes(&self) -> [u8; TOTAL_LEN] {
        self.bytes
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> FixedPublicKey<S, TOTAL_LEN, LEFT_LEN> {
    fn from_array(bytes: [u8; TOTAL_LEN]) -> Self {
        Self {
            bytes,
            marker: PhantomData,
        }
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> CompositePublicKey
    for FixedPublicKey<S, TOTAL_LEN, LEFT_LEN>
{
    const LEN: usize = TOTAL_LEN;

    fn from_parts(classical: &[u8], pq: &[u8]) -> Self {
        Self::from_array(merge_parts::<TOTAL_LEN, LEFT_LEN>(classical, pq))
    }

    fn split(&self) -> (&[u8], &[u8]) {
        (&self.bytes[..LEFT_LEN], &self.bytes[LEFT_LEN..])
    }
}

/// Generic fixed-size composite signature.
///
/// `TOTAL_LEN` is the total serialized length and `LEFT_LEN` is the classical
/// component length. The PQ component occupies the remaining suffix.
pub struct FixedSignature<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> {
    bytes: [u8; TOTAL_LEN],
    marker: PhantomData<fn() -> S>,
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> Clone
    for FixedSignature<S, TOTAL_LEN, LEFT_LEN>
{
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            marker: PhantomData,
        }
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> AsRef<[u8]>
    for FixedSignature<S, TOTAL_LEN, LEFT_LEN>
{
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> FixedSignature<S, TOTAL_LEN, LEFT_LEN> {
    /// Parses a serialized composite signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TOTAL_LEN {
            return Err(HybridSignatureError::InvalidLength {
                expected: TOTAL_LEN,
                actual: bytes.len(),
            });
        }

        let mut out = [0u8; TOTAL_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::from_array(out))
    }

    pub fn to_bytes(&self) -> [u8; TOTAL_LEN] {
        self.bytes
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> FixedSignature<S, TOTAL_LEN, LEFT_LEN> {
    fn from_array(bytes: [u8; TOTAL_LEN]) -> Self {
        Self {
            bytes,
            marker: PhantomData,
        }
    }
}

impl<S, const TOTAL_LEN: usize, const LEFT_LEN: usize> CompositeSignature
    for FixedSignature<S, TOTAL_LEN, LEFT_LEN>
{
    const LEN: usize = TOTAL_LEN;

    fn from_parts(classical: &[u8], pq: &[u8]) -> Self {
        Self::from_array(merge_parts::<TOTAL_LEN, LEFT_LEN>(classical, pq))
    }

    fn split(&self) -> (&[u8], &[u8]) {
        (&self.bytes[..LEFT_LEN], &self.bytes[LEFT_LEN..])
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        <FixedSignature<S, TOTAL_LEN, LEFT_LEN>>::from_bytes(bytes)
    }
}

/// Suite-specific hooks required by the generic fixed-size hybrid engine.
///
/// Concrete suites select their component algorithms, choose the public-key,
/// secret-key, and signature wrapper types, and define how a secret key is
/// composed and split.
pub trait FixedHybridEncoding: FixedHybridComponents {
    /// Composite public-key wrapper.
    type PublicKey: CompositePublicKey;
    /// Composite secret-key wrapper.
    type SecretKey: Zeroize;
    /// Composite signature wrapper.
    type Signature: CompositeSignature;
    /// Serialized secret-key length in bytes.
    const SECRET_KEY_LEN: usize;

    /// Parses and validates a serialized public key.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey>;

    /// Parses and validates a serialized secret key.
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey>;

    /// Parses and validates a serialized signature.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        Self::Signature::from_bytes(bytes)
    }

    /// Combines classical and PQ public-key bytes into the suite's public-key
    /// wrapper.
    fn compose_public_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::PublicKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::PublicKeyBytes,
    ) -> Self::PublicKey {
        Self::PublicKey::from_parts(classical.as_ref(), pq.as_ref())
    }
    /// Combines classical and PQ secret-key bytes into the suite's secret-key
    /// wrapper.
    fn compose_secret_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SecretKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SecretKeyBytes,
    ) -> Self::SecretKey;

    /// Combines classical and PQ signature bytes into the suite's signature
    /// wrapper.
    fn compose_signature(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SignatureBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SignatureBytes,
    ) -> Self::Signature {
        Self::Signature::from_parts(classical.as_ref(), pq.as_ref())
    }
    /// Splits a composite public key into classical and PQ byte slices.
    fn split_public_key(pk: &Self::PublicKey) -> (&[u8], &[u8]) {
        pk.split()
    }

    /// Splits a composite secret key into classical and PQ byte slices.
    fn split_secret_key(sk: &Self::SecretKey) -> (&[u8], &[u8]);

    /// Splits a composite signature into classical and PQ byte slices.
    fn split_signature(sig: &Self::Signature) -> (&[u8], &[u8]) {
        sig.split()
    }
}

/// Generates a fresh keypair for a fixed-size hybrid suite.
pub fn generate<S>(rng: &mut impl CryptoRngCore) -> (S::SecretKey, S::PublicKey)
where
    S: FixedHybridEncoding,
{
    let mut classical_seed = [0u8; MASTER_SEED_LEN];
    rng.fill_bytes(&mut classical_seed);
    let (classical_pk, classical_sk) =
        <S::Classical as ClassicalSignatureAlgorithm>::from_seed(&classical_seed);
    classical_seed.zeroize();

    let (pq_pk, pq_sk) = <S::Pq as FixedPqSignatureAlgorithm>::generate(rng);

    (
        S::compose_secret_key(&classical_sk, &pq_sk),
        S::compose_public_key(&classical_pk, &pq_pk),
    )
}

/// Derives a deterministic keypair from a 32-byte master seed.
pub fn from_seed_slice<S>(seed: &[u8]) -> Result<(S::SecretKey, S::PublicKey)>
where
    S: FixedHybridEncoding,
{
    let mut classical_seed = [0u8; MASTER_SEED_LEN];
    let mut pq_seed = [0u8; MASTER_SEED_LEN];
    derive_component_seeds(seed, &mut classical_seed, &mut pq_seed)?;

    let (classical_pk, classical_sk) =
        <S::Classical as ClassicalSignatureAlgorithm>::from_seed(&classical_seed);
    let (pq_pk, pq_sk) = <S::Pq as FixedPqSignatureAlgorithm>::from_seed(&pq_seed);

    classical_seed.zeroize();
    pq_seed.zeroize();

    Ok((
        S::compose_secret_key(&classical_sk, &pq_sk),
        S::compose_public_key(&classical_pk, &pq_pk),
    ))
}

/// Derives the public key for a suite from its secret key.
pub fn public<S>(sk: &S::SecretKey) -> S::PublicKey
where
    S: FixedHybridEncoding,
{
    let (classical_sk, pq_sk) = S::split_secret_key(sk);
    let classical_pk =
        <S::Classical as ClassicalSignatureAlgorithm>::public_key_from_secret(classical_sk);
    let pq_pk = <S::Pq as FixedPqSignatureAlgorithm>::public_key_from_secret(pq_sk);
    S::compose_public_key(&classical_pk, &pq_pk)
}

/// Produces a hedged composite signature for a fixed-size hybrid suite.
pub fn sign<S>(
    sk: &S::SecretKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl CryptoRngCore,
) -> S::Signature
where
    S: FixedHybridEncoding,
{
    let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
    let (classical_sk, pq_sk) = S::split_secret_key(sk);
    let classical_sig =
        <S::Classical as ClassicalSignatureAlgorithm>::sign(classical_sk, &msg_prime, rng);
    let pq_sig = <S::Pq as FixedPqSignatureAlgorithm>::sign(pq_sk, &msg_prime, rng);
    S::compose_signature(&classical_sig, &pq_sig)
}

/// Produces a deterministic composite signature for a fixed-size hybrid suite.
pub fn sign_deterministic<S>(
    sk: &S::SecretKey,
    msg: &[u8],
    ctx: &[u8],
    nonce: &[u8],
) -> S::Signature
where
    S: FixedHybridEncoding,
{
    let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
    let (classical_sk, pq_sk) = S::split_secret_key(sk);
    let classical_sig = <S::Classical as ClassicalSignatureAlgorithm>::sign_deterministic(
        classical_sk,
        &msg_prime,
        nonce,
    );
    let pq_sig = <S::Pq as FixedPqSignatureAlgorithm>::sign_deterministic(pq_sk, &msg_prime, nonce);
    S::compose_signature(&classical_sig, &pq_sig)
}

/// Verifies a composite signature for a fixed-size hybrid suite.
pub fn verify<S>(pk: &S::PublicKey, msg: &[u8], ctx: &[u8], sig: &S::Signature) -> bool
where
    S: FixedHybridEncoding,
{
    let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
    verify_components::<S>(pk, &msg_prime, sig)
}

/// Verifies the component signatures against an already prepared `msg_prime`.
fn verify_components<S>(pk: &S::PublicKey, msg_prime: &[u8], sig: &S::Signature) -> bool
where
    S: FixedHybridEncoding,
{
    let (classical_pk, pq_pk) = S::split_public_key(pk);
    let (classical_sig, pq_sig) = S::split_signature(sig);

    let classical_ok = <S::Classical as ClassicalSignatureAlgorithm>::verify(
        classical_pk,
        msg_prime,
        classical_sig,
    );
    let pq_ok = <S::Pq as FixedPqSignatureAlgorithm>::verify(pq_pk, msg_prime, pq_sig);

    classical_ok && pq_ok
}
