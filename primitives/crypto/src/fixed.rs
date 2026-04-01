use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::classical::ClassicalSignatureAlgorithm;
use crate::domain::prepare_message;
use crate::pq::FixedPqSignatureAlgorithm;
use crate::suite::{derive_component_seeds, FixedHybridSuite, MASTER_SEED_LEN};
use crate::{HybridSignatureError, Result};

pub trait CompositePublicKey: AsRef<[u8]> + Clone + Sized {
    const LEN: usize;

    fn from_parts(classical: &[u8], pq: &[u8]) -> Self;
    fn split(&self) -> (&[u8], &[u8]);
}

pub trait CompositeSignature: AsRef<[u8]> + Sized {
    const LEN: usize;

    fn from_parts(classical: &[u8], pq: &[u8]) -> Self;
    fn split(&self) -> (&[u8], &[u8]);
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

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
        debug_assert_eq!(classical.len(), LEFT_LEN);
        debug_assert_eq!(pq.len(), TOTAL_LEN - LEFT_LEN);

        let mut bytes = [0u8; TOTAL_LEN];
        bytes[..LEFT_LEN].copy_from_slice(classical);
        bytes[LEFT_LEN..].copy_from_slice(pq);
        Self::from_array(bytes)
    }

    fn split(&self) -> (&[u8], &[u8]) {
        (&self.bytes[..LEFT_LEN], &self.bytes[LEFT_LEN..])
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        <FixedSignature<S, TOTAL_LEN, LEFT_LEN>>::from_bytes(bytes)
    }
}

pub trait FixedHybridEncoding: FixedHybridSuite {
    type PublicKey: CompositePublicKey;
    type SecretKey: Zeroize;
    type Signature: CompositeSignature;
    type Classical: ClassicalSignatureAlgorithm;
    type Pq: FixedPqSignatureAlgorithm;
    const SECRET_KEY_LEN: usize;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey>;
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey>;
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        Self::Signature::from_bytes(bytes)
    }

    fn compose_public_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::PublicKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::PublicKeyBytes,
    ) -> Self::PublicKey {
        Self::PublicKey::from_parts(classical.as_ref(), pq.as_ref())
    }
    fn compose_secret_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SecretKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SecretKeyBytes,
    ) -> Self::SecretKey;
    fn compose_signature(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SignatureBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SignatureBytes,
    ) -> Self::Signature {
        Self::Signature::from_parts(classical.as_ref(), pq.as_ref())
    }
    fn split_public_key(pk: &Self::PublicKey) -> (&[u8], &[u8]) {
        pk.split()
    }
    fn split_secret_key(sk: &Self::SecretKey) -> (&[u8], &[u8]);
    fn split_signature(sig: &Self::Signature) -> (&[u8], &[u8]) {
        sig.split()
    }
}

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

pub fn verify<S>(pk: &S::PublicKey, msg: &[u8], ctx: &[u8], sig: &S::Signature) -> bool
where
    S: FixedHybridEncoding,
{
    let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
    verify_components::<S>(pk, &msg_prime, sig)
}

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
