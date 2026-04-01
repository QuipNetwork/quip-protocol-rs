use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::classical::ClassicalSignatureAlgorithm;
use crate::domain::prepare_message;
use crate::pq::FixedPqSignatureAlgorithm;
use crate::suite::{derive_component_seeds, FixedHybridSuite, MASTER_SEED_LEN};
use crate::{HybridSignatureError, HybridSignatureScheme};

pub trait FixedHybridEncoding: FixedHybridSuite {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey: Zeroize;
    type Signature: AsRef<[u8]>;
    type Classical: ClassicalSignatureAlgorithm;
    type Pq: FixedPqSignatureAlgorithm;

    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, HybridSignatureError>;
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey, HybridSignatureError>;
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, HybridSignatureError>;

    fn compose_public_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::PublicKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::PublicKeyBytes,
    ) -> Self::PublicKey;
    fn compose_secret_key(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SecretKeyBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SecretKeyBytes,
    ) -> Self::SecretKey;
    fn compose_signature(
        classical: &<Self::Classical as ClassicalSignatureAlgorithm>::SignatureBytes,
        pq: &<Self::Pq as FixedPqSignatureAlgorithm>::SignatureBytes,
    ) -> Self::Signature;
    fn split_public_key(pk: &Self::PublicKey) -> (&[u8], &[u8]);
    fn split_secret_key(sk: &Self::SecretKey) -> (&[u8], &[u8]);
    fn split_signature(sig: &Self::Signature) -> (&[u8], &[u8]);
}

impl<S> HybridSignatureScheme for S
where
    S: FixedHybridEncoding,
{
    type PublicKey = S::PublicKey;
    type SecretKey = S::SecretKey;
    type Signature = S::Signature;

    fn public_key_len() -> usize {
        S::PUBLIC_KEY_LEN
    }

    fn secret_key_len() -> usize {
        S::SECRET_KEY_LEN
    }

    fn signature_max_len() -> usize {
        S::SIGNATURE_LEN
    }

    fn generate(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey) {
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

    fn from_seed_slice(
        seed: &[u8],
    ) -> Result<(Self::SecretKey, Self::PublicKey), HybridSignatureError> {
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

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, HybridSignatureError> {
        S::public_key_from_bytes(bytes)
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey, HybridSignatureError> {
        S::secret_key_from_bytes(bytes)
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, HybridSignatureError> {
        S::signature_from_bytes(bytes)
    }

    fn public(sk: &Self::SecretKey) -> Self::PublicKey {
        let (classical_sk, pq_sk) = S::split_secret_key(sk);
        let classical_pk =
            <S::Classical as ClassicalSignatureAlgorithm>::public_key_from_secret(classical_sk);
        let pq_pk = <S::Pq as FixedPqSignatureAlgorithm>::public_key_from_secret(pq_sk);
        S::compose_public_key(&classical_pk, &pq_pk)
    }

    fn sign(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Self::Signature {
        let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
        let (classical_sk, pq_sk) = S::split_secret_key(sk);
        let classical_sig =
            <S::Classical as ClassicalSignatureAlgorithm>::sign(classical_sk, &msg_prime, rng);
        let pq_sig = <S::Pq as FixedPqSignatureAlgorithm>::sign(pq_sk, &msg_prime, rng);
        S::compose_signature(&classical_sig, &pq_sig)
    }

    fn sign_deterministic(
        sk: &Self::SecretKey,
        msg: &[u8],
        ctx: &[u8],
        nonce: &[u8],
    ) -> Self::Signature {
        let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
        let (classical_sk, pq_sk) = S::split_secret_key(sk);
        let classical_sig = <S::Classical as ClassicalSignatureAlgorithm>::sign_deterministic(
            classical_sk,
            &msg_prime,
            nonce,
        );
        let pq_sig =
            <S::Pq as FixedPqSignatureAlgorithm>::sign_deterministic(pq_sk, &msg_prime, nonce);
        S::compose_signature(&classical_sig, &pq_sig)
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool {
        let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
        verify_components::<S>(pk, &msg_prime, sig)
    }

    fn verify_deterministic(
        pk: &Self::PublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &Self::Signature,
        _expected_nonce: &[u8],
    ) -> bool {
        let msg_prime = prepare_message(S::VERSION, S::LABEL, msg, ctx);
        verify_components::<S>(pk, &msg_prime, sig)
    }
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
