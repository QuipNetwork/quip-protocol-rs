#![cfg_attr(not(feature = "std"), no_std)]

//! Pure transaction/account identity helpers for Quip's hybrid signer.
//!
//! This crate is intentionally bytes-oriented:
//! - it derives compact 32-byte account ids from hybrid public bytes
//! - it signs raw payload bytes with the H3 suite
//! - it encodes/decodes the runtime signature envelope as raw bytes
//!
//! It does not depend on runtime traits or `sp_io`.

extern crate alloc;

use alloc::vec::Vec;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use codec::{Decode, DecodeWithMemTracking, Encode};
use quip_crypto_primitives::{
    suite::sr25519_mldsa44::{
        PublicKey as H3PublicKey, SecretKey as H3SecretKey, Signature as H3Signature,
        HYBRID_PK_LEN, HYBRID_SIG_LEN,
    },
    HybridSignatureError, HybridSignatureScheme, Result as HybridResult, Sr25519MlDsa44,
};

/// Serialized H3 public-key length in bytes.
pub const HYBRID_PUBLIC_LEN: usize = HYBRID_PK_LEN;
/// Serialized H3 signature length in bytes.
pub const HYBRID_SIGNATURE_LEN: usize = HYBRID_SIG_LEN;
/// Fixed length of derived Quip account ids.
pub const ACCOUNT_ID_LEN: usize = 32;

/// Domain separator for account-id derivation from the hybrid public key.
pub const ACCOUNT_ID_DOMAIN: &[u8] = b"quip-account-v1";

/// Bytes-level transaction signature envelope.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Encode, Decode, DecodeWithMemTracking)]
pub struct HybridTxSignatureBytes {
    pub public: [u8; HYBRID_PUBLIC_LEN],
    pub signature: [u8; HYBRID_SIGNATURE_LEN],
}

impl HybridTxSignatureBytes {
    /// Creates a bytes-level envelope after validating the input lengths and encodings.
    pub fn new(public: &[u8], signature: &[u8]) -> HybridResult<Self> {
        let public = H3PublicKey::from_bytes(public)?.to_bytes();
        let signature = H3Signature::from_bytes(signature)?.to_bytes();

        Ok(Self { public, signature })
    }

    /// Returns the derived compact account id for the embedded public key.
    pub fn derived_account_id(&self) -> [u8; ACCOUNT_ID_LEN] {
        account_id_from_public_bytes(&self.public)
    }

    /// Verifies the embedded signature against the provided raw message bytes.
    pub fn verify(&self, message: &[u8]) -> bool {
        let Ok(public) = H3PublicKey::from_bytes(&self.public) else {
            return false;
        };
        let Ok(signature) = H3Signature::from_bytes(&self.signature) else {
            return false;
        };

        Sr25519MlDsa44::verify(&public, message, b"", &signature)
    }

    /// SCALE-encodes the bytes-level envelope.
    pub fn encode_envelope(&self) -> Vec<u8> {
        self.encode()
    }

    /// Decodes a SCALE-encoded bytes-level envelope.
    pub fn decode_envelope(bytes: &[u8]) -> HybridResult<Self> {
        let decoded =
            Self::decode(&mut &bytes[..]).map_err(|_| HybridSignatureError::InvalidLength {
                expected: HYBRID_PUBLIC_LEN + HYBRID_SIGNATURE_LEN,
                actual: bytes.len(),
            })?;
        Self::new(&decoded.public, &decoded.signature)
    }
}

/// Derives the compact Quip account id from serialized H3 public bytes.
pub fn account_id_from_public_bytes(public: &[u8]) -> [u8; ACCOUNT_ID_LEN] {
    let mut hasher = Blake2bVar::new(ACCOUNT_ID_LEN).expect("32-byte Blake2 output is valid");
    hasher.update(ACCOUNT_ID_DOMAIN);
    hasher.update(public);

    let mut out = [0u8; ACCOUNT_ID_LEN];
    hasher
        .finalize_variable(&mut out)
        .expect("output length matches buffer");
    out
}

/// Signs raw payload bytes with a 32-byte H3 master seed and returns the bytes-level envelope.
pub fn sign_payload_from_seed(seed: &[u8], payload: &[u8]) -> HybridResult<HybridTxSignatureBytes> {
    let (secret, public) = Sr25519MlDsa44::from_seed_slice(seed)?;
    sign_payload_from_secret(&secret, &public, payload)
}

/// Signs raw payload bytes with an expanded H3 secret key and matching public key.
pub fn sign_payload_from_secret(
    secret: &H3SecretKey,
    public: &H3PublicKey,
    payload: &[u8],
) -> HybridResult<HybridTxSignatureBytes> {
    let signature = Sr25519MlDsa44::sign_deterministic(secret, payload, b"", b"");

    HybridTxSignatureBytes::new(&public.to_bytes(), &signature.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_domain_is_pinned() {
        assert_eq!(ACCOUNT_ID_DOMAIN, b"quip-account-v1");
    }

    #[test]
    fn same_public_key_derives_same_account_id() {
        let (secret, public) = Sr25519MlDsa44::from_seed_slice(&[1u8; 32]).unwrap();
        let _ = secret;
        let first = account_id_from_public_bytes(public.as_ref());
        let second = account_id_from_public_bytes(public.as_ref());

        assert_eq!(first, second);
    }

    #[test]
    fn different_public_keys_derive_different_account_ids() {
        let (_, alice) = Sr25519MlDsa44::from_seed_slice(&[1u8; 32]).unwrap();
        let (_, bob) = Sr25519MlDsa44::from_seed_slice(&[2u8; 32]).unwrap();

        assert_ne!(
            account_id_from_public_bytes(alice.as_ref()),
            account_id_from_public_bytes(bob.as_ref())
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let envelope = sign_payload_from_seed(&[7u8; 32], b"quip-message").unwrap();
        assert!(envelope.verify(b"quip-message"));
        assert!(!envelope.verify(b"wrong-message"));
    }

    #[test]
    fn envelope_round_trips_through_scale() {
        let envelope = sign_payload_from_seed(&[9u8; 32], b"quip-message").unwrap();
        let encoded = envelope.encode_envelope();
        let decoded = HybridTxSignatureBytes::decode_envelope(&encoded).unwrap();

        assert_eq!(decoded, envelope);
        assert!(decoded.verify(b"quip-message"));
    }

    #[test]
    fn envelope_decode_rejects_empty_bytes() {
        assert!(HybridTxSignatureBytes::decode_envelope(&[]).is_err());
    }

    #[test]
    fn tampered_signature_rejects() {
        let mut envelope = sign_payload_from_seed(&[11u8; 32], b"quip-message").unwrap();
        envelope.signature[envelope.signature.len() / 2] ^= 0xFF;

        assert!(!envelope.verify(b"quip-message"));
    }
}
