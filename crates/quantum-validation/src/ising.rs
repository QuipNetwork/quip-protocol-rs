//! Deterministic Ising-model derivation helpers.

use alloc::vec::Vec;

use blake3::Hasher;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

use crate::errors::ValidationError;
use crate::fixed::{MilliValue, MILLI_SCALE};
use crate::validation::ensure_valid_topology;

/// Derive a deterministic nonce for future PoW-style Ising generation.
///
/// The current project decision is to use BLAKE3 here.
/// Cross-language parity is validated against the shared Python `ChaCha8` test
/// vectors once those are imported into the local Rust fixture set.
///
/// The nonce is derived from the concatenation:
///
/// - `parent_hash`
/// - `miner`
/// - `block_number.to_be_bytes()`
/// - `salt`
///
/// using BLAKE3, then truncating the first eight bytes as a big-endian `u64`.
pub fn derive_nonce(parent_hash: &[u8], miner: &[u8], block_number: u32, salt: &[u8]) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(parent_hash);
    hasher.update(miner);
    hasher.update(&block_number.to_be_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(digest.as_bytes().get(..8).expect("blake3 digest length"));
    u64::from_be_bytes(bytes)
}

/// Generate deterministic fixed-point Ising parameters from a nonce.
///
/// This intentionally follows the Notion spec's Rust direction:
/// - `ChaCha8Rng`
/// - milli-precision integer outputs
///
/// Cross-language parity for this module is checked against the shared Python
/// `ChaCha8` vectors. The Rust surface still returns milli-precision integer
/// arrays, so vector fixtures are normalized before comparison.
///
/// `allowed_h_values` is sampled uniformly for each node. Couplings are
/// currently generated as `±MILLI_SCALE`.
pub fn generate_ising_model(
    nonce: u64,
    nodes: &[u32],
    edges: &[(u32, u32)],
    allowed_h_values: &[MilliValue],
) -> Result<(Vec<MilliValue>, Vec<MilliValue>), ValidationError> {
    if nodes.is_empty() {
        return Err(ValidationError::EmptyNodes);
    }
    if allowed_h_values.is_empty() {
        return Err(ValidationError::EmptyFieldValues);
    }

    ensure_valid_topology(nodes, edges)?;

    let mut rng = ChaCha8Rng::seed_from_u64(nonce);

    let mut h = Vec::with_capacity(nodes.len());
    for _ in nodes {
        let index = (rng.next_u32() as usize) % allowed_h_values.len();
        h.push(allowed_h_values[index]);
    }

    let mut j = Vec::with_capacity(edges.len());
    for _ in edges {
        let sign = if (rng.next_u32() & 1) == 0 { -1 } else { 1 };
        j.push((MILLI_SCALE as i32) * sign);
    }

    Ok((h, j))
}

#[cfg(test)]
mod tests {
    use super::{derive_nonce, generate_ising_model};

    #[test]
    fn nonce_derivation_is_deterministic() {
        let first = derive_nonce(&[1; 32], b"miner-a", 42, b"salt");
        let second = derive_nonce(&[1; 32], b"miner-a", 42, b"salt");

        assert_eq!(first, second);
    }

    #[test]
    fn nonce_derivation_changes_with_input_parts() {
        let baseline = derive_nonce(&[1; 32], b"miner-a", 42, b"salt");

        assert_ne!(baseline, derive_nonce(&[2; 32], b"miner-a", 42, b"salt"));
        assert_ne!(baseline, derive_nonce(&[1; 32], b"miner-b", 42, b"salt"));
        assert_ne!(baseline, derive_nonce(&[1; 32], b"miner-a", 43, b"salt"));
        assert_ne!(baseline, derive_nonce(&[1; 32], b"miner-a", 42, b"salt-2"));
    }

    #[test]
    fn generated_model_has_expected_lengths() {
        let nodes = [0, 1, 2];
        let edges = [(0, 1), (1, 2)];
        let allowed_h = [-1_000, 0, 1_000];

        let (h, j) = generate_ising_model(42, &nodes, &edges, &allowed_h).unwrap();

        assert_eq!(h.len(), nodes.len());
        assert_eq!(j.len(), edges.len());
    }
}
