//! Seed-derivation helpers shared by all hybrid suites.
//!
//! A hybrid suite starts from one 32-byte master seed and expands it into one
//! classical component seed plus one PQ component seed. Keeping this logic in a
//! separate module avoids coupling the algorithm traits to any specific suite
//! module.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{HybridSignatureError, Result};

/// Length in bytes of the hybrid master seed.
pub const MASTER_SEED_LEN: usize = 32;

const HKDF_SALT: &[u8] = b"hybrid-sig";
const HKDF_CLASSICAL_INFO: &[u8] = b"classical";
const HKDF_PQ_INFO: &[u8] = b"pq";

/// Expand a single 32-byte master seed into classical and PQ component seeds.
///
/// Seed expansion uses HKDF-SHA256 with fixed domain strings so the two
/// component seeds are deterministic and domain-separated from one another.
pub fn derive_component_seeds(
    seed: &[u8],
    classical_seed: &mut [u8; MASTER_SEED_LEN],
    pq_seed: &mut [u8; MASTER_SEED_LEN],
) -> Result<()> {
    if seed.len() != MASTER_SEED_LEN {
        return Err(HybridSignatureError::InvalidSeedLength {
            expected: MASTER_SEED_LEN,
            actual: seed.len(),
        });
    }

    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    hkdf.expand(HKDF_CLASSICAL_INFO, classical_seed)
        .expect("32-byte HKDF expansion is always valid");
    hkdf.expand(HKDF_PQ_INFO, pq_seed)
        .expect("32-byte HKDF expansion is always valid");
    Ok(())
}
