//! sr25519 backend used by the hybrid signature engine.
//!
//! Key encoding matches the hybrid specification:
//! - seed: 32 bytes
//! - public key: 32 bytes
//! - secret key: 64 bytes in Substrate's raw sr25519 encoding
//! - signature: 64 bytes
//!
//! This backend exposes two signing modes:
//! - [`sign`] performs hedged signing by feeding caller-provided randomness into
//!   schnorrkel's transcript RNG.
//! - [`sign_deterministic`] derives a deterministic RNG stream from
//!   `H(secret || nonce || msg_prime)` and then signs through the same
//!   transcript-based path.
//!
//! The signing context is fixed to the Substrate `b"substrate"` context so
//! verification remains compatible with Substrate's sr25519 primitives.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rand_core::CryptoRngCore;
use sp_core::{sr25519, Pair};
use zeroize::Zeroize;

/// Length in bytes of an sr25519 mini-secret seed.
pub const SEED_LEN: usize = 32;
/// Length in bytes of a serialized sr25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of Substrate's raw sr25519 secret key encoding.
pub const SECRET_KEY_LEN: usize = 64;
/// Length in bytes of an sr25519 signature.
pub const SIGNATURE_LEN: usize = 64;

const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";

/// Derives an sr25519 keypair from a 32-byte seed.
///
/// Returns the public key plus the 64-byte raw secret-key encoding emitted by
/// `sp_core::sr25519::Pair::to_raw_vec()`.
pub fn from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let pair = sr25519::Pair::from_seed_slice(seed).expect("32-byte seed is always valid");
    let public = *pair.public().as_array_ref();
    let secret = pair
        .to_raw_vec()
        .try_into()
        .expect("sp_core sr25519 secret key is always 64 bytes");
    (public, secret)
}

/// Validates a serialized sr25519 public key.
pub fn validate_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    schnorrkel::PublicKey::from_bytes(bytes).is_ok()
}

/// Validates a serialized sr25519 secret key.
pub fn validate_secret_key(bytes: &[u8; SECRET_KEY_LEN]) -> bool {
    sr25519::Pair::from_seed_slice(bytes).is_ok()
}

/// Derives the sr25519 public key from serialized secret-key bytes.
pub fn public_key_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let pair = sr25519::Pair::from_seed_slice(secret).expect("stored sr25519 secret key is valid");
    *pair.public().as_array_ref()
}

/// Signs `msg_prime` with hedged sr25519 signing.
///
/// The supplied RNG is attached to the schnorrkel signing transcript and is
/// used to derive the internal nonce stream.
pub fn sign(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    rng: &mut impl CryptoRngCore,
) -> [u8; SIGNATURE_LEN] {
    let keypair = keypair_from_secret(secret);
    let transcript = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(SUBSTRATE_SIGNING_CONTEXT).bytes(msg_prime),
        rng,
    );
    keypair.sign(transcript).to_bytes()
}

/// Signs `msg_prime` with deterministic sr25519 signing.
///
/// Determinism is implemented by hashing `secret || nonce || msg_prime` into a
/// 32-byte seed and expanding it with the internal [`Blake2Rng`]. That derived
/// RNG is then attached to the schnorrkel signing transcript.
pub fn sign_deterministic(
    secret: &[u8; SECRET_KEY_LEN],
    msg_prime: &[u8],
    nonce: &[u8],
) -> [u8; SIGNATURE_LEN] {
    let rng_seed = blake2_256_secret_parts(&[secret.as_ref(), nonce, msg_prime]);
    let keypair = keypair_from_secret(secret);
    let mut det_rng = Blake2Rng::new(rng_seed);
    let transcript = schnorrkel::context::attach_rng(
        schnorrkel::signing_context(SUBSTRATE_SIGNING_CONTEXT).bytes(msg_prime),
        &mut det_rng,
    );
    keypair.sign(transcript).to_bytes()
}

/// Verifies an sr25519 signature over the already domain-separated message.
pub fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    msg_prime: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let public = sr25519::Public::from_raw(*public);
    let signature = sr25519::Signature::from_raw(*signature);
    sr25519::Pair::verify(&signature, msg_prime, &public)
}

/// Small deterministic RNG used by sr25519 deterministic signing.
///
/// It expands a 32-byte seed into an arbitrary number of bytes by hashing
/// `seed || counter` with BLAKE2 and concatenating the 32-byte blocks.
struct Blake2Rng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl Blake2Rng {
    fn new(seed: [u8; 32]) -> Self {
        let buf = blake2_256_seed_counter(&seed, 0);
        Blake2Rng {
            seed,
            counter: 0,
            buf,
            pos: 0,
        }
    }
}

impl rand_core::RngCore for Blake2Rng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            if self.pos >= 32 {
                self.counter += 1;
                self.buf = blake2_256_seed_counter(&self.seed, self.counter);
                self.pos = 0;
            }

            let take = core::cmp::min(32 - self.pos, dest.len() - offset);
            dest[offset..offset + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Blake2Rng {}

/// Reconstructs a schnorrkel keypair from serialized sr25519 secret key bytes.
fn keypair_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> schnorrkel::Keypair {
    schnorrkel::SecretKey::from_bytes(secret)
        .expect("valid sr25519 secret key")
        .to_keypair()
}

/// Computes `blake2_256(seed || counter_le)`.
fn blake2_256_seed_counter(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&counter.to_le_bytes());
    let hash = sp_core::hashing::blake2_256(&input);
    input.zeroize();
    hash
}

/// Computes a 32-byte BLAKE2 hash over a list of secret and public byte slices.
///
/// This helper hashes incrementally to avoid allocating a temporary buffer that
/// would duplicate secret material on the heap.
fn blake2_256_secret_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2b output is valid");
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output length matches buffer");
    out
}
