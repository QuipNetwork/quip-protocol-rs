use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rand_core::CryptoRngCore;
use sp_core::{sr25519, Pair};
use zeroize::Zeroize;

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 64;

const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";

pub fn from_seed(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let pair = sr25519::Pair::from_seed_slice(seed).expect("32-byte seed is always valid");
    let public = *pair.public().as_array_ref();
    let secret = pair
        .to_raw_vec()
        .try_into()
        .expect("sp_core sr25519 secret key is always 64 bytes");
    (public, secret)
}

pub fn validate_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    schnorrkel::PublicKey::from_bytes(bytes).is_ok()
}

pub fn validate_secret_key(bytes: &[u8; SECRET_KEY_LEN]) -> bool {
    sr25519::Pair::from_seed_slice(bytes).is_ok()
}

pub fn public_key_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let pair = sr25519::Pair::from_seed_slice(secret).expect("stored sr25519 secret key is valid");
    *pair.public().as_array_ref()
}

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

pub fn verify(
    public: &[u8; PUBLIC_KEY_LEN],
    msg_prime: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let public = sr25519::Public::from_raw(*public);
    let signature = sr25519::Signature::from_raw(*signature);
    sr25519::Pair::verify(&signature, msg_prime, &public)
}

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

fn keypair_from_secret(secret: &[u8; SECRET_KEY_LEN]) -> schnorrkel::Keypair {
    schnorrkel::SecretKey::from_bytes(secret)
        .expect("valid sr25519 secret key")
        .to_keypair()
}

fn blake2_256_seed_counter(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed);
    input[32..].copy_from_slice(&counter.to_le_bytes());
    let hash = sp_core::hashing::blake2_256(&input);
    input.zeroize();
    hash
}

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
