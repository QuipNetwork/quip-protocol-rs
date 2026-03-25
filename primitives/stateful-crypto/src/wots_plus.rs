//! WOTS+ stateful signature implementation backed by [`hashsigs_rs`].
//!
//! # Scheme overview
//!
//! A WOTS+ Merkle tree of height `h` gives `2^h` one-time signing slots.
//! The off-chain wallet holds a `master_seed` from which all per-leaf OTS
//! private keys are derived deterministically.  An in-memory Merkle tree
//! over the leaf WOTS+ public keys enables O(h) auth-path extraction at
//! signing time.
//!
//! Each signature contains:
//! - the leaf index (8 bytes)
//! - the leaf WOTS+ public key (64 bytes — needed by the verifier to check
//!   both the OTS sig and the Merkle path without trusting storage)
//! - the WOTS+ signature components (~67 × 32 bytes for w = 16)
//! - the Merkle auth path (h × 32 bytes)
//!
//! For `tree_height = 16`, totals ≈ 2.7 KB per signature, matching the
//! ~3 KB estimate in the architecture plan.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::{SignatureError, StatefulSignature};
use codec::{Decode, Encode};
use hashsigs_rs::WOTSPlus;
use scale_info::TypeInfo;
use sp_core::blake2_256;

/// Hash function interface used by the WOTS+ signature scheme. To be removed once hashsigs_rs is updated.
type HashFn = fn(&[u8]) -> [u8; 32];

/// Hash function used by the WOTS+ signature scheme.
const HASH_FN: HashFn = blake2_256;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns a [`WOTSPlus`] instance configured with a hashing function.
fn wots() -> WOTSPlus {
    WOTSPlus::new(HASH_FN)
}

/// Derive the per-leaf OTS seed from `master_seed` and the leaf `index`.
///
/// `leaf_seed = HASH_FN(master_seed ‖ index_le64)`
fn leaf_seed(master_seed: &[u8; 32], index: u64) -> [u8; 32] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(master_seed);
    buf[32..].copy_from_slice(&index.to_le_bytes());
    HASH_FN(&buf)
}

/// Hash a WOTS+ [`PublicKey`](hashsigs_rs::PublicKey) into a 32-byte Merkle leaf.
fn leaf_hash(pk: &hashsigs_rs::PublicKey) -> [u8; 32] {
    HASH_FN(&pk.to_bytes())
}

/// Combine two 32-byte sibling hashes into a parent node.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    HASH_FN(&buf)
}

// ── Raw signature encoding ────────────────────────────────────────────────────

/// Signature components before byte-packing.
struct RawSig {
    leaf_index: u64,
    /// Raw bytes of the leaf [`hashsigs_rs::PublicKey`] (always 64 bytes).
    leaf_pk_bytes: [u8; 64],
    /// WOTS+ signature chains (variable length, 32 bytes each).
    wots_sig: Vec<[u8; 32]>,
    /// Merkle auth path nodes (one per tree level, 32 bytes each).
    auth_path: Vec<[u8; 32]>,
}

impl RawSig {
    /// Serialize to a flat byte vector (little-endian lengths).
    fn to_bytes(&self) -> Vec<u8> {
        let wots_len = self.wots_sig.len() as u32;
        let auth_len = self.auth_path.len() as u32;
        let capacity = 8 + 64 + 4 + (wots_len as usize) * 32 + 4 + (auth_len as usize) * 32;
        let mut out = Vec::with_capacity(capacity);

        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&self.leaf_pk_bytes);
        out.extend_from_slice(&wots_len.to_le_bytes());
        for chunk in &self.wots_sig {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&auth_len.to_le_bytes());
        for node in &self.auth_path {
            out.extend_from_slice(node);
        }
        out
    }

    /// Deserialise from a flat byte slice.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let min_header = 8 + 64 + 4;
        if bytes.len() < min_header {
            return None;
        }
        let mut cur = 0usize;

        let leaf_index = u64::from_le_bytes(bytes[cur..cur + 8].try_into().ok()?);
        cur += 8;

        let leaf_pk_bytes: [u8; 64] = bytes[cur..cur + 64].try_into().ok()?;
        cur += 64;

        let wots_len = u32::from_le_bytes(bytes[cur..cur + 4].try_into().ok()?) as usize;
        cur += 4;
        if bytes.len() < cur + wots_len * 32 + 4 {
            return None;
        }
        let mut wots_sig = Vec::with_capacity(wots_len);
        Self::push_chunks(bytes, &mut cur, wots_len, &mut wots_sig)?;

        let auth_len = u32::from_le_bytes(bytes[cur..cur + 4].try_into().ok()?) as usize;
        cur += 4;
        if bytes.len() < cur + auth_len * 32 {
            return None;
        }
        let mut auth_path = Vec::with_capacity(auth_len);
        Self::push_chunks(bytes, &mut cur, auth_len, &mut auth_path)?;

        Some(Self {
            leaf_index,
            leaf_pk_bytes,
            wots_sig,
            auth_path,
        })
    }

    fn push_chunks(
        bytes: &[u8],
        current_idx: &mut usize,
        dest_len: usize,
        dest: &mut Vec<[u8; 32]>,
    ) -> Option<()> {
        for _ in 0..dest_len {
            let chunk: [u8; 32] = bytes[*current_idx..*current_idx + 32].try_into().ok()?;
            dest.push(chunk);
            *current_idx += 32;
        }
        Some(())
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// WOTS+ Merkle public key: 32-byte root ‖ 1-byte tree height.
///
/// The tree height determines the total OTS capacity (`2^height` signings).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct WotsPlusPublicKey([u8; 33]);

impl WotsPlusPublicKey {
    fn new(root: [u8; 32], tree_height: u8) -> Self {
        let mut inner = [0u8; 33];
        inner[..32].copy_from_slice(&root);
        inner[32] = tree_height;
        Self(inner)
    }

    /// The Merkle root over all leaf WOTS+ public key hashes.
    pub fn merkle_root(&self) -> &[u8; 32] {
        self.0[..32].try_into().expect("slice is exactly 32 bytes")
    }

    /// Height of the Merkle tree; capacity = `2^tree_height`.
    pub fn tree_height(&self) -> u8 {
        self.0[32]
    }
}

impl AsRef<[u8]> for WotsPlusPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// WOTS+ signature: a variable-length byte blob encoding the leaf index,
/// leaf public key, OTS chains, and Merkle auth path.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct WotsPlusSignature(Vec<u8>);

impl AsRef<[u8]> for WotsPlusSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// On-chain signature state — tracks the next OTS index and tree height.
///
/// This is stored in the identity registry pallet and updated after every
/// successful transaction.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct WotsPlusState {
    /// Next leaf index to be used.  Monotonically increasing; never decreases.
    pub current_index: u64,
    /// Merkle tree height (immutable after identity registration).
    pub tree_height: u8,
}

/// Off-chain secret key.
///
/// Holds the master seed and a precomputed Merkle tree so auth-paths can be
/// extracted in O(tree_height) time without re-hashing the entire tree.
///
/// **Security**: back this up securely.  Losing `master_seed` makes the
/// identity permanently unable to sign new transactions.
pub struct WotsPlusSecretKey {
    pub master_seed: [u8; 32],
    pub tree_height: u8,
    /// 1-indexed binary Merkle tree.
    /// - Index `1` = root
    /// - Leaves at indices `2^tree_height .. 2^(tree_height+1)`
    /// - Total length = `2 * 2^tree_height`
    pub(crate) tree_nodes: Vec<[u8; 32]>,
}

// ── Merkle tree helpers ───────────────────────────────────────────────────────

/// Build a 1-indexed binary Merkle tree over WOTS+ leaf public keys.
///
/// Returns `(secret_key, public_key, initial_state)`.
fn build_tree(
    master_seed: [u8; 32],
    tree_height: u8,
) -> (WotsPlusSecretKey, WotsPlusPublicKey, WotsPlusState) {
    let w = wots();
    let num_leaves: usize = 1 << tree_height;
    let total_nodes = 2 * num_leaves; // indices 0..total_nodes; index 0 unused

    let mut nodes = vec![[0u8; 32]; total_nodes];

    // Derive and hash every leaf WOTS+ public key.
    for i in 0..num_leaves {
        let seed = leaf_seed(&master_seed, i as u64);
        let (pk, _) = w.generate_key_pair(&seed);
        nodes[num_leaves + i] = leaf_hash(&pk);
    }

    // Build internal nodes bottom-up.
    for i in (1..num_leaves).rev() {
        nodes[i] = node_hash(&nodes[2 * i], &nodes[2 * i + 1]);
    }

    let root = nodes[1];
    (
        WotsPlusSecretKey {
            master_seed,
            tree_height,
            tree_nodes: nodes,
        },
        WotsPlusPublicKey::new(root, tree_height),
        WotsPlusState {
            current_index: 0,
            tree_height,
        },
    )
}

/// Extract the Merkle auth path for `leaf_index` from a precomputed tree.
fn extract_auth_path(nodes: &[[u8; 32]], leaf_index: u64, tree_height: u8) -> Vec<[u8; 32]> {
    let num_leaves: usize = 1 << tree_height;
    let mut path = Vec::with_capacity(tree_height as usize);
    let mut idx = num_leaves + leaf_index as usize;

    for _ in 0..tree_height {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push(nodes[sibling]);
        idx /= 2;
    }
    path
}

/// Recompute the Merkle root from a leaf hash and its auth path.
fn recompute_root(leaf_hash: [u8; 32], auth_path: &[[u8; 32]], leaf_index: u64) -> [u8; 32] {
    let mut current = leaf_hash;
    let mut idx = leaf_index;

    for sibling in auth_path {
        current = if idx % 2 == 0 {
            node_hash(&current, sibling) // current is left child
        } else {
            node_hash(sibling, &current) // current is right child
        };
        idx >>= 1;
    }
    current
}

// ── StatefulSignature impl ────────────────────────────────────────────────────

/// Marker type wiring [`WotsPlus`] associated types into the
/// [`StatefulSignature`] trait.
pub struct WotsPlus;

impl StatefulSignature for WotsPlus {
    type PublicKey = WotsPlusPublicKey;
    type Signature = WotsPlusSignature;
    type SecretKey = WotsPlusSecretKey;
    type State = WotsPlusState;

    /// Generate a new keypair with the default tree height of 16
    /// (`2^16 = 65 536` available one-time signings).
    ///
    /// **Note**: this function requires an entropy source.  In std contexts it
    /// uses the system time as a weak seed — use [`WotsPlus::generate_from_seed`]
    /// with cryptographically secure randomness in production.
    fn generate() -> (Self::SecretKey, Self::PublicKey, Self::State) {
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            // Weak seed — replace with a CSPRNG (e.g. `rand::rngs::OsRng`) in production.
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let master_seed = HASH_FN(&nanos.to_le_bytes());
            build_tree(master_seed, 16)
        }
        #[cfg(not(feature = "std"))]
        panic!(
            "WotsPlus::generate() is unavailable in no_std — \
             call WotsPlus::generate_from_seed(seed, height) with entropy \
             from sp_io::crypto::random_seed() or your wallet's RNG."
        )
    }

    fn sign(
        secret: &Self::SecretKey,
        state: &mut Self::State,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError> {
        if !Self::has_remaining_keys(state) {
            return Err(SignatureError::KeysExhausted);
        }

        let index = state.current_index;
        let w = wots();

        // Derive the leaf OTS key pair deterministically.
        let seed = leaf_seed(&secret.master_seed, index);
        let (pk, priv_key) = w.generate_key_pair(&seed);

        // WOTS+ operates on a fixed 32-byte input; hash the message first.
        let msg_hash = HASH_FN(message);
        let wots_sig = w.sign(&priv_key, &msg_hash);

        // Include the leaf public key so the verifier can check both the OTS
        // signature and the Merkle path without trusting any external state.
        let leaf_pk_bytes = pk.to_bytes();

        // Extract the auth path for this leaf from the precomputed tree.
        let auth_path = extract_auth_path(&secret.tree_nodes, index, state.tree_height);

        // Advance the state AFTER all fallible operations succeed.
        state.current_index += 1;

        Ok(WotsPlusSignature(
            RawSig {
                leaf_index: index,
                leaf_pk_bytes,
                wots_sig,
                auth_path,
            }
            .to_bytes(),
        ))
    }

    fn verify(
        public: &Self::PublicKey,
        signature: &Self::Signature,
        message: &[u8],
        state_index: u64,
    ) -> bool {
        let raw = match RawSig::from_bytes(signature.as_ref()) {
            Some(r) => r,
            None => return false,
        };

        // The leaf index in the signature must match what the registry expects.
        if raw.leaf_index != state_index {
            return false;
        }

        // Auth path length must match the tree height encoded in the public key.
        if raw.auth_path.len() != public.tree_height() as usize {
            return false;
        }

        // Parse the leaf WOTS+ public key embedded in the signature.
        let leaf_pk = match hashsigs_rs::PublicKey::from_bytes(&raw.leaf_pk_bytes) {
            Some(pk) => pk,
            None => return false,
        };

        let w = wots();

        // Step 1: verify the WOTS+ OTS signature against the leaf public key.
        let msg_hash = HASH_FN(message);
        if !w.verify(&leaf_pk, &msg_hash, &raw.wots_sig) {
            return false;
        }

        // Step 2: verify the Merkle path from the leaf to the on-chain root.
        let lh = leaf_hash(&leaf_pk);
        let recomputed = recompute_root(lh, &raw.auth_path, raw.leaf_index);
        &recomputed == public.merkle_root()
    }

    fn current_index(state: &Self::State) -> u64 {
        state.current_index
    }

    fn has_remaining_keys(state: &Self::State) -> bool {
        state.current_index < (1u64 << state.tree_height)
    }

    fn total_keys(state: &Self::State) -> u64 {
        1u64 << state.tree_height
    }
}

impl WotsPlus {
    /// Generate a keypair from an explicit entropy seed and tree height.
    ///
    /// | `tree_height` | OTS capacity | Approx. key-gen time |
    /// |---------------|-------------|----------------------|
    /// | 10            | 1 024       | fast (testing)       |
    /// | 16            | 65 536      | ~seconds (default)   |
    /// | 20            | 1 048 576   | ~minutes (high vol.) |
    ///
    /// `master_seed` must come from a cryptographically secure RNG.
    pub fn generate_from_seed(
        master_seed: [u8; 32],
        tree_height: u8,
    ) -> (WotsPlusSecretKey, WotsPlusPublicKey, WotsPlusState) {
        build_tree(master_seed, tree_height)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatefulSignature;

    /// Use a small tree for fast test execution.
    const TEST_HEIGHT: u8 = 4; // 16 OTS keys

    fn test_keypair() -> (WotsPlusSecretKey, WotsPlusPublicKey, WotsPlusState) {
        let seed = HASH_FN(b"quip-protocol-test-seed");
        WotsPlus::generate_from_seed(seed, TEST_HEIGHT)
    }

    #[test]
    fn sign_and_verify_basic() {
        let (sk, pk, mut state) = test_keypair();
        let msg = b"hello quip";

        let sig = WotsPlus::sign(&sk, &mut state, msg).expect("sign must succeed");
        assert!(WotsPlus::verify(&pk, &sig, msg, 0), "signature must verify");
    }

    #[test]
    fn state_advances_after_sign() {
        let (sk, _, mut state) = test_keypair();
        assert_eq!(WotsPlus::current_index(&state), 0);
        WotsPlus::sign(&sk, &mut state, b"tx1").unwrap();
        assert_eq!(WotsPlus::current_index(&state), 1);
    }

    #[test]
    fn wrong_state_index_rejects() {
        let (sk, pk, mut state) = test_keypair();
        let sig = WotsPlus::sign(&sk, &mut state, b"tx").unwrap();
        // state_index = 1 (already advanced), but signature carries leaf_index = 0
        assert!(
            !WotsPlus::verify(&pk, &sig, b"tx", 1),
            "wrong index must fail"
        );
    }

    #[test]
    fn wrong_message_rejects() {
        let (sk, pk, mut state) = test_keypair();
        let sig = WotsPlus::sign(&sk, &mut state, b"correct").unwrap();
        assert!(
            !WotsPlus::verify(&pk, &sig, b"tampered", 0),
            "wrong message must fail"
        );
    }

    #[test]
    fn multiple_sequential_signings() {
        let (sk, pk, mut state) = test_keypair();
        for i in 0..4u64 {
            let msg = format!("tx-{}", i);
            let sig = WotsPlus::sign(&sk, &mut state, msg.as_bytes()).unwrap();
            assert!(WotsPlus::verify(&pk, &sig, msg.as_bytes(), i));
        }
    }

    #[test]
    fn exhausted_key_returns_error() {
        let seed = HASH_FN(b"exhaustion-test");
        let (sk, _, mut state) = WotsPlus::generate_from_seed(seed, 1); // 2 keys only
        WotsPlus::sign(&sk, &mut state, b"a").unwrap();
        WotsPlus::sign(&sk, &mut state, b"b").unwrap();
        let err = WotsPlus::sign(&sk, &mut state, b"c").unwrap_err();
        assert_eq!(err, crate::SignatureError::KeysExhausted);
    }

    #[test]
    fn has_remaining_keys() {
        let seed = HASH_FN(b"remaining-test");
        let (sk, _, mut state) = WotsPlus::generate_from_seed(seed, 1); // 2 keys
        assert!(WotsPlus::has_remaining_keys(&state));
        WotsPlus::sign(&sk, &mut state, b"1").unwrap();
        assert!(WotsPlus::has_remaining_keys(&state));
        WotsPlus::sign(&sk, &mut state, b"2").unwrap();
        assert!(!WotsPlus::has_remaining_keys(&state));
    }
}
