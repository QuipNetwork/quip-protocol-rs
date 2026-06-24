//! Golden-vector parity gate.
//!
//! `golden_vectors.txt` was captured from the signer's byte output **before**
//! the hybrid-crypto deduplication refactor (the move of the H3 suite into the
//! shared `quip-crypto-primitives-core` crate). This test asserts the current
//! implementation still reproduces those exact bytes, so the suite that the
//! browser signs with and the suite the runtime verifies with can never
//! silently drift apart.
//!
//! Vectors cover `seed -> public_key` and `(seed, msg) -> signature envelope`
//! for several fixed seeds plus a BIP39-derived seed.

use quip_transaction_crypto_core::{
    master_seed_from_mnemonic, public_key_from_seed, sign_payload_from_seed,
};

const FIXTURE: &str = include_str!("golden_vectors.txt");

const TEST_PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

fn lookup<'a>(key: &str) -> &'a str {
    for line in FIXTURE.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once('=').expect("fixture line is `name=value`");
        if name == key {
            // Leak-free: FIXTURE is 'static, so the slice is too.
            return value;
        }
    }
    panic!("fixture missing key `{key}`");
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn assert_public(name: &str, seed: &[u8]) {
    // Sanity: the recorded seed matches what we feed in.
    assert_eq!(
        to_hex(seed),
        lookup(&format!("{name}_seed")),
        "{name}: seed bytes drifted from fixture"
    );
    let public = public_key_from_seed(seed).expect("public derivation");
    assert_eq!(
        to_hex(&public),
        lookup(&format!("{name}_public")),
        "{name}: public key drifted from pre-refactor bytes"
    );
}

fn assert_envelope(seed_name: &str, seed: &[u8], msg_name: &str, msg: &[u8]) {
    let envelope = sign_payload_from_seed(seed, msg).expect("signing");
    assert_eq!(
        to_hex(&envelope.encode_envelope()),
        lookup(&format!("{seed_name}_{msg_name}_envelope")),
        "{seed_name}/{msg_name}: signature envelope drifted from pre-refactor bytes"
    );
}

#[test]
fn public_keys_match_pre_refactor_baseline() {
    assert_public("seed_01", &[1u8; 32]);
    assert_public("seed_07", &[7u8; 32]);
    assert_public("seed_09", &[9u8; 32]);
    assert_public("seed_11", &[11u8; 32]);

    let bip39 = master_seed_from_mnemonic(TEST_PHRASE, None).unwrap();
    assert_public("bip39", &bip39);

    let bip39_pw = master_seed_from_mnemonic(TEST_PHRASE, Some("hunter2")).unwrap();
    assert_public("bip39_pw", &bip39_pw);
}

#[test]
fn signature_envelopes_match_pre_refactor_baseline() {
    let messages: [(&str, &[u8]); 3] = [
        ("msg_quip", b"quip-message"),
        ("msg_empty", b""),
        ("msg_fixture", b"quip-signer-fixture"),
    ];

    let bip39 = master_seed_from_mnemonic(TEST_PHRASE, None).unwrap();
    for (mname, msg) in &messages {
        assert_envelope("seed_07", &[7u8; 32], mname, msg);
        assert_envelope("bip39", &bip39, mname, msg);
    }
}
