//! One-shot helper: print the 32-byte master seeds for the well-known
//! `//Alice` and `//Bob` dev URIs alongside the derived HybridTxSignature
//! public bytes and AccountId. Used by quip-miner's Python parity tests to
//! pin the hybrid keystore against chain-genesis-funded accounts.
//!
//! Run via:
//!     cd quip-protocol-rs/crates/transaction-crypto
//!     cargo run --example dump_dev_seeds --features std

use codec::Encode;
use quip_transaction_crypto::{account_id_from_public, HybridPair};
use sp_core::Pair as _;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn dump(name: &str, uri: &str) {
    let pair = HybridPair::from_string(uri, None).expect("dev URI parses");
    let seed = pair.to_raw_vec();
    let public = pair.public();
    let account = account_id_from_public(&public);

    println!("// {} ({})", name, uri);
    println!("master_seed_hex   = {:?}", hex(&seed));
    println!(
        "public_bytes_hex  = {:?} (len={})",
        hex(public.as_ref()),
        public.as_ref().len()
    );
    println!("account_id_hex    = {:?}", hex(&account.encode()));
    println!();
}

fn main() {
    dump("Alice", "//Alice");
    dump("Bob", "//Bob");
    dump("AliceStash", "//Alice//stash");
}
