// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    AccountId, BalancesConfig, RuntimeGenesisConfig, SudoConfig, BABE_GENESIS_EPOCH_CONFIG,
};
use alloc::{vec, vec::Vec};
use frame_support::build_struct_json_patch;
use quip_crypto_primitives::substrate::ed25519_mldsa44::{
    Pair as HybridGrandpaPair, Public as HybridGrandpaPublic,
};
use quip_crypto_primitives::substrate::sr25519_mldsa44::{
    Pair as HybridBabePair, Public as HybridBabePublic,
};
use quip_transaction_crypto::{account_id_from_public, HybridPair as HybridTxPair};
use serde_json::Value;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::crypto::ByteArray;
use sp_core::Pair as _;
use sp_genesis_builder::{self, PresetId};
use sp_keyring::Ed25519Keyring;
use sp_keyring::Sr25519Keyring;

pub const LOCAL_THREE_VALIDATOR_RUNTIME_PRESET: &str = "local_three_validator";

/// Identifier for the public quip-testnet genesis preset.
///
/// The raw chain spec exported from this preset is the canonical
/// `quip-testnet.json` published by `nodes.quip.network`. The preset itself
/// is kept in the binary so the genesis can be re-derived and audited.
pub const QUIP_TESTNET_RUNTIME_PRESET: &str = "quip_testnet";

fn babe_authority_from_seed(seed: &str) -> BabeId {
    HybridBabePair::from_string(seed, None)
        .expect("well-known dev seeds are valid for hybrid BABE authorities")
        .public()
        .into()
}

fn grandpa_authority_from_seed(seed: &str) -> GrandpaId {
    HybridGrandpaPair::from_string(seed, None)
        .expect("well-known dev seeds are valid for hybrid GRANDPA authorities")
        .public()
        .into()
}

fn tx_account_from_seed(seed: &str) -> AccountId {
    let pair = HybridTxPair::from_string(seed, None)
        .expect("well-known dev seeds are valid for hybrid transaction accounts");
    account_id_from_public(&pair.public())
}

/// Parse a hex string (with or without `0x` prefix, leading/trailing whitespace
/// from `include_str!`-loaded files is tolerated) into the raw byte vector.
fn decode_hex(hex: &str) -> Vec<u8> {
    sp_core::bytes::from_hex(hex.trim()).expect("static hex constant is well-formed")
}

/// Build a BABE authority id from raw hybrid public key bytes.
///
/// The bytes must be the SCALE-encoded `sr25519_mldsa44::Public` (sr25519 32-byte
/// prefix followed by the ML-DSA-44 public key). Used by [`quip_testnet_config_genesis`]
/// to commit operator-submitted public material directly into genesis.
fn babe_authority_from_public_hex(hex: &str) -> BabeId {
    HybridBabePublic::from_slice(&decode_hex(hex))
        .expect("static testnet operator BABE public bytes have the expected length")
        .into()
}

/// Build a GRANDPA authority id from raw hybrid public key bytes.
fn grandpa_authority_from_public_hex(hex: &str) -> GrandpaId {
    HybridGrandpaPublic::from_slice(&decode_hex(hex))
        .expect("static testnet operator GRANDPA public bytes have the expected length")
        .into()
}

/// Build a transaction account id from its 32-byte raw hex (the `tx_account_hex`
/// emitted by `derive_genesis_keys`).
fn tx_account_from_hex(hex: &str) -> AccountId {
    let bytes = decode_hex(hex);
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("static testnet operator tx account is exactly 32 bytes");
    AccountId::new(array)
}

// Returns the genesis config presets populated with given parameters.
fn testnet_genesis(
    initial_authorities: Vec<(BabeId, GrandpaId)>,
    endowed_accounts: Vec<AccountId>,
    root: AccountId,
) -> Value {
    build_struct_json_patch!(RuntimeGenesisConfig {
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1u128 << 60))
                .collect::<Vec<_>>(),
        },
        babe: pallet_babe::GenesisConfig {
            authorities: initial_authorities
                .iter()
                .map(|x| (x.0.clone(), 1))
                .collect::<Vec<_>>(),
            epoch_config: BABE_GENESIS_EPOCH_CONFIG,
            ..Default::default()
        },
        grandpa: pallet_grandpa::GenesisConfig {
            authorities: initial_authorities
                .iter()
                .map(|x| (x.1.clone(), 1))
                .collect::<Vec<_>>(),
        },
        sudo: SudoConfig { key: Some(root) },
    })
}

/// Return the development genesis config.
pub fn development_config_genesis() -> Value {
    testnet_genesis(
        vec![(
            babe_authority_from_seed(&Sr25519Keyring::Alice.to_seed()),
            grandpa_authority_from_seed(&Ed25519Keyring::Alice.to_seed()),
        )],
        vec![
            tx_account_from_seed(&Sr25519Keyring::Alice.to_seed()),
            tx_account_from_seed(&Sr25519Keyring::Bob.to_seed()),
            tx_account_from_seed(&Sr25519Keyring::AliceStash.to_seed()),
            tx_account_from_seed(&Sr25519Keyring::BobStash.to_seed()),
        ],
        tx_account_from_seed(&Sr25519Keyring::Alice.to_seed()),
    )
}

/// Return the local genesis config preset.
pub fn local_config_genesis() -> Value {
    testnet_genesis(
        vec![
            (
                babe_authority_from_seed(&Sr25519Keyring::Alice.to_seed()),
                grandpa_authority_from_seed(&Ed25519Keyring::Alice.to_seed()),
            ),
            (
                babe_authority_from_seed(&Sr25519Keyring::Bob.to_seed()),
                grandpa_authority_from_seed(&Ed25519Keyring::Bob.to_seed()),
            ),
        ],
        Sr25519Keyring::iter()
            .filter(|v| v != &Sr25519Keyring::One && v != &Sr25519Keyring::Two)
            .map(|v| tx_account_from_seed(&v.to_seed()))
            .collect::<Vec<_>>(),
        tx_account_from_seed(&Sr25519Keyring::Alice.to_seed()),
    )
}

/// Return the three-validator local genesis config preset.
pub fn local_three_validator_config_genesis() -> Value {
    testnet_genesis(
        vec![
            (
                babe_authority_from_seed(&Sr25519Keyring::Alice.to_seed()),
                grandpa_authority_from_seed(&Ed25519Keyring::Alice.to_seed()),
            ),
            (
                babe_authority_from_seed(&Sr25519Keyring::Bob.to_seed()),
                grandpa_authority_from_seed(&Ed25519Keyring::Bob.to_seed()),
            ),
            (
                babe_authority_from_seed(&Sr25519Keyring::Charlie.to_seed()),
                grandpa_authority_from_seed(&Ed25519Keyring::Charlie.to_seed()),
            ),
        ],
        Sr25519Keyring::iter()
            .filter(|v| v != &Sr25519Keyring::One && v != &Sr25519Keyring::Two)
            .map(|v| tx_account_from_seed(&v.to_seed()))
            .collect::<Vec<_>>(),
        tx_account_from_seed(&Sr25519Keyring::Alice.to_seed()),
    )
}

/// Return the public quip-testnet genesis config preset.
///
/// Each authority slot is held by an independent operator who generated their
/// own libp2p node-key and hybrid BABE/GRANDPA keys offline (see
/// [`scripts/derive-operator-keys.sh`] and [`docs/testnet-keys.md`]). Only the
/// public bytes are committed in this repository; private material lives on
/// each operator's host.
///
/// The endowed set is intentionally identical to the authority set for v0.2.0
/// — there is no separate faucet account yet. Sudo is held by operator 1; a
/// migration to a multisig is tracked for a later release.
pub fn quip_testnet_config_genesis() -> Value {
    let op1_babe =
        babe_authority_from_public_hex(include_str!("genesis_quip_testnet/operator_1_babe.hex"));
    let op1_grandpa = grandpa_authority_from_public_hex(include_str!(
        "genesis_quip_testnet/operator_1_grandpa.hex"
    ));
    let op2_babe =
        babe_authority_from_public_hex(include_str!("genesis_quip_testnet/operator_2_babe.hex"));
    let op2_grandpa = grandpa_authority_from_public_hex(include_str!(
        "genesis_quip_testnet/operator_2_grandpa.hex"
    ));
    let op3_babe =
        babe_authority_from_public_hex(include_str!("genesis_quip_testnet/operator_3_babe.hex"));
    let op3_grandpa = grandpa_authority_from_public_hex(include_str!(
        "genesis_quip_testnet/operator_3_grandpa.hex"
    ));

    let op1_account =
        tx_account_from_hex("c6cb8a79a71b11347a7ce0d983104278c0682dc70b7f90be9afd92ab54f1404b");
    let op2_account =
        tx_account_from_hex("96ab60c5a90f6b18566155d2187fae8f52e3cd43627fb4a40d5c89f3a512bb5b");
    let op3_account =
        tx_account_from_hex("f8a5d50a6b32c3784b1e9fd9811e57b63524e5ec0defaafc289304bf99061db7");

    testnet_genesis(
        vec![
            (op1_babe, op1_grandpa),
            (op2_babe, op2_grandpa),
            (op3_babe, op3_grandpa),
        ],
        vec![op1_account.clone(), op2_account, op3_account],
        op1_account,
    )
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
        sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_config_genesis(),
        LOCAL_THREE_VALIDATOR_RUNTIME_PRESET => local_three_validator_config_genesis(),
        QUIP_TESTNET_RUNTIME_PRESET => quip_testnet_config_genesis(),
        _ => return None,
    };
    Some(
        serde_json::to_string(&patch)
            .expect("serialization to json is expected to work. qed.")
            .into_bytes(),
    )
}

/// List of supported presets.
pub fn preset_names() -> Vec<PresetId> {
    vec![
        PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
        PresetId::from(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET),
        PresetId::from(LOCAL_THREE_VALIDATOR_RUNTIME_PRESET),
        PresetId::from(QUIP_TESTNET_RUNTIME_PRESET),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;

    /// Pinned hex of `tx_account_from_seed("//Alice")`. Acts as a canary for
    /// silent changes to `quip_transaction_crypto::ACCOUNT_ID_DOMAIN` or the
    /// H3 keyring derivation: any such change re-keys every account at
    /// genesis, and this constant is the cheapest grep target for catching
    /// that regression.
    const ALICE_PINNED_ACCOUNT_HEX: &str =
        "504c921d4b618d2cbb53ebebfbc98db585b325c355259545739daafb3146cdb4";

    fn hex_encode(bytes: &[u8]) -> alloc::string::String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(TABLE[(b >> 4) as usize] as char);
            out.push(TABLE[(b & 0xF) as usize] as char);
        }
        out
    }

    #[test]
    fn development_preset_builds() {
        let _ = development_config_genesis();
    }

    #[test]
    fn local_preset_builds() {
        let _ = local_config_genesis();
    }

    #[test]
    fn local_three_validator_preset_builds() {
        let _ = local_three_validator_config_genesis();
    }

    #[test]
    fn quip_testnet_preset_builds() {
        let _ = quip_testnet_config_genesis();
    }

    #[test]
    fn quip_testnet_preset_is_registered() {
        let json = get_preset(&PresetId::from(QUIP_TESTNET_RUNTIME_PRESET));
        assert!(json.is_some(), "quip_testnet preset must be registered");
        let bytes = json.unwrap();
        assert!(!bytes.is_empty(), "preset must produce non-empty JSON");
    }

    /// Pinned operator-1 account hex. Catches silent breaks in either the
    /// hybrid public-key wire format or the `account_id_from_public` derivation
    /// (which would re-key every genesis account and brick the testnet).
    const OPERATOR_1_PINNED_ACCOUNT_HEX: &str =
        "c6cb8a79a71b11347a7ce0d983104278c0682dc70b7f90be9afd92ab54f1404b";

    #[test]
    fn quip_testnet_operator_1_account_is_pinned() {
        let op1 = tx_account_from_hex(OPERATOR_1_PINNED_ACCOUNT_HEX);
        let hex = hex_encode(&op1.encode());
        assert_eq!(hex, OPERATOR_1_PINNED_ACCOUNT_HEX);
    }

    #[test]
    fn alice_account_id_is_pinned() {
        let alice = tx_account_from_seed(&Sr25519Keyring::Alice.to_seed());
        let hex = hex_encode(&alice.encode());
        assert_eq!(
            hex, ALICE_PINNED_ACCOUNT_HEX,
            "Alice's derived account id changed. If this is intentional, update \
             ALICE_PINNED_ACCOUNT_HEX above with the new value: {hex}",
        );
    }
}
