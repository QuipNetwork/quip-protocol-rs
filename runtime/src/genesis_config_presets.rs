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
use quip_crypto_primitives::substrate::ed25519_mldsa44::Pair as HybridGrandpaPair;
use quip_crypto_primitives::substrate::sr25519_mldsa44::Pair as HybridBabePair;
use quip_transaction_crypto::{account_id_from_public, HybridPair as HybridTxPair};
use serde_json::Value;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::Pair as _;
use sp_genesis_builder::{self, PresetId};
use sp_keyring::Ed25519Keyring;
use sp_keyring::Sr25519Keyring;

pub const LOCAL_THREE_VALIDATOR_RUNTIME_PRESET: &str = "local_three_validator";

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

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
        sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_config_genesis(),
        LOCAL_THREE_VALIDATOR_RUNTIME_PRESET => local_three_validator_config_genesis(),
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
