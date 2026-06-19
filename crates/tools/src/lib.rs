use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use codec::{Decode, Encode};
use frame_system::{EventRecord, Phase};
use jsonrpsee::{
    core::{client::ClientT, rpc_params},
    ws_client::{WsClient, WsClientBuilder},
};
use quip_protocol_runtime::{
    self as runtime, BlockNumber, Hash, Nonce, Runtime, RuntimeCall, SignedPayload, TxExtension,
    UncheckedExtrinsic,
};
use quip_transaction_crypto::{account_id_from_public, HybridPair, HybridTxSignature};
use serde_json::Value;
use sp_core::{crypto::Ss58Codec, Pair as _};
use sp_runtime::{generic::Era, traits::SaturatedConversion};
use tokio::time::sleep;

pub const DEFAULT_RPC_URL: &str = "ws://127.0.0.1:9944";
pub const FINALIZATION_POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const FINALIZATION_MAX_POLLS: u32 = 150;

// Runtime blobs are multiple MiB and roughly double in size once hex-encoded into
// JSON-RPC, so jsonrpsee's 10 MiB defaults would reject both the submission and the
// `chain_getBlock` response for the block containing the upgrade.
const MAX_RPC_MESSAGE_SIZE: u32 = 64 * 1024 * 1024;

const WASM_MAGIC: [u8; 4] = *b"\0asm";
// `sp_maybe_compressed_blob::ZSTD_PREFIX`: marks a Substrate zstd-compressed runtime.
const ZSTD_PREFIX: [u8; 8] = [82, 188, 83, 70, 70, 219, 142, 5];

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SignerSources {
    pub suri: Option<String>,
    pub suri_file: Option<PathBuf>,
    pub suri_env: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoadedWasm {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChainContext {
    pub genesis_hash: Hash,
    pub best_hash: Hash,
    pub best_number: BlockNumber,
    pub nonce: Nonce,
    pub spec_version: u32,
    pub transaction_version: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SubmissionMode {
    DryRun,
    Submit,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FinalizedExtrinsic {
    pub block_hash: Hash,
    pub index: u32,
}

pub fn resolve_suri(sources: &SignerSources) -> Result<String> {
    let suri = match (&sources.suri, &sources.suri_file, &sources.suri_env) {
        (Some(suri), None, None) => suri.clone(),
        (None, Some(path), None) => fs::read_to_string(path)
            .with_context(|| format!("reading signer SURI file {}", path.display()))?,
        (None, None, Some(env_name)) => {
            env::var(env_name).with_context(|| format!("reading signer SURI from ${env_name}"))?
        }
        _ => bail!("provide exactly one signer source: --suri, --suri-file, or --suri-env"),
    };

    let suri = suri.trim().to_owned();
    if suri.is_empty() {
        bail!("signer SURI is empty");
    }

    Ok(suri)
}

pub fn pair_from_suri(suri: &str) -> Result<HybridPair> {
    HybridPair::from_string(suri, None).map_err(|err| anyhow!("invalid signer SURI: {err:?}"))
}

pub fn signer_account(pair: &HybridPair) -> runtime::AccountId {
    account_id_from_public(&pair.public())
}

pub fn load_wasm(path: &Path) -> Result<LoadedWasm> {
    let bytes =
        fs::read(path).with_context(|| format!("reading runtime Wasm {}", path.display()))?;
    if bytes.is_empty() {
        bail!("runtime Wasm {} is empty", path.display());
    }
    if !bytes.starts_with(&WASM_MAGIC) && !bytes.starts_with(&ZSTD_PREFIX) {
        bail!(
            "{} is neither raw Wasm nor a Substrate compressed runtime blob",
            path.display()
        );
    }

    Ok(LoadedWasm {
        path: path.to_path_buf(),
        hash: sp_core::hashing::blake2_256(&bytes),
        bytes,
    })
}

pub fn build_upgrade_call(wasm_bytes: Vec<u8>) -> RuntimeCall {
    let set_code =
        RuntimeCall::System(frame_system::Call::<Runtime>::set_code { code: wasm_bytes });

    RuntimeCall::Sudo(pallet_sudo::Call::<Runtime>::sudo {
        call: Box::new(set_code),
    })
}

pub fn build_signed_extrinsic(
    signer: &HybridPair,
    call: RuntimeCall,
    context: ChainContext,
) -> UncheckedExtrinsic {
    let tx_ext = tx_extension(context.best_number, context.nonce);
    let raw_payload = SignedPayload::from_raw(
        call.clone(),
        tx_ext.clone(),
        (
            (),
            (),
            context.spec_version,
            context.transaction_version,
            context.genesis_hash,
            context.best_hash,
            (),
            (),
            (),
            None,
            (),
        ),
    );
    let signature = raw_payload.using_encoded(|encoded| HybridTxSignature::sign(signer, encoded));

    UncheckedExtrinsic::new_signed(
        call,
        account_id_from_public(&signer.public()).into(),
        signature,
        tx_ext,
    )
}

pub fn submission_mode(dry_run: bool, yes: bool) -> Result<SubmissionMode> {
    if dry_run {
        return Ok(SubmissionMode::DryRun);
    }

    if !yes {
        bail!("refusing to submit without --yes; pass --dry-run to inspect without submitting");
    }

    Ok(SubmissionMode::Submit)
}

pub fn encode_extrinsic(extrinsic: &UncheckedExtrinsic) -> Vec<u8> {
    extrinsic.encode()
}

pub fn format_bytes32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn format_hash(hash: &Hash) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

pub fn ss58(account: &runtime::AccountId) -> String {
    account.to_ss58check()
}

pub fn scale_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub async fn ws_client(rpc_url: &str) -> Result<WsClient> {
    WsClientBuilder::default()
        .max_request_size(MAX_RPC_MESSAGE_SIZE)
        .max_response_size(MAX_RPC_MESSAGE_SIZE)
        .build(rpc_url)
        .await
        .with_context(|| format!("connecting to {rpc_url}"))
}

pub async fn fetch_chain_context(
    client: &WsClient,
    signer: &runtime::AccountId,
) -> Result<ChainContext> {
    let genesis_hash: Option<Hash> = client
        .request("chain_getBlockHash", rpc_params![0_u32])
        .await
        .context("fetching genesis hash")?;
    let genesis_hash = genesis_hash.context("node returned no genesis hash")?;

    let best_header: Option<Value> = client
        .request("chain_getHeader", rpc_params![])
        .await
        .context("fetching best header")?;
    let best_header = best_header.context("node returned no best header")?;
    let best_number = parse_header_number(&best_header)?;

    let best_hash: Option<Hash> = client
        .request("chain_getBlockHash", rpc_params![best_number])
        .await
        .context("fetching best block hash")?;
    let best_hash = best_hash.context("node returned no best block hash")?;

    let account = signer.to_ss58check();
    let nonce: Nonce = client
        .request("system_accountNextIndex", rpc_params![account])
        .await
        .context("fetching signer nonce")?;

    // Source spec_version / transaction_version from the live chain rather than
    // the compiled `runtime::VERSION`, so the CheckSpecVersion / CheckTxVersion
    // signed extensions stay valid across runtime upgrades without rebuilding.
    let runtime_version: Value = client
        .request("state_getRuntimeVersion", rpc_params![])
        .await
        .context("fetching runtime version")?;
    let spec_version: u32 = runtime_version
        .get("specVersion")
        .and_then(Value::as_u64)
        .context("state_getRuntimeVersion response missing specVersion")?
        .saturated_into();
    let transaction_version: u32 = runtime_version
        .get("transactionVersion")
        .and_then(Value::as_u64)
        .context("state_getRuntimeVersion response missing transactionVersion")?
        .saturated_into();

    Ok(ChainContext {
        genesis_hash,
        best_hash,
        best_number,
        nonce,
        spec_version,
        transaction_version,
    })
}

pub async fn submit_extrinsic(client: &WsClient, encoded_extrinsic: &[u8]) -> Result<Hash> {
    client
        .request(
            "author_submitExtrinsic",
            rpc_params![scale_hex(encoded_extrinsic)],
        )
        .await
        .context("submitting extrinsic")
}

pub async fn wait_for_finalization(
    client: &WsClient,
    encoded_extrinsic: &[u8],
    start_block: BlockNumber,
) -> Result<FinalizedExtrinsic> {
    wait_for_finalization_with(
        client,
        encoded_extrinsic,
        start_block,
        FINALIZATION_POLL_INTERVAL,
        FINALIZATION_MAX_POLLS,
    )
    .await
}

pub async fn wait_for_finalization_with(
    client: &WsClient,
    encoded_extrinsic: &[u8],
    start_block: BlockNumber,
    poll_interval: Duration,
    max_polls: u32,
) -> Result<FinalizedExtrinsic> {
    let target_extrinsic = scale_hex(encoded_extrinsic);
    let mut last_checked = start_block;

    for _ in 0..max_polls {
        let (finalized_number, finalized_hash) = finalized_head(client).await?;

        if finalized_number > last_checked {
            for block_number in last_checked.saturating_add(1)..=finalized_number {
                let block_hash = if block_number == finalized_number {
                    finalized_hash
                } else {
                    block_hash(client, block_number).await?
                };

                if let Some(index) =
                    finalized_block_extrinsic_index(client, block_hash, &target_extrinsic).await?
                {
                    return Ok(FinalizedExtrinsic { block_hash, index });
                }
            }

            last_checked = finalized_number;
        }

        sleep(poll_interval).await;
    }

    let pool_state = match pending_pool_contains(client, &target_extrinsic).await {
        Ok(true) => "the transaction is still in the node's pending pool and may yet be included".to_owned(),
        Ok(false) => "the transaction is no longer in the node's pending pool (dropped, expired, or already included)".to_owned(),
        Err(err) => format!("the node's pending pool could not be inspected: {err:#}"),
    };

    bail!(
        "timed out after {}s waiting for extrinsic finalization; {pool_state} — verify on-chain \
         state (e.g. spec_version) before re-submitting",
        poll_interval.as_secs().saturating_mul(u64::from(max_polls)),
    );
}

async fn pending_pool_contains(client: &WsClient, target_extrinsic: &str) -> Result<bool> {
    let pending: Vec<String> = client
        .request("author_pendingExtrinsics", rpc_params![])
        .await
        .context("fetching pending extrinsics")?;

    Ok(pending
        .iter()
        .any(|extrinsic| extrinsic.eq_ignore_ascii_case(target_extrinsic)))
}

async fn finalized_head(client: &WsClient) -> Result<(BlockNumber, Hash)> {
    let hash: Hash = client
        .request("chain_getFinalizedHead", rpc_params![])
        .await
        .context("fetching finalized head")?;
    let header: Option<Value> = client
        .request("chain_getHeader", rpc_params![hash])
        .await
        .with_context(|| format!("fetching finalized header {}", format_hash(&hash)))?;
    let header = header.context("node returned no finalized header")?;

    Ok((parse_header_number(&header)?, hash))
}

async fn block_hash(client: &WsClient, block_number: BlockNumber) -> Result<Hash> {
    let hash: Option<Hash> = client
        .request("chain_getBlockHash", rpc_params![block_number])
        .await
        .with_context(|| format!("fetching block hash for #{block_number}"))?;

    hash.with_context(|| format!("node returned no block hash for #{block_number}"))
}

pub async fn sudo_key(client: &WsClient) -> Result<runtime::AccountId> {
    let bytes = storage_at(client, &storage_key(b"Sudo", b"Key"), None)
        .await?
        .context("chain has no sudo key configured (pallet_sudo Key storage is empty)")?;

    runtime::AccountId::decode(&mut bytes.as_slice()).context("decoding on-chain sudo key")
}

pub async fn runtime_spec_version(client: &WsClient, at: Option<Hash>) -> Result<u32> {
    let version: Value = match at {
        Some(hash) => {
            client
                .request("state_getRuntimeVersion", rpc_params![hash])
                .await
        }
        None => {
            client
                .request("state_getRuntimeVersion", rpc_params![])
                .await
        }
    }
    .context("fetching runtime version")?;

    let spec_version = version
        .get("specVersion")
        .and_then(Value::as_u64)
        .context("state_getRuntimeVersion response missing specVersion")?;

    Ok(spec_version.saturated_into())
}

/// Confirms the upgrade extrinsic actually dispatched successfully.
///
/// Inclusion in a finalized block is not success: the extrinsic can fail outright
/// (e.g. signer is not the sudo key → `system.ExtrinsicFailed`), or `sudo` can
/// dispatch while the inner `system.set_code` fails (`sudo.Sudid(Err)`, e.g. the
/// new runtime does not increase `spec_version`). Only the events tell the truth.
pub async fn verify_upgrade_dispatch(
    client: &WsClient,
    finalized: &FinalizedExtrinsic,
) -> Result<()> {
    let bytes = storage_at(
        client,
        &storage_key(b"System", b"Events"),
        Some(finalized.block_hash),
    )
    .await?
    .with_context(|| {
        format!(
            "no system events found in block {}",
            format_hash(&finalized.block_hash)
        )
    })?;
    let events = Vec::<EventRecord<runtime::RuntimeEvent, Hash>>::decode(&mut bytes.as_slice())
        .context(
            "decoding system events (was the tool built from the same runtime as the chain?)",
        )?;

    let phase = Phase::ApplyExtrinsic(finalized.index);
    let mut sudo_succeeded = false;
    for record in events.iter().filter(|record| record.phase == phase) {
        match &record.event {
            runtime::RuntimeEvent::System(frame_system::Event::ExtrinsicFailed {
                dispatch_error,
                ..
            }) => {
                bail!(
                    "upgrade extrinsic failed in block {}: {dispatch_error:?}",
                    format_hash(&finalized.block_hash)
                );
            }
            runtime::RuntimeEvent::Sudo(pallet_sudo::Event::Sudid {
                sudo_result: Err(err),
            }) => {
                bail!(
                    "sudo dispatched but the inner system.set_code failed: {err:?} \
                     (does the new runtime increase spec_version?)"
                );
            }
            runtime::RuntimeEvent::Sudo(pallet_sudo::Event::Sudid {
                sudo_result: Ok(()),
            }) => {
                sudo_succeeded = true;
            }
            _ => {}
        }
    }

    if !sudo_succeeded {
        bail!(
            "no sudo.Sudid success event for extrinsic {} in block {}; the upgrade cannot be \
             confirmed",
            finalized.index,
            format_hash(&finalized.block_hash)
        );
    }

    Ok(())
}

fn storage_key(pallet: &[u8], item: &[u8]) -> String {
    let mut key = sp_core::hashing::twox_128(pallet).to_vec();
    key.extend(sp_core::hashing::twox_128(item));

    format!("0x{}", hex::encode(key))
}

async fn storage_at(client: &WsClient, key: &str, at: Option<Hash>) -> Result<Option<Vec<u8>>> {
    let value: Option<String> = match at {
        Some(hash) => {
            client
                .request("state_getStorage", rpc_params![key, hash])
                .await
        }
        None => client.request("state_getStorage", rpc_params![key]).await,
    }
    .with_context(|| format!("fetching storage {key}"))?;

    value
        .map(|encoded| {
            hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))
                .with_context(|| format!("decoding storage value for {key}"))
        })
        .transpose()
}

fn tx_extension(best_number: BlockNumber, nonce: Nonce) -> TxExtension {
    let period = runtime::configs::BlockHashCount::get()
        .checked_next_power_of_two()
        .map(|count| count / 2)
        .unwrap_or(2) as u64;

    (
        frame_system::AuthorizeCall::<Runtime>::new(),
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckEra::<Runtime>::from(Era::mortal(period, best_number.saturated_into())),
        frame_system::CheckNonce::<Runtime>::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
        frame_metadata_hash_extension::CheckMetadataHash::<Runtime>::new(false),
        frame_system::WeightReclaim::<Runtime>::new(),
    )
}

async fn finalized_block_extrinsic_index(
    client: &WsClient,
    block_hash: Hash,
    target_extrinsic: &str,
) -> Result<Option<u32>> {
    let block: Option<Value> = client
        .request("chain_getBlock", rpc_params![block_hash])
        .await
        .with_context(|| format!("fetching finalized block {}", format_hash(&block_hash)))?;
    // A node that cannot serve a block it reported as finalized is malfunctioning
    // (e.g. pruned); treating this as "not found" would surface as a misleading timeout.
    let block = block.with_context(|| {
        format!(
            "node returned no body for finalized block {}",
            format_hash(&block_hash)
        )
    })?;

    block_extrinsic_index(&block, target_extrinsic)
}

fn block_extrinsic_index(block: &Value, target_extrinsic: &str) -> Result<Option<u32>> {
    let extrinsics = block
        .get("block")
        .and_then(|block| block.get("extrinsics"))
        .and_then(Value::as_array)
        .context("chain_getBlock response missing block.extrinsics")?;

    let index = extrinsics.iter().position(|extrinsic| {
        extrinsic
            .as_str()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(target_extrinsic))
    });

    Ok(index.map(|index| index.saturated_into()))
}

fn parse_header_number(header: &Value) -> Result<BlockNumber> {
    let number = header
        .get("number")
        .and_then(Value::as_str)
        .context("chain_getHeader response missing number")?;
    let digits = number
        .strip_prefix("0x")
        .with_context(|| format!("block number {number} is not 0x-prefixed hex"))?;

    u32::from_str_radix(digits, 16).with_context(|| format!("parsing block number {number}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_wasm_rejects_missing_files() {
        let missing = temp_path("missing.wasm");

        assert!(load_wasm(&missing).is_err());
    }

    #[test]
    fn load_wasm_rejects_empty_files() {
        let path = temp_path("empty.wasm");
        fs::write(&path, []).unwrap();

        let err = load_wasm(&path).unwrap_err().to_string();
        fs::remove_file(&path).unwrap();

        assert!(err.contains("empty"));
    }

    #[test]
    fn load_wasm_rejects_non_wasm_files() {
        let path = temp_path("not-wasm.wasm");
        fs::write(&path, b"{\"this\": \"is a chainspec, not wasm\"}").unwrap();

        let err = load_wasm(&path).unwrap_err().to_string();
        fs::remove_file(&path).unwrap();

        assert!(err.contains("neither raw Wasm"));
    }

    #[test]
    fn load_wasm_accepts_raw_wasm_and_compressed_blobs() {
        for (name, magic) in [
            ("raw.wasm", WASM_MAGIC.as_slice()),
            ("compressed.wasm", ZSTD_PREFIX.as_slice()),
        ] {
            let path = temp_path(name);
            let mut bytes = magic.to_vec();
            bytes.extend([1, 2, 3]);
            fs::write(&path, &bytes).unwrap();

            let loaded = load_wasm(&path);
            fs::remove_file(&path).unwrap();

            assert_eq!(loaded.unwrap().bytes, bytes);
        }
    }

    #[test]
    fn resolve_suri_rejects_missing_sources() {
        let err = resolve_suri(&SignerSources::default())
            .unwrap_err()
            .to_string();

        assert!(err.contains("exactly one"));
    }

    #[test]
    fn resolve_suri_rejects_empty_suri_file() {
        let path = temp_path("empty-suri.txt");
        fs::write(&path, "  \n").unwrap();

        let err = resolve_suri(&SignerSources {
            suri_file: Some(path.clone()),
            ..SignerSources::default()
        })
        .unwrap_err()
        .to_string();
        fs::remove_file(&path).unwrap();

        assert!(err.contains("empty"));
    }

    #[test]
    fn resolve_suri_rejects_missing_suri_file() {
        let err = resolve_suri(&SignerSources {
            suri_file: Some(temp_path("missing-suri.txt")),
            ..SignerSources::default()
        });

        assert!(err.is_err());
    }

    #[test]
    fn pair_from_suri_rejects_garbage() {
        assert!(pair_from_suri("not a valid suri \u{0}").is_err());
    }

    #[test]
    fn resolve_suri_accepts_direct_file_and_env_sources() {
        let direct = resolve_suri(&SignerSources {
            suri: Some("  //Alice  ".to_owned()),
            ..SignerSources::default()
        })
        .unwrap();
        assert_eq!(direct, "//Alice");

        let path = temp_path("suri.txt");
        fs::write(&path, "\n//Bob\n").unwrap();
        let from_file = resolve_suri(&SignerSources {
            suri_file: Some(path.clone()),
            ..SignerSources::default()
        })
        .unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(from_file, "//Bob");

        let env_name = format!("QUIP_TOOLS_TEST_SURI_{}", unique_suffix());
        env::set_var(&env_name, "  //Charlie  ");
        let from_env = resolve_suri(&SignerSources {
            suri_env: Some(env_name.clone()),
            ..SignerSources::default()
        })
        .unwrap();
        env::remove_var(env_name);
        assert_eq!(from_env, "//Charlie");
    }

    #[test]
    fn resolve_suri_rejects_multiple_sources() {
        let err = resolve_suri(&SignerSources {
            suri: Some("//Alice".to_owned()),
            suri_env: Some("SIGNER".to_owned()),
            ..SignerSources::default()
        })
        .unwrap_err()
        .to_string();

        assert!(err.contains("exactly one"));
    }

    #[test]
    fn signed_extrinsic_construction_is_deterministic() {
        let signer = pair_from_suri("//Alice").unwrap();
        let context = ChainContext {
            genesis_hash: Hash::repeat_byte(1),
            best_hash: Hash::repeat_byte(2),
            best_number: 42,
            nonce: 7,
            spec_version: 103,
            transaction_version: 3,
        };

        let left = build_signed_extrinsic(&signer, build_upgrade_call(vec![1, 2, 3]), context);
        let right = build_signed_extrinsic(&signer, build_upgrade_call(vec![1, 2, 3]), context);

        assert_eq!(left.encode(), right.encode());
    }

    #[test]
    fn upgrade_call_is_sudo_wrapped_system_set_code() {
        let call = build_upgrade_call(vec![1, 2, 3]);

        match call {
            RuntimeCall::Sudo(pallet_sudo::Call::sudo { call }) => match *call {
                RuntimeCall::System(frame_system::Call::set_code { code }) => {
                    assert_eq!(code, vec![1, 2, 3]);
                }
                other => panic!("expected system.set_code, got {other:?}"),
            },
            other => panic!("expected sudo call, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_mode_does_not_require_submission_confirmation() {
        assert_eq!(
            submission_mode(true, false).unwrap(),
            SubmissionMode::DryRun
        );
        assert_eq!(submission_mode(true, true).unwrap(), SubmissionMode::DryRun);
        assert!(submission_mode(false, false).is_err());
        assert_eq!(
            submission_mode(false, true).unwrap(),
            SubmissionMode::Submit
        );
    }

    #[test]
    fn parse_header_number_requires_prefixed_hex() {
        let number = parse_header_number(&serde_json::json!({ "number": "0x2a" })).unwrap();
        assert_eq!(number, 42);

        // A decimal value must error rather than silently parse as hex (1000 != 0x1000).
        assert!(parse_header_number(&serde_json::json!({ "number": "1000" })).is_err());
        assert!(parse_header_number(&serde_json::json!({ "number": "0xzz" })).is_err());
        assert!(parse_header_number(&serde_json::json!({ "number": 42 })).is_err());
        assert!(parse_header_number(&serde_json::json!({})).is_err());
    }

    #[test]
    fn block_extrinsic_index_finds_case_insensitive_match() {
        let block = serde_json::json!({
            "block": { "extrinsics": ["0xaa", "0xAbCd", "0xff"] }
        });

        assert_eq!(block_extrinsic_index(&block, "0xabcd").unwrap(), Some(1));
        assert_eq!(block_extrinsic_index(&block, "0xbeef").unwrap(), None);
    }

    #[test]
    fn block_extrinsic_index_rejects_malformed_blocks() {
        let no_extrinsics = serde_json::json!({ "block": {} });

        assert!(block_extrinsic_index(&no_extrinsics, "0xaa").is_err());
    }

    #[test]
    fn block_extrinsic_index_handles_empty_blocks() {
        let empty = serde_json::json!({ "block": { "extrinsics": [] } });

        assert_eq!(block_extrinsic_index(&empty, "0xaa").unwrap(), None);
    }

    fn temp_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!("quip-tools-{}-{name}", unique_suffix()))
    }

    fn unique_suffix() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{nanos}", std::process::id())
    }
}
