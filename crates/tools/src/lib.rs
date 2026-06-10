use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use codec::Encode;
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
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SubmissionMode {
    DryRun,
    Submit,
}

pub fn resolve_suri(sources: &SignerSources) -> Result<String> {
    let source_count = [
        sources.suri.is_some(),
        sources.suri_file.is_some(),
        sources.suri_env.is_some(),
    ]
    .into_iter()
    .filter(|provided| *provided)
    .count();

    if source_count != 1 {
        bail!("provide exactly one signer source: --suri, --suri-file, or --suri-env");
    }

    let suri = if let Some(suri) = &sources.suri {
        suri.clone()
    } else if let Some(path) = &sources.suri_file {
        fs::read_to_string(path)
            .with_context(|| format!("reading signer SURI file {}", path.display()))?
    } else {
        let env_name = sources
            .suri_env
            .as_deref()
            .expect("source count already established one signer source exists");
        env::var(env_name).with_context(|| format!("reading signer SURI from ${env_name}"))?
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
            runtime::VERSION.spec_version,
            runtime::VERSION.transaction_version,
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

    Ok(ChainContext {
        genesis_hash,
        best_hash,
        best_number,
        nonce,
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
) -> Result<Hash> {
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
) -> Result<Hash> {
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

                if finalized_block_contains(client, block_hash, &target_extrinsic).await? {
                    return Ok(block_hash);
                }
            }

            last_checked = finalized_number;
        }

        sleep(poll_interval).await;
    }

    bail!("timed out waiting for extrinsic finalization");
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

async fn finalized_block_contains(
    client: &WsClient,
    block_hash: Hash,
    target_extrinsic: &str,
) -> Result<bool> {
    let block: Option<Value> = client
        .request("chain_getBlock", rpc_params![block_hash])
        .await
        .with_context(|| format!("fetching finalized block {}", format_hash(&block_hash)))?;
    let Some(block) = block else {
        return Ok(false);
    };

    let extrinsics = block
        .get("block")
        .and_then(|block| block.get("extrinsics"))
        .and_then(Value::as_array)
        .context("chain_getBlock response missing block.extrinsics")?;

    Ok(extrinsics.iter().any(|extrinsic| {
        extrinsic
            .as_str()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(target_extrinsic))
    }))
}

fn parse_header_number(header: &Value) -> Result<BlockNumber> {
    let number = header
        .get("number")
        .and_then(Value::as_str)
        .context("chain_getHeader response missing number")?;
    let number = number.strip_prefix("0x").unwrap_or(number);

    u32::from_str_radix(number, 16).with_context(|| format!("parsing best block number 0x{number}"))
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
        assert!(submission_mode(false, false).is_err());
        assert_eq!(
            submission_mode(false, true).unwrap(),
            SubmissionMode::Submit
        );
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
