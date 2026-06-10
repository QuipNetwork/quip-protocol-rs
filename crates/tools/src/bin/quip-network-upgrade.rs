use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;
use quip_tools::{
    build_signed_extrinsic, build_upgrade_call, encode_extrinsic, fetch_chain_context,
    format_bytes32, format_hash, load_wasm, pair_from_suri, resolve_suri, runtime_spec_version,
    scale_hex, signer_account, ss58, submission_mode, submit_extrinsic, sudo_key,
    verify_upgrade_dispatch, wait_for_finalization, ws_client, SignerSources, SubmissionMode,
    DEFAULT_RPC_URL,
};

#[derive(Debug, Parser)]
#[command(name = "quip-network-upgrade")]
#[command(about = "Submit a sudo-wrapped Quip runtime upgrade extrinsic")]
struct Cli {
    #[arg(long, default_value = DEFAULT_RPC_URL)]
    rpc: String,

    #[arg(long)]
    wasm: PathBuf,

    #[arg(long)]
    suri: Option<String>,

    #[arg(long)]
    suri_file: Option<PathBuf>,

    #[arg(long)]
    suri_env: Option<String>,

    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    yes: bool,

    #[arg(long, conflicts_with = "dry_run")]
    wait_finalized: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mode = submission_mode(cli.dry_run, cli.yes)?;
    let signer_suri = resolve_suri(&SignerSources {
        suri: cli.suri,
        suri_file: cli.suri_file,
        suri_env: cli.suri_env,
    })?;
    let signer = pair_from_suri(&signer_suri)?;
    let signer_account = signer_account(&signer);
    let wasm = load_wasm(&cli.wasm)?;
    let call = build_upgrade_call(wasm.bytes.clone());

    let client = ws_client(&cli.rpc).await?;
    let context = fetch_chain_context(&client, &signer_account).await?;
    let onchain_sudo = sudo_key(&client).await?;
    let onchain_spec_version = runtime_spec_version(&client, None).await?;
    let tool_spec_version = quip_protocol_runtime::VERSION.spec_version;
    let extrinsic = build_signed_extrinsic(&signer, call, context);
    let encoded = encode_extrinsic(&extrinsic);
    let extrinsic_hash = sp_core::hashing::blake2_256(&encoded);

    println!("Network upgrade transaction");
    println!("  signer: {}", ss58(&signer_account));
    println!("  on-chain sudo key: {}", ss58(&onchain_sudo));
    println!(
        "  on-chain spec_version: {onchain_spec_version} (tool built with {tool_spec_version})"
    );
    println!("  rpc: {}", cli.rpc);
    println!("  wasm: {}", wasm.path.display());
    println!("  wasm bytes: {}", wasm.bytes.len());
    println!("  wasm hash: {}", format_bytes32(&wasm.hash));
    println!("  nonce: {}", context.nonce);
    println!("  best block: {}", context.best_number);
    println!("  best hash: {}", format_hash(&context.best_hash));
    println!("  genesis hash: {}", format_hash(&context.genesis_hash));
    println!("  call: sudo(system.set_code)");
    println!("  extrinsic bytes: {}", encoded.len());
    println!("  extrinsic hash: {}", format_bytes32(&extrinsic_hash));

    let mut preflight_issues = Vec::new();
    if onchain_sudo != signer_account {
        preflight_issues.push(format!(
            "signer {} is not the on-chain sudo key {}; the upgrade would be rejected",
            ss58(&signer_account),
            ss58(&onchain_sudo)
        ));
    }
    if onchain_spec_version != tool_spec_version {
        preflight_issues.push(format!(
            "tool is built with spec_version {tool_spec_version} but the chain runs \
             {onchain_spec_version}; CheckSpecVersion makes the signature invalid — rebuild the \
             tool from the source matching the live chain"
        ));
    }
    for issue in &preflight_issues {
        eprintln!("warning: {issue}");
    }

    if mode == SubmissionMode::DryRun {
        println!("dry run: not submitted");
        println!("encoded extrinsic: {}", scale_hex(&encoded));
        return Ok(());
    }

    if !preflight_issues.is_empty() {
        bail!("preflight checks failed; aborting before submission");
    }

    let tx_hash = submit_extrinsic(&client, &encoded).await?;
    if tx_hash.as_bytes() != extrinsic_hash.as_slice() {
        bail!(
            "node reported transaction hash {} but the locally computed hash is {}; the node \
             decoded the extrinsic differently than it was built",
            format_hash(&tx_hash),
            format_bytes32(&extrinsic_hash)
        );
    }
    println!("submitted transaction hash: {}", format_hash(&tx_hash));

    if cli.wait_finalized {
        let finalized = wait_for_finalization(&client, &encoded, context.best_number).await?;
        println!("finalized in block: {}", format_hash(&finalized.block_hash));
        verify_upgrade_dispatch(&client, &finalized).await?;
        let new_spec_version = runtime_spec_version(&client, Some(finalized.block_hash)).await?;
        println!("upgrade dispatched successfully (sudo.Sudid: Ok)");
        println!("runtime spec_version: {onchain_spec_version} -> {new_spec_version}");
    } else {
        println!(
            "note: the transaction was only accepted into the node's pool; inclusion and \
             dispatch success are NOT confirmed — pass --wait-finalized to verify the upgrade"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
