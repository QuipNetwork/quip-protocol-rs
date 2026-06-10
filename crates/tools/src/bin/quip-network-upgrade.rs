use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use quip_tools::{
    build_signed_extrinsic, build_upgrade_call, encode_extrinsic, fetch_chain_context,
    format_bytes32, format_hash, load_wasm, pair_from_suri, resolve_suri, scale_hex,
    signer_account, ss58, submission_mode, submit_extrinsic, wait_for_finalization, ws_client,
    SignerSources, SubmissionMode, DEFAULT_RPC_URL,
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

    #[arg(long)]
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
    let extrinsic = build_signed_extrinsic(&signer, call, context);
    let encoded = encode_extrinsic(&extrinsic);
    let extrinsic_hash = sp_core::hashing::blake2_256(&encoded);

    println!("Network upgrade transaction");
    println!("  signer: {}", ss58(&signer_account));
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

    if mode == SubmissionMode::DryRun {
        println!("dry run: not submitted");
        println!("encoded extrinsic: {}", scale_hex(&encoded));
        return Ok(());
    }

    let tx_hash = submit_extrinsic(&client, &encoded).await?;
    println!("submitted transaction hash: {}", format_hash(&tx_hash));

    if cli.wait_finalized {
        let finalized_hash = wait_for_finalization(&client, &encoded, context.best_number).await?;
        println!("finalized in block: {}", format_hash(&finalized_hash));
    }

    Ok(())
}
