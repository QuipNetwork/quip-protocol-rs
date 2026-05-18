#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/derive-operator-keys.sh <operator-index> [hostname]
#
# Generates the BIP39 mnemonic, libp2p node-key, and hybrid genesis public
# material for one quip-testnet bootnode operator. Run this once per slot
# (typically 1, 2, 3). The script:
#
#   * writes secret material (mnemonic, node-key file) to disk with 0600 perms
#   * prints a "public bundle" block to stdout and saves a copy under the
#     operator's output directory; that bundle is what to share back to the
#     release coordinator
#
# Environment overrides:
#   QUIP_NODE_BIN     path to the quip-network-node release binary
#                     (default: <repo>/target/release/quip-network-node)
#   QUIP_OUTPUT_DIR   where per-operator dirs are created
#                     (default: <repo>/quip-testnet-keys)
#   QUIP_HOSTNAME     override the bootnode hostname for the multiaddr;
#                     normally provided as positional arg

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 <operator-index> [hostname]" >&2
	echo "example: $0 1 bootnode-1.testnet.quip.network" >&2
	exit 64
fi

operator_index=$1
hostname=${2:-${QUIP_HOSTNAME:-bootnode-${operator_index}.testnet.quip.network}}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
node_bin=${QUIP_NODE_BIN:-${repo_root}/target/release/quip-network-node}
output_dir=${QUIP_OUTPUT_DIR:-${repo_root}/quip-testnet-keys}

if [[ ! -x "$node_bin" ]]; then
	echo "node binary not found or not executable: $node_bin" >&2
	echo "build it first: cargo build --release -p quip-network-node" >&2
	exit 70
fi

operator_dir=${output_dir}/operator-${operator_index}
if [[ -e "$operator_dir" ]]; then
	echo "operator directory already exists: $operator_dir" >&2
	echo "remove it explicitly or pick a different index to avoid overwriting." >&2
	exit 73
fi

umask 077
mkdir -p "$operator_dir"
# Guardrail: ignore everything in the output dir so secrets can't accidentally
# land in a future `git add .` from the repo root.
echo '*' >"${output_dir}/.gitignore"

echo "[1/3] generating BIP39 mnemonic..."
generate_output=$("$node_bin" key generate 2>&1)
mnemonic=$(printf '%s\n' "$generate_output" |
	sed -n 's/^Secret phrase:[[:space:]]*//p')
if [[ -z "$mnemonic" ]]; then
	echo "failed to parse mnemonic from 'key generate' output" >&2
	printf '%s\n' "$generate_output" >&2
	exit 70
fi
mnemonic_path=${operator_dir}/mnemonic
printf '%s\n' "$mnemonic" >"$mnemonic_path"
chmod 600 "$mnemonic_path"

echo "[2/3] generating libp2p node-key..."
nodekey_path=${operator_dir}/nodekey
# sc-cli marks --file and --base-path as mutually exclusive (see upstream
# substrate/client/cli/src/commands/generate_node_key.rs:62). Using --file
# alone writes the secret to that path; the peer-id is emitted on stderr,
# but we recover it via inspect-node-key below for a robust capture.
"$node_bin" key generate-node-key --file "$nodekey_path" >/dev/null 2>&1
chmod 600 "$nodekey_path"

peer_id=$("$node_bin" key inspect-node-key --file "$nodekey_path" |
	grep -Eo '12D3KooW[A-Za-z0-9]+' |
	head -n1)
if [[ -z "$peer_id" ]]; then
	echo "failed to parse peer-id from inspect-node-key" >&2
	exit 70
fi

echo "[3/3] deriving hybrid BABE/GRANDPA/TX public material..."
derive_output=$(cd "${repo_root}/crates/transaction-crypto" &&
	cargo run --release --quiet \
		--example derive_genesis_keys --features std \
		-- "$mnemonic" 2>&1)
babe_pub=$(printf '%s\n' "$derive_output" |
	awk -F'= *' '/^babe_pub /{print $2}')
grandpa_pub=$(printf '%s\n' "$derive_output" |
	awk -F'= *' '/^grandpa_pub /{print $2}')
tx_ss58=$(printf '%s\n' "$derive_output" |
	awk -F'= *' '/^tx_account_ss58 /{print $2}')
tx_hex=$(printf '%s\n' "$derive_output" |
	awk -F'= *' '/^tx_account_hex /{print $2}')
if [[ -z "$babe_pub" || -z "$grandpa_pub" || -z "$tx_ss58" || -z "$tx_hex" ]]; then
	echo "failed to parse derive_genesis_keys output" >&2
	printf '%s\n' "$derive_output" >&2
	exit 70
fi

multiaddr="/dns4/${hostname}/tcp/30333/p2p/${peer_id}"

bundle_path=${operator_dir}/public-bundle.txt
cat >"$bundle_path" <<EOF
operator: ${operator_index}
hostname: ${hostname}
multiaddr: ${multiaddr}
peer_id: ${peer_id}
babe_pub: ${babe_pub}
grandpa_pub: ${grandpa_pub}
tx_account_ss58: ${tx_ss58}
tx_account_hex: ${tx_hex}
EOF
chmod 644 "$bundle_path"

echo
echo "=== public bundle (safe to share) ==="
cat "$bundle_path"
echo
echo "secret material (do NOT share, do NOT commit):"
echo "  mnemonic: ${mnemonic_path}"
echo "  nodekey:  ${nodekey_path}"
echo "back these up out-of-band; they cannot be regenerated from the public bundle."
