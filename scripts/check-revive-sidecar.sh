#!/usr/bin/env bash
set -euo pipefail

eth_rpc_url="${ETH_RPC_URL:-http://127.0.0.1:8545}"
expected_chain_id="${EXPECTED_CHAIN_ID:-0x539}"
max_attempts="${RPC_READY_ATTEMPTS:-60}"

rpc_call() {
    local method=$1
    curl --fail --silent --show-error \
        --header 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":[],\"id\":1}" \
        "$eth_rpc_url"
}

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    response="$(rpc_call eth_chainId 2>/dev/null || true)"
    if [[ "$response" == *"\"result\":\"${expected_chain_id}\""* ]]; then
        block_response="$(rpc_call eth_blockNumber)"
        if [[ "$block_response" =~ \"result\":\"0x[0-9a-fA-F]+\" ]]; then
            echo "revive sidecar ready: chain_id=${expected_chain_id} url=${eth_rpc_url}"
            exit 0
        fi
    fi

    sleep 2
done

echo "revive sidecar did not become ready at ${eth_rpc_url}" >&2
exit 1
