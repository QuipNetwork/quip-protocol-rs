#!/usr/bin/env bash
set -euo pipefail

subscan_api_url="${SUBSCAN_API_URL:-http://127.0.0.1:4399}"
eth_rpc_url="${ETH_RPC_URL:-http://127.0.0.1:8545}"
max_attempts="${SUBSCAN_READY_ATTEMPTS:-90}"

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    response="$(curl --fail --silent --show-error \
        --header 'content-type: application/json' \
        --data '{"row":1}' \
        "${subscan_api_url}/api/plugin/evm/blocks" 2>/dev/null || true)"

    indexed_block="$(sed -n 's/.*"block_num":\([0-9][0-9]*\).*/\1/p' <<<"$response")"
    if [[ "$response" == *'"code":0'* && -n "$indexed_block" && "$indexed_block" -gt 0 ]]; then
        eth_response="$(curl --fail --silent --show-error \
            --header 'content-type: application/json' \
            --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            "$eth_rpc_url")"
        eth_head_hex="$(sed -n 's/.*"result":"\(0x[0-9a-fA-F][0-9a-fA-F]*\)".*/\1/p' <<<"$eth_response")"
        if [[ -n "$eth_head_hex" ]]; then
            eth_head=$((eth_head_hex))
            if ((indexed_block <= eth_head)); then
                echo "Subscan EVM indexer ready: indexed_block=${indexed_block} eth_head=${eth_head} api=${subscan_api_url}"
                exit 0
            fi
        fi
    fi

    sleep 2
done

echo "Subscan did not expose an indexed EVM block at ${subscan_api_url}" >&2
exit 1
