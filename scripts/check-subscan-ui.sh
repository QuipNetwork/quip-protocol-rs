#!/usr/bin/env bash
set -euo pipefail

subscan_ui_url="${SUBSCAN_UI_URL:-http://127.0.0.1:3000}"
subscan_api_url="${SUBSCAN_API_URL:-http://127.0.0.1:4399}"
browser_api_url="${SUBSCAN_BROWSER_API_URL:-http://localhost:4399}"
browser_origin="${SUBSCAN_UI_ORIGIN:-http://localhost:3000}"
max_attempts="${SUBSCAN_UI_READY_ATTEMPTS:-60}"

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    html="$(curl --fail --silent --show-error "${subscan_ui_url}/" 2>/dev/null || true)"
    runtime_env="$(curl --fail --silent --show-error "${subscan_ui_url}/__ENV.js" 2>/dev/null || true)"

    if [[ "$html" == *'<html'* && \
          "$runtime_env" == *"\"NEXT_PUBLIC_API_HOST\":\"${browser_api_url}\""* ]]; then
        cors_headers="$(curl --fail --silent --show-error \
            --dump-header - \
            --output /dev/null \
            --header "Origin: ${browser_origin}" \
            --header 'content-type: application/json' \
            --data '{}' \
            "${subscan_api_url}/api/scan/metadata" 2>/dev/null || true)"

        if grep --ignore-case --quiet '^access-control-allow-origin: \*' <<<"$cors_headers"; then
            echo "Subscan UI ready: ui=${subscan_ui_url} browser_api=${browser_api_url}"
            exit 0
        fi
    fi

    sleep 2
done

echo "Subscan UI did not become ready at ${subscan_ui_url}" >&2
exit 1
