QUIP_PROTOCOL_ROOT ?= /Users/romanuseinov/projects/quip/quip-protocol
QUIP_PROTOCOL_VENV := $(QUIP_PROTOCOL_ROOT)/.venv
QUIP_PROTOCOL_PYTHON := $(QUIP_PROTOCOL_VENV)/bin/python

WASM_SIGNER_CRATE := crates/transaction-crypto-wasm
WASM_SIGNER_PKG := js/quip-transaction-crypto-wasm
WASM_SIGNER_STAGE := target/wasm-signer-pkg
WASM_SIGNER_NAME := quip_transaction_crypto_wasm

polkadot-sdk:
	git clone --branch polkadot-stable2603 git@github.com:QuipNetwork/polkadot-sdk.git

local-3-node:
	./scripts/start-local3.sh

quantum-validation-venv:
	python3 -m venv $(QUIP_PROTOCOL_VENV)
	$(QUIP_PROTOCOL_PYTHON) -m pip install -e $(QUIP_PROTOCOL_ROOT)

quantum-validation-fixtures:
	QUIP_PROTOCOL_ROOT=$(QUIP_PROTOCOL_ROOT) $(QUIP_PROTOCOL_PYTHON) ./scripts/generate_quantum_validation_fixtures.py

# Build the browser signer WASM (requires `wasm-pack`). Outputs are generated
# and git-ignored; this regenerates them in place. Staged under target/ first so
# the curated package.json in the package dir is preserved.
wasm-signer:
	wasm-pack build $(WASM_SIGNER_CRATE) --target web --release \
		--out-dir $(abspath $(WASM_SIGNER_STAGE)) --out-name $(WASM_SIGNER_NAME)
	cp $(WASM_SIGNER_STAGE)/$(WASM_SIGNER_NAME).js \
		$(WASM_SIGNER_STAGE)/$(WASM_SIGNER_NAME).d.ts \
		$(WASM_SIGNER_STAGE)/$(WASM_SIGNER_NAME)_bg.wasm \
		$(WASM_SIGNER_STAGE)/$(WASM_SIGNER_NAME)_bg.wasm.d.ts \
		$(WASM_SIGNER_PKG)/
	@echo "Built $(WASM_SIGNER_PKG)/$(WASM_SIGNER_NAME)_bg.wasm ($$(wc -c < $(WASM_SIGNER_PKG)/$(WASM_SIGNER_NAME)_bg.wasm) bytes)"

.PHONY: local-3-node quantum-validation-venv quantum-validation-fixtures wasm-signer
