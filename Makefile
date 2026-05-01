QUIP_PROTOCOL_ROOT ?= /Users/romanuseinov/projects/quip/quip-protocol
QUIP_PROTOCOL_VENV := $(QUIP_PROTOCOL_ROOT)/.venv
QUIP_PROTOCOL_PYTHON := $(QUIP_PROTOCOL_VENV)/bin/python

polkadot-sdk:
	git clone --branch polkadot-stable2603 git@github.com:QuipNetwork/polkadot-sdk.git

local-3-node:
	./scripts/start-local3.sh

quantum-validation-venv:
	python3 -m venv $(QUIP_PROTOCOL_VENV)
	$(QUIP_PROTOCOL_PYTHON) -m pip install -e $(QUIP_PROTOCOL_ROOT)

quantum-validation-fixtures:
	QUIP_PROTOCOL_ROOT=$(QUIP_PROTOCOL_ROOT) $(QUIP_PROTOCOL_PYTHON) ./scripts/generate_quantum_validation_fixtures.py
