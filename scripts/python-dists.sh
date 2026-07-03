#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build and validate (check) or build and publish the `quip-signer` Python
# distribution. Single source of truth for the build/check/upload commands so
# the three CI jobs that touch them (release:dry-run-pypi, release:publish-
# testpypi, release:publish-pypi) don't drift -- changing the artefact matrix
# or the upload flow is a one-place edit here.
#
# quip-signer is a single PyO3 abi3 cdylib (mixed maturin layout: the Rust
# extension is dropped into the `quip_signer` package under the crate's
# in-tree `python/` python-source).
# There are no pure-Python peer packages and the crate itself is
# `publish = false`, so -- unlike xquad's multi-package python-dists.sh -- this
# handles exactly one distribution and mints exactly one OIDC token.
#
# Modes:
#   check
#       maturin build (abi3 wheels: linux x86_64 native + linux aarch64 via
#       cargo-zigbuild) + maturin sdist + `twine check`. No network upload, no
#       token. Used by release:dry-run-pypi on every MR/push.
#
#   publish <testpypi|pypi>
#       Same build, then exchange the GitLab OIDC JWT in PYPI_ID_TOKEN for a
#       short-lived API token at the target registry's mint endpoint and
#       `twine upload`. Requires PYPI_ID_TOKEN in env (set by the job's
#       `id_tokens` block in .gitlab-ci.yml). Used by release:publish-testpypi
#       (auto) and release:publish-pypi (manual) on release tags.
#
# Run from the workspace root.

set -euo pipefail

MANIFEST="crates/transaction-crypto-py/Cargo.toml"
DIST="dist"

mode="${1:-}"
target=""
case "${mode}" in
check) ;;
publish)
	target="${2:-}"
	case "${target}" in
	testpypi | pypi) ;;
	*)
		echo "usage: $0 publish {testpypi|pypi}" >&2
		exit 2
		;;
	esac
	;;
*)
	echo "usage: $0 {check | publish <testpypi|pypi>}" >&2
	exit 2
	;;
esac

# --- build the three artefacts --------------------------------------------
# Same matrix as xquad's xqffi cdylib:
#   1. abi3 wheel, linux x86_64  (native build on the CI runner)
#   2. abi3 wheel, linux aarch64 (cross-compiled; zig is the linker)
#   3. sdist                     (universal source fallback for macOS/Windows)
# The abi3 tag (cp39-abi3-...) comes from pyo3's `abi3-py39` feature, so one
# wheel per arch serves CPython >=3.9.
rm -rf "${DIST}"
mkdir -p "${DIST}"

maturin build --release --manifest-path "${MANIFEST}" --out "${DIST}"
maturin build --release --manifest-path "${MANIFEST}" --out "${DIST}" \
	--target aarch64-unknown-linux-gnu --zig
maturin sdist --manifest-path "${MANIFEST}" --out "${DIST}"

# Platform-tag guard. `twine check` validates metadata only -- it does NOT
# inspect platform tags, so a wheel tagged plain `linux_x86_64` (linked against
# a glibc newer than any manylinux profile) passes twine check and is then
# rejected at upload time. Assert every wheel carries a manylinux/musllinux tag
# here so the dry-run actually fails on a non-portable build instead of
# discovering it mid-publish.
for whl in "${DIST}"/*.whl; do
	case "${whl}" in
	*manylinux* | *musllinux*) ;;
	*)
		echo "ERROR: ${whl##*/} has no manylinux/musllinux platform tag; PyPI will reject it." >&2
		echo "       The native build linked against too-new a glibc -- build it via cargo-zigbuild too, or lower the build image's glibc." >&2
		exit 1
		;;
	esac
done

# Wheel-content guard (QUI-792). A wheel is a zip; `twine check` validates
# metadata but NEVER opens the archive, and the manylinux guard above only
# reads the filename tag. When the python-source lived outside the crate,
# `maturin build` packed only `_quip_signer.abi3.so` and silently dropped the
# `quip_signer` package surface -- the wheel passed every check above, then
# imported as an empty namespace package (no `HybridSigner`, etc.). Open each
# wheel and assert the tracked pure-Python surface is present so a layout
# regression fails the build HERE (both dry-run and publish) instead of
# shipping -- or promoting to production -- an unimportable package.
required_members=(
	"quip_signer/__init__.py"   # re-exports the extension's public API
	"quip_signer/__init__.pyi"  # type stubs
	"quip_signer/py.typed"      # PEP 561 typing marker
)
for whl in "${DIST}"/*.whl; do
	names="$(python3 -c 'import sys, zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "${whl}")"
	for member in "${required_members[@]}"; do
		if ! grep -qxF "${member}" <<<"${names}"; then
			echo "ERROR: ${whl##*/} is missing ${member}; the wheel would import as an empty namespace package (QUI-792)." >&2
			echo "       Check crates/transaction-crypto-py/pyproject.toml: python-source must be in-tree (\"python\"), not an out-of-tree path maturin drops from the wheel." >&2
			exit 1
		fi
	done
done

# Import smoke test (QUI-793). The content guard above proves the surface
# *files* are packed; this proves the built wheel actually *imports and runs*
# from a clean install -- catching what a file check can't (a broken extension,
# an ABI/symbol mismatch, a bad re-export). It installs into a throwaway venv
# with the repo source NOT on the path, so -- unlike the pytest suite, which
# runs against `maturin develop` (the editable source tree) -- it exercises the
# artifact a `pip install quip-signer` user actually gets. That develop-vs-wheel
# gap is exactly what let QUI-792 ship. On the shared path, so it also gates the
# publish jobs (the tag pipeline runs `publish`, never `check`).
#
# `--no-index --only-binary=:all:` installs strictly from our built wheels --
# never PyPI, never an sdist compile fallback that could mask a broken wheel.
# pip resolves the one wheel matching this host's tag; the cross-built aarch64
# wheel is not importable here and is skipped by tag.
smoke_root="$(mktemp -d)"
trap 'rm -rf "${smoke_root}"' EXIT
python3 -m venv "${smoke_root}/venv"
"${smoke_root}/venv/bin/pip" install --quiet --disable-pip-version-check \
	--no-index --only-binary=:all: --find-links "${DIST}" quip-signer
# Run from the venv dir so no stray `quip_signer/` in CWD can shadow the install.
( cd "${smoke_root}/venv" && "${smoke_root}/venv/bin/python" - <<'PY'
from quip_signer import (
    HybridSigner,
    account_id_from_public,
    public_from_seed,
    seed_from_mnemonic,
    sign_payload_from_seed,
    verify_envelope,
)

payload = b"quip-signer wheel smoke test"

# Object surface: mnemonic -> sign -> verify, and the documented byte lengths.
signer = HybridSigner.from_mnemonic(
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
)
assert len(signer.public_key) == 1344, "unexpected public key length"
assert len(signer.account_id) == 32, "unexpected account id length"
assert verify_envelope(payload, signer.sign(payload), signer.account_id), \
    "object-path sign/verify failed"

# Free-function surface: seed -> public -> account, and a seed-based round-trip.
seed = seed_from_mnemonic("0x" + "07" * 32)
account = account_id_from_public(public_from_seed(seed))
assert account == HybridSigner.from_seed(seed).account_id, "account derivation mismatch"
assert verify_envelope(payload, sign_payload_from_seed(seed, payload), account), \
    "free-function sign/verify failed"

print("quip-signer wheel smoke test: import + sign/verify OK")
PY
)

if [[ "${mode}" == "check" ]]; then
	twine check "${DIST}"/*
	exit 0
fi

# --- publish: OIDC mint + twine upload ------------------------------------
# TestPyPI and PyPI are independent Trusted-Publishing realms: different OIDC
# audience (set job-side via id_tokens), different mint endpoint, different
# upload URL, and a separate per-project publisher config. The job hands us one
# JWT in PYPI_ID_TOKEN; we exchange it for that project's short-lived API token
# and upload with it. (No multi-package JWT juggling here -- one package, one
# token -- because PyPI's mint endpoint is only single-use per JWT, which only
# bites monorepos publishing several projects from one job.)
case "${target}" in
testpypi)
	mint_url="https://test.pypi.org/_/oidc/mint-token"
	repo_url="https://test.pypi.org/legacy/"
	;;
pypi)
	mint_url="https://pypi.org/_/oidc/mint-token"
	repo_url="https://upload.pypi.org/legacy/"
	;;
esac

: "${PYPI_ID_TOKEN:?PYPI_ID_TOKEN is required for publish mode (OIDC trusted publishing -- set by the GitLab id_tokens block in .gitlab-ci.yml)}"

# Build the request body with python3 rather than string interpolation so a JWT
# containing characters significant to the shell or JSON can't break the body
# (none expected -- JWTs are base64url -- but belt-and-suspenders).
body="$(python3 -c 'import json,sys; print(json.dumps({"token": sys.argv[1]}))' "${PYPI_ID_TOKEN}")"

# --fail-with-body: on a non-2xx, curl still prints the response body (which
# carries the registry's error message) before exiting non-zero.
if ! response="$(curl -sS --fail-with-body -X POST "${mint_url}" \
	-H "Content-Type: application/json" -d "${body}")"; then
	echo "Failed to mint ${target} API token: ${response}" >&2
	exit 1
fi

# A 200 can still carry an error payload (e.g. publisher-config mismatch) with
# no "token" field, so treat a missing token as failure and surface the whole
# response -- with any token value redacted -- to make the misconfig debuggable.
api_token="$(printf '%s' "${response}" |
	python3 -c 'import sys,json; print(json.load(sys.stdin).get("token") or "")' 2>/dev/null || true)"

if [[ -z "${api_token}" ]]; then
	safe_response="$(printf '%s' "${response}" | sed 's/"token":"[^"]*"/"token":"[REDACTED]"/g')"
	echo "Failed to mint ${target} API token (no token in response): ${safe_response}" >&2
	exit 1
fi

# --skip-existing makes re-running a tag pipeline idempotent: re-uploading an
# already-published version is a no-op rather than a hard error, which matters
# because the pyproject version only bumps per release (a re-tag at the same
# version must not fail the pipeline).
TWINE_USERNAME=__token__ TWINE_PASSWORD="${api_token}" \
	twine upload --non-interactive --skip-existing --repository-url "${repo_url}" "${DIST}"/*
