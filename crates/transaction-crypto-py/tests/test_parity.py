"""Golden-vector parity gate for the Python signer.

Reuses the *same* `golden_vectors.txt` baseline the Rust core and the WASM
signer are gated against (captured before the hybrid-crypto dedup refactor), so
all three implementations are provably byte-identical against one fixture.
"""

from pathlib import Path

import quip_signer

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "transaction-crypto-core"
    / "tests"
    / "golden_vectors.txt"
)

TEST_PHRASE = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"

MESSAGES = {
    "msg_quip": b"quip-message",
    "msg_empty": b"",
    "msg_fixture": b"quip-signer-fixture",
}


def _vectors() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in FIXTURE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        name, value = line.split("=", 1)
        out[name] = value
    return out


VEC = _vectors()


def test_public_keys_match_baseline() -> None:
    fixed_seeds = {
        "seed_01": bytes([1]) * 32,
        "seed_07": bytes([7]) * 32,
        "seed_09": bytes([9]) * 32,
        "seed_11": bytes([11]) * 32,
    }
    for name, seed in fixed_seeds.items():
        assert seed.hex() == VEC[f"{name}_seed"], f"{name}: seed drifted"
        public = quip_signer.public_from_seed(seed)
        assert isinstance(public, bytes)
        assert public.hex() == VEC[f"{name}_public"], f"{name}: public drifted"

    bip39 = quip_signer.seed_from_mnemonic(TEST_PHRASE)
    assert bip39.hex() == VEC["bip39_seed"]
    assert quip_signer.public_from_seed(bip39).hex() == VEC["bip39_public"]

    bip39_pw = quip_signer.seed_from_mnemonic(f"{TEST_PHRASE}///hunter2")
    assert bip39_pw.hex() == VEC["bip39_pw_seed"]
    assert quip_signer.public_from_seed(bip39_pw).hex() == VEC["bip39_pw_public"]


def test_signature_envelopes_match_baseline() -> None:
    bip39 = quip_signer.seed_from_mnemonic(TEST_PHRASE)
    seeds = {"seed_07": bytes([7]) * 32, "bip39": bip39}

    for sname, seed in seeds.items():
        for mname, msg in MESSAGES.items():
            envelope = quip_signer.sign_payload_from_seed(seed, msg)
            assert isinstance(envelope, bytes)
            assert (
                envelope.hex() == VEC[f"{sname}_{mname}_envelope"]
            ), f"{sname}/{mname}: envelope drifted"
