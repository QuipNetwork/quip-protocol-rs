#!/usr/bin/env python3
"""
Generate parity fixtures for the Rust `quantum-validation` crate.

This script uses the actual Python reference implementation from:

- shared/quantum_proof_of_work.py

That is the intended source of truth for the parity-covered paths here:

- energy_of_solution
- expected_solution_energy
- calculate_hamming_distance
- calculate_diversity
- _validate_topology_consistency
- validate_solution
- ising_nonce_from_block
- generate_ising_model_from_nonce

For the `ising` path, this script also consumes the shared Python test-vector
file at `tests/chacha8_test_vectors.json`, which is intended to be shared
across Python and Rust.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


def load_reference_impl():
    root = Path(__file__).resolve().parent.parent
    default_python_repo = root.parent / "quip-protocol"
    python_repo = Path(os.environ.get("QUIP_PROTOCOL_ROOT", default_python_repo))
    sys.path.insert(0, str(python_repo))

    try:
        from shared.quantum_proof_of_work import (  # type: ignore
            _validate_topology_consistency,
            calculate_diversity,
            calculate_hamming_distance,
            energy_of_solution,
            generate_ising_model_from_nonce,
            ising_nonce_from_block,
            validate_solution,
        )
        from shared.energy_utils import expected_solution_energy  # type: ignore
    except ModuleNotFoundError as error:
        raise SystemExit(
            "failed to import the Python reference implementation from "
            f"{python_repo}. Install the quip-protocol Python dependencies and "
            "rerun this script in that environment. Original error: "
            f"{error!r}"
        ) from error
    return (
        python_repo,
        energy_of_solution,
        expected_solution_energy,
        calculate_hamming_distance,
        calculate_diversity,
        _validate_topology_consistency,
        ising_nonce_from_block,
        generate_ising_model_from_nonce,
        validate_solution,
    )


def milli(value: float) -> int:
    return int(round(value * 1000))


def build_fixture():
    (
        python_repo,
        energy_of_solution,
        expected_solution_energy,
        calculate_hamming_distance,
        calculate_diversity,
        validate_topology_consistency,
        ising_nonce_from_block,
        generate_ising_model_from_nonce,
        validate_solution,
    ) = load_reference_impl()
    chacha_vectors = json.loads(
        (python_repo / "tests" / "chacha8_test_vectors.json").read_text()
    )

    energy_cases = [
        {
            "name": "simple_two_spin",
            "nodes": [0, 1],
            "h": [500, -1000],
            "edges": [[0, 1]],
            "j": [250],
            "solution": [1, -1],
        },
        {
            "name": "noncontiguous_nodes",
            "nodes": [3, 7, 9],
            "h": [1000, 0, -500],
            "edges": [[3, 7], [7, 9]],
            "j": [-1000, 500],
            "solution": [-1, 1, 1],
        },
        {
            "name": "four_spin_mixed_couplings",
            "nodes": [4, 2, 8, 6],
            "h": [250, -750, 500, 0],
            "edges": [[4, 2], [2, 8], [8, 6], [4, 6]],
            "j": [1000, -500, 750, -1250],
            "solution": [1, 1, -1, -1],
        },
    ]

    for case in energy_cases:
        h = {node: field / 1000.0 for node, field in zip(case["nodes"], case["h"])}
        J = {
            tuple(edge): coupling / 1000.0
            for edge, coupling in zip(case["edges"], case["j"])
        }
        case["expected_milli"] = milli(
            energy_of_solution(case["solution"], h, J, case["nodes"])
        )

    expected_gse_cases = [
        {"name": "small_sparse", "num_nodes": 100, "num_edges": 200},
        {"name": "small_dense", "num_nodes": 20, "num_edges": 190},
        {"name": "advantage_like", "num_nodes": 4580, "num_edges": 41567},
    ]

    for case in expected_gse_cases:
        case["expected_milli"] = milli(
            expected_solution_energy(
                num_nodes=case["num_nodes"],
                num_edges=case["num_edges"],
            )
        )

    diversity_cases = [
        {
            "name": "three_solutions",
            "solutions": [[1, -1], [-1, 1], [1, 1]],
        },
        {
            "name": "with_global_flip_symmetry",
            "solutions": [[1, 1, 1], [-1, -1, -1], [1, -1, 1]],
        },
        {
            "name": "identical_solutions",
            "solutions": [[1, -1, 1, -1], [1, -1, 1, -1]],
        },
    ]

    for case in diversity_cases:
        case["expected_milli"] = milli(calculate_diversity(case["solutions"]))

    hamming_cases = [
        {
            "name": "global_flip_is_zero",
            "a": [1, -1, 1],
            "b": [-1, 1, -1],
        },
        {
            "name": "partial_difference",
            "a": [1, 1, -1, -1],
            "b": [1, -1, -1, 1],
        },
        {
            "name": "half_flip",
            "a": [1, 1, 1, 1],
            "b": [-1, -1, 1, 1],
        },
    ]

    for case in hamming_cases:
        case["expected"] = int(calculate_hamming_distance(case["a"], case["b"]))

    derive_nonce_cases = []
    for case in chacha_vectors["derive_nonce"]:
        derive_nonce_cases.append(
            {
                "name": f"{case['miner_id']}/blk{case['block_number']}",
                "parent_hash_hex": case["parent_hash_hex"],
                "miner": case["miner_id"],
                "block_number": case["block_number"],
                "salt_hex": case["salt_hex"],
                "expected_nonce": int(case["expected_nonce"]),
            }
        )

    ising_model_cases = []
    for case in chacha_vectors["generate_ising_model"]:
        edges = [tuple(edge) for edge in case["edges"]]
        h, J = generate_ising_model_from_nonce(
            case["nonce"],
            case["nodes"],
            edges,
            case["allowed_h_values"],
        )
        ising_model_cases.append(
            {
                "name": f"nonce={case['nonce']}/n{len(case['nodes'])}e{len(case['edges'])}",
                "nonce": case["nonce"],
                "nodes": case["nodes"],
                "edges": case["edges"],
                "allowed_h_values": [milli(value) for value in case["allowed_h_values"]],
                "expected_h": [milli(h[node]) for node in case["nodes"]],
                "expected_j": [
                    milli(J[tuple(edge)])
                    for edge in case["edges"]
                ],
            }
        )

    topology_cases = [
        {
            "name": "valid_binary_topology",
            "nodes": [0, 1],
            "h": [0, 1000],
            "edges": [[0, 1]],
            "j": [1000],
            "allowed_h_values": [-1000, 0, 1000],
            "allowed_j_values": [-1000, 1000],
        },
        {
            "name": "invalid_h_value",
            "nodes": [0, 1],
            "h": [250, 1000],
            "edges": [[0, 1]],
            "j": [1000],
            "allowed_h_values": [-1000, 0, 1000],
            "allowed_j_values": [-1000, 1000],
        },
        {
            "name": "invalid_j_value",
            "nodes": [0, 1],
            "h": [0, 1000],
            "edges": [[0, 1]],
            "j": [500],
            "allowed_h_values": [-1000, 0, 1000],
            "allowed_j_values": [-1000, 1000],
        },
    ]

    for case in topology_cases:
        h = {node: field / 1000.0 for node, field in zip(case["nodes"], case["h"])}
        J = {
            tuple(edge): coupling / 1000.0
            for edge, coupling in zip(case["edges"], case["j"])
        }
        case["expected_errors"] = validate_topology_consistency(
            h,
            J,
            case["nodes"],
            [tuple(edge) for edge in case["edges"]],
            [value / 1000.0 for value in case["allowed_h_values"]],
        )

    solution_validation_cases = [
        {
            "name": "valid_solution",
            "nodes": [0, 1],
            "h": [500, -1000],
            "edges": [[0, 1]],
            "j": [250],
            "spins": [1, -1],
        },
        {
            "name": "invalid_spin_value",
            "nodes": [0, 1],
            "h": [0, 1000],
            "edges": [[0, 1]],
            "j": [1000],
            "spins": [1, 0],
        },
        {
            "name": "invalid_j_value",
            "nodes": [0, 1],
            "h": [0, 1000],
            "edges": [[0, 1]],
            "j": [500],
            "spins": [1, -1],
        },
    ]

    for case in solution_validation_cases:
        h = {node: field / 1000.0 for node, field in zip(case["nodes"], case["h"])}
        J = {
            tuple(edge): coupling / 1000.0
            for edge, coupling in zip(case["edges"], case["j"])
        }
        validation = validate_solution(
            case["spins"],
            h,
            J,
            case["nodes"],
            [tuple(edge) for edge in case["edges"]],
        )
        case["expected_valid"] = bool(validation["valid"])
        case["expected_errors"] = list(validation["errors"])
        case["expected_energy_milli"] = milli(validation["energy"])
        case["expected_satisfaction_rate_milli"] = milli(
            validation["satisfaction_rate"]
        )

    return {
        "source": {
            "python_repo": str(python_repo),
            "python_file": "shared/quantum_proof_of_work.py",
            "chacha8_vectors_file": "tests/chacha8_test_vectors.json",
            "notes": [
                "Fixture generator imports the Python reference implementation directly for energy, diversity, topology, solution validation, and Ising generation.",
                "Ising nonce and model vectors are sourced from the shared Python chacha8_test_vectors.json file and normalized to Rust milli-precision arrays.",
            ],
        },
        "energy_cases": energy_cases,
        "expected_gse_cases": expected_gse_cases,
        "diversity_cases": diversity_cases,
        "hamming_cases": hamming_cases,
        "derive_nonce_cases": derive_nonce_cases,
        "ising_model_cases": ising_model_cases,
        "topology_cases": topology_cases,
        "solution_validation_cases": solution_validation_cases,
    }


def main():
    root = Path(__file__).resolve().parent.parent
    output_path = (
        root
        / "crates"
        / "quantum-validation"
        / "tests"
        / "fixtures"
        / "python_parity.json"
    )
    output_path.write_text(json.dumps(build_fixture(), indent=2) + "\n", encoding="utf-8")
    print(output_path)


if __name__ == "__main__":
    main()
