use quantum_validation::{
    calculate_diversity, derive_nonce, energy_of_solution, expected_gse, generate_ising_model,
    symmetric_hamming, validate_solution, validate_topology_consistency,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureFile {
    energy_cases: Vec<EnergyCase>,
    expected_gse_cases: Vec<ExpectedGseCase>,
    diversity_cases: Vec<DiversityCase>,
    hamming_cases: Vec<HammingCase>,
    derive_nonce_cases: Vec<DeriveNonceCase>,
    ising_model_cases: Vec<IsingModelCase>,
    topology_cases: Vec<TopologyCase>,
    solution_validation_cases: Vec<SolutionValidationCase>,
}

#[derive(Debug, Deserialize)]
struct EnergyCase {
    name: String,
    nodes: Vec<u32>,
    h: Vec<i32>,
    edges: Vec<[u32; 2]>,
    j: Vec<i32>,
    solution: Vec<i8>,
    expected_milli: i64,
}

#[derive(Debug, Deserialize)]
struct DiversityCase {
    name: String,
    solutions: Vec<Vec<i8>>,
    expected_milli: u32,
}

#[derive(Debug, Deserialize)]
struct HammingCase {
    name: String,
    a: Vec<i8>,
    b: Vec<i8>,
    expected: u32,
}

#[derive(Debug, Deserialize)]
struct ExpectedGseCase {
    name: String,
    num_nodes: u32,
    num_edges: u32,
    expected_milli: i64,
}

#[derive(Debug, Deserialize)]
struct DeriveNonceCase {
    name: String,
    parent_hash_hex: String,
    miner: String,
    block_number: u32,
    salt_hex: String,
    expected_nonce: u64,
}

#[derive(Debug, Deserialize)]
struct IsingModelCase {
    name: String,
    nonce: u64,
    nodes: Vec<u32>,
    edges: Vec<[u32; 2]>,
    allowed_h_values: Vec<i32>,
    expected_h: Vec<i32>,
    expected_j: Vec<i32>,
}

#[derive(Debug, Deserialize)]
struct TopologyCase {
    name: String,
    nodes: Vec<u32>,
    h: Vec<i32>,
    edges: Vec<[u32; 2]>,
    j: Vec<i32>,
    allowed_h_values: Vec<i32>,
    allowed_j_values: Vec<i32>,
    expected_errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SolutionValidationCase {
    name: String,
    nodes: Vec<u32>,
    h: Vec<i32>,
    edges: Vec<[u32; 2]>,
    j: Vec<i32>,
    spins: Vec<i8>,
    expected_valid: bool,
    expected_errors: Vec<String>,
    expected_energy_milli: i64,
    expected_satisfaction_rate_milli: u32,
}

fn load_fixture() -> FixtureFile {
    serde_json::from_str(include_str!("fixtures/python_parity.json"))
        .expect("python parity fixture must be valid JSON")
}

#[test]
fn energy_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.energy_cases {
        let edges: Vec<(u32, u32)> = case.edges.iter().map(|edge| (edge[0], edge[1])).collect();
        let actual = energy_of_solution(&case.solution, &case.h, &edges, &case.j, &case.nodes)
            .unwrap_or_else(|error| panic!("energy case {} failed: {error}", case.name));

        assert_eq!(actual, case.expected_milli, "energy case {}", case.name);
    }
}

#[test]
fn expected_gse_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.expected_gse_cases {
        let actual = expected_gse(case.num_nodes, case.num_edges);

        assert_eq!(
            actual, case.expected_milli,
            "expected_gse case {}",
            case.name
        );
    }
}

#[test]
fn diversity_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.diversity_cases {
        let actual = calculate_diversity(&case.solutions)
            .unwrap_or_else(|error| panic!("diversity case {} failed: {error}", case.name));

        assert_eq!(actual, case.expected_milli, "diversity case {}", case.name);
    }
}

#[test]
fn symmetric_hamming_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.hamming_cases {
        let actual = symmetric_hamming(&case.a, &case.b)
            .unwrap_or_else(|error| panic!("hamming case {} failed: {error}", case.name));

        assert_eq!(actual, case.expected, "hamming case {}", case.name);
    }
}

#[test]
fn derive_nonce_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.derive_nonce_cases {
        let parent_hash = hex::decode(&case.parent_hash_hex)
            .unwrap_or_else(|error| panic!("parent_hash decode {} failed: {error}", case.name));
        let salt = hex::decode(&case.salt_hex)
            .unwrap_or_else(|error| panic!("salt decode {} failed: {error}", case.name));
        let actual = derive_nonce(
            &parent_hash,
            case.miner.as_bytes(),
            case.block_number,
            &salt,
        );

        assert_eq!(
            actual, case.expected_nonce,
            "derive_nonce case {}",
            case.name
        );
    }
}

#[test]
fn generate_ising_model_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.ising_model_cases {
        let edges: Vec<(u32, u32)> = case.edges.iter().map(|edge| (edge[0], edge[1])).collect();
        let (actual_h, actual_j) =
            generate_ising_model(case.nonce, &case.nodes, &edges, &case.allowed_h_values)
                .unwrap_or_else(|error| panic!("ising case {} failed: {error}", case.name));

        assert_eq!(actual_h, case.expected_h, "ising h case {}", case.name);
        assert_eq!(actual_j, case.expected_j, "ising j case {}", case.name);
    }
}

#[test]
fn topology_consistency_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.topology_cases {
        let edges: Vec<(u32, u32)> = case.edges.iter().map(|edge| (edge[0], edge[1])).collect();
        let actual = validate_topology_consistency(
            &case.nodes,
            &edges,
            &case.h,
            &case.j,
            Some(&case.allowed_h_values),
            Some(&case.allowed_j_values),
        );

        assert_eq!(actual, case.expected_errors, "topology case {}", case.name);
    }
}

#[test]
fn solution_validation_matches_python_reference_vectors() {
    let fixture = load_fixture();

    for case in &fixture.solution_validation_cases {
        let edges: Vec<(u32, u32)> = case.edges.iter().map(|edge| (edge[0], edge[1])).collect();
        let actual = validate_solution(
            &case.spins,
            &case.nodes,
            &edges,
            &case.h,
            &case.j,
            None,
            Some(&[-1_000, 1_000]),
        );

        assert_eq!(
            actual.valid, case.expected_valid,
            "solution valid {}",
            case.name
        );
        assert_eq!(
            actual.errors, case.expected_errors,
            "solution errors {}",
            case.name
        );
        assert_eq!(
            actual.energy_milli, case.expected_energy_milli,
            "solution energy {}",
            case.name
        );
        assert_eq!(
            actual.satisfaction_rate_milli, case.expected_satisfaction_rate_milli,
            "solution satisfaction {}",
            case.name
        );
    }
}
