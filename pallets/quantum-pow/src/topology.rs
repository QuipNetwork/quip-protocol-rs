use alloc::vec::Vec;
use codec::Encode;
use sp_core::H256;

pub fn hash_topology(nodes: &[u32], edges: &[(u32, u32)]) -> H256 {
    let mut canonical_nodes = nodes.to_vec();
    canonical_nodes.sort_unstable();

    let mut canonical_edges: Vec<(u32, u32)> = edges
        .iter()
        .map(|&(u, v)| if u <= v { (u, v) } else { (v, u) })
        .collect();
    canonical_edges.sort_unstable();

    H256::from(sp_io::hashing::blake2_256(
        &(canonical_nodes, canonical_edges).encode(),
    ))
}

pub fn verify_topology_hash(nodes: &[u32], edges: &[(u32, u32)], expected: H256) -> bool {
    hash_topology(nodes, edges) == expected
}
