use crate::poseidon_config::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::PrimeField;

pub fn generate_random_values<F: PrimeField + Absorb>(seed: F, count: usize) -> Vec<F> {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb the seed
    sponge.absorb(&seed);

    // Generate random values
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(sponge.squeeze_field_elements(1)[0]);
    }

    values
}

pub fn sort_with_permutation<T: Clone, K: Ord>(associated_list: &[(T, K)]) -> (Vec<T>, Vec<usize>) {
    // Create indexed list: [(original_index, (item, sort_key))]
    let mut indexed_list: Vec<(usize, (&T, &K))> = associated_list
        .iter()
        .enumerate()
        .map(|(idx, (item, key))| (idx, (item, key)))
        .collect();

    // Sort by the sort keys (second element of the tuple)
    indexed_list.sort_by_key(|(_, (_, key))| *key);

    // Extract the permutation (which original index ended up where)
    let permutation: Vec<usize> = indexed_list.iter().map(|(idx, _)| *idx).collect();

    // Extract the sorted items in their new order
    let sorted_items: Vec<T> = indexed_list
        .iter()
        .map(|(_, (item, _))| (*item).clone())
        .collect();

    (sorted_items, permutation)
}
