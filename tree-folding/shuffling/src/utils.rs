use nexus_nova::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::PrimeField;

const LOG_TARGET: &str = "tree_folding_shuffling::util";

pub fn generate_random_values<F: Absorb + PrimeField>(seed: F, count: usize) -> Vec<F> {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb the seed
    sponge.absorb(&seed);

    // Generate random values
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = sponge.squeeze_field_elements(1)[0];
        tracing::debug!(target: LOG_TARGET, "Generating random value {}", value);
        values.push(value);
    }

    values
}
