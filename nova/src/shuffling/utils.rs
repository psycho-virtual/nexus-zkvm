use crate::poseidon_config;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb, CryptographicSponge};
use ark_ff::PrimeField;

const LOG_TARGET: &str = "shuffling::util";

pub fn generate_random_values<F: Absorb + PrimeField>(seed: F, count: usize) -> Vec<F> {
    let config = poseidon_config::<F>();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb the seed
    sponge.absorb(&seed);

    // Generate random values
    let values: Vec<F> = (0..count)
        .map(|_| sponge.squeeze_field_elements(1)[0])
        .collect();

    values
}
