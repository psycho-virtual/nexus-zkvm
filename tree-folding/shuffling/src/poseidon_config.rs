use ark_ff::PrimeField;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};

/// Returns config for poseidon sponge with 128-bit security.
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 57;
    const ALPHA: u64 = 5;
    const RATE: usize = 2;
    const CAPACITY: usize = 1;

    let _span = tracing::info_span!(
        target: "shuffle::poseidon", 
        "poseidon_param_generation",
        field_bits = F::MODULUS_BIT_SIZE
    ).entered();
    
    tracing::info!(target: "shuffle::poseidon", "Starting Poseidon parameter generation");
    
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    
    tracing::info!(target: "shuffle::poseidon", "Poseidon parameter generation completed");

    PoseidonConfig {
        full_rounds: FULL_ROUNDS,
        partial_rounds: PARTIAL_ROUNDS,
        alpha: ALPHA,
        ark,
        mds,
        rate: RATE,
        capacity: CAPACITY,
    }
}