use crate::{
    circuit::ShuffleCircuit, data_structures::*, error::ShuffleError, prove::prove_as_subprotocol,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use std::marker::PhantomData;

// Tracing target constants
const LOG_TARGET: &str = "shuffle::setup";

#[derive(Clone, Debug)]
pub enum ProofSystem {
    Groth16,
    Spartan,
    Both,
}

pub struct ShuffleSetup<E: ark_ec::pairing::Pairing, G2: SWCurveConfig> {
    pub groth16_pk: Option<ProvingKey<E>>,
    pub groth16_vk: Option<VerifyingKey<E>>,
    pub spartan_gens: Option<Vec<u8>>, // Serialized SNARKGens
    pub spartan_comm: Option<Vec<u8>>, // Serialized commitment
    pub constraint_count: usize,
    pub public_input_count: usize,
    _phantom: PhantomData<G2>,
}

/// Main proof function with setup
pub fn prove_with_setup<E, G2>(
    seed: G2::BaseField,
    input_deck: EncryptedDeck<Projective<G2>>,
    shuffler_keys: &ElGamalKeys<Projective<G2>>,
    setup: &ShuffleSetup<E, G2>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    G2: SWCurveConfig,
    E: ark_ec::pairing::Pairing<ScalarField = G2::BaseField>,
    G2::BaseField: PrimeField + Absorb,
{
    let mut metrics = ProofMetrics::default();
    let _total_span = tracing::info_span!(target: LOG_TARGET, "prove_total").entered();

    // 1. Call prove_as_subprotocol
    let shuffle_proof = {
        let _span = tracing::info_span!(target: LOG_TARGET, "witness_synthesis").entered();
        let start = std::time::Instant::now();
        let result = prove_as_subprotocol::<Projective<G2>>(seed, input_deck, shuffler_keys)?;
        metrics.witness_synthesis_time = start.elapsed();
        result
    };

    // 2. Create constraint system with witnesses
    let _cs = {
        let _span = tracing::info_span!(target: LOG_TARGET, "constraint_generation").entered();
        let start = std::time::Instant::now();

        let cs = ConstraintSystem::<G2::BaseField>::new_ref();

        // Create and run the circuit
        let circuit =
            ShuffleCircuit::<G2>::new(shuffler_keys.public_key, shuffle_proof.clone(), seed);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| ShuffleError::Synthesis(e))?;

        // Verify constraint count matches setup if provided
        if setup.constraint_count > 0 {
            assert_eq!(
                cs.num_constraints(),
                setup.constraint_count,
                "Circuit structure changed since setup!"
            );
        }

        metrics.constraint_generation_time = start.elapsed();
        metrics.constraint_count = cs.num_constraints();
        metrics.witness_count = cs.num_witness_variables();

        tracing::info!(
            target = LOG_TARGET,
            "Witness synthesis complete: {} constraints, {} witnesses in {:?}",
            metrics.constraint_count,
            metrics.witness_count,
            metrics.constraint_generation_time
        );

        cs
    };

    // 3. Generate proof using precomputed parameters
    let proof_bytes = {
        let _span = tracing::info_span!(target: LOG_TARGET, "proof_generation").entered();
        let start = std::time::Instant::now();

        let result = match proof_system {
            ProofSystem::Groth16 => {
                let pk = setup
                    .groth16_pk
                    .as_ref()
                    .ok_or(ShuffleError::SetupNotFound)?;

                // Create the proving circuit
                let circuit =
                    ShuffleCircuit::<G2>::new(shuffler_keys.public_key, shuffle_proof, seed);

                let proof = Groth16::<E>::prove(
                    pk,
                    circuit,
                    &mut ark_std::rand::rngs::StdRng::seed_from_u64(1234),
                )
                .map_err(|e| {
                    ShuffleError::Synthesis(ark_relations::r1cs::SynthesisError::from(e))
                })?;

                let mut proof_bytes = Vec::new();
                proof
                    .serialize_compressed(&mut proof_bytes)
                    .map_err(|e| ShuffleError::Serialization(e.to_string()))?;
                proof_bytes
            }
            ProofSystem::Spartan => {
                // For now, we'll skip Spartan implementation due to version conflicts
                // The Spartan library needs to be updated to use the same arkworks version
                return Err(ShuffleError::InvalidInput(
                    "Spartan proof system not yet fully implemented".to_string(),
                ));
            }
            _ => {
                return Err(ShuffleError::InvalidInput(
                    "Invalid proof system".to_string(),
                ))
            }
        };

        metrics.proof_generation_time = start.elapsed();
        metrics.proof_size_bytes = result.len();
        result
    };

    // Calculate total time
    let _total_start = std::time::Instant::now();
    metrics.total_time = metrics.constraint_generation_time
        + metrics.witness_synthesis_time
        + metrics.proof_generation_time;

    Ok((proof_bytes, metrics))
}

/// Setup function - generates proving/verifying keys
pub fn setup<E, G2>(proof_system: ProofSystem) -> Result<ShuffleSetup<E, G2>, ShuffleError>
where
    G2: SWCurveConfig,
    E: ark_ec::pairing::Pairing<ScalarField = G2::BaseField>,
    G2::BaseField: PrimeField + Absorb,
{
    let _setup_span = tracing::info_span!(target: LOG_TARGET, "setup_total").entered();
    tracing::info!(target: LOG_TARGET, "Starting setup phase");

    // We need to run the circuit once to get the constraint count
    let (constraint_count, public_input_count, sample_proof, sample_keys, sample_seed) = {
        let _span = tracing::info_span!(target: LOG_TARGET, "circuit_analysis").entered();

        let cs = ConstraintSystem::<G2::BaseField>::new_ref();

        // Create a sample proof to determine circuit structure
        let sample_deck = generate_sample_deck::<Projective<G2>>();
        let sample_keys = ElGamalKeys::new(G2::ScalarField::from(1u64));
        let sample_seed = G2::BaseField::from(42u64);
        let sample_proof =
            prove_as_subprotocol::<Projective<G2>>(sample_seed, sample_deck, &sample_keys)?;

        // Generate the circuit to count constraints
        let circuit =
            ShuffleCircuit::<G2>::new(sample_keys.public_key, sample_proof.clone(), sample_seed);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|e| ShuffleError::Synthesis(e))?;

        let constraint_count = cs.num_constraints();
        let public_input_count = cs.num_instance_variables();

        tracing::info!(
            target = LOG_TARGET,
            "Circuit has {} constraints, {} public inputs",
            constraint_count,
            public_input_count
        );

        (
            constraint_count,
            public_input_count,
            sample_proof,
            sample_keys,
            sample_seed,
        )
    };

    // Generate proof system specific parameters
    let (groth16_pk, groth16_vk, spartan_gens, spartan_comm) = match proof_system {
        ProofSystem::Groth16 => {
            let _span = tracing::info_span!(target: LOG_TARGET, "groth16_setup").entered();
            tracing::info!(target: LOG_TARGET, "Generating Groth16 setup");

            // Use the sample circuit for setup
            let circuit =
                ShuffleCircuit::<G2>::new(sample_keys.public_key, sample_proof, sample_seed);

            let (pk, vk) = Groth16::<E>::circuit_specific_setup(
                circuit,
                &mut ark_std::rand::rngs::StdRng::seed_from_u64(1234),
            )
            .map_err(|e| ShuffleError::Synthesis(ark_relations::r1cs::SynthesisError::from(e)))?;
            (Some(pk), Some(vk), None, None)
        }
        ProofSystem::Spartan => {
            let _span = tracing::info_span!(target: LOG_TARGET, "spartan_setup").entered();
            tracing::info!(target: LOG_TARGET, "Generating Spartan setup");

            // For now, we'll skip Spartan setup due to version conflicts
            // The Spartan library needs to be updated to use the same arkworks version
            let spartan_gens_placeholder = Vec::new();
            let spartan_comm_placeholder = Vec::new();

            (
                None,
                None,
                Some(spartan_gens_placeholder),
                Some(spartan_comm_placeholder),
            )
        }
        ProofSystem::Both => {
            return Err(ShuffleError::InvalidInput(
                "Both proof systems not yet implemented".to_string(),
            ));
        }
    };

    tracing::info!(target = LOG_TARGET, "Setup completed");

    Ok(ShuffleSetup {
        groth16_pk,
        groth16_vk,
        spartan_gens,
        spartan_comm,
        constraint_count,
        public_input_count,
        _phantom: PhantomData,
    })
}

/// Convert arkworks R1CS format to Spartan format
#[allow(dead_code)]
fn convert_to_spartan_format<F>(
    _matrices: &ConstraintMatrices<F>,
    _witness: &[F],
    _inputs: &[F],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ShuffleError>
where
    F: PrimeField,
{
    // For now, return placeholder data
    // The actual Spartan conversion would require the Spartan library to use the same arkworks version
    Ok((Vec::new(), Vec::new(), Vec::new()))
}

/// Convenience function without setup (for testing/single use)
pub fn prove<E, G2>(
    seed: G2::BaseField,
    input_deck: EncryptedDeck<Projective<G2>>,
    shuffler_keys: &ElGamalKeys<Projective<G2>>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    G2: SWCurveConfig,
    E: ark_ec::pairing::Pairing<ScalarField = G2::BaseField>,
    G2::BaseField: PrimeField + Absorb,
{
    let setup = setup::<E, G2>(proof_system.clone())?;
    prove_with_setup::<E, G2>(seed, input_deck, shuffler_keys, &setup, proof_system)
}

fn generate_sample_deck<C: CurveGroup>() -> EncryptedDeck<C>
where
    C::ScalarField: PrimeField,
{
    let generator = C::generator();
    let dummy_cards: Vec<ElGamalCiphertext<C>> = (0..DECK_SIZE)
        .map(|i| {
            let scalar = C::ScalarField::from((i + 1) as u64);
            let scalar_bigint = scalar.into_bigint();
            ElGamalCiphertext {
                c1: generator.mul_bigint(scalar_bigint),
                c2: generator.mul_bigint(scalar_bigint),
            }
        })
        .collect();

    EncryptedDeck::new(dummy_cards).unwrap()
}

// Test
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::{CurveConfig, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
    use ark_snark::SNARK;
    use std::sync::Once;

    const TEST_TARGET: &str = "shuffle";
    static INIT: Once = Once::new();

    fn init_tracing() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_target(true)
                .with_level(true)
                .with_line_number(true)
                .with_file(true)
                .with_timer(tracing_subscriber::fmt::time::uptime())
                .with_max_level(tracing::Level::DEBUG)
                .init();
        });
    }

    #[test]
    fn test_generate_sample_deck() -> Result<(), Box<dyn std::error::Error>> {
        init_tracing();
        // Use GrumpkinProjective as the curve
        let input_deck = generate_sample_deck::<GrumpkinProjective>();
        assert_eq!(input_deck.cards.len(), DECK_SIZE);

        // GrumpkinProjective has:
        // - BaseField = BN254's Fr (since Grumpkin's Fq = BN254's Fr)
        // - ScalarField = BN254's Fq (since Grumpkin's Fr = BN254's Fq)

        // For the seed, we need Grumpkin's base field (which is BN254's Fr)
        let seed = <GrumpkinProjective as CurveGroup>::BaseField::rand(&mut rand::thread_rng());

        // For ElGamal keys, we need Grumpkin's scalar field (which is BN254's Fq)
        let private_key =
            <GrumpkinConfig as CurveConfig>::ScalarField::rand(&mut rand::thread_rng());
        let public_key: GrumpkinProjective = GrumpkinProjective::generator() * private_key;
        let shuffler_keys = ElGamalKeys { private_key, public_key };

        // Making a proof
        let proof = prove_as_subprotocol::<GrumpkinProjective>(seed, input_deck, &shuffler_keys)?;

        // Create the circuit - GrumpkinConfig implements SWCurveConfig
        let circuit: ShuffleCircuit<GrumpkinConfig> =
            ShuffleCircuit::new(shuffler_keys.public_key, proof, seed);

        let mut rng = rand::thread_rng();

        // Guard for measuring constraint system generation time
        let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());
        {
            let _constraint_span =
                tracing::info_span!(target: TEST_TARGET, "constraint_system_generation").entered();

            tracing::debug!(target: TEST_TARGET, "Trying to generate constraints");

            circuit.clone().generate_constraints(cs.clone())?;

            tracing::info!(
                target: TEST_TARGET,
                num_constraints = cs.num_constraints(),
                num_instance_vars = cs.num_instance_variables(),
                num_witness_vars = cs.num_witness_variables(),
                "Constraint system generated"
            );
        }

        // Check if the constraint system is satisfied
        let is_satisfied = cs.is_satisfied()?;
        tracing::info!(
            target: TEST_TARGET,
            satisfied = is_satisfied,
            "Constraint system satisfaction check"
        );
        assert!(is_satisfied, "Constraint system should be satisfied");

        // Setup phase (derive proving and verification keys)
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)?;
        tracing::info!(target: TEST_TARGET, "Groth16 setup complete");

        // Guard for measuring proof generation time (includes witness synthesis)
        {
            let _proof_span =
                tracing::info_span!(target: TEST_TARGET, "proof_generation").entered();

            let _snark_proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;

            tracing::info!(target: TEST_TARGET, "SNARK proof generated successfully");
        }

        Ok(())
    }
}
