use crate::{
    circuit::generate_circuit, data_structures::*, error::ShuffleError, prove::prove_as_subprotocol,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    Group,
};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, ConstraintSystemRef};
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

pub struct ShuffleSetup<E: ark_ec::pairing::Pairing, G: SWCurveConfig> {
    pub groth16_pk: Option<ProvingKey<E>>,
    pub groth16_vk: Option<VerifyingKey<E>>,
    pub spartan_gens: Option<Vec<u8>>, // Serialized SNARKGens
    pub spartan_comm: Option<Vec<u8>>, // Serialized commitment
    pub constraint_count: usize,
    pub public_input_count: usize,
    _phantom: PhantomData<G>,
}

/// Main proof function with setup
#[tracing::instrument(target = LOG_TARGET, skip(input_deck, shuffler_keys, setup))]
pub fn prove_with_setup<E, G>(
    seed: E::ScalarField,
    input_deck: EncryptedDeck<G>,
    shuffler_keys: &ElGamalKeys<G>,
    setup: &ShuffleSetup<E, G>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    G: SWCurveConfig<BaseField = E::ScalarField>,
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField,
{
    let mut metrics = ProofMetrics::default();
    let _total_span = tracing::info_span!(target: LOG_TARGET, "prove_total").entered();

    // 1. Call prove_as_subprotocol
    let shuffle_proof = {
        let _span = tracing::info_span!(target: LOG_TARGET, "witness_synthesis").entered();
        let start = std::time::Instant::now();
        let result = prove_as_subprotocol::<G>(seed, input_deck, shuffler_keys)?;
        metrics.witness_synthesis_time = start.elapsed();
        result
    };

    // 2. Create constraint system with witnesses
    let cs = {
        let _span = tracing::info_span!(target: LOG_TARGET, "constraint_generation").entered();
        let start = std::time::Instant::now();

        let cs = ConstraintSystem::<E::ScalarField>::new_ref();

        // Generate public inputs
        cs.new_input_variable(|| Ok(seed))
            .map_err(|e| ShuffleError::Synthesis(e))?;

        generate_circuit::<G>(cs.clone(), shuffler_keys.public_key, &shuffle_proof, seed)?;

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
                let circuit = ShuffleCircuit::<E, G> {
                    shuffle_proof,
                    shuffler_public_key: shuffler_keys.public_key,
                    seed,
                    _phantom: std::marker::PhantomData,
                };

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
    let total_start = std::time::Instant::now();
    metrics.total_time = metrics.constraint_generation_time
        + metrics.witness_synthesis_time
        + metrics.proof_generation_time;

    Ok((proof_bytes, metrics))
}

/// Setup function - generates proving/verifying keys
#[tracing::instrument(target = LOG_TARGET, skip_all)]
pub fn setup<E, G>(proof_system: ProofSystem) -> Result<ShuffleSetup<E, G>, ShuffleError>
where
    G: SWCurveConfig<BaseField = E::ScalarField>,
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField,
{
    let _setup_span = tracing::info_span!(target: LOG_TARGET, "setup_total").entered();
    tracing::info!(target: LOG_TARGET, "Starting setup phase");

    // We need to run the circuit once to get the constraint count
    let (constraint_count, public_input_count, sample_proof, sample_keys, sample_seed) = {
        let _span = tracing::info_span!(target: LOG_TARGET, "circuit_analysis").entered();

        let cs = ConstraintSystem::<E::ScalarField>::new_ref();

        // Create a sample proof to determine circuit structure
        let sample_deck = generate_sample_deck::<G>();
        let sample_keys = ElGamalKeys::new(E::ScalarField::from(1u64));
        let sample_seed = E::ScalarField::from(42u64);
        let sample_proof = prove_as_subprotocol::<G>(sample_seed, sample_deck, &sample_keys)?;

        // Add public input
        cs.new_input_variable(|| Ok(sample_seed))
            .map_err(|e| ShuffleError::Synthesis(e))?;

        // Generate the circuit to count constraints
        generate_circuit::<G>(
            cs.clone(),
            sample_keys.public_key,
            &sample_proof,
            sample_seed,
        )?;

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
            let circuit = ShuffleCircuit::<E, G> {
                shuffle_proof: sample_proof,
                shuffler_public_key: sample_keys.public_key,
                seed: sample_seed,
                _phantom: std::marker::PhantomData,
            };

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

/// The actual shuffle circuit for pairing-based system
/// This uses the pairing's G1 and G2 groups
struct ShuffleCircuit<E: ark_ec::pairing::Pairing, G: SWCurveConfig>
where
    G: SWCurveConfig<BaseField = E::ScalarField>,
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField,
{
    shuffle_proof: ShuffleProof<G>,
    shuffler_public_key: Projective<G>,
    seed: G::BaseField,
    _phantom: std::marker::PhantomData<(E, G)>,
}

impl<E, G> ark_relations::r1cs::ConstraintSynthesizer<E::ScalarField> for ShuffleCircuit<E, G>
where
    G: SWCurveConfig<BaseField = E::ScalarField>,
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), ark_relations::r1cs::SynthesisError> {
        // Add seed as public input
        let _seed_var = cs.new_input_variable(|| Ok(self.seed))?;

        // Generate the circuit constraints
        generate_circuit::<G>(cs, self.shuffler_public_key, &self.shuffle_proof, self.seed)
    }
}

/// Convenience function without setup (for testing/single use)
pub fn prove<E, G>(
    seed: E::ScalarField,
    input_deck: EncryptedDeck<G>,
    shuffler_keys: &ElGamalKeys<G>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    G: SWCurveConfig<BaseField = E::ScalarField>,
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField,
{
    let setup = setup::<E, G>(proof_system.clone())?;
    prove_with_setup::<E, G>(seed, input_deck, shuffler_keys, &setup, proof_system)
}

fn generate_sample_deck<G: SWCurveConfig>() -> EncryptedDeck<G>
where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
{
    let generator = <Projective<G> as Group>::generator();
    let dummy_cards: Vec<ElGamalCiphertext<G>> = (0..DECK_SIZE)
        .map(|i| {
            let scalar = G::BaseField::from((i + 1) as u64);
            // Convert BaseField to ScalarField via BigInt
            let scalar_bigint = scalar.into_bigint();
            ElGamalCiphertext {
                c1: generator.mul_bigint(scalar_bigint),
                c2: generator.mul_bigint(scalar_bigint),
            }
        })
        .collect();

    EncryptedDeck::new(dummy_cards).unwrap()
}
