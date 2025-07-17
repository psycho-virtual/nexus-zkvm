use crate::{
    circuit::generate_circuit, data_structures::*, error::ShuffleError, prove::prove_as_subprotocol,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_r1cs_std::groups::CurveVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use std::time::Instant;

#[derive(Clone, Debug)]
pub enum ProofSystem {
    Groth16,
    Spartan,
    Both,
}

pub struct ShuffleSetup<E: ark_ec::pairing::Pairing> {
    pub groth16_pk: Option<ProvingKey<E>>,
    pub groth16_vk: Option<VerifyingKey<E>>,
    // pub spartan_pp: Option<SpartanPreprocessing<E::ScalarField>>,
    pub constraint_count: usize,
    pub public_input_count: usize,
}

/// Main proof function with setup
#[tracing::instrument(target = "shuffle::prove", skip(input_deck, shuffler_keys, setup))]
pub fn prove_with_setup<E, CV>(
    seed: E::ScalarField,
    input_deck: EncryptedDeck<E::G2>,
    shuffler_keys: &ElGamalKeys<E::G2>,
    setup: &ShuffleSetup<E>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    CV: CurveVar<E::G2, E::ScalarField>,
{
    let mut metrics = ProofMetrics::default();
    let total_start = Instant::now();

    // 1. Call prove_as_subprotocol
    let start = Instant::now();
    let shuffle_proof = prove_as_subprotocol::<E::G1, _>(seed, input_deck, shuffler_keys)?;
    metrics.witness_synthesis_time = start.elapsed();

    // 2. Create constraint system with witnesses
    let start = Instant::now();
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();

    // Set public inputs
    let _seed_input = cs
        .new_input_variable(|| Ok(seed))
        .map_err(|e| ShuffleError::Synthesis(e))?;
    // Note: We can't directly allocate the curve point as a scalar field element
    // The circuit will handle public key allocation internally

    generate_circuit::<E, CV>(
        cs.clone(),
        &shuffle_proof,
        &shuffler_keys.public_key,
        seed,
    )?;

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

    // 3. Generate proof using precomputed parameters
    let start = Instant::now();
    let proof_bytes = match proof_system {
        ProofSystem::Groth16 => {
            let pk = setup
                .groth16_pk
                .as_ref()
                .ok_or(ShuffleError::SetupNotFound)?;

            // Create the proving circuit
            let circuit = ShuffleCircuit::<E, CV> {
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
            .map_err(|e| ShuffleError::Synthesis(ark_relations::r1cs::SynthesisError::from(e)))?;

            let mut proof_bytes = Vec::new();
            proof
                .serialize_compressed(&mut proof_bytes)
                .map_err(|e| ShuffleError::Serialization(e.to_string()))?;
            proof_bytes
        }
        ProofSystem::Spartan => {
            return Err(ShuffleError::InvalidInput(
                "Spartan not yet implemented".to_string(),
            ));
        }
        _ => {
            return Err(ShuffleError::InvalidInput(
                "Invalid proof system".to_string(),
            ))
        }
    };

    metrics.proof_generation_time = start.elapsed();
    metrics.proof_size_bytes = proof_bytes.len();
    metrics.total_time = total_start.elapsed();

    Ok((proof_bytes, metrics))
}

/// Setup function - generates proving/verifying keys
#[tracing::instrument(target = "shuffle::setup", skip_all)]
pub fn setup<E, CV>(proof_system: ProofSystem) -> Result<ShuffleSetup<E>, ShuffleError>
where
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    CV: CurveVar<E::G2, E::ScalarField>,
{
    let start = Instant::now();
    tracing::info!(target = "shuffle::setup", "Starting setup phase");

    // We need to run the circuit once to get the constraint count
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();

    // Create a sample proof to determine circuit structure
    let sample_deck = generate_sample_deck::<E::G2>();
    let sample_keys = ElGamalKeys::new(E::ScalarField::from(1u64));
    let sample_seed = E::ScalarField::from(42u64);
    let sample_proof = prove_as_subprotocol::<E::G1, _>(sample_seed, sample_deck, &sample_keys)?;

    // Generate the circuit to count constraints
    generate_circuit::<E, CV>(
        cs.clone(),
        &sample_proof,
        &sample_keys.public_key,
        sample_seed,
    )?;

    let constraint_count = cs.num_constraints();
    let public_input_count = cs.num_instance_variables();

    tracing::info!(
        target = "shuffle::setup",
        "Circuit has {} constraints, {} public inputs",
        constraint_count,
        public_input_count
    );

    // Generate proof system specific parameters
    let (groth16_pk, groth16_vk) = match proof_system {
        ProofSystem::Groth16 | ProofSystem::Both => {
            tracing::info!(target = "shuffle::setup", "Generating Groth16 setup");

            // Use the sample circuit for setup
            let circuit = ShuffleCircuit::<E, CV> {
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
            (Some(pk), Some(vk))
        }
        ProofSystem::Spartan => (None, None),
    };

    let setup_time = start.elapsed();
    tracing::info!(
        target = "shuffle::setup",
        "Setup completed in {:?}",
        setup_time
    );

    Ok(ShuffleSetup {
        groth16_pk,
        groth16_vk,
        constraint_count,
        public_input_count,
    })
}

/// The actual shuffle circuit for pairing-based system
/// This uses the pairing's G1 and G2 groups
struct ShuffleCircuit<E: ark_ec::pairing::Pairing, CV> {
    shuffle_proof: ShuffleProof<E::G1, E::G2>,
    shuffler_public_key: E::G2,
    seed: E::ScalarField,
    _phantom: std::marker::PhantomData<CV>,
}

impl<E, CV> ark_relations::r1cs::ConstraintSynthesizer<E::ScalarField> for ShuffleCircuit<E, CV>
where
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    CV: CurveVar<E::G2, E::ScalarField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), ark_relations::r1cs::SynthesisError> {
        // For now, we need to use the compatibility function
        // This is a limitation of the current architecture
        generate_circuit::<E, CV>(
            cs,
            &self.shuffle_proof,
            &self.shuffler_public_key,
            self.seed,
        )
    }
}

/// Convenience function without setup (for testing/single use)
pub fn prove<E, CV>(
    seed: E::ScalarField,
    input_deck: EncryptedDeck<E::G2>,
    shuffler_keys: &ElGamalKeys<E::G2>,
    proof_system: ProofSystem,
) -> Result<(Vec<u8>, ProofMetrics), ShuffleError>
where
    E: ark_ec::pairing::Pairing,
    E::ScalarField: PrimeField + Absorb,
    CV: CurveVar<E::G2, E::ScalarField>,
{
    let setup = setup::<E, CV>(proof_system.clone())?;
    prove_with_setup::<E, CV>(seed, input_deck, shuffler_keys, &setup, proof_system)
}

fn generate_sample_deck<C: CurveGroup>() -> EncryptedDeck<C> {
    let generator = C::generator();
    let dummy_cards: Vec<ElGamalCiphertext<C>> = (0..DECK_SIZE)
        .map(|i| {
            let scalar = C::ScalarField::from((i + 1) as u64);
            ElGamalCiphertext {
                c1: generator * scalar,
                c2: generator * scalar,
            }
        })
        .collect();

    EncryptedDeck::new(dummy_cards).unwrap()
}
