//! Binary for generating Spartan proofs for RS Shuffle with Re-encryption Circuit
//!
//! This binary demonstrates how to:
//! 1. Create an RSShuffleWithReencryptionCircuit
//! 2. Generate R1CS constraints
//! 3. Create and verify a Spartan SNARK proof
//!
//! Usage: cargo run --bin rs_shuffle_spartan_proof --release

use ark_bn254::{Bn254, Fr as BaseField, G1Projective as Bn254Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use ark_spartan::polycommitments::zeromorph::Zeromorph;
use ark_spartan::{Assignment, Instance, SNARKGens, VarsAssignment, SNARK};
use ark_std::UniformRand;
use merlin::Transcript;
use nexus_nova::shuffling::rs_shuffle::WitnessData;
use nexus_nova::shuffling::{
    data_structures::ElGamalCiphertext,
    rs_shuffle::{
        circuit::RSShuffleWithReencryptionCircuit,
        witness_preparation::apply_rs_shuffle_permutation, LEVELS, N,
    },
};
use nexus_nova::zeromorph::PolyCommitmentScheme;
use std::time::Instant;
use tracing::info;

/// Type alias for the polynomial commitment scheme
/// We use BN254 for Spartan since it supports pairings
type PC = Zeromorph<Bn254>;

/// Generate test data for the RS shuffle with re-encryption circuit
fn generate_test_data() -> (
    Vec<ElGamalCiphertext<GrumpkinProjective>>, // initial ciphertexts
    Vec<ElGamalCiphertext<GrumpkinProjective>>, // shuffled ciphertexts
    Vec<ElGamalCiphertext<GrumpkinProjective>>, // final re-encrypted ciphertexts
    GrumpkinProjective,                         // shuffler public key
    Vec<BaseField>,                             // re-encryption randomizations
    BaseField,                                  // seed
    BaseField,                                  // alpha
    BaseField,                                  // beta
    WitnessData<N, LEVELS>,                     // witness data
    usize,                                      // num_samples
) {
    info!("Generating test data for RS shuffle with re-encryption...");

    let mut rng = ark_std::test_rng();
    let generator = GrumpkinProjective::generator();

    // Generate shuffler keys
    let shuffler_private_key = <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::rand(&mut rng);
    let shuffler_public_key = generator * shuffler_private_key;

    // Create N initial ciphertexts with distinct messages
    let ct_init: Vec<ElGamalCiphertext<GrumpkinProjective>> = (0..N)
        .map(|i| {
            let message =
                <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::from((i + 1) as u64);
            let randomness = <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::rand(&mut rng);
            ElGamalCiphertext::encrypt_scalar(message, randomness, shuffler_public_key)
        })
        .collect();

    // Generate witness data and apply shuffle
    let seed = BaseField::from(42u64);
    let (witness_data, num_samples, ct_after_shuffle_array) =
        apply_rs_shuffle_permutation::<BaseField, _>(seed, &ct_init.clone().try_into().unwrap());

    // Generate re-encryption randomizations
    let rerandomizations: Vec<BaseField> = (0..N)
        .map(|_| {
            // Convert from ScalarField to BaseField
            let scalar = <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::rand(&mut rng);
            let scalar_bytes = scalar.into_bigint().to_bytes_le();
            BaseField::from_le_bytes_mod_order(&scalar_bytes)
        })
        .collect();

    // Apply re-encryption
    let ct_final: Vec<ElGamalCiphertext<GrumpkinProjective>> = ct_after_shuffle_array
        .iter()
        .zip(rerandomizations.iter())
        .map(|(ct, &r)| {
            // Convert BaseField to ScalarField for re-encryption
            let r_bytes = r.into_bigint().to_bytes_le();
            let r_scalar =
                <GrumpkinConfig as ark_ec::CurveConfig>::ScalarField::from_le_bytes_mod_order(
                    &r_bytes,
                );
            ct.add_encryption_layer(r_scalar, shuffler_public_key)
        })
        .collect();

    // Generate Fiat-Shamir challenges
    let alpha = BaseField::from(17u64);
    let beta = BaseField::from(23u64);

    info!("Test data generation complete");

    (
        ct_init,
        ct_after_shuffle_array.to_vec(),
        ct_final,
        shuffler_public_key,
        rerandomizations,
        seed,
        alpha,
        beta,
        witness_data,
        num_samples,
    )
}

/// Create and prove the RS shuffle with re-encryption circuit
fn create_and_prove_circuit() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rs_shuffle_spartan_proof=info".parse()?)
                .add_directive("nexus_nova=debug".parse()?),
        )
        .init();

    info!("=== RS Shuffle with Re-encryption Spartan Proof Generation ===");
    info!("Circuit parameters: N={}, LEVELS={}", N, LEVELS);

    // Generate test data
    let (
        ct_init,
        ct_after_shuffle,
        ct_final,
        shuffler_pk,
        rerandomizations,
        seed,
        alpha,
        beta,
        witness_data,
        num_samples,
    ) = generate_test_data();

    // Create the circuit (still using Grumpkin for the circuit itself)
    info!("Creating RSShuffleWithReencryptionCircuit...");
    let circuit = RSShuffleWithReencryptionCircuit::<BaseField, GrumpkinProjective> {
        ct_init_pub: ct_init.clone(),
        ct_after_shuffle: ct_after_shuffle.clone(),
        ct_final_reencrypted: ct_final.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations: rerandomizations,
        alpha,
        beta,
        witness: witness_data,
        num_samples,
    };

    // Generate R1CS constraints
    info!("Generating R1CS constraints...");
    let cs_timer = Instant::now();

    let cs = ConstraintSystem::<BaseField>::new_ref();
    cs.set_mode(SynthesisMode::Setup);

    circuit.generate_constraints(cs.clone())?;

    // Check constraint satisfaction
    if !cs.is_satisfied()? {
        return Err("Constraints not satisfied".into());
    }

    let num_constraints = cs.num_constraints();
    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();

    let r1cs_time = cs_timer.elapsed();
    info!("R1CS generation complete in {:?}", r1cs_time);
    info!(
        "Circuit size: {} constraints, {} public inputs, {} private inputs",
        num_constraints, num_instance, num_witness
    );

    // Extract R1CS matrices
    info!("Extracting R1CS matrices...");
    let matrices = cs.to_matrices().ok_or("Failed to extract R1CS matrices")?;

    // Get witness and instance assignments
    let cs_borrow = cs.borrow().ok_or("Failed to borrow constraint system")?;
    let witness_assignment = cs_borrow.witness_assignment.clone();
    let instance_assignment = cs_borrow.instance_assignment.clone();

    // Convert arkworks matrix format to Spartan format
    // arkworks: Vec<Vec<(F, usize)>> where inner vec is (value, column) for each row
    // Spartan: Vec<(usize, usize, F)> where tuple is (row, column, value)
    let convert_matrix = |matrix: &Vec<Vec<(BaseField, usize)>>| -> Vec<(usize, usize, BaseField)> {
        let mut sparse_matrix = Vec::new();
        for (row_idx, row) in matrix.iter().enumerate() {
            for &(value, col_idx) in row.iter() {
                sparse_matrix.push((row_idx, col_idx, value));
            }
        }
        sparse_matrix
    };

    let a_sparse = convert_matrix(&matrices.a);
    let b_sparse = convert_matrix(&matrices.b);
    let c_sparse = convert_matrix(&matrices.c);

    // Count non-zero entries for setup
    let num_nz_entries = a_sparse.len().max(b_sparse.len()).max(c_sparse.len());

    // Create Spartan Instance
    info!("Creating Spartan instance...");
    let inst = Instance::new(
        num_constraints,
        num_witness,
        num_instance,
        &a_sparse,
        &b_sparse,
        &c_sparse,
    )?;

    // Setup SRS for polynomial commitment
    info!("Setting up SRS for polynomial commitment...");
    let srs_timer = Instant::now();
    let num_vars = num_witness + num_instance;
    let srs = PC::setup(num_vars, b"rs_shuffle_srs", &mut ark_std::test_rng())
        .map_err(|e| format!("Failed to setup SRS: {:?}", e))?;
    info!("SRS setup complete in {:?}", srs_timer.elapsed());

    // Setup Spartan generators
    info!("Setting up Spartan generators...");
    let gens_timer = Instant::now();

    let gens = SNARKGens::<Bn254Projective, PC>::new(
        &srs,
        num_constraints,
        num_witness,
        num_instance,
        num_nz_entries,
    );

    info!("Generator setup complete in {:?}", gens_timer.elapsed());

    // Create computation commitment and decommitment
    info!("Creating computation commitment...");
    let (comm, decomm) = SNARK::<Bn254Projective, PC>::encode(&inst, &gens);

    // Create proof
    info!("Generating SNARK proof...");
    let proof_timer = Instant::now();

    // Convert witness assignment to VarsAssignment
    let vars = VarsAssignment::new(&witness_assignment[1..])?;

    // Create inputs assignment
    let inputs = Assignment::new(&instance_assignment[1..])?;

    let mut prover_transcript = Transcript::new(b"rs_shuffle_reencryption_snark");

    let proof = SNARK::<Bn254Projective, PC>::prove(
        &inst,
        &comm,
        &decomm,
        vars,
        &inputs,
        &gens,
        &mut prover_transcript,
    );

    let proof_time = proof_timer.elapsed();
    info!("Proof generation complete in {:?}", proof_time);

    // Serialize proof to measure size
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    info!("Proof size: {} bytes", proof_bytes.len());

    // Verify proof
    info!("Verifying SNARK proof...");
    let verify_timer = Instant::now();

    let mut verifier_transcript = Transcript::new(b"rs_shuffle_reencryption_snark");

    let result = proof.verify(&comm, &inputs, &mut verifier_transcript, &gens);

    let verify_time = verify_timer.elapsed();

    match result {
        Ok(()) => {
            info!("✅ Proof verification SUCCESSFUL in {:?}", verify_time);
        }
        Err(e) => {
            return Err(format!("❌ Proof verification FAILED: {:?}", e).into());
        }
    }

    // Print summary
    info!("\n=== Summary ===");
    info!("Circuit size: {} constraints", num_constraints);
    info!("Public inputs: {}", num_instance);
    info!("Private inputs: {}", num_witness);
    info!("Proof size: {} bytes", proof_bytes.len());
    info!("Proof generation time: {:?}", proof_time);
    info!("Verification time: {:?}", verify_time);
    info!(
        "Prover time / constraint: {:?}",
        proof_time / num_constraints as u32
    );

    Ok(())
}

fn main() {
    if let Err(e) = create_and_prove_circuit() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
