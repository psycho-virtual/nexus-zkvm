//! Binary for generating Groth16 proofs for RS Shuffle with Re-encryption Circuit
//!
//! This binary demonstrates how to:
//! 1. Create an RSShuffleWithReencryptionCircuit
//! 2. Perform trusted setup for Groth16
//! 3. Generate and verify a Groth16 SNARK proof
//!
//! Groth16 advantages over Spartan:
//! - Smaller proof size (~128 bytes)
//! - Faster verification (constant time)
//! - Circuit-specific trusted setup (can be cached)
//!
//! Usage: cargo run --bin rs_shuffle_groth16_proof --release

use ark_bn254::{Bn254, Fr as BaseField};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use nexus_nova::shuffling::rs_shuffle::WitnessData;
use nexus_nova::shuffling::{
    data_structures::ElGamalCiphertext,
    rs_shuffle::{
        circuit::RSShuffleWithReencryptionCircuit,
        witness_preparation::apply_rs_shuffle_permutation, LEVELS, N,
    },
};
use std::fs::File;
use std::path::Path;
use tracing::{info, instrument};

/// Type alias for the pairing-friendly curve
/// BN254 is ideal for Groth16 as it has efficient pairings
type E = Bn254;

/// Save proving key to a file
#[instrument(level = "info", skip(pk))]
fn save_proving_key(pk: &ProvingKey<E>, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    info!("Saving proving key to {:?}...", path);
    let mut file = File::create(path)?;
    pk.serialize_with_mode(&mut file, Compress::Yes)?;
    file.sync_all()?;
    info!("Proving key saved successfully");
    Ok(())
}

/// Load proving key from a file
#[instrument(level = "info")]
fn load_proving_key(path: &Path) -> Result<ProvingKey<E>, Box<dyn std::error::Error>> {
    info!("Loading proving key from {:?}...", path);
    let mut file = File::open(path)?;
    let pk = ProvingKey::<E>::deserialize_with_mode(&mut file, Compress::Yes, Validate::Yes)?;
    info!("Proving key loaded successfully");
    Ok(pk)
}

/// Save verifying key to a file
#[instrument(level = "info", skip(vk))]
fn save_verifying_key(vk: &VerifyingKey<E>, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    info!("Saving verifying key to {:?}...", path);
    let mut file = File::create(path)?;
    vk.serialize_with_mode(&mut file, Compress::Yes)?;
    file.sync_all()?;
    info!("Verifying key saved successfully");
    Ok(())
}

/// Load verifying key from a file
#[instrument(level = "info")]
fn load_verifying_key(path: &Path) -> Result<VerifyingKey<E>, Box<dyn std::error::Error>> {
    info!("Loading verifying key from {:?}...", path);
    let mut file = File::open(path)?;
    let vk = VerifyingKey::<E>::deserialize_with_mode(&mut file, Compress::Yes, Validate::Yes)?;
    info!("Verifying key loaded successfully");
    Ok(vk)
}

/// Load cached proving and verifying keys
#[instrument(level = "info")]
fn load_cached_keys(pk_path: &Path, vk_path: &Path) -> Result<(ProvingKey<E>, VerifyingKey<E>), Box<dyn std::error::Error>> {
    info!("Loading cached keys...");
    let pk = load_proving_key(pk_path)?;
    let vk = load_verifying_key(vk_path)?;
    info!("Successfully loaded cached keys");
    Ok((pk, vk))
}

/// Perform trusted setup for Groth16
#[instrument(level = "info", skip(circuit, rng))]
fn perform_trusted_setup(
    circuit: RSShuffleWithReencryptionCircuit<BaseField, GrumpkinProjective>,
    rng: &mut StdRng,
) -> Result<(ProvingKey<E>, VerifyingKey<E>), Box<dyn std::error::Error>> {
    info!("Performing trusted setup for Groth16...");
    info!("WARNING: This is using a deterministic RNG - DO NOT use in production!");
    
    // Circuit-specific setup generates both proving and verifying keys
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, rng)?;
    
    info!("Trusted setup complete");
    Ok((pk, vk))
}

/// Perform trusted setup or load from cache
#[instrument(level = "info", skip(circuit))]
fn setup_or_load_keys(
    circuit: RSShuffleWithReencryptionCircuit<BaseField, GrumpkinProjective>,
) -> Result<(ProvingKey<E>, VerifyingKey<E>), Box<dyn std::error::Error>> {
    let pk_path = Path::new("rs_shuffle_groth16_pk.bin");
    let vk_path = Path::new("rs_shuffle_groth16_vk.bin");

    // Try to load cached keys first
    if pk_path.exists() && vk_path.exists() {
        info!("Found cached proving and verifying keys");
        
        match load_cached_keys(pk_path, vk_path) {
            Ok(keys) => return Ok(keys),
            Err(e) => {
                info!("Failed to load cached keys: {}, regenerating...", e);
            }
        }
    }

    // Perform trusted setup if keys don't exist or loading failed
    let mut rng = StdRng::seed_from_u64(0u64);
    let (pk, vk) = perform_trusted_setup(circuit, &mut rng)?;

    // Save keys for future use
    if let Err(e) = save_proving_key(&pk, pk_path) {
        info!("Warning: Failed to save proving key: {}", e);
    }
    if let Err(e) = save_verifying_key(&vk, vk_path) {
        info!("Warning: Failed to save verifying key: {}", e);
    }

    Ok((pk, vk))
}

/// Generate Groth16 proof
#[instrument(level = "info", skip(pk, circuit, rng))]
fn generate_groth16_proof(
    pk: &ProvingKey<E>,
    circuit: RSShuffleWithReencryptionCircuit<BaseField, GrumpkinProjective>,
    rng: &mut StdRng,
) -> Result<ark_groth16::Proof<E>, Box<dyn std::error::Error>> {
    info!("Generating Groth16 proof...");
    let proof = Groth16::<E>::prove(pk, circuit, rng)?;
    info!("Proof generation complete");
    Ok(proof)
}

/// Verify Groth16 proof
#[instrument(level = "info", skip(pvk, public_inputs, proof))]
fn verify_groth16_proof(
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[BaseField],
    proof: &ark_groth16::Proof<E>,
) -> Result<bool, Box<dyn std::error::Error>> {
    info!("Verifying Groth16 proof...");
    let is_valid = Groth16::<E>::verify_with_processed_vk(pvk, public_inputs, proof)?;
    info!("Proof verification complete");
    Ok(is_valid)
}

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

    let mut rng = StdRng::seed_from_u64(42u64);
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

/// Create and prove the RS shuffle with re-encryption circuit using Groth16
fn create_and_prove_circuit() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 52; // Number of ciphertexts to shuffle

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rs_shuffle_groth16_proof=info".parse()?),
        )
        .init();

    info!("=== RS Shuffle with Re-encryption Groth16 Proof Generation ===");
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

    // Create the actual circuit with real data
    info!("Creating RSShuffleWithReencryptionCircuit...");
    let circuit = RSShuffleWithReencryptionCircuit::<BaseField, GrumpkinProjective> {
        ct_init_pub: ct_init.clone(),
        ct_after_shuffle: ct_after_shuffle.clone(),
        ct_final_reencrypted: ct_final.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations: rerandomizations.clone(),
        alpha,
        beta,
        witness: witness_data.clone(),
        num_samples,
    };

    // Perform trusted setup or load cached keys using the real circuit
    let (pk, vk) = setup_or_load_keys(circuit)?;

    // Analyze circuit size
    info!("Analyzing circuit complexity...");
    let cs = ConstraintSystem::<BaseField>::new_ref();
    let analysis_circuit = RSShuffleWithReencryptionCircuit::<BaseField, GrumpkinProjective> {
        ct_init_pub: ct_init.clone(),
        ct_after_shuffle: ct_after_shuffle.clone(),
        ct_final_reencrypted: ct_final.clone(),
        seed,
        shuffler_pk,
        encryption_randomizations: rerandomizations.clone(),
        alpha,
        beta,
        witness: witness_data.clone(),
        num_samples,
    };

    analysis_circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    let num_constraints = cs.num_constraints();
    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();

    // Get public inputs from the constraint system
    let public_inputs = cs
        .borrow()
        .ok_or("Failed to borrow constraint system")?
        .instance_assignment[1..]
        .to_vec(); // Skip the first element (always 1)

    info!("\n=== Circuit Complexity Analysis ===");
    info!("Number of ciphertexts (N): {}", N);
    info!("Total R1CS constraints: {}", num_constraints);
    info!("Total witnesses (private): {}", num_witness);
    info!("Total public inputs: {}", num_instance - 1); // Exclude the constant 1
    info!("Total variables: {}", num_witness + num_instance);
    info!(
        "Constraints per ciphertext: {:.2}",
        num_constraints as f64 / N as f64
    );
    info!(
        "Witnesses per ciphertext: {:.2}",
        num_witness as f64 / N as f64
    );
    info!("===================================\n");

    // Create the actual circuit with real data for proving
    info!("Creating circuit with actual witness data...");
    let prove_circuit = RSShuffleWithReencryptionCircuit::<BaseField, GrumpkinProjective> {
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

    // Generate Groth16 proof
    let mut rng = StdRng::seed_from_u64(1234u64);
    let proof = generate_groth16_proof(&pk, prove_circuit, &mut rng)?;

    // Serialize proof to measure size
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    info!("Proof size: {} bytes", proof_bytes.len());

    // Prepare verifying key for faster verification
    let pvk = PreparedVerifyingKey::from(vk.clone());

    // Verify proof
    let is_valid = verify_groth16_proof(&pvk, &public_inputs, &proof)?;

    if is_valid {
        info!("✅ Proof verification SUCCESSFUL");
    } else {
        return Err("❌ Proof verification FAILED".into());
    }

    // Print summary
    info!("\n=== Performance Summary ===");
    info!("Proof System: Groth16");
    info!("Number of ciphertexts shuffled: {}", N);
    info!("Circuit size: {} constraints", num_constraints);
    info!("Public inputs: {}", public_inputs.len());
    info!("Private witnesses: {}", num_witness);
    info!("Proof size: {} bytes (constant size!)", proof_bytes.len());
    info!("Constraints per ciphertext: {:.2}", num_constraints as f64 / N as f64);
    info!("Witnesses per ciphertext: {:.2}", num_witness as f64 / N as f64);
    info!("\n=== Groth16 Advantages ===");
    info!("✓ Smallest proof size (~128 bytes)");
    info!("✓ Fastest verification (single pairing)");
    info!("✓ One-time trusted setup can be reused");
    info!("✓ Ideal for on-chain verification");

    Ok(())
}

fn main() {
    if let Err(e) = create_and_prove_circuit() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
