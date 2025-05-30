use super::sha256::{Sha256Circuit, calculate_sha256_native, conversions};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::sponge::Absorb;
use crate::circuits::nova::StepCircuit;
use ark_crypto_primitives::sponge::constraints::SpongeWithGadget;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use std::marker::PhantomData;
use std::time::Instant;
use tracing;

// Tracing target for sequential SHA-256 circuit operations
const SEQUENTIAL_SHA256_TARGET: &str = "sequential_sha256";

/// A circuit for sequential SHA-256 hash operations
/// Each step takes the previous hash as input and produces a new hash
pub struct SequentialSha256Circuit<F: PrimeField> {
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> SequentialSha256Circuit<F> {
    /// Create a new sequential SHA-256 circuit
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F> for SequentialSha256Circuit<F> {
    // Set ARITY to 1 (one input state variable)
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Starting constraint generation for SHA-256 step");
        let constraint_start = Instant::now();
        
        // Extract the current state (previous hash)
        let current_state = &z[0];

        // Get the value of the current state if available
        // In newer ark versions, we need to handle this differently
        let state_bytes = match current_state.value() {
            Ok(val) => {
                let bytes = conversions::field_to_bytes(&val);
                tracing::debug!(
                    target: SEQUENTIAL_SHA256_TARGET,
                    "Input state value available, converted to bytes of length {}",
                    bytes.len()
                );
                bytes
            },
            Err(_) => {
                tracing::debug!(
                    target: SEQUENTIAL_SHA256_TARGET,
                    "Input state value not available, using default bytes"
                );
                vec![0u8; 32] // Default for constraint generation
            },
        };

        tracing::debug!(
            target: SEQUENTIAL_SHA256_TARGET,
            "Creating SHA-256 circuit instance for constraint generation"
        );
        // Create a SHA-256 circuit for this step using the previous hash as input
        let sha_circuit = Sha256Circuit::<F>::new(&state_bytes);

        tracing::debug!(
            target: SEQUENTIAL_SHA256_TARGET,
            "Generating constraints for SHA-256 operation"
        );
        let inner_constraint_start = Instant::now();
        
        // Generate constraints for the SHA-256 operation directly
        // Note: We're creating a fresh SHA-256 circuit and running it directly
        // rather than calling its generate_constraints method, which allows us
        // to properly integrate with the HyperNova system
        let dummy_fp_var = FpVar::<F>::zero();
        let empty_vec = vec![];
        
        let result = sha_circuit.generate_constraints(cs.clone(), &dummy_fp_var, &empty_vec)?;
        
        let inner_constraint_duration = inner_constraint_start.elapsed();
        tracing::debug!(
            target: SEQUENTIAL_SHA256_TARGET,
            "SHA-256 constraints generated in {:?}",
            inner_constraint_duration
        );
        
        // Log constraint system information
        let num_constraints = cs.num_constraints();
        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();
        
        tracing::debug!(
            target: SEQUENTIAL_SHA256_TARGET,
            "Constraint system stats: {} constraints, {} instance variables, {} witness variables",
            num_constraints,
            num_instance_variables,
            num_witness_variables
        );

        let constraint_duration = constraint_start.elapsed();
        tracing::debug!(
            target: SEQUENTIAL_SHA256_TARGET,
            "SHA-256 step constraint generation completed in {:?}",
            constraint_duration
        );

        Ok(result)
    }
}

/// Function to run sequential SHA-256 operations with IVC proofs
/// Note: This function is commented out since the imports need to be adapted
/// to the actual project structure. The function signature may need to be updated
/// based on the available types in this codebase.
/*
pub fn run_sequential_sha256<G1, G2, C1, C2, RO>(
    initial_message: &[u8],
    steps: usize,
    params: &PublicParams<G1, G2, C1, C2, RO, SequentialSha256Circuit<G1::ScalarField>>,
) -> Result<IVCProof<G1, G2, C1, C2, RO, SequentialSha256Circuit<G1::ScalarField>>, Box<dyn std::error::Error>>
where
    G1: ark_ec::short_weierstrass::SWCurveConfig,
    G2: ark_ec::short_weierstrass::SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    G1::ScalarField: Absorb,
    G2::ScalarField: Absorb,
    C1: PolyCommitmentScheme<ark_ec::short_weierstrass::Projective<G1>>,
    C2: CommitmentScheme<ark_ec::short_weierstrass::Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
{
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Starting sequential SHA-256 processing for {} steps", steps);
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "\n[Sequential Processing] Initializing with message: \"{}\"", String::from_utf8_lossy(initial_message));

    // Calculate initial hash from the input message
    let initial_hash = calculate_sha256_native(initial_message);
    let initial_hash_hex = initial_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Initial hash (hex): {}", initial_hash_hex);

    // Convert initial hash to field element
    let initial_field = conversions::bytes_to_field(&initial_hash);
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Initial field element: {}", initial_field);
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Initial hash calculated and converted to field element");

    // Set initial state
    let z_0 = vec![initial_field];

    // Create a new circuit instance
    let circuit = SequentialSha256Circuit::<G1::ScalarField>::new();
    
    // Create initial IVC proof
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "[Sequential Processing] Creating initial IVC proof...");
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Creating initial IVC proof");
    let mut recursive_snark = IVCProof::new(&z_0);

    // Perform sequential steps
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "[Sequential Processing] Running {} sequential SHA-256 operations...", steps);
    for i in 0..steps {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Step {}: Generating proof...", i + 1);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Step {}/{}: Starting proof generation", i + 1, steps);
        
        let start = std::time::Instant::now();
        recursive_snark = recursive_snark.prove_step(params, &circuit)?;
        let duration = start.elapsed();
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "    Completed in {:.2?}", duration);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Step {}/{}: Proof generated in {:?}", i + 1, steps, duration);

        // Access the current z_i value - it's already a field element, not FpVar
        let z_i_val = recursive_snark.z_i()[0];
        let bytes = conversions::field_to_bytes(&z_i_val);
        let hash_hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "    Hash at step {} (hex): {}", i + 1, hash_hex);
    }

    // Verify the final proof
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "[Sequential Processing] Verifying the final proof...");
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Starting verification of final proof");
    
    let verify_time = std::time::Instant::now();
    recursive_snark.verify(params)?;
    let verify_duration = verify_time.elapsed();
    
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  ✓ Verification completed in {:.2?}", verify_duration);
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Final proof verified successfully in {:?}", verify_duration);

    Ok(recursive_snark)
}
*/

/// Run and verify a sequential chain using only native SHA-256 for comparison
pub fn run_native_sequential_sha256(initial_message: &[u8], steps: usize) -> Vec<u8> {
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "\n[Native Sequential] Running {} native SHA-256 operations for comparison", steps);
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Running native sequential SHA-256 for {} steps (for comparison)", steps);

    // Calculate initial hash
    let mut current_hash = calculate_sha256_native(initial_message);
    let current_hash_hex = current_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
    tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Initial hash (hex): {}", current_hash_hex);

    // Perform sequential steps
    for i in 0..steps {
        let hash_start = Instant::now();
        current_hash = calculate_sha256_native(&current_hash);
        let hash_duration = hash_start.elapsed();
        
        let hash_hex = current_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Native step {}/{}: Hash calculated in {:?}", i + 1, steps, hash_duration);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "    Hash at step {} (hex): {}", i + 1, hash_hex);
    }

    current_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    
    // Note: These test types are commented out as they need to be adapted
    // to the actual project structure and available types
    /*
    use crate::{
        poseidon_config,
        provider::zeromorph::Zeromorph,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;

    type G1 = ark_bn254::g1::Config;
    type G2 = ark_grumpkin::GrumpkinConfig;
    type C1 = Zeromorph<ark_bn254::Bn254>;
    type C2 = PedersenCommitment<ark_grumpkin::Projective>;
    type RO = PoseidonSponge<ark_bn254::Fr>;
    */

    #[test]
    fn test_sequential_sha256_circuit_creation() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing sequential SHA-256 circuit creation");
        
        // Test that we can create the circuit
        let circuit = SequentialSha256Circuit::<Fr>::new();
        
        // Verify the ARITY is correct
        assert_eq!(SequentialSha256Circuit::<Fr>::ARITY, 1);
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Sequential SHA-256 circuit creation test passed");
    }
    
    #[test]
    fn test_native_sequential_sha256() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing native sequential SHA-256");
        
        // Initial data to hash
        let initial_data = b"hello world".to_vec();
        let steps = 3;

        // Run native implementation
        let final_hash = run_native_sequential_sha256(&initial_data, steps);
        
        // Verify we got a 32-byte hash
        assert_eq!(final_hash.len(), 32);
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Native sequential SHA-256 test passed");
    }
    
    /*
    // This test is commented out since it requires the full IVC infrastructure
    // to be properly set up with the correct types from this codebase
    #[test]
    fn test_sequential_sha256() -> Result<(), Box<dyn std::error::Error>> {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Starting sequential_sha256_test");
        
        // Initial data to hash
        let initial_data = b"hello world".to_vec();

        // Setup HyperNova
        let circuit = SequentialSha256Circuit::<Fr>::new();
        let ro_config = poseidon_config();
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Setting up test public parameters");
        
        let params = PublicParams::<G1, G2, C1, C2, RO, SequentialSha256Circuit<Fr>>::test_setup(
            ro_config,
            &circuit
        )?;

        // Number of sequential steps to perform
        let steps = 3;

        // Run with ZK proofs
        let proof = run_sequential_sha256::<G1, G2, C1, C2, RO>(
            &initial_data,
            steps,
            &params
        )?;

        // Run native implementation for comparison
        let expected_hash = run_native_sequential_sha256(&initial_data, steps);

        // Get final hash from proof
        let final_field = proof.z_i()[0];
        let final_hash = conversions::field_to_bytes(&final_field);

        // Compare results
        let hash_match = expected_hash == final_hash;
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "\n[Test Result] ZK proof hash matches native implementation: {}",
                 if hash_match { "Yes ✓" } else { "No ✗" });

        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Test result: ZK proof hash matches native implementation: {}",
                 if hash_match { "Yes" } else { "No"  });

        assert!(hash_match, "Hash mismatch between ZK proof and native implementation");

        Ok(())
    }
    */
} 