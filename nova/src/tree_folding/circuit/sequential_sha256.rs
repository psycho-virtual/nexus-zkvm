use super::sha256::{Sha256Circuit, calculate_sha256_native, conversions};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use crate::circuits::nova::StepCircuit;
use std::marker::PhantomData;
use std::time::Instant;
use ark_std::Zero;

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
        println!("Starting constraint generation for SHA-256 step");
        let constraint_start = Instant::now();
        
        // Extract the current state (previous hash)
        let current_state = &z[0];

        // Get the value of the current state if available
        let state_bytes = match current_state.value() {
            Ok(val) => {
                let bytes = conversions::field_to_bytes(&val);
                println!("Input state value available, converted to bytes of length {}", bytes.len());
                bytes
            },
            Err(_) => {
                println!("Input state value not available, using default bytes");
                vec![0u8; 32] // Default for constraint generation
            },
        };

        println!("Creating SHA-256 circuit instance for constraint generation");
        // Create a SHA-256 circuit for this step using the previous hash as input
        let sha_circuit = Sha256Circuit::<F>::new(&state_bytes);

        println!("Generating constraints for SHA-256 operation");
        let inner_constraint_start = Instant::now();
        
        // Generate constraints for the SHA-256 operation directly
        let dummy_fp_var = FpVar::<F>::zero();
        let empty_vec = vec![];
        
        let result = sha_circuit.generate_constraints(cs.clone(), &dummy_fp_var, &empty_vec)?;
        
        let inner_constraint_duration = inner_constraint_start.elapsed();
        println!("SHA-256 constraints generated in {:?}", inner_constraint_duration);
        
        // Log constraint system information
        let num_constraints = cs.num_constraints();
        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();
        
        println!("Constraint system stats: {} constraints, {} instance variables, {} witness variables",
            num_constraints,
            num_instance_variables,
            num_witness_variables
        );

        let constraint_duration = constraint_start.elapsed();
        println!("SHA-256 step constraint generation completed in {:?}", constraint_duration);

        Ok(result)
    }
}

/// Run and verify a sequential chain using only native SHA-256 for comparison
pub fn run_native_sequential_sha256(initial_message: &[u8], steps: usize) -> Vec<u8> {
    println!("\n[Native Sequential] Running {} native SHA-256 operations for comparison", steps);
    println!("Running native sequential SHA-256 for {} steps (for comparison)", steps);

    // Calculate initial hash
    let mut current_hash = calculate_sha256_native(initial_message);
    let current_hash_hex = current_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
    println!("Initial hash (hex): {}", current_hash_hex);

    // Perform sequential steps
    for i in 0..steps {
        let hash_start = Instant::now();
        current_hash = calculate_sha256_native(&current_hash);
        let hash_duration = hash_start.elapsed();
        
        let hash_hex = current_hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        println!("Native step {}/{}: Hash calculated in {:?}", i + 1, steps, hash_duration);
        println!("    Hash at step {} (hex): {}", i + 1, hash_hex);
    }

    current_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_r1cs_std::alloc::AllocVar;
    use std::time::Duration;

    // Helper function to create a fresh constraint system
    fn create_constraint_system() -> ConstraintSystemRef<Fr> {
        ConstraintSystem::<Fr>::new_ref()
    }

    // Helper function to safely create circuit inputs
    fn create_circuit_inputs(cs: &ConstraintSystemRef<Fr>, input_data: &[u8]) -> (FpVar<Fr>, Vec<FpVar<Fr>>) {
        let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u32))).unwrap();
        let hash = calculate_sha256_native(input_data);
        let hash_field = conversions::bytes_to_field::<Fr>(&hash);
        let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(hash_field)).unwrap()];
        (i_var, z_var)
    }

    #[test]
    fn test_sequential_sha256_circuit_creation() {
        println!("Testing sequential SHA-256 circuit creation");
        
        // Test that we can create the circuit
        let _circuit = SequentialSha256Circuit::<Fr>::new();
        
        // Verify the ARITY is correct
        assert_eq!(SequentialSha256Circuit::<Fr>::ARITY, 1);
        
        println!("✓ Sequential SHA-256 circuit creation test passed");
    }

    #[test]
    fn test_constraint_generation() {
        println!("Testing constraint generation for sequential SHA-256 circuit");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        let cs = create_constraint_system();
        
        // Create inputs
        let (i_var, z_var) = create_circuit_inputs(&cs, b"hello world");
        
        // Generate constraints
        let start = Instant::now();
        let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
        let elapsed = start.elapsed();
        
        if elapsed > Duration::from_secs(30) {
            println!("Warning: Constraint generation took longer than 30 seconds: {:?}", elapsed);
        }
        
        // Check that constraint generation succeeds
        assert!(result.is_ok(), "Constraint generation should succeed");
        
        let output = result.unwrap();
        assert_eq!(output.len(), 1, "Output should have exactly one element (next hash)");
        
        // Check that constraints were actually generated
        let num_constraints = cs.num_constraints();
        println!("Generated {} constraints in {:?}", num_constraints, elapsed);
        assert!(num_constraints > 0, "Should generate some constraints");
        
        println!("✓ Constraint generation test passed");
    }

    #[test]
    fn test_native_sequential_sha256() {
        println!("Testing native sequential SHA-256");
        
        // Initial data to hash
        let initial_data = b"hello world".to_vec();
        let steps = 3;

        // Run native implementation
        let final_hash = run_native_sequential_sha256(&initial_data, steps);
        
        // Verify we got a 32-byte hash
        assert_eq!(final_hash.len(), 32);
        
        // Verify the computation manually
        let mut expected = calculate_sha256_native(&initial_data);
        for i in 0..steps {
            expected = calculate_sha256_native(&expected);
            println!("Step {} hash: {:?}", i + 1, hex::encode(&expected));
        }
        
        assert_eq!(final_hash, expected, "Native sequential computation should match manual computation");
        
        println!("✓ Native sequential SHA-256 test passed");
    }
} 