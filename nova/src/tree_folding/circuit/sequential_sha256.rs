use super::sha256::{Sha256Circuit, calculate_sha256_native, conversions};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use crate::circuits::nova::StepCircuit;
use std::marker::PhantomData;
use std::time::Instant;
use tracing;
use ark_std::Zero;

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
    use ark_relations::r1cs::ConstraintSystem;
    use ark_r1cs_std::alloc::AllocVar;

    #[test]
    fn test_sequential_sha256_circuit_creation() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing sequential SHA-256 circuit creation");
        
        // Test that we can create the circuit
        let _circuit = SequentialSha256Circuit::<Fr>::new();
        
        // Verify the ARITY is correct
        assert_eq!(SequentialSha256Circuit::<Fr>::ARITY, 1);
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Sequential SHA-256 circuit creation test passed");
    }

    #[test]
    fn test_constraint_generation() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing constraint generation for sequential SHA-256 circuit");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Create dummy inputs
        let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u32))).unwrap();
        
        // Create a dummy previous hash (32 bytes as field element)
        let initial_hash = b"hello world";
        let native_hash = calculate_sha256_native(initial_hash);
        let hash_field = conversions::bytes_to_field::<Fr>(&native_hash);
        let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(hash_field)).unwrap()];
        
        // Generate constraints
        let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
        
        // Check that constraint generation succeeds
        assert!(result.is_ok(), "Constraint generation should succeed");
        
        let output = result.unwrap();
        assert_eq!(output.len(), 1, "Output should have exactly one element (next hash)");
        
        // Check that constraints were actually generated
        let num_constraints = cs.num_constraints();
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Generated {} constraints", num_constraints);
        assert!(num_constraints > 0, "Should generate some constraints");
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Constraint generation test passed");
    }

    #[test]
    fn test_multiple_constraint_generations() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing multiple constraint generations");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        
        for iteration in 0..3 {
            tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Iteration {}", iteration + 1);
            
            let cs = ConstraintSystem::<Fr>::new_ref();
            let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(iteration as u32))).unwrap();
            
            // Use different input for each iteration
            let test_data = format!("test data {}", iteration);
            let native_hash = calculate_sha256_native(test_data.as_bytes());
            let hash_field = conversions::bytes_to_field::<Fr>(&native_hash);
            let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(hash_field)).unwrap()];
            
            let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
            assert!(result.is_ok(), "Constraint generation should succeed for iteration {}", iteration);
            
            let num_constraints = cs.num_constraints();
            tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Iteration {} generated {} constraints", iteration + 1, num_constraints);
        }
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Multiple constraint generation test passed");
    }

    #[test]
    fn test_constraint_system_statistics() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing constraint system statistics");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Record initial state
        let initial_constraints = cs.num_constraints();
        let initial_instance_vars = cs.num_instance_variables();
        let initial_witness_vars = cs.num_witness_variables();
        
        // Create inputs and generate constraints
        let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(42u32))).unwrap();
        let test_hash = calculate_sha256_native(b"statistical test");
        let hash_field = conversions::bytes_to_field::<Fr>(&test_hash);
        let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(hash_field)).unwrap()];
        
        let _result = circuit.generate_constraints(cs.clone(), &i_var, &z_var).unwrap();
        
        // Record final state
        let final_constraints = cs.num_constraints();
        let final_instance_vars = cs.num_instance_variables();
        let final_witness_vars = cs.num_witness_variables();
        
        // Calculate differences
        let added_constraints = final_constraints - initial_constraints;
        let added_instance_vars = final_instance_vars - initial_instance_vars;
        let added_witness_vars = final_witness_vars - initial_witness_vars;
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Constraint system statistics:");
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Constraints added: {}", added_constraints);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Instance variables added: {}", added_instance_vars);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Witness variables added: {}", added_witness_vars);
        
        // Verify that constraints were actually added
        assert!(added_constraints > 0, "Should add constraints for SHA-256 operation");
        assert!(added_witness_vars > 0, "Should add witness variables");
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Constraint system statistics test passed");
    }

    #[test]
    fn test_satisfiability() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing circuit satisfiability");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Create inputs with actual values
        let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(1u32))).unwrap();
        
        // Use a known input and expected output
        let input_data = b"satisfiability test";
        let input_hash = calculate_sha256_native(input_data);
        let input_field = conversions::bytes_to_field::<Fr>(&input_hash);
        
        let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(input_field)).unwrap()];
        
        // Generate constraints
        let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
        assert!(result.is_ok(), "Constraint generation should succeed");
        
        let output = result.unwrap();
        assert_eq!(output.len(), 1, "Should produce one output");
        
        // Finalize the constraint system and check if it's satisfied
        cs.finalize();
        let is_satisfied = cs.is_satisfied().unwrap_or(false);
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Circuit satisfiability: {}", is_satisfied);
        assert!(is_satisfied, "Circuit should be satisfiable with valid inputs");
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Satisfiability test passed");
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
        
        // Verify the computation manually
        let mut expected = calculate_sha256_native(&initial_data);
        for i in 0..steps {
            expected = calculate_sha256_native(&expected);
            tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Step {} hash: {:?}", i + 1, hex::encode(&expected));
        }
        
        assert_eq!(final_hash, expected, "Native sequential computation should match manual computation");
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Native sequential SHA-256 test passed");
    }

    #[test]
    fn test_conversions() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing field/bytes conversions");
        
        // Test with a known hash
        let test_data = b"conversion test";
        let hash_bytes = calculate_sha256_native(test_data);
        
        // Convert to field and back
        let field_val = conversions::bytes_to_field::<Fr>(&hash_bytes);
        let recovered_bytes = conversions::field_to_bytes(&field_val);
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Original hash: {:?}", hex::encode(&hash_bytes));
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Field element: {:?}", field_val);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Recovered hash: {:?}", hex::encode(&recovered_bytes));
        
        // Note: Due to field size limitations, we might not recover exactly the same bytes
        // but the conversion should be deterministic
        assert_eq!(recovered_bytes.len(), 32, "Should always produce 32 bytes");
        
        // Test round-trip conversion multiple times
        for i in 0..5 {
            let test_msg = format!("round trip test {}", i);
            let hash = calculate_sha256_native(test_msg.as_bytes());
            let field = conversions::bytes_to_field::<Fr>(&hash);
            let back_to_bytes = conversions::field_to_bytes(&field);
            
            // Conversion should be deterministic
            let field2 = conversions::bytes_to_field::<Fr>(&hash);
            assert_eq!(field, field2, "Field conversion should be deterministic");
            
            let back_to_bytes2 = conversions::field_to_bytes(&field);
            assert_eq!(back_to_bytes, back_to_bytes2, "Bytes conversion should be deterministic");
        }
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Conversions test passed");
    }

    #[test]
    fn test_circuit_with_different_inputs() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing circuit with different input patterns");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        
        // Test with various input patterns
        let test_cases = vec![
            b"".to_vec(),                    // Empty input
            b"a".to_vec(),                   // Single character
            b"short".to_vec(),              // Short input
            b"this is a longer input string that should work fine".to_vec(), // Longer input
            (0..256).map(|i| i as u8).collect::<Vec<u8>>(), // Full byte range
        ];
        
        for (i, test_case) in test_cases.iter().enumerate() {
            tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing case {}: {} bytes", i + 1, test_case.len());
            
            let cs = ConstraintSystem::<Fr>::new_ref();
            let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(i as u32))).unwrap();
            
            // Hash the test case and convert to field
            let hash = calculate_sha256_native(test_case);
            let field = conversions::bytes_to_field::<Fr>(&hash);
            let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(field)).unwrap()];
            
            // Generate constraints
            let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
            assert!(result.is_ok(), "Constraint generation should succeed for test case {}", i + 1);
            
            // Check that the output is valid
            let output = result.unwrap();
            assert_eq!(output.len(), 1, "Should produce exactly one output");
            
            // Verify the output represents a valid field element
            let output_value = output[0].value();
            assert!(output_value.is_ok(), "Output should have a valid value for test case {}", i + 1);
        }
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Different inputs test passed");
    }

    #[test]
    fn test_constraint_generation_setup_mode() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing constraint generation in setup mode");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Set to setup mode (this is important for parameter generation)
        cs.set_mode(ark_relations::r1cs::SynthesisMode::Setup);
        
        // Create dummy variables for setup (values don't matter in setup mode)
        let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::zero())).unwrap();
        let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::zero())).unwrap()];
        
        // Generate constraints in setup mode
        let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
        assert!(result.is_ok(), "Constraint generation should succeed in setup mode");
        
        // Finalize and check the shape
        cs.finalize();
        let num_constraints = cs.num_constraints();
        let num_variables = cs.num_witness_variables() + cs.num_instance_variables();
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Setup mode results:");
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Constraints: {}", num_constraints);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Variables: {}", num_variables);
        
        assert!(num_constraints > 0, "Should generate constraints in setup mode");
        assert!(num_variables > 0, "Should generate variables in setup mode");
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Setup mode test passed");
    }

    // Benchmark-style test to measure performance
    #[test]
    fn test_circuit_performance() {
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Testing circuit generation performance");
        
        let circuit = SequentialSha256Circuit::<Fr>::new();
        let iterations = 10usize;
        let mut total_time = std::time::Duration::new(0, 0);
        let mut total_constraints = 0usize;
        
        for i in 0..iterations {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(i as u32))).unwrap();
            
            let test_data = format!("performance test iteration {}", i);
            let hash = calculate_sha256_native(test_data.as_bytes());
            let field = conversions::bytes_to_field::<Fr>(&hash);
            let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(field)).unwrap()];
            
            let start = std::time::Instant::now();
            let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
            let elapsed = start.elapsed();
            
            assert!(result.is_ok(), "Constraint generation should succeed in iteration {}", i);
            
            total_time += elapsed;
            total_constraints += cs.num_constraints();
            
            if i == 0 {
                tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "First iteration: {:?}, {} constraints", elapsed, cs.num_constraints());
            }
        }
        
        let avg_time = total_time / iterations as u32;
        let avg_constraints = total_constraints / iterations;
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "Performance summary:");
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Average time per generation: {:?}", avg_time);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Average constraints per generation: {}", avg_constraints);
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "  Total time for {} iterations: {:?}", iterations, total_time);
        
        // Basic performance assertions
        assert!(avg_time.as_millis() < 10000, "Average generation time should be reasonable (< 10s)");
        assert!(avg_constraints > 1000, "Should generate a reasonable number of constraints (> 1000)");
        
        tracing::debug!(target: SEQUENTIAL_SHA256_TARGET, "✓ Performance test passed");
    }
} 