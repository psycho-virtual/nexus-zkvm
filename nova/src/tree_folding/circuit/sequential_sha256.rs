use super::sha256::{calculate_sha256_native, conversions, Sha256Circuit};
use crate::circuits::nova::StepCircuit;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;
use tracing::{debug, info, info_span};

/// A circuit for sequential SHA-256 hash operations
/// Each step takes the previous hash as input and produces a new hash
#[derive(Debug)]
pub struct SequentialSha256Circuit<F: PrimeField> {
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> SequentialSha256Circuit<F> {
    /// Create a new sequential SHA-256 circuit
    pub fn new() -> Self {
        Self { _phantom: PhantomData }
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
        let span = info_span!("constraint_generation", arity = Self::ARITY);
        let _enter = span.enter();

        info!("Starting constraint generation for SHA-256 step");

        // Extract the current state (previous hash)
        let current_state = &z[0];

        // Get the value of the current state if available
        let state_bytes = match current_state.value() {
            Ok(val) => {
                let bytes = conversions::field_to_bytes(&val);
                debug!(
                    "Input state value available, converted to bytes of length {}",
                    bytes.len()
                );
                bytes
            }
            Err(_) => {
                debug!("Input state value not available, using default bytes");
                vec![0u8; 32] // Default for constraint generation
            }
        };

        debug!("Creating SHA-256 circuit instance for constraint generation");
        // Create a SHA-256 circuit for this step using the previous hash as input
        let sha_circuit = Sha256Circuit::<F>::new(&state_bytes);

        debug!("Generating constraints for SHA-256 operation");

        // Generate constraints for the SHA-256 operation directly
        let dummy_fp_var = FpVar::<F>::zero();
        let empty_vec = vec![];

        let result = {
            let span = info_span!("sha256_constraints");
            let _enter = span.enter();
            sha_circuit.generate_constraints(cs.clone(), &dummy_fp_var, &empty_vec)?
        };

        // Log constraint system information
        let num_constraints = cs.num_constraints();
        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();

        debug!(
            "Constraint system stats: {} constraints, {} instance variables, {} witness variables",
            num_constraints, num_instance_variables, num_witness_variables
        );

        info!("SHA-256 step constraint generation completed");

        Ok(result)
    }
}

/// Run and verify a sequential chain using only native SHA-256 for comparison
pub fn run_native_sequential_sha256(initial_message: &[u8], steps: usize) -> Vec<u8> {
    let span = info_span!(
        "native_sequential_sha256",
        steps = steps,
        initial_msg_len = initial_message.len()
    );
    let _enter = span.enter();

    info!(
        "\n[Native Sequential] Running {} native SHA-256 operations for comparison",
        steps
    );
    info!(
        "Running native sequential SHA-256 for {} steps (for comparison)",
        steps
    );

    // Calculate initial hash
    let mut current_hash = calculate_sha256_native(initial_message);
    let current_hash_hex = current_hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    debug!("Initial hash (hex): {}", current_hash_hex);

    // Perform sequential steps
    for i in 0..steps {
        current_hash = {
            let span = info_span!("hash_step", step = i + 1, total_steps = steps);
            let _enter = span.enter();
            calculate_sha256_native(&current_hash)
        };

        let hash_hex = current_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        debug!("Native step {}/{}: Hash calculated", i + 1, steps);
        debug!("    Hash at step {} (hex): {}", i + 1, hash_hex);
    }

    current_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use std::time::Duration;
    use tracing::info_span;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    const TEST_TARGET: &str = "nexus-nova";

    // Helper function to set up tracing for tests
    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    // Helper function to create a fresh constraint system
    fn create_constraint_system() -> ConstraintSystemRef<Fr> {
        ConstraintSystem::<Fr>::new_ref()
    }

    // Helper function to safely create circuit inputs
    fn create_circuit_inputs(
        cs: &ConstraintSystemRef<Fr>,
        input_data: &[u8],
    ) -> (FpVar<Fr>, Vec<FpVar<Fr>>) {
        let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u32))).unwrap();
        let hash = calculate_sha256_native(input_data);
        let hash_field = conversions::bytes_to_field::<Fr>(&hash);
        let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(hash_field)).unwrap()];
        (i_var, z_var)
    }

    #[test]
    fn test_sequential_sha256_circuit_creation() {
        let _guard = setup_test_tracing();
        tracing::info!("Testing sequential SHA-256 circuit creation");

        // Test that we can create the circuit
        let _circuit = SequentialSha256Circuit::<Fr>::new();

        // Verify the ARITY is correct
        assert_eq!(SequentialSha256Circuit::<Fr>::ARITY, 1);

        tracing::info!("✓ Sequential SHA-256 circuit creation test passed");
    }

    #[test]
    fn test_constraint_generation() {
        let _guard = setup_test_tracing();
        tracing::info!("Testing constraint generation for sequential SHA-256 circuit");

        let circuit = SequentialSha256Circuit::<Fr>::new();
        let cs = create_constraint_system();

        // Create inputs
        let (i_var, z_var) = create_circuit_inputs(&cs, b"hello world");

        // Generate constraints with timing
        let (result, elapsed) = {
            let span = info_span!("constraint_generation_test", input = "hello world");
            let _enter = span.enter();
            let start = std::time::Instant::now();
            let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var);
            let elapsed = start.elapsed();
            (result, elapsed)
        };

        if elapsed > Duration::from_secs(30) {
            tracing::info!(
                "Warning: Constraint generation took longer than 30 seconds: {:?}",
                elapsed
            );
        }

        // Check that constraint generation succeeds
        assert!(result.is_ok(), "Constraint generation should succeed");

        let output = result.unwrap();
        assert_eq!(
            output.len(),
            1,
            "Output should have exactly one element (next hash)"
        );

        // Check that constraints were actually generated
        let num_constraints = cs.num_constraints();
        tracing::debug!("Generated {} constraints in {:?}", num_constraints, elapsed);
        assert!(num_constraints > 0, "Should generate some constraints");

        tracing::info!("✓ Constraint generation test passed");
    }

    #[test]
    fn test_native_sequential_sha256() {
        let _guard = setup_test_tracing();
        tracing::info!("Testing native sequential SHA-256");

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
            tracing::debug!("Step {} hash: {:?}", i + 1, hex::encode(&expected));
        }

        assert_eq!(
            final_hash, expected,
            "Native sequential computation should match manual computation"
        );

        tracing::info!("✓ Native sequential SHA-256 test passed");
    }
}
