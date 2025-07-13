use super::{FnCircuit, IntoFpVarVec};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;
use tracing::{debug, info, info_span, instrument};

// Import the SHA-256 gadget
use ark_crypto_primitives::crh::{
    sha256::constraints::Sha256Gadget,
    CRHSchemeGadget,
};

const LOG_TARGET: &str = "nexus-nova::tree_folding::mangrove::circuit::sha256_leaf";

/// A circuit for computing a chain of SHA-256 hashes
/// Each iteration takes the previous hash as input and produces a new hash
#[derive(Debug)]
pub struct Sha256LeafCircuit<F: PrimeField> {
    /// Number of iterations to perform
    pub num_iterations: usize,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> Sha256LeafCircuit<F> {
    /// Create a new SHA-256 leaf circuit
    pub fn new(num_iterations: usize) -> Self {
        Self { 
            num_iterations, 
            _phantom: PhantomData 
        }
    }
}

use super::sha256_var::Sha256Var;

// Implement IntoFpVarVec for FpVar (our input/output type)
impl<F: PrimeField> IntoFpVarVec<F> for FpVar<F> {
    fn into_fp_var_vec(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![self.clone()])
    }
}

impl<F: PrimeField> FnCircuit<F, Sha256Var<F>, Sha256Var<F>> for Sha256LeafCircuit<F> {
    #[instrument(target = LOG_TARGET, skip(self, cs, input))]
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        input: &Sha256Var<F>,
    ) -> Result<Sha256Var<F>, SynthesisError> {
        let span = info_span!(target: LOG_TARGET, "constraint_generation");
        let _enter = span.enter();

        info!(target: LOG_TARGET, "Starting constraint generation for SHA-256 leaf");

        // Start with the input bytes
        let mut state = input.bytes.clone();

        debug!(
            target: LOG_TARGET,
            "Input state: {} bytes",
            state.len()
        );

        // Create SHA-256 parameters (constant)
        let params_var = ark_crypto_primitives::crh::sha256::constraints::UnitVar::<F>::default();

        // Unrolled hash chain
        for i in 0..self.num_iterations {
            debug!(
                target: LOG_TARGET,
                "SHA-256 iteration {}/{}",
                i + 1,
                self.num_iterations
            );

            // Use the SHA-256 gadget to compute the hash
            let digest_var = Sha256Gadget::<F>::evaluate(&params_var, &state)?;
            
            // Extract the bytes from DigestVar (it contains Vec<UInt8<F>>)
            // The arkworks SHA256 gadget returns DigestVar which wraps the bytes
            state = digest_var.0;

            // The output should already be 32 bytes, but let's make sure
            assert_eq!(state.len(), 32, "SHA-256 output should be 32 bytes");
            
            debug!(
                target: LOG_TARGET,
                "Iteration {} completed",
                i + 1,
            );
        }

        // Create result Sha256Var
        let result = Sha256Var::new(state)?;

        // Log constraint system information
        let num_constraints = cs.num_constraints();
        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();

        debug!(
            target: LOG_TARGET,
            "Constraint system stats: {} constraints, {} instance variables, {} witness variables",
            num_constraints, num_instance_variables, num_witness_variables
        );

        info!(target: LOG_TARGET, "SHA-256 leaf constraint generation completed");

        Ok(result)
    }
}

/// Run a chain of SHA-256 operations natively for comparison
#[instrument(target = LOG_TARGET, skip(initial_data))]
pub fn run_native_sha256_chain(initial_data: &[u8], iterations: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256 as NativeSha256};

    let span = info_span!(
        target: LOG_TARGET,
        "native_sha256_chain",
        iterations = iterations,
        initial_data_len = initial_data.len()
    );
    let _enter = span.enter();

    info!(
        target: LOG_TARGET,
        "Running {} native SHA-256 operations for comparison",
        iterations
    );

    let mut current_hash = initial_data.to_vec();
    
    for i in 0..iterations {
        let mut hasher = NativeSha256::new();
        hasher.update(&current_hash);
        current_hash = hasher.finalize().to_vec();

        debug!(target: LOG_TARGET, "Native step {}/{}: Hash calculated", i + 1, iterations);
        debug!(target: LOG_TARGET, "    Hash at step {} (hex): {}", i + 1, hex::encode(&current_hash));
    }

    current_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target("nexus-nova", tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer()
                    .without_time()
                    .with_line_number(true),
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_sha256_leaf_circuit_creation() {
        let _guard = setup_test_tracing();
        let circuit = Sha256LeafCircuit::<Fr>::new(3);
        
        assert_eq!(circuit.num_iterations, 3);
    }

    #[test]
    fn test_constraint_generation() {
        let _guard = setup_test_tracing();
        let circuit = Sha256LeafCircuit::<Fr>::new(2);
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Create initial input as Sha256Var
        let initial_data = vec![1u8; 32]; // Use 32 bytes directly
        
        let input_var = Sha256Var::<Fr>::new_variable(
            cs.clone(),
            || Ok(initial_data),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        
        let result = circuit.generate_constraints(cs.clone(), &input_var);
        
        assert!(result.is_ok());
        assert!(cs.num_constraints() > 0);
    }

    #[test]
    fn test_native_sha256_chain() {
        let _guard = setup_test_tracing();
        let initial_data = b"hello world";
        let iterations = 3;
        
        let final_hash = run_native_sha256_chain(initial_data, iterations);
        
        // Verify manually
        let mut expected = initial_data.to_vec();
        for _ in 0..iterations {
            use sha2::{Digest, Sha256 as NativeSha256};
            let mut hasher = NativeSha256::new();
            hasher.update(&expected);
            expected = hasher.finalize().to_vec();
        }
        
        assert_eq!(final_hash, expected);
    }

    #[test]
    fn test_circuit_matches_native() {
        let _guard = setup_test_tracing();
        tracing::info!(target: LOG_TARGET, "Starting test_circuit_matches_native");
        
        let iterations = 2;
        let circuit = Sha256LeafCircuit::<Fr>::new(iterations);
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Start with 32 bytes - required for Sha256Var
        let initial_bytes = vec![1u8; 32];
        tracing::debug!(target: LOG_TARGET, "Initial bytes: {:?}", hex::encode(&initial_bytes));
        
        let input_var = Sha256Var::<Fr>::new_variable(
            cs.clone(),
            || Ok(initial_bytes.clone()),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        
        // Run circuit
        let circuit_result = circuit.generate_constraints(cs.clone(), &input_var).unwrap();
        let circuit_output = circuit_result.value().unwrap();
        tracing::debug!(target: LOG_TARGET, "Circuit output bytes: {:?}", hex::encode(&circuit_output));
        
        // Run native computation for comparison
        let native_output = run_native_sha256_chain(&initial_bytes, iterations);
        
        // Verify the circuit ran successfully
        assert!(cs.is_satisfied().unwrap());
        tracing::info!(target: LOG_TARGET, "Circuit satisfied constraints successfully");
        
        // Compare circuit_output with native_output
        assert_eq!(circuit_output, native_output, "Circuit output should match native computation");
    }

    #[test]
    fn test_sha256_leaf_circuit_single_iteration() {
        let _guard = setup_test_tracing();
        tracing::info!(target: LOG_TARGET, "Starting test_sha256_leaf_circuit_single_iteration");
        
        let circuit = Sha256LeafCircuit::<Fr>::new(1);
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Start with a simple known input
        let input_bytes = vec![0u8; 32];
        let input_var = Sha256Var::<Fr>::new_variable(
            cs.clone(),
            || Ok(input_bytes),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        
        // Run circuit
        let circuit_result = circuit.generate_constraints(cs.clone(), &input_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        // The circuit should produce a valid result
        let _output = circuit_result.value().unwrap();
        
        // Verify constraints were generated
        assert!(cs.num_constraints() > 0);
    }
}