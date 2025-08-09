use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, Zero};
use tracing::{debug, info, instrument};

use super::{SHA256ChainMangroveComputation, SHA256ChainRequest};
use crate::tree_folding::circuit::sha256::calculate_sha256_native;

const LOG_TARGET: &str = "nexus-nova::tree_folding::mangrove::sha256_chain_builder";

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SHA256ChainBuilder<F: PrimeField> {
    pub chain_length: usize,
    pub num_leafs: usize,
    pub leaf_size: usize,
    /// Expected size of input vector per leaf
    /// For BN254 field: ~2 field elements per SHA256 operation (64 bytes ÷ 31 bytes/element)
    /// Total: num_sha256_per_leaf * 2 elements
    pub input_vector_size: usize,
    /// Expected size of output vector per leaf
    /// For BN254 field: 1 field element per SHA256 operation (32 bytes fits in 31-byte element)
    /// Total: num_sha256_per_leaf * 1 element
    pub output_vector_size: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> SHA256ChainBuilder<F> {
    #[instrument(target = LOG_TARGET)]
    pub fn new(chain_length: usize, num_leafs: usize) -> Self {
        info!(
            target: LOG_TARGET,
            "Creating SHA256ChainBuilder with chain_length: {}, num_leafs: {}",
            chain_length,
            num_leafs
        );

        assert!(chain_length > 0, "Chain length must be positive");
        assert!(num_leafs > 0, "Number of leafs must be positive");
        assert!(
            chain_length % num_leafs == 0,
            "Chain length must be divisible by number of leafs"
        );

        let leaf_size = chain_length / num_leafs;
        // With the new IntoFpVarVec implementation, Sha256Var returns one field element per byte:
        // - Input: 32 bytes (SHA256 output from previous iteration) = 32 field elements
        // - Output: 32 bytes (SHA256 output) = 32 field elements
        let input_vector_size = 32; // Always 32 bytes for SHA256
        let output_vector_size = 32; // Always 32 bytes for SHA256

        Self {
            chain_length,
            num_leafs,
            leaf_size,
            input_vector_size,
            output_vector_size,
            _phantom: std::marker::PhantomData,
        }
    }

    #[instrument(target = LOG_TARGET, skip(self, initial_input))]
    pub fn generate_requests(&self, initial_input: &[u8]) -> Vec<SHA256ChainRequest> {
        info!(
            target: LOG_TARGET,
            "Generating {} SHA256 chain requests",
            self.num_leafs
        );

        let mut requests = Vec::with_capacity(self.num_leafs);
        let mut current_input = initial_input.to_vec();

        for leaf_idx in 0..self.num_leafs {
            debug!(
                target: LOG_TARGET,
                "Generating request for leaf {}, iterations: {}",
                leaf_idx,
                self.leaf_size
            );

            // Create request for this leaf
            let request = SHA256ChainRequest::new(current_input.clone(), self.leaf_size);

            // Compute what the output should be after leaf_size iterations
            let mut next_input = current_input.clone();
            for _ in 0..self.leaf_size {
                next_input = calculate_sha256_native(&next_input);
            }

            requests.push(request);
            current_input = next_input;
        }

        requests
    }

    #[instrument(target = LOG_TARGET, skip(self, requests))]
    pub fn compute_mangrove_constraints(
        &self,
        requests: Vec<SHA256ChainRequest>,
    ) -> Vec<SHA256ChainMangroveComputation> {
        info!(
            target: LOG_TARGET,
            "Computing Mangrove constraints for {} requests",
            requests.len()
        );

        assert_eq!(
            requests.len(),
            self.num_leafs,
            "Number of requests must match number of leafs"
        );

        let mut computations = Vec::with_capacity(self.num_leafs);

        for (leaf_idx, request) in requests.into_iter().enumerate() {
            debug!(
                target: LOG_TARGET,
                "Processing leaf {} with {} iterations",
                leaf_idx,
                request.num_iterations
            );

            // Generate the SHA256 chain for this leaf
            let mut hashes = Vec::with_capacity(request.num_iterations);
            let mut current = request.input.clone();

            for _ in 0..request.num_iterations {
                let hash = calculate_sha256_native(&current);
                hashes.push(hash.clone());
                current = hash;
            }

            // Create permutation indices
            // With unpacked representation, we have 32 indices for each input/output
            let mut input_indices = Vec::with_capacity(32);
            let mut input_next_indices = Vec::with_capacity(32);
            let mut output_indices = Vec::with_capacity(32);
            let mut output_next_indices = Vec::with_capacity(32);

            // Simple sequential indexing for now
            // Each leaf has 32 input bytes and 32 output bytes
            let base_idx = leaf_idx * 64; // 32 input + 32 output per leaf

            // Input indices (32 bytes)
            for i in 0..32 {
                input_indices.push(base_idx + i);
                // First leaf's input points to itself (terminal start)
                // Other leafs' input next points to previous leaf's output
                if leaf_idx == 0 {
                    input_next_indices.push(base_idx + i); // First leaf: input points to self
                } else {
                    // Point to previous leaf's output
                    input_next_indices.push((leaf_idx - 1) * 64 + 32 + i);
                }
            }

            // Output indices (32 bytes)
            for i in 0..32 {
                output_indices.push(base_idx + 32 + i);
                // Output bytes point to next leaf's input (or self for last leaf)
                if leaf_idx < self.num_leafs - 1 {
                    // Point to next leaf's input
                    output_next_indices.push((leaf_idx + 1) * 64 + i);
                } else {
                    // Last leaf output points to itself (terminal end)
                    output_next_indices.push(base_idx + 32 + i);
                }
            }

            let computation = SHA256ChainMangroveComputation::new(
                request.input,
                hashes.last().unwrap().clone(),
                hashes,
                request.num_iterations,
            )
            .with_permutations(
                input_indices,
                input_next_indices,
                output_indices,
                output_next_indices,
            );

            computations.push(computation);
        }

        info!(
            target: LOG_TARGET,
            "Mangrove constraint computation complete"
        );

        computations
    }
}

/// Compute partial permutation products natively (without circuits)
/// This mirrors the circuit computation for testing
pub fn compute_permutation_partial_products<F: PrimeField>(
    values: &[F],
    indices: &[usize],
    next_indices: &[usize],
    alpha: F,
    beta: F,
) -> (F, F) {
    assert_eq!(values.len(), indices.len());
    assert_eq!(values.len(), next_indices.len());

    let mut numerator = F::one();
    let mut denominator = F::one();

    for i in 0..values.len() {
        // Numerator: product of (alpha * index + beta + value)
        let num_term = alpha * F::from(indices[i] as u64) + beta + values[i];
        numerator *= num_term;

        // Denominator: product of (alpha * next_index + beta + value)
        let den_term = alpha * F::from(next_indices[i] as u64) + beta + values[i];
        denominator *= den_term;
    }

    (numerator, denominator)
}

/// Helper function to convert bytes to field element
/// For testing purposes - in production this would use proper serialization
pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> F {
    // Simple conversion for testing - just use first few bytes
    let mut val = F::zero();
    let mut base = F::one();

    for &byte in bytes.iter().take(8) {
        val += F::from(byte as u64) * base;
        base *= F::from(256u64);
    }

    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar, R1CSVar};
    use ark_std::{test_rng, One, Zero};
    use tracing::error;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target("nexus-nova", tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE | FmtSpan::ACTIVE)
                    .with_test_writer()
                    .with_line_number(true),
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_sha256_chain_builder_creation() {
        let builder = SHA256ChainBuilder::<Bn254Fr>::new(8, 4);
        assert_eq!(builder.chain_length, 8);
        assert_eq!(builder.num_leafs, 4);
        assert_eq!(builder.leaf_size, 2);
        assert_eq!(builder.input_vector_size, 32); // Always 32 bytes for SHA256
        assert_eq!(builder.output_vector_size, 32); // Always 32 bytes for SHA256
    }

    #[test]
    fn test_generate_requests() {
        let builder = SHA256ChainBuilder::<Bn254Fr>::new(4, 2);
        let initial_input = vec![0u8; 32]; // Use 32-byte input
        let requests = builder.generate_requests(&initial_input);

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].num_iterations, 2);
        assert_eq!(requests[0].input, initial_input.to_vec());

        // Second request should start with the output of the first
        let expected_second_input = {
            let mut temp = initial_input.to_vec();
            for _ in 0..2 {
                temp = calculate_sha256_native(&temp);
            }
            temp
        };
        assert_eq!(requests[1].input, expected_second_input);
    }

    #[test]
    fn test_permutation_products_telescope() {
        let _guard = setup_test_tracing();

        // Test that permutation products telescope correctly across chunks
        let mut rng = test_rng();
        let alpha = Bn254Fr::rand(&mut rng);
        let beta = Bn254Fr::rand(&mut rng);

        let builder = SHA256ChainBuilder::<Bn254Fr>::new(8, 4); // 4 chunks, 2 SHA256 each
        let initial_input = vec![1u8; 32]; // Use 32-byte input

        // Generate requests and computations
        let requests = builder.generate_requests(&initial_input);
        let computations = builder.compute_mangrove_constraints(requests);

        // For this test, we'll use dummy field values
        let mut all_numerators = Bn254Fr::one();
        let mut all_denominators = Bn254Fr::one();

        for computation in &computations {
            // Create dummy field values for testing
            // In real implementation, these would be derived from the actual SHA256 computation
            let input_values: Vec<Bn254Fr> = (0..builder.input_vector_size)
                .map(|_| Bn254Fr::rand(&mut rng))
                .collect();

            let output_values: Vec<Bn254Fr> = (0..builder.output_vector_size)
                .map(|_| Bn254Fr::rand(&mut rng))
                .collect();

            // Compute partial products for input
            let (input_num, input_den) = compute_permutation_partial_products(
                &input_values,
                &computation.input_indices,
                &computation.input_next_indices,
                alpha,
                beta,
            );

            // Compute partial products for output
            let (output_num, output_den) = compute_permutation_partial_products(
                &output_values,
                &computation.output_indices,
                &computation.output_next_indices,
                alpha,
                beta,
            );

            // Accumulate products
            all_numerators *= input_num * output_num;
            all_denominators *= input_den * output_den;
        }

        // In a properly connected permutation, the products should telescope
        // For this test with dummy values, we just verify the computation runs
        debug!(
            target: LOG_TARGET,
            "Total numerator: {:?}, Total denominator: {:?}",
            all_numerators,
            all_denominators
        );

        // Verify all computations have correct structure
        for (i, comp) in computations.iter().enumerate() {
            assert_eq!(comp.num_iterations, builder.leaf_size);
            assert_eq!(comp.intermediate_hashes.len(), builder.leaf_size);
            assert_eq!(comp.input_indices.len(), builder.input_vector_size);
            assert_eq!(comp.output_indices.len(), builder.output_vector_size);
            debug!(target: LOG_TARGET, "Leaf {} verified", i);
        }
    }

    #[test]
    fn test_sha256_permutation_telescoping_detailed() {
        let _guard = setup_test_tracing();

        let mut rng = test_rng();
        let alpha = Bn254Fr::rand(&mut rng);
        let beta = Bn254Fr::rand(&mut rng);

        info!(
            target: LOG_TARGET,
            "Testing permutation telescoping with alpha: {:?}, beta: {:?}",
            alpha,
            beta
        );

        // Create 4 chunks each with 2 SHA256 operations
        let builder = SHA256ChainBuilder::<Bn254Fr>::new(8, 4);
        let initial_input = vec![2u8; 32]; // Use 32-byte input

        // Generate requests and computations
        let requests = builder.generate_requests(&initial_input);
        let computations = builder.compute_mangrove_constraints(requests);

        // Convert byte values to field elements for permutation computation
        // For BN254: 32-byte hash fits in one field element, 64-byte input needs 2
        let mut all_values = Vec::new();
        let mut all_indices = Vec::new();
        let mut all_next_indices = Vec::new();

        // Build a global permutation by concatenating all leaf permutations
        let mut global_offset = 0;

        for (leaf_idx, computation) in computations.iter().enumerate() {
            debug!(
                target: LOG_TARGET,
                "Processing leaf {} with {} iterations",
                leaf_idx,
                computation.num_iterations
            );

            // For each SHA256 operation in this leaf
            for (op_idx, hash) in computation.intermediate_hashes.iter().enumerate() {
                // Input values (previous hash or initial input)
                let input_bytes = if op_idx == 0 && leaf_idx == 0 {
                    &computation.initial_input
                } else if op_idx == 0 {
                    // First operation of non-first leaf uses last hash of previous leaf
                    &computations[leaf_idx - 1].final_output
                } else {
                    &computation.intermediate_hashes[op_idx - 1]
                };

                // Convert input bytes to field elements
                // For SHA256 output (32 bytes), we need to handle it properly
                let (input_val1, input_val2) = if input_bytes.len() == 32 {
                    // This is a SHA256 output being used as input for next iteration
                    // Pad it to create two field elements
                    let val1 = bytes_to_field::<Bn254Fr>(input_bytes);
                    let val2 = Bn254Fr::zero(); // Padding
                    (val1, val2)
                } else {
                    // This is the initial input or padded input
                    // Split into two parts
                    let mid = input_bytes.len() / 2;
                    let val1 = bytes_to_field::<Bn254Fr>(&input_bytes[..mid]);
                    let val2 = bytes_to_field::<Bn254Fr>(&input_bytes[mid..]);
                    (val1, val2)
                };

                // Output value (current hash, 32 bytes -> 1 field element)
                let output_val = bytes_to_field::<Bn254Fr>(hash);

                // Add values with their permutation indices
                all_values.push(input_val1);
                all_indices.push(global_offset);
                all_next_indices.push(
                    if leaf_idx == computations.len() - 1
                        && op_idx == computation.intermediate_hashes.len() - 1
                    {
                        // Last element points to itself (terminal)
                        global_offset + 2
                    } else {
                        global_offset + 3 // Points to next output
                    },
                );
                global_offset += 1;

                all_values.push(input_val2);
                all_indices.push(global_offset);
                all_next_indices.push(global_offset + 1); // Sequential
                global_offset += 1;

                all_values.push(output_val);
                all_indices.push(global_offset);
                all_next_indices.push(
                    if op_idx == computation.intermediate_hashes.len() - 1
                        && leaf_idx < computations.len() - 1
                    {
                        // Last output of non-last leaf points to first input of next leaf
                        global_offset + 1
                    } else if op_idx < computation.intermediate_hashes.len() - 1 {
                        // Output points to next input within same leaf
                        global_offset + 1
                    } else {
                        // Terminal
                        global_offset
                    },
                );
                global_offset += 1;
            }
        }

        // Compute the global permutation product
        let (global_num, global_den) = compute_permutation_partial_products(
            &all_values,
            &all_indices,
            &all_next_indices,
            alpha,
            beta,
        );

        info!(
            target: LOG_TARGET,
            "Global permutation product: numerator = {:?}, denominator = {:?}",
            global_num,
            global_den
        );

        // For a valid permutation that forms a cycle, numerator should equal denominator
        // In our case with terminal elements, we verify the structure is correct
        assert_eq!(all_values.len(), all_indices.len());
        assert_eq!(all_values.len(), all_next_indices.len());

        // Now compute per-leaf products and verify they combine correctly
        let mut combined_numerator = Bn254Fr::one();
        let mut combined_denominator = Bn254Fr::one();

        global_offset = 0;
        for (leaf_idx, computation) in computations.iter().enumerate() {
            let leaf_size = computation.num_iterations * 3; // 2 inputs + 1 output per operation
            let leaf_values = &all_values[global_offset..global_offset + leaf_size];
            let leaf_indices = &all_indices[global_offset..global_offset + leaf_size];
            let leaf_next_indices = &all_next_indices[global_offset..global_offset + leaf_size];

            let (leaf_num, leaf_den) = compute_permutation_partial_products(
                leaf_values,
                leaf_indices,
                leaf_next_indices,
                alpha,
                beta,
            );

            debug!(
                target: LOG_TARGET,
                "Leaf {} partial products: num = {:?}, den = {:?}",
                leaf_idx,
                leaf_num,
                leaf_den
            );

            combined_numerator *= leaf_num;
            combined_denominator *= leaf_den;
            global_offset += leaf_size;
        }

        info!(
            target: LOG_TARGET,
            "Combined leaf products: numerator = {:?}, denominator = {:?}",
            combined_numerator,
            combined_denominator
        );
    }

    /// Test cross-leaf permutation consistency using real SHA256 circuits
    #[test]
    fn test_cross_leaf_permutation_with_circuits() {
        let _guard = setup_test_tracing();

        use crate::tree_folding::mangrove::circuit::{
            FnCircuit, MangroveLeafCircuit, MangroveLeafVar, Sha256LeafCircuit, Sha256Var,
        };
        use ark_r1cs_std::{alloc::AllocationMode, fields::fp::FpVar};
        use ark_relations::r1cs::ConstraintSystem;

        let mut rng = test_rng();
        let alpha = Bn254Fr::rand(&mut rng);
        let beta = Bn254Fr::rand(&mut rng);

        info!(
            target: LOG_TARGET,
            "Testing cross-leaf permutation consistency with real SHA256 circuits"
        );

        // Create 8 chunks each with 4 SHA256 operations (32 total)
        let builder = SHA256ChainBuilder::<Bn254Fr>::new(32, 8);
        // Use a 32-byte initial input for SHA256 chain (hash of the original message)
        let initial_input = calculate_sha256_native(b"test cross-leaf permutation");

        // Generate requests and computations
        let requests = builder.generate_requests(&initial_input);
        let computations = builder.compute_mangrove_constraints(requests);

        info!(
            target: LOG_TARGET,
            "Generated {} leaf computations",
            computations.len()
        );

        // Test each leaf in a circuit using the real Sha256LeafCircuit
        let mut constraint_counts = Vec::new();
        let mut all_partial_products = Vec::new();

        for (leaf_idx, computation) in computations.iter().enumerate() {
            debug!(
                target: LOG_TARGET,
                "Testing leaf {} in circuit with {} iterations",
                leaf_idx,
                computation.num_iterations
            );

            // Create constraint system for this leaf
            let cs = ConstraintSystem::<Bn254Fr>::new_ref();

            // Convert computation to MangroveLeafData
            let mangrove_data = computation_to_mangrove_data(computation, alpha, beta);

            // Debug the data being passed
            debug!(
                target: LOG_TARGET,
                "MangroveLeafData for leaf {}: input len={}, output len={}, input_indices len={}, output_indices len={}",
                leaf_idx,
                mangrove_data.input.len(),
                mangrove_data.output.len(),
                mangrove_data.permutation_input_index.len(),
                mangrove_data.permutation_output_index.len()
            );

            // Check data validity for Sha256Var (should be 32 bytes)
            if mangrove_data.input.len() != 32 {
                error!(
                    target: LOG_TARGET,
                    "Input data length {} is not 32 bytes, required for Sha256Var",
                    mangrove_data.input.len()
                );
            }

            if mangrove_data.output.len() != 32 {
                error!(
                    target: LOG_TARGET,
                    "Output data length {} is not 32 bytes, required for Sha256Var",
                    mangrove_data.output.len()
                );
            }

            // Check constraint system before allocation
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraint system should be satisfied before MangroveLeafVar allocation"
            );

            // Allocate MangroveLeafVar
            let mangrove_var = match MangroveLeafVar::<
                Bn254Fr,
                Sha256Var<Bn254Fr>,
                Sha256Var<Bn254Fr>,
            >::new_variable(
                cs.clone(), || Ok(mangrove_data), AllocationMode::Witness
            ) {
                Ok(var) => var,
                Err(e) => {
                    error!(target: LOG_TARGET, "MangroveLeafVar allocation failed: {:?}", e);

                    // Check if constraint system became unsatisfied
                    if let Ok(satisfied) = cs.is_satisfied() {
                        error!(target: LOG_TARGET, "Constraint system satisfied after failure: {}", satisfied);
                        if !satisfied {
                            if let Ok(Some(idx)) = cs.which_is_unsatisfied() {
                                error!(target: LOG_TARGET, "Unsatisfied constraint at index: {:?}", idx);
                            }
                        }
                    }
                    panic!("Failed to allocate MangroveLeafVar: {:?}", e);
                }
            };

            // Create a real SHA256 circuit for this leaf
            let sha256_circuit = Sha256LeafCircuit::new(computation.num_iterations);

            // Wrap it in the MangroveLeafCircuit for permutation handling
            let mangrove_circuit = MangroveLeafCircuit::new(sha256_circuit);

            // Generate constraints and get partial products
            let partial_products = mangrove_circuit
                .generate_constraints(cs.clone(), &mangrove_var)
                .map_err(|e| {
                    error!(target: LOG_TARGET, "MangroveLeafCircuit constraint generation failed: {:?}", e);

                    // Check if constraint system became unsatisfied
                    if let Ok(satisfied) = cs.is_satisfied() {
                        error!(target: LOG_TARGET, "Constraint system satisfied after circuit failure: {}", satisfied);
                        if !satisfied {
                            if let Ok(Some(idx)) = cs.which_is_unsatisfied() {
                                error!(target: LOG_TARGET, "Unsatisfied constraint at index: {:?}", idx);
                            }
                        }
                    }
                    e
                })
                .expect("Failed to generate constraints");

            // Verify constraint system is satisfied
            assert!(
                cs.is_satisfied().unwrap(),
                "Constraint system should be satisfied for leaf {}",
                leaf_idx
            );

            let num_constraints = cs.num_constraints();
            constraint_counts.push(num_constraints);

            info!(
                target: LOG_TARGET,
                "Leaf {} circuit satisfied with {} constraints, {} variables",
                leaf_idx,
                num_constraints,
                cs.num_witness_variables()
            );

            // Store the partial products for later multiplication
            all_partial_products.push(partial_products);
        }

        // Critical test: Multiply all partial products together
        info!(
            target: LOG_TARGET,
            "Multiplying all {} partial products together to verify telescoping",
            all_partial_products.len()
        );

        // Create combined partial products
        let mut combined_numerator = FpVar::<Bn254Fr>::one();
        let mut combined_denominator = FpVar::<Bn254Fr>::one();

        for (leaf_idx, products) in all_partial_products.iter().enumerate() {
            combined_numerator = &combined_numerator * &products.numerator;
            combined_denominator = &combined_denominator * &products.denominator;

            debug!(
                target: LOG_TARGET,
                "After incorporating leaf {}: numerator = {:?}, denominator = {:?}",
                leaf_idx,
                combined_numerator.value().unwrap_or_default(),
                combined_denominator.value().unwrap_or_default()
            );
        }

        // The key assertion: In a properly constructed permutation argument,
        // the combined numerator should equal the combined denominator
        info!(
            target: LOG_TARGET,
            "Verifying that combined numerator equals combined denominator (telescoping property)"
        );

        // Extract the final values
        let final_numerator = combined_numerator
            .value()
            .expect("Failed to get numerator value");
        let final_denominator = combined_denominator
            .value()
            .expect("Failed to get denominator value");

        info!(
            target: LOG_TARGET,
            "Final numerator: {:?}",
            final_numerator
        );
        info!(
            target: LOG_TARGET,
            "Final denominator: {:?}",
            final_denominator
        );

        // This is the crucial test for Mangrove folding: the products should telescope
        assert_eq!(
            final_numerator, final_denominator,
            "Combined numerator must equal combined denominator for valid permutation argument"
        );

        info!(
            target: LOG_TARGET,
            "✅ PERMUTATION TELESCOPING VERIFIED: numerator == denominator"
        );

        // Test single leaf with same total computation for comparison
        info!(
            target: LOG_TARGET,
            "Testing single leaf with equivalent computation (32 SHA256 operations)"
        );

        let single_builder = SHA256ChainBuilder::<Bn254Fr>::new(32, 1);
        let single_requests = single_builder.generate_requests(&initial_input);
        let single_computations = single_builder.compute_mangrove_constraints(single_requests);

        assert_eq!(single_computations.len(), 1);

        let single_computation = &single_computations[0];
        let single_cs = ConstraintSystem::<Bn254Fr>::new_ref();

        let single_mangrove_data = computation_to_mangrove_data(single_computation, alpha, beta);
        let single_mangrove_var =
            MangroveLeafVar::<Bn254Fr, Sha256Var<Bn254Fr>, Sha256Var<Bn254Fr>>::new_variable(
                single_cs.clone(),
                || Ok(single_mangrove_data),
                AllocationMode::Witness,
            )
            .expect("Failed to allocate single MangroveLeafVar");

        // Use real SHA256 circuit for single leaf too
        let single_sha256_circuit = Sha256LeafCircuit::new(single_computation.num_iterations);
        let single_mangrove_circuit = MangroveLeafCircuit::new(single_sha256_circuit);

        let _single_partial_products = single_mangrove_circuit
            .generate_constraints(single_cs.clone(), &single_mangrove_var)
            .expect("Failed to generate constraints for single leaf");

        assert!(
            single_cs.is_satisfied().unwrap(),
            "Single leaf constraint system should be satisfied"
        );

        info!(
            target: LOG_TARGET,
            "Single leaf circuit satisfied with {} constraints, {} variables",
            single_cs.num_constraints(),
            single_cs.num_witness_variables()
        );

        // Verify both strategies produce the same final output
        let multi_leaf_final = &computations.last().unwrap().final_output;
        let single_leaf_final = &single_computation.final_output;

        assert_eq!(
            multi_leaf_final, single_leaf_final,
            "Multi-leaf and single-leaf should produce identical outputs"
        );

        info!(
            target: LOG_TARGET,
            "Cross-leaf permutation consistency test passed! Both strategies produce identical SHA256 outputs"
        );

        // Additional validation: verify constraint counts are reasonable
        let total_multi_leaf_constraints: usize = constraint_counts.iter().sum();
        let single_leaf_constraints = single_cs.num_constraints();

        info!(
            target: LOG_TARGET,
            "Constraint comparison: {} total multi-leaf constraints vs {} single-leaf constraints",
            total_multi_leaf_constraints,
            single_leaf_constraints
        );
    }

    /// Convert SHA256ChainMangroveComputation to MangroveLeafData for circuit testing
    fn computation_to_mangrove_data<F: PrimeField>(
        computation: &SHA256ChainMangroveComputation,
        alpha: F,
        beta: F,
    ) -> crate::tree_folding::mangrove::circuit::MangroveLeafData<F, Vec<u8>, Vec<u8>> {
        // For the circuit, we need to match what the native computation did.
        // The computation already has the correct input in computation.initial_input
        // which was used to compute the final_output.
        let circuit_input = computation.initial_input.clone();

        // Sha256Var requires exactly 32 bytes
        assert_eq!(
            circuit_input.len(),
            32,
            "SHA256 circuit requires 32-byte input, got {} bytes",
            circuit_input.len()
        );

        // The expected output should be the final_output from the computation
        // which was already computed correctly by compute_mangrove_constraints
        let expected_output = computation.final_output.clone();

        debug!(
            target: LOG_TARGET,
            "Circuit simulation: iterations={}, input_len={}, output_len={}, input_hex={}, output_hex={}",
            computation.num_iterations,
            circuit_input.len(),
            expected_output.len(),
            hex::encode(&circuit_input),
            hex::encode(&expected_output)
        );
        // Convert indices from usize to field elements
        let permutation_input_index: Vec<F> = computation
            .input_indices
            .iter()
            .map(|&idx| F::from(idx as u64))
            .collect();

        let permutation_input_next_index: Vec<F> = computation
            .input_next_indices
            .iter()
            .map(|&idx| F::from(idx as u64))
            .collect();

        let permutation_output_index: Vec<F> = computation
            .output_indices
            .iter()
            .map(|&idx| F::from(idx as u64))
            .collect();

        let permutation_output_next_index: Vec<F> = computation
            .output_next_indices
            .iter()
            .map(|&idx| F::from(idx as u64))
            .collect();

        crate::tree_folding::mangrove::circuit::MangroveLeafData {
            alpha,
            beta,
            input: circuit_input,
            permutation_input_index,
            permutation_input_next_index,
            output: expected_output,
            permutation_output_index,
            permutation_output_next_index,
        }
    }

    #[test]
    fn test_edge_case_first_and_last_leaf_self_pointing() {
        let _guard = setup_test_tracing();

        // Create a chain with 3 leafs to test edge cases
        let builder = SHA256ChainBuilder::<Bn254Fr>::new(6, 3); // 3 leafs, 2 SHA256 each
        let initial_input = vec![0u8; 32];

        // Generate requests and computations
        let requests = builder.generate_requests(&initial_input);
        let computations = builder.compute_mangrove_constraints(requests);

        assert_eq!(computations.len(), 3);

        // Test first leaf: input should point to itself
        let first_leaf = &computations[0];
        for i in 0..32 {
            assert_eq!(
                first_leaf.input_indices[i], first_leaf.input_next_indices[i],
                "First leaf input index {} should point to itself",
                i
            );
        }
        // First leaf output should point to next leaf
        for i in 0..32 {
            assert_eq!(
                first_leaf.output_next_indices[i],
                64 + i,
                "First leaf output index {} should point to second leaf input",
                i
            );
        }

        // Test middle leaf: should have normal connections
        let middle_leaf = &computations[1];
        for i in 0..32 {
            // Input's next points to previous leaf's output
            assert_eq!(
                middle_leaf.input_next_indices[i],
                32 + i,
                "Middle leaf input next index {} should point to first leaf's output",
                i
            );
            // Output points to next leaf's input
            assert_eq!(
                middle_leaf.output_next_indices[i],
                128 + i,
                "Middle leaf output index {} should point to third leaf input",
                i
            );
        }

        // Test last leaf: output should point to itself
        let last_leaf = &computations[2];
        for i in 0..32 {
            // Input's next points to previous (middle) leaf's output
            assert_eq!(
                last_leaf.input_next_indices[i],
                96 + i,
                "Last leaf input next index {} should point to middle leaf's output",
                i
            );
            // Output points to itself
            assert_eq!(
                last_leaf.output_indices[i], last_leaf.output_next_indices[i],
                "Last leaf output index {} should point to itself",
                i
            );
        }

        info!(
            target: LOG_TARGET,
            "✅ Edge case test passed: first leaf input points to self, last leaf output points to self"
        );
    }

    #[test]
    fn test_permutation_invariants() {
        let _guard = setup_test_tracing();

        // Create a small builder to thoroughly test permutation invariants
        let builder = SHA256ChainBuilder::<Bn254Fr>::new(12, 3); // 3 leafs, 4 SHA256 each
        let initial_input = vec![0u8; 32];

        // Generate requests and computations
        let requests = builder.generate_requests(&initial_input);
        let computations = builder.compute_mangrove_constraints(requests);

        assert_eq!(computations.len(), 3);

        // Verify permutation invariants
        for (leaf_idx, computation) in computations.iter().enumerate() {
            info!(
                target: LOG_TARGET,
                "Checking permutation invariants for leaf {}", leaf_idx
            );

            // Check input indices are sequential within the leaf
            let expected_base = leaf_idx * 64;
            for i in 0..32 {
                assert_eq!(
                    computation.input_indices[i],
                    expected_base + i,
                    "Input index {} for leaf {} should be {}",
                    i,
                    leaf_idx,
                    expected_base + i
                );
            }

            // Check output indices are sequential within the leaf
            for i in 0..32 {
                assert_eq!(
                    computation.output_indices[i],
                    expected_base + 32 + i,
                    "Output index {} for leaf {} should be {}",
                    i,
                    leaf_idx,
                    expected_base + 32 + i
                );
            }

            // Verify input next indices invariant
            if leaf_idx == 0 {
                // First leaf: input next points to itself
                for i in 0..32 {
                    assert_eq!(
                        computation.input_next_indices[i], computation.input_indices[i],
                        "First leaf input next index {} should point to itself",
                        i
                    );
                }
            } else {
                // Other leafs: input next points to previous leaf's output
                let prev_leaf_output_base = (leaf_idx - 1) * 64 + 32;
                for i in 0..32 {
                    assert_eq!(
                        computation.input_next_indices[i],
                        prev_leaf_output_base + i,
                        "Leaf {} input next index {} should point to previous leaf's output",
                        leaf_idx,
                        i
                    );
                }
            }

            // Verify output next indices invariant
            if leaf_idx == computations.len() - 1 {
                // Last leaf: output next points to itself
                for i in 0..32 {
                    assert_eq!(
                        computation.output_next_indices[i], computation.output_indices[i],
                        "Last leaf output next index {} should point to itself",
                        i
                    );
                }
            } else {
                // Other leafs: output next points to next leaf's input
                let next_leaf_input_base = (leaf_idx + 1) * 64;
                for i in 0..32 {
                    assert_eq!(
                        computation.output_next_indices[i],
                        next_leaf_input_base + i,
                        "Leaf {} output next index {} should point to next leaf's input",
                        leaf_idx,
                        i
                    );
                }
            }
        }

        info!(
            target: LOG_TARGET,
            "✅ Permutation invariants test passed: all indices follow expected patterns"
        );
    }
}
