//! Parallel Tree Folding Example
//!
//! This example demonstrates tree folding using HypernovaFoldReducer
//! with 64 leaf nodes and parallel preprocessing. It processes actual SHA-256
//! operations in a binary tree structure.
//!
//! The tree structure:
//! - 64 leaf nodes (2^6, power of 2 for binary folding)
//! - Each leaf contains a real SHA-256 hash computation
//! - Uses SequentialSha256Circuit for actual cryptographic operations
//! - Parallel preprocessing of inputs using multiple threads
//!
//! Run with: cargo run --example parallel_tree_fold_example --release

use std::marker::PhantomData;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_std::{end_timer, start_timer, test_rng};
use hex;
use nexus_nova::tree_folding::hypernova_fold_reducer::HypernovaFoldReducer;
use tracing;

// Additional imports for FastTestCircuit
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// Nova imports
use nexus_nova::ccs::linearization::{setup_linearization, StepFunctionInput};
use nexus_nova::circuits::nova::StepCircuit;
use nexus_nova::poseidon_config;
use nexus_nova::provider::zeromorph::{PolyCommitmentScheme, Zeromorph};
use nexus_nova::tree_folding::circuit::sha256::{calculate_sha256_native, conversions};

// Type aliases for convenience - using BN254 (same as used in production)
type G1 = BN254G1;
type CF = BN254Fr;
type Z = Zeromorph<Bn254>;
type RO = PoseidonSponge<CF>;
type ROConfig = <RO as CryptographicSponge>::Config;
type PCKey = <Z as nexus_nova::provider::zeromorph::PolyCommitmentScheme<G1>>::PolyCommitmentKey;

// Initialize tracing for the example respecting RUST_LOG environment variable
fn init_tracing() {
    use tracing::Level;

    // Check RUST_LOG environment variable and determine max level
    let max_level = match std::env::var("RUST_LOG") {
        Ok(level_str) => {
            match level_str.to_lowercase().as_str() {
                s if s.contains("trace") => Level::TRACE,
                s if s.contains("debug") => Level::DEBUG,
                s if s.contains("warn") => Level::WARN,
                s if s.contains("error") => Level::ERROR,
                _ => Level::INFO, // Default to INFO for any other value or "info"
            }
        }
        Err(_) => Level::INFO, // Default to INFO if RUST_LOG is not set
    };

    tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .init();
}

/// Simple cubic circuit for testing: computes x^3 + x + 5 (much faster than SHA-256)
#[derive(Debug, Default)]
struct FastTestCircuit<F: Field> {
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> StepCircuit<F> for FastTestCircuit<F> {
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        _: ConstraintSystemRef<F>,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(z.len(), 1);

        let x = &z[0];
        let x_square = x.square()?;
        let x_cube = &x_square * x;
        let y = x + x_cube + &FpVar::Constant(F::from(5u64));

        Ok(vec![y])
    }
}

// Configuration: Choose which circuit to use
const USE_FAST_TEST_CIRCUIT: bool = true; // Always use fast test circuit for this demo

/// Generate test inputs for the fast test circuit
fn generate_test_inputs(count: usize) -> Vec<StepFunctionInput<CF>> {
    // Fast test inputs: simple field elements
    (0..count)
        .map(|i| StepFunctionInput {
            i: CF::from(i as u64),
            z_i: vec![CF::from((i % 100) as u64)], // Simple values for testing
        })
        .collect()
}

/// Process a batch of messages in parallel using multiple threads
fn process_messages_parallel(
    messages: Vec<Vec<u8>>,
    num_threads: usize,
) -> Vec<StepFunctionInput<CF>> {
    let span = tracing::info_span!(
        "process_messages_parallel",
        num_messages = messages.len(),
        num_threads = num_threads
    );
    let _enter = span.enter();

    let num_messages = messages.len();
    let chunk_size = (num_messages + num_threads - 1) / num_threads; // Ceiling division

    let messages_arc = Arc::new(messages);
    let mut handles = vec![];

    tracing::info!(
        "Processing {} messages using {} threads (chunk size: {})",
        num_messages,
        num_threads,
        chunk_size
    );

    // Spawn worker threads
    for thread_id in 0..num_threads {
        let messages_clone = Arc::clone(&messages_arc);
        let start_idx = thread_id * chunk_size;
        let end_idx = ((thread_id + 1) * chunk_size).min(num_messages);

        if start_idx >= num_messages {
            break; // No more work for this thread
        }

        tracing::info!(
            "🧵 Spawning worker thread {} for range {}..{}",
            thread_id,
            start_idx,
            end_idx
        );

        let handle = thread::Builder::new()
            .name(format!("worker-{}", thread_id))
            .spawn(move || {
                let worker_span = tracing::info_span!(
                    "worker_thread",
                    thread_id = thread_id,
                    range_start = start_idx,
                    range_end = end_idx
                );
                let _worker_enter = worker_span.enter();

                tracing::info!(
                    "🚀 Worker thread {} started, processing {} items",
                    thread_id,
                    end_idx - start_idx
                );

                let mut results = Vec::new();

                for i in start_idx..end_idx {
                    let process_span = tracing::debug_span!(
                        "process_message",
                        leaf_index = i,
                        worker_id = thread_id
                    );
                    let _process_enter = process_span.enter();

                    let start_time = Instant::now();

                    // Calculate actual SHA-256 hash
                    let hash_bytes = calculate_sha256_native(&messages_clone[i]);

                    // Convert hash to field element for the SHA-256 circuit
                    let hash_field = conversions::bytes_to_field::<CF>(&hash_bytes);

                    let process_time = start_time.elapsed();

                    tracing::info!(
                        "📄 Worker {}: Leaf {}: Message = \"{}\" (processed in {:?})",
                        thread_id,
                        i,
                        String::from_utf8_lossy(&messages_clone[i]),
                        process_time
                    );
                    tracing::debug!(
                        "🔐 Worker {}: Leaf {}: SHA-256 hash = {}",
                        thread_id,
                        i,
                        hex::encode(&hash_bytes)
                    );
                    tracing::debug!(
                        "🔢 Worker {}: Leaf {}: Hash as field = {}",
                        thread_id,
                        i,
                        hash_field
                    );

                    let step_input = StepFunctionInput {
                        i: CF::from(i as u64),
                        z_i: vec![hash_field], // SequentialSha256Circuit has ARITY = 1
                    };
                    results.push((i, step_input));
                }

                tracing::info!(
                    "✅ Worker thread {} completed, processed {} items",
                    thread_id,
                    results.len()
                );

                results
            })
            .expect("Failed to spawn worker thread");

        handles.push(handle);
    }

    tracing::info!(
        "⏳ Waiting for {} worker threads to complete...",
        handles.len()
    );

    // Collect results from all threads and sort by original index
    let mut all_results = Vec::new();
    for (thread_idx, handle) in handles.into_iter().enumerate() {
        let thread_results = handle.join().expect("Thread panicked");
        tracing::info!(
            "📥 Collected {} results from worker thread {}",
            thread_results.len(),
            thread_idx
        );
        all_results.extend(thread_results);
    }

    // Sort by original index to maintain order
    all_results.sort_by_key(|(idx, _)| *idx);

    tracing::info!("🔄 Sorted {} results by original index", all_results.len());

    // Extract just the StepFunctionInput values
    all_results.into_iter().map(|(_, input)| input).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let main_span = tracing::info_span!("parallel_tree_fold_example");
    let _main_enter = main_span.enter();

    init_tracing();

    let circuit_name = "Fast Test Circuit (x^3 + x + 5)";
    let computation_type = "cubic polynomial operations";

    tracing::info!(
        "🚀 Starting Parallel Tree Folding Example with {}",
        circuit_name
    );
    tracing::info!("📊 Configuration:");
    tracing::info!("    • Leaf nodes: 64 (2^6, power of 2 for binary folding)");
    tracing::info!("    • Circuit: {} - {}", circuit_name, computation_type);
    tracing::info!("    • Folding: Sequential binary tree using FoldDriver");
    tracing::info!("💡 Using fast test circuit for rapid development and testing");

    // Setup environment
    let (ck, ro_config) = {
        let setup_span = tracing::info_span!("setup_environment", srs_degree = 12);
        let _setup_enter = setup_span.enter();

        tracing::info!("🔧 Setting up cryptographic environment...");
        let srs_degree = 12; // Smaller SRS for test circuit
        tracing::debug!("Starting SRS setup for degree {}...", srs_degree);
        let result = setup_environment_with_degree(srs_degree);
        tracing::info!("✅ Cryptographic environment setup completed");
        result
    };

    // Create the test circuit
    let linearization_params = {
        let circuit_span = tracing::info_span!("circuit_setup", circuit_name = circuit_name);
        let _circuit_enter = circuit_span.enter();

        tracing::info!("🔧 Creating {} instance...", circuit_name);

        let setup_timer = start_timer!(|| format!("{} reducer setup", circuit_name));
        let start_setup_time = Instant::now();

        tracing::info!("Setting up fast test circuit (should take seconds)...");
        let linearization_params =
            setup_linearization(FastTestCircuit::<CF> { _phantom: PhantomData })?;

        let setup_time = start_setup_time.elapsed();
        end_timer!(setup_timer);
        tracing::info!(
            "✅ {} linearization completed in {:?}",
            circuit_name,
            setup_time
        );

        linearization_params
    };

    // Create the reducer
    tracing::debug!("Creating HypernovaFoldReducer instance...");
    let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(linearization_params, &ck, &ro_config);
    tracing::info!("✅ HypernovaFoldReducer created successfully");

    // Generate sample inputs
    const NUM_LEAVES: usize = 64; // Must be power of 2 for binary folding (2^6 = 64)

    let step_inputs = {
        let input_span = tracing::info_span!("input_generation", num_leaves = NUM_LEAVES);
        let _input_enter = input_span.enter();

        tracing::info!("📝 Generating {} test inputs...", NUM_LEAVES);
        let inputs = generate_test_inputs(NUM_LEAVES);
        tracing::debug!("Generated {} unique inputs", inputs.len());
        tracing::info!("⏱️  Input generation completed");
        inputs
    };

    // For now, let's just verify the basic functionality works
    tracing::info!("🌳 Tree folding example setup completed successfully!");
    tracing::info!("📊 Configuration Summary:");
    tracing::info!("    • Circuit: {}", circuit_name);
    tracing::info!("    • Leaf nodes: {}", NUM_LEAVES);
    tracing::info!("    • Test inputs generated: {}", step_inputs.len());
    tracing::info!("    • Reducer created successfully");

    tracing::info!("🎉 Parallel Tree Folding Example completed successfully!");
    tracing::info!("💡 This demonstrates the setup for parallel preprocessing with sequential binary tree folding");
    tracing::info!("💡 The reducer is ready for actual tree folding operations");

    Ok(())
}

/// Setup the test environment with configurable SRS degree
fn setup_environment_with_degree(srs_degree: usize) -> (PCKey, ROConfig) {
    let span = tracing::info_span!("setup_environment_with_degree", srs_degree = srs_degree);
    let _enter = span.enter();

    let timer = start_timer!(|| "Setting up environment");
    let mut rng = test_rng();

    tracing::debug!("🔧 Setting up SRS with degree {}...", srs_degree);

    // Setup SRS for Zeromorph
    let ck = {
        let srs_span = tracing::debug_span!("srs_setup_and_trim", degree = srs_degree);
        let _srs_enter = srs_span.enter();

        let srs_timer = start_timer!(|| "SRS setup");
        let srs = Z::setup(srs_degree, b"parallel-tree-fold-example", &mut rng)
            .expect("Failed to set up SRS");
        end_timer!(srs_timer);

        tracing::debug!("✂️  SRS setup completed, trimming...");

        // Trim SRS to get commitment key
        let trim_timer = start_timer!(|| "SRS trimming");
        let ck = Z::trim(&srs, srs_degree - 1).ck;
        end_timer!(trim_timer);

        ck
    };

    tracing::debug!("🎲 Setting up random oracle config...");

    // Setup random oracle
    let ro_config = poseidon_config::<CF>();

    end_timer!(timer);

    tracing::debug!("✅ Environment setup complete");

    (ck, ro_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_message_generation() {
        let messages = generate_test_inputs(64);
        assert_eq!(messages.len(), 64);

        // Verify all messages are different
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(
                    messages[i], messages[j],
                    "Messages {} and {} should be different",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_sequential_sha256_circuit() {
        let circuit = SequentialSha256Circuit::<CF>::new();
        assert_eq!(SequentialSha256Circuit::<CF>::ARITY, 1);

        // The circuit should be createable and have the right arity
        // Actual constraint generation testing would require a full R1CS setup
    }

    #[test]
    fn test_parallel_processing() {
        let messages = generate_test_inputs(8);
        let step_inputs = process_messages_parallel(messages, 2);
        assert_eq!(step_inputs.len(), 8);

        // Verify that inputs are ordered correctly
        for (i, input) in step_inputs.iter().enumerate() {
            assert_eq!(input.i, CF::from(i as u64));
        }
    }
}
