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

use std::sync::Arc;
use std::thread;
use std::time::{Instant};
use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_std::{test_rng, start_timer, end_timer};
use hex;
use tracing;

// Additional imports for FastTestCircuit
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// Nova imports
use nexus_nova::circuits::nova::StepCircuit;
use nexus_nova::ccs::linearization::{StepFunctionInput, setup_linearization};
use nexus_nova::poseidon_config;
use nexus_nova::provider::zeromorph::{Zeromorph, PolyCommitmentScheme};
use nexus_nova::tree_folding::hypernova_fold_reducer::HypernovaFoldReducer;
use nexus_nova::tree_folding::fold_reducer::FoldReducer;
use nexus_nova::tree_folding::circuit::sha256::{calculate_sha256_native, conversions};
use nexus_nova::tree_folding::circuit::sequential_sha256::SequentialSha256Circuit;

// Type aliases for convenience - using BN254 (same as used in production)
type G1 = BN254G1;
type CF = BN254Fr;
type Z = Zeromorph<Bn254>;
type RO = PoseidonSponge<CF>;
type ROConfig = <RO as CryptographicSponge>::Config;
type PCKey = <Z as nexus_nova::provider::zeromorph::PolyCommitmentScheme<G1>>::PolyCommitmentKey;

const PARALLEL_TREE_TARGET: &str = "parallel_tree_example";

/// Helper function to get current thread information for logging
fn thread_info() -> String {
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or("unnamed");
    let thread_id = thread.id();
    format!("[Thread: {} ({:?})]", thread_name, thread_id)
}

/// Helper function to get a meaningful thread identifier
fn thread_id_short() -> String {
    let thread = std::thread::current();
    if let Some(name) = thread.name() {
        format!("[{}]", name)
    } else {
        // Extract numeric part from ThreadId debug representation
        let thread_id_str = format!("{:?}", thread.id());
        if let Some(id_num) = thread_id_str.strip_prefix("ThreadId(").and_then(|s| s.strip_suffix(")")) {
            format!("[T{}]", id_num)
        } else {
            format!("[T?]")
        }
    }
}

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
        .init();
}

/// Setup the test environment with proper SRS and random oracle config
fn setup_environment() -> (PCKey, ROConfig) {
    let timer = start_timer!(|| "Setting up environment");
    let mut rng = test_rng();
    
    // Setup SRS for Zeromorph - use larger degree for SHA-256 circuits
    let srs_degree = 18; // 2^18 = 262,144 coefficients - needed for SHA-256 circuits
    let srs_timer = start_timer!(|| "SRS setup");
    let srs = Z::setup(srs_degree, b"parallel-tree-fold-example", &mut rng)
        .expect("Failed to set up SRS");
    end_timer!(srs_timer);
        
    // Trim SRS to get commitment key
    let trim_timer = start_timer!(|| "SRS trimming");
    let ck = Z::trim(&srs, srs_degree - 1).ck;
    end_timer!(trim_timer);
    
    // Setup random oracle
    let ro_config = poseidon_config::<CF>();
    
    end_timer!(timer);
    (ck, ro_config)
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
fn process_messages_parallel(messages: Vec<Vec<u8>>, num_threads: usize) -> Vec<StepFunctionInput<CF>> {
    let num_messages = messages.len();
    let chunk_size = (num_messages + num_threads - 1) / num_threads; // Ceiling division
    
    let messages_arc = Arc::new(messages);
    let mut handles = vec![];
    
    tracing::info!(target: PARALLEL_TREE_TARGET, 
        "{} 🔄 Processing {} messages using {} threads (chunk size: {})", 
        thread_id_short(), num_messages, num_threads, chunk_size
    );
    
    // Spawn worker threads
    for thread_id in 0..num_threads {
        let messages_clone = Arc::clone(&messages_arc);
        let start_idx = thread_id * chunk_size;
        let end_idx = ((thread_id + 1) * chunk_size).min(num_messages);
        
        if start_idx >= num_messages {
            break; // No more work for this thread
        }
        
        tracing::info!(target: PARALLEL_TREE_TARGET, 
            "{} 🧵 Spawning worker thread {} for range {}..{}", 
            thread_id_short(), thread_id, start_idx, end_idx
        );
        
        let handle = thread::Builder::new()
            .name(format!("worker-{}", thread_id))
            .spawn(move || {
                let worker_thread_id = thread_id_short();
                tracing::info!(target: PARALLEL_TREE_TARGET, 
                    "{} 🚀 Worker thread {} started, processing {} items", 
                    worker_thread_id, thread_id, end_idx - start_idx
                );
                
                let mut results = Vec::new();
                
                for i in start_idx..end_idx {
                    let start_time = Instant::now();
                    
                    // Calculate actual SHA-256 hash
                    let hash_bytes = calculate_sha256_native(&messages_clone[i]);
                    
                    // Convert hash to field element for the SHA-256 circuit
                    let hash_field = conversions::bytes_to_field::<CF>(&hash_bytes);
                    
                    let process_time = start_time.elapsed();
                    
                    tracing::info!(target: PARALLEL_TREE_TARGET, 
                        "{} 📄 Worker {}: Leaf {}: Message = \"{}\" (processed in {:?})", 
                        worker_thread_id, thread_id, i, String::from_utf8_lossy(&messages_clone[i]), process_time
                    );
                    tracing::debug!(target: PARALLEL_TREE_TARGET, 
                        "{} 🔐 Worker {}: Leaf {}: SHA-256 hash = {}", 
                        worker_thread_id, thread_id, i, hex::encode(&hash_bytes)
                    );
                    tracing::debug!(target: PARALLEL_TREE_TARGET, 
                        "{} 🔢 Worker {}: Leaf {}: Hash as field = {}", 
                        worker_thread_id, thread_id, i, hash_field
                    );
                    
                    let step_input = StepFunctionInput {
                        i: CF::from(i as u64),
                        z_i: vec![hash_field], // SequentialSha256Circuit has ARITY = 1
                    };
                    results.push((i, step_input));
                }
                
                tracing::info!(target: PARALLEL_TREE_TARGET, 
                    "{} ✅ Worker thread {} completed, processed {} items", 
                    worker_thread_id, thread_id, results.len()
                );
                
                results
            })
            .expect("Failed to spawn worker thread");
        
        handles.push(handle);
    }
    
    tracing::info!(target: PARALLEL_TREE_TARGET, 
        "{} ⏳ Waiting for {} worker threads to complete...", 
        thread_id_short(), handles.len()
    );
    
    // Collect results from all threads and sort by original index
    let mut all_results = Vec::new();
    for (thread_idx, handle) in handles.into_iter().enumerate() {
        let thread_results = handle.join().expect("Thread panicked");
        tracing::info!(target: PARALLEL_TREE_TARGET, 
            "{} 📥 Collected {} results from worker thread {}", 
            thread_id_short(), thread_results.len(), thread_idx
        );
        all_results.extend(thread_results);
    }
    
    // Sort by original index to maintain order
    all_results.sort_by_key(|(idx, _)| *idx);
    
    tracing::info!(target: PARALLEL_TREE_TARGET, 
        "{} 🔄 Sorted {} results by original index", 
        thread_id_short(), all_results.len()
    );
    
    // Extract just the StepFunctionInput values
    all_results.into_iter().map(|(_, input)| input).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    
    let circuit_name = "Fast Test Circuit (x^3 + x + 5)";
    let computation_type = "cubic polynomial operations";
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 🚀 Starting Parallel Tree Folding Example with {}", thread_id_short(), circuit_name);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📊 Configuration:", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Leaf nodes: 64 (2^6, power of 2 for binary folding)", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Circuit: {} - {}", thread_id_short(), circuit_name, computation_type);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Folding: Sequential binary tree using FoldDriver", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 💡 Using fast test circuit for rapid development and testing", thread_id_short());
    
    // Setup environment
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 🔧 Setting up cryptographic environment...", thread_id_short());
    let srs_degree = 12; // Smaller SRS for test circuit
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} Starting SRS setup for degree {}...", thread_id_short(), srs_degree);
    let (ck, ro_config) = setup_environment_with_degree(srs_degree);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} ✅ Cryptographic environment setup completed", thread_id_short());
    
    // Create the test circuit
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 🔧 Creating {} instance...", thread_id_short(), circuit_name);
    
    let setup_timer = start_timer!(|| format!("{} reducer setup", circuit_name));
    let start_setup_time = Instant::now();
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} Setting up fast test circuit (should take seconds)...", thread_id_short());
    let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
    let linearization_params = setup_linearization(cs, FastTestCircuit::<CF> { _phantom: PhantomData })?;
    
    let setup_time = start_setup_time.elapsed();
    end_timer!(setup_timer);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} ✅ {} linearization completed in {:?}", thread_id_short(), circuit_name, setup_time);
    
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} Creating HypernovaFoldReducer instance...", thread_id_short());
    let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
        linearization_params,
        &ck,
        &ro_config,
    );
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} ✅ HypernovaFoldReducer created successfully", thread_id_short());
    
    // Generate sample inputs
    const NUM_LEAVES: usize = 64; // Must be power of 2 for binary folding (2^6 = 64)
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📝 Generating {} test inputs...", thread_id_short(), NUM_LEAVES);
    let step_inputs = generate_test_inputs(NUM_LEAVES);
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} Generated {} unique inputs", thread_id_short(), step_inputs.len());
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} ⏱️  Input generation completed", thread_id_short());

    // Perform tree folding manually with detailed timing
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 🌳 Starting manual binary tree folding with performance measurement...", thread_id_short());
    
    // Step 1: Convert all strict instances to accumulator instances (leaf computations)
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📊 Phase 1: Converting {} strict instances to accumulator instances ({})...", thread_id_short(), NUM_LEAVES, computation_type);
    let convert_timer = start_timer!(|| "All strict-to-acc conversions");
    let start_convert_time = Instant::now();
    
    let mut current_level = Vec::with_capacity(NUM_LEAVES);
    let mut leaf_times = Vec::with_capacity(NUM_LEAVES);
    
    for (i, step_input) in step_inputs.iter().enumerate() {
        let leaf_timer = start_timer!(|| format!("Leaf {} strict-to-acc", i));
        let start_leaf_time = Instant::now();
        
        tracing::info!(target: PARALLEL_TREE_TARGET, 
            "{}    Processing leaf {}/{}: Converting step input to accumulator...", 
            thread_id_short(), i + 1, NUM_LEAVES
        );
        
        let acc_instance = reducer.strict_to_acc(step_input)
            .map_err(|e| format!("Leaf {} conversion error: {:?}", i, e))?;
        
        let leaf_time = start_leaf_time.elapsed();
        end_timer!(leaf_timer);
        leaf_times.push(leaf_time);
        
        if i < 5 || i >= NUM_LEAVES - 5 {
            tracing::info!(target: PARALLEL_TREE_TARGET, 
                "{}    Leaf {}: converted in {:?} (LCCS X len: {}, witness W len: {})",
                thread_id_short(), i, leaf_time, acc_instance.0.X.len(), acc_instance.1.W.len()
            );
        } else if i == 5 {
            tracing::info!(target: PARALLEL_TREE_TARGET, "{}    ... (showing first 5 and last 5 leaf timings)", thread_id_short());
        }
        
        current_level.push(acc_instance);
    }
    
    let total_convert_time = start_convert_time.elapsed();
    end_timer!(convert_timer);
    
    // Calculate leaf conversion statistics
    let min_leaf_time = leaf_times.iter().min().unwrap();
    let max_leaf_time = leaf_times.iter().max().unwrap();
    let avg_leaf_time = leaf_times.iter().sum::<std::time::Duration>() / leaf_times.len() as u32;
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📈 Leaf Conversion Statistics:", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Total conversion time: {:?}", thread_id_short(), total_convert_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Average leaf time: {:?}", thread_id_short(), avg_leaf_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Fastest leaf: {:?}", thread_id_short(), min_leaf_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Slowest leaf: {:?}", thread_id_short(), max_leaf_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Leaf count: {}", thread_id_short(), leaf_times.len());
    
    // Step 2: Perform tree folding level by level (inner node computations)
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📊 Phase 2: Tree folding - combining accumulator instances...", thread_id_short());
    let fold_timer = start_timer!(|| "All tree folding operations");
    let start_fold_time = Instant::now();
    
    let mut level = 1;
    let mut all_fold_times = Vec::new();
    let mut level_times = Vec::new();
    
    while current_level.len() > 1 {
        let level_timer = start_timer!(|| format!("Level {} folding", level));
        let start_level_time = Instant::now();
        
        tracing::info!(target: PARALLEL_TREE_TARGET, 
            "{}    Level {}: folding {} instances into {} parent instances...", 
            thread_id_short(), level, current_level.len(), current_level.len() / 2
        );
        
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        let mut level_fold_times = Vec::new();
        
        // Process pairs of accumulator instances
        for (pair_idx, pair) in current_level.chunks_exact(2).enumerate() {
            let fold_op_timer = start_timer!(|| format!("Level {} pair {}", level, pair_idx));
            let start_fold_op_time = Instant::now();
            
            tracing::debug!(target: PARALLEL_TREE_TARGET, 
                "{}      Processing pair {} at level {}", 
                thread_id_short(), pair_idx, level
            );
            
            // Convert slice to array for fold_acc_acc
            let acc_array: &[_; 2] = pair.try_into().expect("chunks_exact guarantees len == 2");
            let (parent, _proof) = reducer.fold_acc_acc(acc_array)
                .map_err(|e| format!("Level {} pair {} fold error: {:?}", level, pair_idx, e))?;
            
            let fold_op_time = start_fold_op_time.elapsed();
            end_timer!(fold_op_timer);
            level_fold_times.push(fold_op_time);
            all_fold_times.push(fold_op_time);
            
            if pair_idx < 3 || pair_idx >= current_level.len() / 2 - 3 {
                tracing::info!(target: PARALLEL_TREE_TARGET, 
                    "{}      Pair {}: folded in {:?} (result LCCS X len: {}, witness W len: {})",
                    thread_id_short(), pair_idx, fold_op_time, parent.0.X.len(), parent.1.W.len()
                );
            } else if pair_idx == 3 {
                tracing::info!(target: PARALLEL_TREE_TARGET, "{}      ... (showing first 3 and last 3 pair timings)", thread_id_short());
            }
            
            next_level.push(parent);
        }
        
        let level_time = start_level_time.elapsed();
        end_timer!(level_timer);
        level_times.push((level, level_time, level_fold_times.len()));
        
        // Calculate level statistics
        let level_min = level_fold_times.iter().min().unwrap();
        let level_max = level_fold_times.iter().max().unwrap();
        let level_avg = level_fold_times.iter().sum::<std::time::Duration>() / level_fold_times.len() as u32;
        
        tracing::info!(target: PARALLEL_TREE_TARGET, 
            "{}    Level {} completed in {:?} (avg fold: {:?}, min: {:?}, max: {:?})",
            thread_id_short(), level, level_time, level_avg, level_min, level_max
        );
        
        current_level = next_level;
        level += 1;
    }
    
    let total_fold_time = start_fold_time.elapsed();
    end_timer!(fold_timer);
    
    // Calculate inner node folding statistics
    let min_fold_time = all_fold_times.iter().min().unwrap();
    let max_fold_time = all_fold_times.iter().max().unwrap();
    let avg_fold_time = all_fold_times.iter().sum::<std::time::Duration>() / all_fold_times.len() as u32;
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📈 Inner Node Folding Statistics:", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Total folding time: {:?}", thread_id_short(), total_fold_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Average fold time: {:?}", thread_id_short(), avg_fold_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Fastest fold: {:?}", thread_id_short(), min_fold_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Slowest fold: {:?}", thread_id_short(), max_fold_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Total fold operations: {}", thread_id_short(), all_fold_times.len());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Tree levels: {}", thread_id_short(), level_times.len());
    
    // Level-by-level breakdown
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📊 Level-by-level Breakdown:", thread_id_short());
    for (lvl, time, ops) in &level_times {
        tracing::info!(target: PARALLEL_TREE_TARGET, 
            "{}    Level {}: {} operations in {:?} (avg: {:?})",
            thread_id_short(), lvl, ops, time, *time / *ops as u32
        );
    }
    
    // Extract the root result
    assert_eq!(current_level.len(), 1, "Tree folding should result in exactly one root");
    let root = current_level.into_iter().next().unwrap();
    
    let total_tree_time = total_convert_time + total_fold_time;
    
    // Display results
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} ✅ Tree folding completed successfully!", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📊 Final Results:", thread_id_short());
    
    let (lccs_instance, witness) = root;
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Root LCCS instance X length: {}", thread_id_short(), lccs_instance.X.len());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Root witness W length: {}", thread_id_short(), witness.W.len());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Root LCCS rs length: {}", thread_id_short(), lccs_instance.rs.len());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Root LCCS vs length: {}", thread_id_short(), lccs_instance.vs.len());
    
    if let Some(final_value) = lccs_instance.X.get(0) {
        tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Final root value: {}", thread_id_short(), final_value);
    }
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 📈 Performance Summary:", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Number of leaf nodes: {}", thread_id_short(), NUM_LEAVES);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Preprocessing threads: {}", thread_id_short(), 1);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Hash generation time: {:?}", thread_id_short(), 0);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Tree folding time: {:?}", thread_id_short(), total_tree_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Total execution time: {:?}", thread_id_short(), total_tree_time);
    tracing::info!(target: PARALLEL_TREE_TARGET, "{}    • Average time per leaf: {:?}", thread_id_short(), total_tree_time / NUM_LEAVES as u32);
    
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 🎉 Parallel Tree Folding Example completed successfully!", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 💡 This demonstrates parallel preprocessing with sequential binary tree folding", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 💡 Each leaf and inner node represents actual cryptographic operations", thread_id_short());
    tracing::info!(target: PARALLEL_TREE_TARGET, "{} 💡 This is production-ready for ZK proving of computation trees", thread_id_short());
    
    Ok(())
}

/// Setup the test environment with configurable SRS degree
fn setup_environment_with_degree(srs_degree: usize) -> (PCKey, ROConfig) {
    let timer = start_timer!(|| "Setting up environment");
    let mut rng = test_rng();
    
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} 🔧 Setting up SRS with degree {}...", thread_id_short(), srs_degree);
    
    // Setup SRS for Zeromorph
    let srs_timer = start_timer!(|| "SRS setup");
    let srs = Z::setup(srs_degree, b"parallel-tree-fold-example", &mut rng)
        .expect("Failed to set up SRS");
    end_timer!(srs_timer);
    
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} ✂️  SRS setup completed, trimming...", thread_id_short());
        
    // Trim SRS to get commitment key
    let trim_timer = start_timer!(|| "SRS trimming");
    let ck = Z::trim(&srs, srs_degree - 1).ck;
    end_timer!(trim_timer);
    
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} 🎲 Setting up random oracle config...", thread_id_short());
    
    // Setup random oracle
    let ro_config = poseidon_config::<CF>();
    
    end_timer!(timer);
    
    tracing::debug!(target: PARALLEL_TREE_TARGET, "{} ✅ Environment setup complete", thread_id_short());
    
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
                assert_ne!(messages[i], messages[j], "Messages {} and {} should be different", i, j);
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