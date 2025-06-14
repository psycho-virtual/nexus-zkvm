use crate::ccs::linearization::{setup_linearization, StepFunctionInput};
use crate::poseidon_config;
use crate::tree_folding::circuit::sequential_sha256::SequentialSha256Circuit;
use crate::tree_folding::circuit::sha256::{conversions, calculate_sha256_native};
use crate::tree_folding::hypernova_fold_reducer::{HypernovaFoldReducer, HypernovaFoldError};
use crate::ccs::{LCCSInstance, CCSWitness};
use crate::absorb::AbsorbEmulatedFp;
use ark_crypto_primitives::sponge::{CryptographicSponge, Absorb};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_relations::r1cs::ConstraintSystem;
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_std::test_rng;
use ark_ec::{CurveGroup};
use ark_ff::{PrimeField, ToConstraintField};
use std::sync::Arc;
use tracing::{info, debug, instrument};
use crate::parallel_tree::parallel_tree_folder::ParallelTreeFolder;
use crate::parallel_tree::parallel_tree_folder::ParallelTreeError;
use num_cpus;

const LOG_TARGET: &str = "nexus-nova::parallel_tree::sha256_chain_folder";

/// Error type for SHA-256 chain folding operations
#[derive(Debug)]
pub enum Sha256ChainError {
    /// Setup failed
    SetupFailed(String),
    /// Invalid input
    InvalidInput(String),
    /// Parallel tree computation failed
    ParallelTreeFailed(ParallelTreeError),
    /// Hypernova folding failed
    HypernovaFailed(HypernovaFoldError),
}

impl From<ParallelTreeError> for Sha256ChainError {
    fn from(err: ParallelTreeError) -> Self {
        Sha256ChainError::ParallelTreeFailed(err)
    }
}

impl From<HypernovaFoldError> for Sha256ChainError {
    fn from(err: HypernovaFoldError) -> Self {
        Sha256ChainError::HypernovaFailed(err)
    }
}

/// A specialized folder for proving chains of SHA-256 hash values
/// This struct provides a high-level interface for creating and proving
/// sequential SHA-256 computations using the Hypernova folding protocol
/// through the ParallelTreeFolder infrastructure
pub struct Sha256ChainFolder<G, C, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G> + std::fmt::Debug + 'static,
    C::PolyCommitmentKey: Sync + Clone + Send + Sync,
    RO: CryptographicSponge<Config = PoseidonConfig<G::ScalarField>> + Send + Sync + 'static,
    RO::Config: Send + Sync + Clone,
{
    /// Commitment key
    ck: C::PolyCommitmentKey,
    /// Random oracle configuration
    ro_config: RO::Config,
}

/// Result of SHA-256 chain folding
pub struct Sha256ChainResult<G, C>
where
    G: CurveGroup,
    C: PolyCommitmentScheme<G>,
{
    /// The folded LCCS instance representing the root of the computation tree
    pub lccs_instance: LCCSInstance<G, C>,
    /// The corresponding witness
    pub witness: CCSWitness<G>,
    /// The final hash value from the native computation (for verification)
    pub final_hash: Vec<u8>,
    /// Number of messages processed
    pub num_messages: usize,
}

impl<G, C, RO> Sha256ChainFolder<G, C, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G> + std::fmt::Debug + 'static,
    C::PolyCommitmentKey: Sync + Clone + Send + Sync,
    RO: CryptographicSponge<Config = PoseidonConfig<G::ScalarField>> + Send + Sync + 'static,
    RO::Config: Send + Sync + Clone,
{
    /// Create a new SHA-256 chain folder with default setup
    /// This will initialize the cryptographic parameters needed for folding
    #[instrument(level = "info")]
    pub fn new() -> Result<Self, Sha256ChainError> {
        tracing::info!(target = LOG_TARGET, "🚀 Initializing SHA-256 chain folder");
        
        let mut rng = test_rng();
        
        // Setup SRS for Zeromorph - use larger degree for SHA-256 circuit
        let srs_degree = 17; // 2^17 = ~130k coefficients for SHA-256 constraints
        tracing::info!(target = LOG_TARGET, "Setting up SRS with degree 2^{} = {} coefficients", srs_degree, 1 << srs_degree);
        
        let srs = C::setup(srs_degree, b"sha256-chain-folder", &mut rng)
            .map_err(|e| Sha256ChainError::SetupFailed(format!("SRS setup failed: {:?}", e)))?;

        // Trim SRS to get commitment key
        tracing::debug!(target = LOG_TARGET, "Trimming SRS to create commitment key");
        let ck = C::trim(&srs, srs_degree - 1).ck;

        // Setup random oracle configuration
        let ro_config = poseidon_config::<G::ScalarField>();

        tracing::info!(target = LOG_TARGET, "✅ SHA-256 chain folder initialized successfully");

        Ok(Self {
            ck,
            ro_config,
        })
    }

    /// Process a chain of messages and prove their sequential SHA-256 hashes
    /// 
    /// This function:
    /// 1. Takes a vector of messages
    /// 2. Creates StepFunctionInput instances for each message  
    /// 3. Uses ParallelTreeFolder to fold them into a tree structure using Hypernova
    /// 4. Returns the folded proof and verification data
    #[instrument(level = "info", skip(self, messages))]
    pub fn run(&self, messages: Vec<Vec<u8>>) -> Result<Sha256ChainResult<G, C>, Sha256ChainError> {
        if messages.is_empty() {
            return Err(Sha256ChainError::InvalidInput("Messages list cannot be empty".to_string()));
        }

        // Check that we have a power-of-2 number of messages for the binary tree
        let num_messages = messages.len();
        if !num_messages.is_power_of_two() {
            return Err(Sha256ChainError::InvalidInput(
                format!("Number of messages must be a power of 2, got {}", num_messages)
            ));
        }

        tracing::info!(target = LOG_TARGET, "📝 Processing {} messages through SHA-256 chain folding", num_messages);

        // Step 1: Create StepFunctionInput instances for each message
        let mut leaves = Vec::with_capacity(num_messages);
        let mut current_hash = None;

        for (i, message) in messages.iter().enumerate() {
            tracing::debug!(target = LOG_TARGET, "Creating step function input {} for message of {} bytes", i, message.len());
            
            // For the first message, use the message itself
            // For subsequent messages, use the previous hash as input
            let input_data = if i == 0 {
                message.clone()
            } else {
                current_hash.clone().unwrap()
            };

            // Calculate the actual SHA-256 hash for this step (for verification)
            let hash_result = calculate_sha256_native(&input_data);
            current_hash = Some(hash_result.clone());

            // Convert the input to a field element for the circuit
            let input_field = conversions::bytes_to_field::<G::ScalarField>(&input_data);

            // Create the step function input
            let step_input = StepFunctionInput {
                i: G::ScalarField::from(i as u64),
                z_i: vec![input_field],
            };

            leaves.push(step_input);
            
            tracing::debug!(
                target = LOG_TARGET,
                step = i,
                input_hash = input_data.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                output_hash = hash_result.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                "Finished step {i}"
            );
        }

        tracing::info!(target = LOG_TARGET, "⏱️  Created {} step function inputs", leaves.len());

        let cs = ConstraintSystem::<G::ScalarField>::new_ref();

        // Step 2: Create linearization parameters
        let circuit = SequentialSha256Circuit::<G::ScalarField>::new();
        let params = setup_linearization(cs, circuit)
            .map_err(|e| Sha256ChainError::SetupFailed(format!("Linearization setup failed: {:?}", e)))?;

        // Create the reducer with the newly created parameters
        // HypernovaFoldReducer requires references with 'static lifetime. To satisfy this without
        // leaking the *original* values, we clone `ck` and `ro_config`, box them, and leak the boxes.
        // This is safe for the duration of the program and avoids lifetime issues.

        let ck_static: &'static C::PolyCommitmentKey = Box::leak(Box::new(self.ck.clone()));
        let ro_static: &'static RO::Config = Box::leak(Box::new(self.ro_config.clone()));

        let reducer = Arc::new(HypernovaFoldReducer::<
            G,
            C,
            SequentialSha256Circuit<G::ScalarField>,
            RO,
        >::new(
            params,
            ck_static,
            ro_static,
        ));

        // Create the parallel tree folder with the reducer
        let folder = ParallelTreeFolder::new(reducer);

        let (lccs_instance, witness) = folder.run(leaves)?;

        // Step 4: Verify the final hash matches our native computation
        let final_hash = current_hash.unwrap();
        
        tracing::info!(
            target = LOG_TARGET,
            num_messages,
            final_hash = final_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            lccs_size = lccs_instance.X.len(),
            witness_size = witness.W.len(),
            "📊 SHA-256 chain folding results"
        );

        Ok(Sha256ChainResult {
            lccs_instance,
            witness,
            final_hash,
            num_messages,
        })
    }

    /// Get the number of worker threads
    pub fn num_workers(&self) -> usize {
        num_cpus::get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::zeromorph::Zeromorph;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_test_curves::bls12_381::{Bls12_381 as E, Fr as CF, G1Projective as G1};
    use std::sync::Once;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    };

    // Type aliases for test cases - using BLS12-381 test curve
    type TestPC = Zeromorph<E>;
    type TestRO = PoseidonSponge<CF>;
    type TestSha256ChainFolder = Sha256ChainFolder<G1, TestPC, TestRO>;

    const TEST_TARGET: &str = "nexus-nova";

    // Helper function to set up tracing for tests
    fn setup_test_tracing() {
        static INIT: Once = Once::new();
        
        INIT.call_once(|| {
            let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG);

            let subscriber = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                        .with_test_writer() // This ensures output goes to test stdout
                        .with_thread_ids(false) // Keep thread IDs for identification
                        .with_thread_names(true) // Turn off thread names to avoid excessive padding
                        .with_file(true)
                        .with_line_number(true)
                        .with_target(false)
                        .compact(), // Use compact formatting to reduce spacing
                )
                .with(filter);

            // Set as global default - this will be shared across all threads
            tracing::subscriber::set_global_default(subscriber)
                .expect("Failed to set global tracing subscriber");
                
            tracing::info!(target: TEST_TARGET, "🔧 Global tracing subscriber initialized");
        });
    }

    #[test]
    fn test_sha256_chain_folder_creation() {
        setup_test_tracing();
        tracing::info!(target = TEST_TARGET, "🧪 Testing SHA-256 chain folder creation");

        let folder = TestSha256ChainFolder::new().expect("Failed to create SHA-256 chain folder");
        
        // Verify that we have reasonable worker count
        assert!(folder.num_workers() > 0);
        
        tracing::info!(
            target = TEST_TARGET,
            workers = folder.num_workers(),
            "✅ SHA-256 chain folder creation test passed (workers: {})", folder.num_workers()
        );
    }

    #[test]
    fn test_sha256_chain_two_messages() {
        setup_test_tracing();
        tracing::info!(target = TEST_TARGET, "🧪 Testing SHA-256 chain with two messages");

        let folder = TestSha256ChainFolder::new().expect("Failed to create SHA-256 chain folder");
        
        // Test with two simple messages
        let messages = vec![
            b"hello".to_vec(),
            b"world".to_vec(),
        ];

        tracing::info!(target = TEST_TARGET, "📝 Processing {} messages", messages.len());

        let result = folder.run(messages).expect("Failed to process SHA-256 chain");

        // Verify results
        assert_eq!(result.num_messages, 2);
        assert_eq!(result.final_hash.len(), 32); // SHA-256 produces 32-byte hashes
        assert!(!result.lccs_instance.X.is_empty());
        assert!(!result.witness.W.is_empty());

        tracing::info!(
            target = TEST_TARGET,
            final_hash = result.final_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "✅ Two-message SHA-256 chain test passed"
        );
    }

    #[test]
    fn test_sha256_chain_four_messages() {
        setup_test_tracing();
        tracing::info!(target = TEST_TARGET, "🧪 Testing SHA-256 chain with four messages");

        let folder = TestSha256ChainFolder::new().expect("Failed to create SHA-256 chain folder");
        
        // Test with four messages
        let messages = vec![
            b"message 1".to_vec(),
            b"message 2".to_vec(),
            b"message 3".to_vec(),
            b"message 4".to_vec(),
        ];

        tracing::info!(target = TEST_TARGET, "📝 Processing {} messages", messages.len());

        let result = folder.run(messages).expect("Failed to process SHA-256 chain");

        // Verify results
        assert_eq!(result.num_messages, 4);
        assert_eq!(result.final_hash.len(), 32);
        assert!(!result.lccs_instance.X.is_empty());
        assert!(!result.witness.W.is_empty());

        tracing::info!(
            target = TEST_TARGET,
            final_hash = result.final_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "✅ Four-message SHA-256 chain test passed"
        );
    }

    #[test]
    fn test_sha256_chain_64_messages() {
        setup_test_tracing();
        tracing::info!(target = TEST_TARGET, "🧪 Testing SHA-256 chain with 64 messages (depth=6)");

        let folder = TestSha256ChainFolder::new().expect("Failed to create SHA-256 chain folder");
        
        // Generate 64 messages
        let messages: Vec<Vec<u8>> = (1..=64)
            .map(|i| format!("message_{:02}", i).into_bytes())
            .collect();

        tracing::info!(target = TEST_TARGET, "📝 Processing {} messages (tree depth: {})", 
            messages.len(), 
            (messages.len() as f64).log2() as usize
        );

        let start_time = std::time::Instant::now();
        let result = folder.run(messages).expect("Failed to process SHA-256 chain");
        let duration = start_time.elapsed();

        // Verify results
        assert_eq!(result.num_messages, 64);
        assert_eq!(result.final_hash.len(), 32); // SHA-256 produces 32-byte hashes
        assert!(!result.lccs_instance.X.is_empty());
        assert!(!result.witness.W.is_empty());

        tracing::info!(
            target = TEST_TARGET,
            duration_ms = duration.as_millis(),
            final_hash = result.final_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            lccs_size = result.lccs_instance.X.len(),
            witness_size = result.witness.W.len(),
            "✅ 64-message SHA-256 chain test completed in {}ms (final_hash: {final_hash})", 
            duration.as_millis(),
            final_hash = result.final_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        );
    }
} 