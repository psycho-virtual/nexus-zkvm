use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::fmt::Debug;
use tracing::instrument;

use super::block_pool::BlockPool;
use super::scheduler::Scheduler;
use crate::fold_reducer::FoldReducer;

const LOG_TARGET: &str = "nexus-nova::parallel_tree::parallel_tree_folder";

/// A convenient wrapper for running parallel tree fold operations
///
/// This struct abstracts away the complexity of setting up the scheduler,
/// leaf producer, and worker coordination, providing a simple API for
/// parallel tree computations.
pub struct ParallelTreeFolder<L, P, Proof, Error>
where
    L: Send + Sync + Clone + Debug + 'static,
    P: Send + Sync + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + Debug + 'static,
{
    reducer: Arc<
        dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error>
            + Send
            + Sync,
    >,
    num_workers: usize,
}

impl<L, P, Proof, Error> ParallelTreeFolder<L, P, Proof, Error>
where
    L: Send + Sync + Clone + Debug + 'static,
    P: Send + Sync + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + Debug + 'static,
{
    /// Create a new ParallelTreeFolder
    ///
    /// # Arguments
    /// * `fold_reducer` - The reducer implementing the fold operations
    ///
    /// # Returns
    /// A new ParallelTreeFolder configured with the default number of workers
    pub fn new(
        fold_reducer: Arc<
            dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error>
                + Send
                + Sync,
        >,
    ) -> Self {
        Self::with_workers(fold_reducer, num_cpus::get())
    }

    /// Create a new ParallelTreeFolder with custom worker count
    ///
    /// # Arguments
    /// * `fold_reducer` - The reducer implementing the fold operations
    /// * `num_workers` - Number of worker threads to use
    ///
    /// # Returns
    /// A new ParallelTreeFolder configured for the specified parameters
    pub fn with_workers(
        fold_reducer: Arc<
            dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error>
                + Send
                + Sync,
        >,
        num_workers: usize,
    ) -> Self {
        Self {
            reducer: fold_reducer,
            num_workers,
        }
    }

    /// Run the parallel tree fold operation
    ///
    /// # Arguments
    /// * `leaves` - An iterator of leaf values to process
    ///
    /// # Returns
    /// * `Ok(result)` - The computed result from the root of the tree
    /// * `Err(error)` - If the computation failed or timed out
    ///
    /// # Example
    /// ```ignore
    /// let folder = ParallelTreeFolder::new(reducer);
    /// let leaves = vec![1, 2, 3, 4];
    /// let result = folder.run(leaves).expect("Computation failed");
    /// ```
    pub fn run<I>(&self, leaves: I) -> Result<P, ParallelTreeError>
    where
        I: IntoIterator<Item = L>,
        I::IntoIter: Send + 'static,
    {
        // Collect leaves to calculate the depth
        let leaves_vec: Vec<L> = leaves.into_iter().collect();
        let num_leaves = leaves_vec.len();
        
        // Validate that number of leaves is a power of 2 and non-zero
        if num_leaves == 0 {
            return Err(ParallelTreeError::InvalidInput("Number of leaves cannot be zero".to_string()));
        }
        if !num_leaves.is_power_of_two() {
            return Err(ParallelTreeError::InvalidInput(
                format!("Number of leaves must be a power of 2, got {}", num_leaves)
            ));
        }
        
        // Calculate depth: depth = log2(num_leaves)
        let depth = (num_leaves as f64).log2() as usize;
        let pool_size = (self.num_workers * 4); // Ensure enough buffers
        
        let span = tracing::info_span!(target: LOG_TARGET, "run", 
            depth = depth, 
            num_workers = self.num_workers, 
            pool_size = pool_size,
            num_leaves = num_leaves
        );
        let _enter = span.enter();
        
        tracing::info!(target = LOG_TARGET, "🚀 Starting parallel tree fold operation");
        
        tracing::info!(target = LOG_TARGET, "📦 Creating buffer pool with size {}", pool_size);
        // Create the buffer pool
        let pool = Arc::new(
            BlockPool::<P>::new(pool_size)
                .map_err(|_| ParallelTreeError::PoolCreationFailed)?,
        );

        tracing::info!(target = LOG_TARGET, "✅ Created buffer pool successfully");

        tracing::info!(target = LOG_TARGET, "⚙️  Creating scheduler with {} workers", self.num_workers);
        // Create the scheduler with workers
        let scheduler = Scheduler::<L, P, Proof, Error>::with_workers(
            pool.clone(),
            depth,
            self.reducer.clone(),
            self.num_workers,
        );

        tracing::info!(target = LOG_TARGET, "✅ Created scheduler successfully");

        // Convert the vector back to a boxed iterator
        let leaf_stream = Box::new(leaves_vec.into_iter());

        tracing::info!(target = LOG_TARGET, "Spawning leaf producer");
        // Spawn the leaf producer
        scheduler.spawn_leaf_producer(leaf_stream);

        // Wait for computation to complete
        let start_time = std::time::Instant::now();
        let mut last_log_time = start_time;
        
        while !scheduler.is_computation_complete() {
            // Log status every 10 seconds
            let now = std::time::Instant::now();
            if now.duration_since(last_log_time) >= Duration::from_secs(10) {
                tracing::debug!(target = LOG_TARGET, 
                    "Still waiting for computation to complete after {} seconds", 
                    now.duration_since(start_time).as_secs()
                );
                last_log_time = now;
            }
            
            thread::sleep(Duration::from_millis(10));
        }

        // Get the result from the root
        let result = scheduler
            .get_root_result()
            .ok_or(ParallelTreeError::NoRootResult)?;

        // Clean shutdown
        scheduler.stop();

        Ok(result)
    }

    /// Get the number of worker threads
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }
}

/// Errors that can occur during parallel tree folding
#[derive(Debug)]
pub enum ParallelTreeError {
    /// Failed to create the buffer pool
    PoolCreationFailed,
    /// Computation did not complete within the timeout
    ComputationTimeout,
    /// No result available from the root node
    NoRootResult,
    /// Invalid input
    InvalidInput(String),
}

impl std::fmt::Display for ParallelTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParallelTreeError::PoolCreationFailed => write!(f, "Failed to create buffer pool"),
            ParallelTreeError::ComputationTimeout => write!(f, "Computation timed out"),
            ParallelTreeError::NoRootResult => write!(f, "No result available from root node"),
            ParallelTreeError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for ParallelTreeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold_reducer::FoldReducer;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    const TEST_TARGET: &str = "nexus-nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG)
            .with_target(LOG_TARGET, tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    // Test payload
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestPayload(u32);

    // Simple sum reducer for testing
    struct SumReducer;

    impl FoldReducer<2> for SumReducer {
        type StrictInst = TestPayload;
        type AccInst = TestPayload;
        type FoldProof = ();
        type Error = ();

        fn fold_acc_acc(
            &self,
            acc_children: &[Self::AccInst; 2],
        ) -> Result<(Self::AccInst, Self::FoldProof), Self::Error> {
            let sum = acc_children[0].0 + acc_children[1].0;
            Ok((TestPayload(sum), ()))
        }

        fn verify_step(&self, _parent: &Self::AccInst, _proof: &Self::FoldProof) -> bool {
            true
        }

        fn strict_to_acc(&self, strict: &Self::StrictInst) -> Result<Self::AccInst, Self::Error> {
            Ok(*strict)
        }
    }

    #[test]
    fn test_parallel_tree_folder_basic() {
        let reducer = Arc::new(SumReducer);
        let folder = ParallelTreeFolder::new(reducer);

        let leaves = vec![
            TestPayload(1),
            TestPayload(2),
            TestPayload(3),
            TestPayload(4),
        ];
        let result = folder.run(leaves).expect("Computation should succeed");

        assert_eq!(result, TestPayload(10)); // 1 + 2 + 3 + 4 = 10
    }

    #[test]
    fn test_parallel_tree_folder_with_workers() {
        let reducer = Arc::new(SumReducer);
        let folder = ParallelTreeFolder::with_workers(reducer, 2);

        let leaves = vec![TestPayload(5), TestPayload(7)];
        let result = folder.run(leaves).expect("Computation should succeed");

        assert_eq!(result, TestPayload(12)); // 5 + 7 = 12
    }

    #[test]
    fn test_folder_properties() {
        let reducer = Arc::new(SumReducer);
        let folder = ParallelTreeFolder::with_workers(reducer, 4);

        assert_eq!(folder.num_workers(), 4);
    }

    #[test]
    fn test_parallel_tree_folder_large_scale() {
        let _guard = setup_test_tracing();
        
        let reducer = Arc::new(SumReducer);
        let folder = ParallelTreeFolder::new(reducer);

        // Create 1024 leaf values (1, 2, 3, ..., 1024)
        let leaves: Vec<TestPayload> = (1..=1024).map(TestPayload).collect();

        // Expected sum: 1 + 2 + 3 + ... + 1024 = 1024 * 1025 / 2 = 524800
        let expected_sum = 1024 * 1025 / 2;

        tracing::info!(target = TEST_TARGET,
            "Starting large-scale computation with {} leaves",
            leaves.len()
        );
        tracing::info!(target = TEST_TARGET, "Expected sum: {}", expected_sum);
        tracing::info!(target = TEST_TARGET, "Using {} worker threads", folder.num_workers());

        let start_time = std::time::Instant::now();
        let result = folder
            .run(leaves)
            .expect("Large-scale computation should succeed");
        let duration = start_time.elapsed();

        tracing::info!(target = TEST_TARGET, "Computation completed in {:?}", duration);
        tracing::info!(target = TEST_TARGET, "Actual result: {}", result.0);

        assert_eq!(result, TestPayload(expected_sum as u32));
    }

    #[test]
    fn test_parallel_tree_folder_stress_test() {
        let _guard = setup_test_tracing();
        
        let reducer = Arc::new(SumReducer);
        // Use fewer workers to stress test the coordination
        let folder = ParallelTreeFolder::with_workers(reducer, 2);

        // Create 256 leaf values with larger numbers to test overflow handling
        let leaves: Vec<TestPayload> = (1..=256).map(|i| TestPayload(i * 100)).collect();

        // Expected sum: 100 * (1 + 2 + ... + 256) = 100 * 256 * 257 / 2 = 3,283,200
        let expected_sum = 100 * 256 * 257 / 2;

        tracing::info!(target = TEST_TARGET,
            "Starting stress test with {} leaves and {} workers",
            256,
            folder.num_workers()
        );

        let result = folder
            .run(leaves)
            .expect("Stress test computation should succeed");

        assert_eq!(result, TestPayload(expected_sum as u32));
    }
}
