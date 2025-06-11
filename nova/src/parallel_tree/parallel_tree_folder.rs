use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::block_pool::BlockPool;
use super::scheduler::Scheduler;
use crate::fold_reducer::FoldReducer;

/// A convenient wrapper for running parallel tree fold operations
///
/// This struct abstracts away the complexity of setting up the scheduler,
/// leaf producer, and worker coordination, providing a simple API for
/// parallel tree computations.
pub struct ParallelTreeFolder<L, P, Proof, Error>
where
    L: Send + Sync + Clone + 'static,
    P: Send + Sync + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + std::fmt::Debug + 'static,
{
    depth: usize,
    reducer: Arc<
        dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error>
            + Send
            + Sync,
    >,
    num_workers: usize,
    pool_size: usize,
}

impl<L, P, Proof, Error> ParallelTreeFolder<L, P, Proof, Error>
where
    L: Send + Sync + Clone + 'static,
    P: Send + Sync + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + std::fmt::Debug + 'static,
{
    /// Create a new ParallelTreeFolder
    ///
    /// # Arguments
    /// * `depth` - The depth of the binary tree (2^depth leaf nodes)
    /// * `fold_reducer` - The reducer implementing the fold operations
    ///
    /// # Returns
    /// A new ParallelTreeFolder configured for the specified depth and reducer
    pub fn new(
        depth: usize,
        fold_reducer: Arc<
            dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error>
                + Send
                + Sync,
        >,
    ) -> Self {
        let num_workers = num_cpus::get();
        let num_leaves = 1 << depth; // 2^depth
        let pool_size = (num_workers * 4).max(num_leaves); // Ensure enough buffers

        Self {
            depth,
            reducer: fold_reducer,
            num_workers,
            pool_size,
        }
    }

    /// Create a new ParallelTreeFolder with custom worker count
    ///
    /// # Arguments
    /// * `depth` - The depth of the binary tree (2^depth leaf nodes)
    /// * `fold_reducer` - The reducer implementing the fold operations
    /// * `num_workers` - Number of worker threads to use
    ///
    /// # Returns
    /// A new ParallelTreeFolder configured for the specified parameters
    pub fn with_workers(
        depth: usize,
        fold_reducer: Arc<
            dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error>
                + Send
                + Sync,
        >,
        num_workers: usize,
    ) -> Self {
        let num_leaves = 1 << depth; // 2^depth
        let pool_size = (num_workers * 4).max(num_leaves); // Ensure enough buffers

        Self {
            depth,
            reducer: fold_reducer,
            num_workers,
            pool_size,
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
    /// let folder = ParallelTreeFolder::new(2, reducer);
    /// let leaves = vec![1, 2, 3, 4];
    /// let result = folder.run(leaves).expect("Computation failed");
    /// ```
    pub fn run<I>(&self, leaves: I) -> Result<P, ParallelTreeError>
    where
        I: IntoIterator<Item = L>,
        I::IntoIter: Send + 'static,
    {
        // Create the buffer pool
        let pool = Arc::new(
            BlockPool::<P>::new(self.pool_size)
                .map_err(|_| ParallelTreeError::PoolCreationFailed)?,
        );

        // Create the scheduler with workers
        let scheduler = Scheduler::<L, P, Proof, Error>::with_workers(
            pool.clone(),
            self.depth,
            self.reducer.clone(),
            self.num_workers,
        );

        // Convert the iterator to a boxed iterator
        let leaf_stream = Box::new(leaves.into_iter());

        // Spawn the leaf producer
        scheduler.spawn_leaf_producer(leaf_stream);

        // Wait for computation to complete
        let timeout_iterations = 10000; // 10 seconds at 1ms intervals
        let mut complete = false;

        for _ in 0..timeout_iterations {
            if scheduler.is_computation_complete() {
                complete = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        if !complete {
            scheduler.stop();
            return Err(ParallelTreeError::ComputationTimeout);
        }

        // Get the result from the root
        let result = scheduler
            .get_root_result()
            .ok_or(ParallelTreeError::NoRootResult)?;

        // Clean shutdown
        scheduler.stop();

        Ok(result)
    }

    /// Get the expected number of leaf nodes for this folder
    pub fn num_leaves(&self) -> usize {
        1 << self.depth
    }

    /// Get the number of worker threads
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
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
}

impl std::fmt::Display for ParallelTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParallelTreeError::PoolCreationFailed => write!(f, "Failed to create buffer pool"),
            ParallelTreeError::ComputationTimeout => write!(f, "Computation timed out"),
            ParallelTreeError::NoRootResult => write!(f, "No result available from root node"),
        }
    }
}

impl std::error::Error for ParallelTreeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold_reducer::FoldReducer;

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
        let folder = ParallelTreeFolder::new(2, reducer); // 4 leaves

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
        let folder = ParallelTreeFolder::with_workers(1, reducer, 2); // 2 leaves, 2 workers

        let leaves = vec![TestPayload(5), TestPayload(7)];
        let result = folder.run(leaves).expect("Computation should succeed");

        assert_eq!(result, TestPayload(12)); // 5 + 7 = 12
    }

    #[test]
    fn test_folder_properties() {
        let reducer = Arc::new(SumReducer);
        let folder = ParallelTreeFolder::with_workers(3, reducer, 4);

        assert_eq!(folder.depth(), 3);
        assert_eq!(folder.num_leaves(), 8); // 2^3
        assert_eq!(folder.num_workers(), 4);
    }

    #[test]
    fn test_parallel_tree_folder_large_scale() {
        let reducer = Arc::new(SumReducer);
        let folder = ParallelTreeFolder::new(10, reducer); // 2^10 = 1024 leaves

        // Create 1024 leaf values (1, 2, 3, ..., 1024)
        let leaves: Vec<TestPayload> = (1..=1024).map(TestPayload).collect();

        // Expected sum: 1 + 2 + 3 + ... + 1024 = 1024 * 1025 / 2 = 524800
        let expected_sum = 1024 * 1025 / 2;

        println!(
            "Starting large-scale computation with {} leaves",
            leaves.len()
        );
        println!("Expected sum: {}", expected_sum);
        println!("Using {} worker threads", folder.num_workers());

        let start_time = std::time::Instant::now();
        let result = folder
            .run(leaves)
            .expect("Large-scale computation should succeed");
        let duration = start_time.elapsed();

        println!("Computation completed in {:?}", duration);
        println!("Actual result: {}", result.0);

        assert_eq!(result, TestPayload(expected_sum as u32));
    }

    #[test]
    fn test_parallel_tree_folder_stress_test() {
        let reducer = Arc::new(SumReducer);
        // Use fewer workers to stress test the coordination
        let folder = ParallelTreeFolder::with_workers(8, reducer, 2); // 2^8 = 256 leaves, 2 workers

        // Create 256 leaf values with larger numbers to test overflow handling
        let leaves: Vec<TestPayload> = (1..=256).map(|i| TestPayload(i * 100)).collect();

        // Expected sum: 100 * (1 + 2 + ... + 256) = 100 * 256 * 257 / 2 = 3,283,200
        let expected_sum = 100 * 256 * 257 / 2;

        println!(
            "Starting stress test with {} leaves and {} workers",
            folder.num_leaves(),
            folder.num_workers()
        );

        let result = folder
            .run(leaves)
            .expect("Stress test computation should succeed");

        assert_eq!(result, TestPayload(expected_sum as u32));
    }
}
