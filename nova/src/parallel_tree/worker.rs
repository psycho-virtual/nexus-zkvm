use crossbeam_queue::ArrayQueue;
use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::sync::Once;

use super::block_pool::{BlockPool, Payload};
use super::task::{Task, TaskHeap};
use crate::fold_reducer::FoldReducer;
use crate::parallel_tree::{BufHandle, BufId};

// -----------------------------------------------------------------------------
// Worker local state
// -----------------------------------------------------------------------------

pub const READY_Q_CAP: usize = 512;

// Tracing target for worker operations
const WORKER_TARGET: &str = "nexus-nova::parallel_tree::worker";

// Type aliases for the fold reducer
pub struct DummyStrictInst;
#[derive(Clone, Copy)]
pub struct DummyAccInst;
pub struct DummyFoldProof;

// Simple error type for worker operations
#[derive(Debug)]
pub enum WorkerError {
    TaskNotFound(usize),
    WrongTaskType(usize),
    ProcessingFailed(usize, String),
    BufferClaimFailed(usize),
    StateTransitionFailed(usize, String),
    FoldOperationFailed(usize, String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::TaskNotFound(idx) => write!(f, "Task not found at index {}", idx),
            WorkerError::WrongTaskType(idx) => write!(f, "Wrong task type at index {}", idx),
            WorkerError::ProcessingFailed(idx, msg) => write!(f, "Processing failed for task {}: {}", idx, msg),
            WorkerError::BufferClaimFailed(idx) => write!(f, "Buffer claim failed for task {}", idx),
            WorkerError::StateTransitionFailed(idx, msg) => write!(f, "State transition failed for task {}: {}", idx, msg),
            WorkerError::FoldOperationFailed(idx, msg) => write!(f, "Fold operation failed for task {}: {}", idx, msg),
        }
    }
}

impl std::error::Error for WorkerError {}



/// Trait that defines the associated types for worker parameters
pub trait WorkerParams {
    /// The type that represents leaf input data (must be a Payload)
    type LeafInput: Payload + Send + Sync + Clone + 'static;

    /// The type that represents internal node data (must be a Payload)
    type Inner: Payload + Send + Sync + 'static;

    /// The type that represents fold proofs
    type Proof: Send + Sync + 'static;

    /// The error type for folding operations
    type Error: Send + Sync + std::fmt::Debug + 'static;
}

pub struct WorkerLocal<P: WorkerParams> {
    pub id: usize,
    pub ready_q: Arc<ArrayQueue<usize>>, // Indices of ready parent nodes
    pub leaf_queue: Arc<ArrayQueue<(P::LeafInput, usize)>>, // (leaf_data, node_index) pairs
    pub task_heap: Arc<TaskHeap>,        // Shared heap of all tasks
    pub pool: Arc<BlockPool<P::Inner>>,
    pub reducer: Arc<
        dyn FoldReducer<
                2,
                StrictInst = P::LeafInput,
                AccInst = P::Inner,
                FoldProof = P::Proof,
                Error = P::Error,
            > + Send
            + Sync,
    >,
}

impl<P: WorkerParams> WorkerLocal<P> {
    /// Run the worker loop until the `stop` flag is set.
    #[tracing::instrument(skip_all, fields(worker_id = self.id), name = "worker_run", level = "info", target = WORKER_TARGET)]
    pub fn run(self, stop: Arc<AtomicUsize>) {
        // Pin to a dedicated core if available.
        if let Some(core_ids) = core_affinity::get_core_ids() {
            if let Some(core) = core_ids.get(self.id) {
                let _ = core_affinity::set_for_current(*core);
            }
        }

        // Main loop
        while stop.load(Ordering::Acquire) == 0 {
            // Priority 1 – ready tasks (tasks that are READY and need to be consumed)
            if let Some(task_idx) = self.ready_q.pop() {
                if let Err(err) = self.process_ready_inner_node(task_idx) {
                    tracing::error!(target: WORKER_TARGET,
                        "❌ Worker {}: Failed to process inner node {}: {}",
                        self.id, task_idx, err
                    );
                }
                continue;
            }

            // Priority 2 – leaf input processing
            if let Some((leaf_data, leaf_idx)) = self.leaf_queue.pop() {
                if let Err(err) = self.process_leaf_input(leaf_data, leaf_idx) {
                    tracing::error!(target: WORKER_TARGET,
                        "❌ Worker {}: Failed to process leaf {}: {}",
                        self.id, leaf_idx, err
                    );
                }
                continue;
            }

            // Yield – nothing to do right now.
            std::thread::yield_now();
        }
    }

    /// Process leaf input data to produce a result
    #[tracing::instrument(skip_all, fields(leaf_idx, worker_id = self.id), name = "process_leaf_input", level = "debug", target = WORKER_TARGET)]
    fn process_leaf_input(&self, leaf_data: P::LeafInput, leaf_idx: usize) -> Result<(), WorkerError> {
        // Get the task from the heap
        let task = self.task_heap.get(leaf_idx)
            .ok_or(WorkerError::TaskNotFound(leaf_idx))?;
        
        // Ensure it's a leaf task
        let leaf_task = match task {
            Task::Leaf(leaf_task) => leaf_task,
            _ => return Err(WorkerError::WrongTaskType(leaf_idx)),
        };

        // Allocate a buffer from the pool with back-pressure
        let handle = loop {
            if let Some(h) = self.pool.alloc() {
                break h;
            }
            // No block available - yield to let other workers make progress
            if self.pool.free_count() == 0 {
                std::thread::yield_now();
            }
        };

        let buf_id = handle.into_id();

        // Try to start processing this leaf with the allocated buffer
        if !leaf_task.try_start_processing(buf_id) {
            // Failed to start processing - release the buffer
            if let Some(release_handle) = self.pool.claim(buf_id) {
                release_handle.release();
            }
            return Err(WorkerError::ProcessingFailed(leaf_idx, "Failed to start processing".to_string()));
        }

        // Convert leaf input to accumulator using reducer with timing
        let acc = tracing::debug_span!(target: WORKER_TARGET, "strict_to_acc_conversion", leaf_idx)
            .in_scope(|| self.reducer.strict_to_acc(&leaf_data))
            .map_err(|err| {
                // Reset leaf task state back to NOT_STARTED on conversion failure
                leaf_task.state.store(super::task::leaf_state::NOT_STARTED, Ordering::Release);
                leaf_task.buffer_id.store(-1, Ordering::Release);
                
                // Release the buffer since conversion failed
                if let Some(release_handle) = self.pool.claim(buf_id) {
                    release_handle.release();
                }
                
                WorkerError::ProcessingFailed(leaf_idx, format!("strict_to_acc failed: {:?}", err))
            })?;

        // Claim the buffer to write to it
        let mut write_handle = self.pool.claim(buf_id)
            .ok_or(WorkerError::BufferClaimFailed(leaf_idx))?;
        
        write_handle.write(&acc);
        // Convert back to buf_id (this consumes write_handle but keeps buffer allocated)
        let final_buf_id = write_handle.into_id();
        assert_eq!(buf_id, final_buf_id); // Sanity check

        // Try to update task state to Ready
        if !leaf_task.try_set_ready() {
            // Release the buffer since we failed to set ready state
            if let Some(release_handle) = self.pool.claim(final_buf_id) {
                release_handle.release();
            }
            return Err(WorkerError::StateTransitionFailed(leaf_idx, "Failed to set ready state".to_string()));
        }

        tracing::debug!(target: WORKER_TARGET,
            "✅ Leaf {}: Successfully set to READY state",
            leaf_idx
        );

        // Notify parent that this child is ready
        // Only add to deque if both children are now ready
        if let Some(parent_idx) = TaskHeap::parent(leaf_idx) {
            if let Some(Task::Node(parent_node)) = self.task_heap.get(parent_idx) {
                if parent_node.notify_child_ready() {
                    // Both children are now ready, add parent to deque for processing
                    let _ = self.ready_q.push(parent_idx);
                    tracing::debug!(target: WORKER_TARGET,
                        "Leaf {}: Notified parent {} (both children ready)",
                        leaf_idx, parent_idx
                    );
                } else {
                    tracing::debug!(target: WORKER_TARGET,
                        "Leaf {}: Notified parent {} (waiting for sibling)",
                        leaf_idx, parent_idx
                    );
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(task_idx, worker_id = self.id), name = "start_consuming_task", level = "debug", target = WORKER_TARGET)]
    fn start_consuming_task_and_get_buf_handle(
        &self,
        task_idx: usize,
    ) -> Option<BufHandle<P::Inner>> {
        if let Some(task) = self.task_heap.get(task_idx) {
            match task {
                Task::Leaf(leaf_task) => {
                    // Get buffer ID first while still in READY state
                    if let Some(buf_id) = leaf_task.get_buf_id_if_ready() {
                        if leaf_task.try_start_consuming() {
                            // Get buffer handle after successfully starting consumption
                            if let Some(handle) = self.pool.claim(buf_id) {
                                tracing::debug!(target: WORKER_TARGET,
                                    "Leaf {}: Successfully started consuming", task_idx
                                );
                                tracing::debug!(target: WORKER_TARGET,
                                    "Leaf {}: Buffer id: {:?}", task_idx, buf_id
                                );
                                return Some(handle);
                            }
                        }
                    }
                }
                Task::Node(node_task) => {
                    // Get buffer ID first while still in READY state
                    if let Some(buf_id) = node_task.get_buf_id_if_ready() {
                        if node_task.try_start_consuming() {
                            // Get buffer handle after successfully starting consumption
                            if let Some(handle) = self.pool.claim(buf_id) {
                                tracing::debug!(target: WORKER_TARGET,
                                    "Node {}: Successfully started consuming", task_idx
                                );
                                tracing::debug!(target: WORKER_TARGET,
                                    "Node {}: Buffer id: {:?}", task_idx, buf_id
                                );
                                return Some(handle);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[tracing::instrument(skip_all, fields(inner_idx, worker_id = self.id, level = tracing::field::Empty, col = tracing::field::Empty), name = "process_ready_inner_node", level = "debug", target = WORKER_TARGET)]
    fn process_ready_inner_node(&self, inner_idx: usize) -> Result<(), WorkerError> {
        // Record level and column information in the span
        let span = tracing::Span::current();
        span.record("level", self.task_heap.level(inner_idx));
        span.record("col", self.task_heap.col(inner_idx));

        tracing::debug!(target: WORKER_TARGET,
            "🌳 Processing node at level {:?}, column {:?}",
            self.task_heap.level(inner_idx),
            self.task_heap.col(inner_idx)
        );

        // Get the task from the heap
        let task = self.task_heap.get(inner_idx)
            .ok_or(WorkerError::TaskNotFound(inner_idx))?;
        
        // Ensure it's a node task
        let node_task = match task {
            Task::Node(node_task) => node_task,
            _ => return Err(WorkerError::WrongTaskType(inner_idx)),
        };

        // Only process nodes that are in WAITING_BOTH_CHILDREN state (both children ready)
        let current_state = node_task.get_state();
        if current_state != super::task::node_state::WAITING_BOTH_CHILDREN {
            return Err(WorkerError::StateTransitionFailed(inner_idx, 
                format!("Node not in WAITING_BOTH_CHILDREN state (current: {})", current_state)));
        }

        tracing::debug!(target: WORKER_TARGET,
            "🔄 Inner {}: Processing ready inner node...",
            inner_idx
        );

        let left_idx = TaskHeap::left(inner_idx);
        let right_idx = TaskHeap::right(inner_idx);

        // Get buffer handles from children
        let left_handle = self.start_consuming_task_and_get_buf_handle(left_idx)
            .ok_or(WorkerError::BufferClaimFailed(left_idx))?;
        let right_handle = self.start_consuming_task_and_get_buf_handle(right_idx)
            .ok_or(WorkerError::BufferClaimFailed(right_idx))?;

        tracing::debug!(target: WORKER_TARGET,
            "Inner {}: Both children ready with buffer handles",
            inner_idx
        );

        // Read accumulators from buffers
        let acc_left: P::Inner = left_handle.read();
        let acc_right: P::Inner = right_handle.read();

        tracing::debug!(target: WORKER_TARGET,
            "Inner {}: Successfully read accumulator instances from buffers",
            inner_idx
        );

        // Build the children array
        let acc_children: [P::Inner; 2] = [acc_left, acc_right];

        // Fold the accumulators with timing
        tracing::debug!(target: WORKER_TARGET,
            "Inner {}: Starting fold_acc_acc operation...",
            inner_idx
        );

        let (parent_acc, _proof) = match tracing::debug_span!(target: WORKER_TARGET, "fold_acc_acc_operation", inner_idx)
            .in_scope(|| self.reducer.fold_acc_acc(&acc_children)) {
            Ok(result) => result,
            Err(err) => {
                // Release both buffers since folding failed
                left_handle.release();
                right_handle.release();
                return Err(WorkerError::FoldOperationFailed(inner_idx, format!("{:?}", err)));
            }
        };

        // Mark children as consumed and clear their buffer IDs
        Self::set_consumed_task(&self.task_heap, left_idx);
        Self::set_consumed_task(&self.task_heap, right_idx);
        self.task_heap.clear_buffer_id(left_idx);
        self.task_heap.clear_buffer_id(right_idx);

        // Reuse the left buffer for the result, free the right buffer
        let mut result_handle = left_handle;
        right_handle.release();

        // Write result to the reused buffer
        result_handle.write(&parent_acc);
        let result_buf_id = result_handle.into_id();

        // First transition to PROCESSING state
        if !node_task.try_start_processing(result_buf_id) {
            // Reset state back to WAITING_BOTH_CHILDREN and clear buffer
            node_task.state.store(
                super::task::node_state::WAITING_BOTH_CHILDREN,
                Ordering::Release,
            );

            // Release the buffer since we failed to start processing
            if let Some(release_handle) = self.pool.claim(result_buf_id) {
                release_handle.release();
            }
            return Err(WorkerError::StateTransitionFailed(inner_idx, "Failed to start processing".to_string()));
        }

        // Then transition to READY state
        if !node_task.try_set_ready() {
            // Reset processing state back to WAITING_BOTH_CHILDREN
            node_task.state.store(
                super::task::node_state::WAITING_BOTH_CHILDREN,
                Ordering::Release,
            );
            node_task.buffer_id.store(-1, Ordering::Release);

            // Release the buffer since we failed
            if let Some(release_handle) = self.pool.claim(result_buf_id) {
                release_handle.release();
            }
            return Err(WorkerError::StateTransitionFailed(inner_idx, "Failed to set ready state".to_string()));
        }

        tracing::debug!(target: WORKER_TARGET,
            "✅ Inner {}: Successfully set to READY state",
            inner_idx
        );

        // For non-root nodes, notify parent that this child is ready
        if let Some(parent_idx) = TaskHeap::parent(inner_idx) {
            if let Some(Task::Node(parent_node)) = self.task_heap.get(parent_idx) {
                if parent_node.notify_child_ready() {
                    // Both children are now ready, add parent to deque for processing
                    let _ = self.ready_q.push(parent_idx);
                    tracing::debug!(target: WORKER_TARGET,
                        "Added parent {} to ready queue (notified by inner {})",
                        parent_idx, inner_idx
                    );
                    tracing::debug!(target: WORKER_TARGET,
                        "Inner {}: Notified parent {} (both children ready)",
                        inner_idx, parent_idx
                    );
                } else {
                    tracing::debug!(target: WORKER_TARGET,
                        "Inner {}: Notified parent {} (waiting for sibling)",
                        inner_idx, parent_idx
                    );
                }
            }
        }

        // For root node, mark children as consumed but keep root in ready state
        // For non-root nodes, just stay in ready state until parent consumes them
        if inner_idx == 0 {
            // Root node: mark children as consumed but keep root in READY state
            Self::set_consumed_task(&self.task_heap, left_idx);
            Self::set_consumed_task(&self.task_heap, right_idx);

            tracing::debug!(target: WORKER_TARGET,
                "Root {}: Marked children [{}, {}] as consumed, keeping root in READY state",
                inner_idx, left_idx, right_idx
            );
        }
        // Note: Non-root nodes stay in READY state until their parent processes them

        Ok(())
    }

    #[inline]
    fn set_consumed_task(task_heap: &TaskHeap, task_idx: usize) {
        if let Some(task) = task_heap.get(task_idx) {
            match task {
                Task::Leaf(leaf) => {
                    leaf.try_set_consumed();
                }
                Task::Node(node) => {
                    node.try_set_consumed();
                }
            }
        }
    }
}

impl<P: WorkerParams> Debug for WorkerLocal<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Worker[{}] State:", self.id)?;

        // Show ready queue
        writeln!(f, "  Ready Queue (len={}):", self.ready_q.len())?;

        // Show leaf queue
        writeln!(f, "  Leaf Queue (len={}):", self.leaf_queue.len())?;

        // Show pool info
        writeln!(f, "  Pool: {} free buffers", self.pool.free_count())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tracing_subscriber::{
        fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
    };

    const TEST_TARGET: &str = "nexus-nova::parallel_tree::worker::tests";

    fn setup_test_tracing() {
        static INIT: Once = Once::new();
        
        INIT.call_once(|| {
            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    // Fallback to our specific targets if RUST_LOG is not set
                    EnvFilter::new("debug")
                        .add_directive(format!("{}=trace", TEST_TARGET).parse().unwrap())
                        .add_directive(format!("{}=trace", WORKER_TARGET).parse().unwrap())
                });

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

    // ---------------------------------------------------------------------
    // Test payload for worker tests
    // ---------------------------------------------------------------------

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LeafPayload(u32);

    impl Payload for LeafPayload {
        fn encode_into(&self, dst: &mut [u8]) -> usize {
            let bytes = self.0.to_le_bytes();
            dst[..4].copy_from_slice(&bytes);
            4
        }

        unsafe fn decode_from(src: &[u8]) -> Self {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&src[..4]);
            LeafPayload(u32::from_le_bytes(buf))
        }
    }

    struct SimpleReducer;

    impl FoldReducer<2> for SimpleReducer {
        type StrictInst = LeafPayload;
        type AccInst = LeafPayload;
        type FoldProof = ();
        type Error = ();

        fn fold_acc_acc(
            &self,
            acc_children: &[Self::AccInst; 2],
        ) -> Result<(Self::AccInst, Self::FoldProof), Self::Error> {
            // Sum the children
            let sum = acc_children[0].0 + acc_children[1].0;
            Ok((LeafPayload(sum), ()))
        }

        fn verify_step(&self, _parent: &Self::AccInst, _proof: &Self::FoldProof) -> bool {
            true
        }

        fn strict_to_acc(&self, strict: &Self::StrictInst) -> Result<Self::AccInst, Self::Error> {
            Ok(*strict)
        }
    }

    // Define WorkerParams for our test scenario
    struct TestWorkerParams;

    impl WorkerParams for TestWorkerParams {
        type LeafInput = LeafPayload;
        type Inner = LeafPayload;
        type Proof = ();
        type Error = ();
    }

    /// Helper function to check if all non-root nodes are consumed and root has the expected value
    fn check_processing_complete_with_expected_root_value(
        task_heap: &TaskHeap,
        pool: &BlockPool<LeafPayload>,
        expected_root_value: LeafPayload,
    ) -> bool {
        // Check if all non-root nodes are consumed
        let all_non_root_consumed = (1..task_heap.size()).all(|node_idx| {
            task_heap.get(node_idx).map_or(false, |task| match task {
                Task::Leaf(leaf) => {
                    leaf.get_state() == crate::parallel_tree::task::leaf_state::CONSUMED
                }
                Task::Node(node) => {
                    node.get_state() == crate::parallel_tree::task::node_state::CONSUMED
                }
            })
        });

        // Check if root has correct value and is in PROCESSED_WAITING_FOR_CONSUMPTION state
        let root_correct = task_heap.get(0).map_or(false, |task| match task {
            Task::Node(root_node) => {
                root_node.get_state()
                    == crate::parallel_tree::task::node_state::PROCESSED_WAITING_FOR_CONSUMPTION
                    && root_node
                        .get_buf_id_if_ready()
                        .and_then(|buf_id| pool.claim(buf_id))
                        .map_or(false, |handle| handle.read() == expected_root_value)
            }
            _ => false,
        });

        all_non_root_consumed && root_correct
    }

    /// Helper function to assert final state for test verification
    fn assert_final_processing_state(
        task_heap: &TaskHeap,
        pool: &BlockPool<LeafPayload>,
        expected_root_value: LeafPayload,
    ) {
        // Assert all non-root nodes are consumed
        for node_idx in 1..task_heap.size() {
            if let Some(task) = task_heap.get(node_idx) {
                match task {
                    Task::Leaf(leaf) => {
                        assert_eq!(
                            leaf.get_state(),
                            crate::parallel_tree::task::leaf_state::CONSUMED,
                            "Leaf at index {} should be consumed",
                            node_idx
                        );
                    }
                    Task::Node(node) => {
                        assert_eq!(
                            node.get_state(),
                            crate::parallel_tree::task::node_state::CONSUMED,
                            "Node at index {} should be consumed",
                            node_idx
                        );
                    }
                }
            }
        }

        // Assert root state and value
        if let Some(Task::Node(root_node)) = task_heap.get(0) {
            assert_eq!(
                root_node.get_state(),
                crate::parallel_tree::task::node_state::PROCESSED_WAITING_FOR_CONSUMPTION,
                "Root should be ready (not consumed)"
            );
            if let Some(buf_id) = root_node.get_buf_id_if_ready() {
                if let Some(handle) = pool.claim(buf_id) {
                    let acc = handle.read();
                    assert_eq!(
                        acc, expected_root_value,
                        "Root should have correct accumulated value"
                    );
                }
            }
        } else {
            panic!("Root should be a Node task");
        }
    }

    /// Polls until processing is complete with expected root value, with debug logging
    ///
    /// # Arguments
    /// * `task_heap` - The task heap to check
    /// * `pool` - The buffer pool for metrics
    /// * `ready_q` - Ready queue for metrics
    /// * `leaf_queue` - Leaf queue for metrics  
    /// * `expected_root_value` - Expected value in the root node
    /// * `timeout_iterations` - Maximum iterations before timeout
    /// * `debug_interval` - How often to log debug info
    ///
    /// # Returns
    /// * `true` if processing completed successfully within timeout
    /// * `false` if timeout was reached
    #[tracing::instrument(
        target = TEST_TARGET,
        level = "debug",
        skip_all,
        fields(
            expected_root_value = ?expected_root_value,
            timeout_iterations,
            debug_interval,
            task_heap_size = task_heap.size()
        ),
        name = "poll_until_processing_complete"
    )]
    fn poll_until_processing_complete(
        task_heap: &TaskHeap,
        pool: &BlockPool<LeafPayload>,
        ready_q: &ArrayQueue<usize>,
        leaf_queue: &ArrayQueue<(LeafPayload, usize)>,
        expected_root_value: LeafPayload,
        timeout_iterations: usize,
        debug_interval: usize,
    ) -> bool {
        for i in 0..timeout_iterations {
            // Debug logging at specified intervals
            if i % debug_interval == 0 {
                tracing::debug!(
                    target: TEST_TARGET,
                    iteration = i,
                    task_heap = ?&*task_heap,
                    ready_q_len = ready_q.len(),
                    leaf_q_len = leaf_queue.len(),
                    pool_free = pool.free_count(),
                    "Polling iteration status"
                );
            }

            // Check if processing is complete
            if check_processing_complete_with_expected_root_value(
                task_heap,
                pool,
                expected_root_value,
            ) {
                return true;
            }

            // Sleep before next iteration
            std::thread::sleep(Duration::from_millis(1));
        }

        false // Timeout reached
    }

    /// Simple polling function for basic conditions without debug logging
    fn poll_until_condition_simple<F>(condition_check: F, timeout_iterations: usize) -> bool
    where
        F: Fn() -> bool,
    {
        for _ in 0..timeout_iterations {
            if condition_check() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    #[test]
    #[tracing::instrument(target = TEST_TARGET, level = "info", name = "worker_processes_single_leaf")]
    fn worker_processes_single_leaf() {
        setup_test_tracing();
        tracing::info!(target: TEST_TARGET, "Starting worker_processes_single_leaf test");

        // Create a pool with 1 block
        let pool = Arc::new(BlockPool::<LeafPayload>::new(1).expect("pool creation failed"));

        // Create a task heap with 2 leaves (k=1)
        let task_heap = Arc::new(TaskHeap::new(1));

        // Channels/queues for the worker
        let ready_q: Arc<ArrayQueue<usize>> = Arc::new(ArrayQueue::new(READY_Q_CAP));
        let leaf_queue: Arc<ArrayQueue<(LeafPayload, usize)>> =
            Arc::new(ArrayQueue::new(READY_Q_CAP));

        // Push the leaf work to the leaf queue
        let leaf_idx = 1; // In a heap with k=1, leaf indices start at 1
        leaf_queue
            .push((LeafPayload(42), leaf_idx))
            .expect("push to leaf queue failed");

        let stop = Arc::new(AtomicUsize::new(0));

        // Create a debug worker to show state
        let reducer_arc: Arc<
            dyn FoldReducer<
                    2,
                    StrictInst = LeafPayload,
                    AccInst = LeafPayload,
                    FoldProof = (),
                    Error = (),
                > + Send
                + Sync,
        > = Arc::new(SimpleReducer);

        // Spawn worker.
        let worker_thread = {
            let ready_q_c = ready_q.clone();
            let leaf_q_c = leaf_queue.clone();
            let task_heap_c = task_heap.clone();
            let pool_c = pool.clone();
            let stop_c = stop.clone();
            
            std::thread::Builder::new()
                .name("test-worker-0".to_string()) // Name the thread for better tracing
                .spawn(move || {
                    tracing::info!(target: WORKER_TARGET, "🚀 Worker thread starting (single leaf test)");
                    
                    let worker = WorkerLocal::<TestWorkerParams> {
                        id: 0,
                        ready_q: ready_q_c,
                        leaf_queue: leaf_q_c,
                        task_heap: task_heap_c,
                        pool: pool_c,
                        reducer: reducer_arc,
                    };
                    
                    tracing::info!(target: WORKER_TARGET, "About to enter worker.run() loop");
                    worker.run(stop_c);
                    tracing::info!(target: WORKER_TARGET, "Worker.run() completed");
                })
                .expect("Failed to spawn worker thread")
        };

        // Wait until the worker processes the leaf (leaf should become ready)
        let processed = poll_until_condition_simple(
            || {
                task_heap.get(leaf_idx).map_or(false, |task| match task {
                    Task::Leaf(leaf_task) => {
                        leaf_task.get_state() == crate::parallel_tree::task::leaf_state::READY
                    }
                    _ => false,
                })
            },
            1000, // timeout_iterations
        );

        // Stop the worker and join the thread
        stop.store(1, Ordering::Release);
        worker_thread.join().expect("worker thread panicked");

        assert!(processed, "worker did not process leaf within timeout");

        // Verify the leaf is now in Ready state (not consumed, since no parent processed it)
        if let Some(Task::Leaf(leaf_task)) = task_heap.get(leaf_idx) {
            assert_eq!(
                leaf_task.get_state(),
                crate::parallel_tree::task::leaf_state::READY
            );
            // Also verify it has a buffer ID
            assert!(leaf_task.get_buf_id_if_ready().is_some());
        } else {
            panic!("Expected leaf task at index {}", leaf_idx);
        }
    }

    #[test]
    #[tracing::instrument(target = TEST_TARGET, level = "info", name = "worker_merges_two_leaves_into_parent")]
    fn worker_merges_two_leaves_into_parent() {
        setup_test_tracing();
        tracing::info!(target: TEST_TARGET, "Starting worker_merges_two_leaves_into_parent test");

        // Create a pool with 2 blocks
        let pool = Arc::new(BlockPool::<LeafPayload>::new(2).expect("pool creation failed"));

        // Create a task heap with 2 leaves (k=1)
        let task_heap = Arc::new(TaskHeap::new(1));

        // Set up indices
        let left_idx = 1;
        let right_idx = 2;

        // Channels/queues for the worker
        let ready_q: Arc<ArrayQueue<usize>> = Arc::new(ArrayQueue::new(READY_Q_CAP));
        let leaf_queue: Arc<ArrayQueue<(LeafPayload, usize)>> =
            Arc::new(ArrayQueue::new(READY_Q_CAP));

        // Push leaf work to the leaf queue (this is the new way)
        leaf_queue
            .push((LeafPayload(10), left_idx))
            .expect("push left leaf");
        leaf_queue
            .push((LeafPayload(20), right_idx))
            .expect("push right leaf");

        let stop = Arc::new(AtomicUsize::new(0));

        // Create a debug worker to show state
        let reducer_arc: Arc<
            dyn FoldReducer<
                    2,
                    StrictInst = LeafPayload,
                    AccInst = LeafPayload,
                    FoldProof = (),
                    Error = (),
                > + Send
                + Sync,
        > = Arc::new(SimpleReducer);

        // Spawn worker.
        let worker_thread = {
            let ready_q_c = ready_q.clone();
            let leaf_q_c = leaf_queue.clone();
            let task_heap_c = task_heap.clone();
            let pool_c = pool.clone();
            let stop_c = stop.clone();
            
            std::thread::Builder::new()
                .name("test-worker-1".to_string()) // Name the thread for better tracing
                .spawn(move || {
                    tracing::info!(target: WORKER_TARGET, "🚀 Worker thread starting (two leaves test)");
                    
                    let worker = WorkerLocal::<TestWorkerParams> {
                        id: 0,
                        ready_q: ready_q_c,
                        leaf_queue: leaf_q_c,
                        task_heap: task_heap_c,
                        pool: pool_c,
                        reducer: reducer_arc,
                    };
                    
                    tracing::info!(target: WORKER_TARGET, "About to enter worker.run() loop");
                    worker.run(stop_c);
                    tracing::info!(target: WORKER_TARGET, "Worker.run() completed");
                })
                .expect("Failed to spawn worker thread")
        };

        // Wait until all processing is complete
        let all_processed = poll_until_processing_complete(
            &task_heap,
            &pool,
            &ready_q,
            &leaf_queue,
            LeafPayload(30),
            1000, // timeout_iterations
            100,  // debug_interval
        );

        // Stop the worker and join the thread
        stop.store(1, Ordering::Release);
        worker_thread.join().expect("worker thread panicked");

        assert!(
            all_processed,
            "worker did not process all nodes correctly within timeout"
        );

        // Final verification: all non-root nodes should be consumed, root should be ready with correct value
        assert_final_processing_state(&task_heap, &pool, LeafPayload(30));
    }

    /// Enqueue four leaves and verify the worker merges them into the root accumulator.
    #[test]
    #[tracing::instrument(target = TEST_TARGET, level = "info", name = "worker_processes_four_leaves_into_root")]
    fn worker_processes_four_leaves_into_root() {
        setup_test_tracing();
        tracing::info!(target: TEST_TARGET, "Starting worker_processes_four_leaves_into_root test");

        // Pool: 8 blocks (4 logical cores) – sufficient for processing 4 leaves
        let pool = Arc::new(BlockPool::<LeafPayload>::new(4).expect("pool creation failed"));

        // Task heap with 4 leaves (k = 2) – 7 total nodes.
        let task_heap = Arc::new(TaskHeap::new(2));

        // Indices
        let leaf_start = task_heap.leaf_start(); // should be 3
        let leaves = [leaf_start, leaf_start + 1, leaf_start + 2, leaf_start + 3];

        // Queues for the worker.
        let ready_q: Arc<ArrayQueue<usize>> = Arc::new(ArrayQueue::new(READY_Q_CAP));
        let leaf_queue: Arc<ArrayQueue<(LeafPayload, usize)>> =
            Arc::new(ArrayQueue::new(READY_Q_CAP));

        // Push all leaf work to the leaf queue
        let leaf_values = [1u32, 2, 3, 4];
        for (idx, &val) in leaves.iter().zip(&leaf_values) {
            leaf_queue
                .push((LeafPayload(val), *idx))
                .expect("push leaf work");
        }

        let stop = Arc::new(AtomicUsize::new(0));

        // Spawn worker.
        let worker_thread = {
            let ready_q_c = ready_q.clone();
            let leaf_q_c = leaf_queue.clone();
            let task_heap_c = task_heap.clone();
            let pool_c = pool.clone();
            let stop_c = stop.clone();
            
            std::thread::Builder::new()
                .name("test-worker-2".to_string()) // Name the thread for better tracing
                .spawn(move || {
                    tracing::info!(target: WORKER_TARGET, "🚀 Worker thread starting (four leaves test)");
                    
                    let reducer_arc: Arc<
                        dyn FoldReducer<
                                2,
                                StrictInst = LeafPayload,
                                AccInst = LeafPayload,
                                FoldProof = (),
                                Error = (),
                            > + Send
                            + Sync,
                    > = Arc::new(SimpleReducer);

                    let worker = WorkerLocal::<TestWorkerParams> {
                        id: 0,
                        ready_q: ready_q_c,
                        leaf_queue: leaf_q_c,
                        task_heap: task_heap_c,
                        pool: pool_c,
                        reducer: reducer_arc,
                    };
                    
                    tracing::info!(target: WORKER_TARGET, "About to enter worker.run() loop");
                    worker.run(stop_c);
                    tracing::info!(target: WORKER_TARGET, "Worker.run() completed");
                })
                .expect("Failed to spawn worker thread")
        };

        // Wait until all processing is complete
        let all_processed = poll_until_processing_complete(
            &task_heap,
            &pool,
            &ready_q,
            &leaf_queue,
            LeafPayload(10),
            2000, // timeout_iterations
            200,  // debug_interval
        );

        // Stop worker.
        stop.store(1, Ordering::Release);
        worker_thread.join().expect("worker thread panic");

        assert!(
            all_processed,
            "not all nodes processed correctly within timeout"
        );

        // Final verification: all non-root nodes should be consumed, root should be ready with correct value
        assert_final_processing_state(&task_heap, &pool, LeafPayload(10));
    }

    #[test]
    fn test_tracing_across_threads() {
        setup_test_tracing();
        
        tracing::info!(target: TEST_TARGET, "📧 Main thread log");
        
        let handle = std::thread::Builder::new()
            .name("tracing-test-thread".to_string())
            .spawn(|| {
                tracing::info!(target: TEST_TARGET, "🧵 Child thread log");
                std::thread::sleep(Duration::from_millis(10));
                tracing::info!(target: TEST_TARGET, "🧵 Child thread log after delay");
            })
            .expect("Failed to spawn test thread");
        
        handle.join().unwrap();
        tracing::info!(target: TEST_TARGET, "📧 Back in main thread");
    }
}
