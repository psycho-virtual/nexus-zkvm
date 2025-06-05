use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crossbeam_deque::{Stealer, Worker as DequeWorker};
use crossbeam_queue::ArrayQueue;

use super::block_pool::{BlockPool, Payload};
use super::task::{Task, TaskHeap};
use crate::fold_reducer::FoldReducer;
use crate::parallel_tree::{BufHandle, BufId};

// -----------------------------------------------------------------------------
// Worker local state
// -----------------------------------------------------------------------------

pub const READY_Q_CAP: usize = 512;

// Tracing target for worker operations
const WORKER_TARGET: &str = "worker";

// Type aliases for the fold reducer
pub struct DummyStrictInst;
#[derive(Clone, Copy)]
pub struct DummyAccInst;
pub struct DummyFoldProof;

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
                self.process_ready_inner_node(task_idx);
                continue;
            }

            // Priority 2 – leaf input processing
            if let Some((leaf_data, leaf_idx)) = self.leaf_queue.pop() {
                self.process_leaf_input(leaf_data, leaf_idx);
                continue;
            }

            // Yield – nothing to do right now.
            std::thread::yield_now();
        }
    }

    /// Process leaf input data to produce a result
    #[inline]
    fn process_leaf_input(&self, leaf_data: P::LeafInput, leaf_idx: usize) {
        if let Some(task) = self.task_heap.get(leaf_idx) {
            if let Task::Leaf(leaf_task) = task {
                tracing::debug!(target: WORKER_TARGET,
                    "🌱 Leaf {}: Processing strict instance to accumulator...",
                    leaf_idx
                );

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

                tracing::debug!(target: WORKER_TARGET,
                    "Leaf {}: Allocated buffer, starting strict_to_acc conversion...",
                    leaf_idx
                );

                let buf_id = handle.into_id(); // TODO: issue is that the handle is being reused here

                // Try to start processing this leaf with the allocated buffer
                if leaf_task.try_start_processing(buf_id) {
                    // Convert leaf input to accumulator using reducer with timing
                    let convert_start = Instant::now();
                    let convert_result = self.reducer.strict_to_acc(&leaf_data);
                    let convert_time = convert_start.elapsed();

                    match convert_result {
                        Ok(acc) => {
                            tracing::debug!(target: WORKER_TARGET,
                                "✅ Leaf {}: strict_to_acc completed successfully in {:?}",
                                leaf_idx, convert_time
                            );

                            // Claim the buffer to write to it
                            if let Some(mut write_handle) = self.pool.claim(buf_id) {
                                write_handle.write(&acc);
                                // Convert back to buf_id (this consumes write_handle but keeps buffer allocated)
                                let final_buf_id = write_handle.into_id();
                                assert_eq!(buf_id, final_buf_id); // Sanity check

                                // Try to update task state to Ready
                                if leaf_task.try_set_ready() {
                                    tracing::debug!(target: WORKER_TARGET,
                                        "✅ Leaf {}: Successfully set to READY state",
                                        leaf_idx
                                    );

                                    // Notify parent that this child is ready
                                    // Only add to deque if both children are now ready
                                    if let Some(parent_idx) = TaskHeap::parent(leaf_idx) {
                                        if let Some(Task::Node(parent_node)) =
                                            self.task_heap.get(parent_idx)
                                        {
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
                                } else {
                                    tracing::warn!(target: WORKER_TARGET,
                                        "❌ Leaf {}: Failed to set ready state",
                                        leaf_idx
                                    );

                                    // Release the buffer since we failed to set ready state
                                    if let Some(release_handle) = self.pool.claim(final_buf_id) {
                                        release_handle.release();
                                    }
                                }
                            } else {
                                tracing::error!(target: WORKER_TARGET,
                                    "❌ Leaf {}: Failed to claim buffer for writing",
                                    leaf_idx
                                );
                                return;
                            }
                        }
                        Err(err) => {
                            tracing::error!(target: WORKER_TARGET,
                                "❌ Leaf {}: strict_to_acc failed in {:?}: {:?}",
                                leaf_idx, convert_time, err
                            );

                            // Reset leaf task state back to NOT_STARTED
                            leaf_task
                                .state
                                .store(super::task::leaf_state::NOT_STARTED, Ordering::Release);
                            leaf_task.buffer_id.store(-1, Ordering::Release);

                            // Release the buffer since conversion failed
                            if let Some(release_handle) = self.pool.claim(buf_id) {
                                release_handle.release();
                            }

                            // Inform scheduler by panicking - this will make the whole program fail
                            panic!("Leaf processing failed for leaf {}: {:?}", leaf_idx, err);
                        }
                    }
                } else {
                    tracing::warn!(target: WORKER_TARGET,
                        "❌ Leaf {}: Failed to start processing",
                        leaf_idx
                    );
                    // Failed to start processing - release the buffer
                    if let Some(release_handle) = self.pool.claim(buf_id) {
                        release_handle.release();
                    }
                }
            }
        }
    }

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

    #[inline]
    fn process_ready_inner_node(&self, inner_idx: usize) {
        println!("DEBUG: Processing ready inner node {}", inner_idx);
        if let Some(task) = self.task_heap.get(inner_idx) {
            if let Task::Node(node_task) = task {
                println!("DEBUG: Node {} state: {}", inner_idx, node_task.get_state());
                // Only process nodes that are in WAITING_BOTH_CHILDREN state (both children ready)
                if node_task.get_state() == super::task::node_state::WAITING_BOTH_CHILDREN {
                    tracing::debug!(target: WORKER_TARGET,
                        "🔄 Inner {}: Processing ready inner node...",
                        inner_idx
                    );

                    let left_idx = TaskHeap::left(inner_idx);
                    let right_idx = TaskHeap::right(inner_idx);

                    // Get buffer handles from children
                    let left_handle = self.start_consuming_task_and_get_buf_handle(left_idx);
                    let right_handle = self.start_consuming_task_and_get_buf_handle(right_idx);

                    if let (Some(left_handle), Some(right_handle)) = (left_handle, right_handle) {
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

                        let fold_start = Instant::now();
                        let fold_result = self.reducer.fold_acc_acc(&acc_children);
                        let fold_time = fold_start.elapsed();

                        match fold_result {
                            Ok((parent_acc, _proof)) => {
                                tracing::debug!(target: WORKER_TARGET,
                                    "✅ Inner {}: fold_acc_acc completed successfully in {:?}",
                                    inner_idx, fold_time
                                );

                                // TODO: We have to set consuming for the left child and the right child. We also should deallocate the buf_id that they contain as well in the task heap elements that they are in
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
                                if node_task.try_start_processing(result_buf_id) {
                                    // Then transition to READY state
                                    if node_task.try_set_ready() {
                                        println!(
                                            "DEBUG: Node {} successfully set to ready state",
                                            inner_idx
                                        );
                                        tracing::debug!(target: WORKER_TARGET,
                                            "✅ Inner {}: Successfully set to READY state",
                                            inner_idx
                                        );

                                        // For non-root nodes, notify parent that this child is ready
                                        if let Some(parent_idx) = TaskHeap::parent(inner_idx) {
                                            if let Some(Task::Node(parent_node)) =
                                                self.task_heap.get(parent_idx)
                                            {
                                                if parent_node.notify_child_ready() {
                                                    // Both children are now ready, add parent to deque for processing
                                                    let _ = self.ready_q.push(parent_idx);
                                                    println!("DEBUG: Added parent {} to ready queue (notified by inner {})", parent_idx, inner_idx);
                                                    tracing::debug!(target: WORKER_TARGET,
                                                        "Inner {}: Notified parent {} (both children ready)",
                                                        inner_idx, parent_idx
                                                    );
                                                } else {
                                                    println!("DEBUG: Notified parent {} but still waiting for sibling (notified by inner {})", parent_idx, inner_idx);
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
                                    } else {
                                        tracing::error!(target: WORKER_TARGET,
                                            "❌ Inner {}: Failed to set ready state",
                                            inner_idx
                                        );

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
                                    }
                                } else {
                                    tracing::error!(target: WORKER_TARGET,
                                        "❌ Inner {}: Failed to start processing",
                                        inner_idx
                                    );

                                    // Reset state back to WAITING_BOTH_CHILDREN and clear buffer
                                    node_task.state.store(
                                        super::task::node_state::WAITING_BOTH_CHILDREN,
                                        Ordering::Release,
                                    );

                                    // Release the buffer since we failed to start processing
                                    if let Some(release_handle) = self.pool.claim(result_buf_id) {
                                        release_handle.release();
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::error!(target: WORKER_TARGET,
                                    "❌ Inner {}: fold_acc_acc failed in {:?}: {:?}",
                                    inner_idx, fold_time, err
                                );

                                // Release both buffers since folding failed - use original handles
                                left_handle.release();
                                right_handle.release();
                            }
                        }
                    } else {
                        tracing::debug!(target: WORKER_TARGET,
                            "Inner {}: Children not ready or failed to start consuming",
                            inner_idx
                        );
                    }
                } else {
                    tracing::debug!(target: WORKER_TARGET,
                        "Inner {}: Node not in WAITING_BOTH_CHILDREN state (state: {}), skipping",
                        inner_idx, node_task.get_state()
                    );
                }
            } else {
                tracing::warn!(target: WORKER_TARGET,
                    "❌ Inner {}: Expected node task, found leaf task",
                    inner_idx
                );
            }
        } else {
            tracing::warn!(target: WORKER_TARGET,
                "❌ Inner {}: Task not found in heap",
                inner_idx
            );
        }
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
    use std::thread;
    use std::time::Duration;

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

    #[test]
    fn worker_processes_single_leaf() {
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

        let debug_worker = WorkerLocal::<TestWorkerParams> {
            id: 999, // Debug worker ID
            ready_q: ready_q.clone(),
            leaf_queue: leaf_queue.clone(),
            task_heap: task_heap.clone(),
            pool: pool.clone(),
            reducer: reducer_arc.clone(),
        };

        // Spawn worker.
        let worker_thread = {
            let ready_q_c = ready_q.clone();
            let leaf_q_c = leaf_queue.clone();
            let task_heap_c = task_heap.clone();
            let pool_c = pool.clone();
            let stop_c = stop.clone();
            std::thread::spawn(move || {
                let worker = WorkerLocal::<TestWorkerParams> {
                    id: 0,
                    ready_q: ready_q_c,
                    leaf_queue: leaf_q_c,
                    task_heap: task_heap_c,
                    pool: pool_c,
                    reducer: reducer_arc,
                };
                worker.run(stop_c);
            })
        };

        // Wait until the worker processes the leaf (leaf should become ready)
        let mut processed = false;
        for _ in 0..1000 {
            if let Some(Task::Leaf(leaf_task)) = task_heap.get(leaf_idx) {
                // Leaf should eventually be in READY state (not consumed, since no parent processes it)
                if leaf_task.get_state() == crate::parallel_tree::task::leaf_state::READY {
                    processed = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }

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
    fn worker_merges_two_leaves_into_parent() {
        // Create a pool with 2 blocks
        let pool = Arc::new(BlockPool::<LeafPayload>::new(2).expect("pool creation failed"));

        // Create a task heap with 2 leaves (k=1)
        let task_heap = Arc::new(TaskHeap::new(1));

        // Set up indices
        let parent_idx = 0;
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

        let debug_worker = WorkerLocal::<TestWorkerParams> {
            id: 999, // Debug worker ID
            ready_q: ready_q.clone(),
            leaf_queue: leaf_queue.clone(),
            task_heap: task_heap.clone(),
            pool: pool.clone(),
            reducer: reducer_arc.clone(),
        };

        // Spawn worker.
        let worker_thread = {
            let ready_q_c = ready_q.clone();
            let leaf_q_c = leaf_queue.clone();
            let task_heap_c = task_heap.clone();
            let pool_c = pool.clone();
            let stop_c = stop.clone();
            std::thread::spawn(move || {
                let worker = WorkerLocal::<TestWorkerParams> {
                    id: 0,
                    ready_q: ready_q_c,
                    leaf_queue: leaf_q_c,
                    task_heap: task_heap_c,
                    pool: pool_c,
                    reducer: reducer_arc,
                };
                worker.run(stop_c);
            })
        };

        // Wait until all processing is complete
        let mut all_processed = false;
        for i in 0..1000 {
            // Debug: print states every 100 iterations
            if i % 100 == 0 {
                println!("--- Iteration {} ---", i);
                println!("{:?}", &*task_heap);
                println!("{:?}", debug_worker);
                println!("---");
            }

            // Check if all non-root nodes are consumed and root has correct value
            let left_consumed = if let Some(Task::Leaf(left_leaf)) = task_heap.get(left_idx) {
                left_leaf.get_state() == crate::parallel_tree::task::leaf_state::CONSUMED
            } else {
                false
            };

            let right_consumed = if let Some(Task::Leaf(right_leaf)) = task_heap.get(right_idx) {
                right_leaf.get_state() == crate::parallel_tree::task::leaf_state::CONSUMED
            } else {
                false
            };

            let root_correct = if let Some(Task::Node(parent_node)) = task_heap.get(parent_idx) {
                // Root should be in READY state (not consumed) and have correct value
                if parent_node.get_state()
                    == crate::parallel_tree::task::node_state::PROCESSED_WAITING_FOR_CONSUMPTION
                {
                    if let Some(buf_id) = parent_node.get_buf_id_if_ready() {
                        if let Some(handle) = pool.claim(buf_id) {
                            let acc = handle.read();
                            acc == LeafPayload(30)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if left_consumed && right_consumed && root_correct {
                all_processed = true;
                break;
            }

            thread::sleep(Duration::from_millis(1));
        }

        // Stop the worker and join the thread
        stop.store(1, Ordering::Release);
        worker_thread.join().expect("worker thread panicked");

        assert!(
            all_processed,
            "worker did not process all nodes correctly within timeout"
        );

        // Final verification: all non-root nodes should be consumed, root should be ready with correct value
        if let Some(Task::Leaf(left_leaf)) = task_heap.get(left_idx) {
            assert_eq!(
                left_leaf.get_state(),
                crate::parallel_tree::task::leaf_state::CONSUMED,
                "Left leaf should be consumed"
            );
        }

        if let Some(Task::Leaf(right_leaf)) = task_heap.get(right_idx) {
            assert_eq!(
                right_leaf.get_state(),
                crate::parallel_tree::task::leaf_state::CONSUMED,
                "Right leaf should be consumed"
            );
        }

        if let Some(Task::Node(parent_node)) = task_heap.get(parent_idx) {
            assert_eq!(
                parent_node.get_state(),
                crate::parallel_tree::task::node_state::PROCESSED_WAITING_FOR_CONSUMPTION,
                "Root should be ready (not consumed)"
            );
            if let Some(buf_id) = parent_node.get_buf_id_if_ready() {
                if let Some(handle) = pool.claim(buf_id) {
                    let acc = handle.read();
                    assert_eq!(
                        acc,
                        LeafPayload(30),
                        "Root should have correct accumulated value"
                    );
                }
            }
        }
    }

    /// Enqueue four leaves and verify the worker merges them into the root accumulator.
    #[test]
    fn worker_processes_four_leaves_into_root() {
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
            std::thread::spawn(move || {
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
                worker.run(stop_c);
            })
        };

        // Wait until all processing is complete
        let mut all_processed = false;
        for i in 0..2000 {
            // Debug: print worker and task heap state every 200 iterations
            if i % 200 == 0 {
                println!("--- Iteration {} ---", i);
                println!("{:?}", &*task_heap);
                println!(
                    "Worker queues: ready_q_len={}, leaf_q_len={}, pool_free={}",
                    ready_q.len(),
                    leaf_queue.len(),
                    pool.free_count()
                );
                println!("---");
            }

            // Check if all non-root nodes are consumed and root has correct value
            let mut all_non_root_consumed = true;

            // Check all nodes except root (index 0)
            for node_idx in 1..task_heap.size() {
                if let Some(task) = task_heap.get(node_idx) {
                    let consumed = match task {
                        Task::Leaf(leaf) => {
                            leaf.get_state() == crate::parallel_tree::task::leaf_state::CONSUMED
                        }
                        Task::Node(node) => {
                            node.get_state() == crate::parallel_tree::task::node_state::CONSUMED
                        }
                    };
                    if !consumed {
                        all_non_root_consumed = false;
                        break;
                    }
                }
            }

            // Check if root has correct value and is in READY state
            let root_correct = if let Some(Task::Node(root_node)) = task_heap.get(0) {
                if root_node.get_state()
                    == crate::parallel_tree::task::node_state::PROCESSED_WAITING_FOR_CONSUMPTION
                {
                    if let Some(buf_id) = root_node.get_buf_id_if_ready() {
                        if let Some(handle) = pool.claim(buf_id) {
                            let acc = handle.read();
                            acc == LeafPayload(10)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if all_non_root_consumed && root_correct {
                all_processed = true;
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Stop worker.
        stop.store(1, Ordering::Release);
        worker_thread.join().expect("worker thread panic");

        assert!(
            all_processed,
            "not all nodes processed correctly within timeout"
        );

        // Final verification: all non-root nodes should be consumed
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

        // Root should be ready with correct value
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
                        acc,
                        LeafPayload(10),
                        "Root should have correct accumulated value (sum of 1+2+3+4)"
                    );
                }
            }
        }
    }
}
