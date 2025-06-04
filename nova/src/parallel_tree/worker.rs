use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crossbeam_deque::{Stealer, Worker as DequeWorker};
use crossbeam_queue::ArrayQueue;

use super::block_pool::{BlockPool, Payload};
use super::task::{Task, TaskHeap};
use crate::fold_reducer::FoldReducer;

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
    pub deque: DequeWorker<usize>, // Now stores indices into the TaskHeap
    pub ready_q: Arc<ArrayQueue<usize>>, // Indices of ready parent nodes
    pub leaf_queue: Arc<ArrayQueue<(P::LeafInput, usize)>>, // (leaf_data, node_index) pairs
    pub task_heap: Arc<TaskHeap>,  // Shared heap of all tasks
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
    pub fn run(self, stop: Arc<AtomicUsize>, stealer_pool: Vec<Stealer<usize>>) {
        let Self {
            id,
            deque,
            ready_q,
            leaf_queue,
            task_heap,
            pool,
            reducer,
        } = self;

        // Pin to a dedicated core if available.
        if let Some(core_ids) = core_affinity::get_core_ids() {
            if let Some(core) = core_ids.get(id) {
                let _ = core_affinity::set_for_current(*core);
            }
        }

        // Main loop
        while stop.load(Ordering::Acquire) == 0 {
            // Priority 1 – ready tasks (tasks that are READY and need to be consumed)
            if let Some(task_idx) = ready_q.pop() {
                Self::process_inner_input(task_idx, &task_heap, &ready_q, &pool, &reducer);
                continue;
            }

            // Priority 2 – own deque (parent state checking)
            if let Some(node_idx) = deque.pop() {
                Self::check_parent_state(node_idx, &task_heap, &ready_q, &deque, &pool, &reducer);
                continue;
            }

            // Priority 3 – leaf input processing
            if let Some((leaf_data, leaf_idx)) = leaf_queue.pop() {
                Self::process_leaf_input(
                    leaf_data, leaf_idx, &task_heap, &ready_q, &pool, &reducer,
                );
                continue;
            }

            // Priority 4 – steal from others
            let mut stole = false;
            for stealer in &stealer_pool {
                match stealer.steal() {
                    crossbeam_deque::Steal::Success(node_idx) => {
                        Self::check_parent_state(
                            node_idx, &task_heap, &ready_q, &deque, &pool, &reducer,
                        );
                        stole = true;
                        break;
                    }
                    crossbeam_deque::Steal::Retry => { /* try next */ }
                    crossbeam_deque::Steal::Empty => {}
                }
            }
            if stole {
                continue;
            }

            // Yield – nothing to do right now.
            std::thread::yield_now();
        }
    }


    /// Check and update parent state when a child changes
    #[inline]
    fn check_parent_state(
        node_idx: usize,
        task_heap: &TaskHeap,
        ready_q: &Arc<ArrayQueue<usize>>,
        deque: &DequeWorker<usize>,
        pool: &Arc<BlockPool<P::Inner>>,
        reducer: &Arc<
            dyn FoldReducer<
                    2,
                    StrictInst = P::LeafInput,
                    AccInst = P::Inner,
                    FoldProof = P::Proof,
                    Error = P::Error,
                > + Send
                + Sync,
        >,
    ) {
        if let Some(task) = task_heap.get(node_idx) {
            if let Task::Node(node_task) = task {
                // Only process nodes that are in WAITING_BOTH_CHILDREN state
                if node_task.get_state() == super::task::node_state::WAITING_BOTH_CHILDREN {
                    Self::try_compute_node(node_idx, task_heap, ready_q, deque, pool, reducer);
                }
            }
        }
    }

    /// Try to compute a node's result when both children are ready
    #[inline]
    fn try_compute_node(
        node_idx: usize,
        task_heap: &TaskHeap,
        ready_q: &Arc<ArrayQueue<usize>>,
        deque: &DequeWorker<usize>,
        pool: &Arc<BlockPool<P::Inner>>,
        reducer: &Arc<
            dyn FoldReducer<
                    2,
                    StrictInst = P::LeafInput,
                    AccInst = P::Inner,
                    FoldProof = P::Proof,
                    Error = P::Error,
                > + Send
                + Sync,
        >,
    ) {
        if let Some(task) = task_heap.get(node_idx) {
            if let Task::Node(node_task) = task {
                // Only process if the node is in WAITING_BOTH_CHILDREN state
                if node_task.get_state() == super::task::node_state::WAITING_BOTH_CHILDREN {
                    let left_idx = TaskHeap::left(node_idx);
                    let right_idx = TaskHeap::right(node_idx);

                    tracing::debug!(target: WORKER_TARGET,
                        "🔄 Node {}: Attempting to compute result from children [{}, {}]",
                        node_idx, left_idx, right_idx
                    );

                    // Get buffer IDs from children
                    let left_buf_id = task_heap.get_buf_id_if_ready(left_idx);
                    let right_buf_id = task_heap.get_buf_id_if_ready(right_idx);

                    if let (Some(left_id), Some(right_id)) = (left_buf_id, right_buf_id) {
                        tracing::debug!(target: WORKER_TARGET,
                            "Node {}: Both children ready with buffer IDs [{}, {}]",
                            node_idx, left_id, right_id
                        );

                        // Get handles to children's buffers
                        if let (Some(mut left_handle), Some(right_handle)) =
                            (pool.claim(left_id), pool.claim(right_id))
                        {
                            // Read accumulators from buffers
                            let acc_left: P::Inner = left_handle.read();
                            let acc_right: P::Inner = right_handle.read();

                            tracing::debug!(target: WORKER_TARGET,
                                "Node {}: Successfully read accumulator instances from buffers",
                                node_idx
                            );

                            // Build the children array
                            let acc_children: [P::Inner; 2] = [acc_left, acc_right];

                            // Fold the accumulators with timing
                            tracing::debug!(target: WORKER_TARGET,
                                "Node {}: Starting fold_acc_acc operation...",
                                node_idx
                            );

                            let fold_start = Instant::now();
                            let fold_result = reducer.fold_acc_acc(&acc_children);
                            let fold_time = fold_start.elapsed();

                            match fold_result {
                                Ok((parent_acc, _proof)) => {
                                    tracing::debug!(target: WORKER_TARGET,
                                        "✅ Node {}: fold_acc_acc completed successfully in {:?}",
                                        node_idx, fold_time
                                    );

                                    // Reuse the left buffer for the parent result
                                    left_handle.write(&parent_acc);
                                    let parent_buf_id = left_handle.into_id();

                                    // Release the right buffer back to the pool immediately
                                    right_handle.release();

                                    tracing::debug!(target: WORKER_TARGET,
                                        "Node {}: Stored folded result in buffer {}, released buffer {}",
                                        node_idx, parent_buf_id, right_id
                                    );

                                    // Try to start processing this node with the computed buffer
                                    if node_task.try_start_processing(parent_buf_id) {
                                        // Set this node to ready with the computed result
                                        if node_task.try_set_ready() {
                                            tracing::debug!(target: WORKER_TARGET,
                                                "✅ Node {}: Successfully set to READY state",
                                                node_idx
                                            );

                                            // For non-root nodes, DON'T add to ready queue - they should be consumed by their parent
                                            // Only add to ready queue if this is the root node (has no parent)
                                            if TaskHeap::parent(node_idx).is_none() {
                                                let _ = ready_q.push(node_idx);
                                                tracing::debug!(target: WORKER_TARGET,
                                                    "Node {}: Root node added to ready queue",
                                                    node_idx
                                                );
                                            }

                                            // Notify parent that this child is now ready
                                            // Only add to deque if both children are now ready
                                            if let Some(parent_idx) = TaskHeap::parent(node_idx) {
                                                if let Some(Task::Node(parent_node)) =
                                                    task_heap.get(parent_idx)
                                                {
                                                    if parent_node.notify_child_ready() {
                                                        // Both children are now ready, add parent to deque for processing
                                                        deque.push(parent_idx);
                                                        tracing::debug!(target: WORKER_TARGET,
                                                            "Node {}: Notified parent {} (both children ready)",
                                                            node_idx, parent_idx
                                                        );
                                                    }
                                                }
                                            }

                                            // Mark children as consumed - their buffers are now managed by this node
                                            // Left child's buffer is now owned by this node, right child's buffer was released
                                            Self::try_consume_task(task_heap, left_idx);
                                            Self::try_consume_task(task_heap, right_idx);

                                            tracing::debug!(target: WORKER_TARGET,
                                                "Node {}: Marked children [{}, {}] as consumed",
                                                node_idx, left_idx, right_idx
                                            );
                                        } else {
                                            tracing::warn!(target: WORKER_TARGET,
                                                "❌ Node {}: Failed to set to ready state",
                                                node_idx
                                            );
                                        }
                                    } else {
                                        tracing::warn!(target: WORKER_TARGET,
                                            "❌ Node {}: Failed to start processing",
                                            node_idx
                                        );
                                        // Release the buffer if we failed to start processing
                                        if let Some(handle) = pool.claim(parent_buf_id) {
                                            handle.release();
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(target: WORKER_TARGET,
                                        "❌ Node {}: fold_acc_acc failed in {:?}: {:?}",
                                        node_idx, fold_time, err
                                    );
                                    // Keep the original buffers since folding failed
                                }
                            }
                        } else {
                            tracing::warn!(target: WORKER_TARGET,
                                "❌ Node {}: Failed to claim child buffers [{}, {}]",
                                node_idx, left_id, right_id
                            );
                        }
                    } else {
                        tracing::debug!(target: WORKER_TARGET,
                            "Node {}: Children not ready - left_buf: {:?}, right_buf: {:?}",
                            node_idx, left_buf_id, right_buf_id
                        );
                    }
                }
            }
        }
    }

    #[inline]
    fn process_inner_input(
        inner_idx: usize,
        task_heap: &TaskHeap,
        ready_q: &Arc<ArrayQueue<usize>>,
        pool: &Arc<BlockPool<P::Inner>>,
        reducer: &Arc<
            dyn FoldReducer<
                    2,
                    StrictInst = P::LeafInput,
                    AccInst = P::Inner,
                    FoldProof = P::Proof,
                    Error = P::Error,
                > + Send
                + Sync,
        >,
    ) {
        if let Some(task) = task_heap.get(inner_idx) {
            if let Task::Node(node_task) = task {
                // Only process nodes that are in READY state
                if node_task.get_state() == super::task::node_state::READY {
                    tracing::debug!(target: WORKER_TARGET,
                        "🔄 Inner {}: Processing ready inner node...",
                        inner_idx
                    );

                    let left_idx = TaskHeap::left(inner_idx);
                    let right_idx = TaskHeap::right(inner_idx);

                    // Get buffer IDs from children
                    let left_buf_id = task_heap.get_buf_id_if_ready(left_idx);
                    let right_buf_id = task_heap.get_buf_id_if_ready(right_idx);

                    if let (Some(left_id), Some(right_id)) = (left_buf_id, right_buf_id) {
                        tracing::debug!(target: WORKER_TARGET,
                            "Inner {}: Both children ready with buffer IDs [{}, {}]",
                            inner_idx, left_id, right_id
                        );

                        // Start consuming this node
                        if node_task.try_start_consuming() {
                            // Get handles to children's buffers
                            if let (Some(mut left_handle), Some(right_handle)) =
                                (pool.claim(left_id), pool.claim(right_id))
                            {
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
                                let fold_result = reducer.fold_acc_acc(&acc_children);
                                let fold_time = fold_start.elapsed();

                                match fold_result {
                                    Ok((parent_acc, _proof)) => {
                                        tracing::debug!(target: WORKER_TARGET,
                                            "✅ Inner {}: fold_acc_acc completed successfully in {:?}",
                                            inner_idx, fold_time
                                        );

                                        // Reuse the left buffer for the parent result
                                        left_handle.write(&parent_acc);
                                        let final_buf_id = left_handle.into_id();

                                        // Release the right buffer back to the pool immediately
                                        right_handle.release();

                                        tracing::debug!(target: WORKER_TARGET,
                                            "Inner {}: Stored folded result in buffer {}, released buffer {}",
                                            inner_idx, final_buf_id, right_id
                                        );

                                        // Mark this node as consumed
                                        if node_task.try_set_consumed() {
                                            tracing::debug!(target: WORKER_TARGET,
                                                "✅ Inner {}: Successfully consumed and stored folded data",
                                                inner_idx
                                            );

                                            // For non-root nodes, notify parent that this child was consumed
                                            if let Some(parent_idx) = TaskHeap::parent(inner_idx) {
                                                if let Some(Task::Node(parent_node)) = task_heap.get(parent_idx) {
                                                    // Check if parent should be notified for processing
                                                    let parent_state = parent_node.get_state();
                                                    if parent_state == super::task::node_state::WAITING_BOTH_CHILDREN {
                                                        // Add parent to ready queue for potential processing
                                                        let _ = ready_q.push(parent_idx);
                                                        tracing::debug!(target: WORKER_TARGET,
                                                            "Inner {}: Notified parent {} for potential processing",
                                                            inner_idx, parent_idx
                                                        );
                                                    }
                                                }
                                            }

                                            // Mark children as consumed - their buffers are now managed by this node
                                            Self::try_consume_task(task_heap, left_idx);
                                            Self::try_consume_task(task_heap, right_idx);

                                            tracing::debug!(target: WORKER_TARGET,
                                                "Inner {}: Marked children [{}, {}] as consumed",
                                                inner_idx, left_idx, right_idx
                                            );
                                        } else {
                                            tracing::warn!(target: WORKER_TARGET,
                                                "❌ Inner {}: Failed to set consumed state",
                                                inner_idx
                                            );
                                            
                                            // Release the buffer since we failed to set consumed state
                                            if let Some(release_handle) = pool.claim(final_buf_id) {
                                                release_handle.release();
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!(target: WORKER_TARGET,
                                            "❌ Inner {}: fold_acc_acc failed in {:?}: {:?}",
                                            inner_idx, fold_time, err
                                        );
                                        // Keep the original buffers since folding failed
                                        // Reset node state since we couldn't process it
                                        node_task.state.store(super::task::node_state::READY, Ordering::Release);
                                    }
                                }
                            } else {
                                tracing::warn!(target: WORKER_TARGET,
                                    "❌ Inner {}: Failed to claim child buffers [{}, {}]",
                                    inner_idx, left_id, right_id
                                );
                                // Reset node state since we couldn't process it
                                node_task.state.store(super::task::node_state::READY, Ordering::Release);
                            }
                        } else {
                            tracing::warn!(target: WORKER_TARGET,
                                "❌ Inner {}: Failed to start consuming",
                                inner_idx
                            );
                        }
                    } else {
                        tracing::debug!(target: WORKER_TARGET,
                            "Inner {}: Children not ready - left_buf: {:?}, right_buf: {:?}",
                            inner_idx, left_buf_id, right_buf_id
                        );
                    }
                } else {
                    tracing::debug!(target: WORKER_TARGET,
                        "Inner {}: Node not in READY state (state: {}), skipping",
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

    /// Process leaf input data to produce a result
    #[inline]
    fn process_leaf_input(
        leaf_data: P::LeafInput,
        leaf_idx: usize,
        task_heap: &TaskHeap,
        ready_q: &Arc<ArrayQueue<usize>>,
        pool: &Arc<BlockPool<P::Inner>>,
        reducer: &Arc<
            dyn FoldReducer<
                    2,
                    StrictInst = P::LeafInput,
                    AccInst = P::Inner,
                    FoldProof = P::Proof,
                    Error = P::Error,
                > + Send
                + Sync,
        >,
    ) {
        if let Some(task) = task_heap.get(leaf_idx) {
            if let Task::Leaf(leaf_task) = task {
                tracing::debug!(target: WORKER_TARGET,
                    "🌱 Leaf {}: Processing strict instance to accumulator...",
                    leaf_idx
                );

                // Allocate a buffer from the pool with back-pressure
                let handle = loop {
                    if let Some(h) = pool.alloc() {
                        break h;
                    }
                    // No block available - yield to let other workers make progress
                    if pool.free_count() == 0 {
                        std::thread::yield_now();
                    }
                };

                tracing::debug!(target: WORKER_TARGET,
                    "Leaf {}: Allocated buffer, starting strict_to_acc conversion...",
                    leaf_idx
                );

                let buf_id = handle.into_id();

                // Try to start processing this leaf with the allocated buffer
                if leaf_task.try_start_processing(buf_id) {
                    // Convert leaf input to accumulator using reducer with timing
                    let convert_start = Instant::now();
                    let convert_result = reducer.strict_to_acc(&leaf_data);
                    let convert_time = convert_start.elapsed();
                    
                    match convert_result {
                        Ok(acc) => {
                            tracing::debug!(target: WORKER_TARGET,
                                "✅ Leaf {}: strict_to_acc completed successfully in {:?}",
                                leaf_idx, convert_time
                            );

                            // Claim the buffer to write to it
                            if let Some(mut write_handle) = pool.claim(buf_id) {
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
                                        if let Some(Task::Node(parent_node)) = task_heap.get(parent_idx) {
                                            if parent_node.notify_child_ready() {
                                                // Both children are now ready, add parent to deque for processing
                                                let _ = ready_q.push(parent_idx);
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
                                        "❌ Leaf {}: Failed to set to ready state",
                                        leaf_idx
                                    );
                                    
                                    // Release the buffer since we failed to set ready state
                                    if let Some(release_handle) = pool.claim(buf_id) {
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
                            leaf_task.state.store(super::task::leaf_state::NOT_STARTED, Ordering::Release);
                            leaf_task.buffer_id.store(-1, Ordering::Release);

                            // Release the buffer since conversion failed
                            if let Some(release_handle) = pool.claim(buf_id) {
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
                    if let Some(release_handle) = pool.claim(buf_id) {
                        release_handle.release();
                    }
                }
            }
        }
    }

    #[inline]
    fn try_consume_task(task_heap: &TaskHeap, task_idx: usize) {
        if let Some(task) = task_heap.get(task_idx) {
            match task {
                Task::Leaf(leaf) => {
                    if leaf.try_start_consuming() {
                        let _ = leaf.try_set_consumed();
                    }
                }
                Task::Node(node) => {
                    if node.try_start_consuming() {
                        let _ = node.try_set_consumed();
                    }
                }
            }
        }
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

        // Spawn the worker thread
        let worker_thread = {
            let ready_q_clone = ready_q.clone();
            let leaf_queue_clone = leaf_queue.clone();
            let task_heap_clone = task_heap.clone();
            let pool_clone = pool.clone();
            let stop_clone = stop.clone();

            thread::spawn(move || {
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
                    deque: crossbeam_deque::Worker::new_fifo(),
                    ready_q: ready_q_clone,
                    leaf_queue: leaf_queue_clone,
                    task_heap: task_heap_clone,
                    pool: pool_clone,
                    reducer: reducer_arc,
                };

                worker.run(stop_clone, Vec::new());
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

        // Spawn the worker thread
        let worker_thread = {
            let ready_q_clone = ready_q.clone();
            let leaf_queue_clone = leaf_queue.clone();
            let task_heap_clone = task_heap.clone();
            let pool_clone = pool.clone();
            let stop_clone = stop.clone();

            thread::spawn(move || {
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
                    deque: crossbeam_deque::Worker::new_fifo(),
                    ready_q: ready_q_clone,
                    leaf_queue: leaf_queue_clone,
                    task_heap: task_heap_clone,
                    pool: pool_clone,
                    reducer: reducer_arc,
                };

                worker.run(stop_clone, Vec::new());
            })
        };

        // Wait until all processing is complete
        let mut all_processed = false;
        for i in 0..1000 {
            // Debug: print states every 100 iterations
            if i % 100 == 0 {
                if let Some(Task::Leaf(left_leaf)) = task_heap.get(left_idx) {
                    println!("Left leaf state: {}", left_leaf.get_state());
                }
                if let Some(Task::Leaf(right_leaf)) = task_heap.get(right_idx) {
                    println!("Right leaf state: {}", right_leaf.get_state());
                }
                if let Some(Task::Node(parent_node)) = task_heap.get(parent_idx) {
                    println!("Parent state: {}", parent_node.get_state());
                }
                println!("Ready queue len: {}", ready_q.len());
                println!("Leaf queue len: {}", leaf_queue.len());
                println!("Pool free count: {}", pool.free_count());
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
                if parent_node.get_state() == crate::parallel_tree::task::node_state::READY {
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
                crate::parallel_tree::task::node_state::READY,
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
                    deque: crossbeam_deque::Worker::new_fifo(),
                    ready_q: ready_q_c,
                    leaf_queue: leaf_q_c,
                    task_heap: task_heap_c,
                    pool: pool_c,
                    reducer: reducer_arc,
                };
                worker.run(stop_c, Vec::new());
            })
        };

        // Wait until all processing is complete
        let mut all_processed = false;
        for _ in 0..2000 {
            // ~2s
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
                if root_node.get_state() == crate::parallel_tree::task::node_state::READY {
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
                crate::parallel_tree::task::node_state::READY,
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
