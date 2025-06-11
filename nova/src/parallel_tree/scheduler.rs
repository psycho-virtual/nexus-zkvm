use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crossbeam_deque::{Stealer, Worker as DequeWorker};
use crossbeam_queue::ArrayQueue;

use crate::fold_reducer::FoldReducer;
use super::block_pool::{BlockPool};
use super::task::TaskHeap;
use super::worker::{WorkerLocal, WorkerParams, READY_Q_CAP};

// -----------------------------------------------------------------------------
// Leaf producer thread
// -----------------------------------------------------------------------------

pub struct LeafProducer<L: Send + Sync + Clone + 'static> {
    stream: Box<dyn Iterator<Item = L> + Send>,
    _heap_depth: usize, // k value for the binary heap (2^k leaf nodes)
}

impl<L: Send + Sync + Clone + 'static> LeafProducer<L> {
    pub fn new(stream: Box<dyn Iterator<Item = L> + Send>, heap_depth: usize) -> Self {
        Self { stream, _heap_depth: heap_depth }
    }

    pub fn spawn(self, task_heap: Arc<TaskHeap>, leaf_queues: Vec<Arc<ArrayQueue<(L, usize)>>>, stop: Arc<AtomicUsize>) {
        std::thread::spawn(move || {
            let leaf_start = task_heap.leaf_start();
            let num_leaves = task_heap.num_leaves();
            let num_workers = leaf_queues.len();
            let mut next_leaf_idx = leaf_start;
            
            for leaf in self.stream {
                // Skip if we've filled all leaf slots
                if next_leaf_idx >= leaf_start + num_leaves {
                    break;
                }
                
                // Calculate which worker should handle this leaf based on contiguous chunks
                let relative_leaf_idx = next_leaf_idx - leaf_start;
                let worker_idx = std::cmp::min(
                    relative_leaf_idx * num_workers / num_leaves,
                    num_workers - 1
                );
                
                // Push the (leaf_data, node_index) pair to the appropriate worker queue
                loop {
                    if leaf_queues[worker_idx].push((leaf.clone(), next_leaf_idx)).is_ok() {
                        break;
                    }
                    std::thread::yield_now();
                    
                    if stop.load(std::sync::atomic::Ordering::Acquire) == 1 {
                        return;
                    }
                }
                
                next_leaf_idx += 1;
            }
        });
    }
}

// -----------------------------------------------------------------------------
// Scheduler parameters implementing WorkerParams trait
// -----------------------------------------------------------------------------

pub struct SchedulerParams<L, P, Proof, Error> {
    _phantom_l: PhantomData<L>,
    _phantom_p: PhantomData<P>,
    _phantom_proof: PhantomData<Proof>,
    _phantom_error: PhantomData<Error>,
}

impl<L, P, Proof, Error> WorkerParams for SchedulerParams<L, P, Proof, Error>
where
    L: Send + Sync + Clone + 'static,
    P: Send + Sync + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + std::fmt::Debug + 'static,
{
    type LeafInput = L;
    type Inner = P;
    type Proof = Proof;
    type Error = Error;
}

// -----------------------------------------------------------------------------
// Scheduler – orchestration layer
// -----------------------------------------------------------------------------

pub struct Scheduler<L, P, Proof, Error>
where
    L: Send + Sync + Clone + 'static,
    P: Send + Sync + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + std::fmt::Debug + 'static,
{
    pool: Arc<BlockPool<P>>,
    task_heap: Arc<TaskHeap>,
    workers: Vec<std::thread::JoinHandle<()>>,
    leaf_queues: Vec<Arc<ArrayQueue<(L, usize)>>>,
    stop: Arc<AtomicUsize>,
    _phantom: PhantomData<P>,
    _phantom2: PhantomData<L>,
    _phantom3: PhantomData<Proof>,
    _phantom4: PhantomData<Error>,
}

impl<L, P, Proof, Error> Scheduler<L, P, Proof, Error>
where
    P: Send + Sync + 'static,
    L: Send + Sync + Clone + 'static,
    Proof: Send + Sync + 'static,
    Error: Send + Sync + std::fmt::Debug + 'static,
{
    pub fn new(
        pool: Arc<BlockPool<P>>, 
        heap_depth: usize, 
        reducer: Arc<dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error> + Send + Sync>
    ) -> Self {
        let num_cores = num_cpus::get();
        Self::with_workers(pool, heap_depth, reducer, num_cores)
    }

    pub fn with_workers(
        pool: Arc<BlockPool<P>>, 
        heap_depth: usize, 
        reducer: Arc<dyn FoldReducer<2, StrictInst = L, AccInst = P, FoldProof = Proof, Error = Error> + Send + Sync>,
        num_workers: usize
    ) -> Self {
        let num_cores = num_workers.max(1); // Ensure at least 1 worker
        let stop = Arc::new(AtomicUsize::new(0));
        
        // Create the task heap with 2^heap_depth leaf nodes
        let task_heap = Arc::new(TaskHeap::new(heap_depth));

        let mut worker_handles = Vec::with_capacity(num_cores);
        let mut stealers: Vec<Stealer<usize>> = Vec::with_capacity(num_cores);
        let mut ready_queues = Vec::with_capacity(num_cores);
        let mut leaf_queues: Vec<Arc<ArrayQueue<(L, usize)>>> = Vec::with_capacity(num_cores);

        // First create deques so we can collect all stealers
        for _ in 0..num_cores {
            let deque = DequeWorker::new_lifo();
            stealers.push(deque.stealer());
            ready_queues.push(Arc::new(ArrayQueue::new(READY_Q_CAP)));
            leaf_queues.push(Arc::new(ArrayQueue::new(READY_Q_CAP)));
        }

        let pool_arc = pool.clone();
        let reducer_arc = reducer.clone();
        let task_heap_arc = task_heap.clone();

        for id in 0..num_cores {
            // Move the deque out of the vector
            let ready_q = ready_queues[id].clone();
            let leaf_queue = leaf_queues[id].clone();
            let pool_clone = pool_arc.clone();
            let reducer_clone = reducer_arc.clone();
            let task_heap_clone = task_heap_arc.clone();
            let stop_flag = stop.clone();

            let handle = std::thread::spawn(move || {
                let worker = WorkerLocal::<SchedulerParams<L, P, Proof, Error>> {
                    id,
                    ready_q,
                    leaf_queue,
                    task_heap: task_heap_clone,
                    pool: pool_clone,
                    reducer: reducer_clone,
                };
                worker.run(stop_flag);
            });
            worker_handles.push(handle);
        }

        Self {
            pool,
            task_heap,
            workers: worker_handles,
            leaf_queues,
            stop,
            _phantom: PhantomData,
            _phantom2: PhantomData,
            _phantom3: PhantomData,
            _phantom4: PhantomData,
        }
    }
    
    /// Spawn the leaf producer that feeds the task heap
    pub fn spawn_leaf_producer(&self, stream: Box<dyn Iterator<Item = L> + Send>) {
        let producer = LeafProducer::new(stream, 0);
        producer.spawn(self.task_heap.clone(), self.leaf_queues.clone(), self.stop.clone());
    }

    /// Get a reference to the task heap for inspection
    pub fn task_heap(&self) -> &Arc<TaskHeap> {
        &self.task_heap
    }

    /// Get a reference to the block pool for accessing results
    pub fn pool(&self) -> &Arc<BlockPool<P>> {
        &self.pool
    }

    /// Get the root result if available (root is at index 0)
    pub fn get_root_result(&self) -> Option<P> {
        if let Some(super::task::Task::Node(root_node)) = self.task_heap.get(0) {
            if let Some(buf_id) = root_node.get_buf_id_if_ready() {
                if let Some(handle) = self.pool.claim(buf_id) {
                    Some(handle.read())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Check if all non-root nodes are consumed and root is ready
    pub fn is_computation_complete(&self) -> bool {
        // Check if root is ready
        let root_ready = if let Some(super::task::Task::Node(root_node)) = self.task_heap.get(0) {
            root_node.get_state() == super::task::node_state::PROCESSED_WAITING_FOR_CONSUMPTION
        } else {
            false
        };

        if !root_ready {
            return false;
        }

        // Check if all non-root nodes are consumed
        for idx in 1..self.task_heap.size() {
            if let Some(task) = self.task_heap.get(idx) {
                let consumed = match task {
                    super::task::Task::Leaf(leaf) => leaf.get_state() == super::task::leaf_state::CONSUMED,
                    super::task::Task::Node(node) => node.get_state() == super::task::node_state::CONSUMED,
                };
                if !consumed {
                    return false;
                }
            }
        }

        true
    }

    /// Stop all workers
    pub fn stop(self) {
        self.stop.store(1, std::sync::atomic::Ordering::Release);
        
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // Test payload for scheduler tests
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LeafPayload(u32);

    // Dummy proof type for tests
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DummyFoldProof;

    struct SimpleReducer;

    impl FoldReducer<2> for SimpleReducer {
        type StrictInst = LeafPayload;
        type AccInst = LeafPayload;
        type FoldProof = DummyFoldProof;
        type Error = ();

        fn fold_acc_acc(
            &self,
            acc_children: &[Self::AccInst; 2],
        ) -> Result<(Self::AccInst, Self::FoldProof), Self::Error> {
            // Sum the children
            let sum = acc_children[0].0 + acc_children[1].0;
            Ok((LeafPayload(sum), DummyFoldProof))
        }

        fn verify_step(&self, _parent: &Self::AccInst, _proof: &Self::FoldProof) -> bool {
            true
        }

        fn strict_to_acc(&self, strict: &Self::StrictInst) -> Result<Self::AccInst, Self::Error> {
            Ok(*strict)
        }
    }

    #[test]
    fn scheduler_sums_four_leaf_nodes() {
        let pool = Arc::new(BlockPool::<LeafPayload>::new(16).expect("pool creation failed"));
        let reducer: Arc<dyn FoldReducer<2, StrictInst = LeafPayload, AccInst = LeafPayload, FoldProof = DummyFoldProof, Error = ()> + Send + Sync> = Arc::new(SimpleReducer);
        
        let scheduler = Scheduler::<LeafPayload, LeafPayload, DummyFoldProof, ()>::new(pool, 2, reducer);
        
        // Feed leaf data through producer
        let leaf_stream = Box::new([LeafPayload(1), LeafPayload(2), LeafPayload(3), LeafPayload(4)].into_iter());
        scheduler.spawn_leaf_producer(leaf_stream);
        
        // Wait for computation to complete
        let mut complete = false;
        for _ in 0..1000 {
            if scheduler.is_computation_complete() {
                complete = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        
        assert!(complete, "computation did not complete within timeout");
        
        // Verify result
        if let Some(result) = scheduler.get_root_result() {
            assert_eq!(result, LeafPayload(10), "expected sum of 1+2+3+4 = 10");
        } else {
            panic!("no root result available");
        }
        
        scheduler.stop();
    }

    #[test]
    fn scheduler_sums_two_leaf_nodes() {
        let pool = Arc::new(BlockPool::<LeafPayload>::new(16).expect("pool creation failed"));
        let reducer: Arc<dyn FoldReducer<2, StrictInst = LeafPayload, AccInst = LeafPayload, FoldProof = DummyFoldProof, Error = ()> + Send + Sync> = Arc::new(SimpleReducer);
        
        let scheduler = Scheduler::<LeafPayload, LeafPayload, DummyFoldProof, ()>::new(pool, 1, reducer);
        
        // Feed leaf data through producer
        let leaf_stream = Box::new([LeafPayload(5), LeafPayload(7)].into_iter());
        scheduler.spawn_leaf_producer(leaf_stream);
        
        // Wait for computation to complete
        let mut complete = false;
        for _ in 0..1000 {
            if scheduler.is_computation_complete() {
                complete = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        
        assert!(complete, "computation did not complete within timeout");
        
        // Verify result
        if let Some(result) = scheduler.get_root_result() {
            assert_eq!(result, LeafPayload(12), "expected sum of 5+7 = 12");
        } else {
            panic!("no root result available");
        }
        
        scheduler.stop();
    }

    #[test]
    fn scheduler_stress_test_sixteen_leaves() {
        let pool = Arc::new(BlockPool::<LeafPayload>::new(32).expect("pool creation failed"));
        let reducer: Arc<dyn FoldReducer<2, StrictInst = LeafPayload, AccInst = LeafPayload, FoldProof = DummyFoldProof, Error = ()> + Send + Sync> = Arc::new(SimpleReducer);
        
        let scheduler = Scheduler::<LeafPayload, LeafPayload, DummyFoldProof, ()>::with_workers(pool, 4, reducer, 4);
        
        // Feed 16 leaf values (1 through 16)
        let leaf_values: Vec<LeafPayload> = (1..=16).map(LeafPayload).collect();
        let expected_sum = (1..=16).sum::<u32>();
        
        let leaf_stream = Box::new(leaf_values.into_iter());
        scheduler.spawn_leaf_producer(leaf_stream);
        
        // Wait for computation to complete
        let mut complete = false;
        for _ in 0..2000 {
            if scheduler.is_computation_complete() {
                complete = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        
        assert!(complete, "computation did not complete within timeout");
        
        // Verify result
        if let Some(result) = scheduler.get_root_result() {
            assert_eq!(result, LeafPayload(expected_sum), "expected sum of 1..=16 = {}", expected_sum);
        } else {
            panic!("no root result available");
        }
        
        scheduler.stop();
    }
} 