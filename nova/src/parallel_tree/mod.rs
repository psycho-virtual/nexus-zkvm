// Parallel tree module - based on the design in `parallel_tree.md`.
//
// This module is split into the following components:
// - block_pool: Memory-bounded payload buffers
// - task: Task representation and heap structure for flat array-based operations
// - worker: Worker local state and task execution
// - scheduler: Task scheduling and orchestration

pub mod block_pool;
pub mod task;
pub mod worker;
pub mod scheduler;

// Re-export the public API so that downstream crates can simply `use
// crate::parallel_tree::{BlockPool, Task, Scheduler, ...};`

pub use block_pool::{BlockPool, BufHandle, BufId, Payload};
pub use task::{Task, TaskHeap, LeafTask, NodeTask, leaf_state, node_state};
pub use worker::{WorkerLocal, READY_Q_CAP, DummyStrictInst, DummyAccInst, DummyFoldProof};
pub use scheduler::{Scheduler, LeafProducer}; 