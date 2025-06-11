// Parallel tree module - based on the design in `parallel_tree.md`.
//
// This module is split into the following components:
// - block_pool: Memory-bounded payload buffers
// - task: Task representation and heap structure for flat array-based operations
// - worker: Worker local state and task execution
// - scheduler: Task scheduling and orchestration

pub mod block_pool;
pub mod parallel_tree_folder;
pub mod scheduler;
pub mod sha256_chain_folder;
pub mod task;
pub mod worker;

// Re-export the public API so that downstream crates can simply `use
// crate::parallel_tree::{BlockPool, Task, Scheduler, ...};`

pub use block_pool::{BlockPool, BufHandle, BufId};
pub use scheduler::{LeafProducer, Scheduler};
pub use task::{leaf_state, node_state, LeafTask, NodeTask, Task, TaskHeap};
pub use worker::{DummyAccInst, DummyFoldProof, DummyStrictInst, WorkerLocal, READY_Q_CAP};
