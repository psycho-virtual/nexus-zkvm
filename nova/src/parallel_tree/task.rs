//! Lock-free task state machines and contiguous task heap implementation
#![allow(clippy::upper_case_acronyms)]

use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::fmt::{self, Debug, Formatter};
use super::block_pool::BufId;

// -----------------------------------------------------------------------------
// Atomic Task state machines
// -----------------------------------------------------------------------------

pub struct LeafTask {
    /// Buffer ID for this leaf's computed result. -1 if no buffer assigned.
    pub buffer_id: AtomicI64,
    /// State of the leaf task:
    /// 0 = Not started
    /// 1 = Currently processing
    /// 2 = Processed and waiting for consumption (buffer_id will be non-negative)
    /// 3 = Being Consumed
    /// 4 = Consumed
    pub state: AtomicU32,
}

pub struct NodeTask {
    /// Buffer ID for this node's computed result. -1 if no buffer assigned.
    pub buffer_id: AtomicI64,
    /// State of the inner node:
    /// 0 = Not started
    /// 1 = Got 1 child - waiting for the other
    /// 2 = Got 2 children and is ready to be used
    /// 3 = Currently processing
    /// 4 = Processed and waiting for consumption (buffer_id will be non-negative)
    /// 5 = Being Consumed
    /// 6 = Consumed
    pub state: AtomicU32,
}

// State constants for LeafTask
pub mod leaf_state {
    pub const NOT_STARTED: u32 = 0;
    pub const PROCESSING: u32 = 1;
    pub const READY: u32 = 2;
    pub const PROCESSED_WAITING_FOR_CONSUMPTION: u32 = 3;
    pub const CONSUMED: u32 = 4;
}

// State constants for NodeTask
pub mod node_state {
    pub const NOT_STARTED: u32 = 0;
    pub const WAITING_ONE_CHILD: u32 = 1;
    pub const WAITING_BOTH_CHILDREN: u32 = 2;
    pub const PROCESSING: u32 = 3;
    pub const PROCESSED_WAITING_FOR_CONSUMPTION: u32 = 4;
    pub const BEING_CONSUMED: u32 = 5;
    pub const CONSUMED: u32 = 6;
}

impl LeafTask {
    pub fn new() -> Self {
        Self {
            buffer_id: AtomicI64::new(-1),
            state: AtomicU32::new(leaf_state::NOT_STARTED),
        }
    }

    /// Try to transition from NOT_STARTED to PROCESSING and set buffer_id
    pub fn try_start_processing(&self, buf_id: BufId) -> bool {
        self.buffer_id.store(buf_id as i64, Ordering::Release);
        if self
            .state
            .compare_exchange(
                leaf_state::NOT_STARTED,
                leaf_state::PROCESSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            true
        } else {
            self.buffer_id.store(-1, Ordering::Release);
            false
        }
    }

    /// Try to transition from PROCESSING to READY (buffer_id already set)
    pub fn try_set_ready(&self) -> bool {
        self.state
            .compare_exchange(
                leaf_state::PROCESSING,
                leaf_state::READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Try to transition from READY to BEING_CONSUMED
    pub fn try_start_consuming(&self) -> bool {
        self.state
            .compare_exchange(
                leaf_state::READY,
                leaf_state::PROCESSED_WAITING_FOR_CONSUMPTION,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Try to transition from BEING_CONSUMED to CONSUMED
    pub fn try_set_consumed(&self) -> bool {
        self.state
            .compare_exchange(
                leaf_state::PROCESSED_WAITING_FOR_CONSUMPTION,
                leaf_state::CONSUMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == leaf_state::READY
    }

    #[inline]
    pub fn get_buf_id_if_ready(&self) -> Option<BufId> {
        if self.is_ready() {
            let id = self.buffer_id.load(Ordering::Acquire);
            if id >= 0 {
                Some(id as BufId)
            } else {
                None
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn get_state(&self) -> u32 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    pub fn get_buf_id(&self) -> Option<BufId> {
        let id = self.buffer_id.load(Ordering::Acquire);
        if id >= 0 {
            Some(id as BufId)
        } else {
            None
        }
    }

    /// Clear the buffer ID by setting it to -1
    #[inline]
    pub fn clear_buffer_id(&self) {
        self.buffer_id.store(-1, Ordering::Release);
    }
}

impl NodeTask {
    pub fn new() -> Self {
        Self {
            buffer_id: AtomicI64::new(-1),
            state: AtomicU32::new(node_state::NOT_STARTED),
        }
    }

    pub fn try_got_first_child(&self) -> bool {
        self.state
            .compare_exchange(
                node_state::NOT_STARTED,
                node_state::WAITING_ONE_CHILD,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn try_got_second_child(&self) -> bool {
        self.state
            .compare_exchange(
                node_state::WAITING_ONE_CHILD,
                node_state::WAITING_BOTH_CHILDREN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn notify_child_ready(&self) -> bool {
        if self.try_got_first_child() {
            return false;
        }
        self.try_got_second_child()
    }

    pub fn try_start_processing(&self, buf_id: BufId) -> bool {
        self.buffer_id.store(buf_id as i64, Ordering::Release);
        if self
            .state
            .compare_exchange(
                node_state::WAITING_BOTH_CHILDREN,
                node_state::PROCESSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            true
        } else {
            self.buffer_id.store(-1, Ordering::Release);
            false
        }
    }

    pub fn try_set_ready(&self) -> bool {
        self.state
            .compare_exchange(
                node_state::PROCESSING,
                node_state::PROCESSED_WAITING_FOR_CONSUMPTION,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn try_start_consuming(&self) -> bool {
        self.state
            .compare_exchange(
                node_state::PROCESSED_WAITING_FOR_CONSUMPTION,
                node_state::BEING_CONSUMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn try_set_consumed(&self) -> bool {
        self.state
            .compare_exchange(
                node_state::BEING_CONSUMED,
                node_state::CONSUMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == node_state::PROCESSED_WAITING_FOR_CONSUMPTION
    }

    #[inline]
    pub fn has_both_children(&self) -> bool {
        self.state.load(Ordering::Acquire) == node_state::WAITING_BOTH_CHILDREN
    }

    #[inline]
    pub fn get_buf_id_if_ready(&self) -> Option<BufId> {
        if self.is_ready() {
            let id = self.buffer_id.load(Ordering::Acquire);
            if id >= 0 {
                Some(id as BufId)
            } else {
                None
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn get_state(&self) -> u32 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    pub fn get_buf_id(&self) -> Option<BufId> {
        let id = self.buffer_id.load(Ordering::Acquire);
        if id >= 0 {
            Some(id as BufId)
        } else {
            None
        }
    }

    /// Clear the buffer ID by setting it to -1
    #[inline]
    pub fn clear_buffer_id(&self) {
        self.buffer_id.store(-1, Ordering::Release);
    }
}

/// Union type for tasks in the heap
pub enum Task {
    Leaf(LeafTask),
    Node(NodeTask),
}

impl Task {
    pub fn new_leaf() -> Self {
        Task::Leaf(LeafTask::new())
    }
    pub fn new_node() -> Self {
        Task::Node(NodeTask::new())
    }
    pub fn is_ready(&self) -> bool {
        match self {
            Task::Leaf(l) => l.is_ready(),
            Task::Node(n) => n.is_ready(),
        }
    }
    pub fn get_buf_id_if_ready(&self) -> Option<BufId> {
        match self {
            Task::Leaf(l) => l.get_buf_id_if_ready(),
            Task::Node(n) => n.get_buf_id_if_ready(),
        }
    }
}

// -----------------------------------------------------------------------------
// Binary heap structure for tasks
// -----------------------------------------------------------------------------

/// A binary heap structure that stores all tasks in a contiguous array
pub struct TaskHeap {
    tasks: Vec<Task>,
    size: usize,
    num_leaves: usize,
}

impl TaskHeap {
    pub fn new(k: usize) -> Self {
        let num_leaves = 1 << k;
        let size = (2 * num_leaves) - 1;
        let mut tasks = Vec::with_capacity(size);
        for i in 0..size {
            if i >= size - num_leaves {
                tasks.push(Task::new_leaf());
            } else {
                tasks.push(Task::new_node());
            }
        }
        Self {
            tasks,
            size,
            num_leaves,
        }
    }

    #[inline]
    pub fn parent(i: usize) -> Option<usize> {
        if i == 0 {
            None
        } else {
            Some((i - 1) / 2)
        }
    }
    #[inline]
    pub fn left(i: usize) -> usize {
        2 * i + 1
    }
    #[inline]
    pub fn right(i: usize) -> usize {
        2 * i + 2
    }
    #[inline]
    pub fn is_leaf(&self, i: usize) -> bool {
        i >= self.size - self.num_leaves
    }
    pub fn get(&self, i: usize) -> Option<&Task> {
        self.tasks.get(i)
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }
    pub fn leaf_start(&self) -> usize {
        self.size - self.num_leaves
    }
    #[inline]
    pub fn is_ready(&self, index: usize) -> bool {
        self.get(index).map_or(false, |t| t.is_ready())
    }
    #[inline]
    pub fn get_buf_id_if_ready(&self, index: usize) -> Option<BufId> {
        self.get(index)?.get_buf_id_if_ready()
    }

    /// Clear the buffer ID for the task at the given index
    #[inline]
    pub fn clear_buffer_id(&self, index: usize) {
        if let Some(task) = self.get(index) {
            match task {
                Task::Leaf(leaf) => leaf.clear_buffer_id(),
                Task::Node(node) => node.clear_buffer_id(),
            }
        }
    }
}

impl Debug for TaskHeap {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "TaskHeap (size={}, leaves={}):", self.size, self.num_leaves)?;
        writeln!(f, "Tree structure:")?;
        
        // Helper function to convert leaf state to string
        let leaf_state_name = |state: u32| -> &'static str {
            match state {
                0 => "NotStarted",
                1 => "Processing", 
                2 => "Ready",
                3 => "WaitingConsumption",
                4 => "Consumed",
                _ => "Unknown",
            }
        };
        
        // Helper function to convert node state to string
        let node_state_name = |state: u32| -> &'static str {
            match state {
                0 => "NotStarted",
                1 => "WaitingOne", 
                2 => "WaitingBoth",
                3 => "Processing",
                4 => "WaitingConsumption",
                5 => "BeingConsumed",
                6 => "Consumed",
                _ => "Unknown",
            }
        };
        
        // Print the tree level by level
        let mut level = 0;
        let mut nodes_in_level = 1;
        let mut node_idx = 0;
        
        while node_idx < self.size {
            write!(f, "Level {}: ", level)?;
            
            for i in 0..nodes_in_level {
                if node_idx >= self.size {
                    break;
                }
                
                if i > 0 {
                    write!(f, ", ")?;
                }
                
                match &self.tasks[node_idx] {
                    Task::Leaf(leaf) => {
                        let state = leaf.get_state();
                        let state_name = leaf_state_name(state);
                        let buf_id = leaf.get_buf_id().map(|id| id.to_string()).unwrap_or_else(|| "None".to_string());
                        write!(f, "Leaf[{}]({}, buf={})", node_idx, state_name, buf_id)?;
                    }
                    Task::Node(node) => {
                        let state = node.get_state();
                        let state_name = node_state_name(state);
                        let buf_id = node.get_buf_id().map(|id| id.to_string()).unwrap_or_else(|| "None".to_string());
                        write!(f, "Node[{}]({}, buf={})", node_idx, state_name, buf_id)?;
                    }
                }
                node_idx += 1;
            }
            writeln!(f)?;
            
            level += 1;
            nodes_in_level *= 2;
        }
        
        Ok(())
    }
} 