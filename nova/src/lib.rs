#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::large_enum_variant)]

pub mod absorb;
pub mod provider; // Making this public for our use
mod sparse;
mod utils;
mod tracing_utils;

pub mod circuits;
pub mod folding; // Making folding module public
mod gadgets;

#[cfg(test)]
mod test_utils;

pub mod ccs;
pub mod commitment;
pub mod r1cs;
pub mod tree_folding;
pub mod shuffling;

// -----------------------------------------------------------------------------
// Parallel tree execution engine
// -----------------------------------------------------------------------------

// Expose the `parallel_tree` module which provides a lock-free, task-based
// binary-tree scheduler optimised for multi-core execution.  The module is
// entirely self-contained but depends on the `FoldReducer` trait already
// defined under `tree_folding::fold_reducer`.  We re-export that sub-module at
// the crate root so that existing paths like `crate::fold_reducer::FoldReducer`
// continue to compile when used inside the parallel-tree implementation.

pub use tree_folding::fold_reducer as fold_reducer;

pub mod parallel_tree;

pub use circuits::{
    hypernova::{self}, // uses same StepCircuit trait as Nova
    nova::{self, StepCircuit},
    supernova::{self, NonUniformCircuit},
};
pub use provider::{pedersen, poseidon::poseidon_config, zeromorph};

pub(crate) const LOG_TARGET: &str = "nexus-nova";
