//! RS (Rao-Sandelius) Shuffling Algorithm Implementation
//!
//! This module implements the stable-partition shuffle with bucket-local constraints
//! and grand-product permutation checks.

/// Number of ciphertexts (deck size)
pub const N: usize = 52;

/// Depth of shuffle levels
pub const LEVELS: usize = 5;

/// Total number of split bits needed (N * LEVELS)
pub const BITS_NEED: usize = N * LEVELS; // 260 split bits total

pub mod circuit;
pub mod data_structures;
pub mod permutation;
pub mod witness_preparation;

pub use circuit::{verify_row_constraints, RSShuffleCircuit};
pub use data_structures::{SortedRow, UnsortedRow, WitnessData};
pub use witness_preparation::prepare_witness_data;
