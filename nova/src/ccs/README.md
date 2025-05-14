# Customizable Constraint Systems (CCS) Module

This module provides implementation of Customizable Constraint Systems (CCS) and related protocols as described in the HyperNova papers. CCS is a generalization of R1CS (Rank-1 Constraint Systems) that allows for more flexible constraint systems.

## Overview

The CCS module implements several key components:

- **CCS Shape**: Defines the structure of constraints in a customizable format
- **CCS Instance**: Represents a specific instance of a CCS problem with concrete values
- **LCCS (Linearized CCS)**: Supports efficient instance folding through linearization
- **ACCS (Atomic CCS)**: Provides relaxed form of CCS for efficient folding without cross-terms

## Directory Structure

- `mod.rs`: Core CCS data structures and relationships
- `mle.rs`: Helper code for multilinear extension operations
- `lccs_folding.rs`: Implementation of LCCS folding operations using multi-linear sum-check

## Key Data Structures

### CCSShape

The fundamental structure that defines a CCS instance:

```rust
pub struct CCSShape<G: CurveGroup> {
    pub num_constraints: usize,    // 'm' in the CCS/HyperNova papers
    pub num_vars: usize,           // Witness length, 'm - l - 1'
    pub num_io: usize,             // Length of public input 'X', 'l + 1'
    pub num_matrices: usize,       // Number of matrices, 't'
    pub num_multisets: usize,      // Number of multisets, 'q'
    pub max_cardinality: usize,    // Max cardinality of multisets, 'd'
    pub Ms: Vec<SparseMatrix<G::ScalarField>>,  // Constraint matrices
    pub cSs: Vec<(G::ScalarField, Vec<usize>)>, // Multisets of selector indices
}
```

### CCSWitness

Holds the witness for a CCS instance:

```rust
pub struct CCSWitness<G: CurveGroup> {
    pub W: Vec<G::ScalarField>,
}
```

### CCSInstance

Represents a complete CCS instance with commitment to witness:

```rust
pub struct CCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    pub commitment_W: C::Commitment,
    pub X: Vec<G::ScalarField>,  // X is assumed to start with a `ScalarField::ONE`
}
```

### LCCSInstance

A linearized CCS instance with evaluation points:

```rust
pub struct LCCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    pub commitment_W: C::Commitment,
    pub X: Vec<G::ScalarField>,
    pub rs: Vec<G::ScalarField>,  // (Random) evaluation point
    pub vs: Vec<G::ScalarField>,  // Evaluation targets
}
```

## Key Operations

### Instance Folding

The module implements instance folding operations that allow combining multiple instances efficiently:

- `fold()`: Combines two instances into one (basic folding)
- `fold_lccs()`: Specialized folding for LCCS instances
- `verify_folded_instance()`: Verifies that a folded instance is valid

## Running Tests

The module includes comprehensive tests for all functionality. To run these tests:

```bash
# Run all CCS tests
cargo test --package nexus-nova --lib ccs

# Run specific test file
cargo test --package nexus-nova --lib ccs::lccs_fold

# Run a specific test
cargo test --package nexus-nova --lib ccs::tests::test_fold_lccs
```

## Key Test Cases

- `test_fold_lccs` (in `mod.rs`): Tests the LCCS instance folding protocol with a focus on verifying that the folded instance satisfies the CCS relation.
  
- `test_sumcheck_lccs_folding` (in `lccs_folding.rs`): Tests the complete LCCS folding with sum-check protocol including verification of folding homomorphic properties.

- `test_multi_fold_lccs`: Tests folding multiple LCCS instances sequentially to ensure consistency across multiple folding operations.

- `test_r1cs_to_ccs`: Tests conversion from R1CS to CCS to ensure proper transformation between constraint systems.

- `is_satisfied` and `is_satisfied_linearized`: Tests CCS constraint satisfaction on specific instances.

## Important Implementation Details

When implementing or fixing issues with LCCS folding:

1. **Vector ordering consistency**: It's critical that the order of elements in the `z` vector is consistent between `is_satisfied_linearized` and `compute_sigmas`. Both should use `[instance.X.as_slice(), witness.W.as_slice()]`.

2. **Polynomial evaluation**: Make sure to use the same method (`vec_to_mle` vs `vec_to_ark_mle`) consistently for polynomial evaluation.

3. **Witness folding**: The witness folding should follow the same pattern as the folded instance, using the square of rho for the second witness.

4. **Verification**: The `verify_folded_instance` function performs several checks:
   - Commitment homomorphism
   - u value and X values folding
   - vs values (must match evaluation at the merged evaluation point)
   - CCS relation satisfaction

## Documentation

For more detailed information about the CCS module and its implementation, please refer to:

1. The docstrings in the source code
2. The HyperNova paper: [https://eprint.iacr.org/2023/573](https://eprint.iacr.org/2023/573)
3. The KiloNova paper for ACCS: [https://eprint.iacr.org/2023/745](https://eprint.iacr.org/2023/745)
