# Hypernova Folding

This directory contains implementations of various folding schemes compatible with Nova, specifically designed for use with Hypernova.

## Code Structure

The Hypernova folding directory is organized as follows:

```
hypernova/
├── accs_folding.rs      - Atomic CCS folding implementation
├── cyclefold/           - Cyclefold implementation
│   ├── mod.rs           - Module definitions
│   └── nimfs/           - NIMFS in cyclefold context
├── ml_sumcheck/         - Multi-linear sumcheck implementation
│   ├── data_structures.rs
│   ├── mod.rs
│   ├── protocol/        - Protocol implementation
│   │   ├── mod.rs
│   │   ├── prover.rs    - Prover implementation
│   │   └── verifier.rs  - Verifier implementation
│   └── tests.rs         - Tests for sumcheck
├── mod.rs               - Module definitions
├── nimfs.rs             - NIMFS implementation
└── README.md            - This file
```

## Key Components

1. **ACCS Folding**: Implements the Atomic CCS folding protocol based on Construction 1 from the KiloNova paper.

2. **NIMFS**: Nova's Interactive Multi-function Folding Scheme implementation, which is the core folding scheme for Hypernova.

3. **ML Sumcheck**: The multi-linear sumcheck protocol implementation, which is used by both ACCS and NIMFS folding.

4. **Cyclefold**: Implementation of cyclefold, which optimizes folding for cyclic circuits.

## Running Tests

### NIMFS Tests

Run the standard NIMFS folding test:
```bash
cargo test folding::hypernova::nimfs::tests::prove_verify_as_subprotocol -- --nocapture
```

Run the NIMFS benchmark test (matching latticefold format):
```bash
cargo test folding::hypernova::nimfs::tests::test_full_folding -- --nocapture
```

### ACCS Folding Tests

Run the standard ACCS folding test:
```bash
cargo test folding::hypernova::accs_folding::tests::test_accs_folding_protocol -- --nocapture
```

Run the ACCS folding benchmark test (matching latticefold format):
```bash
cargo test folding::hypernova::accs_folding::tests::test_full_accs_folding -- --nocapture
```

### All Hypernova Tests

Run all Hypernova tests:
```bash
cargo test folding::hypernova -- --nocapture
```

## Benchmarking

The benchmark tests provide detailed timing information and statistics about the folding operations. These tests are designed to match the format of the latticefold tests to facilitate easy comparison:

- Test setup time
- Witness and constraint system dimensions
- Folding performance
- Proof element counts
- Sigma and theta vector sizes

## Implementation Notes

1. **ACCS Folding**:
   - Uses two sumcheck proofs (for polynomial f and g)
   - Creates a final combined folded instance

2. **NIMFS**:
   - Uses a single sumcheck proof 
   - Optimized for linear combinations of CCS instances
   - Core protocol for Hypernova folding

Both implementations use BLS12-381 elliptic curve and Poseidon hash for generating challenges.

## Future Improvements

- Add more comprehensive benchmarks comparing folding schemes
- Optimize matrix operations for large-scale folding
- Add cycle-specific optimizations for cyclefold