# Folding Benchmarks

This crate provides simplified benchmarks for comparing the performance of different folding protocols in the HyperNova project:

1. **ACCS Folding** - Atomic CCS based folding from the KiloNova paper
2. **NIMFS Folding** - Non-Interactive MLE-based Folding of Spartan, the original folding method

## Running Benchmarks

To run the benchmarks, use the following commands:

```bash
# Run ACCS folding benchmarks
cargo run -p folding-benches --bin accs_folding

# Run NIMFS folding benchmarks
cargo run -p folding-benches --bin nimfs_folding
```

## Benchmark Metrics

The benchmarks measure:
- Proving time (milliseconds)
- Verification time (milliseconds)

Results are displayed directly in the console in a simple table format.

## Simplified Structure

These benchmarks have been simplified to avoid performance issues:

1. **No Criterion Framework**: Using direct timing measurements with `std::time::Instant` instead of Criterion
2. **Limited Circuit Size**: Only running with 4 constraints to prevent system freezes with larger circuits
3. **Simple Output**: Plain text table showing timing results in milliseconds

## Dynamic SRS Scaling

The benchmarks automatically scale the SRS (Structured Reference String) size based on the circuit size to ensure:
1. Appropriately sized SRS to avoid "TooManyCoefficients" errors
2. Optimized setup for each circuit size

## Configuration

The benchmarks can be further configured by modifying:
- `benches/shared/mod.rs` - Default circuit sizes and SRS degree calculation
- `benches/accs_folding.rs` and `benches/nimfs_folding.rs` - Protocol-specific benchmarks

## Parameters

The benchmarks use the following parameters by default:
- Sample size: 10 runs per circuit size
- Results are averaged across all runs