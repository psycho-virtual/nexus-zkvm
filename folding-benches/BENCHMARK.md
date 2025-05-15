# Folding Benchmarks - Benchmark Guide

This document provides instructions for running the benchmarks that compare ACCS folding and NIMFS folding performance.

## Available Benchmarks

The benchmarking suite includes the following:

1. **ACCS Folding Benchmarks**
   - Prove time measurements
   - Verify time measurements
   - Memory usage tracking

2. **NIMFS Folding Benchmarks**
   - Prove time measurements
   - Verify time measurements
   - Memory usage tracking

## Running the Benchmarks

### Option 1: Run All Benchmarks (Recommended)

The simplest way to run all benchmarks and generate comparison reports is to use the provided runner:

```bash
# Build and run all benchmarks, generating comprehensive reports
cargo run --release --bin run_all
```

This will:
1. Run all benchmarks
2. Generate CSV data of the results
3. Create visualization HTML files for comparing performance
4. Save all results to the `./results` directory

### Option 2: Run Individual Benchmarks

You can also run individual benchmarks:

```bash
# Run ACCS folding benchmarks only
cargo bench --bench accs_folding

# Run NIMFS folding benchmarks only
cargo bench --bench nimfs_folding

# Run with flamegraph profiling (requires Linux or specific setup on macOS)
cargo bench --bench accs_folding -- --profile-time=*
```

## Benchmark Parameters

The benchmarks run with the following parameters:

- Circuit sizes: 6400, 22000, 55000, 120000, 250000 constraints
- Each benchmark runs with 10 samples
- Warm-up time: 1 second
- Measurement time: 5 seconds

You can modify these parameters in the respective benchmark files.

## Analyzing Results

After running the benchmarks, you can find the results in:

1. **Criterion Output**: `target/criterion/` - contains raw benchmark data
2. **CSV Results**: `./results/benchmark_results.csv` - contains parsed metrics
3. **HTML Visualizations**: `./results/*.html` - interactive plots comparing performance

The HTML visualizations allow you to:
- Compare proving time between ACCS and NIMFS
- Compare verification time between ACCS and NIMFS
- Compare memory usage between the two approaches
- Observe scaling behavior as circuit size increases

## Expected Findings

When comparing ACCS folding vs NIMFS folding, you can expect to observe:

1. **Prove Time**: ACCS folding typically requires more computation due to the additional sumcheck protocol, which may lead to longer proving times for complex circuits.

2. **Verify Time**: ACCS verification is structurally different and may have different scaling properties.

3. **Memory Usage**: The memory profile of ACCS vs NIMFS differs due to different data structures and protocol steps.

4. **Scaling Behavior**: Observe how each folding method scales with increasing circuit size. The slopes of these curves reveal which method is more efficient at scale.

## Customizing the Benchmarks

To customize the benchmarks for your specific use case:

1. Modify `shared/mod.rs` to add your own circuit implementations
2. Update the constraint sizes in `DEFAULT_CONSTRAINT_SIZES` array
3. Customize the number of samples and warm-up times in the benchmarks