# Profiling Guide for Shuffling Performance Issues

## Quick Start: Finding the Bottleneck

### 1. **Run the Enhanced Test**
```bash
cd tree-folding/shuffling
RUST_LOG=shuffle=debug cargo test test_poseidon_hash_2_points -- --nocapture
```

This will show:
- Config generation time
- Native vs constraint generation comparison
- Breakdown of time spent in each phase

### 2. **Use Cargo Flamegraph** (Recommended)
```bash
# Install
cargo install flamegraph

# Run with sudo on macOS (for dtrace)
sudo cargo flamegraph --test test_poseidon_hash_2_points
# Output: flamegraph.svg

# Or for release mode (more realistic performance)
sudo cargo flamegraph --release --test test_poseidon_hash_2_points
```

### 3. **Use Built-in Arkworks Profiling**
```rust
use ark_std::{start_timer, end_timer};

let timer = start_timer!(|| "Poseidon config generation");
let config = poseidon_config::<Fr>();
end_timer!(timer);
```

### 4. **Memory Profiling with Valgrind** (Linux)
```bash
cargo build --release --test test_poseidon_hash_2_points
valgrind --tool=massif --massif-out-file=massif.out target/release/deps/test_poseidon_hash_2_points-*
ms_print massif.out > memory_profile.txt
```

### 5. **CPU Profiling on macOS with Instruments**
```bash
# Build release binary
cargo build --release --test test_poseidon_hash_2_points

# Find the test binary
find target/release/deps -name "nexus_shuffling-*" -type f | grep -v "\.d$"

# Run with Instruments
instruments -t "Time Profiler" target/release/deps/nexus_shuffling-[hash]
```

### 6. **Add Strategic Timing Points**
```rust
#[derive(Default)]
struct ProfilingData {
    poseidon_config: Duration,
    sponge_creation: Duration,
    absorb_operations: Vec<Duration>,
    squeeze_operations: Vec<Duration>,
    constraint_generation: Duration,
}

impl ProfilingData {
    fn report(&self) {
        println!("=== Profiling Report ===");
        println!("Poseidon config: {:?}", self.poseidon_config);
        println!("Sponge creation: {:?}", self.sponge_creation);
        println!("Avg absorb: {:?}", self.avg_duration(&self.absorb_operations));
        println!("Avg squeeze: {:?}", self.avg_duration(&self.squeeze_operations));
        println!("Total constraints: {:?}", self.constraint_generation);
    }
    
    fn avg_duration(&self, durations: &[Duration]) -> Duration {
        let sum: Duration = durations.iter().sum();
        sum / durations.len() as u32
    }
}
```

### 7. **Compare with Nova's Implementation**
Run the same profiling on Nova's sumcheck to compare:
```bash
cd nova
cargo test test_verify_all_sumcheck -- --nocapture
```

## Specific Things to Look For

1. **MDS Matrix Generation**: Check if `find_poseidon_ark_and_mds` is being called multiple times
2. **Constraint System Overhead**: Look for excessive cloning or allocation
3. **Field Operations**: Check if field arithmetic is using optimal implementations
4. **Memory Allocation**: Look for unnecessary allocations in hot paths

## Quick Fixes to Try

1. **Cache Poseidon Config**:
```rust
use once_cell::sync::Lazy;
static POSEIDON_CONFIG: Lazy<PoseidonConfig<Fr>> = Lazy::new(|| {
    poseidon_config::<Fr>()
});
```

2. **Enable LTO and Codegen Units**:
```toml
[profile.release]
lto = "fat"
codegen-units = 1
```

3. **Use Release Mode with Debug Info**:
```toml
[profile.bench]
inherits = "release"
debug = true
```

## Interpreting Results

- If `poseidon_config` takes 60+ seconds: The MDS generation is the bottleneck
- If constraint generation is slow but config is fast: Look at the circuit implementation
- If native operations are also slow: The field operations might not be optimized

## Next Steps

Based on profiling results:
1. If config generation is slow → Cache or precompute configs
2. If constraint generation is slow → Optimize circuit gadgets
3. If memory is high → Look for unnecessary cloning
4. If parallelism would help → Enable parallel features