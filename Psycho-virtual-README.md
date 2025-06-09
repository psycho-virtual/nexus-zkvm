
## Building Project

```rust
cd nova && cargo build
```

## Running Tests

```rust
cd nova
RUST_LOG=debug cargo test ccs -- --nocapture | ../pretty_logs.py
RUST_LOG=debug cargo test tree_folding -- --nocapture | ../pretty_logs.py
RUST_LOG=debug cargo test parallel_tree -- --nocapture | ../pretty_logs.py
```

You need to run specific tests

These are the tests that you should run

## Running Integration Test

``rust
cd nova
RUST_LOG=DEBUG cargo run --example parallel_tree_fold_example --release
```