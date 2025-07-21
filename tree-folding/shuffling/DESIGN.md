# Card Shuffling Proof Module - Engineering Design

## Overview

This module implements a zero-knowledge proof system for verifying that a deck of 52 ElGamal-encrypted cards has been properly shuffled. The proof ensures that the output is a valid permutation of the input without revealing the permutation itself.

## Two-Curve System Architecture

This implementation uses a two-curve system to handle the elliptic curve operations efficiently within the constraint system:

### Primary Curve (BN254)
- **Role**: The main curve over which the R1CS constraint system operates
- **Field**: The circuit's constraint system works in BN254's scalar field
- **Usage**: All R1CS constraints and field arithmetic happen in this field

### Secondary Curve (Grumpkin or similar)
- **Role**: The actual curve where ElGamal encryption operations occur
- **Relationship**: Forms a cycle with BN254 where:
  - BN254.ScalarField = SecondCurve.BaseField
  - BN254.BaseField = SecondCurve.ScalarField
- **Usage**: ElGamal ciphertexts (c1, c2) are points on this curve

### Why Two Curves?

1. **Native vs Non-Native Arithmetic**: When verifying ElGamal operations inside a SNARK, we need to perform elliptic curve arithmetic. If we used BN254 for both the circuit and the ElGamal operations, we'd be doing BN254 arithmetic inside BN254 field arithmetic, which is extremely expensive.

2. **Curve Cycles**: By using a curve cycle, the secondary curve's base field matches the primary curve's scalar field. This means:
   - ElGamal points can be represented as field elements in the constraint system
   - Scalar multiplications on the secondary curve become native field operations
   - No expensive non-native field arithmetic is required

3. **Efficient Implementation**: Operations like `EmulatedFpVar` are used to represent the secondary curve's scalar field elements within the primary curve's constraint system, enabling efficient constraint generation.

### Key Operations in Circuit

The core constraint patterns for verifying elliptic curve operations are straightforward:

```rust
// Verify: g_out = g1 + r * g2
let out = g1 + g2.scalar_mul_le(r_bits.iter())?;
out.enforce_equal(&g_out)?;
```

This pattern enables efficient verification of:
- ElGamal encryption: `c1 = m + r*G, c2 = r*pk`
- Re-randomization: `c1' = c1 + r'*G, c2' = c2 + r'*pk`
- Partial decryption: `c2' = c2 - s*c1`

## ElGamal Encryption Scheme

### 1. Encryption Circuit

#### 1.1 Nominal Math
For one card $(m_0, m_1) \in G^2$:

$$r \xleftarrow{\$} F_r, \quad R = r \cdot g, \quad c_1 = m_0 + R, \quad P = r \cdot pk, \quad c_2 = m_1 + P$$

The prover should keep $r$ secret but output $(c_1, c_2)$.

#### 1.2 Circuit View

| Signal | Public/Private | Gadget(s) |
|--------|---------------|-----------|
| $m_0 = (x_{m0}, y_{m0})$ | public | supplied as inputs |
| $m_1 = (x_{m1}, y_{m1})$ | public or "commit-then-reveal" | |
| $pk = (x_{pk}, y_{pk})$ | public | hard-coded in instance |
| $r$ | private | scalar witness |
| $R = r \cdot g$ | private point | ▢ FixedBaseMul($r$, $g$) |
| $c_1$ | public | ▢ EdwardsAdd($m_0$, $R$) |
| $P = r \cdot pk$ | private point | ▢ VarBaseMul($r$, $pk$) |
| $c_2$ | public | ▢ EdwardsAdd($m_1$, $P$) |

**Optimization tip**: If you publish just $(c_1, c_2)$ on-chain and keep $(m_0, m_1)$ private until reveal time, you can replace the first addition with a commitment gadget.

#### 1.3 Pseudo-code Skeleton

```rust
// Inputs: xm0, ym0, xm1, ym1, xpk, ypk (all field elements)
signal private r;

// fixed-base mul
point R = FixedBaseMul(r);        // (xR, yR)

// c1 = m0 + R
point c1 = EdwardsAdd((xm0, ym0), R);

// variable-base mul: P = r * pk
point P = VarBaseMul(r, (xpk, ypk));

// c2 = m1 + P
point c2 = EdwardsAdd((xm1, ym1), P);

// expose c1, c2 as public outputs
```

### 2. Single-share Partial Decryption Circuit

A player $P_i$ proves she subtracted $s_i R$ correctly.

#### 2.1 Nominal Math
Input ciphertext $(c_1, c_2)$, secret share $s_i$:

$$c_2' = c_2 - s_i \cdot c_1$$

Publish $(c_1, c_2')$ and a proof.

#### 2.2 Circuit View

| Signal | Public/Private | Gadget |
|--------|---------------|--------|
| $(c_1, c_2)$ | public | instance inputs |
| $s_i$ | private | scalar witness |
| $S = s_i \cdot c_1$ | private point | ▢ VarBaseMul($s_i$, $c_1$) |
| $c_2'$ | public | ▢ EdwardsSub($c_2$, $S$) |

The circuit enforces: $c_2' + S = c_2$

#### 2.3 Pseudo-code Skeleton

```rust
signal private s;          // the player's secret share

// multiply share with c1
point S = VarBaseMul(s, c1);

// new second component
point c2_prime = EdwardsSub(c2, S);

// expose c2_prime; verifier checks chain of decryptions off-circuit
```

### 3. Re-randomization for Shuffling

For shuffling, we add a new layer of encryption on top of existing ciphertexts. Given an encrypted card $(c_1, c_2)$:

$$r' \xleftarrow{\$} F_r, \quad c_1' = c_1 + r' \cdot g, \quad c_2' = c_2 + r' \cdot pk_{shuffler}$$

This maintains the homomorphic property while hiding the permutation.

## Module Location

`tree-folding/shuffling/`

## Core Components

### 1. Data Structures

```rust
// Input structure
pub struct EncryptedDeck<C: CurveGroup> {
    pub cards: Vec<ElGamalCiphertext<C>>, // 52 encrypted cards
}

// ElGamal ciphertext representation
pub struct ElGamalCiphertext<C: CurveGroup> {
    pub c1: C,
    pub c2: C,
}

// ElGamal key pair for the shuffler
pub struct ElGamalKeys<C: CurveGroup> {
    pub private_key: C::ScalarField,  // x
    pub public_key: C,                 // Y = xG
}

// Output structure from prove_as_subprotocol
pub struct ShuffleProof<F: PrimeField, C: CurveGroup> {
    pub input_deck: EncryptedDeck<C>,
    pub shuffled_deck: EncryptedDeck<C>,
    pub random_values: Vec<F>, // 52 Poseidon-generated values
    pub permutation: Vec<usize>, // The actual permutation applied
}

// Setup parameters (computed once, reused for all proofs)
pub struct ShuffleSetup<F: PrimeField> {
    pub r1cs_matrices: R1CSMatrices<F>,
    pub groth16_pk: Option<ProvingKey<F>>,
    pub spartan_pp: Option<SpartanPreprocessing<F>>,
    pub constraint_count: usize,
    pub public_input_count: usize,
}

// Implement AllocVar trait for in-circuit allocation
impl<F: PrimeField, C: CurveGroup> AllocVar<ShuffleProof<F, C>, F> for ShuffleProofVar<F, C> {
    // Implementation details...
}
```

### 2. Setup Phase

#### `setup`
One-time setup that generates reusable parameters:

```rust
#[tracing::instrument(target = "shuffle::setup", skip_all)]
pub fn setup<F: PrimeField, C: CurveGroup>(
    proof_system: ProofSystem,
) -> Result<ShuffleSetup<F>, Error> {
    let start = Instant::now();
    
    // Create constraint system with symbolic inputs
    let cs = ConstraintSystemRef::new_ref();
    
    // Generate circuit with dummy values to extract structure
    let dummy_deck = generate_dummy_deck::<C>();
    let dummy_seed = F::from(1u64);
    let dummy_proof = prove_as_subprotocol(dummy_seed, dummy_deck)?;
    
    generate_circuit(cs.clone(), &dummy_proof)?;
    
    // Extract R1CS matrices
    let matrices = cs.to_matrices()?;
    let constraint_count = cs.num_constraints();
    let public_input_count = cs.num_public_inputs();
    
    tracing::info!(target = "shuffle_setup", 
        "Circuit has {} constraints, {} public inputs", 
        constraint_count, public_input_count
    );
    
    // Generate proof system specific parameters
    let (groth16_pk, spartan_pp) = match proof_system {
        ProofSystem::Groth16 => {
            let (pk, vk) = Groth16::setup(cs.clone(), &mut rng)?;
            (Some(pk), None)
        },
        ProofSystem::Spartan => {
            let pp = Spartan::preprocess(&matrices)?;
            (None, Some(pp))
        },
        ProofSystem::Both => {
            let (pk, vk) = Groth16::setup(cs.clone(), &mut rng)?;
            let pp = Spartan::preprocess(&matrices)?;
            (Some(pk), Some(pp))
        },
    };
    
    let setup_time = start.elapsed();
    tracing::info!(target = "shuffle_setup", "Setup completed in {:?}", setup_time);
    
    Ok(ShuffleSetup {
        r1cs_matrices: matrices,
        groth16_pk,
        spartan_pp,
        constraint_count,
        public_input_count,
    })
}
```

### 3. Main Functions

#### `prove_as_subprotocol`
Performs the shuffling operation outside the SNARK:

```rust
#[tracing::instrument(target = "shuffle::subprotocol", skip(input_deck, shuffler_keys))]
pub fn prove_as_subprotocol<F: PrimeField, C: CurveGroup>(
    seed: F,
    input_deck: EncryptedDeck<C>,
    shuffler_keys: &ElGamalKeys<C>,
) -> Result<ShuffleProof<F, C>, Error> {
    // 1. Generate 52 random values using Poseidon with seed
    // 2. Generate 52 randomness values r'_i for re-randomization
    // 3. Add encryption layer to each card:
    //    - New c1 = c1 + r'_i * G
    //    - New c2 = c2 + r'_i * Y (where Y is shuffler's public key)
    // 4. Create associated list: [(re_randomized_card_i, random_i)]
    // 5. Sort by random values to get permutation
    // 6. Apply permutation to get shuffled deck
    // 7. Return ShuffleProof with all components
}
```

**Steps:**
1. Initialize Poseidon hasher with the seed
2. Generate 52 random field elements for sorting
3. Generate 52 randomness values for re-randomization
4. Re-randomize each encrypted card by adding a new encryption layer
5. Create tuples of (re_randomized_card, random_value)
6. Sort tuples by random_value
7. Extract the permuted deck and permutation indices
8. Return proof structure

#### `generate_circuit`
Builds the R1CS constraint system for verification:

```rust
#[tracing::instrument(target = "shuffle::circuit", skip_all)]
pub fn generate_circuit<F: PrimeField, C: CurveGroup>(
    cs: ConstraintSystemRef<F>,
    proof: &ShuffleProof<F, C>,
) -> Result<(), SynthesisError> {
    // 1. Allocate witnesses
    // 2. Verify Poseidon random generation
    // 3. Implement grand product argument for multiset equivalence
    // 4. Enforce permutation constraints
}
```

**Circuit Logic:**
1. **Witness Allocation**: Allocate input deck, shuffled deck, and random values
2. **Random Value Verification**: Verify that random values were correctly generated from seed using Poseidon
3. **Multiset Equivalence**: Use grand product argument to prove:
   - Product(input_cards[i] + α) = Product(shuffled_cards[i] + α)
   - Where α is a random challenge
4. **Consistency Check**: Verify that shuffled deck matches the claimed permutation

#### `prove_with_setup`
Main entry point that uses precomputed setup:

```rust
#[tracing::instrument(target = "shuffle::prove", skip(input_deck, shuffler_keys, setup))]
pub fn prove_with_setup<F: PrimeField, C: CurveGroup>(
    seed: F,
    input_deck: EncryptedDeck<C>,
    shuffler_keys: &ElGamalKeys<C>,
    setup: &ShuffleSetup<F>,
    proof_system: ProofSystem,
) -> Result<(Proof, ProofMetrics), Error> {
    let mut metrics = ProofMetrics::default();
    let total_start = Instant::now();
    
    // 1. Call prove_as_subprotocol
    let start = Instant::now();
    let shuffle_proof = prove_as_subprotocol(seed, input_deck, shuffler_keys)?;
    metrics.witness_synthesis_time = start.elapsed();
    
    // 2. Create constraint system with witnesses
    let start = Instant::now();
    let cs = ConstraintSystemRef::new_ref();
    generate_circuit(cs.clone(), &shuffle_proof)?;
    
    // Verify constraint count matches setup
    assert_eq!(cs.num_constraints(), setup.constraint_count, 
        "Circuit structure changed since setup!");
    metrics.constraint_generation_time = start.elapsed();
    
    // 3. Generate proof using precomputed parameters
    let start = Instant::now();
    let proof = match proof_system {
        ProofSystem::Groth16 => {
            let pk = setup.groth16_pk.as_ref()
                .ok_or("Groth16 proving key not found in setup")?;
            Groth16::prove_with_pk(pk, cs.clone(), &shuffle_proof)?
        },
        ProofSystem::Spartan => {
            let pp = setup.spartan_pp.as_ref()
                .ok_or("Spartan preprocessing not found in setup")?;
            Spartan::prove_with_pp(pp, cs.clone(), &shuffle_proof)?
        },
    };
    metrics.proof_generation_time = start.elapsed();
    metrics.proof_size_bytes = proof.serialized_size();
    
    metrics.total_time = total_start.elapsed();
    metrics.constraint_count = setup.constraint_count;
    metrics.witness_count = cs.num_witness_variables();
    
    Ok((proof, metrics))
}

// Convenience function without setup (for testing/single use)
pub fn prove<F: PrimeField, C: CurveGroup>(
    seed: F,
    input_deck: EncryptedDeck<C>,
    shuffler_keys: &ElGamalKeys<C>,
    proof_system: ProofSystem,
) -> Result<(Proof, ProofMetrics), Error> {
    let setup = setup::<F, C>(proof_system)?;
    prove_with_setup(seed, input_deck, shuffler_keys, &setup, proof_system)
}
```

### 4. Grand Product Argument Implementation

The grand product argument ensures multiset equivalence between input and output:

```rust
// In-circuit implementation
#[tracing::instrument(target = "shuffle::grand_product", skip_all)]
fn verify_grand_product<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    input_set: &[FpVar<F>],
    output_set: &[FpVar<F>],
    challenge: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Compute: ∏(input_i + α) = ∏(output_i + α)
    let input_product = input_set.iter()
        .fold(Ok(FpVar::one()), |acc, elem| {
            acc.and_then(|a| a.mul(&(elem + challenge)))
        })?;
    
    let output_product = output_set.iter()
        .fold(Ok(FpVar::one()), |acc, elem| {
            acc.and_then(|a| a.mul(&(elem + challenge)))
        })?;
    
    input_product.enforce_equal(&output_product)?;
    Ok(())
}
```

### 5. Integration with Proof Systems

Support for both Groth16 and Spartan with setup reuse:

```rust
pub enum ProofSystem {
    Groth16,
    Spartan,
    Both, // For benchmarking both systems
}

impl ProofSystem {
    pub fn generate_proof_with_pk<F: PrimeField>(
        &self,
        cs: ConstraintSystemRef<F>,
        pk: &ProvingKey<F>,
        witnesses: Vec<F>,
    ) -> Result<Proof, Error> {
        // Use precomputed proving key
    }
    
    pub fn generate_proof_with_pp<F: PrimeField>(
        &self,
        cs: ConstraintSystemRef<F>,
        pp: &SpartanPreprocessing<F>,
        witnesses: Vec<F>,
    ) -> Result<Proof, Error> {
        // Use precomputed preprocessing
    }
}
```

## Performance Metrics

### Constraint Analysis for BN254

For a 52-card shuffle using BN254 curve:

```rust
pub struct ConstraintMetrics {
    // Witness allocation
    pub card_witnesses: usize,              // 52 * 2 (c1, c2) = 104 curve points
    pub random_value_witnesses: usize,      // 52 field elements
    
    // Constraint counts
    pub poseidon_constraints: usize,        // ~52 * 220 = 11,440 (220 per hash)
    pub grand_product_constraints: usize,   // 52 multiplications + 1 equality = 53
    pub curve_arithmetic_constraints: usize, // 52 * 2 * 3 = 312 (native field ops)
    pub total_constraints: usize,           // ~11,805
}
```

### Performance Measurement Points

```rust
pub struct ProofMetrics {
    // Phase timings
    pub setup_time: Option<Duration>,       // One-time setup cost
    pub constraint_generation_time: Duration,
    pub witness_synthesis_time: Duration,
    pub commitment_time: Duration,
    pub polynomial_construction_time: Duration,
    pub proof_generation_time: Duration,
    pub total_time: Duration,
    
    // Additional metrics
    pub constraint_count: usize,
    pub witness_count: usize,
    pub proof_size_bytes: usize,
}
```

### Expected Performance Characteristics

For BN254 with 52 cards:

**Setup (one-time):**
- Groth16 trusted setup: ~2-3 seconds
- Spartan preprocessing: ~500-800ms
- R1CS matrix extraction: ~100-200ms

**Per-proof (with setup reuse):**

**Groth16:**
- Constraint generation: ~10-20ms (with setup)
- Witness synthesis: ~20-40ms
- Proof generation: ~200-300ms (using precomputed CRS)
- Proof size: ~192 bytes
- Total: ~250-350ms

**Spartan:**
- Constraint generation: ~10-20ms (with setup)
- Witness synthesis: ~20-40ms
- Polynomial construction: ~100-150ms
- Proof generation: ~250-350ms (using preprocessing)
- Proof size: ~10-20 KB
- Total: ~400-550ms

## Binary Executable

### Benchmarking Binary

Create `tree-folding/shuffling/benches/shuffle_bench.rs`:

```rust
use std::time::Instant;
use ark_bn254::{Bn254, Fr, G1Projective};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    /// Proof system to use
    #[structopt(long, default_value = "groth16")]
    proof_system: String,
    
    /// Number of iterations for averaging
    #[structopt(long, default_value = "10")]
    iterations: usize,
    
    /// Include setup time in measurements
    #[structopt(long)]
    include_setup: bool,
    
    /// Output format (json or human)
    #[structopt(long, default_value = "human")]
    format: String,
}

fn main() {
    let args = Cli::from_args();
    
    // Initialize logger
    tracing_subscriber::fmt::init();
    
    // Generate test deck and keys
    let deck = generate_random_deck::<G1Projective>();
    let shuffler_keys = generate_shuffler_keys::<G1Projective>();
    let seed = Fr::from(42u64);
    
    // Determine proof system
    let proof_system = match args.proof_system.as_str() {
        "spartan" => ProofSystem::Spartan,
        "both" => ProofSystem::Both,
        _ => ProofSystem::Groth16,
    };
    
    // Run setup once
    let setup_start = Instant::now();
    let setup = setup::<Fr, G1Projective>(proof_system).expect("Setup failed");
    let setup_time = setup_start.elapsed();
    
    tracing::info!(target = "shuffle_bench", 
        "Setup completed in {:?} ({} constraints)", 
        setup_time, setup.constraint_count
    );
    
    let mut all_metrics = Vec::new();
    
    for i in 0..args.iterations {
        tracing::info!(target = "shuffle_bench", "Running iteration {}/{}", i+1, args.iterations);
        
        let start = Instant::now();
        let (_, mut metrics) = prove_with_setup(
            Fr::from((i + 42) as u64), // Vary seed per iteration
            deck.clone(),
            &shuffler_keys,
            &setup,
            proof_system
        ).expect("Proof generation failed");
        
        if args.include_setup && i == 0 {
            metrics.setup_time = Some(setup_time);
        }
        
        all_metrics.push(metrics);
        
        tracing::info!(target = "shuffle_bench", "Iteration {} took {:?}", i+1, start.elapsed());
    }
    
    // Output results
    match args.format.as_str() {
        "json" => output_json(&all_metrics),
        _ => output_human_readable(&all_metrics),
    }
}

fn output_human_readable(metrics: &[ProofMetrics]) {
    tracing::info!(target = "shuffle_bench", "\n=== Shuffle Proof Benchmarks ===\n");
    
    if let Some(setup_time) = metrics.first().and_then(|m| m.setup_time) {
        tracing::info!(target = "shuffle_bench", "Setup Phase:");
        tracing::info!(target = "shuffle_bench", "  One-time setup: {:?}", setup_time);
    }
    
    tracing::info!(target = "shuffle_bench", "Per-Proof Metrics (averaged over {} runs):", metrics.len());
    
    let avg_constraint_gen = average_duration(metrics.iter().map(|m| m.constraint_generation_time));
    let avg_witness_synth = average_duration(metrics.iter().map(|m| m.witness_synthesis_time));
    let avg_proof_gen = average_duration(metrics.iter().map(|m| m.proof_generation_time));
    let avg_total = average_duration(metrics.iter().map(|m| m.total_time));
    
    tracing::info!(target = "shuffle_bench", "  Constraint generation: {:?}", avg_constraint_gen);
    tracing::info!(target = "shuffle_bench", "  Witness synthesis: {:?}", avg_witness_synth);
    tracing::info!(target = "shuffle_bench", "  Proof generation: {:?}", avg_proof_gen);
    tracing::info!(target = "shuffle_bench", "  Total time: {:?}", avg_total);
    
    tracing::info!(target = "shuffle_bench", "Circuit Statistics:");
    tracing::info!(target = "shuffle_bench", "  Constraints: {}", metrics[0].constraint_count);
    tracing::info!(target = "shuffle_bench", "  Witnesses: {}", metrics[0].witness_count);
    tracing::info!(target = "shuffle_bench", "  Proof size: {} bytes", metrics[0].proof_size_bytes);
}
```

### Cargo Configuration

Add to `tree-folding/Cargo.toml`:

```toml
[[bin]]
name = "shuffle-bench"
path = "shuffling/benches/shuffle_bench.rs"

[dependencies]
ark-bn254 = { version = "0.4.0" }
structopt = "0.3"
serde_json = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
```

### Usage

```bash
# Run with Groth16 (default)
cargo run --release --bin shuffle-bench

# Run with Spartan
cargo run --release --bin shuffle-bench -- --proof-system spartan

# Run 100 iterations with setup time included
cargo run --release --bin shuffle-bench -- --iterations 100 --include-setup

# Compare both proof systems
cargo run --release --bin shuffle-bench -- --proof-system both --format json

# With detailed logging
RUST_LOG=shuffle=debug,shuffle_bench=debug cargo run --release --bin shuffle-bench

# With trace-level instrumentation
RUST_LOG=shuffle=trace,shuffle_bench=trace cargo run --release --bin shuffle-bench
```