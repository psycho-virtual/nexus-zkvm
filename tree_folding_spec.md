# HyperNova Tree Folding Engineering Specification

## Overview

This document specifies the implementation of HyperNova folding in a tree structure for the Nexus zkVM. The implementation will support two types of folding operations:

1. **Folding two CCS instances** - Used at leaf nodes to fold fresh CCS instances
2. **Folding two LCCS instances** - Used at inner nodes to fold linearized CCS instances

Both folding operations use the same sumcheck formula on g(x) but differ in their instance types:
- For CCS folding: All LCCS instances are zero
- For LCCS folding: All CCS instances are zero vectors

## Mathematical Foundation

### Core Sumcheck Formula

The general sumcheck polynomial g(x) for both folding types:

```
g(x) := ∑_{j∈[t],k∈[μ]} γ^((k-1)·t+j) · L_{j,k}(x) + ∑_{k∈[ν]} γ^(μ·t+k) · Q_k(x)

where:
L_{j,k}(x) := eq(r_x, x) · ∑_{y∈{0,1}^s'} M_j(x, y) · z_{1,k}(y)
Q_k(x) := eq(β, x) · ∑_{i=1}^q c_i · ∏_{j∈S_i} ∑_{y∈{0,1}^s'} M_j(x, y) · z_{2,k}(y)

T := ∑_{j∈[t],k∈[μ]} γ^((k-1)·t+j) · L_k.φ.v_j
```

### Folding Result

After sumcheck, compute:
- For each j ∈ [t], k ∈ [μ]: `σ_{j,k} = ∑_{y∈{0,1}^s'} M_j(r'_x, y) · z_{1,k}(y)`
- For each j ∈ [t], k ∈ [ν]: `θ_{j,k} = ∑_{y∈{0,1}^s'} M_j(r'_x, y) · z_{2,k}(y)`

The folded instance is computed as:
```
C ← ∑_{k∈[μ]} ρ^k · L_k.φ.C + ∑_{k∈[ν]} ρ^(μ+k) · C_k.φ.C
u ← ∑_{k∈[μ]} ρ^k · L_k.φ.u + ∑_{k∈[ν]} ρ^(μ+k) · 1
x ← ∑_{k∈[μ]} ρ^k · L_k.φ.x + ∑_{k∈[ν]} ρ^(μ+k) · C_k.φ.x
v_j ← ∑_{k∈[μ]} ρ^k · σ_{j,k} + ∑_{k∈[ν]} ρ^(μ+k) · θ_{j,k}
```

## Implementation Location

All modifications and implementations described in this specification will be made in the `nova/src/tree_folding` module of the Nexus zkVM codebase. This module will contain the HyperNova tree folding implementation with support for both CCS and LCCS folding operations.

## File Structure

```
nova/src/tree_folding/
├── mod.rs                    # Module exports and types
├── nimfs.rs                  # Multi-folding implementations  
├── sumcheck.rs               # Sumcheck protocol (prover & verifier combined)
└── circuit/                  # Circuit implementations
    ├── mod.rs                # Circuit module exports
    ├── sumcheck.rs           # Sumcheck verifier circuit implementation
    ├── lccs_verifier.rs      # LCCS folding verifier gadget
    └── ccs_verifier.rs       # CCS folding verifier gadget
```

## Core Data Structures

### 1. Multi-CCS Proof Structure

```rust
/// Proof for folding multiple CCS instances together
pub struct MultiCCSProof<G: Group> {
    /// Sumcheck proof for the folding
    pub sumcheck_proof: SumcheckProof<G::ScalarField>,
    /// Claimed evaluations σ_{j,k} for each matrix j and instance k
    pub sigmas: Vec<Vec<G::ScalarField>>,
    /// Claimed evaluations θ_{j,k} for each matrix j and instance k
    pub thetas: Vec<Vec<G::ScalarField>>,
}

impl<G: Group> MultiCCSProof<G> {
    /// Prove folding of two CCS instances into LCCS
    pub fn prove_as_subprotocol<C: PolyCommitmentScheme<G>>(
        random_oracle: &mut RO,
        vk: &G::ScalarField,
        shape: &CCSShape<G>,
        (u1, w1): (&CCSInstance<G, C>, &CCSWitness<G>),
        (u2, w2): (&CCSInstance<G, C>, &CCSWitness<G>),
    ) -> Result<(Self, (LCCSInstance<G, C>, CCSWitness<G>), G::BaseField), Error> {
        // Implementation
    }
    
    /// Verify folding of two CCS instances
    pub fn verify_as_subprotocol<C: PolyCommitmentScheme<G>>(
        &self,
        random_oracle: &mut RO,
        vk: &G::ScalarField,
        shape: &CCSShape<G>,
        U1: &CCSInstance<G, C>,
        U2: &CCSInstance<G, C>,
        U_folded: &LCCSInstance<G, C>,
    ) -> Result<(), Error> {
        // Implementation
    }
}
```

### 2. Multi-LCCS Proof Structure

```rust
/// Proof for folding multiple LCCS instances together
pub struct MultiLCCSProof<G: Group> {
    /// Sumcheck proof for the folding
    pub sumcheck_proof: SumcheckProof<G::ScalarField>,
    /// Claimed evaluations σ_{j,k} for each matrix j and instance k
    pub sigmas: Vec<Vec<G::ScalarField>>,
    /// Claimed evaluations θ_{j,k} for each matrix j and instance k
    pub thetas: Vec<Vec<G::ScalarField>>,
}

impl<G: Group> MultiLCCSProof<G> {
    /// Prove folding of two LCCS instances
    pub fn prove_as_subprotocol<C: PolyCommitmentScheme<G>>(
        random_oracle: &mut RO,
        vk: &G::ScalarField,
        shape: &CCSShape<G>,
        (U1, W1): (&LCCSInstance<G, C>, &CCSWitness<G>),
        (U2, W2): (&LCCSInstance<G, C>, &CCSWitness<G>),
    ) -> Result<(Self, (LCCSInstance<G, C>, CCSWitness<G>), G::BaseField), Error> {
        // Implementation
    }
    
    /// Verify folding of two LCCS instances
    pub fn verify_as_subprotocol<C: PolyCommitmentScheme<G>>(
        &self,
        random_oracle: &mut RO,
        vk: &G::ScalarField,
        shape: &CCSShape<G>,
        U1: &LCCSInstance<G, C>,
        U2: &LCCSInstance<G, C>,
        U_folded: &LCCSInstance<G, C>,
    ) -> Result<(), Error> {
        // Implementation
    }
}
```

### 3. Sumcheck Implementation

```rust
/// Generic sumcheck prover for tree folding
pub struct SumcheckProver<F: PrimeField> {
    /// Number of variables
    pub num_vars: usize,
    /// Degree bound
    pub degree: usize,
}

impl<F: PrimeField> SumcheckProver<F> {
    /// Run sumcheck protocol for the polynomial g(x)
    pub fn prove<RO: RandomOracle>(
        &self,
        random_oracle: &mut RO,
        polynomial: impl Fn(&[F]) -> F,
        claimed_sum: F,
    ) -> Result<SumcheckProof<F>, Error> {
        // Implementation
    }
}

/// Generic sumcheck verifier
pub struct SumcheckVerifier<F: PrimeField> {
    /// Number of variables
    pub num_vars: usize,
    /// Degree bound
    pub degree: usize,
}

impl<F: PrimeField> SumcheckVerifier<F> {
    /// Verify sumcheck proof
    pub fn verify<RO: RandomOracle>(
        &self,
        random_oracle: &mut RO,
        proof: &SumcheckProof<F>,
        claimed_sum: F,
    ) -> Result<(F, Vec<F>), Error> {
        // Returns (final_eval, evaluation_point)
    }
}

/// Utility functions for constructing sumcheck polynomials
pub mod utils {
    use super::*;
    
    /// Convert two CCS instances into the polynomial g(x) for sumcheck
    /// This sets μ=0 (no LCCS instances) and ν=2 (two CCS instances)
    pub fn ccs_to_sumcheck_polynomial<G: Group, C: PolyCommitmentScheme<G>>(
        shape: &CCSShape<G>,
        ccs1: &CCSInstance<G, C>,
        witness1: &CCSWitness<G>,
        ccs2: &CCSInstance<G, C>, 
        witness2: &CCSWitness<G>,
        gamma: G::ScalarField,
        beta: &[G::ScalarField],
    ) -> impl Fn(&[G::ScalarField]) -> G::ScalarField {
        // Returns g(x) = γ^(0·t+1) · Q_1(x) + γ^(0·t+2) · Q_2(x)
        // where Q_k(x) = eq(β, x) · ∑_{i=1}^q c_i · ∏_{j∈S_i} ∑_{y∈{0,1}^s'} M_j(x, y) · z_{2,k}(y)
        move |x: &[G::ScalarField]| {
            // Implementation
        }
    }
    
    /// Convert two LCCS instances into the polynomial g(x) for sumcheck
    /// This sets μ=2 (two LCCS instances) and ν=0 (no CCS instances)
    pub fn lccs_to_sumcheck_polynomial<G: Group, C: PolyCommitmentScheme<G>>(
        shape: &CCSShape<G>,
        lccs1: &LCCSInstance<G, C>,
        witness1: &CCSWitness<G>,
        lccs2: &LCCSInstance<G, C>,
        witness2: &CCSWitness<G>,
        gamma: G::ScalarField,
    ) -> impl Fn(&[G::ScalarField]) -> G::ScalarField {
        // Returns g(x) = ∑_{j∈[t],k∈[2]} γ^((k-1)·t+j) · L_{j,k}(x)
        // where L_{j,k}(x) = eq(r_x, x) · ∑_{y∈{0,1}^s'} M_j(x, y) · z_{1,k}(y)
        move |x: &[G::ScalarField]| {
            // Implementation
        }
    }
}

```

### 4. Circuit Gadgets

```rust
/// Gadget for verifying sumcheck proofs in-circuit
pub struct SumcheckVerifierGadget;

impl SumcheckVerifierGadget {
    /// Verify all sumcheck rounds in-circuit
    pub fn verify_all_sumcheck<G1, RO>(
        random_oracle: &mut RO::Var,
        sumcheck_evals: &[Vec<FpVar<G1::ScalarField>>],
        expected_sum_of_polynomial: FpVar<G1::ScalarField>,
        sumcheck_rounds: usize,
    ) -> Result<(FpVar<G1::ScalarField>, Vec<FpVar<G1::ScalarField>>), SynthesisError> {
        // Implementation using lagrange interpolation
    }
}

/// Gadget for verifying CCS folding with CycleFold
pub struct MultiCCSProofVerifierGadget;

impl MultiCCSProofVerifierGadget {
    /// Verify CCS folding in-circuit with secondary curve
    pub fn ccs_fold_verify<G1, C1, G2, C2>(
        ccs_proof: &CCSFoldProofVar,
        random_oracle: &mut RO,
        U1: &primary::CCSInstanceFromR1CSVar<G1, C1>,
        U2: &primary::CCSInstanceFromR1CSVar<G1, C1>,
        U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
        commitment_W_proof: &secondary::ProofVar<G2, C2>,
        U_folded: &LCCSInstanceVar<G1, C1>,
    ) -> Result<(), Error> {
        // Verify sumcheck and CycleFold operations
    }
}

/// Gadget for verifying LCCS folding
pub struct MultiLCCSProofVerifierGadget;

impl MultiLCCSProofVerifierGadget {
    /// Verify LCCS folding in-circuit
    pub fn lccs_fold_verify<G, C: PolyCommitmentScheme<G>>(
        lccs_proof: &LCCSFoldProofVar,
        random_oracle: &mut RO,
        U1: &LCCSInstanceVar<G, C>,
        U2: &LCCSInstanceVar<G, C>,
        U_folded: &LCCSInstanceVar<G, C>,
    ) -> Result<(), Error> {
        // Verify sumcheck and elliptic curve operations
    }
}

```

## Implementation Plan

### Phase 1: Core Sumcheck Implementation
1. Implement generic sumcheck prover/verifier for the polynomial g(x)
2. Add support for multi-instance folding (μ LCCS + ν CCS instances)
3. Unit tests for sumcheck correctness

### Phase 2: Folding Protocols
1. Implement `MultiLCCSProof::prove_as_subprotocol` and `verify_as_subprotocol`
2. Implement `MultiCCSProof::prove_as_subprotocol` and `verify_as_subprotocol`
3. Integration with existing CCS/LCCS structures

### Phase 3: Circuit Gadgets
1. Implement `SumcheckVerifierGadget` with lagrange interpolation
2. Implement `MultiLCCSProofVerifierGadget` for in-circuit LCCS verification
3. Implement `MultiCCSProofVerifierGadget` with CycleFold support

### Phase 4: Tree Integration
1. Integrate with existing tree folding infrastructure
2. Add support for parallel folding at each tree level
3. Performance optimizations

## Key Design Decisions

1. **Separation of Concerns**: Keep sumcheck protocol generic and reusable
2. **Type Safety**: Use phantom types to distinguish between CCS and LCCS instances
3. **CycleFold Integration**: Support secondary curve operations for CCS folding
4. **Efficient Interpolation**: Use precomputed Lagrange interpolation constants

## Testing Strategy

### Per-File Testing Plans

#### 1. `mod.rs` - Module exports and types
**Tests to include:**
- Type construction and serialization tests
- Instance and witness creation with valid/invalid parameters
- Commitment scheme integration tests
- Error type coverage

#### 2. `nimfs.rs` - Multi-folding implementations
**Tests to include:**
- `MultiCCSProof::prove_as_subprotocol` and `MultiCCSProof::verify_as_subprotocol` correctness:
  - Construct two CCS instances of the cubic instances. Synthesize that the witness. Synthesize each of their witnesses. Then run `prove_as_subprotocol on these two CCS instances. fold them together. Then, run verify_as_subprotocol on the folded instances and ensure that it is correct
    - Construct two CCS instances of the SHA-256 instances from sequentialSha256.rs file. Synthesize each of their witnesses. Then ensure that the witnesses are coorect. Then run `prove_as_subprotocol on these two CCS instances. fold them together. Then, run verify_as_subprotocol on the folded instances and ensure that it is correct
- `MultiLCCSProof::prove_as_subprotocol` and `MultiLCCSProof::verify_as_subprotocol` correctness:
  - Construct four CCS instances of the cubic instances. Synthesize their witnesses. For the first two instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then for the second instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then, fold those folded instances together via  `MultiLCCSProof::prove_as_subprotocol`. Then, verify them via `MultiLCCSProof::verify_as_subprotocol`
  - Construct four CCS instances of the sequential SHA-256 instances. Synthesize their witnesses. For the first two instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then for the second instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then, fold those folded instances together via  `MultiLCCSProof::prove_as_subprotocol`. Then, verify them via `MultiLCCSProof::verify_as_subprotocol`

#### 3. `sumcheck.rs` - Sumcheck protocol
**Tests to include:**
- Convert cubic instance as CCS instance. Then run the sumcheck protocol on those CCS instances via proving it. Then, verify that the proof is correct.
- Convert SHA256 instance as CCS instance. Then run the sumcheck protocol on those CCS instances via proving it. Then, verify that the proof is correct.
- Test utility functions:
  - `ccs_to_sumcheck_polynomial`: Create two CCS instances, convert to g(x), verify polynomial evaluations match expected values
  - `lccs_to_sumcheck_polynomial`: Create two LCCS instances, convert to g(x), verify polynomial evaluations match expected values
  - Cross-check that both utility functions produce correct sumcheck polynomials by running full sumcheck protocol

#### 4. `circuit/mod.rs` - Circuit module exports
**Tests to include:**
- Module integration

#### 5. `circuit/sumcheck.rs` - Sumcheck verifier gadget  
**Tests to include:**
- Turn cubic into a CCS instance. Then run the sumcheck protocol on those CCS instances via proving it. Then, construct the circuit that verifies that the sumcheck proof is correct. Then, verify it.
- Turn sequential SHA256 into a CCS instance. Then run the sumcheck protocol on those CCS instances via proving it. Then, construct the circuit that verifies that the sumcheck proof is correct. Then, verify it.

#### 6. `circuit/ccs_verifier.rs` - CCS folding verifier gadget  
**Tests to include:**
- Turn two cubic computations ito their CCS instance-witness pairs. Then construct the `MultiCCSProof::prove_as_subprotocol` for these two CCS instances. Then construct the verifier circuit for the verifying the proof using `ccs_fold_verify` on it. You would probably also need to run the sums of the elliptic curves on another circuit as well.
- Turn two sequential SHA 256 computations ito their CCS instance-witness pairs. Then construct the `MultiCCSProof::prove_as_subprotocol` for these two CCS instances. Then construct the verifier circuit for the verifying the proof using `ccs_fold_verify` on it. Then run the circuit and ensure that you can generate the witness. Then, verify that the witnesses is fulfilled. You would probably also need to run the sums of the elliptic curves on the different circuit as well. Then, make sure that the circuit is folded correctly.

#### 7. `circuit/lccs_verifier.rs` - LCCS folding verifier gadget
**Tests to include:**
- Construct four CCS instances of the cubic instances. Synthesize their witnesses. For the first two instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then for the second instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then, fold those folded instances together via  `MultiLCCSProof::prove_as_subprotocol`. Then, construct the proof verifying it's correctness using `lccs_fold_verify`. Then run the circuit and ensure that you can generate the witness. Then, verify that the witnesses is fulfilled. You would probably also need to run the sums of the elliptic curves on the different circuit as well. Then, make sure that the circuit is folded correctly.
