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
nova/src/ccs/
├── ccs_fold.rs               # CCS folding implementation (reuses linearization.rs functions)

nova/src/tree_folding/
├── mod.rs                    # Module exports and types
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
/// Reuses existing linearization infrastructure from linearization.rs
pub struct MultiCCSProof<G: Group> {
    /// Sumcheck proof for the folding (reuses MLSumcheck from linearization.rs)
    pub sumcheck_proof: Vec<ProverMsg<G::ScalarField>>,
    /// Challenge gamma used in the sumcheck polynomial
    pub gamma: G::ScalarField,
    /// Challenge beta vector used in the sumcheck polynomial
    pub beta: Vec<G::ScalarField>,
    /// Evaluation point r_x from sumcheck
    pub r_x: Vec<G::ScalarField>,
    /// Claimed evaluations θ_{j,1} for each matrix j and first instance
    pub thetas1: Vec<G::ScalarField>,
    /// Claimed evaluations θ_{j,2} for each matrix j and second instance
    pub thetas2: Vec<G::ScalarField>,
}

impl<G: Group> MultiCCSProof<G> {
    /// Prove folding of two CCS instances into LCCS
    /// Uses construct_ccs_polynomial and linearization infrastructure
    pub fn prove_as_subprotocol<C: PolyCommitmentScheme<G>, RO: RandomOracle>(
        shape: &CCSShape<G>,
        (u1, w1): (&CCSInstance<G, C>, &CCSWitness<G>),
        (u2, w2): (&CCSInstance<G, C>, &CCSWitness<G>),
        random_oracle: &mut RO,
    ) -> Result<(Self, LCCSInstance<G, C>, CCSWitness<G>), Error> {
        // Step 1: Sample challenges γ and β from random oracle
        let gamma: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
        let sumcheck_rounds = safe_loglike!(shape.num_constraints) as usize;
        let beta = random_oracle.squeeze_field_elements(sumcheck_rounds);

        // Step 2: Construct combined witness vectors z1 and z2
        let z1 = [u1.X.as_slice(), w1.W.as_slice()].concat();
        let z2 = [u2.X.as_slice(), w2.W.as_slice()].concat();

        // Step 3: Construct the combined g(x) polynomial for both CCS instances
        // g(x) = γ^1 · Q_1(x) + γ^2 · Q_2(x) where Q_k(x) uses construct_ccs_polynomial logic
        let polynomial = construct_combined_ccs_polynomial(shape, &z1, &z2, &beta, gamma)?;

        // Step 4: Run sumcheck protocol (reuse from linearization.rs step 4)
        let (sumcheck_proof, prover_state) = MLSumcheck::prove_as_subprotocol(random_oracle, &polynomial);
        let r_x = prover_state.randomness;

        // Step 5: Compute theta values for both instances
        let thetas1 = compute_theta_values(shape, &z1, &r_x);
        let thetas2 = compute_theta_values(shape, &z2, &r_x);

        // Step 6: Fold the instances using existing fold_and_linearize_ccs
        let (lccs_folded, witness_folded) = fold_and_linearize_ccs(
            shape, u1, u2, w1, w2, 
            &thetas1, &thetas2, &r_x, random_oracle
        )?;

        let proof = Self {
            sumcheck_proof,
            gamma,
            beta,
            r_x,
            thetas1,
            thetas2,
        };

        Ok((proof, lccs_folded, witness_folded))
    }
    
    /// Verify folding of two CCS instances
    /// Uses verification infrastructure from linearization.rs
    pub fn verify_as_subprotocol<C: PolyCommitmentScheme<G>, RO: RandomOracle>(
        &self,
        shape: &CCSShape<G>,
        U1: &CCSInstance<G, C>,
        U2: &CCSInstance<G, C>,
        U_folded: &LCCSInstance<G, C>,
        random_oracle: &mut RO,
    ) -> Result<(), Error> {
        // Step 1: Regenerate challenges (same as verification in linearization.rs)
        let gamma: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
        let expected_rounds = safe_loglike!(shape.num_constraints) as usize;
        let beta = random_oracle.squeeze_field_elements(expected_rounds);

        // Verify stored challenges match
        if gamma != self.gamma || beta != self.beta {
            return Err(Error::NotSatisfied);
        }

        // Step 2: Reconstruct the combined polynomial
        let z1 = [U1.X.as_slice(), vec![G::ScalarField::ZERO; shape.num_vars - U1.X.len()]].concat();
        let z2 = [U2.X.as_slice(), vec![G::ScalarField::ZERO; shape.num_vars - U2.X.len()]].concat();
        let polynomial = construct_combined_ccs_polynomial(shape, &z1, &z2, &beta, gamma)?;

        // Step 3: Verify sumcheck proof (reuse from linearization.rs)
        let subclaim = MLSumcheck::verify_as_subprotocol(
            random_oracle,
            &polynomial.info(),
            G::ScalarField::ZERO,
            &self.sumcheck_proof,
        ).map_err(|_| Error::NotSatisfied)?;

        // Step 4: Verify evaluation point matches
        if subclaim.point != self.r_x {
            return Err(Error::NotSatisfied);
        }

        // Step 5: Verify folded instance consistency using existing verification logic
        // This uses the same folding verification as in fold_and_linearize_ccs
        verify_ccs_folding_consistency(
            shape, U1, U2, U_folded, 
            &self.thetas1, &self.thetas2, &self.r_x, random_oracle
        )?;

        Ok(())
    }
}

/// Constructs the combined g(x) polynomial for folding two CCS instances
/// Uses the existing construct_ccs_polynomial logic but combines two instances
fn construct_combined_ccs_polynomial<G: CurveGroup>(
    shape: &CCSShape<G>,
    z1: &[G::ScalarField],
    z2: &[G::ScalarField],
    beta: &[G::ScalarField],
    gamma: G::ScalarField,
) -> Result<ListOfProductsOfPolynomials<G::ScalarField>, Error> {
    // Implementation combines the polynomial construction logic for both instances
    // Similar to construct_css_polynomial but handles two witness vectors
}

/// Verifies the consistency of CCS folding
fn verify_ccs_folding_consistency<G: CurveGroup, C: PolyCommitmentScheme<G>, RO: RandomOracle>(
    shape: &CCSShape<G>,
    u1: &CCSInstance<G, C>,
    u2: &CCSInstance<G, C>,
    u_folded: &LCCSInstance<G, C>,
    thetas1: &[G::ScalarField],
    thetas2: &[G::ScalarField],
    r_x: &[G::ScalarField],
    random_oracle: &mut RO,
) -> Result<(), Error> {
    // Implementation verifies that the folding was done correctly
    // Reuses logic from fold_and_linearize_ccs verification
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

### 3. Reused Components from linearization.rs

The MultiCCSProof and MultiLCCSProof implementations will reuse the following existing components from `nova/src/ccs/linearization.rs`:

- **`construct_css_polynomial`** - For building the sumcheck polynomial g(x)
- **`MLSumcheck::prove_as_subprotocol`** - For running the sumcheck protocol
- **`MLSumcheck::verify_as_subprotocol`** - For verifying sumcheck proofs
- **`compute_theta_values`** - For computing matrix evaluations at the sumcheck point
- **`fold_and_linearize_ccs`** - For folding CCS instances into LCCS
- **Challenge sampling and verification patterns** - From the linearization protocol

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

### Phase 1: Core CCS Polynomial Extension
1. Extend `construct_css_polynomial` to handle two CCS instances simultaneously
2. Implement `construct_combined_ccs_polynomial` for MultiCCSProof
3. Add utility functions for combining witness vectors from two instances

### Phase 2: Folding Protocols (Reusing linearization.rs)
1. Implement `MultiCCSProof::prove_as_subprotocol` using existing linearization infrastructure:
   - Use existing challenge sampling patterns
   - Reuse `MLSumcheck::prove_as_subprotocol` 
   - Reuse `compute_theta_values` for both instances
   - Reuse `fold_and_linearize_ccs` for final folding
2. Implement `MultiCCSProof::verify_as_subprotocol` using existing verification patterns
3. Implement `MultiLCCSProof` with similar reuse strategy
4. Integration and compatibility testing with existing CCS/LCCS structures

### Phase 3: Circuit Gadgets (Leveraging existing patterns)
1. Implement `SumcheckVerifierGadget` by adapting verification patterns from linearization.rs
2. Implement `MultiLCCSProofVerifierGadget` for in-circuit LCCS verification  
3. Implement `MultiCCSProofVerifierGadget` with CycleFold support

### Phase 4: Tree Integration and Testing
1. Integrate with existing tree folding infrastructure
2. Add comprehensive tests following the testing strategy below
3. Performance optimizations and benchmarking

## Key Design Decisions

1. **Reuse of Existing Infrastructure**: Leverage the robust linearization.rs implementation instead of duplicating sumcheck logic
2. **Code Deduplication**: Use existing `construct_css_polynomial`, `MLSumcheck`, `compute_theta_values`, and `fold_and_linearize_ccs` functions
3. **Type Safety**: Use phantom types to distinguish between CCS and LCCS instances
4. **CycleFold Integration**: Support secondary curve operations for CCS folding
5. **Efficient Interpolation**: Use precomputed Lagrange interpolation constants from existing implementation
6. **Consistent Challenge Generation**: Follow the same random oracle patterns as linearization for compatibility

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

#### 3. `ccs_fold.rs` - CCS folding implementations (reusing linearization.rs)
**Tests to include:**
- Test `construct_combined_ccs_polynomial` with two cubic CCS instances:
  - Create two CCS instances from cubic circuit, verify combined polynomial construction
  - Run sumcheck protocol using reused `MLSumcheck::prove_as_subprotocol`
  - Verify proof using `MLSumcheck::verify_as_subprotocol`
- Test `construct_combined_ccs_polynomial` with two SHA256 CCS instances:
  - Create two CCS instances from SHA256 circuit, verify combined polynomial construction
  - Run full sumcheck protocol and verify correctness
- Integration tests with existing linearization.rs functions:
  - Verify `compute_theta_values` works correctly with folding inputs
  - Verify `fold_and_linearize_ccs` integration with MultiCCSProof output

#### 4. `circuit/mod.rs` - Circuit module exports
**Tests to include:**
- Module integration

#### 5. `circuit/sumcheck.rs` - Sumcheck verifier gadget (adapted from linearization.rs)
**Tests to include:**
- Test with cubic CCS instances folding:
  - Create two cubic CCS instances, run `MultiCCSProof::prove_as_subprotocol`
  - Construct circuit using `SumcheckVerifierGadget` adapted from linearization verification patterns  
  - Verify the circuit can validate the sumcheck proof correctly
- Test with sequential SHA256 CCS instances folding:
  - Create two SHA256 CCS instances, run `MultiCCSProof::prove_as_subprotocol`
  - Construct verification circuit and ensure witness generation succeeds
  - Verify circuit constraints are satisfied

#### 6. `circuit/ccs_verifier.rs` - CCS folding verifier gadget  
**Tests to include:**
- Turn two cubic computations ito their CCS instance-witness pairs. Then construct the `MultiCCSProof::prove_as_subprotocol` for these two CCS instances. Then construct the verifier circuit for the verifying the proof using `ccs_fold_verify` on it. You would probably also need to run the sums of the elliptic curves on another circuit as well.
- Turn two sequential SHA 256 computations ito their CCS instance-witness pairs. Then construct the `MultiCCSProof::prove_as_subprotocol` for these two CCS instances. Then construct the verifier circuit for the verifying the proof using `ccs_fold_verify` on it. Then run the circuit and ensure that you can generate the witness. Then, verify that the witnesses is fulfilled. You would probably also need to run the sums of the elliptic curves on the different circuit as well. Then, make sure that the circuit is folded correctly.

#### 7. `circuit/lccs_verifier.rs` - LCCS folding verifier gadget
**Tests to include:**
- Construct four CCS instances of the cubic instances. Synthesize their witnesses. For the first two instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then for the second instances, fold them together via `MultiCCSProof::prove_as_subprotocol`. Then, fold those folded instances together via  `MultiLCCSProof::prove_as_subprotocol`. Then, construct the proof verifying it's correctness using `lccs_fold_verify`. Then run the circuit and ensure that you can generate the witness. Then, verify that the witnesses is fulfilled. You would probably also need to run the sums of the elliptic curves on the different circuit as well. Then, make sure that the circuit is folded correctly.
