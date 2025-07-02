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
    ├── sumcheck.rs           # Core sumcheck verification functions
    │                         # - verify_all_sumcheck (moved from linearization_augmented_circuit.rs)
    │                         # - compute_equality_polynomial (moved from linearization_augmented_circuit.rs)
    │                         # - verify_target_sumcheck_for_ccs_folding
    │                         # - verify_target_sumcheck_for_lccs_folding
    ├── lccs_verifier.rs      # LCCS folding verifier gadget (uses sumcheck.rs functions)
    └── ccs_verifier.rs       # CCS folding verifier gadget (uses sumcheck.rs functions)
```

## Core Data Structures

### 1. CCS Folding Proof Structure

```rust
/// Proof for folding multiple CCS instances together
/// Reuses existing linearization infrastructure from linearization.rs
pub struct CCSFoldingProof<G: Group> {
    /// Sumcheck proof for the folding (reuses MLSumcheck from linearization.rs)
    pub sumcheck_proof: Vec<ProverMsg<G::ScalarField>>,
    /// Challenge gamma used in the sumcheck polynomial
    pub gamma: G::ScalarField,
    /// Challenge beta vector used in the sumcheck polynomial
    pub beta: Vec<G::ScalarField>,
    /// Evaluation point r_x from sumcheck
    pub r_x: Vec<G::ScalarField>,
    /// Claimed evaluations θ_{j,1} for each matrix j and first CCS instance
    pub theta1: Vec<G::ScalarField>,
    /// Claimed evaluations θ_{j,2} for each matrix j and second CCS instance
    pub theta2: Vec<G::ScalarField>,
}

impl<G: Group> CCSFoldingProof<G> {
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
        let theta1 = compute_theta_values(shape, &z1, &r_x);
        let theta2 = compute_theta_values(shape, &z2, &r_x);

        // Step 6: Fold the instances using existing fold_and_linearize_ccs
        let (lccs_folded, witness_folded) = fold_and_linearize_ccs(
            shape, u1, u2, w1, w2, 
            &theta1, &theta2, &r_x, random_oracle
        )?;

        let proof = Self {
            sumcheck_proof,
            gamma,
            beta,
            r_x,
            theta1,
            theta2,
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
            &self.theta1, &self.theta2, &self.r_x, random_oracle
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
    theta1: &[G::ScalarField],
    theta2: &[G::ScalarField],
    r_x: &[G::ScalarField],
    random_oracle: &mut RO,
) -> Result<(), Error> {
    // Implementation verifies that the folding was done correctly
    // Reuses logic from fold_and_linearize_ccs verification
}
```

### 2. LCCS Folding Proof Structure

```rust
/// Proof for folding multiple LCCS instances together
pub struct LCCSFoldingProof<G: Group> {
    /// Sumcheck proof for the folding
    pub sumcheck_proof: SumcheckProof<G::ScalarField>,
    /// Claimed evaluations σ_{j,1} for each matrix j and first LCCS instance
    pub sigma1: Vec<G::ScalarField>,
    /// Claimed evaluations σ_{j,2} for each matrix j and second LCCS instance  
    pub sigma2: Vec<G::ScalarField>,
}

impl<G: Group> LCCSFoldingProof<G> {
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

The CCSFoldingProof and LCCSFoldingProof implementations will reuse the following existing components from `nova/src/ccs/linearization.rs`:

- **`construct_css_polynomial`** - For building the sumcheck polynomial g(x)
- **`MLSumcheck::prove_as_subprotocol`** - For running the sumcheck protocol
- **`MLSumcheck::verify_as_subprotocol`** - For verifying sumcheck proofs
- **`compute_theta_values`** - For computing matrix evaluations at the sumcheck point
- **`fold_and_linearize_ccs`** - For folding CCS instances into LCCS
- **Challenge sampling and verification patterns** - From the linearization protocol

### 4. Circuit Gadgets

#### Sumcheck Verifier Circuit (`circuit/sumcheck.rs`)

This module contains the core sumcheck verification gadgets moved and adapted from `linearization_augmented_circuit.rs`:

```rust
/// Verify all sumcheck rounds and collect challenges
/// Moved from linearization_augmented_circuit.rs
pub fn verify_all_sumcheck<G1, RO>(
    random_oracle: &mut RO::Var,
    sumcheck_evals: &[Vec<FpVar<G1::ScalarField>>],
    expected_sum_of_polynomial: FpVar<G1::ScalarField>,
    sumcheck_rounds: usize,
) -> Result<(FpVar<G1::ScalarField>, Vec<FpVar<G1::ScalarField>>), SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    // Implementation performs complete sumcheck verification process:
    // 1. Uses provided expected sum as initial value for verification  
    // 2. Iterates through all sumcheck proof rounds
    // 3. For each round: absorbs polynomial evaluations, generates challenge r_k, 
    //    verifies round consistency p_k(0) + p_k(1) = p_{k-1}(r_{k-1}),
    //    computes next expected value via Lagrange interpolation
    // 4. Returns final expected value and vector of challenge points r_k
}

/// Compute the equality polynomial eq(a, b) = ∏ᵢ [aᵢ·bᵢ + (1-aᵢ)·(1-bᵢ)]
/// Moved from linearization_augmented_circuit.rs
pub fn compute_equality_polynomial<G1>(
    a: &[FpVar<G1::ScalarField>],
    b: &[FpVar<G1::ScalarField>],
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    // Implementation computes multilinear extension of equality predicate
    // Used for computing both e1 = eq(r_x, r'_x) and e2 = eq(β, r'_x)
}

/// Verify target sumcheck equality for CCS folding
/// For CCS folding: μ = 0 (no LCCS instances), only CCS instances (ν = 2)
/// Mathematical expression:
/// c = γ^1 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,1} + γ^2 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,2}
/// 
/// Full expansion for two CCS instances (k=1,2):
/// - k=1 term: γ^1 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,1}
/// - k=2 term: γ^2 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,2}
/// 
/// where:
/// - e2 = eq(β, r'_x) 
/// - θ_{j,1} = ∑_{y∈{0,1}^s'} M_j(r'_x, y) · z_{2,1}(y) (first CCS witness evaluations)
/// - θ_{j,2} = ∑_{y∈{0,1}^s'} M_j(r'_x, y) · z_{2,2}(y) (second CCS witness evaluations)
/// - γ^1 scales first CCS instance, γ^2 scales second CCS instance
/// - ∑_{i=1}^q c_i · ∏_{j∈S_i} represents the CCS constraint structure
pub fn verify_target_sumcheck_for_ccs_folding<G1>(
    gamma: &FpVar<G1::ScalarField>,
    e2: &FpVar<G1::ScalarField>,
    theta1: &[FpVar<G1::ScalarField>], // θ_{j,1} for each matrix j for first CCS instance
    theta2: &[FpVar<G1::ScalarField>], // θ_{j,2} for each matrix j for second CCS instance
    multiset_coeffs: &[(G1::ScalarField, Vec<usize>)], // (c_i, S_i) pairs
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    // Implementation computes: γ^1 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,1} + γ^2 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,2}
}

/// Verify target sumcheck equality for LCCS folding  
/// For LCCS folding: ν = 0 (no CCS instances), only LCCS instances (μ = 2)
/// Mathematical expression:
/// c = ∑_{j∈[t]} γ^j · e1 · σ_{j,1} + ∑_{j∈[t]} γ^(t+j) · e1 · σ_{j,2}
/// 
/// Full expansion for two LCCS instances (k=1,2):
/// - k=1 term: ∑_{j∈[t]} γ^((1-1)·t+j) · e1 · σ_{j,1} = ∑_{j∈[t]} γ^j · e1 · σ_{j,1}
/// - k=2 term: ∑_{j∈[t]} γ^((2-1)·t+j) · e1 · σ_{j,2} = ∑_{j∈[t]} γ^(t+j) · e1 · σ_{j,2}
/// 
/// where:
/// - e1 = eq(r_x, r'_x)
/// - σ_{j,1} = ∑_{y∈{0,1}^s'} M_j(r'_x, y) · z_{1,1}(y) (first LCCS witness evaluations)
/// - σ_{j,2} = ∑_{y∈{0,1}^s'} M_j(r'_x, y) · z_{1,2}(y) (second LCCS witness evaluations)
/// - γ^j scales matrix j evaluation for first instance, γ^(t+j) for second instance
/// - t is the number of matrices
pub fn verify_target_sumcheck_for_lccs_folding<G1>(
    gamma: &FpVar<G1::ScalarField>,
    e1: &FpVar<G1::ScalarField>,
    sigma1: &[FpVar<G1::ScalarField>], // σ_{j,1} for each matrix j for first LCCS instance
    sigma2: &[FpVar<G1::ScalarField>], // σ_{j,2} for each matrix j for second LCCS instance
    num_matrices: usize, // t
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    // Implementation computes: ∑_{j∈[t]} γ^j · e1 · σ_{j,1} + ∑_{j∈[t]} γ^(t+j) · e1 · σ_{j,2}
}
```

#### CCS Folding Verifier Circuit (`circuit/ccs_verifier.rs`)

```rust
/// Gadget for verifying CCS folding with CycleFold
pub struct CCSFoldingProofVerifierGadget;

impl CCSFoldingProofVerifierGadget {
    /// Verify CCS folding in-circuit with secondary curve
    /// Uses functions from circuit/sumcheck.rs for verification
    pub fn ccs_fold_verify<G1, C1, G2, C2>(
        ccs_proof: &CCSFoldProofVar,
        random_oracle: &mut RO,
        U1: &primary::CCSInstanceFromR1CSVar<G1, C1>,
        U2: &primary::CCSInstanceFromR1CSVar<G1, C1>,
        U_secondary: &secondary::RelaxedR1CSInstanceVar<G2, C2>,
        commitment_W_proof: &secondary::ProofVar<G2, C2>,
        U_folded: &LCCSInstanceVar<G1, C1>,
    ) -> Result<(), Error> {
        // 1. Use verify_all_sumcheck from circuit/sumcheck.rs
        // 2. Use compute_equality_polynomial to compute e2 = eq(β, r'_x) 
        // 3. Use verify_target_sumcheck_for_ccs_folding for final verification
        // 4. Verify CycleFold operations for elliptic curve arithmetic
    }
}
```

#### LCCS Folding Verifier Circuit (`circuit/lccs_verifier.rs`)

```rust
/// Gadget for verifying LCCS folding
pub struct LCCSFoldingProofVerifierGadget;

impl LCCSFoldingProofVerifierGadget {
    /// Verify LCCS folding in-circuit
    /// Uses functions from circuit/sumcheck.rs for verification
    pub fn lccs_fold_verify<G, C: PolyCommitmentScheme<G>>(
        lccs_proof: &LCCSFoldProofVar,
        random_oracle: &mut RO,
        U1: &LCCSInstanceVar<G, C>,
        U2: &LCCSInstanceVar<G, C>,
        U_folded: &LCCSInstanceVar<G, C>,
    ) -> Result<(), Error> {
        // 1. Use verify_all_sumcheck from circuit/sumcheck.rs
        // 2. Use compute_equality_polynomial to compute e1 = eq(r_x, r'_x)
        // 3. Use verify_target_sumcheck_for_lccs_folding for final verification
        // 4. Verify elliptic curve operations for instance folding
    }
}

```

## Implementation Plan

### Phase 1: Core CCS Polynomial Extension
1. Extend `construct_css_polynomial` to handle two CCS instances simultaneously
2. Implement `construct_combined_ccs_polynomial` for CCSFoldingProof
3. Add utility functions for combining witness vectors from two instances

### Phase 2: Folding Protocols (Reusing linearization.rs)
1. Implement `CCSFoldingProof::prove_as_subprotocol` using existing linearization infrastructure:
   - Use existing challenge sampling patterns
   - Reuse `MLSumcheck::prove_as_subprotocol` 
   - Reuse `compute_theta_values` for both instances
   - Reuse `fold_and_linearize_ccs` for final folding
2. Implement `CCSFoldingProof::verify_as_subprotocol` using existing verification patterns
3. Implement `LCCSFoldingProof` with similar reuse strategy
4. Integration and compatibility testing with existing CCS/LCCS structures

### Phase 3: Circuit Gadgets (Moving and adapting from linearization_augmented_circuit.rs)
1. Create `circuit/sumcheck.rs` with functions moved from `linearization_augmented_circuit.rs`:
   - Move `verify_all_sumcheck` (complete sumcheck verification with challenge collection)
   - Move `compute_equality_polynomial` (equality predicate computation)
   - Implement `verify_target_sumcheck_for_ccs_folding` (CCS-specific target verification)
   - Implement `verify_target_sumcheck_for_lccs_folding` (LCCS-specific target verification)
2. Implement `LCCSFoldingProofVerifierGadget` for in-circuit LCCS verification using sumcheck.rs functions
3. Implement `CCSFoldingProofVerifierGadget` with CycleFold support using sumcheck.rs functions

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
- `CCSFoldingProof::prove_as_subprotocol` and `CCSFoldingProof::verify_as_subprotocol` correctness:
  - Construct two CCS instances of the cubic instances. Synthesize that the witness. Synthesize each of their witnesses. Then run `prove_as_subprotocol on these two CCS instances. fold them together. Then, run verify_as_subprotocol on the folded instances and ensure that it is correct
    - Construct two CCS instances of the SHA-256 instances from sequentialSha256.rs file. Synthesize each of their witnesses. Then ensure that the witnesses are coorect. Then run `prove_as_subprotocol on these two CCS instances. fold them together. Then, run verify_as_subprotocol on the folded instances and ensure that it is correct
- `LCCSFoldingProof::prove_as_subprotocol` and `LCCSFoldingProof::verify_as_subprotocol` correctness:
  - Construct four CCS instances of the cubic instances. Synthesize their witnesses. For the first two instances, fold them together via `CCSFoldingProof::prove_as_subprotocol`. Then for the second instances, fold them together via `CCSFoldingProof::prove_as_subprotocol`. Then, fold those folded instances together via  `LCCSFoldingProof::prove_as_subprotocol`. Then, verify them via `LCCSFoldingProof::verify_as_subprotocol`
  - Construct four CCS instances of the sequential SHA-256 instances. Synthesize their witnesses. For the first two instances, fold them together via `CCSFoldingProof::prove_as_subprotocol`. Then for the second instances, fold them together via `CCSFoldingProof::prove_as_subprotocol`. Then, fold those folded instances together via  `LCCSFoldingProof::prove_as_subprotocol`. Then, verify them via `LCCSFoldingProof::verify_as_subprotocol`

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
  - Verify `fold_and_linearize_ccs` integration with CCSFoldingProof output

#### 4. `circuit/mod.rs` - Circuit module exports
**Tests to include:**
- Module integration

#### 5. `circuit/sumcheck.rs` - Core sumcheck verification functions (moved from linearization_augmented_circuit.rs)
**Tests to include:**
- Test `verify_all_sumcheck` function:
  - Setup CCS parameters for the computaions of cubic circuit, then compute the CCS instance-witness pairs for that matrix. Then, construct a sumcheck proof of it. Then, construct another circuit and construct the verification circuit of the sumcheck proof verification. Then, verify that the sumcheck proof verification circuit is satisified with the sumcheck proof
  - Setup CCS parameters for the computaions of SHA-256 circuit, then compute the CCS instance-witness pairs for that matrix. Then, construct a sumcheck proof of it. Then, construct another circuit and construct the verification circuit of the sumcheck proof verification. Then, verify that the sumcheck proof verification circuit is satisified with the sumcheck proof
  - Setup CCS parameters for the computaions of cubic circuit, then compute the CCS instance-witness pairs for that matrix. Setup g(x) that matches the folding lccs matrix done on lccs_fold.rs. Then, construct a sumcheck proof of it. Then, construct another circuit and construct the verification circuit of the sumcheck proof verification. Then, verify that the sumcheck proof verification circuit is satisified with the sumcheck proof
    - Setup is basically like:
    ```
    let poly = construct_sumcheck_polynomial(shape, lccs1, lccs2, witness1, witness2, &gamma);

    // 3. Run the sum-check protocol
    let (sumcheck_proof, sumcheck_state) = MLSumcheck::prove_as_subprotocol(random_oracle, &poly);
    ```
    Make sure you import that construct_sumcheck_polynomial in lccs_fold.rs
  - Do the same thing as above for SHA256 circuit
- Test `verify_target_sumcheck_for_ccs_folding` function:
  - Create two cubic CCS instances, run `CCSFoldingProof::prove_as_subprotocol` to get theta1 and theta2
    - Compute e2 = eq(β, r'_x) using `compute_equality_polynomial`
    - Verify target equality: c = γ^1 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,1} + γ^2 · e2 · ∑_{i=1}^q c_i · ∏_{j∈S_i} θ_{j,2}
  - Test with SHA256 CCS instances for larger constraint systems
- Test `verify_target_sumcheck_for_lccs_folding` function:
  - Create four cubic CCS instances, fold first two and second two into LCCS instances
    - Fold the two LCCS instances using `LCCSFoldingProof::prove_as_subprotocol` to get sigma1 and sigma2
    - Compute e1 = eq(r_x, r'_x) using `compute_equality_polynomial`
  - Verify target equality: c = ∑_{j∈[t]} γ^j · e1 · σ_{j,1} + ∑_{j∈[t]} γ^(t+j) · e1 · σ_{j,2}
  - Test with SHA256 instances for comprehensive verification

#### 6. `circuit/ccs_verifier.rs` - CCS folding verifier gadget  
**Tests to include:**
- Turn two cubic computations ito their CCS instance-witness pairs. Then construct the `CCSFoldingProof::prove_as_subprotocol` for these two CCS instances. Then construct the verifier circuit for the verifying the proof using `ccs_fold_verify` on it. You would probably also need to run the sums of the elliptic curves on another circuit as well.
- Turn two sequential SHA 256 computations ito their CCS instance-witness pairs. Then construct the `CCSFoldingProof::prove_as_subprotocol` for these two CCS instances. Then construct the verifier circuit for the verifying the proof using `ccs_fold_verify` on it. Then run the circuit and ensure that you can generate the witness. Then, verify that the witnesses is fulfilled. You would probably also need to run the sums of the elliptic curves on the different circuit as well. Then, make sure that the circuit is folded correctly.

#### 7. `circuit/lccs_verifier.rs` - LCCS folding verifier gadget
**Tests to include:**
- Construct four CCS instances of the cubic instances. Synthesize their witnesses. For the first two instances, fold them together via `CCSFoldingProof::prove_as_subprotocol`. Then for the second instances, fold them together via `CCSFoldingProof::prove_as_subprotocol`. Then, fold those folded instances together via `LCCSFoldingProof::prove_as_subprotocol` to get sigma1 and sigma2. Then, construct the proof verifying its correctness using `lccs_fold_verify` which uses `verify_target_sumcheck_for_lccs_folding` with the separate sigma1 and sigma2 vectors. Then run the circuit and ensure that you can generate the witness. Then, verify that the witnesses is fulfilled. You would probably also need to run the sums of the elliptic curves on the different circuit as well. Then, make sure that the circuit is folded correctly.
