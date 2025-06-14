# HyperNova Tree Folding: Leaf-Prover Routine

## Mangrove Tree Folding Framework

This document describes the Mangrove tree folding framework and the leaf-prover routine for HyperNova, which transforms CCS instances into a linearized form suitable for efficient folding.

### Overview

The Mangrove framework provides a scalable approach to folding-based SNARKs by:
1. Chunking computation into operation-specific pieces
2. Creating a two-layer commitment structure
3. Applying linearization to enable efficient folding

### CCS Arithmetization and Operation-Based Chunking

Unlike the uniform chunking approach presented in the original Mangrove paper, our implementation uses the **CCS (Customizable Constraint System)** arithmetization scheme with an operation-based chunking strategy that dramatically reduces the number of copy constraints.

#### Key Differences from Uniform Chunking:

1. **Reduced Copy Constraints**: 
   - In Mangrove's uniform approach, each constraint requires copy constraints for every wire connection, resulting in a large number of copy constraints
   - With CCS, copy constraints are only needed when inputs and outputs are shared between different chunks
   - This reduction is achieved by grouping similar operations together

2. **Operation-Based Chunking**:
   Instead of arbitrary uniform chunks, we organize chunks based on common cryptographic operations:
   
   - **SHA-256 Chunk**: Contains multiple SHA-256 hash computations
   - **ECDSA Chunk**: Contains multiple ECDSA digital signature verification computations
   - **Aggregation Chunk**: A final chunk that combines the outputs from all operation-specific chunks

3. **Constraint Distribution**:
   - The total folded computation handles approximately 500,000 constraints
   - Each operation-specific chunk processes multiple instances of the same operation type
   - Inter-chunk copy constraints are minimized to only the necessary input/output connections

This operation-based approach provides several advantages:
- **Better locality**: Similar operations share common sub-circuits and lookup tables
- **Reduced overhead**: Fewer copy constraints mean less proving work
- **Natural parallelism**: Different operation types can be processed independently

### Commitment Structure

The Mangrove framework employs a two-layer commitment structure:

#### 1. Public Parameters Commitment (Poseidon-based)

For each chunk `j`, we create a commitment to the public permutation parameters:
```
plk_j = Poseidon_Commit(j, σ_j)
```

These commitments are then organized into a Merkle tree using Poseidon hashes:
```
h_plk = MerkleTree_Poseidon([plk_1, plk_2, ..., plk_T])
```

This Merkle root `h_plk` represents a commitment to the entire permutation structure and is computed during preprocessing.

#### 2. Witness Values Commitment (Pedersen + Poseidon)

The witness commitment follows a hybrid approach:

**Step 1**: For each chunk `j`, create a Pedersen commitment to the witness values:
```
C_j = Pedersen_Commit(w_j; r_j)
```
where `r_j` is the commitment randomness.

**Step 2**: Organize these Pedersen commitments into a Merkle tree using Poseidon:
```
h_w = MerkleTree_Poseidon([C_1, C_2, ..., C_T])
```

This two-layer approach provides:
- **Pedersen commitments**: Enable efficient folding operations due to their linear homomorphic properties
- **Poseidon Merkle tree**: Provides succinct authentication paths and efficient verification

### Permutation Copy Constraints

The global copy constraints are handled through a randomized permutation argument:

1. **Challenge Generation**: After committing to witness values, derive challenges `(α, β)` using Fiat-Shamir:
   ```
   (α, β) = RO(h_plk || h_w || public_inputs)
   ```

2. **Partial Product Computation**: Each chunk `j` computes a partial product for the permutation check:
   ```
   p_j = ∏_{i=1}^{m} [H_{α,β}(w_i, m(j-1) + i) / H_{α,β}(w_i, σ_i)]
   ```
   where `H_{α,β}(x, y) = (x + α·y) + β` is a universal hash function, and `w_i` are the witness values within chunk `j`.

3. **Cross-Chunk Verification**: The partial products from all chunks must satisfy at the end of the root:
   ```
   ∏_{j=1}^T p_j = 1
   ```
   This ensures global consistency of the permutation constraints across all chunks.

### Leaf Computation Details

Each leaf computation encapsulates an application circuit `F_j` that is **wrapped** with additional tree-folding computations. The base application circuit (e.g., SHA-256 or ECDSA verification) is augmented with the necessary operations for maintaining the tree structure and permutation consistency.

#### Leaf Constraint Relations

For each chunk `j`, the complete set of constraints can be represented as the following mathematical relations:

```
F_j(w_j) = 0                                           // Base application circuit constraints
p_j = ∏_{i∈I_j} [H_{α,β}(w_i, i) / H_{α,β}(w_i, σ_i)] // Partial permutation product
h_w,j = Poseidon_Hash(Pedersen_Commit(w_j))           // Witness commitment hash
h_plk,j = Poseidon_Hash(Pedersen_Commit(j || σ_j))    // Public parameters commitment hash
```

#### Leaf Circuit Structure:
The leaf circuit takes as input:
- `w_j`: The witness for the application circuit `F_j`
- `σ_j`: The copy constraints for leaf `j`
- `C_w,j`: Pedersen commitment to the witness (computed outside the circuit)
- `C_plk,j`: Pedersen commitment to the public parameters and copy constraints (computed outside the circuit)

And outputs:
- `p_j`: The partial permutation product
- `h_w,j`: Poseidon hash of the witness commitment
- `h_plk,j`: Poseidon hash of the public parameter commitment

### Inner Node Computation

Inner nodes aggregate values within an augmented circuit:

```
p_parent = ∏_{i=1}^k p_i                                    // Product aggregation
h_w,parent = Poseidon_Hash(h_w,1 || h_w,2 || ... || h_w,k)  // Witness hash aggregation
h_plk,parent = Poseidon_Hash(h_plk,1 || h_plk,2 || ... || h_plk,k) // Parameter hash aggregation
```

At the root: `p_root = 1` ensures global permutation consistency.

---

## Leaf Linearization Details
The leaf-prover routine transforms a fresh CCS instance into a linearized form through the following steps:

There is no running accumulator at this level. Two distinct witnesses appear:
- $w_{base}$ – satisfies the original CCS constraints that represent both the application's chunk circuit (e.g., SHA-256 round) and Mangrove's leaf-specific constraints (partial permutation product $p_j$, witness commitment hash $h_{w,j}$, etc.)
- $w_{aug}$ – satisfies the augmented R1CS circuit (contains $w_{base}$ plus all auxiliary data for tree folding)

For randomness we use a domain-separated random oracle $R: \{0,1\}^* \to \mathbb{F}$.

### Function Signature

```
LeafLineariseCCS(
    pk_NIFS,              // prover key for CCS→LCCS folding scheme
    s_CCS,                // fixed CCS structure
    u_CCS, w_base         // fresh CCS instance & witness
) -> (
    L, w_L,               // resulting LCCS pair (fold output)
    u_aug, w_aug          // augmented-circuit instance & witness
)
```

Note: $pk_{NIFS}$ already embeds the verifier key $vk_{NIFS}$ that the step-circuit will call.

### Step 1: CCS Linearization and NIFS Folding

**Purpose:** Linearize the fresh CCS instance into LCCS format and fold it using the NIFS protocol.

#### 1.1 Sample a random value of B using the commitment of the z, the witness of the application logic
```
C := Commit(w_base; r_C)
r_C ← R("commit" ∥ w_base)
β ← R("beta" ∥ r_C)  // Derive folding randomness from commitment using domain-separated RO
γ ← R("gamma" ∥ r_C) // Derive gamma parameter for linear combination using same commitment
```

#### 1.2 Run the Sum-Check Protocol
**Polynomial to prove zero sum:**
```
g(X) = γ * eq(β, X) ∑_{i=1}^q c_i ∏_{j ∈ S_i} [∑_y M_{f_j}(X, y) · z_e(y)]
```

Run the standard public-coin Sum-Check with claimed sum:
```
S = ∑_{X ∈ {0,1}^s} g(X) = 0
```

The constraints of the sumcheck represent:

```
F_j(w_j) = 0                                           // Application circuit constraints
p_j = ∏_{i∈I_j} [H_{α,β}(w_i, i) / H_{α,β}(w_i, σ_i)] // Partial permutation product
h_w,j = Poseidon_Hash(Pedersen_Commit(w_j))           // Witness commitment hash
h_plk,j = Poseidon_Hash(Pedersen_Commit(j || σ_j))    // Public parameters hash
```

**Obtain:**
- Final evaluation point $r_x$ (generated by the Sum-Check protocol)
- Univariate polynomials of degree $d$ for each round
- Sumcheck Transcript $π_{SC}$

The verifier part of Sum-Check finally checks $g(r_x) = 0$.

#### 1.3 Compute Linear Values
Using the $r_x$ values obtained from the Sum-Check protocol, compute for every selector $j = 1, \ldots, t$:
```
\v_j := ∑_{y ∈ {0,1}^{s'}} M_{f_j}(r_x, y) · z_e(y)
```

### Step 2: Build the Augmented Step-Circuit Instance

**Purpose:** Construct an augmented R1CS circuit that verifies:
1. The Sum-Check protocol was executed correctly
2. The auxiliary values {v_j} were computed correctly 
3. The NIFS folding verification equation holds

#### 2.1 Augmented Circuit Public Inputs
The augmented circuit takes as public inputs:
```
(x,                           // original CCS public input
 r'ₓ,                         // folding evaluation point
 v₁, ..., vₜ                 // folded linear values
)
```

#### 2.2 Circuit Mathematical Relations

##### (a) Application Circuit Constraints
The circuit includes the original computation:
```
F_j(w_{base}) = 0                                           // Application circuit constraints
p_j = ∏_{i∈I_j} [H_{α,β}(w_i, i) / H_{α,β}(w_i, σ_i)] // Partial permutation product
h_w,j = Poseidon_Hash(Pedersen_Commit(w_j))           // Witness commitment hash
h_plk,j = Poseidon_Hash(Pedersen_Commit(j || σ_j))    // Public parameters hash
```

**Random Oracle Value Computation:**
The augmented circuit must first compute the random oracle values β and γ that were used in the original protocol:

```
β ← R("beta" ∥ r_C)    // Derive folding randomness from commitment
γ ← R("gamma" ∥ r_C)   // Derive gamma parameter for linear combination
```

These values are critical for verifying:
- The Sum-Check polynomial g(X) which includes the factor γ * eq(β, x)
- The NIFS verification equation which uses powers of γ
- The equality check e₂ = eq(β, r'ₓ)

##### (b) Sum-Check Verification Constraints
The circuit verifies the Sum-Check proof by enforcing:

**Round polynomial consistency:** For each round k = 1, ..., s:
```
p_k(0) + p_k(1) = p_{k-1}(r_{k-1})
```

**Final evaluation check:**
```
g(r_x) = ∑_{i=1}^q c_i ∏_{j ∈ S_i} v_j = 0
```

**Sum-Check randomness derivation:**
```
r_x = (r₁, r₂, ..., r_s) derived from π_SC
```

##### (c) Auxiliary Values Verification Constraints
The circuit verifies that the auxiliary values were computed correctly:

**Equality check computations:**
```
e₂ = eq(β, r'ₓ)
```

**Main verification equation:**
```
c = ∑_{k∈[ν]} γ · e₂ · ∑_{i=1}^q cᵢ ∏_{j∈Sᵢ} θⱼ,ₖ
```

#### 2.3 Synthesize Augmented Witness w_aug

The augmented circuit witness `w_aug` is the solution that satisfies the augmented circuit. It contains the following values:
```
(w_base, r_C, π_SC, {σⱼ,ₖ}, {θⱼ,ₖ}, ρ, r_aug, intermediate_values)
```

as well as other intermediate values needed to satisfy all the verification constraints in the augmented circuit.

#### 2.4 Construct u_aug

**Commit to augmented witness:**
```
r_aug ← R("aug-commit" ∥ w_aug)
C_aug := Commit(w_aug; r_aug)
```

**Augmented circuit instance:**
```
u_aug = (C_aug,          // commitment to augmented witness
         x,              // public input from base circuit
         r_x,            // sum-check randomness derived from π_SC
         v_1, ..., v_t,  // CCS structure values
         ρ,              // randomness scalar from prover
         r_aug)          // commitment randomness for augmented witness
```



### Step 3: Return Values

```
return (⊥, ⊥,                    // empty LCCS pair (no actual folding at leaf level)
        u_aug, w_aug)            // augmented circuit instance & witness for HyperNova
```

The output consists of:
- **Empty LCCS pair** `(⊥, ⊥)` - No folding occurs at the leaf level, so we return empty/default values
- **Augmented circuit instance and witness** `(u_aug, w_aug)` - Ready to be fed into the parents of HyperNova

The augmented circuit encapsulates:
1. The verification of the Sum-Check protocol execution
2. The correctness of the CCS linearization 
3. The NIFS verification equation
4. All necessary auxiliary computations

## FoldInnerLCCS Algorithm

**Purpose:** Folds two inner-node LCCS proofs into one, and fabricates the "augmented-circuit" instance that will be fed to the next-higher HyperNova layer. The inner node computation would also ensure that the Mangrove partial permuations of the leaves are multiplied correctly as well as merging the hashes of the public values/permutation constraints and the witnesses. This routine is used when both children of the recursion tree are themselves linearised CCS nodes (no raw CCS leaves remain).

### Function Signature

```
FoldInnerLCCS(
    pk_NIFS, s,                 // folding-scheme prover key & CCS structure
    (U_1, W_1),                 // first child LCCS instance & witness
    (U_2, W_2),                 // second child LCCS instance & witness
    (u_1, w_1),                 // first child synthesized witness from previous round
    (u_2, w_2),                 // second child synthesized witness from previous round
    (U_secondary, W_secondary)  // Secondary circuit accumulator & witness
    pp_secondary,               // Pedersen commitment parameters on G₂
    shape_secondary,            // R1CS constraint shape for secondary circuit
) -> (
    U_F, W_F,                   // folded LCCS instance & witness
    u_aug, w_aug                // augmented circuit (instance, witness)
)
```

Note: `pk_NIFS` embeds the verifier key `vk_NIFS`; all randomness comes from domain-separated hash `R`.

### Step 1: Public Objects of the Two Children

**LCCS instances and witnesses from child nodes:**
Each child LCCS pair is:
```
U_i = (C_i, 1, x_i, r_{x,i}, v_{i,1}, …, v_{i,t})    // LCCS instance
W_i                                                  // LCCS witness
```
where `i ∈ {1, 2}` and:
- `C_i`: Commitment to the witness vector
- `x_i`: Public input vector 
- `r_{x,i}`: Evaluation point from Sum-Check protocol
- `v_{i,j}`: Linear combination values for each selector j
- `w_i`: Private witness vector satisfying the LCCS relation

**Synthesized witnesses from previous folding rounds:**
Each synthesized witness pair is:
```
u_i = (C_i, x_i, r_i, v_{i,1}, …, v_{i,t})          // synthesized instance
w_i = witness from previous round                   // synthesized witness
```
where `i ∈ {1, 2}` and:
- `C_i`: Commitment to the synthesized witness
- `x_i`: Public input from the augmented circuit  
- `r_i`: Randomness/evaluation point from previous folding
- `v_{i,j}`: Folded linear values from previous round
- `w_i`: Private witness containing all auxiliary data from previous folding operations

**Secondary circuit accumulator and parameters:**
```
U_secondary: RelaxedR1CSInstance<G2, C2> = {
    commitment_W: C2::Commitment,     // ∈ G₂ (Pedersen commitment to witness)
    commitment_E: C2::Commitment,     // ∈ G₂ (Pedersen commitment to error vector)  
    X: Vec<G2::ScalarField>          // ∈ 𝔽₂^{11} (public inputs for elliptic curve ops)
}

W_secondary: RelaxedR1CSWitness<G2> = {
    W: Vec<G2::ScalarField>,         // ∈ 𝔽₂^{num_vars} (private witness)
    <!-- E: Vec<G2::ScalarField>          // ∈ 𝔽₂^{num_constraints} (error vector for relaxation) -->
}

pp_secondary: C2::PP                 // Pedersen commitment parameters on curve G₂
shape_secondary: R1CSShape<G2>       // R1CS constraint matrices (A, B, C) for 11-IO circuit
```

Where:
- **G₂**: Secondary elliptic curve with G₂::ScalarField = G₁::BaseField = 𝔽₂
- **C2**: Pedersen commitment scheme operating on G₂  
- **11-IO circuit**: Enforces elliptic curve addition `g_out = g₁ + r·g₂` with public inputs `[1, g₁.x, g₁.y, g₁.z, g₂.x, g₂.y, g₂.z, g_out.x, g_out.y, g_out.z, r]`


If `(U_secondary, W_secondary)` is not available for some reason, they can be set to null values. Specifically, the following:

```
U_secondary_null: RelaxedR1CSInstance<G2, C2> = {
    commitment_W: C2::Commitment::zero(),     // Identity element on G₂ (point at infinity)
    commitment_E: C2::Commitment::zero(),     // Identity element on G₂ (point at infinity)
    X: vec![G2::ScalarField::zero(); 11]     // Vector of 11 zero elements in 𝔽₂
}

W_secondary_null: RelaxedR1CSWitness<G2> = {
    W: vec![G2::ScalarField::zero(); num_vars]  // Vector of zeros with length num_vars
}
```


### Step 2: Sumcheck and Linearization

#### 2.1 Polynomial to Collapse the Two Siblings

Define, with fresh verifier coefficients `γ ← R` and `r_x <- R`:

```
g(X) = eq(r_{x,1}, X) · ∑_{y∈{0,1}^{s'}} M_{fⱼ}(X, y) · z_{e,1}(y) 
     + γ · eq(r_{x,2}, X) · ∑_{y∈{0,1}^{s'}} M_{fⱼ}(X, y) · z_{e,2}(y)
```

*Notice that z_{e,1}(y) and z_{e,2}(y) are the folded witness values of the application circuit witnesses*
*We do not include in the sumcheck with witnesses involving the sythesized witness*

The two LCCS equations hold iff:
```
∑_{X∈{0,1}^s} g(X) = 0
```

#### 2.2 Prover ↔ Verifier Sum-Check

Verifier challenges through the random oracle produce `r'ₓ ∈ F^s` and the claimed value `c = g(r'ₓ)`.

**Prover sends:**
```
σ'_{1,j} = ∑_y M_{fⱼ}(r'ₓ, y) · z_{e,1}(y)
σ'_{2,j} = ∑_y M_{fⱼ}(r'ₓ, y) · z_{e,2}(y)
```

**Verifier recomputes** `g(r'ₓ)` with the formula above and accepts the transcript `π_SC` if it matches `c`.

*Note: Because the degree per variable is ≤ d+1, soundness error is (d+1)s/|F|.*


### Step 3: Folding in the Primary and Secondary Circuit  (Homomorphic Combination)

**Sample folding challenge:**
```
ρ ← R("fold-ρ" ∥ C1 | C2 | C1 | C2 ∥ r'ₓ) ∈ F
```

**Compute random linear combinations of the LCCS commitments in the Seconary Circuit**

The Secondary circuit would compute the following:
```
C_F := C_L + ρ · C_R + p^2 · C_l  + p^3 · C_r
```
where the public parameters of the circuit is ρ, C_L, C_R, C_l, C_r

Then, we generate the a new secondary witness, w_{synth_secondary}, that satisfies this secondary circuit with the given inputs

**Folding within Nova**
Then, compute T and Comm(T)
```
T = A·w_secondary ∘ B·w_synth_secondary  +  A·w_secondary ∘ B·w_synth_secondary  –  u₁·C·w_synth_secondary  –  u₂·C·w_secondary
```

Sample ρ' using Comm(T):
p' <- RO(Comm(T))

Then, construct fold the elements:

W_secondary' = W_secondary + ρ' * w_secondary
Comm(T_secondary') = Comm(T_secondary) + ρ' * Comm(T_secondary)
Comm(W_secondary') = Comm(W_secondary) + ρ' * Comm(w_secondary)
x_secondary' = X_secondary + p' * x_secondary

```
x_F := x_1 + ρ · x_2 + ρ^2 · x_{synth,1} + ρ^3 · x_{synth,2}
r_{x,F} := r_{x,1} + ρ · r_{x,2} + ρ^2 · r_1 + ρ^3 · r_2
v_{j,F} := v_{j,1} + ρ · v_{j,2} + ρ^2 · v_{synth,1,j} + ρ^3 · v_{synth,2,j}  (for j = 1…t)
W_F := w_1 + ρ · w_2 + ρ^2 · w_{synth,1} + ρ^3 · w_{synth,2}
```

**Fold-output instance:**
```
U_F := (C_F, 1, x_F, r_{x,F}, v_{1,F}, …, v_{t,F})
```

*Note: Multiple MSMs are needed to update both the LCCS and synthesized commitments.*

### Step 4: Augmented Circuit Computations within Primary Circuit

The step-circuit `FoldVerifier(vk_NIFS, U_L, U_R, u_l, u_r, ρ, π_SC)` is embedded into Nova's next layer. It contains four verification blocks:


#### 4.1 Sum-Check Verifier for the fold
Checks each round polynomial & finally g(r'ₓ) = c = 0

### 4.2 Computing the Mangrove merge constraints for each child
```
p_parent = ∏_{i=1}^k p_i                                    // Product aggregation
h_w,parent = Poseidon_Hash(h_w,1 || h_w,2 || ... || h_w,k)  // Witness hash aggregation
h_plk,parent = Poseidon_Hash(h_plk,1 || h_plk,2 || ... || h_plk,k) // Parameter hash aggregation
```

### 4.3 Recompute the verifier challenge for folding the secondary circuit
```
ρ ← R("fold-ρ" ∥ π_SC ∥ r'ₓ ∥ C_1 ∥ C_2 ∥ x_1 ∥ x_2)
p' <- RO(Comm(T))
```
This ensures that the folding challenge ρ incorporates both the sumcheck transcript and the synthesized witness commitments.


#### 4.4 LCCS field-arithmetic Folding Challenge Computation
Recompute x_F, r_{x,F}, v_{j,F} and assert they equal the public outputs in U_{F}
- **x_F** = x_1 + ρ·x_2 + ρ²·x_{synth,1} + ρ⁴·x_{synth,2} (folded public input)
- **r_{x,F}** = r_{x,1} + ρ·r_{x,2} + ρ²·r_1 + ρ⁴·r_2 (folded evaluation point)
- **v_{j,F}** = v_{j,1} + ρ·v_{j,2} + ρ²·v_{synth,1,j} + ρ⁴·v_{synth,2,j} ∀j∈[1..t] (folded linear values)

*Note: These homomorphic combinations require multiple multi-scalar multiplications (MSMs) to update both the LCCS commitments and synthesized witness commitments.*

#### 4.5 Compute Nova Folding Verifier Logic
Recompute the following in circuit:

W_secondary' = W_secondary + ρ' * w_secondary
Comm(T_secondary') = Comm(T_secondary) + ρ' * Comm(T_secondary)
Comm(W_secondary') = Comm(W_secondary) + ρ' * Comm(w_secondary)


The circuit outputs `accept = 1`.

**The augmented circuit synthesizes its witness containing:**

The circuit does not construct these values but rather includes them as:
- Existing witnesses from child LCCS instances
- Randomness derived from the protocol transcript
- Cryptographic proofs that will be verified by constraints

```
(C_F,                            // LCCS witness vectors from folding
U_F, w_2, w*,                             // synthesized witness components
ρ, π_SC, r'ₓ,                             // folding challenge, sum-check transcript, eval point
σ'_{1,1..t}, σ'_{2,1..t},                 // LCCS inner-product proofs
σ'_{synth,1,1..t}, σ'_{synth,2,1..t})     // synthesized witness evaluation proofs
```


### Step 5: Commit

**Derive commitment from the synthesized witness:**
```
r_aug ← R("aug-commit" ∥ w_aug)
C_aug := Commit(w_aug; r_aug)
```

**Compute augmented instance from the circuit's public inputs and commitment:**
u_aug := (C_aug,          // commitment to augmented witness
          x,              // public input from original circuit
          C,              // original witness commitment
          r'ₓ,            // evaluation point from sum-check
          v₁, ..., vₜ,    // linear combination values for selectors
          )              // folding parameter from NIFS


### Step 6: Return

```
return (U_F, W_F,          // folded LCCS pair
        u_aug, w_aug)      // augmented circuit package
```

**Performance characteristics:**
- Multiple MSMs for both LCCS and synthesized witness folding
- O(t·d·log m) field ops for the inner Sum-Check  
- Logarithmic verifier work inside the parent circuit
- Preserves HyperNova's linear-in-witness prover cost and succinct verification

---

## Folding Correctness of the HyperNova/Mangrove System

This section establishes that our folding mechanism correctly aggregates child proofs into parent proofs, ensuring that acceptance at any node implies validity of all its descendants.

### Mathematical Relations Being Folded

The folding operation combines two child instances into a parent instance using a challenge `ρ`. We distinguish between linear and non-linear components:

#### Linear Folding Relations

For the linear components, the parent stores the ρ-weighted affine combination:

```
C_F    = C_L + ρ·C_R                      ∈ G    // Commitment (curve point)
x_F    = x_L + ρ·x_R                      ∈ F^m  // Public input vector  
r_F    = r_L + ρ·r_R                      ∈ F^s  // Evaluation point
v_F    = v_L + ρ·v_R                      ∈ F^t  // Selector values (entrywise)
W_F    = W_L + ρ·W_R                      ∈ F^ℓ  // Witness vector
```

These leverage the additive homomorphism of Pedersen commitments and linearity of the constraint system.

#### Non-Linear Folding Relations

For the multiplicative and hash-based components:

```
p_F      = p_L · p_R                           ∈ F    // Permutation product (multiplicative)
h_w,F    = Poseidon(h_w,L || h_w,R)           ∈ F    // Witness Merkle parent
h_plk,F  = Poseidon(h_plk,L || h_plk,R)       ∈ F    // Permutation Merkle parent
```

These form a semiring homomorphism with multiplication in F and hash concatenation for tree aggregation.

### Core Folding Correctness Lemma

#### Lemma (Folding Correctness)
**Statement**: Given valid child instances `(X_L, W_L), (X_R, W_R) ∈ R_leaf`, and folding challenge `ρ ∈ F`, the folded instance `(X_F, W_F)` computed by the above relations satisfies `(X_F, W_F) ∈ R_leaf`.

**Proof**:

1. **Commitment Correctness**:
   ```
   Commit(W_F) = Commit(W_L + ρ·W_R)
               = Commit(W_L) + ρ·Commit(W_R)    // By Pedersen linearity
               = C_L + ρ·C_R
               = C_F
   ```
   Hence `C_F` correctly opens to `W_F`.

2. **Application Constraints**:
   Every constraint gate in `F` is either:
   - **Linear**: `a·w_i + b = 0`
   - **Bilinear**: `w_i · w_j - w_k = 0`
   
   For linear constraints:
   ```
   F_linear(W_F) = F_linear(W_L + ρ·W_R)
                 = F_linear(W_L) + ρ·F_linear(W_R)
                 = 0 + ρ·0 = 0
   ```
   
   For bilinear constraints, using `W_F = W_L + ρ·W_R`:
   ```
   (w_{i,L} + ρ·w_{i,R})(w_{j,L} + ρ·w_{j,R}) - (w_{k,L} + ρ·w_{k,R})
   = w_{i,L}·w_{j,L} + ρ(w_{i,L}·w_{j,R} + w_{i,R}·w_{j,L}) + ρ²·w_{i,R}·w_{j,R} - w_{k,L} - ρ·w_{k,R}
   ```
   Since both children satisfy their constraints, this equals `0`.

3. **Sum-Check Linear Values**:
   Each selector value `v_j` is an affine function of the witness:
   ```
   v_{j,F} = ⟨a_j, W_F⟩ = ⟨a_j, W_L + ρ·W_R⟩
           = ⟨a_j, W_L⟩ + ρ·⟨a_j, W_R⟩
           = v_{j,L} + ρ·v_{j,R}
   ```

4. **Permutation Product**:
   Since children operate on disjoint wire indices (domain-separated by chunk):
   - Left child: `p_L = ∏_{i∈I_L} H_{α,β}(w_{i,L}, σ_i)`
   - Right child: `p_R = ∏_{i∈I_R} H_{α,β}(w_{i,R}, σ_i)`
   - Parent: `p_F = ∏_{i∈I_L∪I_R} H_{α,β}(w_i, σ_i) = p_L · p_R`
   
   The multiplication correctly concatenates the two disjoint factorizations.

5. **Merkle Root Consistency**:
   By construction of Poseidon Merkle trees:
   ```
   h_w,F = Poseidon(h_w,L || h_w,R)    // Parent of two children
   h_plk,F = Poseidon(h_plk,L || h_plk,R)
   ```
   These are exactly the Merkle parent computations, preserving tree authenticity.

Therefore, all constraints of `R_leaf` are satisfied by `(X_F, W_F)`. □

### Verifier Checks and Child Validation

The step-circuit `FoldVerifier` embedded in the augmented R1CS enforces two critical verification blocks:

#### Verification Block A: Child Validity

| **Sub-verifier** | **What it Proves** | **Failure Consequence** |
|------------------|-------------------|------------------------|
| Sum-Check Verifier (Left) | `(X_L, W_L)` satisfies `F_L = 0`, permutation, etc. | Invalid left child detected |
| Sum-Check Verifier (Right) | `(X_R, W_R)` satisfies `F_R = 0`, permutation, etc. | Invalid right child detected |

If either child lies outside `R_leaf`, the corresponding Sum-Check fails, preventing proof creation.

#### Verification Block B: Folding Equations

The circuit enforces all eight folding identities from above:
- Linear combinations: `C_F = C_L + ρ·C_R`, `x_F = x_L + ρ·x_R`, etc.
- Multiplicative: `p_F = p_L · p_R`
- Hash aggregations: `h_w,F = Poseidon(h_w,L || h_w,R)`, etc.

These ensure the published parent instance is exactly the prescribed fold of the verified children.

### Tree-Wide Folding Correctness

We prove correctness inductively over the tree structure.

#### Definition
Let `P(v)` denote the statement: "If the verifier accepts the proof at node `v`, then the instance-witness pair of every leaf in `v`'s subtree lies in `R_leaf`."

#### Theorem (Inductive Folding Correctness)
**Statement**: `P(v)` holds for every node `v` in the tree.

**Proof by Structural Induction**:

**Base Case (Leaf)**: At a leaf, `FoldVerifier` reduces to:
- Sum-Check verification of the CCS constraints
- Commitment verification
- No folding equations (no children)

This is exactly the SNARK for the leaf relation, so `P(leaf)` holds.

**Inductive Step (Internal Node)**: Assume `P(left)` and `P(right)` hold for a node's children.
If the verifier accepts at node `v`:
1. Both children's proofs satisfy their verifiers (Block A)
2. Folding equations hold (Block B)
3. By induction hypothesis, every leaf below each child is valid
4. Therefore, every leaf below `v` is valid

Hence `P(v)` holds.

**Conclusion**: By structural induction, `P(root)` holds. A single accepted proof at the root convinces the verifier that all leaf computations are satisfied. □

### Why Forged Children Cannot Pass Through Folding

#### Theorem (No Propagation of Forgeries)
**Statement**: If an adversary provides instances `(X_L, X_R, X_F, π)` where `π` verifies but `X_R ∉ R_leaf` (is invalid), then no valid proof `π` can exist.

**Proof by Contradiction**:
Assume such a proof `π` exists. Since `X_R` is invalid, at least one constraint in its Sum-Check (Block A) evaluates to non-zero. The step-circuit is a deterministic R1CS circuit where:
- All constraints must evaluate to exactly zero
- No witness assignment can make a non-zero constraint become zero

Therefore, no satisfying witness for the augmented circuit exists, implying no SNARK proof can be generated. This contradicts the existence of `π`.

The same argument applies recursively: invalid nodes cannot be "laundered" through folding at any level of the tree.

### Implementation Details

#### Handling Multiple Children
When folding `k > 2` children, we extend the linear combination:
```
X_F = X_1 + ρ·X_2 + ρ²·X_3 + ... + ρ^{k-1}·X_k
```

The permutation products multiply: `p_F = ∏_{i=1}^k p_i`

The Merkle hashes aggregate: `h_F = Poseidon(h_1 || ... || h_k)`

#### Synthesized Witness Folding
For synthesized witnesses from augmented circuits:
```
C_F = C_L + ρ·C_R + ρ²·C_{synth,L} + ρ³·C_{synth,R}
```
This maintains the homomorphic structure while incorporating auxiliary folding data.

---

## Completeness of the HyperNova/Mangrove Proof System

This section formally establishes the completeness property of our proof system, demonstrating that valid computations always produce accepting proofs.

### The Statement Being Proved

#### Exact Relation Definition

The HyperNova/Mangrove proof system proves knowledge of a witness for the following relation:

```
R_HN = {
    ((x, h_plk, h_w); (w_base, aux)) | 
    the following four conditions hold:
}
```

Where the conditions are:

1. **Application Constraints**: For every chunk `j ∈ [T]` with witness `w_j`:
   ```
   F_j(w_j) = 0                                           // Application circuit (SHA-256/ECDSA/aggregation)
   G_T(s_j, w_j) = T_tid_j                                // Lookup constraints (if present)
   ```
   Where `F_j` includes both the application logic and Mangrove-specific gadgets.

2. **Global Copy-Permutation**: Let `z := (x || w_base) ∈ F^n`. For all `i ∈ [n]`:
   ```
   z_i = z_{σ(i)}
   ```
   Equivalently, the partial products satisfy:
   ```
   ∏_{j=1}^T p_j = 1
   ```

3. **Commitment Consistency**:
   - **Witness commitments**: For every leaf `j`:
     ```
     C_{w,j} = Pedersen(w_j; r_j)
     h_{w,j} = Poseidon(C_{w,j})
     ```
   - **Permutation commitments**:
     ```
     C_{plk,j} = Pedersen(j || σ_j || s_j; r'_j)
     h_{plk,j} = Poseidon(C_{plk,j})
     ```
   - **Merkle roots**:
     ```
     h_w = MerkleTree_Poseidon([C_{w,1}, ..., C_{w,T}])
     h_plk = MerkleTree_Poseidon([C_{plk,1}, ..., C_{plk,T}])
     ```

4. **Knowledge Soundness**: All commitments correctly open to their claimed values.

**Public Statement**: `(x, h_plk, h_w)` - The public input, permutation commitment root, and witness commitment root.

**Private Witness**: `(w_base, aux)` - The application witness and auxiliary data (Pedersen randomness, Merkle paths, folding transcripts, etc.).

### Definition of Perfect Completeness

**Definition (Perfect Completeness)**: A non-interactive argument scheme `(Gen, Prove, Verify)` for relation `R` has *perfect completeness* if:

```
∀ ((x,w) ∈ R) ∀ (ρ ∈ {0,1}*) : Verify(pp, x, Prove(pp, x, w; ρ)) = 1
```

That is: for every valid statement-witness pair, the honest prover (regardless of its internal randomness `ρ`) produces a proof that the deterministic verifier accepts with probability 1.

### Tree Structure and Proof Organization

The proof is organized as a tree where each node contains:

```
Z = (p,            // Partial permutation product
     h_w,          // Merkle hash of witness commitments under this subtree
     h_plk,        // Merkle hash of permutation commitments under this subtree
     X)            // Folded polynomial-opening instance
```

Each node satisfies a predicate `φ` that ensures:
- Base case (leaves): All local CCS constraints hold
- Recursive case (inner nodes): Children are valid and aggregation is correct

### Proof of Perfect Completeness

We establish completeness through a series of lemmas building from leaves to root.

#### Lemma 1 (Leaf Correctness)
**Statement**: For every leaf `j`, the tuple `(Z_j, π_j, W_j)` output by `LeafLineariseCCS` satisfies the base case of predicate `φ`.

**Proof**: 
By assumption, `(x, h_plk, h_w); (w_base, aux) ∈ R_HN`. This means:
- `F_j(w_j) = 0` holds (application constraints)
- The partial product `p_j` is correctly computed
- Commitments `h_{w,j}` and `h_{plk,j}` match their definitions

The leaf linearization:
1. Runs Sum-Check on the constraint polynomial `g(X)` with zero sum
2. Computes linear values `v_j` correctly
3. Constructs augmented witness satisfying all verification constraints

Since all algebraic equations in `f^{α,β}_G` evaluate to 0 and Merkle hashes match, the verifier accepts. □

#### Lemma 2 (Inner Node Correctness)
**Statement**: If `φ` accepts for children `v_1, ..., v_k`, then `FoldInnerLCCS` produces `(Z_v, π_v, W_v)` that satisfies `φ` for node `v`.

**Proof**:
The inner node computation:
1. **Hash aggregation**: 
   ```
   h_{w,v} = Poseidon(h_{w,v_1} || ... || h_{w,v_k})
   h_{plk,v} = Poseidon(h_{plk,v_1} || ... || h_{plk,v_k})
   ```
   These match the verifier's recomputation exactly.

2. **Product aggregation**:
   ```
   p_v = ∏_{i=1}^k p_{v_i}
   ```
   By induction, this telescopes correctly to the root.

3. **Folding correctness**: The NIFS folding scheme's correctness guarantees:
   ```
   V_Fold(X_{v_1}, ..., X_{v_k}, X_v, proof) = 1
   ```

All components of `φ` are satisfied. □

#### Lemma 3 (Root Acceptance)
**Statement**: If the root message `Z_★ = (p_★ = 1, h_w, h_plk, X_★)` satisfies `V_PCD(Z_★, π_★) = 1`, then the external verifier accepts.

**Proof**:
The external verifier checks:
1. **PCD verification**: `V_PCD(vk_pcd, Z_★, π_★) = 1` ✓ (given)
2. **Polynomial opening**: `(X_★, W_★) ∈ R_open` ✓ (from `φ`)
3. **Global permutation**: `p_★ = 1` ✓ (in `Z_★`)
4. **Merkle roots**: Match preprocessing and commitment ✓ (from `φ`)

All checks pass, so the verifier outputs accept. □

### How the Root Proof Certifies All Leaf Computations

The key insight is that accepting a root proof transitively validates the entire computation tree through the PCD structure.

#### Theorem (Complete Tree Validation)
**Statement**: If `V_PCD(vk_pcd, Z_v, π_v) = 1` for a node `v`, then `φ` holds at `v` and all its descendants.

**Proof by structural induction**:

**Base case (leaf)**: The PCD verifier applies `φ`'s base case, which explicitly includes:
- `F_j(w_j) = 0` (application constraints)
- Correct partial permutation product
- Valid commitment hashes

Acceptance implies all leaf constraints hold.

**Inductive step**: For an inner node with verified children:
- PCD checks each child proof recursively
- By induction hypothesis, all descendants satisfy `φ`
- The node's own constraints (aggregation, folding) are verified

Therefore, `φ` propagates from root to all leaves.

**At the root**: When `v = ★`:
```
φ(Z_★) is true
  ⟹ φ(Z_u) is true for every node u
  ⟹ All leaf CCS constraints F_j(w_j) = 0 hold
```

### Why the Verifier is Fully Convinced

The verifier's acceptance of the root proof provides complete assurance because:

1. **No Direct Leaf Verification Needed**: The PCD structure ensures that accepting the root transitively validates all leaves without examining them individually.

2. **Constraint Propagation**: The predicate `φ` explicitly includes leaf constraints in its base case, so PCD success at the root implies all application circuits were satisfied.

3. **Deterministic Verification**: All verifier checks are deterministic functions of public data (except Fiat-Shamir hashes), ensuring consistent acceptance.

4. **Global Consistency**: The permutation product `p_★ = 1` at the root certifies that all cross-chunk copy constraints are satisfied globally.

### Perfect Completeness Theorem

**Theorem (Perfect Completeness)**: For every `((x, h_plk, h_w); (w_base, aux)) ∈ R_HN`, the honest prover produces a proof `π` such that `Verify(pp, (x, h_plk, h_w), π) = 1` with probability 1.

**Proof**:
Given a valid witness:
1. By Lemma 1, all leaves produce accepting proofs
2. By Lemma 2 applied inductively, all inner nodes produce accepting proofs  
3. By Lemma 3, the root proof causes the external verifier to accept
4. The prover's randomness only affects commitment openings that are later verified, never invalidating constraints

Therefore, acceptance probability = 1. □

### Handling Zero Divisors

**Note on Statistical vs Perfect Completeness**: The system achieves perfect completeness only with the "denominator elimination" modification. Without it, completeness is statistical with failure probability ≤ `(m+t)/|F|` when `α` hits a zero divisor.

**Zero Divisor Fix**: Multiply through by denominators in the permutation argument:
```
∏_{i∈I_j} [H_{α,β}(w_i, i)] = ∏_{i∈I_j} [H_{α,β}(w_i, σ_i)]
```
This polynomial equation remains valid even when `α` would cause division by zero, preserving perfect completeness.

---

## Knowledge Soundness of the HyperNova/Mangrove Proof System

This section formally establishes the knowledge soundness property of our proof system, demonstrating that the verifier can detect invalid proofs and that fake proofs cannot be hidden through folding.

### Prerequisites and Security Assumptions

Our soundness proof relies on the following standard cryptographic assumptions:

| **Primitive** | **Security Property** | **Usage in Our System** |
|---------------|----------------------|-------------------------|
| Pedersen Commitment | Computationally binding & additively homomorphic | Prevents prover from changing witnessed chunks after commitment |
| Poseidon Hash | Collision resistance | Secures the two Merkle trees (witness and permutation) |
| NIFS Folding Scheme | Knowledge soundness | If parent instance accepted, all children instances must be valid |
| PCD Scheme | Knowledge soundness | Accepting root proof implies φ holds at every node |
| Leaf NARK | Perfect soundness | Forged CCS/LCCS chunk proof is detected |

All primitives are assumed secure against probabilistic polynomial-time (PPT) adversaries.

### Definition of Adaptive Knowledge Soundness

**Definition (Adaptive Knowledge Soundness)**: For every PPT adversary `A`, there exists an expected polynomial-time extractor `E` such that for every security parameter `λ`:

```
Pr[Verify(pp, x, Π) = 1 ∧ (x ∉ L(R_HN))] ≤ negl(λ)
```

And more precisely, for knowledge soundness:

```
Pr[Verify(pp, x, Π, ao) = 1 ∧ 
   E^A(pp, x, Π, ao) outputs witness w such that (x, w) ∈ R_HN] 
   ≥ Pr[Verify accepts] - negl(λ)
```

Where `ao` is the adversary's auxiliary output, ensuring the extractor produces a witness for the same instance that convinced the verifier.

**More formally**, a prover `P*` is knowledge sound if:

```
Pr[ Verifier(pp, x, Π) = accept ∧ (x, w) ∉ R_HN
    : (Π, x) ← P*(pp, aux) ] ≤ negl(λ)                     // Soundness

Pr[ Verifier(pp, x, Π) = accept ∧ (x, w) ∈ R_HN
    ∧ w ← E(pp, x, Π, ao) ] ≥ Pr[Verifier accepts] - negl(λ)  // Knowledge extraction
```

The extractor must output witnesses for every leaf (hence for the entire computation) while running in expected polynomial time.

### Per-Node Folding Knowledge Property

Before establishing global knowledge soundness, we first prove a crucial per-node property.

#### Lemma (Node-Level Folding Knowledge)
**Statement**: Let a parent node carry:
- Data: `Z = (p, h_plk, h_w, X)` (instance)
- Witness: `W`
- Proof: `pf` (folding proof)
- Children: `(Z_1, X_1), ..., (Z_k, X_k)` with proofs `π_1, ..., π_k`

If the node verifier (predicate φ) accepts, then there exists an efficient extractor `E_fold` that outputs:
```
witnesses W_1, ..., W_k such that (X_i, W_i) ∈ R_leaf for every i
```

**Proof**: The predicate φ runs `V_Fold(fvk, [X_i], X, pf)`. Since the folding scheme is knowledge sound, there exists `E_fold` (independent of HyperNova) that, from `([X_i], X, pf)` and the verifier's randomness, returns valid witnesses `W_i` for all children. □

This lemma is the cornerstone of our extraction strategy: each folding proof "knows" the witnesses of its children.

### Local Detectability (Single-Node Soundness)

We first establish that invalid proofs are detected at the node level.

#### Lemma 1 (Node-Level Soundness)
**Statement**: For any arity-k node with children statements `Z_1, ..., Z_k`, if any of the following conditions fail, the verifier rejects:

| **Failure Type** | **Detection Mechanism** |
|-----------------|------------------------|
| Child proof `π_i` is forged | `V_PCD(vk_pcd, Z_i, π_i) = 0` |
| Folding proof is invalid | `V_Fold(fvk, [X_1,...,X_k], X, pf) = 0` |
| Incorrect hash/product aggregation | Explicit equality checks in φ fail |
| Leaf CCS constraints violated | Leaf branch of φ + NARK soundness |

**Proof**: Each verification consists of either:
- Explicit field/hash element equality checks
- Calls to sound sub-verifiers (PCD, folding, NARK)

Any violation causes at least one check to fail, resulting in rejection. □

### The Three-Layer Extraction Process

We construct a global extractor `E*` that works in three distinct layers, each leveraging different knowledge-sound components.

#### Layer 1: PCD Tree Unrolling

Run the knowledge extractor `E_PCD` guaranteed by the PCD system on the root proof `(Z_root, π_root)`.

**Output**: The entire proof tree
```
T = { (Z_v, X_v, pf_v, π_v) | v ranges over all nodes }
```
along with the local randomness used in each φ-verification.

**Guarantee**: By PCD knowledge soundness, predicate φ holds at every node in T.

#### Layer 2: Folding Witness Extraction

Traverse the tree T from root to leaves:

1. **For each internal node v**:
   - Feed `(X_{v,1}, ..., X_{v,k}, X_v, pf_v)` to `E_fold`
   - Obtain witnesses `W_{v,1}, ..., W_{v,k}` for all children
   - Store these witnesses and recurse on children

2. **Continue until all leaves are reached**

**Guarantee**: By the node-level folding knowledge lemma, we recover valid witnesses for all intermediate instances.

#### Layer 3: Leaf Witness Extraction

When reaching a leaf node ℓ:
- Its instance is `X_ℓ = (commitments, ...)`
- The predicate φ has already verified the leaf NARK and accepted
- Apply the NARK's knowledge extractor `E_leaf` to obtain `w_leaf`

**Output**: Witness `w_leaf` such that `(X_ℓ, w_leaf) ∈ R_leaf`

**Final assembly**: Collect all leaf witnesses into `w = (w_leaf)_leaves` that satisfies every chunk relation.

#### Running Time Analysis

The total extraction time is:
```
T_E = T_P · poly(λ)
```
where `T_P` is the adversary's running time.

**Breakdown**:
- Layer 1 (PCD): One extraction per node = `O(|T| · poly(λ))`
- Layer 2 (Folding): One extraction per internal node = `O(|T_internal| · poly(λ))`
- Layer 3 (Leaf): One extraction per leaf = `O(|T_leaves| · poly(λ))`

Since `|T| = O(T_P)`, the extractor runs in expected polynomial time.

### The Extraction Chain: From Root to Leaves

We now demonstrate how accepting the root proof allows extraction of valid witnesses for all leaves.

#### Step 1: PCD Tree Extraction

**Lemma 2 (PCD Extraction)**: If the verifier accepts `Π = (Z_★, π_★, ...)`, then by the knowledge soundness of the PCD scheme, there exists an extractor `E^PCD` that outputs:

```
T = {(Z_v, X_v, pf_v, π_v) | v is any node in the tree}
```

along with witnesses for leaf NARKs, except with negligible probability.

Moreover, `E^PCD` guarantees that predicate `φ` holds at every node in `T`.

#### Step 2: Folding Witness Extraction

**Lemma 3 (Folding Extraction)**: For each internal node `v` where `φ` holds, since `V_Fold` accepted `(X_{v,1},...,X_{v,k}, X_v, pf_v)`, the folding scheme's knowledge soundness provides an extractor `E^Fold` that outputs witnesses proving each child instance `X_{v,i}` is valid.

**Proof**: Apply `E^Fold` recursively from root to leaves. For each leaf `ℓ`, we recover a witness satisfying the polynomial relation `R_open(L_x, L_e, f_{α,β}^G)`, which encodes:
- The CCS chunk constraints
- The local permutation product check
- The commitment consistency requirements

#### Step 3: Leaf Constraint Satisfaction

**Lemma 4 (Leaf Soundness)**: The leaf instance `X_ℓ` contains:
- Pedersen commitment to chunk witness
- Hash-chained products and Merkle hashes

The leaf check in `φ` re-runs the deterministic NARK verifier. By the NARK's soundness, acceptance implies the chunk constraints `F_j(w_j) = 0` truly hold.

### Global Knowledge Soundness Theorem

#### Theorem (HyperNova/Mangrove Knowledge Soundness)
**Statement**: The extractor `E*` defined by the three-layer process satisfies the definition of knowledge soundness. Consequently, any prover that convinces the verifier must "know" complete witnesses for all leaves.

**Proof**:
Given a valid proof `Π` that the verifier accepts, the extractor `E*` outputs a valid witness `w` such that `(x, w) ∈ R_HN`.

1. **PCD Tree Unrolling**: `E^PCD` outputs the entire proof tree `T`
2. **Folding Witness Extraction**: `E^Fold` outputs valid witnesses for all intermediate instances
3. **Leaf Witness Extraction**: `E_leaf` outputs a valid witness for the leaf

Since `E*` outputs a valid witness for every node in the tree, it satisfies the definition of knowledge soundness. □

### Folding Implies Knowledge of Children

A key insight is that the folding operation itself enforces knowledge of children's witnesses.

#### Theorem (Folding Knowledge Implication)
**Statement**: If a prover produces a valid folding proof `pf` such that `V_Fold(fvk, [X_L, X_R], X_parent, pf) = 1`, then the prover must "know" valid witnesses `W_L, W_R` for both children.

**Proof**:
1. **By folding knowledge soundness**: The existence of an accepting folding proof implies the existence of an extractor `E_fold` that can recover `W_L, W_R`.

2. **Witness validity**: These extracted witnesses must satisfy:
   - `(X_L, W_L) ∈ R_leaf` (left child is valid)
   - `(X_R, W_R) ∈ R_leaf` (right child is valid)

3. **Implication**: The prover cannot create a valid folding proof without implicitly demonstrating knowledge of both children's witnesses.

This property is crucial for security: it means that folding acts as a "knowledge barrier" - invalid instances cannot pass through because producing the folding proof would require knowing witnesses that don't exist.

### Why Fake Proofs Cannot Be Hidden by Folding

A critical security property is that invalid child proofs cannot be "laundered" through the folding operation.

#### Theorem 2 (No Folding of Invalid Proofs)
**Statement**: Given two forged child instances `X_L, X_R` (where the corresponding constraints don't actually hold), no PPT adversary can produce a folding proof `pf` that makes the parent node accept.

**Proof**:
Suppose `A` attempts to fold invalid `X_L, X_R` by producing `pf` such that:
```
V_Fold(fvk, [X_L, X_R], X_parent, pf) = 1
```

By the folding scheme's knowledge soundness:
1. Extractor `E^Fold` recovers witnesses `(W_L, W_R)` for the children
2. These witnesses must satisfy the polynomial relations for `X_L, X_R`
3. But this implies the "forged" instances were actually valid!

This contradiction shows that invalid children are detected either:
- **Locally**: When verifying their individual proofs (Lemma 1)
- **During folding**: The folding verifier rejects invalid combinations

**Corollary**: Soundness violations cannot propagate up the tree. Every invalid node is caught at its own level or when attempting to fold it with siblings.

### Soundness Error Analysis

The overall soundness error is the maximum of:

1. **Sum-Check soundness error**: `(d+1)s/|F|` per node
2. **Fiat-Shamir security**: `negl(λ)` for random oracle model
3. **Commitment binding failure**: `negl(λ)` under discrete log assumption
4. **PCD/Folding extraction failure**: `negl(λ)` by assumption

For a field size `|F| > 2^256` and appropriate security parameters, the total soundness error is negligible.

---

## Unified Summary: Security Properties of HyperNova/Mangrove

The HyperNova/Mangrove proof system achieves three fundamental security properties:

### 1. Folding Correctness
The system correctly aggregates child proofs into parent proofs through:
- **Algebraic Homomorphism**: Leveraging Pedersen commitment linearity, multiplicative permutation products, and Poseidon Merkle tree aggregation
- **Step-Circuit Verification**: Two-block verification ensuring both child validity (Block A) and correct folding equations (Block B)
- **Inductive Propagation**: Tree-wide correctness follows from node-level correctness, ensuring acceptance at any node implies validity of all descendants

### 2. Perfect Completeness
Valid computations always produce accepting proofs through:
- **Structured PCD Predicate**: Carefully designed to include all necessary constraints at both leaf and inner nodes
- **Deterministic Verification**: All checks are deterministic except Fiat-Shamir challenges
- **Tree Aggregation**: Validity propagates correctly from leaves to root via proper hash aggregation and product multiplication
- **Zero-Divisor Handling**: Denominator elimination ensures perfect (not statistical) completeness

### 3. Knowledge Soundness
The verifier can detect invalid proofs and extract witnesses through:
- **Three-Layer Extraction**: PCD unrolling → Folding extraction → Leaf extraction
- **Per-Node Knowledge**: Each folding proof implies knowledge of children's witnesses
- **No Hidden Forgeries**: Folding acts as a "knowledge barrier" - invalid instances cannot be laundered
- **Efficient Extraction**: Extractor runs in time T_P · poly(λ), maintaining efficiency

### Security Foundation
The system's security reduces to standard assumptions:
- Pedersen commitments (binding & homomorphic)
- Poseidon hash (collision resistance)  
- NIFS folding scheme (knowledge soundness)
- PCD scheme (knowledge soundness)
- Leaf NARK (perfect soundness)

### Key Insight
A single valid root proof guarantees the entire computation tree is correct. The verifier never needs to examine individual leaves - the recursive structure ensures that root acceptance transitively validates all leaf computations through the PCD predicate φ. This provides scalable verification for large computations split across operation-specific chunks (SHA-256, ECDSA, aggregation) while maintaining strong security guarantees.
