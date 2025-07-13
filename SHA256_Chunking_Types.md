# SHA256 Chunking with Mangrove Folding - Type Signatures

Core data structures, traits, and function signatures for implementing chunked SHA256 operations with permutation-based folding proofs.

---

## Core Data Structures

### SHA256ChainRequest

```rust
use ark_std::vec::Vec;

/// Initial request for SHA256 chain computation before permutation calculations
#[derive(Clone, Debug)]
pub struct SHA256ChainRequest<F: Field> {
    pub id: usize,
    pub num_sha256: usize,
    pub input: Vec<F>,
    pub output: Vec<F>,
}
```

### SHA256ChainMangroveComputation

```rust
/// Complete computation with all partial permutations
#[derive(Clone, Debug)]
pub struct SHA256ChainMangroveComputation<F: Field> {
    pub id: usize,
    pub start_permutation_idx: usize
    pub num_sha256: usize,
    pub input: Vec<F>,
    pub output: Vec<F>,
    pub input_permutation: Vec<PermutationTuple<F>>,
    pub output_permutation: Vec<PermutationTuple<F>>,
    // IMPORTANT: There is an invariant the next permutations for one of the an output_permutation would match the vector of the next input
    // IMPORTANT: There is an invariant that the number of elements for input and output would match the size of input_permutation and output_permutation
}

impl<F: Field> SHA256ChainMangroveComputation<F> {
    pub fn from_request_with_permutations(
        request: SHA256ChainRequest<F>,
        input_permutation: Vec<PermutationTuple<F>>,
        output_permutation: Vec<PermutationTuple<F>>,
    ) -> Self;

    pub fn request(&self) -> SHA256ChainRequest<F>;
}
```

### SHA256ChainBuilder

```rust
pub struct SHA256ChainBuilder<F: Field> {
    pub chain_length: usize,
    pub num_leafs: usize,
    pub leaf_size: usize,
    /// Expected size of input vector per leaf
    /// For BN254 field: ~2 field elements per SHA256 operation (64 bytes ÷ 31 bytes/element)
    /// Total: num_sha256_per_leaf * 2 elements
    pub input_vector_size: usize,
    /// Expected size of output vector per leaf
    /// For BN254 field: 1 field element per SHA256 operation (32 bytes fits in 31-byte element)
    /// Total: num_sha256_per_leaf * 1 element
    pub output_vector_size: usize,
}

fn create_leafs(request: SHA256ChainRequest<F>) -> SHA256ChainMangroveComputation<F>

impl<F: Field> SHA256ChainBuilder<F> {
    pub fn new(chain_length: usize, num_leafs: usize) -> Self;
    pub fn generate_requests(&self, initial_input: &[u8]) -> Vec<SHA256ChainRequest<F>>;
    pub fn compute_mangrove_constraints(&self, requests: Vec<SHA256ChainRequest<F>>) -> Vec<SHA256ChainMangroveComputation<F>>;
}
```

### SHA256LeafCircuit

```rust
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, uint8::UInt8, alloc::AllocVar, R1CSVar};

/// Trait for types that can be flattened to a vector of FpVar without allocation
pub trait IntoFpVarVec<F: PrimeField> {
    fn fp_vars(&self) -> Vec<FpVar<F>>;
}

### SHA 256 Circuit

```rust
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

/// R1CS constraint variable for PermutationTuple
#[derive(Clone, Debug)]
pub struct PermutationTupleVar<F: PrimeField> {
    /// Local index within the chunk
    pub local_idx: FpVar<F>,
    /// Field element value
    pub value: FpVar<F>,
    /// Next global index in the permutation
    pub next_global_idx: FpVar<F>,
}

impl<F: PrimeField> IntoFpVarVec<F> for PermutationTupleVar<F> {
    fn fp_vars(&self) -> Vec<FpVar<F>> {
        vec![
            self.local_idx.clone(),
            self.value.clone(),
            self.next_global_idx.clone(),
        ]
    }
}

/// R1CS constraint variable for SHA256 input/output
/// Native representation: Vec<u8>
/// Circuit representation: Vec<Vec<FpVar<F>>>
#[derive(Clone, Debug)]
pub struct SHA256Var<F: PrimeField> {
    /// Each inner Vec<FpVar<F>> represents bytes packed into field elements
    /// For SHA256 input: typically 64 bytes packed into field elements
    /// For SHA256 output: 32 bytes packed into field elements
    pub bytes_as_field_groups: Vec<Vec<FpVar<F>>>,
}

impl<F: PrimeField> R1CSVar<F> for SHA256Var<F> {
    type Value = Vec<u8>;

    fn cs(&self) -> ConstraintSystemRef<F>;
    fn value(&self) -> Result<Self::Value, SynthesisError>;
}

impl<F: PrimeField> AllocVar<Vec<u8>, F> for SHA256Var<F> {
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError>;
}

impl<F: PrimeField> IntoFpVarVec<F> for SHA256Var<F> {
    fn fp_vars(&self) -> Vec<FpVar<F>> {
        self.bytes_as_field_groups
            .iter()
            .flat_map(|group| group.iter().cloned())
            .collect()
    }
}

/// Native Mangrove leaf data structure for any input/output types
/// This is the native computation equivalent of MangroveLeafVar
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct MangroveLeafData<F: PrimeField, Input, Output>
where
    Input: Clone,
    Output: Clone,
{
    /// Alpha challenge for permutation argument
    pub alpha: F,
    /// Beta challenge for permutation argument
    pub beta: F,

    /// Input data
    pub input: Input,
    /// Permutation indices for input
    pub permutation_input_index: Vec<F>,
    /// Next permutation indices for input
    pub permutation_input_next_index: Vec<F>,

    /// Output data
    pub output: Output,
    /// Permutation indices for output
    pub permutation_output_index: Vec<F>,
    /// Next permutation indices for output
    pub permutation_output_next_index: Vec<F>,
}

/// Generic Mangrove constraint structure for any circuit input/output types
#[derive(Clone, Debug)]
pub struct MangroveLeafVar<F: PrimeField, Input, Output>
where
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
{
    /// Alpha challenge for permutation argument
    pub alpha: FpVar<F>,
    /// Beta challenge for permutation argument
    pub beta: FpVar<F>,
    /// Input representation
    pub input: Input,
    pub permutation_input_index: Vec<FpVar<F>>,
    pub permutation_input_next_index: Vec<FpVar<F>>,

    /// Output representation
    pub output: Output,
    pub permutation_output_index: Vec<FpVar<F>>,
    pub permutation_output_next_index: Vec<FpVar<F>>,
}

/// Type alias for SHA256 leaf with Mangrove constraints
pub type SHA256LeafMangroveVar<F> = MangroveLeafVar<F, SHA256Var<F>, SHA256Var<F>>;

// TODO: There should be a corresponding MangroveConstraintSystem
impl<F, Input, Output> AllocVar<MangroveLeafData<F>, F> for MangroveLeafVar<F, Input, Output>
where
    F: PrimeField,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: From<Vec<F>>,
    Output::Value: From<Vec<F>>,
{
    fn new_variable<T: Borrow<MangroveLeafData<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let data = f()?;
        let data = data.borrow();

        // Allocate the scalar challenges as variables
        let alpha = FpVar::<F>::new_variable(
            cs.clone(),
            || Ok(data.alpha),
            mode,
        )?;
        let beta = FpVar::<F>::new_variable(
            cs.clone(),
            || Ok(data.beta),
            mode,
        )?;

        // Allocate the I/O state gadgets
        let input = Input::new_variable(cs.clone(), || Ok(data.input_val.clone().into()), mode)?;
        let output = Output::new_variable(cs.clone(), || Ok(data.output_val.clone().into()), mode)?;

        // Allocate the four permutation-index vectors
        let permutation_input_index: Vec<_> = data.leaf_job.input_permutation.iter()
            .map(|p| FpVar::new_variable(cs.clone(), || Ok(F::from(p.local_idx as u64)), mode))
            .collect::<Result<_, _>>()?;

        let permutation_input_next_index: Vec<_> = data.leaf_job.input_permutation.iter()
            .map(|p| FpVar::new_variable(cs.clone(), || Ok(F::from(p.next_global_idx as u64)), mode))
            .collect::<Result<_, _>>()?;

        let permutation_output_index: Vec<_> = data.leaf_job.output_permutation.iter()
            .map(|p| FpVar::new_variable(cs.clone(), || Ok(F::from(p.local_idx as u64)), mode))
            .collect::<Result<_, _>>()?;

        let permutation_output_next_index: Vec<_> = data.leaf_job.output_permutation.iter()
            .map(|p| FpVar::new_variable(cs.clone(), || Ok(F::from(p.next_global_idx as u64)), mode))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            alpha,
            beta,
            input,
            permutation_input_index,
            permutation_input_next_index,
            output,
            permutation_output_index,
            permutation_output_next_index,
        })
    }
}

pub trait FnCircuit<F: PrimeField, Input, Output>: Send + Sync
where
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
{
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        input: &Input,
    ) -> Result<Output, SynthesisError>;
}

/// Generic Mangrove Leaf Circuit that wraps any base circuit with permutation handling
/// This circuit computes the base function and generates permutation partial products
pub struct MangroveLeafCircuit<F: PrimeField, C, Input, Output>
where
    F: PrimeField,
    C: FnCircuit<F, Input, Output>,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
{
    /// The base circuit that computes the actual function (e.g., SHA256)
    pub base_circuit: C,
    /// Phantom data for type parameters
    _phantom: std::marker::PhantomData<(F, Input, Output)>,
}

impl<F, C, Input, Output> MangroveLeafCircuit<F, C, Input, Output>
where
    F: PrimeField,
    C: FnCircuit<F, Input, Output>,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
{
    pub fn new(base_circuit: C) -> Self {
        Self {
            base_circuit,
            _phantom: std::marker::PhantomData,
        }
    }
}



impl<F, C, Input, Output> FnCircuit<F, MangroveLeafVar<F, Input, Output>, PermutationPartialProducts<F>>
    for MangroveLeafCircuit<F, C, Input, Output>
where
    F: PrimeField,
    C: FnCircuit<F, Input, Output>,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
{
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        mangrove_var: &MangroveLeafVar<F, Input, Output>,
    ) -> Result<PermutationPartialProducts<F>, SynthesisError> {
        // Step 1: Run the base circuit to compute the output
        let output = self.base_circuit.generate_constraints(cs.clone(), &mangrove_var.input)?;

        // Step 2: Compute input permutation partial products
        let input_products = compute_permutation_partial_products(
            &mangrove_var.input,
            &mangrove_var.permutation_input_index,
            &mangrove_var.permutation_input_next_index,
            &mangrove_var.alpha,
            &mangrove_var.beta,
        )?;

        // Step 3: Compute output permutation partial products
        let output_products = compute_permutation_partial_products(
            &output,
            &mangrove_var.permutation_output_index,
            &mangrove_var.permutation_output_next_index,
            &mangrove_var.alpha,
            &mangrove_var.beta,
        )?;

        // Step 4: Combine the partial products
        // Final numerator = input_numerator * output_numerator
        // Final denominator = input_denominator * output_denominator
        let final_numerator = input_products.numerator * &output_products.numerator;
        let final_denominator = input_products.denominator * &output_products.denominator;

        Ok(PermutationPartialProducts {
            numerator: final_numerator,
            denominator: final_denominator,
        })
    }
}

/// Type alias for SHA256 with Mangrove permutation handling
pub type SHA256MangroveCircuit<F> = MangroveLeafCircuit<F, SHA256Circuit<F>, SHA256Var<F>, SHA256Var<F>>;

pub struct SHA256LeafCircuit<F: PrimeField> {
    pub leaf: SHA256LeafJob<F>,
    pub id: u32,
}

/// SHA256 Circuit Implementation (base circuit without permutation handling)
pub struct SHA256Circuit<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> SHA256Circuit<F> {
    pub fn new() -> Self;
}

impl<F: PrimeField> FnCircuit<F, SHA256Var<F>, SHA256Var<F>> for SHA256Circuit<F> {
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        input: &SHA256Var<F>,
    ) -> Result<SHA256Var<F>, SynthesisError>;
}

/// Helper functions for SHA256Var
impl<F: PrimeField> SHA256Var<F> {
    /// Convert to UInt8 vector for use with crypto primitives
    pub fn to_uint8_vec(&self) -> Result<Vec<UInt8<F>>, SynthesisError>;

    /// Create from UInt8 vector
    pub fn from_uint8_vec(cs: ConstraintSystemRef<F>, bytes: &[UInt8<F>]) -> Result<Self, SynthesisError>;

    /// Pack bytes into field elements (for witness generation)
    pub fn pack_bytes_to_field_groups(bytes: &[u8]) -> Vec<Vec<F>>;

    /// Unpack field elements to bytes (for value extraction)
    pub fn unpack_to_bytes(&self) -> Result<Vec<u8>, SynthesisError>;
}

/// Struct to hold partial products for permutation argument
#[derive(Clone, Debug)]
pub struct PermutationPartialProducts<F: PrimeField> {
    /// Product of (alpha * index + beta + value) terms
    pub numerator: FpVar<F>,
    /// Product of (alpha * next_index + beta + value) terms
    pub denominator: FpVar<F>,
}

/// Helper function to compute permutation partial products
fn compute_permutation_partial_products<F: PrimeField>(
    values: &SHA256Var<F>,
    indices: &[FpVar<F>],
    next_indices: &[FpVar<F>],
    alpha: &FpVar<F>,
    beta: &FpVar<F>,
) -> Result<PermutationPartialProducts<F>, SynthesisError>;
```



## Key Design Benefits

### Immutable Design
- **SHA256LeafData**: Immutable struct for basic leaf information
- **SHA256LeafJob**: Immutable struct created from data + permutations
- No mutating methods that modify internal state

### Type Safety
- Clear distinction between raw leaf data and permutation-enhanced leafs
- Cannot accidentally use leaf data without permutations where full leaf job is needed
- Compiler enforces proper construction flow

### Builder Pattern
- Natural progression: SHA256LeafData → SHA256LeafJob
- Clean separation of concerns between data computation and permutation calculation
- Enables parallel processing of different stages

### FnCircuit Integration
- Compatible with Nova/HyperNova folding schemes
- Functional circuit pattern for composable operations
- Structured input/output serialization for circuit operations

## Testing Strategy

### 1. Unit Tests

#### SHA256Circuit Tests
- Verify single SHA256 computation matches native Rust implementation
- Test constraint satisfaction for known SHA256 test vectors
- Validate circuit produces correct output variables

### 2. Integration Tests

#### SHA256ChainBuilder Tests
- Test leaf generation for various chain lengths
- Verify leaf boundaries and data continuity
- Test permutation tuple generation between leafs

#### Cross-Leaf Permutation Consistency Test
**Critical test to verify the permutation argument across different leaf strategies:**
- Create 8 leafs with 4 SHA256 rounds each (32 total rounds)
- Generate constraints and compute partial products for each leaf
- Multiply all partial products together: combined_numerator / combined_denominator
- Verify the result equals 1 (numerator == denominator)
- Create a single leaf with 32 SHA256 rounds using same initial input
- Verify its partial product also equals 1
- Both strategies should produce identical final SHA256 output

This test validates that:
- Permutation arguments correctly connect leafs
- The product telescopes properly across leaf boundaries
- Different leaf strategies maintain consistency
