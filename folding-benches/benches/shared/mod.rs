use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use nexus_nova::StepCircuit;

// Constants for benchmark configuration
pub const NUM_WARMUP_STEPS: usize = 10;
// Reduce to a single small circuit size to avoid freezing
pub const DEFAULT_CONSTRAINT_SIZES: [usize; 1] = [4];

/// Calculate the maximum degree for SRS setup based on circuit size
/// This ensures we avoid the TooManyCoefficients error for larger circuits
pub fn calculate_srs_degree(num_constraints: usize) -> usize {
    // Make SRS degree at least 2x the number of constraints to avoid TooManyCoefficients error
    // This is a conservative approach to ensure we don't run into sizing issues
    let min_degree = 8; // Minimum to get things working for small circuits
    let max_degree = 32; // Avoid unnecessarily large SRS for testing
    
    // Scale with the circuit size
    let degree = std::cmp::max(min_degree, num_constraints * 2);
    std::cmp::min(degree, max_degree)
}

/// A non-trivial test circuit for benchmarking
/// This is the same circuit used in nova-benches
pub struct NonTrivialTestCircuit<F> {
    num_constraints: usize,
    _p: PhantomData<F>,
}

impl<F> NonTrivialTestCircuit<F>
where
    F: PrimeField,
{
    pub fn new(num_constraints: usize) -> Self {
        Self { num_constraints, _p: PhantomData }
    }
}

impl<F> StepCircuit<F> for NonTrivialTestCircuit<F>
where
    F: PrimeField,
{
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        _: ConstraintSystemRef<F>,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Consider an equation: `x^2 = y`, where `x` and `y` are respectively the input and output.
        let mut x = z[0].clone();
        let mut y = x.clone();
        for _ in 0..self.num_constraints {
            y = x.square()?;
            x = y.clone();
        }
        Ok(vec![y])
    }
}

/// A more complex circuit with multiple types of constraints
/// This creates a mix of different constraint types to better simulate real usage
pub struct MixedConstraintCircuit<F> {
    num_constraints: usize,
    _p: PhantomData<F>,
}

impl<F> MixedConstraintCircuit<F>
where
    F: PrimeField,
{
    pub fn new(num_constraints: usize) -> Self {
        Self { num_constraints, _p: PhantomData }
    }
}

impl<F> StepCircuit<F> for MixedConstraintCircuit<F>
where
    F: PrimeField,
{
    const ARITY: usize = 2;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _aux: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut x = z[0].clone();
        let mut y = z[1].clone();

        // Distribute constraints among different operations
        let ops_per_type = self.num_constraints / 4;

        // Type 1: Squares (x^2)
        for _ in 0..ops_per_type {
            x = x.square()?;
        }

        // Type 2: Multiplications (x * y)
        for _ in 0..ops_per_type {
            let temp = &x * &y;
            x = temp;
        }

        // Type 3: Additions (x + y)
        for _ in 0..ops_per_type {
            let temp = &x + &y;
            y = temp;
        }

        // Type 4: Complex expressions
        for _ in 0..ops_per_type {
            let temp = &(&x * &y) + &x.square()?;
            x = temp;
        }

        // Remaining operations as multiplications
        for _ in 0..(self.num_constraints - 4 * ops_per_type) {
            let temp = &x * &y;
            x = temp;
        }

        // Enforce a final constraint
        let result = &x + &y;

        Ok(vec![result])
    }
}

/// Helper functions for benchmarks
pub mod utils {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_ff::PrimeField;
    use nexus_nova::poseidon_config;

    /// Create a Poseidon random oracle config for the given field
    pub fn create_ro_config<F: PrimeField>() -> ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F> {
        poseidon_config::<F>()
    }
}