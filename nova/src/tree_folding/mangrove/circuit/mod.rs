pub mod mangrove_leaf;
pub mod sha256_leaf_circuit;
pub mod sha256_var;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub use mangrove_leaf::{
    compute_permutation_partial_products, MangroveLeafCircuit, MangroveLeafData, MangroveLeafVar,
    PermutationPartialProductsVar,
};
pub use sha256_leaf_circuit::Sha256LeafCircuit;
pub use sha256_var::Sha256Var;

/// A trait for converting types into a vector of FpVar
pub trait IntoFpVarVec<F: PrimeField> {
    fn into_fp_var_vec(&self) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

/// A trait for function circuits that transform inputs to outputs
pub trait FnCircuit<F: PrimeField, Input, Output>
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
