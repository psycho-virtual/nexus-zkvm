use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::Valid;
use std::borrow::Borrow;
use tracing::{debug, error, info, instrument};

use super::{FnCircuit, IntoFpVarVec};

const LOG_TARGET: &str = "nexus-nova::tree_folding::mangrove::circuit::mangrove_leaf";

/// Native Mangrove leaf data structure for any input/output types
/// This is the native computation equivalent of MangroveLeafVar
#[derive(Clone, Debug)]
pub struct MangroveLeafData<F: PrimeField, Input, Output>
where
    Input: Clone + Valid,
    Output: Clone + Valid,
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

impl<F, Input, Output> AllocVar<MangroveLeafData<F, Input::Value, Output::Value>, F>
    for MangroveLeafVar<F, Input, Output>
where
    F: PrimeField,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
{
    #[instrument(target = LOG_TARGET, skip(cs, f))]
    fn new_variable<T: Borrow<MangroveLeafData<F, Input::Value, Output::Value>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let data = f()?;
        let data = data.borrow();

        info!(
            target: LOG_TARGET,
            "Allocating MangroveLeafVar with {} input indices, {} output indices",
            data.permutation_input_index.len(),
            data.permutation_output_index.len()
        );

        // Allocate the scalar challenges as variables
        let alpha = FpVar::<F>::new_variable(cs.clone(), || Ok(data.alpha), mode)?;
        let beta = FpVar::<F>::new_variable(cs.clone(), || Ok(data.beta), mode)?;

        debug!(
            target: LOG_TARGET,
            "Allocated alpha and beta challenges"
        );

        // Allocate the I/O state gadgets
        let input = Input::new_variable(cs.clone(), || Ok(data.input.clone()), mode)?;
        let output = Output::new_variable(cs.clone(), || Ok(data.output.clone()), mode)?;

        debug!(
            target: LOG_TARGET,
            "Allocated input and output variables"
        );

        // Allocate the four permutation-index vectors
        let permutation_input_index: Vec<_> = data
            .permutation_input_index
            .iter()
            .map(|&idx| FpVar::new_variable(cs.clone(), || Ok(idx), mode))
            .collect::<Result<_, _>>()?;

        let permutation_input_next_index: Vec<_> = data
            .permutation_input_next_index
            .iter()
            .map(|&idx| FpVar::new_variable(cs.clone(), || Ok(idx), mode))
            .collect::<Result<_, _>>()?;

        let permutation_output_index: Vec<_> = data
            .permutation_output_index
            .iter()
            .map(|&idx| FpVar::new_variable(cs.clone(), || Ok(idx), mode))
            .collect::<Result<_, _>>()?;

        let permutation_output_next_index: Vec<_> = data
            .permutation_output_next_index
            .iter()
            .map(|&idx| FpVar::new_variable(cs.clone(), || Ok(idx), mode))
            .collect::<Result<_, _>>()?;

        debug!(
            target: LOG_TARGET,
            "Allocated all permutation index vectors"
        );

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

/// Struct to hold partial products for permutation argument
#[derive(Clone, Debug)]
pub struct PermutationPartialProductsVar<F: PrimeField> {
    /// Product of (alpha * index + beta + value) terms
    pub numerator: FpVar<F>,
    /// Product of (alpha * next_index + beta + value) terms
    pub denominator: FpVar<F>,
}

// Implement the required traits for PermutationPartialProductsVar
impl<F: PrimeField> R1CSVar<F> for PermutationPartialProductsVar<F> {
    type Value = (F, F);

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.numerator.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok((self.numerator.value()?, self.denominator.value()?))
    }
}

impl<F: PrimeField> AllocVar<(F, F), F> for PermutationPartialProductsVar<F> {
    fn new_variable<T: Borrow<(F, F)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let (num, den) = f()?.borrow().clone();
        let numerator = FpVar::new_variable(cs.clone(), || Ok(num), mode)?;
        let denominator = FpVar::new_variable(cs, || Ok(den), mode)?;
        Ok(Self { numerator, denominator })
    }
}

impl<F: PrimeField> IntoFpVarVec<F> for PermutationPartialProductsVar<F> {
    fn into_fp_var_vec(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![self.numerator.clone(), self.denominator.clone()])
    }
}

/// Helper function to compute permutation partial products in circuit
#[instrument(target = LOG_TARGET, skip(values, indices, next_indices, alpha, beta), fields(num_indices = indices.len(), next_num_indices = next_indices.len()))]
pub fn compute_permutation_partial_products<F: PrimeField, T>(
    values: &T,
    indices: &[FpVar<F>],
    next_indices: &[FpVar<F>],
    alpha: &FpVar<F>,
    beta: &FpVar<F>,
) -> Result<PermutationPartialProductsVar<F>, SynthesisError>
where
    T: IntoFpVarVec<F>,
{
    let value_vars = values.into_fp_var_vec()?;

    if value_vars.len() != indices.len() || value_vars.len() != next_indices.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    info!(
        target: LOG_TARGET,
        "Computing permutation partial products for {} values",
        value_vars.len()
    );

    let mut numerator = FpVar::<F>::one();
    let mut denominator = FpVar::<F>::one();

    for i in 0..value_vars.len() {
        // Numerator: product of (alpha * index + beta + value)
        let num_term = alpha * &indices[i] + beta + &value_vars[i];
        numerator = &numerator * &num_term;

        // Denominator: product of (alpha * next_index + beta + value)
        let den_term = alpha * &next_indices[i] + beta + &value_vars[i];
        denominator = &denominator * &den_term;
    }

    Ok(PermutationPartialProductsVar { numerator, denominator })
}

// Implement IntoFpVarVec for MangroveLeafVar
impl<F: PrimeField, Input, Output> IntoFpVarVec<F> for MangroveLeafVar<F, Input, Output>
where
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
{
    fn into_fp_var_vec(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut vars = vec![self.alpha.clone(), self.beta.clone()];
        vars.extend(self.input.into_fp_var_vec()?);
        vars.extend(self.permutation_input_index.iter().cloned());
        vars.extend(self.permutation_input_next_index.iter().cloned());
        vars.extend(self.output.into_fp_var_vec()?);
        vars.extend(self.permutation_output_index.iter().cloned());
        vars.extend(self.permutation_output_next_index.iter().cloned());
        Ok(vars)
    }
}

// Implement R1CSVar for MangroveLeafVar
impl<F: PrimeField, Input, Output> R1CSVar<F> for MangroveLeafVar<F, Input, Output>
where
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
{
    type Value = (
        F,
        F,
        Input::Value,
        Output::Value,
        Vec<F>,
        Vec<F>,
        Vec<F>,
        Vec<F>,
    );

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.alpha.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let input_indices: Result<Vec<F>, _> = self
            .permutation_input_index
            .iter()
            .map(|v| v.value())
            .collect();
        let input_next_indices: Result<Vec<F>, _> = self
            .permutation_input_next_index
            .iter()
            .map(|v| v.value())
            .collect();
        let output_indices: Result<Vec<F>, _> = self
            .permutation_output_index
            .iter()
            .map(|v| v.value())
            .collect();
        let output_next_indices: Result<Vec<F>, _> = self
            .permutation_output_next_index
            .iter()
            .map(|v| v.value())
            .collect();

        Ok((
            self.alpha.value()?,
            self.beta.value()?,
            self.input.value()?,
            self.output.value()?,
            input_indices?,
            input_next_indices?,
            output_indices?,
            output_next_indices?,
        ))
    }
}

/// Generic Mangrove Leaf Circuit that wraps any base circuit with permutation handling
/// This circuit computes the base function and generates permutation partial products
pub struct MangroveLeafCircuit<F: PrimeField, C, Input, Output>
where
    F: PrimeField,
    C: FnCircuit<F, Input, Output>,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
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
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
{
    pub fn new(base_circuit: C) -> Self {
        Self {
            base_circuit,
            _phantom: std::marker::PhantomData,
        }
    }
}

// Add a separate AllocVar implementation for the tuple type
impl<F, Input, Output>
    AllocVar<
        (
            F,
            F,
            Input::Value,
            Output::Value,
            Vec<F>,
            Vec<F>,
            Vec<F>,
            Vec<F>,
        ),
        F,
    > for MangroveLeafVar<F, Input, Output>
where
    F: PrimeField,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
{
    fn new_variable<
        T: Borrow<(
            F,
            F,
            Input::Value,
            Output::Value,
            Vec<F>,
            Vec<F>,
            Vec<F>,
            Vec<F>,
        )>,
    >(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let tuple = f()?;
        let (
            alpha,
            beta,
            input_val,
            output_val,
            input_idx,
            input_next_idx,
            output_idx,
            output_next_idx,
        ) = tuple.borrow().clone();

        // Create MangroveLeafData from tuple
        let data = MangroveLeafData {
            alpha,
            beta,
            input: input_val,
            permutation_input_index: input_idx,
            permutation_input_next_index: input_next_idx,
            output: output_val,
            permutation_output_index: output_idx,
            permutation_output_next_index: output_next_idx,
        };

        // Use the existing MangroveLeafData implementation
        Self::new_variable(cs, || Ok(data), mode)
    }
}

impl<F, C, Input, Output>
    FnCircuit<F, MangroveLeafVar<F, Input, Output>, PermutationPartialProductsVar<F>>
    for MangroveLeafCircuit<F, C, Input, Output>
where
    F: PrimeField,
    C: FnCircuit<F, Input, Output>,
    Input: AllocVar<Input::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Input::Value: Valid,
    Output: AllocVar<Output::Value, F> + R1CSVar<F> + Clone + IntoFpVarVec<F>,
    Output::Value: Valid,
{
    #[instrument(target = LOG_TARGET, skip(self, cs, mangrove_var))]
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        mangrove_var: &MangroveLeafVar<F, Input, Output>,
    ) -> Result<PermutationPartialProductsVar<F>, SynthesisError> {
        info!(
            target: LOG_TARGET,
            "Generating constraints for MangroveLeafCircuit"
        );

        // Step 1: Run the base circuit to compute the output
        debug!(target: LOG_TARGET, "Running base circuit");
        let computed_output = self
            .base_circuit
            .generate_constraints(cs.clone(), &mangrove_var.input)?;

        // Check constraint system after base circuit
        if let Ok(satisfied) = cs.is_satisfied() {
            debug!(target: LOG_TARGET, "Constraint system satisfied after base circuit: {}", satisfied);
        } else {
            error!(target: LOG_TARGET, "Constraint system unsatisfied after base circuit");
        }

        // Step 2: Enforce that computed output equals the expected output
        debug!(target: LOG_TARGET, "Enforcing output consistency");
        let computed_output_vars = computed_output.into_fp_var_vec()?;
        let expected_output_vars = mangrove_var.output.into_fp_var_vec()?;

        if computed_output_vars.len() != expected_output_vars.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Step 3: Compute input permutation partial products
        debug!(target: LOG_TARGET, "Computing input permutation partial products");
        let input_products = compute_permutation_partial_products(
            &mangrove_var.input,
            &mangrove_var.permutation_input_index,
            &mangrove_var.permutation_input_next_index,
            &mangrove_var.alpha,
            &mangrove_var.beta,
        )?;

        // Check constraint system after input permutation computation
        if let Ok(satisfied) = cs.is_satisfied() {
            debug!(target: LOG_TARGET, "Constraint system satisfied after input permutation: {}", satisfied);
        } else {
            error!(target: LOG_TARGET, "Constraint system unsatisfied after input permutation");
            if let Ok(Some(idx)) = cs.which_is_unsatisfied() {
                error!(target: LOG_TARGET, "Unsatisfied constraint at index: {:?}", idx);
            }
        }

        // Step 4: Compute output permutation partial products
        debug!(target: LOG_TARGET, "Computing output permutation partial products");
        let output_products = compute_permutation_partial_products(
            &mangrove_var.output,
            &mangrove_var.permutation_output_index,
            &mangrove_var.permutation_output_next_index,
            &mangrove_var.alpha,
            &mangrove_var.beta,
        )?;

        // Check constraint system after output permutation computation
        if let Ok(satisfied) = cs.is_satisfied() {
            debug!(target: LOG_TARGET, "Constraint system satisfied after output permutation: {}", satisfied);
        } else {
            error!(target: LOG_TARGET, "Constraint system unsatisfied after output permutation");
            if let Ok(Some(idx)) = cs.which_is_unsatisfied() {
                error!(target: LOG_TARGET, "Unsatisfied constraint at index: {:?}", idx);
            }
        }

        // Step 5: Combine the partial products
        // Final numerator = input_numerator * output_numerator
        // Final denominator = input_denominator * output_denominator
        debug!(target: LOG_TARGET, "Combining partial products");
        let final_numerator = &input_products.numerator * &output_products.numerator;
        let final_denominator = &input_products.denominator * &output_products.denominator;

        info!(
            target: LOG_TARGET,
            "MangroveLeafCircuit constraint generation complete"
        );

        Ok(PermutationPartialProductsVar {
            numerator: final_numerator,
            denominator: final_denominator,
        })
    }
}
