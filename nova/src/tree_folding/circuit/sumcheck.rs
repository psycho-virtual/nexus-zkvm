//! Sumcheck verifier circuit utilities
//!
//! This module provides reusable gadgets for verifying the multi-linear
//! sumcheck protocol **in–circuit**.  Most of the logic is copied from the
//! implementation that already exists in
//! `linearization_augmented_circuit.rs` but has been extracted so it can be
//! reused by the CCS and LCCS folding verifier gadgets.

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::AdditiveGroup;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};

use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use tracing::instrument;

use crate::ccs::Error;

// Re–export the constant that specifies how many native field elements are
// squeezed for the verifier challenge in each sum-check round.
use crate::folding::hypernova::ml_sumcheck::protocol::verifier::SQUEEZE_NATIVE_ELEMENTS_NUM;
use crate::folding::hypernova::ml_sumcheck::PolynomialInfo;

const LOG_TARGET: &str = "nexus-nova::tree_folding::circuit::sumcheck";

/// Maximum cardinality (q) used by the polynomial interpolations (taken from
/// the linearization circuit).  A value of **2** is sufficient for all of the
/// folding constructions we currently support.
///
/// NOTE:  If this constant ever changes in the linearization module make sure
/// to update it here as well so that both gadgets stay in sync.
pub const MAX_CARDINALITY: usize = 2;

// ----------------------------------------------------------------------------------
//  Equality polynomial
// ----------------------------------------------------------------------------------

/// Compute the equality polynomial `eq(a, b)` where
///
/// `eq(a,b) = ∏ᵢ [aᵢ·bᵢ + (1-aᵢ)·(1-bᵢ)]`.
///
/// This is the standard multi-linear extension of the equality predicate and is
/// used in many protocols (including the HyperNova folding constructions).
#[inline]
pub fn compute_equality_polynomial<G1>(
    a: &[FpVar<G1::ScalarField>],
    b: &[FpVar<G1::ScalarField>],
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    assert_eq!(a.len(), b.len(), "Input vectors must be the same length");

    let one = FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE);
    let res = a
        .iter()
        .zip(b.iter())
        .map(|(ai, bi)| {
            // a_i * b_i + (1-a_i)*(1-b_i)
            let term1 = ai * bi;
            let term2 = (one.clone() - ai) * (one.clone() - bi);
            term1 + term2
        })
        .fold(one.clone(), |acc, x| acc * x);

    Ok(res)
}

/// Compute the equality polynomial `eq(a, b)` for **native** field elements.
///
/// This is the native version that works with `G::ScalarField` directly,
/// used in contexts where we don't need circuit constraints.
pub fn compute_equality_polynomial_native<G: CurveGroup>(
    a: &[G::ScalarField],
    b: &[G::ScalarField],
) -> Result<G::ScalarField, Error> {
    if a.len() != b.len() {
        return Err(Error::NotSatisfied);
    }

    let result: G::ScalarField = a
        .iter()
        .zip(b.iter())
        .map(|(ai, bi)| {
            // Compute aᵢ·bᵢ + (1-aᵢ)·(1-bᵢ)
            // = aᵢ·bᵢ + 1 - aᵢ - bᵢ + aᵢ·bᵢ
            // = 2·aᵢ·bᵢ - aᵢ - bᵢ + 1
            let ai_bi = *ai * bi;
            ai_bi + ai_bi - ai - bi + G::ScalarField::ONE
        })
        .product();

    Ok(result)
}

// ----------------------------------------------------------------------------------
//  Single round check (internal helper)
// ----------------------------------------------------------------------------------

/// Verify a single round of the sum-check protocol.
///
/// For round *k* we must check `p_k(0) + p_k(1) = p_{k-1}(r_{k-1})` and then
/// perform Lagrange interpolation (using the degree-two barycentric formula)
/// to compute `p_k(r_k)`.
fn verify_sumcheck_round<G1>(
    expected: &FpVar<G1::ScalarField>,
    evals: &[FpVar<G1::ScalarField>],
    r: &FpVar<G1::ScalarField>,
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    // Enforce the consistency equation p_k(0) + p_k(1) = p_{k-1}(r_{k-1}).
    expected.enforce_equal(&(&evals[0] + &evals[1]))?;

    tracing::trace!(target: LOG_TARGET, "Round consistency check passed");

    // Compute Lagrange interpolation: p(r) = Σ_{i=0}^{len-1} p_i * L_i(r)
    // where L_i(r) = Π_{j≠i} (r - j) / (i - j)
    let len = MAX_CARDINALITY + 2;
    let zero = FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ZERO);
    let one = FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE);

    let mut result = zero;

    for i in 0..len {
        let mut numerator = one.clone();
        let mut denominator = G1::ScalarField::ONE;

        // Compute Π_{j≠i} (r - j) and Π_{j≠i} (i - j)
        for j in 0..len {
            if i != j {
                let j_field = G1::ScalarField::from(j as u64);
                let i_field = G1::ScalarField::from(i as u64);

                numerator = numerator * (r - j_field);
                denominator = denominator * (i_field - j_field);
            }
        }

        // L_i(r) = numerator / denominator
        let lagrange_basis = numerator.mul_by_inverse(&FpVar::Constant(denominator))?;

        // Add p_i * L_i(r) to result
        result = result + (&evals[i] * &lagrange_basis);
    }

    Ok(result)
}

// ----------------------------------------------------------------------------------
//  Full multi-round verifier
// ----------------------------------------------------------------------------------

/// Verify all sumcheck rounds and collect challenges.
///
/// This function performs the complete sumcheck verification process:
/// 1. Uses the provided expected sum as the initial value for verification
/// 2. Iterates through all sumcheck proof rounds, performing the following for each:
///    - Absorbs polynomial evaluations from the prover message
///    - Generates and absorbs the verifier challenge r_k
///    - Verifies round consistency: p_k(0) + p_k(1) = p_{k-1}(r_{k-1})
///    - Computes the next expected value via Lagrange interpolation
///    - Collects the challenge points for final verification
///
/// # Arguments
///
/// * `random_oracle` - The cryptographic sponge for challenge generation
/// * `sumcheck_evals` - The polynomial evaluations for each round
/// * `expected_sum_of_polynomial` - The expected initial sum to verify against
/// * `sumcheck_rounds` - Number of sumcheck rounds to process
///
/// # Returns
///
/// Returns a tuple containing:
/// - The final expected value after all rounds
/// - Vector of challenge points r_k from each round
#[allow(clippy::type_complexity)]
#[instrument(level = "debug", skip(random_oracle, sumcheck_evals))]
pub fn verify_all_sumcheck<G1, RO>(
    cs: &mut ConstraintSystemRef<G1::ScalarField>,
    random_oracle: &mut RO::Var,
    sumcheck_evals: &[Vec<FpVar<G1::ScalarField>>],
    expected_sum_of_polynomial: FpVar<G1::ScalarField>,
    polynomial_info: &PolynomialInfo,
) -> Result<(FpVar<G1::ScalarField>, Vec<FpVar<G1::ScalarField>>), SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    ns!(cs, "Absorbing Polynomial Info into Random oracle");
    // Absorb polynomial info to synchronize with prover's random oracle state
    let polynomial_info_fields = vec![
        FpVar::Constant(G1::ScalarField::from(
            polynomial_info.max_multiplicands as u64,
        )),
        FpVar::Constant(G1::ScalarField::from(polynomial_info.num_variables as u64)),
        FpVar::Constant(G1::ScalarField::from(polynomial_info.num_terms as u64)),
    ];
    random_oracle.absorb(&polynomial_info_fields)?;

    let sumcheck_rounds = polynomial_info.num_variables;

    // Start with the provided expected sum as the initial expected value
    let mut expected = expected_sum_of_polynomial.clone();
    let mut rs_p: Vec<FpVar<G1::ScalarField>> = Vec::with_capacity(sumcheck_rounds);

    tracing::debug!(target: LOG_TARGET, "Starting sumcheck verification with {} rounds", sumcheck_rounds);
    // Debug check: verify constraint system state before starting rounds
    if let Ok(is_satisfied) = rs_p.cs().is_satisfied() {
        if is_satisfied {
            tracing::debug!(target: LOG_TARGET, "Constraint system is already satisfied before sumcheck rounds");
        } else {
            tracing::error!(target: LOG_TARGET, "Constraint system is not satisfied before sumcheck rounds");
        }
    }

    for round in 0..sumcheck_rounds {
        ns!(cs, "Sumcheck Round");
        // Absorb polynomial evaluations (the prover message)
        let evals = &sumcheck_evals[round];
        random_oracle.absorb(evals)?;

        // Fetch verifier challenge r_k and immediately absorb it per spec.
        let r_k = random_oracle.squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)?[0].clone();
        tracing::debug!(target: LOG_TARGET, "Round {}: Generated challenge r_k = {:?}", round, r_k.value().unwrap_or_else(|_| G1::ScalarField::ZERO));
        random_oracle.absorb(&r_k)?;

        // Enforce p_k(0) + p_k(1) = p_{k-1}(r_{k-1}) and derive the next
        // expected value via Lagrange interpolation.
        expected = verify_sumcheck_round::<G1>(&expected, evals, &r_k)?;
        rs_p.push(r_k.clone());

        // Check if the constraint system is satisfied after this round
        if !r_k.cs().is_satisfied().unwrap_or(false) {
            tracing::error!(target: LOG_TARGET, "Round {}: Constraint system not satisfied after verification", round);
        }

        tracing::debug!(target: LOG_TARGET, "Round {} verified successfully", round);
    }

    tracing::debug!(target: LOG_TARGET, "✓ All {} sumcheck rounds completed successfully", sumcheck_rounds);
    Ok((expected, rs_p))
}

// ----------------------------------------------------------------------------------
//  Target checks for folding applications
// ----------------------------------------------------------------------------------

/// Verify the target sum-check equality for *CCS* folding (ν = 2).
#[allow(clippy::too_many_arguments)]
pub fn verify_target_sumcheck_for_ccs_folding<G1>(
    gamma: &FpVar<G1::ScalarField>,
    e2: &FpVar<G1::ScalarField>,
    theta1: &[FpVar<G1::ScalarField>],
    theta2: &[FpVar<G1::ScalarField>],
    multiset_coeffs: &[(G1::ScalarField, Vec<usize>)],
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    // Helper to compute   Σ_i c_i · Π_{j in S_i} θ_{j,k}
    let eval_sum = |thetas: &[FpVar<G1::ScalarField>]| -> FpVar<G1::ScalarField> {
        multiset_coeffs
            .iter()
            .map(|(c_i, S_i)| {
                S_i.iter()
                    .fold(FpVar::Constant(*c_i), |acc, &j| acc * &thetas[j])
            })
            .sum()
    };

    let term1 = gamma.clone() * e2 * &eval_sum(theta1);
    let gamma_sq = gamma * gamma;
    let term2 = gamma_sq * e2 * &eval_sum(theta2);

    tracing::debug!(target: LOG_TARGET, "CCS folding target verification completed");
    Ok(term1 + term2)
}

/// Verify the target sum-check equality for *LCCS* folding (μ = 2).
#[allow(clippy::too_many_arguments)]
pub fn verify_target_sumcheck_for_lccs_folding<G1>(
    gamma: &FpVar<G1::ScalarField>,
    e1: &FpVar<G1::ScalarField>,
    sigma1: &[FpVar<G1::ScalarField>],
    sigma2: &[FpVar<G1::ScalarField>],
    num_matrices: usize,
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    assert_eq!(sigma1.len(), num_matrices);
    assert_eq!(sigma2.len(), num_matrices);

    // ∑_{j} γ^j · e1 · σ_{j,1}
    let mut gamma_pow = FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE);
    let mut term1 = FpVar::<G1::ScalarField>::zero();
    for j in 0..num_matrices {
        term1 += &gamma_pow * e1 * &sigma1[j];
        gamma_pow *= gamma; // γ^{j+1}
    }

    // term2 starts with γ^t
    let mut term2_gamma_pow = gamma_pow.clone();
    let mut term2 = FpVar::<G1::ScalarField>::zero();
    for j in 0..num_matrices {
        term2 += &term2_gamma_pow * e1 * &sigma2[j];
        term2_gamma_pow *= gamma; // γ^{t+j+1}
    }

    tracing::debug!(target: LOG_TARGET, "LCCS folding target verification completed");
    Ok(term1 + term2)
}

// ----------------------------------------------------------------------------------
//  Tests
// ----------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ccs::{
            ccs_fold::construct_combined_ccs_polynomial,
            linearization::{
                setup_linearization, synthesize_and_linearize_step,
                synthesize_step_circuit_with_params, StepFunctionInput,
            },
        },
        circuits::nova::StepCircuit,
        folding::hypernova::ml_sumcheck::MLSumcheck,
        poseidon_config,
        provider::zeromorph::Zeromorph,
        tree_folding::circuit::{
            sequential_sha256::SequentialSha256Circuit,
            sha256::{calculate_sha256_native, conversions},
        },
    };
    use ark_bn254::{Bn254, Fr, G1Projective as G1};
    use ark_crypto_primitives::sponge::{
        poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
        CryptographicSponge,
    };
    use ark_ec::AdditiveGroup;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_spartan::polycommitments::PolyCommitmentScheme;
    use ark_std::{marker::PhantomData, test_rng, UniformRand};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    type Z = Zeromorph<Bn254>;

    // Simple cubic circuit: y = x^3 + x + 5
    #[derive(Debug)]
    struct CubicCircuit<F: PrimeField> {
        _p: PhantomData<F>,
    }
    impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
        const ARITY: usize = 1;
        fn generate_constraints(
            &self,
            _cs: ark_relations::r1cs::ConstraintSystemRef<F>,
            _i: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, ark_relations::r1cs::SynthesisError> {
            assert_eq!(z.len(), 1);
            let x = &z[0];
            let y = x.clone() + x.square()? * x + FpVar::Constant(F::from(5u64));
            Ok(vec![y])
        }
    }

    // Tracing target for sumcheck tests
    const TEST_TARGET: &str = "nexus-nova::tree_folding::circuit::sumcheck::test";

    // Helper function to set up tracing for tests
    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target("nexus-nova", tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer()
                    .without_time()
                    .with_line_number(true),
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_verify_all_sumcheck_cubic() {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        tracing::info!(target: TEST_TARGET, "🧮 Starting cubic circuit sumcheck verification test");

        let config = poseidon_config::<Fr>();
        // Commitment key (not actually used in this test but required by linearization helpers)
        let num_vars = 8; // 2^8 >= constraints for cubic circuit
        let ck = {
            let srs = Z::setup(num_vars, b"test", &mut rng).unwrap();
            let keys = Z::trim(&srs, num_vars);
            keys.ck
        };

        // Setup CCS shape
        let cs_setup = ConstraintSystem::<Fr>::new_ref();
        let params =
            setup_linearization::<G1, _>(cs_setup, CubicCircuit::<Fr> { _p: PhantomData }).unwrap();

        // Prover side – linearize one step to obtain a real sumcheck proof
        let mut prover_ro = PoseidonSponge::new(&config);
        let input_state = Fr::rand(&mut rng);
        let step_input = StepFunctionInput { i: Fr::ONE, z_i: vec![input_state] };
        let cs_prover = ConstraintSystem::<Fr>::new_ref();
        let lin_res = synthesize_and_linearize_step::<G1, Z, _, _>(
            cs_prover,
            &params,
            &step_input,
            &ck,
            &mut prover_ro,
        )
        .unwrap();

        let sumcheck_rounds = lin_res.linearization.sumcheck_rounds;
        let sumcheck_evals_native: Vec<Vec<Fr>> = lin_res
            .linearization
            .sumcheck_proof
            .iter()
            .map(|msg| msg.evaluations.clone())
            .collect();

        // Build circuit witness for the evaluations
        let mut cs = ConstraintSystem::<Fr>::new_ref();
        let sumcheck_evals_var: Vec<Vec<FpVar<Fr>>> = sumcheck_evals_native
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|e| FpVar::new_witness(cs.clone(), || Ok(*e)).unwrap())
                    .collect()
            })
            .collect();

        // Create SpongeVar for verifier
        let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);
        // The prover squeezed γ once and β sumcheck_rounds times before starting rounds.
        sponge_var.squeeze_field_elements(1).unwrap();
        sponge_var.squeeze_field_elements(sumcheck_rounds).unwrap();

        // Expected initial sum is zero for satisfied CCS instance
        let expected_zero = FpVar::<Fr>::Constant(Fr::ZERO);

        let res = verify_all_sumcheck::<ark_bn254::g1::Config, PoseidonSponge<Fr>>(
            &mut cs,
            &mut sponge_var,
            &sumcheck_evals_var,
            expected_zero,
            &lin_res.linearization.polynomial.info(),
        )
        .unwrap();

        // Ensure constraint system satisfied
        assert!(cs.is_satisfied().unwrap());
        // Also basic sanity: number of challenges collected matches rounds
        assert_eq!(res.1.len(), sumcheck_rounds);

        tracing::info!(target: TEST_TARGET, "✅ Cubic circuit sumcheck verification completed successfully");
        tracing::info!(target: TEST_TARGET, "Generated {} challenges for {} rounds", res.1.len(), sumcheck_rounds);
        tracing::info!(target: TEST_TARGET, "Total constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_verify_all_sumcheck_sha256() {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        tracing::info!(target: TEST_TARGET, "🔐 Starting SHA256 circuit sumcheck verification test");
        let config = poseidon_config::<Fr>();

        // Setup commitment key with more variables for SHA256
        let num_vars = 16; // SHA256 requires significantly more variables
        let ck = {
            let srs = Z::setup(num_vars, b"test", &mut rng).unwrap();
            let keys = Z::trim(&srs, num_vars);
            keys.ck
        };

        // Setup CCS shape for SHA256 circuit
        let cs_setup = ConstraintSystem::<Fr>::new_ref();
        let params =
            setup_linearization::<G1, _>(cs_setup, SequentialSha256Circuit::<Fr>::new()).unwrap();

        tracing::debug!(target: TEST_TARGET, "✓ SHA256 linearization parameters setup completed");

        // Prover side – linearize one step to obtain a real sumcheck proof
        let mut prover_ro = PoseidonSponge::new(&config);

        // Create SHA256 input: hash of "hello world"
        let initial_message = b"hello world";
        let initial_hash = calculate_sha256_native(initial_message);
        let hash_as_field = conversions::bytes_to_field::<Fr>(&initial_hash);

        tracing::debug!(target: TEST_TARGET, "SHA256 input hash (hex): {}",
            initial_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());

        let step_input = StepFunctionInput { i: Fr::ONE, z_i: vec![hash_as_field] };

        let cs_prover = ConstraintSystem::<Fr>::new_ref();
        let lin_res = synthesize_and_linearize_step::<G1, Z, _, _>(
            cs_prover,
            &params,
            &step_input,
            &ck,
            &mut prover_ro,
        )
        .unwrap();

        let sumcheck_rounds = lin_res.linearization.sumcheck_rounds;

        tracing::debug!(target: TEST_TARGET, "✓ SHA256 linearization completed successfully");
        tracing::debug!(target: TEST_TARGET,
            "SHA256 linearization data - sumcheck rounds: {}, evaluations per round: {}",
            sumcheck_rounds,
            lin_res.linearization.sumcheck_proof.len()
        );
        let sumcheck_evals_native: Vec<Vec<Fr>> = lin_res
            .linearization
            .sumcheck_proof
            .iter()
            .map(|msg| msg.evaluations.clone())
            .collect();

        // Build circuit witness for the evaluations
        let mut cs = ConstraintSystem::<Fr>::new_ref();
        let sumcheck_evals_var: Vec<Vec<FpVar<Fr>>> = sumcheck_evals_native
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|e| FpVar::new_witness(cs.clone(), || Ok(*e)).unwrap())
                    .collect()
            })
            .collect();

        // Create SpongeVar for verifier
        let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);
        // The prover squeezed γ once and β sumcheck_rounds times before starting rounds
        let gamma = sponge_var.squeeze_field_elements(1).unwrap();
        let beta = sponge_var.squeeze_field_elements(sumcheck_rounds).unwrap();

        tracing::debug!(target: TEST_TARGET, "Generated γ: {:?}", gamma[0].value().unwrap_or_else(|_| Fr::ZERO));
        tracing::debug!(target: TEST_TARGET, "Generated β values: {:?}",
                    beta.iter().map(|b| b.value().unwrap_or_else(|_| Fr::ZERO)).collect::<Vec<_>>());

        // Get polynomial info from the linearization result
        let polynomial_info = lin_res.linearization.polynomial.info();

        // Expected initial sum is zero for satisfied CCS instance
        let expected_zero = FpVar::<Fr>::Constant(Fr::ZERO);

        let res = verify_all_sumcheck::<ark_bn254::g1::Config, PoseidonSponge<Fr>>(
            &mut cs,
            &mut sponge_var,
            &sumcheck_evals_var,
            expected_zero,
            &polynomial_info,
        )
        .unwrap();

        // Ensure constraint system satisfied
        if !cs.is_satisfied().unwrap() {
            // 1) Which *index* failed?
            let idx = cs.which_is_unsatisfied().unwrap().unwrap();

            // 2) Map that index to its human-readable name.
            let names = cs.constraint_names().unwrap();
            if let Ok(idx_num) = idx.parse::<usize>() {
                if idx_num < names.len() {
                    println!("unsatisfied @{}: {}", idx, names[idx_num]);
                    tracing::debug!(target: TEST_TARGET, "unsatisfied @{}: {}", idx, names[idx_num]);

                    panic!(
                        "SHA256 sumcheck verification failed: constraint system is not satisfied. \
                         This indicates the sumcheck proof verification generated invalid constraints.\n\
                         First unsatisfied constraint: {}",
                        names[idx_num]
                    );
                } else {
                    panic!(
                        "SHA256 sumcheck verification failed: constraint system is not satisfied. \
                         This indicates the sumcheck proof verification generated invalid constraints.\n\
                         Invalid constraint index: {}",
                        idx
                    );
                }
            } else {
                panic!(
                    "SHA256 sumcheck verification failed: constraint system is not satisfied. \
                     This indicates the sumcheck proof verification generated invalid constraints.\n\
                     Invalid constraint identifier: {}",
                    idx
                );
            }
        }

        // Also basic sanity: number of challenges collected matches rounds
        assert_eq!(res.1.len(), sumcheck_rounds,
            "SHA256 sumcheck verification failed: mismatch between number of challenges collected ({}) \
             and expected sumcheck rounds ({}). This indicates a bug in the sumcheck verification logic.",
            res.1.len(), sumcheck_rounds);

        tracing::info!(target: TEST_TARGET, "✅ SHA256 sumcheck verification completed successfully");
        tracing::info!(target: TEST_TARGET, "Generated {} challenges for {} rounds", res.1.len(), sumcheck_rounds);
        tracing::info!(target: TEST_TARGET, "Total constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_construct_combined_ccs_polynomial_cubic() {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        tracing::info!(target: TEST_TARGET, "🧮 Starting combined CCS polynomial construction test for cubic circuits");

        let config = poseidon_config::<Fr>();
        let num_vars = 8; // 2^8 >= constraints for cubic circuit
        let ck = {
            let srs = Z::setup(num_vars, b"test", &mut rng).unwrap();
            let keys = Z::trim(&srs, num_vars);
            keys.ck
        };

        // Setup CCS shape
        let cs_setup = ConstraintSystem::<Fr>::new_ref();
        let params =
            setup_linearization::<G1, _>(cs_setup, CubicCircuit::<Fr> { _p: PhantomData }).unwrap();

        // Create two different CCS instances with different inputs
        let input1 = Fr::rand(&mut rng);
        let input2 = Fr::rand(&mut rng);

        let step_input1 = StepFunctionInput { i: Fr::ONE, z_i: vec![input1] };
        let step_input2 = StepFunctionInput { i: Fr::from(2u64), z_i: vec![input2] };

        // Synthesize two CCS instances
        let cs1 = ConstraintSystem::<Fr>::new_ref();
        let (u1, w1) =
            synthesize_step_circuit_with_params::<G1, Z, _>(cs1, &params, &step_input1, &ck)
                .unwrap();

        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let (u2, w2) =
            synthesize_step_circuit_with_params::<G1, Z, _>(cs2, &params, &step_input2, &ck)
                .unwrap();

        // Prepare witness vectors for polynomial construction
        let z1 = [u1.X.clone(), w1.W.clone()].concat();
        let z2 = [u2.X.clone(), w2.W.clone()].concat();

        // Generate random challenge values
        let gamma = Fr::rand(&mut rng);
        let num_sumcheck_vars = (params.ccs_shape.num_constraints as f64).log2().ceil() as usize;
        let beta: Vec<Fr> = (0..num_sumcheck_vars).map(|_| Fr::rand(&mut rng)).collect();

        tracing::debug!(target: TEST_TARGET, "Test parameters: num_constraints={}, num_sumcheck_vars={}, z1_len={}, z2_len={}",
            params.ccs_shape.num_constraints, num_sumcheck_vars, z1.len(), z2.len());

        // Test the combined polynomial construction
        let combined_poly =
            construct_combined_ccs_polynomial::<G1>(&params.ccs_shape, &z1, &z2, &beta, gamma)
                .unwrap();

        tracing::debug!(target: TEST_TARGET, "✓ Combined polynomial construction completed successfully");
        tracing::debug!(target: TEST_TARGET, "Combined polynomial num_variables: {}, products count: {}",
            combined_poly.num_variables, combined_poly.products.len());

        // Verify the polynomial has the expected structure
        assert_eq!(
            combined_poly.num_variables, num_sumcheck_vars,
            "Combined polynomial should have {} variables, got {}",
            num_sumcheck_vars, combined_poly.num_variables
        );

        // Verify that the polynomial has products (non-empty)
        assert!(
            !combined_poly.products.is_empty(),
            "Combined polynomial should have at least one product term"
        );

        // Run the sumcheck protocol on the combined polynomial
        let mut prover_ro = PoseidonSponge::new(&config);
        let (sumcheck_proof, _prover_state) =
            MLSumcheck::prove_as_subprotocol(&mut prover_ro, &combined_poly);

        tracing::debug!(target: TEST_TARGET, "✓ Sumcheck proof generated with {} rounds", sumcheck_proof.len());

        // Extract evaluations from the sumcheck proof
        let sumcheck_evals_native: Vec<Vec<Fr>> = sumcheck_proof
            .iter()
            .map(|msg| msg.evaluations.clone())
            .collect();

        // Build circuit witness for the evaluations
        let mut cs = ConstraintSystem::<Fr>::new_ref();
        let sumcheck_evals_var: Vec<Vec<FpVar<Fr>>> = sumcheck_evals_native
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|e| FpVar::new_witness(cs.clone(), || Ok(*e)).unwrap())
                    .collect()
            })
            .collect();

        // Create SpongeVar for verifier (fresh random oracle)
        let mut verifier_sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);

        // For CCS folding, the expected sum should be zero for satisfied instances
        let expected_zero = FpVar::<Fr>::Constant(Fr::ZERO);

        // Get polynomial info from the actual constructed polynomial
        let polynomial_info = combined_poly.info();

        let verification_result = verify_all_sumcheck::<ark_bn254::g1::Config, PoseidonSponge<Fr>>(
            &mut cs,
            &mut verifier_sponge_var,
            &sumcheck_evals_var,
            expected_zero,
            &polynomial_info,
        )
        .unwrap();

        tracing::debug!(target: TEST_TARGET, "✓ Sumcheck verification completed successfully");
        tracing::debug!(target: TEST_TARGET, "Final expected value: {:?}", verification_result.0.value().unwrap_or_else(|_| Fr::ZERO));
        tracing::debug!(target: TEST_TARGET, "Challenges collected: {}", verification_result.1.len());

        // Ensure constraint system is satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraint system should be satisfied after sumcheck verification"
        );

        // Verify we got the expected number of challenges
        assert_eq!(
            verification_result.1.len(),
            sumcheck_proof.len(),
            "Number of challenges should match number of sumcheck rounds"
        );

        tracing::info!(target: TEST_TARGET, "✅ Combined CCS polynomial construction and sumcheck verification completed successfully");
        tracing::info!(target: TEST_TARGET, "Constructed polynomial with {} variables and {} products, verified with {} rounds",
            combined_poly.num_variables, combined_poly.products.len(), sumcheck_proof.len());
    }

    #[test]
    fn test_construct_combined_ccs_polynomial_sha256_chain() {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        tracing::info!(target: TEST_TARGET, "🔗 Starting combined CCS polynomial construction test for SHA256 chain");

        let config = poseidon_config::<Fr>();
        let num_vars = 16; // SHA256 requires more variables
        let ck = {
            let srs = Z::setup(num_vars, b"test", &mut rng).unwrap();
            let keys = Z::trim(&srs, num_vars);
            keys.ck
        };

        // Setup CCS shape for SHA256 circuit
        let cs_setup = ConstraintSystem::<Fr>::new_ref();
        let params =
            setup_linearization::<G1, _>(cs_setup, SequentialSha256Circuit::<Fr>::new()).unwrap();

        // Create SHA256 chain: y = SHA256("hello world"), z = SHA256(y)
        let initial_message = b"hello world";
        let y_hash = calculate_sha256_native(initial_message);
        let z_hash = calculate_sha256_native(&y_hash);

        // Convert hashes to field elements
        let y_hash_field = conversions::bytes_to_field::<Fr>(&y_hash);
        let z_hash_field = conversions::bytes_to_field::<Fr>(&z_hash);

        tracing::debug!(target: TEST_TARGET, "First SHA256 input: {:?}",
            initial_message.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        tracing::debug!(target: TEST_TARGET, "First SHA256 output (y): {}",
            y_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        tracing::debug!(target: TEST_TARGET, "Second SHA256 output (z): {}",
            z_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());

        // Create step inputs for the two instances
        let step_input1 = StepFunctionInput { i: Fr::ONE, z_i: vec![y_hash_field] };
        let step_input2 = StepFunctionInput {
            i: Fr::from(2u64),
            z_i: vec![z_hash_field],
        };

        // Synthesize two CCS instances
        let cs1 = ConstraintSystem::<Fr>::new_ref();
        let (u1, w1) =
            synthesize_step_circuit_with_params::<G1, Z, _>(cs1, &params, &step_input1, &ck)
                .unwrap();

        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let (u2, w2) =
            synthesize_step_circuit_with_params::<G1, Z, _>(cs2, &params, &step_input2, &ck)
                .unwrap();

        tracing::debug!(target: TEST_TARGET, "✓ Both SHA256 CCS instances synthesized successfully");
        tracing::debug!(target: TEST_TARGET, "Instance 1: X_len={}, W_len={}", u1.X.len(), w1.W.len());
        tracing::debug!(target: TEST_TARGET, "Instance 2: X_len={}, W_len={}", u2.X.len(), w2.W.len());

        // Prepare witness vectors for polynomial construction
        let z1 = [u1.X.clone(), w1.W.clone()].concat();
        let z2 = [u2.X.clone(), w2.W.clone()].concat();

        // Generate random challenge values
        let gamma = Fr::rand(&mut rng);
        let num_sumcheck_vars = (params.ccs_shape.num_constraints as f64).log2().ceil() as usize;
        let beta: Vec<Fr> = (0..num_sumcheck_vars).map(|_| Fr::rand(&mut rng)).collect();

        tracing::debug!(target: TEST_TARGET, "Test parameters: num_constraints={}, num_sumcheck_vars={}, z1_len={}, z2_len={}",
            params.ccs_shape.num_constraints, num_sumcheck_vars, z1.len(), z2.len());

        // Test the combined polynomial construction
        let combined_poly =
            construct_combined_ccs_polynomial::<G1>(&params.ccs_shape, &z1, &z2, &beta, gamma)
                .unwrap();

        tracing::debug!(target: TEST_TARGET, "✓ Combined SHA256 polynomial construction completed successfully");
        tracing::debug!(target: TEST_TARGET, "Combined polynomial num_variables: {}, products count: {}",
            combined_poly.num_variables, combined_poly.products.len());

        // Verify the polynomial has the expected structure
        assert_eq!(
            combined_poly.num_variables, num_sumcheck_vars,
            "Combined polynomial should have {} variables, got {}",
            num_sumcheck_vars, combined_poly.num_variables
        );

        // Verify that the polynomial has products (non-empty)
        assert!(
            !combined_poly.products.is_empty(),
            "Combined polynomial should have at least one product term"
        );

        // Run the sumcheck protocol on the combined polynomial
        let mut prover_ro = PoseidonSponge::new(&config);
        let (sumcheck_proof, _prover_state) =
            MLSumcheck::prove_as_subprotocol(&mut prover_ro, &combined_poly);

        tracing::debug!(target: TEST_TARGET, "✓ Sumcheck proof generated with {} rounds", sumcheck_proof.len());

        // Extract evaluations from the sumcheck proof
        let sumcheck_evals_native: Vec<Vec<Fr>> = sumcheck_proof
            .iter()
            .map(|msg| msg.evaluations.clone())
            .collect();

        // Build circuit witness for the evaluations
        let mut cs = ConstraintSystem::<Fr>::new_ref();
        let sumcheck_evals_var: Vec<Vec<FpVar<Fr>>> = sumcheck_evals_native
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|e| FpVar::new_witness(cs.clone(), || Ok(*e)).unwrap())
                    .collect()
            })
            .collect();

        // Create SpongeVar for verifier (fresh random oracle)
        let mut verifier_sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);

        // For CCS folding, the expected sum should be zero for satisfied instances
        let expected_zero = FpVar::<Fr>::Constant(Fr::ZERO);

        // Get polynomial info from the actual constructed polynomial
        let polynomial_info = combined_poly.info();

        let verification_result = verify_all_sumcheck::<ark_bn254::g1::Config, PoseidonSponge<Fr>>(
            &mut cs,
            &mut verifier_sponge_var,
            &sumcheck_evals_var,
            expected_zero,
            &polynomial_info,
        )
        .unwrap();

        tracing::debug!(target: TEST_TARGET, "✓ Sumcheck verification completed successfully");
        tracing::debug!(target: TEST_TARGET, "Final expected value: {:?}", verification_result.0.value().unwrap_or_else(|_| Fr::ZERO));
        tracing::debug!(target: TEST_TARGET, "Challenges collected: {}", verification_result.1.len());

        // Ensure constraint system is satisfied
        assert!(
            cs.is_satisfied().unwrap(),
            "SHA256 chain sumcheck verification failed: constraint system is not satisfied. \
             This indicates the sumcheck proof verification generated invalid constraints."
        );

        // Verify we got the expected number of challenges
        assert_eq!(
            verification_result.1.len(),
            sumcheck_proof.len(),
            "Number of challenges should match number of sumcheck rounds"
        );

        tracing::info!(target: TEST_TARGET, "✅ SHA256 chain CCS polynomial construction and sumcheck verification completed successfully");
        tracing::info!(target: TEST_TARGET, "Folded SHA256 chain with {} variables and {} products, verified with {} rounds",
            combined_poly.num_variables, combined_poly.products.len(), sumcheck_proof.len());
    }
}
