//! Sumcheck verification circuit implementation
//!
//! This module implements constraint system-compatible sumcheck protocol verification
//! for use within R1CS circuits. It provides functions to verify sumcheck proofs
//! and perform related cryptographic operations within constraint systems.

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::Zero;
use tracing::instrument;

use crate::folding::hypernova::ml_sumcheck::protocol::verifier::SQUEEZE_NATIVE_ELEMENTS_NUM;

/// Configuration constants for the sumcheck protocol
pub const MAX_CARDINALITY: usize = 2;

const LOG_TARGET: &str = "nexus-nova::tree_folding::circuit::sumcheck";

/// Generate the challenges (γ, β) for the sumcheck verification.
///
/// This function derives the necessary randomness for the sumcheck protocol
/// using the Fiat-Shamir transform applied to the instance data. It handles
/// the initial challenge generation that occurs before the sumcheck rounds.
///
/// # Arguments
///
/// * `random_oracle` - The cryptographic sponge for challenge generation
/// * `sumcheck_rounds` - Number of sumcheck rounds to generate beta challenges for
///
/// # Returns
///
/// Returns a tuple containing:
/// - `gamma`: Challenge for combining polynomial evaluations  
/// - `beta`: Vector of challenges for equality polynomial evaluation
#[instrument(
    level = "debug",
    skip(random_oracle),
    fields(sumcheck_rounds = sumcheck_rounds)
)]
pub fn generate_sumcheck_challenges<G1, RO>(
    random_oracle: &mut RO::Var,
    sumcheck_rounds: usize,
) -> Result<(FpVar<G1::ScalarField>, Vec<FpVar<G1::ScalarField>>), SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    // Generate gamma challenge (single field element)
    let gamma = random_oracle.squeeze_field_elements(1)?[0].clone();

    // Generate beta challenges (one element per sumcheck round)
    let beta = random_oracle.squeeze_field_elements(sumcheck_rounds)?;

    Ok((gamma, beta))
}

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
#[instrument(
    level = "debug",
    skip(random_oracle, sumcheck_evals),
    fields(
        sumcheck_rounds = sumcheck_rounds,
        num_eval_rounds = sumcheck_evals.len(),
    )
)]
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
    // Start with the provided expected sum as the initial expected value
    let mut expected = expected_sum_of_polynomial;

    let mut rs_p: Vec<FpVar<G1::ScalarField>> = Vec::with_capacity(sumcheck_rounds);

    for round in 0..sumcheck_rounds {
        tracing::debug!(target: LOG_TARGET, "🔍 Starting sumcheck round {}", round);

        // Absorb polynomial evaluations (the prover message)
        let evals = &sumcheck_evals[round];

        random_oracle.absorb(evals).map_err(|e| {
            tracing::error!(target: LOG_TARGET, "🔍 Error absorbing evals in round {}: {:?}", round, e);
            e
        })?;

        // Fetch verifier challenge r_k and immediately absorb it per spec.
        let r_k = random_oracle
            .squeeze_field_elements(SQUEEZE_NATIVE_ELEMENTS_NUM)
            .map_err(|e| {
                tracing::error!(target: LOG_TARGET, "🔍 Error squeezing r_k in round {}: {:?}", round, e);
                e
            })?[0]
            .clone();

        tracing::debug!("🔍 Round {} r_k: {:?}", round, r_k.value());

        random_oracle.absorb(&r_k).map_err(|e| {
            tracing::error!(target: LOG_TARGET, "🔍 Error absorbing r_k in round {}: {:?}", round, e);
            e
        })?;

        // Enforce p_k(0) + p_k(1) = p_{k-1}(r_{k-1}) and derive the next
        // expected value via Lagrange interpolation.
        expected = verify_sumcheck_round::<G1>(round, &expected, evals, &r_k).map_err(|e| {
            tracing::error!(target: LOG_TARGET, "🔍 Error in verify_sumcheck_round {}: {:?}", round, e);
            e
        })?;

        tracing::debug!(target: LOG_TARGET, "🔍 Round {} expected after: {:?}", round, expected.value());

        rs_p.push(r_k);
    }

    Ok((expected, rs_p))
}

/// Verify a single round of the sumcheck protocol.
///
/// For each round k, this verifies that p_k(0) + p_k(1) = p_{k-1}(r_{k-1})
/// and performs Lagrange interpolation to evaluate the polynomial at the challenge point.
///
/// # Arguments
///
/// * `round` - The current round number
/// * `expected` - The expected evaluation from the previous round (p_{k-1}(r_{k-1}))
/// * `evals` - The polynomial evaluations [p_k(0), p_k(1), p_k(2), p_k(3)] for this round
/// * `r` - The verifier challenge r_k for this round
///
/// # Returns
///
/// The evaluation p_k(r_k) of the interpolated polynomial at the challenge point r_k.
pub fn verify_sumcheck_round<G1>(
    round: usize,
    expected: &FpVar<G1::ScalarField>,
    evals: &[FpVar<G1::ScalarField>],
    r: &FpVar<G1::ScalarField>,
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    tracing::debug!(
        target: LOG_TARGET,
        "🔍 verify_sumcheck_round round={}, r={:?}, expected={:?}, evals={:?}",
        round,
        r.value(),
        expected.value(),
        evals.iter().map(|e| e.value()).collect::<Vec<_>>()
    );

    // Enforce the consistency condition p_k(0) + p_k(1) = p_{k-1}(r_{k-1})
    expected
        .enforce_equal(&(&evals[0] + &evals[1]))
        .map_err(|e| {
            tracing::error!("🔍 Error in consistency check: {:?}", e);
            e
        })?;

    // Constants used for degree-two Lagrange interpolation over points 0,1,2,3.
    let interpolation_constants = [
        (G1::ScalarField::from(0u64), G1::ScalarField::from(-6i64)),
        (G1::ScalarField::from(1u64), G1::ScalarField::from(2i64)),
        (G1::ScalarField::from(2u64), G1::ScalarField::from(-2i64)),
        (G1::ScalarField::from(3u64), G1::ScalarField::from(6i64)),
    ];

    // Compute  Π_j (x - j)
    let prod: FpVar<G1::ScalarField> = (0..(MAX_CARDINALITY + 2)).fold(
        FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE),
        |acc, idx| acc * (r - interpolation_constants[idx].0),
    );

    tracing::debug!("🔍 prod value: {:?}", prod.value());

    // Evaluate the polynomial at point r using the barycentric form.
    let next_expected: FpVar<G1::ScalarField> = (0..(MAX_CARDINALITY + 2))
        .map(|i| {
            let num = &prod * &evals[i];
            let denom = (r - interpolation_constants[i].0) * interpolation_constants[i].1;

            tracing::debug!(
                "🔍 Lagrange term {}: num={:?}, denom={:?}",
                i,
                num.value(),
                denom.value()
            );

            // Check if denominator is zero before calling mul_by_inverse
            match denom.value() {
                Ok(denom_val) if denom_val.is_zero() => {
                    tracing::error!(
                        "🔍 Division by zero detected at Lagrange term {}, r={:?}, interpolation_point={:?}",
                        i,
                        r.value(),
                        interpolation_constants[i].0
                    );
                    return Err(SynthesisError::AssignmentMissing);
                }
                _ => {}
            }

            num.mul_by_inverse(&denom).map_err(|e| {
                tracing::error!("🔍 Error in mul_by_inverse for term {}: {:?}", i, e);
                e
            })
        })
        .collect::<Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>>()?
        .iter()
        .sum();

    tracing::debug!("🔍 next_expected value: {:?}", next_expected.value());

    Ok(next_expected)
}

/// Compute the equality polynomial eq(a, b) = ∏ᵢ [aᵢ·bᵢ + (1-aᵢ)·(1-bᵢ)]
///
/// This is a fundamental building block for sumcheck verification that computes
/// the multilinear extension of the equality predicate.
///
/// # Arguments
///
/// * `a` - First vector of field elements
/// * `b` - Second vector of field elements
///
/// # Returns
///
/// Returns the evaluation of the equality polynomial eq(a,b).
#[inline]
pub fn compute_equality_polynomial<G1>(
    a: &[FpVar<G1::ScalarField>],
    b: &[FpVar<G1::ScalarField>],
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    assert_eq!(a.len(), b.len());

    let one = FpVar::<G1::ScalarField>::Constant(G1::ScalarField::ONE);

    let result = a
        .iter()
        .zip(b.iter())
        .map(|(ai, bi)| {
            let term1 = ai * bi; // a_i * b_i
            let term2 = (one.clone() - ai) * (one.clone() - bi); // (1-a_i)*(1-b_i)
            term1 + term2
        })
        .fold(one.clone(), |acc, x| acc * x);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_config;
    use ark_bn254::Fr;
    use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_equality_polynomial() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        // Test vectors of length 3
        let a: Vec<FpVar<Fr>> = (0..3)
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::rand(&mut rng))))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let b: Vec<FpVar<Fr>> = (0..3)
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::rand(&mut rng))))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // Compute equality polynomial in circuit
        let result = compute_equality_polynomial::<ark_bn254::g1::Config>(&a, &b).unwrap();

        // Verify constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Compute expected result outside of circuit
        let a_vals: Vec<Fr> = a.iter().map(|v| v.value().unwrap()).collect();
        let b_vals: Vec<Fr> = b.iter().map(|v| v.value().unwrap()).collect();

        let expected: Fr = a_vals
            .iter()
            .zip(b_vals.iter())
            .map(|(ai, bi)| {
                let term1 = *ai * bi; // a_i * b_i
                let term2 = (Fr::ONE - ai) * (Fr::ONE - bi); // (1-a_i)*(1-b_i)
                term1 + term2
            })
            .product();

        assert_eq!(result.value().unwrap(), expected);
    }

    #[test]
    fn test_sumcheck_round_verification() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        // Create mock polynomial evaluations at points 0, 1, 2, 3
        let evals: Vec<FpVar<Fr>> = (0..MAX_CARDINALITY + 2)
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::rand(&mut rng))))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // Create expected value (should equal evals[0] + evals[1])
        let expected = &evals[0] + &evals[1];

        // Create random challenge point
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();

        // Run sumcheck round verification
        let _result =
            verify_sumcheck_round::<ark_bn254::g1::Config>(0, &expected, &evals, &r).unwrap();

        // Verify constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_generate_sumcheck_challenges() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let config = poseidon_config::<Fr>();
        let mut random_oracle = PoseidonSpongeVar::new(cs.clone(), &config);

        // Absorb some initial data
        let vk = FpVar::new_witness(cs.clone(), || Ok(Fr::from(42u64))).unwrap();
        random_oracle.absorb(&vk).unwrap();

        let sumcheck_rounds = 4;
        let (_gamma, beta) = generate_sumcheck_challenges::<
            ark_bn254::g1::Config,
            PoseidonSponge<Fr>,
        >(&mut random_oracle, sumcheck_rounds)
        .unwrap();

        // Verify we got the right number of beta challenges
        assert_eq!(beta.len(), sumcheck_rounds);

        // Verify constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
    }
} 