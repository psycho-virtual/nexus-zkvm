//! CCS Folding Implementation
//!
//! This module implements the folding protocol for CCS (Customizable Constraint System) instances.
//! It provides the ability to fold two CCS instances into a single LCCS (Linearized CCS) instance
//! using the HyperNova sumcheck protocol.
//!
//! The implementation reuses existing infrastructure from linearization.rs to:
//! 1. Construct the combined sumcheck polynomial g(x) for two CCS instances
//! 2. Run the sumcheck protocol using MLSumcheck
//! 3. Compute theta values for both instances
//! 4. Fold the instances using existing folding logic

use super::{
    linearization::{compute_theta_values, fold_and_linearize_ccs},
    mle::vec_to_ark_mle,
    CCSInstance, CCSShape, CCSWitness, Error, LCCSInstance,
};
use crate::folding::hypernova::ml_sumcheck::protocol::prover::ProverMsg;
use crate::{
    folding::hypernova::ml_sumcheck::{ListOfProductsOfPolynomials, MLSumcheck},
    safe_loglike,
};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::PrimeField;
use ark_spartan::dense_mlpoly::EqPolynomial;
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_std::rc::Rc;
use tracing::instrument;

const LOG_TARGET: &str = "nexus-nova::ccs::ccs_fold";

/// Proof for folding two CCS instances together into a single LCCS instance
/// Reuses existing linearization infrastructure from linearization.rs
#[derive(Clone)]
pub struct MultiCCSProof<G: CurveGroup> {
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

impl<G: CurveGroup> MultiCCSProof<G> {
    /// Prove folding of two CCS instances into LCCS
    /// Uses construct_ccs_polynomial and linearization infrastructure
    #[instrument(
        target = LOG_TARGET,
        level = "debug",
        skip(shape, u1, w1, u2, w2, random_oracle),
        fields(
            u1_x_len = u1.X.len(),
            u2_x_len = u2.X.len(),
            w1_len = w1.W.len(),
            w2_len = w2.W.len(),
            num_matrices = shape.num_matrices,
            num_constraints = shape.num_constraints
        )
    )]
    pub fn prove_as_subprotocol<C: PolyCommitmentScheme<G>, RO: CryptographicSponge>(
        shape: &CCSShape<G>,
        (u1, w1): (&CCSInstance<G, C>, &CCSWitness<G>),
        (u2, w2): (&CCSInstance<G, C>, &CCSWitness<G>),
        random_oracle: &mut RO,
    ) -> Result<(Self, LCCSInstance<G, C>, CCSWitness<G>), Error>
    where
        G::ScalarField: PrimeField + Absorb,
    {
        // Step 1: Sample challenges γ and β from random oracle
        let (gamma, beta, _sumcheck_rounds) =
            tracing::debug_span!(target: LOG_TARGET, "challenge_sampling").in_scope(|| {
                let gamma: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
                let sumcheck_rounds = safe_loglike!(shape.num_constraints) as usize;
                let beta = random_oracle.squeeze_field_elements(sumcheck_rounds);

                tracing::debug!("Sampled challenges: γ, β with {} elements", sumcheck_rounds);
                (gamma, beta, sumcheck_rounds)
            });

        // Step 2: Construct combined witness vectors z1 and z2
        let (z1, z2) =
            tracing::debug_span!(target: LOG_TARGET, "witness_construction").in_scope(|| {
                let z1 = [u1.X.as_slice(), w1.W.as_slice()].concat();
                let z2 = [u2.X.as_slice(), w2.W.as_slice()].concat();

                tracing::debug!(
                    "Constructed witness vectors: z1.len={}, z2.len={}",
                    z1.len(),
                    z2.len()
                );
                (z1, z2)
            });

        // Step 3: Construct the combined g(x) polynomial for both CCS instances
        let polynomial = tracing::debug_span!(target: LOG_TARGET, "polynomial_construction")
            .in_scope(|| construct_combined_ccs_polynomial(shape, &z1, &z2, &beta, gamma))?;

        // Step 4: Run sumcheck protocol (reuse from linearization.rs step 4)
        let (sumcheck_proof, r_x) = tracing::debug_span!(target: LOG_TARGET, "sumcheck_protocol")
            .in_scope(|| {
                tracing::debug!("Running ML sum-check protocol");

                // The claimed sum should be 0 for satisfied CCS instances
                let (sumcheck_proof, prover_state) =
                    MLSumcheck::prove_as_subprotocol(random_oracle, &polynomial);
                let r_x = prover_state.randomness;

                tracing::debug!(
                    "Sum-check protocol completed (proof rounds: {}, r_x length: {})",
                    sumcheck_proof.len(),
                    r_x.len()
                );

                (sumcheck_proof, r_x)
            });

        // Step 5: Compute theta values for both instances
        let (thetas1, thetas2) = tracing::debug_span!(target: LOG_TARGET, "theta_computation")
            .in_scope(|| {
                let thetas1 = compute_theta_values(shape, &z1, &r_x);
                let thetas2 = compute_theta_values(shape, &z2, &r_x);

                tracing::debug!("Computed theta values: {} for each instance", thetas1.len());
                (thetas1, thetas2)
            });

        // Step 6: Fold the instances using existing fold_and_linearize_ccs
        let (lccs_folded, witness_folded) =
            tracing::debug_span!(target: LOG_TARGET, "instance_folding").in_scope(|| {
                fold_and_linearize_ccs(
                    shape,
                    u1,
                    u2,
                    w1,
                    w2,
                    &thetas1,
                    &thetas2,
                    &r_x,
                    random_oracle,
                )
            })?;

        let proof = Self {
            sumcheck_proof,
            gamma,
            beta,
            r_x,
            thetas1,
            thetas2,
        };

        tracing::info!("✅ CCS folding proof generation completed");

        Ok((proof, lccs_folded, witness_folded))
    }

    /// Verify folding of two CCS instances
    /// Uses verification infrastructure from linearization.rs
    #[instrument(
        target = LOG_TARGET,
        level = "debug",
        skip(self, shape, U1, U2, U_folded, random_oracle),
        fields(
            proof_rounds = self.sumcheck_proof.len(),
            U1_x_len = U1.X.len(),
            U2_x_len = U2.X.len(),
            thetas1_len = self.thetas1.len(),
            thetas2_len = self.thetas2.len()
        )
    )]
    pub fn verify_as_subprotocol<C: PolyCommitmentScheme<G>, RO: CryptographicSponge>(
        &self,
        shape: &CCSShape<G>,
        U1: &CCSInstance<G, C>,
        U2: &CCSInstance<G, C>,
        U_folded: &LCCSInstance<G, C>,
        random_oracle: &mut RO,
    ) -> Result<(), Error>
    where
        G::ScalarField: PrimeField + Absorb,
    {

        // Step 1: Regenerate challenges (same as verification in linearization.rs)
        let (gamma, beta) = tracing::debug_span!(target: LOG_TARGET, "challenge_regeneration")
            .in_scope(|| {
                let gamma: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
                let expected_rounds = safe_loglike!(shape.num_constraints) as usize;
                let beta = random_oracle.squeeze_field_elements(expected_rounds);

                tracing::debug!(
                    "Regenerated challenges: γ, β with {} elements",
                    expected_rounds
                );

                // Verify stored challenges match
                if gamma != self.gamma {
                    tracing::error!("Gamma challenge mismatch");
                    return Err(Error::NotSatisfied);
                }
                if beta != self.beta {
                    tracing::error!("Beta challenge mismatch");
                    return Err(Error::NotSatisfied);
                }

                Ok::<_, Error>((gamma, beta))
            })?;

        // Step 2: Reconstruct the combined polynomial
        let polynomial = tracing::debug_span!(target: LOG_TARGET, "polynomial_reconstruction")
            .in_scope(|| {
                // Reconstruct witness vectors (for verification, we don't have access to actual witnesses)
                // We use placeholder vectors of the right size for polynomial construction
                let z1 = vec![G::ScalarField::ZERO; U1.X.len() + shape.num_vars];
                let z2 = vec![G::ScalarField::ZERO; U2.X.len() + shape.num_vars];

                // The verification doesn't need the actual polynomial values, just the structure
                construct_combined_ccs_polynomial(shape, &z1, &z2, &beta, gamma)
            })?;

        // Step 3: Verify sumcheck proof (reuse from linearization.rs)
        let subclaim =
            tracing::debug_span!(target: LOG_TARGET, "sumcheck_verification").in_scope(|| {
                let subclaim = MLSumcheck::verify_as_subprotocol(
                    random_oracle,
                    &polynomial.info(),
                    G::ScalarField::ZERO,
                    &self.sumcheck_proof,
                )
                .map_err(|_| Error::NotSatisfied)?;

                tracing::debug!("Sumcheck verification passed");
                Ok::<_, Error>(subclaim)
            })?;

        // Step 4: Verify evaluation point matches
        if subclaim.point != self.r_x {
            tracing::error!("Evaluation point mismatch");
            return Err(Error::NotSatisfied);
        }

        // Step 5: Verify folded instance consistency using existing verification logic
        tracing::debug_span!(target: LOG_TARGET, "folding_consistency_check").in_scope(|| {
            verify_ccs_folding_consistency(
                shape,
                U1,
                U2,
                U_folded,
                &self.thetas1,
                &self.thetas2,
                &self.r_x,
                random_oracle,
            )
        })?;

        tracing::info!("✅ CCS folding proof verification completed");

        Ok(())
    }
}

/// Constructs the combined g(x) polynomial for folding two CCS instances
/// Uses the existing construct_ccs_polynomial logic but combines two instances
///
/// The combined polynomial is: g(x) = γ^1 · Q_1(x) + γ^2 · Q_2(x)
/// where Q_k(x) = eq(β, x) · ∑_{i=1}^q c_i · ∏_{j∈S_i} ∑_{y∈{0,1}^s'} M_j(x, y) · z_k(y)
#[instrument(
    target = LOG_TARGET,
    level = "debug",
    skip(shape, z1, z2, beta, gamma),
    fields(
        num_matrices = shape.num_matrices,
        num_multisets = shape.num_multisets,
        z1_len = z1.len(),
        z2_len = z2.len(),
        beta_len = beta.len()
    )
)]
fn construct_combined_ccs_polynomial<G: CurveGroup>(
    shape: &CCSShape<G>,
    z1: &[G::ScalarField],
    z2: &[G::ScalarField],
    beta: &[G::ScalarField],
    gamma: G::ScalarField,
) -> Result<ListOfProductsOfPolynomials<G::ScalarField>, Error> {
    if z1.len() != z2.len() {
        return Err(Error::InvalidWitnessLength);
    }

    let num_vars = safe_loglike!(shape.num_constraints) as usize;

    // Create a new ListOfProductsOfPolynomials to represent g(x)
    let mut polynomial = ListOfProductsOfPolynomials::new(num_vars);

    // Create the eq(β, x) polynomial
    let eq_beta = EqPolynomial::new(beta.to_vec());
    let eq_beta_mle = vec_to_ark_mle(eq_beta.evals().as_slice());

    // Build g(x) by iterating over each constraint (multiset) for both instances
    // Following the pattern from construct_css_polynomial but for two instances
    let instances = [(z1, gamma), (z2, gamma * gamma)]; // (witness, gamma_power)

    (0..shape.num_multisets).for_each(|i| {
        for (z, gamma_power) in &instances {
            let mut summand = shape.cSs[i]
                .1
                .iter()
                .map(|j| Rc::new(vec_to_ark_mle(shape.Ms[*j].multiply_vec(z).as_slice())))
                .collect::<Vec<Rc<ark_poly::DenseMultilinearExtension<G::ScalarField>>>>();

            summand.push(Rc::new(eq_beta_mle.clone()));

            polynomial.add_product(summand.iter().cloned(), shape.cSs[i].0 * gamma_power);
        }
    });

    tracing::debug!("Combined polynomial construction completed");

    Ok(polynomial)
}

/// Verifies the consistency of CCS folding
/// Reuses logic from fold_and_linearize_ccs verification
#[instrument(
    target = LOG_TARGET,
    level = "debug",
    skip(shape, u1, u2, u_folded, thetas1, thetas2, r_x, random_oracle),
    fields(
        thetas1_len = thetas1.len(),
        thetas2_len = thetas2.len(),
        r_x_len = r_x.len()
    )
)]
fn verify_ccs_folding_consistency<
    G: CurveGroup,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
>(
    shape: &CCSShape<G>,
    u1: &CCSInstance<G, C>,
    u2: &CCSInstance<G, C>,
    u_folded: &LCCSInstance<G, C>,
    thetas1: &[G::ScalarField],
    thetas2: &[G::ScalarField],
    r_x: &[G::ScalarField],
    random_oracle: &mut RO,
) -> Result<(), Error>
where
    G::ScalarField: PrimeField + Absorb,
{
    tracing::debug!("Verifying CCS folding consistency");

    // Validate input compatibility
    if u1.X.len() != u2.X.len() {
        return Err(Error::InvalidInputLength);
    }

    if thetas1.len() != thetas2.len() {
        return Err(Error::InvalidTargets);
    }

    if thetas1.len() != shape.num_matrices {
        return Err(Error::InvalidTargets);
    }

    // Absorb theta values to regenerate the folding challenge
    random_oracle.absorb(&thetas1);
    random_oracle.absorb(&thetas2);

    // Sample folding challenge ρ ← F
    let rho: G::ScalarField = random_oracle.squeeze_field_elements(1)[0];
    tracing::debug!("Regenerated folding challenge ρ: {:?}", rho);

    // Verify folded commitment consistency
    let expected_commitment = u1.commitment_W.clone() + u2.commitment_W.clone() * rho;
    if u_folded.commitment_W != expected_commitment {
        tracing::error!("Commitment folding verification failed");
        return Err(Error::NotSatisfied);
    }

    // Verify folded u and x values consistency
    let (u1_val, x1) = (&u1.X[0], &u1.X[1..]);
    let (u2_val, x2) = (&u2.X[0], &u2.X[1..]);

    let expected_u = *u1_val + rho * u2_val;
    let expected_x: Vec<G::ScalarField> = x1
        .iter()
        .zip(x2.iter())
        .map(|(a, b)| *a + rho * b)
        .collect();

    if u_folded.X[0] != expected_u {
        tracing::error!("U value folding verification failed");
        return Err(Error::NotSatisfied);
    }

    if u_folded.X[1..] != expected_x {
        tracing::error!("X values folding verification failed");
        return Err(Error::NotSatisfied);
    }

    // Verify folded v values consistency
    let expected_vs: Vec<G::ScalarField> = thetas1
        .iter()
        .zip(thetas2.iter())
        .map(|(theta1, theta2)| *theta1 + rho * theta2)
        .collect();

    if u_folded.vs != expected_vs {
        tracing::error!("V values folding verification failed");
        return Err(Error::NotSatisfied);
    }

    // Verify evaluation point consistency
    if u_folded.rs != *r_x {
        tracing::error!("Evaluation point verification failed");
        return Err(Error::NotSatisfied);
    }

    tracing::debug!("CCS folding consistency verification passed");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ccs::linearization::{
            setup_linearization, synthesize_step_circuit_with_params, StepFunctionInput,
        },
        circuits::nova::StepCircuit,
        poseidon_config,
        tree_folding::circuit::sequential_sha256::SequentialSha256Circuit,
        zeromorph::Zeromorph,
    };
    use ark_bn254::{Bn254, Fr as CF, G1Projective as G};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};
    use derivative::Derivative;
    use std::marker::PhantomData;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    type Z = Zeromorph<Bn254>;

    // Helper function to convert poly commit errors
    fn convert_poly_error<T>(result: Result<T, ark_poly_commit::Error>) -> Result<T, Error> {
        result.map_err(|_| Error::NotSatisfied)
    }

    const TEST_TARGET: &str = "nexus-nova";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG)
            .with_target(LOG_TARGET, tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    #[derive(Derivative)]
    #[derivative(Debug, Clone)]
    struct CubicCircuit<F: Field> {
        #[derivative(Debug = "ignore")]
        _phantom: PhantomData<F>,
    }

    impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
        const ARITY: usize = 1;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            assert_eq!(z.len(), 1);

            let x = &z[0];
            let x_square = x.square()?;
            let x_cube = &x_square * x;
            let y = x + x_cube + &FpVar::Constant(F::from(5u64));

            Ok(vec![y])
        }
    }

    /// Test CCS folding with two cubic circuit instances
    #[test]
    fn test_multi_ccs_proof_cubic_instances() -> Result<(), Error> {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        // Setup environment
        let srs_degree = 12; // Smaller SRS for test circuit
        let srs = convert_poly_error(Z::setup(srs_degree, b"test-ccs-fold-cubic", &mut rng))?;
        let ck = Z::trim(&srs, srs_degree - 1).ck;
        let ro_config = poseidon_config::<CF>();

        // Setup linearization parameters
        let cs_setup = ConstraintSystem::<CF>::new_ref();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        let params = setup_linearization(cs_setup, circuit)?;

        // Generate random inputs for both circuits
        let x1 = CF::rand(&mut rng);
        let x2 = CF::rand(&mut rng);

        // Create step function inputs
        let input1 = StepFunctionInput { i: CF::from(1u64), z_i: vec![x1] };
        let input2 = StepFunctionInput { i: CF::from(2u64), z_i: vec![x2] };

        // Create CCS instances and witnesses
        let cs1 = ConstraintSystem::<CF>::new_ref();
        let (u1, w1) = synthesize_step_circuit_with_params(cs1, &params, &input1, &ck)?;

        let cs2 = ConstraintSystem::<CF>::new_ref();
        let (u2, w2) = synthesize_step_circuit_with_params(cs2, &params, &input2, &ck)?;

        // Create separate random oracle for proving
        let mut prove_oracle = PoseidonSponge::new(&ro_config);

        // Generate proof and fold instances
        let (proof, u_folded, w_folded) = MultiCCSProof::<G>::prove_as_subprotocol(
            &params.ccs_shape,
            (&u1, &w1),
            (&u2, &w2),
            &mut prove_oracle,
        )?;

        // Create fresh random oracle for verification (same initial state)
        let mut verify_oracle = PoseidonSponge::new(&ro_config);

        // Verify the proof
        proof.verify_as_subprotocol(&params.ccs_shape, &u1, &u2, &u_folded, &mut verify_oracle)?;

        // Verify the folded instance satisfies the constraints
        params
            .ccs_shape
            .is_satisfied_linearized::<Z>(&u_folded, &w_folded, &ck)?;

        Ok(())
    }

    /// Test CCS folding with two SHA-256 circuit instances
    #[test]
    fn test_multi_ccs_proof_sha256_instances() -> Result<(), Error> {
        let _guard = setup_test_tracing();
        let mut rng = test_rng();

        // Setup environment with larger SRS for SHA256 circuit
        let srs_degree = 18; // Increased SRS degree for SHA256 circuit
        let srs = convert_poly_error(Z::setup(srs_degree, b"test-ccs-fold-sha256", &mut rng))?;
        let ck = Z::trim(&srs, srs_degree - 1).ck;
        let ro_config = poseidon_config::<CF>();

        // Create SHA256 circuit instances
        let circuit = SequentialSha256Circuit::<CF>::new();

        // Setup linearization parameters using the circuit
        let cs1 = ConstraintSystem::<CF>::new_ref();
        let params = setup_linearization(cs1.clone(), circuit)?;

        // Generate step inputs for both circuits (using different step indices)
        let step_input1 = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(123u64)], // Different input values
        };
        let step_input2 = StepFunctionInput {
            i: CF::from(2u64),
            z_i: vec![CF::from(456u64)], // Different input values
        };

        // Create instances and witnesses
        let cs1 = ConstraintSystem::<CF>::new_ref();
        let (u1, w1) = synthesize_step_circuit_with_params(cs1, &params, &step_input1, &ck)?;

        let cs2 = ConstraintSystem::<CF>::new_ref();
        let (u2, w2) = synthesize_step_circuit_with_params(cs2, &params, &step_input2, &ck)?;

        // Create separate random oracle for proving
        let mut prove_oracle = PoseidonSponge::new(&ro_config);

        // Generate proof and fold instances
        let (proof, u_folded, w_folded) = MultiCCSProof::<G>::prove_as_subprotocol(
            &params.ccs_shape,
            (&u1, &w1),
            (&u2, &w2),
            &mut prove_oracle,
        )?;

        // Create fresh random oracle for verification (same initial state)
        let mut verify_oracle = PoseidonSponge::new(&ro_config);

        // Verify the proof
        proof.verify_as_subprotocol(&params.ccs_shape, &u1, &u2, &u_folded, &mut verify_oracle)?;

        // Verify the folded instance satisfies the constraints
        params
            .ccs_shape
            .is_satisfied_linearized::<Z>(&u_folded, &w_folded, &ck)?;

        Ok(())
    }
}
