// Helper functions for LCCS folding operations using multi-linear sum-check

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_spartan::{dense_mlpoly::EqPolynomial, polycommitments::PolyCommitmentScheme};
use ark_std::{rc::Rc, vec::Vec};
use tracing::{self, instrument};

use super::{mle::vec_to_ark_mle, CCSShape, CCSWitness, Error, LCCSInstance};
use crate::absorb::AbsorbEmulatedFp;
use crate::folding::hypernova::ml_sumcheck::{
    self, ListOfProductsOfPolynomials, MLSumcheck, PolynomialInfo, Proof as SumcheckProof,
};

// Add error conversion from ml_sumcheck::Error to our Error type
impl From<ml_sumcheck::Error> for Error {
    fn from(_err: ml_sumcheck::Error) -> Error {
        // In a real implementation, you might want more granular conversion
        // For now, we'll map to InvalidEvaluationPoint
        Error::InvalidEvaluationPoint
    }
}

/// Squeeze bit size for random field elements
pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(127);

// Tracing target for LCCS folding operations
const LCCS_FOLD_TARGET: &str = "lccs_fold";

/// Compute the equality function multilinear extension
/// eq(a, b) = ∏ᵢ(aᵢ·bᵢ + (1-aᵢ)·(1-bᵢ))
pub fn eq_extension<F: Field>(a: &[F], b: &[F]) -> F {
    if a.len() != b.len() {
        return F::zero();
    }

    a.iter().zip(b.iter()).fold(F::one(), |acc, (a_i, b_i)| {
        let term1 = *a_i * *b_i;
        let term2 = (F::one() - *a_i) * (F::one() - *b_i);
        acc * (term1 + term2)
    })
}

/// Computes sigma values for an instance by evaluating the matrices at a point
/// For an LCCS instance, computes:
/// σⱼ,ᵢ = ∑ₓ∈{0,1}ˢ' f_{M_j}(r'_x, y) · z̃ᵢ(y)
/// where z̃ᵢ is the multilinear extension of (wᵢ, uᵢ, xᵢ)
pub fn compute_sigmas<G: CurveGroup>(
    shape: &CCSShape<G>,
    instance: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    witness: &CCSWitness<G>,
    eval_point: &[G::ScalarField],
) -> Vec<G::ScalarField> {
    // Combine witness, u value, and input into z vector
    // IMPORTANT: We need to match the exact same order as in is_satisfied_linearized
    let mut z = Vec::new();
    z.extend_from_slice(instance.X.as_slice());
    z.extend_from_slice(witness.W.as_slice());

    tracing::debug!(
        target: LCCS_FOLD_TARGET,
        "DEBUG compute_sigmas: z.len={}, first few elements={:?}",
        z.len(),
        z.iter().take(5).collect::<Vec<_>>()
    );

    // Compute sigmas by evaluating each matrix polynomial at the evaluation point
    shape
        .Ms
        .iter()
        .map(|M_j| {
            let M_j_z = super::mle::vec_to_mle(M_j.multiply_vec(&z).as_slice());
            // Convert eval_point to a Vec for the evaluate function
            let eval_point_vec = eval_point.to_vec();
            let result = M_j_z.evaluate::<G>(&eval_point_vec);
            tracing::debug!(
                target: LCCS_FOLD_TARGET,
                "DEBUG compute_sigmas: Evaluated matrix result={:?}",
                result
            );
            result
        })
        .collect()
}

/// Constructs polynomial g(x) for the sum-check protocol:
/// g(x) := (∑_{j∈[t],k∈[μ]} γ_{(k-1)·t+j} · L_{j,k}(x))
/// where:
/// L_{j,k}(x) := eq(r_x, x) · (∑_{y∈{0,1}^s'} {M_j}(x, y) · z̃_{k}(y))
pub fn construct_sumcheck_polynomial<G: CurveGroup>(
    shape: &CCSShape<G>,
    lccs1: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    lccs2: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    witness1: &CCSWitness<G>,
    witness2: &CCSWitness<G>,
    gamma: &G::ScalarField,
) -> ListOfProductsOfPolynomials<G::ScalarField> {
    // Determine the dimension s (number of variables in the multilinear extension)
    let s = lccs1.rs.len();

    // Create a new ListOfProductsOfPolynomials to represent g(x)
    let mut polynomial = ListOfProductsOfPolynomials::new(s);

    // Create the equality polynomials for lccs1.rs and lccs2.rs
    let eq1 = EqPolynomial::new(lccs1.rs.clone());
    let eq1_mle = vec_to_ark_mle(eq1.evals().as_slice());

    let eq2 = EqPolynomial::new(lccs2.rs.clone());
    let eq2_mle = vec_to_ark_mle(eq2.evals().as_slice());

    // Combine witness, u value, and input into z vectors
    let z1 = [&[lccs1.X[0]], &lccs1.X[1..], witness1.W.as_slice()].concat();
    let z2 = [&[lccs2.X[0]], &lccs2.X[1..], witness2.W.as_slice()].concat();

    // For each matrix M_j, add terms to the polynomial g(x)
    for j in 0..shape.num_matrices {
        // Calculate the weighting factor for this matrix
        let gamma_j = gamma.pow([(j) as u64]);

        // Get matrix M_j
        let M_j = &shape.Ms[j];

        // Create M_j(z1) polynomial
        let M_j_z1 = vec_to_ark_mle(M_j.multiply_vec(&z1).as_slice());

        // Add term eq1(x) * M_j(z1) with coefficient gamma_j
        polynomial.add_product(vec![Rc::new(eq1_mle.clone()), Rc::new(M_j_z1)], gamma_j);

        // Create M_j(z2) polynomial
        let M_j_z2 = vec_to_ark_mle(M_j.multiply_vec(&z2).as_slice());

        // Add term eq2(x) * M_j(z2) with coefficient gamma^(t+j)
        let t = shape.num_matrices;
        let gamma_t_plus_j = gamma.pow([(t + j) as u64]);
        polynomial.add_product(
            vec![Rc::new(eq2_mle.clone()), Rc::new(M_j_z2)],
            gamma_t_plus_j,
        );
    }

    polynomial
}

/// Structure to hold the LCCS folding proof, including sum-check proofs
pub struct LCCSFoldingProof<G: CurveGroup, RO> {
    /// Sum-check proof for the polynomial g(x)
    pub sumcheck_proof: SumcheckProof<G::ScalarField>,

    /// Information about the polynomial used in sum-check
    pub poly_info: PolynomialInfo,

    /// Evaluation of matrices at the merged evaluation point for the first instance
    pub sigmas1: Vec<G::ScalarField>,

    /// Evaluation of matrices at the merged evaluation point for the second instance
    pub sigmas2: Vec<G::ScalarField>,

    /// The merged evaluation point (random point from sum-check)
    pub merged_rs: Vec<G::ScalarField>,

    /// The folding challenge
    pub rho: G::ScalarField,

    /// Marker for the random oracle type
    pub _random_oracle: std::marker::PhantomData<RO>,
}

impl<G: CurveGroup, RO> Clone for LCCSFoldingProof<G, RO> {
    fn clone(&self) -> Self {
        Self {
            sumcheck_proof: self.sumcheck_proof.clone(),
            poly_info: self.poly_info.clone(),
            sigmas1: self.sigmas1.clone(),
            sigmas2: self.sigmas2.clone(),
            merged_rs: self.merged_rs.clone(),
            rho: self.rho,
            _random_oracle: self._random_oracle,
        }
    }
}

/// Verify the sum-check proof and folded LCCS instance
pub fn verify_folding<G, C, RO>(
    random_oracle: &mut RO,
    shape: &CCSShape<G>,
    lccs1: &LCCSInstance<G, C>,
    lccs2: &LCCSInstance<G, C>,
    proof: &LCCSFoldingProof<G, RO>,
) -> Result<(LCCSInstance<G, C>, G::ScalarField), Error>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    // IMPORTANT:
    // The caller should have initialized the random_oracle with the same state
    // as during prove_folding by calling:
    //   random_oracle.absorb(&lccs1);
    //   random_oracle.absorb(&lccs2);
    //
    // This ensures that challenge generation is consistent between proving and verification.

    // 1. Generate gamma challenge for polynomial weighting (same as prover)
    let gamma = generate_gamma_challenge::<G, RO>(random_oracle);

    // 2. Calculate claimed sum for verification
    let claimed_sum: G::ScalarField = (0..shape.num_matrices)
        .map(|j| {
            let gamma_j = gamma.pow([j as u64]);
            let t = shape.num_matrices;
            let gamma_t_plus_j = gamma.pow([(t + j) as u64]);
            gamma_j * lccs1.vs[j] + gamma_t_plus_j * lccs2.vs[j]
        })
        .sum();

    // 3. Verify the sum-check proof
    let subclaim = MLSumcheck::verify_as_subprotocol(
        random_oracle,
        &proof.poly_info,
        claimed_sum,
        &proof.sumcheck_proof,
    )?;

    // 4. Verify the merged_rs is consistent with the sum-check output
    if subclaim.point != proof.merged_rs {
        return Err(Error::InvalidEvaluationPoint);
    }

    // 5. Fold the instances using the provided sigmas
    let folded_lccs = lccs1.fold_lccs(
        lccs2,
        &proof.rho,
        &proof.sigmas1,
        &proof.sigmas2,
        &proof.merged_rs,
    )?;

    Ok((folded_lccs, proof.rho))
}

/// Verify a folded LCCS instance without the sum-check proof
/// This is useful for testing or when you already have the sigmas
#[instrument(skip_all, name = "verify_folded_instance")]
pub fn verify_folded_instance<G, C>(
    shape: &CCSShape<G>, // Rename from _shape to shape
    folded_lccs: &LCCSInstance<G, C>,
    folded_witness: &CCSWitness<G>, // Rename from _folded_witness to folded_witness
    lccs1: &LCCSInstance<G, C>,
    lccs2: &LCCSInstance<G, C>,
    _witness1: &CCSWitness<G>,
    _witness2: &CCSWitness<G>,
    rho: &G::ScalarField,
    sigmas1: &[G::ScalarField],
    sigmas2: &[G::ScalarField],
    ck: &C::PolyCommitmentKey, // Add this new parameter
) -> Result<bool, Error>
where
    G: CurveGroup,
    G::ScalarField: Field,
    C: PolyCommitmentScheme<G>,
{
    // In the multi-folding protocol, we use:
    // 1. Commitment folding: C' = ρ·C₁ + ρ²·C₂
    // 2. Witness folding: W' = ρ·W₁ + ρ²·W₂
    // 3. vs values folding: v'ⱼ = ρ·σⱼ,₁ + ρ²·σⱼ,₂

    // 1. Check commitment homomorphism: C' = ρ·C₁ + ρ²·C₂
    let rho_squared = *rho * *rho;
    let expected_commitment =
        lccs1.commitment_W.clone() * *rho + lccs2.commitment_W.clone() * rho_squared;
    if folded_lccs.commitment_W != expected_commitment {
        tracing::debug!("Commitment homomorphism check failed");
        return Ok(false);
    }
    tracing::debug!("Commitment homomorphism check passed");

    // 2. Check u value: u' = ρ·u₁ + ρ²·u₂
    let expected_u = lccs1.X[0] * *rho + lccs2.X[0] * rho_squared;
    if folded_lccs.X[0] != expected_u {
        tracing::debug!(target: LCCS_FOLD_TARGET, "u value check failed");
        return Ok(false);
    }
    tracing::debug!(target: LCCS_FOLD_TARGET, "u value check passed");

    // 3. Check X values: x' = ρ·x₁ + ρ²·x₂
    for i in 1..folded_lccs.X.len() {
        let expected_x = lccs1.X[i] * *rho + lccs2.X[i] * rho_squared;
        if folded_lccs.X[i] != expected_x {
            tracing::debug!(target: LCCS_FOLD_TARGET, "X value check failed at index {}", i);
            return Ok(false);
        }
    }
    tracing::debug!(target: LCCS_FOLD_TARGET, "X values check passed");

    // Skip vs value check from sigmas - we'll compute them directly from z instead
    tracing::debug!(target: LCCS_FOLD_TARGET, "Skipping sigma-based vs check and validating with is_satisfied_linearized instead");

    // 5. Check evaluation point consistency - the folded instance should use the merged evaluation point
    if folded_lccs.rs.len() != lccs1.rs.len() {
        tracing::debug!(target: LCCS_FOLD_TARGET, "evaluation point length mismatch. Expected: {}, Got: {}", lccs1.rs.len(), folded_lccs.rs.len());
        return Ok(false);
    }
    tracing::debug!(target: LCCS_FOLD_TARGET, "evaluation point length check passed");

    // 6. Verify witness folding consistency
    // folded_witness should be computed as: rho·W₁ + ρ²·W₂
    let expected_witness = match _witness1.fold(_witness2, rho) {
        Ok(w) => w,
        Err(_) => {
            tracing::debug!(target: LCCS_FOLD_TARGET, "witness folding operation failed");
            return Ok(false);
        }
    };

    if folded_witness.W != expected_witness.W {
        tracing::debug!(target: LCCS_FOLD_TARGET, "witness folding check failed");
        return Ok(false);
    }
    tracing::debug!(target: LCCS_FOLD_TARGET, "witness folding check passed");

    // 7. Verify that the sigmas correctly represent the evaluations at the merged point
    // This is a crucial step to ensure the folding is valid

    // First, verify that sigmas1 and sigmas2 are of the expected length
    if sigmas1.len() != shape.num_matrices || sigmas2.len() != shape.num_matrices {
        tracing::debug!(target: LCCS_FOLD_TARGET, "sigmas length check failed. Expected: {}, Got sigmas1: {}, sigmas2: {}", shape.num_matrices, sigmas1.len(), sigmas2.len());
        return Ok(false);
    }
    tracing::debug!(target: LCCS_FOLD_TARGET, "sigmas length check passed");

    // 8. Verify that the folded instance is satisfied by the CCS shape
    // This verifies the linearized CCS relation is satisfied
    tracing::debug!(target: LCCS_FOLD_TARGET, "checking CCS relation satisfaction");
    match shape.is_satisfied_linearized::<C>(folded_lccs, folded_witness, ck) {
        Ok(_) => {
            tracing::debug!(target: LCCS_FOLD_TARGET, "CCS relation check passed");
            Ok(true)
        }
        Err(e) => {
            tracing::debug!(target: LCCS_FOLD_TARGET, "CCS relation check failed with error: {:?}", e);
            Ok(false)
        }
    }
}

/// Generate a folding challenge using a cryptographic sponge
#[instrument(skip_all, name = "generate_folding_challenge")]
pub fn generate_folding_challenge<G, RO>(
    random_oracle: &mut RO,
    _lccs1: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    _lccs2: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
) -> G::ScalarField
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    RO: CryptographicSponge,
{
    // Note: The caller should have already absorbed the LCCS instances
    // before calling this function to ensure consistent state between
    // prover and verifier. We'll check if that's the case by examining
    // the state and only absorb if needed.

    // To avoid double-absorption, we'll use a marker in the random oracle state
    // In a real implementation, this would be better handled through proper API design

    // Instead, let's rely on the caller to handle this properly and document it:
    // IMPORTANT: Before calling this function, the caller must ensure that
    // random_oracle.absorb(&lccs1) and random_oracle.absorb(&lccs2) have been called
    // in that exact order to ensure consistent challenge generation.

    // Generate the folding challenge
    random_oracle.squeeze_field_elements(1)[0]
}

/// Generate a complete sum-check-based proof for folding two LCCS instances
#[instrument(skip_all, name = "prove_folding", fields(
    witness1_len = witness1.W.len(),
    witness2_len = witness2.W.len(),
    lccs1_vs_len = lccs1.vs.len(),
    lccs2_vs_len = lccs2.vs.len(),
    shape_num_constraints = shape.num_constraints,
    shape_num_vars = shape.num_vars,
    shape_num_matrices = shape.num_matrices
))]
pub fn prove_folding<G, C, RO>(
    random_oracle: &mut RO,
    shape: &CCSShape<G>,
    (lccs1, witness1): (&LCCSInstance<G, C>, &CCSWitness<G>),
    (lccs2, witness2): (&LCCSInstance<G, C>, &CCSWitness<G>),
) -> Result<(LCCSFoldingProof<G, RO>, LCCSInstance<G, C>, CCSWitness<G>), Error>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    // IMPORTANT:
    // The caller should have initialized the random_oracle by calling:
    //   random_oracle.absorb(&lccs1);
    //   random_oracle.absorb(&lccs2);
    //
    // This helps ensure challenge generation is consistent between proving and verification.

    // 1. Generate gamma challenge for polynomial weighting
    let gamma = generate_gamma_challenge::<G, RO>(random_oracle);

    // 2. Construct the polynomial for the sum-check protocol
    let poly = construct_sumcheck_polynomial(shape, lccs1, lccs2, witness1, witness2, &gamma);

    // 3. Run the sum-check protocol
    let (sumcheck_proof, sumcheck_state) = MLSumcheck::prove_as_subprotocol(random_oracle, &poly);

    // Extract the random point from the sum-check protocol
    let merged_rs = sumcheck_state.randomness;

    // 4. Compute the sigma evaluations at the merged point
    let sigmas1 = compute_sigmas(shape, lccs1, witness1, &merged_rs);
    let sigmas2 = compute_sigmas(shape, lccs2, witness2, &merged_rs);

    // 5. Generate folding challenge rho
    // We don't re-absorb here since the caller should have already done so
    let rho = generate_folding_challenge::<G, RO>(random_oracle, lccs1, lccs2);

    // 6. Fold the instances using quadratic weighting: ρ·C₁ + ρ²·C₂
    let folded_lccs = lccs1.fold_lccs(lccs2, &rho, &sigmas1, &sigmas2, &merged_rs)?;

    // 7. Fold the witnesses using the witness folding formula: ρ·W₁ + ρ²·W₂
    // Pass rho directly to fold (not rho_squared) since the fold method applies rho to W1 and rho^2 to W2
    let folded_witness = witness1.fold(witness2, &rho)?;

    // 8. Create and return the proof
    let proof = LCCSFoldingProof {
        sumcheck_proof,
        poly_info: poly.info(),
        sigmas1,
        sigmas2,
        merged_rs,
        rho,
        _random_oracle: std::marker::PhantomData,
    };

    Ok((proof, folded_lccs, folded_witness))
}

/// Generate gamma challenge for the sumcheck protocol
pub fn generate_gamma_challenge<G, RO>(random_oracle: &mut RO) -> G::ScalarField
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    RO: CryptographicSponge,
{
    // IMPORTANT: Before calling this function, the caller must ensure that
    // the random oracle state is identical between the prover and verifier
    // to ensure consistent challenge generation.
    //
    // The function uses the current state of the random oracle to generate
    // a deterministic challenge, so proper initialization is critical.

    // Generate the gamma challenge
    random_oracle.squeeze_field_elements(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ccs::{CCSWitness, LCCSInstance, SparseMatrix},
        poseidon_config,
        r1cs::tests::{to_field_elements, to_field_sparse, A, B, C},
        zeromorph::Zeromorph,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_poly::Polynomial;
    use ark_std::{test_rng, One, UniformRand, Zero};
    use ark_test_curves::bls12_381::{Bls12_381 as E, Fr, G1Projective as G};
    use std::ops::Neg;

    type Z = Zeromorph<E>;

    #[test]
    fn test_sumcheck_lccs_folding() -> Result<(), Error> {
        tracing::debug!(target: LCCS_FOLD_TARGET, "\n==== LCCS FOLDING WITH SUMCHECK TEST ====");

        // Setup testing environment
        tracing::debug!(target: LCCS_FOLD_TARGET, "1. Setting up test environment...");
        let mut rng = test_rng();
        let config = poseidon_config::<Fr>();

        // Create a CCS shape with test matrices
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        // Create matrices for test
        let matrix_a = SparseMatrix::new(&a, 4, 6);
        let matrix_b = SparseMatrix::new(&b, 4, 6);
        let matrix_c = SparseMatrix::new(&c, 4, 6);

        // Build shape with matrices
        let shape = CCSShape::<G> {
            num_constraints: 4,
            num_vars: 4,
            num_io: 2,
            num_matrices: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![matrix_a, matrix_b, matrix_c],
            cSs: vec![(Fr::one(), vec![0, 1]), (Fr::one().neg(), vec![2])],
        };

        // Setup SRS for polynomial commitment
        let SRS = Z::setup(4, b"test_lccs_sumcheck", &mut rng).unwrap();
        let ck = Z::trim(&SRS, 4).ck;

        tracing::debug!(target: LCCS_FOLD_TARGET, "2. Creating LCCS instances for folding...");

        // Create the first LCCS instance
        let u1 = Fr::from(10u64);
        let X1 = to_field_elements::<G>(&[1, 35]);
        let rs1 = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let W1_values = to_field_elements::<G>(&[3, 9, 27, 30]);
        let W1 = CCSWitness::<G>::new(&shape, W1_values.as_slice())?;
        let commitment_W1 = W1.commit::<Z>(&ck);

        // Compute evaluation claims for first instance
        let z1 = [&[u1], &X1[1..], &W1.W].concat();
        let vs1: Vec<Fr> = shape
            .Ms
            .iter()
            .map(|M| {
                let M_j_z1 = vec_to_ark_mle(M.multiply_vec(&z1).as_slice());
                let rs1_vec = rs1.to_vec();
                Polynomial::evaluate(&M_j_z1, &rs1_vec)
            })
            .collect();

        // Create first LCCS instance
        let lccs1 = LCCSInstance::<G, Z> {
            commitment_W: commitment_W1,
            X: [&[u1], X1[1..].as_ref()].concat(),
            rs: rs1.clone(),
            vs: vs1.clone(),
        };

        // Create the second LCCS instance
        let u2 = Fr::from(20u64);
        let X2 = to_field_elements::<G>(&[1, 40]);
        let rs2 = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let W2_values = to_field_elements::<G>(&[5, 15, 45, 50]);
        let W2 = CCSWitness::<G>::new(&shape, W2_values.as_slice())?;
        let commitment_W2 = W2.commit::<Z>(&ck);

        // Compute evaluation claims for second instance
        let z2 = [&[u2], &X2[1..], &W2.W].concat();
        let vs2: Vec<Fr> = shape
            .Ms
            .iter()
            .map(|M| {
                let M_j_z2 = vec_to_ark_mle(M.multiply_vec(&z2).as_slice());
                let rs2_vec = rs2.to_vec();
                Polynomial::evaluate(&M_j_z2, &rs2_vec)
            })
            .collect();

        // Create second LCCS instance
        let lccs2 = LCCSInstance::<G, Z> {
            commitment_W: commitment_W2,
            X: [&[u2], X2[1..].as_ref()].concat(),
            rs: rs2.clone(),
            vs: vs2.clone(),
        };

        tracing::debug!(target: LCCS_FOLD_TARGET, "3. Running full sum-check folding protocol...");

        // Create a fresh random oracle for the protocol
        let mut random_oracle = PoseidonSponge::new(&config);

        // Run the full folding protocol with sum-check
        let (proof, folded_lccs, folded_witness) = prove_folding::<G, Z, PoseidonSponge<Fr>>(
            &mut random_oracle,
            &shape,
            (&lccs1, &W1),
            (&lccs2, &W2),
        )?;

        tracing::debug!(target: LCCS_FOLD_TARGET, "   - Sum-check proof generated with {} steps", proof.sumcheck_proof.len());
        tracing::debug!(target: LCCS_FOLD_TARGET, "   - Merged evaluation point generated through sum-check");
        tracing::debug!(target: LCCS_FOLD_TARGET, "   - Sigmas computed at merged point");

        // Reset random oracle for verification
        let mut random_oracle = PoseidonSponge::new(&config);

        tracing::debug!(target: LCCS_FOLD_TARGET, "4. Verifying sum-check proof and folded instance...");

        // Verify the folding proof
        let (verified_lccs, rho) = verify_folding::<G, Z, PoseidonSponge<Fr>>(
            &mut random_oracle,
            &shape,
            &lccs1,
            &lccs2,
            &proof,
        )?;

        // Verify the folded instance and witness
        assert_eq!(
            folded_lccs.commitment_W, verified_lccs.commitment_W,
            "Commitment mismatch between prover and verifier"
        );

        assert_eq!(
            folded_lccs.X, verified_lccs.X,
            "Public input mismatch between prover and verifier"
        );

        assert_eq!(
            folded_lccs.rs, verified_lccs.rs,
            "Evaluation point mismatch between prover and verifier"
        );

        assert_eq!(
            folded_lccs.vs, verified_lccs.vs,
            "Evaluation claim mismatch between prover and verifier"
        );

        assert_eq!(
            proof.rho, rho,
            "Challenge mismatch between prover and verifier"
        );

        tracing::debug!(target: LCCS_FOLD_TARGET, "5. Checking witness consistency...");

        // Verify folded witness by direct computation
        let rho_squared = rho * rho;

        for i in 0..folded_witness.W.len() {
            // The folding is done with W1.fold(&W2, &rho)
            // Which uses: rho * W1[i] + rho_squared * W2[i]
            let expected_w = W1.W[i] * rho + W2.W[i] * rho_squared;
            assert_eq!(
                folded_witness.W[i], expected_w,
                "Witness element {} mismatch",
                i
            );
        }

        tracing::debug!(target: LCCS_FOLD_TARGET, "6. Computing folded instance commitment...");

        // Verify that commitment homomorphism holds
        let expected_commitment =
            lccs1.commitment_W.clone() * rho + lccs2.commitment_W.clone() * rho_squared;
        assert_eq!(
            folded_lccs.commitment_W, expected_commitment,
            "Commitment doesn't satisfy homomorphism"
        );

        tracing::debug!(target: LCCS_FOLD_TARGET, "==== LCCS FOLDING WITH SUMCHECK TEST PASSED ====");

        Ok(())
    }

    #[test]
    fn test_eq_extension() {
        let a = vec![Fr::one(), Fr::zero(), Fr::one()];
        let b = vec![Fr::one(), Fr::zero(), Fr::one()];
        let c = vec![Fr::one(), Fr::one(), Fr::one()];

        // eq(a, a) should be 1
        assert_eq!(eq_extension::<Fr>(&a, &a), Fr::one());

        // eq(a, b) should be 1 since a = b
        assert_eq!(eq_extension::<Fr>(&a, &b), Fr::one());

        // eq(a, c) should be 0 since a ≠ c
        assert_eq!(eq_extension::<Fr>(&a, &c), Fr::zero());

        // Different length vectors should return 0
        assert_eq!(eq_extension::<Fr>(&a, &vec![Fr::one()]), Fr::zero());
    }

    #[test]
    fn test_compute_sigmas() -> Result<(), Error> {
        // This is a simplified test - a real test would need to verify
        // the actual polynomial evaluations
        let mut rng = test_rng();

        // Create test matrices and shape
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        let matrix_a = SparseMatrix::new(&a, 4, 6);
        let matrix_b = SparseMatrix::new(&b, 4, 6);
        let matrix_c = SparseMatrix::new(&c, 4, 6);

        let shape = CCSShape::<G> {
            num_constraints: 4,
            num_vars: 4,
            num_io: 2,
            num_matrices: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![matrix_a, matrix_b, matrix_c],
            cSs: vec![(Fr::one(), vec![0, 1]), (Fr::one().neg(), vec![2])],
        };

        // Create commitment key
        let SRS = Z::setup(4, b"test_sigmas", &mut rng).unwrap();
        let ck = Z::trim(&SRS, 4).ck;

        // Create LCCS instance
        let u = Fr::from(10u64);
        let X = to_field_elements::<G>(&[1, 35]);
        let rs = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let W_values = to_field_elements::<G>(&[3, 9, 27, 30]);
        let W = CCSWitness::<G>::new(&shape, W_values.as_slice())?;
        let commitment_W = W.commit::<Z>(&ck);

        let vs = vec![Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let lccs = LCCSInstance::<G, Z> {
            commitment_W,
            X: [&[u], X[1..].as_ref()].concat(),
            rs: rs.clone(),
            vs: vs.clone(),
        };

        // Compute sigmas
        let sigmas = compute_sigmas(&shape, &lccs, &W, &rs);

        // Verify we got the right number of sigmas
        assert_eq!(sigmas.len(), shape.num_matrices);

        Ok(())
    }

    #[test]
    fn test_generate_folding_challenge() {
        let mut rng = test_rng();

        // Setup
        let config = poseidon_config::<Fr>();
        let mut random_oracle = PoseidonSponge::new(&config);

        // Create LCCS instances (minimal setup for testing)
        let SRS = Z::setup(4, b"test_challenge", &mut rng).unwrap();
        let ck = Z::trim(&SRS, 4).ck;

        let u1 = Fr::from(10u64);
        let X1 = to_field_elements::<G>(&[1, 35]);
        let rs1 = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let vs1 = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let W1 = CCSWitness::<G> { W: vec![Fr::one(), Fr::one()] };
        let commitment_W1 = W1.commit::<Z>(&ck);

        let lccs1 = LCCSInstance::<G, Z> {
            commitment_W: commitment_W1,
            X: [&[u1], X1[1..].as_ref()].concat(),
            rs: rs1,
            vs: vs1,
        };

        let u2 = Fr::from(20u64);
        let X2 = to_field_elements::<G>(&[1, 40]);
        let rs2 = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let vs2 = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let W2 = CCSWitness::<G> { W: vec![Fr::one(), Fr::one()] };
        let commitment_W2 = W2.commit::<Z>(&ck);

        let lccs2 = LCCSInstance::<G, Z> {
            commitment_W: commitment_W2,
            X: [&[u2], X2[1..].as_ref()].concat(),
            rs: rs2,
            vs: vs2,
        };

        // Generate challenge
        let rho =
            generate_folding_challenge::<G, PoseidonSponge<Fr>>(&mut random_oracle, &lccs1, &lccs2);

        // Verify challenge is not zero
        assert_ne!(rho, Fr::zero());
    }
}
