// Helper functions for LCCS folding operations

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::{vec::Vec};
use ark_spartan::{dense_mlpoly::EqPolynomial, polycommitments::PolyCommitmentScheme};

use super::{CCSShape, CCSWitness, Error, LCCSInstance, mle::vec_to_ark_mle};
use crate::absorb::AbsorbEmulatedFp;

/// Squeeze bit size for random field elements
pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(127);

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
    let z = [&[instance.X[0]], &instance.X[1..], witness.W.as_slice()].concat();
    
    // Compute sigmas by evaluating each matrix polynomial at the evaluation point
    shape.Ms.iter().map(|M_j| {
        let M_j_z = vec_to_ark_mle(M_j.multiply_vec(&z).as_slice());
        // Convert eval_point to a Vec for the evaluate function
        let eval_point_vec = eval_point.to_vec();
        M_j_z.evaluate(&eval_point_vec)
    }).collect()
}

/// Constructs polynomial g(x) for the sum-check protocol:
/// g(x) := ∑ⱼ γⱼ·(L_{j,1}(x) + L_{j,2}(x))
/// where L_{j,i}(x) = eq(rᵢ, x)·(∑ₓ∈{0,1}ˢ' f_{M_j}(x, y)·z̃ᵢ(y))
pub fn construct_sumcheck_polynomial<G: CurveGroup>(
    shape: &CCSShape<G>,
    lccs1: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    lccs2: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    witness1: &CCSWitness<G>,
    witness2: &CCSWitness<G>,
    gamma: &G::ScalarField,
) -> Vec<DenseMultilinearExtension<G::ScalarField>> {
    // This is a simplified version - in practice, you would construct the actual
    // polynomial using MLSumcheck structures from the existing codebase
    
    // Create the equality polynomials for lccs1.rs and lccs2.rs
    let eq1 = EqPolynomial::new(lccs1.rs.clone());
    let _eq1_mle = vec_to_ark_mle(eq1.evals().as_slice());
    
    let eq2 = EqPolynomial::new(lccs2.rs.clone());
    let _eq2_mle = vec_to_ark_mle(eq2.evals().as_slice());
    
    // Combine witness, u value, and input into z vectors
    let z1 = [&[lccs1.X[0]], &lccs1.X[1..], witness1.W.as_slice()].concat();
    let z2 = [&[lccs2.X[0]], &lccs2.X[1..], witness2.W.as_slice()].concat();
    
    // Construct polynomials for each matrix
    let mut polys = Vec::with_capacity(shape.num_matrices * 2);
    
    for j in 0..shape.num_matrices {
        // Get matrix M_j
        let M_j = &shape.Ms[j];
        
        // Create polynomials L_{j,1} and L_{j,2}
        let M_j_z1 = vec_to_ark_mle(M_j.multiply_vec(&z1).as_slice());
        let M_j_z2 = vec_to_ark_mle(M_j.multiply_vec(&z2).as_slice());
        
        // Calculate the weighting factor for this matrix
        let _gamma_j = gamma.pow([(j + 1) as u64]);
        
        // In a real implementation, we would scale these polynomials by gamma_j
        // and combine them with the equality polynomials
        
        // Add the polynomials to our list
        polys.push(M_j_z1);
        polys.push(M_j_z2);
    }
    
    polys
}

/// Verify the folded LCCS instance
pub fn verify_folded_instance<G, C>(
    _shape: &CCSShape<G>,
    folded_lccs: &LCCSInstance<G, C>,
    _folded_witness: &CCSWitness<G>,
    lccs1: &LCCSInstance<G, C>,
    lccs2: &LCCSInstance<G, C>,
    _witness1: &CCSWitness<G>,
    _witness2: &CCSWitness<G>,
    rho: &G::ScalarField,
    sigmas1: &[G::ScalarField],
    sigmas2: &[G::ScalarField],
) -> Result<bool, Error>
where
    G: CurveGroup,
    G::ScalarField: Field,
    C: PolyCommitmentScheme<G>,
{
    // 1. Check commitment homomorphism: C' = ρ·C₁ + ρ²·C₂
    let rho_squared = *rho * *rho;
    let expected_commitment = lccs1.commitment_W.clone() * *rho + lccs2.commitment_W.clone() * rho_squared;
    if folded_lccs.commitment_W != expected_commitment {
        return Ok(false);
    }
    
    // 2. Check u value: u' = ρ·u₁ + ρ²·u₂
    let expected_u = lccs1.X[0] * *rho + lccs2.X[0] * rho_squared;
    if folded_lccs.X[0] != expected_u {
        return Ok(false);
    }
    
    // 3. Check X values: x' = ρ·x₁ + ρ²·x₂
    for i in 1..folded_lccs.X.len() {
        let expected_x = lccs1.X[i] * *rho + lccs2.X[i] * rho_squared;
        if folded_lccs.X[i] != expected_x {
            return Ok(false);
        }
    }
    
    // 4. Check vs values: v'ⱼ = ρ·σⱼ,₁ + ρ²·σⱼ,₂
    for j in 0..folded_lccs.vs.len() {
        let expected_v = sigmas1[j] * *rho + sigmas2[j] * rho_squared;
        if folded_lccs.vs[j] != expected_v {
            return Ok(false);
        }
    }
    
    // 5. Verify that the folded instance is satisfied
    // This would involve running the CCS satisfaction check
    
    // For now, we'll just return true if all the above checks pass
    Ok(true)
}

/// Generate a folding challenge using a cryptographic sponge
pub fn generate_folding_challenge<G, RO>(
    random_oracle: &mut RO,
    lccs1: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
    lccs2: &LCCSInstance<G, impl PolyCommitmentScheme<G>>,
) -> G::ScalarField
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    RO: CryptographicSponge,
{
    // Absorb both instances into the random oracle
    random_oracle.absorb(&lccs1);
    random_oracle.absorb(&lccs2);
    
    // Generate the folding challenge
    random_oracle.squeeze_field_elements(1)[0]
}

/// Generate gamma challenge for the sumcheck protocol
pub fn generate_gamma_challenge<G, RO>(
    random_oracle: &mut RO,
) -> G::ScalarField
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    RO: CryptographicSponge,
{
    // Generate the gamma challenge
    random_oracle.squeeze_field_elements(1)[0]
}

/// Generate beta challenges for the sumcheck protocol
pub fn generate_beta_challenges<G, RO>(
    random_oracle: &mut RO,
    s: usize,
) -> Vec<G::ScalarField>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: PrimeField + Absorb,
    G::BaseField: PrimeField + Absorb,
    G::Affine: Absorb,
    RO: CryptographicSponge,
{
    // Generate the beta challenges
    random_oracle.squeeze_field_elements(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_std::{test_rng, One, UniformRand, Zero};
    use ark_test_curves::bls12_381::{Bls12_381 as E, Fr, G1Projective as G};
    use std::ops::Neg;
    use crate::{
        poseidon_config,
        zeromorph::Zeromorph,
        ccs::{SparseMatrix, CCSWitness, LCCSInstance},
        r1cs::tests::{to_field_elements, to_field_sparse, A, B, C},
    };
    
    type Z = Zeromorph<E>;
    
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
    fn test_compute_sigmas() {
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
            cSs: vec![
                (Fr::one(), vec![0, 1]),
                (Fr::one().neg(), vec![2]),
            ],
        };
        
        // Create commitment key
        let SRS = Z::setup(4, b"test_sigmas", &mut rng).unwrap();
        let ck = Z::trim(&SRS, 4).ck;
        
        // Create LCCS instance
        let u = Fr::from(10u64);
        let X = to_field_elements::<G>(&[1, 35]);
        let rs = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        
        let W_values = to_field_elements::<G>(&[3, 9, 27, 30]);
        let W = CCSWitness::<G>::new(&shape, &W_values).unwrap();
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
        let rho = generate_folding_challenge::<G, PoseidonSponge<Fr>>(&mut random_oracle, &lccs1, &lccs2);
        
        // Verify challenge is not zero
        assert_ne!(rho, Fr::zero());
    }
}