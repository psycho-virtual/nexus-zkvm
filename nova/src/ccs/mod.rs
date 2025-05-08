use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_std::{fmt, fmt::Display, ops::Neg, Zero};

#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

use crate::safe_loglike;

pub use super::sparse::{MatrixRef, SparseMatrix};
use super::{absorb::AbsorbEmulatedFp, r1cs::R1CSShape};
use mle::vec_to_mle;

pub mod mle;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    InvalidWitnessLength,
    InvalidInputLength,
    InvalidEvaluationPoint,
    InvalidTargets,
    NotSatisfied,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWitnessLength => write!(f, "invalid witness length"),
            Self::InvalidInputLength => write!(f, "invalid input length"),
            Self::InvalidEvaluationPoint => write!(f, "invalid evaluation point"),
            Self::InvalidTargets => write!(f, "invalid targets"),
            Self::NotSatisfied => write!(f, "not satisfied"),
        }
    }
}

/// A type that holds the shape of the CCS matrices
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSShape<G: CurveGroup> {
    /// `m` in the CCS/HyperNova papers.
    pub num_constraints: usize,
    /// Witness length.
    ///
    /// `m - l - 1` in the CCS/HyperNova papers.
    pub num_vars: usize,
    /// Length of the public input `X`. It is expected to have a leading
    /// `ScalarField::ONE` element, thus this field must be non-zero.
    ///
    /// `l + 1`, w.r.t. the CCS/HyperNova papers.
    pub num_io: usize,
    /// Number of matrices.
    ///
    /// `t` in the CCS/HyperNova papers.
    pub num_matrices: usize,
    /// Number of multisets.
    ///
    /// `q` in the CCS/HyperNova papers.
    pub num_multisets: usize,
    /// Max cardinality of the multisets.
    ///
    /// `d` in the CCS/HyperNova papers.
    pub max_cardinality: usize,
    /// Set of constraint matrices.
    pub Ms: Vec<SparseMatrix<G::ScalarField>>,
    /// Multisets of selector indices, each paired with a constant multiplier.
    pub cSs: Vec<(G::ScalarField, Vec<usize>)>,
}

impl<G: CurveGroup> fmt::Display for CCSShape<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CCSShape {{ num_constraints: {}, num_vars: {}, num_io: {}, num_matrices: {}, num_multisets: {}, max_cardinality: {}, Ms: [{}], cSs: [{}] }}",
               self.num_constraints,
               self.num_vars,
               self.num_io,
               self.num_matrices,
               self.num_multisets,
               self.max_cardinality,
               self.Ms.iter().map(|M| format!("[_, {}]", M.len())).collect::<Vec<_>>().join(", "),
               self.cSs.iter().map(|cS| format!("({}, [_, {}])", cS.0, cS.1.len())).collect::<Vec<_>>().join(", "),
        )
    }
}

impl<G: CurveGroup> CCSShape<G> {
    /// Checks if the CCS instance together with the witness `W` satisfies the CCS constraints determined by `shape`.
    pub fn is_satisfied<C: PolyCommitmentScheme<G>>(
        &self,
        U: &CCSInstance<G, C>,
        W: &CCSWitness<G>,
        ck: &C::PolyCommitmentKey,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();
        let Mzs: Vec<Vec<G::ScalarField>> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| M.multiply_vec(&z))
            .collect();

        let mut acc = vec![G::ScalarField::ZERO; self.num_constraints];
        for (c, S) in &self.cSs {
            let mut hadamard_product = vec![*c; self.num_constraints];

            for idx in S {
                ark_std::cfg_iter_mut!(hadamard_product)
                    .enumerate()
                    .for_each(|(j, x)| *x *= Mzs[*idx][j]);
            }

            ark_std::cfg_iter_mut!(acc)
                .enumerate()
                .for_each(|(i, s)| *s += hadamard_product[i]);
        }

        if ark_std::cfg_iter!(acc).any(|s| !s.is_zero()) {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != W.commit::<C>(ck) {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }

    pub fn is_satisfied_linearized<C: PolyCommitmentScheme<G>>(
        &self,
        U: &LCCSInstance<G, C>,
        W: &CCSWitness<G>,
        ck: &C::PolyCommitmentKey,
    ) -> Result<(), Error> {
        assert_eq!(W.W.len(), self.num_vars);
        assert_eq!(U.X.len(), self.num_io);

        let z = [U.X.as_slice(), W.W.as_slice()].concat();
        let Mzs: Vec<G::ScalarField> = ark_std::cfg_iter!(&self.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<G>(U.rs.as_slice()))
            .collect();

        if ark_std::cfg_into_iter!(0..self.num_matrices).any(|idx| Mzs[idx] != U.vs[idx]) {
            return Err(Error::NotSatisfied);
        }

        if U.commitment_W != W.commit::<C>(ck) {
            return Err(Error::NotSatisfied);
        }

        Ok(())
    }
}

/// Create an object of type `CCSShape` from the specified R1CS shape
impl<G: CurveGroup> From<R1CSShape<G>> for CCSShape<G> {
    fn from(shape: R1CSShape<G>) -> Self {
        Self {
            num_constraints: shape.num_constraints,
            num_io: shape.num_io,
            num_vars: shape.num_vars,
            num_matrices: 3,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![shape.A, shape.B, shape.C],
            cSs: vec![
                (G::ScalarField::ONE, vec![0, 1]),
                (G::ScalarField::ONE.neg(), vec![2]),
            ],
        }
    }
}

/// A type that holds a witness for a given CCS instance.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSWitness<G: CurveGroup> {
    pub W: Vec<G::ScalarField>,
}

/// A type that holds an CCS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    /// Commitment to witness.
    pub commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField::ONE`.
    pub X: Vec<G::ScalarField>,
}

impl<G: CurveGroup> CCSWitness<G> {
    /// A method to create a witness object using a vector of scalars.
    pub fn new(shape: &CCSShape<G>, W: &[G::ScalarField]) -> Result<Self, Error> {
        if shape.num_vars != W.len() {
            Err(Error::InvalidWitnessLength)
        } else {
            Ok(Self { W: W.to_owned() })
        }
    }

    pub fn zero(shape: &CCSShape<G>) -> Self {
        Self {
            W: vec![G::ScalarField::ZERO; shape.num_vars],
        }
    }

    /// Commits to the witness as a polynomial using the supplied key
    pub fn commit<C: PolyCommitmentScheme<G>>(&self, ck: &C::PolyCommitmentKey) -> C::Commitment {
        C::commit(&vec_to_mle(&self.W), ck)
    }

    /// Folds an incoming [`CCSWitness`] into the current one.
    pub fn fold(&self, W2: &CCSWitness<G>, rho: &G::ScalarField) -> Result<Self, Error> {
        let W1 = &self.W;
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(Error::InvalidWitnessLength);
        }

        let W: Vec<G::ScalarField> = ark_std::cfg_iter!(W1)
            .zip(W2)
            .map(|(a, b)| *a + *rho * *b)
            .collect();

        Ok(Self { W })
    }
}

impl<G, C> Absorb for CCSInstance<G, C>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: Absorb,
    C: PolyCommitmentScheme<G>,
    C::Commitment: Into<Vec<G>>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W.clone().into().iter().for_each(|c| {
            <G as AbsorbEmulatedFp<G::ScalarField>>::to_sponge_field_elements(c, dest)
        });

        (&self.X[1..]).to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> CCSInstance<G, C> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &CCSShape<G>,
        commitment_W: &C::Commitment,
        X: &[G::ScalarField],
    ) -> Result<Self, Error> {
        if X.is_empty() {
            return Err(Error::InvalidInputLength);
        }
        if shape.num_io != X.len() {
            Err(Error::InvalidInputLength)
        } else {
            Ok(Self {
                commitment_W: commitment_W.clone(),
                X: X.to_owned(),
            })
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> fmt::Debug for CCSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CCSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("X", &self.X)
            .finish()
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Clone for CCSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> PartialEq for CCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W && self.X == other.X
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Eq for CCSInstance<G, C> where C::Commitment: Eq {}

impl<G, C> Absorb for LCCSInstance<G, C>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: Absorb,
    C: PolyCommitmentScheme<G>,
    C::Commitment: Into<Vec<G>>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W.clone().into().iter().for_each(|c| {
            <G as AbsorbEmulatedFp<G::ScalarField>>::to_sponge_field_elements(c, dest)
        });

        self.X.to_sponge_field_elements(dest);
        self.rs.to_sponge_field_elements(dest);
        self.vs.to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> LCCSInstance<G, C> {
    /// A method to create an instance object using constituent elements.
    pub fn new(
        shape: &CCSShape<G>,
        commitment_W: &C::Commitment,
        X: &[G::ScalarField],
        rs: &[G::ScalarField],
        vs: &[G::ScalarField],
    ) -> Result<Self, Error> {
        if X.is_empty() || shape.num_io != X.len() {
            Err(Error::InvalidInputLength)
        } else if safe_loglike!(shape.num_constraints) != rs.len() as u32 {
            Err(Error::InvalidEvaluationPoint)
        } else if shape.num_matrices != vs.len() {
            Err(Error::InvalidTargets)
        } else {
            Ok(Self {
                commitment_W: commitment_W.clone(),
                X: X.to_owned(),
                rs: rs.to_owned(),
                vs: vs.to_owned(),
            })
        }
    }

    /// Folds an incoming **non-linearized** [`CCSInstance`] into the current one. Its auxillary inputs include a partial
    /// evaluation point `rs` and the sum of the evaluations at that point extended over the hypercube for both the current
    /// (`sigmas`) and incoming (`thetas`) instances.
    pub fn fold(
        &self,
        U2: &CCSInstance<G, C>,
        rho: &G::ScalarField,
        rs: &[G::ScalarField],
        sigmas: &[G::ScalarField],
        thetas: &[G::ScalarField],
    ) -> Result<Self, Error> {
        // in concept, uX1 = (u_1, x_1), oX2 = (1, x_2)
        // however, we don't guarantee oX2[0] = 1 during construction, so elide it during folding
        let (uX1, comm_W1) = (&self.X, self.commitment_W.clone());
        let (oX2, comm_W2) = (&U2.X, U2.commitment_W.clone());

        if self.rs.len() != rs.len() {
            return Err(Error::InvalidEvaluationPoint);
        }

        if sigmas.len() != thetas.len() {
            return Err(Error::InvalidTargets);
        }

        let (u1, X1) = (&uX1[0], &uX1[1..]);
        let X2 = &oX2[1..];

        let commitment_W = comm_W1 + comm_W2 * *rho;

        let u = [*u1 + *rho];
        let X: Vec<G::ScalarField> = ark_std::cfg_iter!(X1)
            .zip(X2)
            .map(|(a, b)| *a + *b * *rho)
            .collect();

        let vs: Vec<G::ScalarField> = ark_std::cfg_iter!(sigmas)
            .zip(thetas)
            .map(|(sigma, theta)| *sigma + *theta * *rho)
            .collect();

        Ok(Self {
            commitment_W,
            X: [&u, X.as_slice()].concat(),
            rs: rs.to_owned(),
            vs,
        })
    }
}

/// A type that holds an ACCS (Atomic CCS) instance as defined in the KiloNova paper.
///
/// Atomic CCS (ACCS) Relations are a relaxed form of Customizable Constraint Systems
/// that contain independent linear claims on instance-witness pairs and structures.
/// This enables efficient folding of multiple non-uniform instances without generating cross terms.
/// ACCS is derived from an "early stopping" version of SuperSpartan.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ACCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    /// Commitment to multilinear polynomial in s_y - 1 variables
    pub commitment_W: C::Commitment,
    /// Scalar value v_0 ∈ F
    pub v0: G::ScalarField,
    /// Public inputs io ∈ F^l
    pub io: Vec<G::ScalarField>,
    /// Evaluation point for x variables, r_x ∈ F^s_x
    pub r_x: Vec<G::ScalarField>,
    /// Evaluation point for y variables, r_y ∈ F^s_y
    pub r_y: Vec<G::ScalarField>,
    /// Evaluation targets v_j for j ∈ [t], where t is the number of sparse polynomials
    pub vs: Vec<G::ScalarField>,
    /// Evaluation of polynomial z at point r_y
    pub v_z: G::ScalarField,
}

impl<G, C> Absorb for ACCSInstance<G, C>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::ScalarField: Absorb,
    C: PolyCommitmentScheme<G>,
    C::Commitment: Into<Vec<G>>,
{
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unreachable!()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.commitment_W.clone().into().iter().for_each(|c| {
            <G as AbsorbEmulatedFp<G::ScalarField>>::to_sponge_field_elements(c, dest)
        });

        self.v0.to_sponge_field_elements(dest);
        self.io.to_sponge_field_elements(dest);
        self.r_x.to_sponge_field_elements(dest);
        self.r_y.to_sponge_field_elements(dest);
        self.vs.to_sponge_field_elements(dest);
        self.v_z.to_sponge_field_elements(dest);
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> ACCSInstance<G, C> {
    /// Creates a new ACCS instance with the provided parameters
    pub fn new(
        commitment_W: &C::Commitment,
        v0: &G::ScalarField,
        io: &[G::ScalarField],
        r_x: &[G::ScalarField],
        r_y: &[G::ScalarField],
        vs: &[G::ScalarField],
        v_z: &G::ScalarField,
    ) -> Result<Self, Error> {
        if io.is_empty() {
            return Err(Error::InvalidInputLength);
        }
        
        Ok(Self {
            commitment_W: commitment_W.clone(),
            v0: *v0,
            io: io.to_owned(),
            r_x: r_x.to_owned(),
            r_y: r_y.to_owned(),
            vs: vs.to_owned(),
            v_z: *v_z,
        })
    }
    
    /// Folds two ACCS instances together
    pub fn fold(
        &self,
        other: &ACCSInstance<G, C>,
        rho: &G::ScalarField,
    ) -> Result<Self, Error> {
        // Check that dimensions match
        if self.io.len() != other.io.len() ||
           self.r_x.len() != other.r_x.len() ||
           self.r_y.len() != other.r_y.len() ||
           self.vs.len() != other.vs.len() {
            return Err(Error::InvalidInputLength);
        }
        
        // Fold the commitments
        let commitment_W = self.commitment_W.clone() + other.commitment_W.clone() * *rho;
        
        // Fold v0
        let v0 = self.v0 + *rho * other.v0;
        
        // Fold io values
        let io: Vec<G::ScalarField> = ark_std::cfg_iter!(&self.io)
            .zip(&other.io)
            .map(|(a, b)| *a + *rho * *b)
            .collect();
            
        // r_x and r_y are typically challenge points and stay the same
        // This is a design decision - in some protocols they could be folded
        let r_x = self.r_x.clone();
        let r_y = self.r_y.clone();
        
        // Fold the evaluation targets
        let vs: Vec<G::ScalarField> = ark_std::cfg_iter!(&self.vs)
            .zip(&other.vs)
            .map(|(a, b)| *a + *rho * *b)
            .collect();
            
        // Fold v_z
        let v_z = self.v_z + *rho * other.v_z;
        
        Ok(Self {
            commitment_W,
            v0,
            io,
            r_x,
            r_y,
            vs,
            v_z,
        })
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> fmt::Debug for ACCSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACCSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("v0", &self.v0)
            .field("io", &self.io)
            .field("r_x", &self.r_x)
            .field("r_y", &self.r_y)
            .field("vs", &self.vs)
            .field("v_z", &self.v_z)
            .finish()
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Clone for ACCSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            v0: self.v0,
            io: self.io.clone(),
            r_x: self.r_x.clone(),
            r_y: self.r_y.clone(),
            vs: self.vs.clone(),
            v_z: self.v_z,
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> PartialEq for ACCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W &&
        self.v0 == other.v0 &&
        self.io == other.io &&
        self.r_x == other.r_x &&
        self.r_y == other.r_y &&
        self.vs == other.vs &&
        self.v_z == other.v_z
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Eq for ACCSInstance<G, C> where C::Commitment: Eq {}

/// A type that holds an LCCS instance.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct LCCSInstance<G: CurveGroup, C: PolyCommitmentScheme<G>> {
    /// Commitment to MLE of witness.
    ///
    /// C in HyperNova/CCS papers.
    pub commitment_W: C::Commitment,
    /// X is assumed to start with a `ScalarField` field element `u`.
    pub X: Vec<G::ScalarField>,
    /// (Random) evaluation point
    pub rs: Vec<G::ScalarField>,
    /// Evaluation targets
    pub vs: Vec<G::ScalarField>,
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> fmt::Debug for LCCSInstance<G, C>
where
    C::Commitment: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LCCSInstance")
            .field("commitment_W", &self.commitment_W)
            .field("X", &self.X)
            .field("rs", &self.rs)
            .field("vs", &self.vs)
            .finish()
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Clone for LCCSInstance<G, C> {
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
            rs: self.rs.clone(),
            vs: self.vs.clone(),
        }
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> PartialEq for LCCSInstance<G, C> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment_W == other.commitment_W
            && self.X == other.X
            && self.rs == other.rs
            && self.vs == other.vs
    }
}

impl<G: CurveGroup, C: PolyCommitmentScheme<G>> Eq for LCCSInstance<G, C> where C::Commitment: Eq {}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use crate::zeromorph::Zeromorph;
    use ark_spartan::polycommitments::PCSKeys;
    use ark_std::{test_rng, UniformRand};
    use ark_test_curves::bls12_381::{Bls12_381 as E, Fr, G1Projective as G};

    type Z = Zeromorph<E>;

    use crate::r1cs::tests::{to_field_elements, to_field_sparse, A, B, C};
    
    // Tests for ACCSInstance
    #[test]
    fn test_accs_create() -> Result<(), Error> {
        let mut rng = test_rng();
        
        // Set up parameters for SRS
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);
        
        // Create a simple witness
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = CCSWitness::<G>::new(
            &CCSShape::<G> { 
                num_constraints: 4, 
                num_vars: 4, 
                num_io: 2, 
                num_matrices: 3, 
                num_multisets: 2,
                max_cardinality: 2,
                Ms: vec![],  // Empty for test
                cSs: vec![], // Empty for test
            }, 
            &W
        )?;
        
        // Create commitment
        let commitment_W = witness.commit::<Z>(&ck);
        
        // Create ACCS instance parameters
        let v0 = Fr::from(42u32);
        let io = to_field_elements::<G>(&[1, 35]);
        let r_x: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let r_y: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let vs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let v_z = Fr::from(123u32);
        
        // Create the instance
        let accs = ACCSInstance::<G, Z>::new(
            &commitment_W,
            &v0,
            &io,
            &r_x.as_slice(),
            &r_y.as_slice(),
            &vs.as_slice(),
            &v_z,
        )?;
        
        // Verify fields are correctly set
        assert_eq!(accs.commitment_W, commitment_W);
        assert_eq!(accs.v0, v0);
        assert_eq!(accs.io, io);
        assert_eq!(accs.r_x, r_x);
        assert_eq!(accs.r_y, r_y);
        assert_eq!(accs.vs, vs);
        assert_eq!(accs.v_z, v_z);
        
        Ok(())
    }
    
    #[test]
    fn test_accs_fold() -> Result<(), Error> {
        let mut rng = test_rng();
        
        // Set up parameters for SRS
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);
        
        // Create two simple witnesses
        let W1 = to_field_elements::<G>(&[3, 9, 27, 30]);
        let W2 = to_field_elements::<G>(&[4, 10, 28, 31]);
        
        let shape = CCSShape::<G> { 
            num_constraints: 4, 
            num_vars: 4, 
            num_io: 2, 
            num_matrices: 3, 
            num_multisets: 2,
            max_cardinality: 2,
            Ms: vec![],  // Empty for test
            cSs: vec![], // Empty for test
        };
        
        let witness1 = CCSWitness::<G>::new(&shape, &W1)?;
        let witness2 = CCSWitness::<G>::new(&shape, &W2)?;
        
        // Create commitments
        let commitment_W1 = witness1.commit::<Z>(&ck);
        let commitment_W2 = witness2.commit::<Z>(&ck);
        
        // Create ACCS instance parameters
        let v0_1 = Fr::from(42u32);
        let v0_2 = Fr::from(24u32);
        let io = to_field_elements::<G>(&[1, 35]);
        let r_x: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let r_y: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let vs1: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let vs2: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let v_z1 = Fr::from(123u32);
        let v_z2 = Fr::from(456u32);
        
        // Create the instances
        let accs1 = ACCSInstance::<G, Z>::new(
            &commitment_W1,
            &v0_1,
            &io,
            &r_x.as_slice(),
            &r_y.as_slice(),
            &vs1.as_slice(),
            &v_z1,
        )?;
        
        let accs2 = ACCSInstance::<G, Z>::new(
            &commitment_W2,
            &v0_2,
            &io,
            &r_x.as_slice(),
            &r_y.as_slice(),
            &vs2.as_slice(),
            &v_z2,
        )?;
        
        // Folding factor
        let rho = Fr::from(7u32);
        
        // Fold the instances
        let folded_accs = accs1.fold(&accs2, &rho)?;
        
        // Verify folded fields are correctly computed
        assert_eq!(folded_accs.commitment_W, commitment_W1 + commitment_W2 * rho);
        assert_eq!(folded_accs.v0, v0_1 + rho * v0_2);
        
        // Check vs array folding
        for i in 0..vs1.len() {
            assert_eq!(folded_accs.vs[i], vs1[i] + rho * vs2[i]);
        }
        
        // Check v_z folding
        assert_eq!(folded_accs.v_z, v_z1 + rho * v_z2);
        
        Ok(())
    }
    
    #[test]
    fn test_accs_invalid_inputs() -> Result<(), Error> {
        let mut rng = test_rng();
        
        // Set up parameters for SRS
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);
        
        // Create a simple witness
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = CCSWitness::<G>::new(
            &CCSShape::<G> { 
                num_constraints: 4, 
                num_vars: 4, 
                num_io: 2, 
                num_matrices: 3, 
                num_multisets: 2,
                max_cardinality: 2,
                Ms: vec![],  // Empty for test
                cSs: vec![], // Empty for test
            }, 
            &W
        )?;
        
        // Create commitment
        let commitment_W = witness.commit::<Z>(&ck);
        
        // Create ACCS instance parameters
        let v0 = Fr::from(42u32);
        let empty_io: Vec<Fr> = vec![];
        let r_x: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let r_y: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let vs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let v_z = Fr::from(123u32);
        
        // Test with empty io (should fail)
        let result = ACCSInstance::<G, Z>::new(
            &commitment_W,
            &v0,
            &empty_io,
            &r_x.as_slice(),
            &r_y.as_slice(),
            &vs.as_slice(),
            &v_z,
        );
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidInputLength);
        
        // Create two valid instances with different length fields
        let valid_io = to_field_elements::<G>(&[1, 35]);
        let accs1 = ACCSInstance::<G, Z>::new(
            &commitment_W,
            &v0,
            &valid_io,
            &r_x.as_slice(),
            &r_y.as_slice(),
            &vs.as_slice(),
            &v_z,
        )?;
        
        // Create a second instance with different sized vs
        let different_vs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let accs2 = ACCSInstance::<G, Z>::new(
            &commitment_W,
            &v0,
            &valid_io,
            &r_x.as_slice(),
            &r_y.as_slice(),
            &different_vs.as_slice(),
            &v_z,
        )?;
        
        // Test folding with mismatched vs lengths (should fail)
        let rho = Fr::from(7u32);
        let result = accs1.fold(&accs2, &rho);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidInputLength);
        
        Ok(())
    }

    #[test]
    fn test_r1cs_to_ccs() -> Result<(), Error> {
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape.clone());
        assert_eq!(ccs_shape.num_constraints, NUM_CONSTRAINTS);
        assert_eq!(ccs_shape.num_constraints, r1cs_shape.num_constraints);

        assert_eq!(ccs_shape.num_vars, NUM_WITNESS);
        assert_eq!(ccs_shape.num_vars, r1cs_shape.num_vars);

        assert_eq!(ccs_shape.num_io, NUM_PUBLIC);
        assert_eq!(ccs_shape.num_io, r1cs_shape.num_io);

        assert_eq!(ccs_shape.num_matrices, 3);
        assert_eq!(ccs_shape.num_multisets, 2);
        assert_eq!(ccs_shape.max_cardinality, 2);

        assert_eq!(ccs_shape.Ms.len(), 3);
        assert_eq!(
            ccs_shape.Ms[0],
            SparseMatrix::new(&a, NUM_CONSTRAINTS, NUM_WITNESS + NUM_PUBLIC)
        );
        assert_eq!(
            ccs_shape.Ms[1],
            SparseMatrix::new(&b, NUM_CONSTRAINTS, NUM_WITNESS + NUM_PUBLIC)
        );
        assert_eq!(
            ccs_shape.Ms[2],
            SparseMatrix::new(&c, NUM_CONSTRAINTS, NUM_WITNESS + NUM_PUBLIC)
        );

        assert_eq!(ccs_shape.cSs.len(), 2);
        assert_eq!(ccs_shape.cSs[0], (Fr::ONE, vec![0, 1]));
        assert_eq!(ccs_shape.cSs[1], (Fr::ONE.neg(), vec![2]));

        Ok(())
    }

    #[test]
    fn zero_instance_is_satisfied() -> Result<(), Error> {
        #[rustfmt::skip]
        let a = {
            let a: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            to_field_sparse::<G>(a)
        };

        const NUM_CONSTRAINTS: usize = 3;
        const NUM_WITNESS: usize = 1;
        const NUM_PUBLIC: usize = 2;

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &a, &a).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X)?;

        ccs_shape.is_satisfied(&instance, &witness, &ck)?;
        Ok(())
    }

    #[test]
    fn is_satisfied() -> Result<(), Error> {
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X)?;

        ccs_shape.is_satisfied(&instance, &witness, &ck)?;

        // Change commitment.
        let invalid_commitment = commitment_W + commitment_W;
        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &invalid_commitment, &X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let invalid_witness = CCSWitness::<G>::new(&ccs_shape, &invalid_W)?;
        let commitment_invalid_W = invalid_witness.commit::<Z>(&ck);

        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_invalid_W, &X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &invalid_witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &invalid_X)?;
        assert_eq!(
            ccs_shape.is_satisfied(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );
        Ok(())
    }

    #[test]
    fn zero_instance_is_satisfied_linearized() -> Result<(), Error> {
        #[rustfmt::skip]
        let a = {
            let a: &[&[u64]] = &[
                &[1, 2, 3],
                &[3, 4, 5],
                &[6, 7, 8],
            ];
            to_field_sparse::<G>(a)
        };

        const NUM_CONSTRAINTS: usize = 3;
        const NUM_WITNESS: usize = 1;
        const NUM_PUBLIC: usize = 2;

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &a, &a).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(2, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 2);

        let X = to_field_elements::<G>(&[0, 0]);
        let W = to_field_elements::<G>(&[0]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let s = safe_loglike!(NUM_CONSTRAINTS);
        let rs: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let z = [X.as_slice(), W.as_slice()].concat();
        let vs: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<G>(rs.as_slice()))
            .collect();

        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X, &rs, &vs)?;

        ccs_shape.is_satisfied_linearized::<Z>(&instance, &witness, &ck)?;

        Ok(())
    }

    #[test]
    fn is_satisfied_linearized() -> Result<(), Error> {
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let witness = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = witness.commit::<Z>(&ck);

        let s = safe_loglike!(NUM_CONSTRAINTS);
        let rs: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let z = [X.as_slice(), W.as_slice()].concat();
        let vs: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<G>(rs.as_slice()))
            .collect();

        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X, &rs, &vs)?;

        ccs_shape.is_satisfied_linearized::<Z>(&instance, &witness, &ck)?;

        // Change commitment.
        let invalid_commitment = commitment_W + commitment_W;
        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &invalid_commitment, &X, &rs, &vs)?;
        assert_eq!(
            ccs_shape.is_satisfied_linearized(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid witness.
        let invalid_W = to_field_elements::<G>(&[4, 9, 27, 30]);
        let invalid_witness = CCSWitness::<G>::new(&ccs_shape, &invalid_W)?;
        let commitment_invalid_W = invalid_witness.commit::<Z>(&ck);

        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_invalid_W, &X, &rs, &vs)?;
        assert_eq!(
            ccs_shape.is_satisfied_linearized(&instance, &invalid_witness, &ck),
            Err(Error::NotSatisfied)
        );

        // Provide invalid public input.
        let invalid_X = to_field_elements::<G>(&[1, 36]);
        let instance = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &invalid_X, &rs, &vs)?;
        assert_eq!(
            ccs_shape.is_satisfied_linearized(&instance, &witness, &ck),
            Err(Error::NotSatisfied)
        );

        Ok(())
    }

    #[test]
    fn folded_instance_is_satisfied() -> Result<(), Error> {
        // Fold linearized and non-linearized instances together and verify that resulting
        // linearized instance is satisfied.
        let (a, b, c) = {
            (
                to_field_sparse::<G>(A),
                to_field_sparse::<G>(B),
                to_field_sparse::<G>(C),
            )
        };

        const NUM_CONSTRAINTS: usize = 4;
        const NUM_WITNESS: usize = 4;
        const NUM_PUBLIC: usize = 2;

        let rho: Fr = Fr::from(11);

        let r1cs_shape: R1CSShape<G> =
            R1CSShape::<G>::new(NUM_CONSTRAINTS, NUM_WITNESS, NUM_PUBLIC, &a, &b, &c).unwrap();

        let ccs_shape = CCSShape::from(r1cs_shape);

        let mut rng = test_rng();
        let SRS = Z::setup(3, b"test", &mut rng).unwrap();
        let PCSKeys { ck, .. } = Z::trim(&SRS, 3);

        let X = to_field_elements::<G>(&[1, 35]);
        let W = to_field_elements::<G>(&[3, 9, 27, 30]);
        let W2 = CCSWitness::<G>::new(&ccs_shape, &W)?;

        let commitment_W = W2.commit::<Z>(&ck);

        let U2 = CCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X)?;

        let s = safe_loglike!(NUM_CONSTRAINTS);
        let rs1: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let z1 = [X.as_slice(), W.as_slice()].concat();
        let vs1: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z1).as_slice()).evaluate::<G>(rs1.as_slice()))
            .collect();

        let U1 = LCCSInstance::<G, Z>::new(&ccs_shape, &commitment_W, &X, &rs1, &vs1)?;
        let W1 = W2.clone();

        let z2 = z1.clone();
        let rs2: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();

        let sigmas: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z1).as_slice()).evaluate::<G>(rs2.as_slice()))
            .collect();

        let thetas: Vec<Fr> = ark_std::cfg_iter!(&ccs_shape.Ms)
            .map(|M| vec_to_mle(M.multiply_vec(&z2).as_slice()).evaluate::<G>(rs2.as_slice()))
            .collect();

        let folded_instance = U1.fold(&U2, &rho, &rs2, &sigmas, &thetas)?;

        let witness = W1.fold(&W2, &rho)?;

        ccs_shape.is_satisfied_linearized(&folded_instance, &witness, &ck)?;
        Ok(())
    }
}
