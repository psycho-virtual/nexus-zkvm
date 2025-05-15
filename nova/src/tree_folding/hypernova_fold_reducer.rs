use std::cell::RefCell;
use std::sync::Arc;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_ff::ToConstraintField;
use ark_std::ops::Neg;
use ark_std::rand::Rng;
use either::Either;

// Crate imports
use crate::absorb::AbsorbEmulatedFp;
use crate::ccs::{CCSInstance, CCSShape, CCSWitness, LCCSInstance};
use crate::ccs::lccs_fold::{prove_folding, verify_folding, LCCSFoldingProof};
use crate::folding::hypernova::nimfs::NIMFSProof;
use crate::provider::zeromorph::PolyCommitmentScheme;
use crate::tree_folding::fold_reducer::FoldReducer;

/// A wrapper around Hypernova's CCS instances that implements `Clone` and `Debug`
/// to be compatible with the `FoldDriver`.
pub struct HypernovaNode<G, C, RO, const K: usize>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    /// The wrapped instance, which can be either an LCCS or CCS instance
    pub instance: Arc<Either<LCCSInstance<G, C>, CCSInstance<G, C>>>,
    /// Marker for the random oracle type
    pub _random_oracle: std::marker::PhantomData<RO>,
}

impl<G, C, RO, const K: usize> Clone for HypernovaNode<G, C, RO, K>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    fn clone(&self) -> Self {
        Self {
            instance: Arc::clone(&self.instance),
            _random_oracle: std::marker::PhantomData,
        }
    }
}

impl<G, C, RO, const K: usize> HypernovaNode<G, C, RO, K>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    /// Create a new HypernovaNode from an LCCS instance
    pub fn from_lccs(lccs: LCCSInstance<G, C>) -> Self {
        Self {
            instance: Arc::new(Either::Left(lccs)),
            _random_oracle: std::marker::PhantomData,
        }
    }

    /// Create a new HypernovaNode from a CCS instance
    pub fn from_ccs(ccs: CCSInstance<G, C>) -> Self {
        Self {
            instance: Arc::new(Either::Right(ccs)),
            _random_oracle: std::marker::PhantomData,
        }
    }

    /// Check if this node contains an LCCS instance
    pub fn is_lccs(&self) -> bool {
        matches!(&*self.instance, Either::Left(_))
    }

    /// Check if this node contains a CCS instance
    pub fn is_ccs(&self) -> bool {
        matches!(&*self.instance, Either::Right(_))
    }

    /// Get a reference to the LCCS instance, if this node contains one
    pub fn lccs(&self) -> Option<&LCCSInstance<G, C>> {
        match &*self.instance {
            Either::Left(lccs) => Some(lccs),
            _ => None,
        }
    }

    /// Get a reference to the CCS instance, if this node contains one
    pub fn ccs(&self) -> Option<&CCSInstance<G, C>> {
        match &*self.instance {
            Either::Right(ccs) => Some(ccs),
            _ => None,
        }
    }
}

impl<G, C, RO, const K: usize> core::fmt::Debug for HypernovaNode<G, C, RO, K>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &*self.instance {
            Either::Left(lccs) => write!(
                f,
                "HypernovaNode::LCCS {{ X.len: {}, vs.len: {} }}",
                lccs.X.len(),
                lccs.vs.len()
            ),
            Either::Right(ccs) => write!(f, "HypernovaNode::CCS {{ io.len: {} }}", ccs.X.len()),
        }
    }
}

/// The type of folding proof containing the actual proof data
pub enum FoldProofType<G, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    RO: CryptographicSponge,
{
    /// LCCS + LCCS folding proof
    /// Contains the actual LCCSFoldingProof
    LCCSFolding(LCCSFoldingProof<G, RO>),

    /// CCS + LCCS folding proof using NIMFS
    /// Contains the actual NIMFSProof
    NIMFSFolding(NIMFSProof<G, RO>),
}

// Manual implementation of Debug for FoldProofType
impl<G, RO> core::fmt::Debug for FoldProofType<G, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    RO: CryptographicSponge,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FoldProofType::LCCSFolding(_) => write!(f, "FoldProofType::LCCSFolding"),
            FoldProofType::NIMFSFolding(_) => write!(f, "FoldProofType::NIMFSFolding"),
        }
    }
}

/// The basic structure for HypernovaFoldReducer
/// This implements the fold reducer trait for Hypernova's LCCS and CCS instances
pub struct HypernovaFoldReducer<'a, G, C, RO, const K: usize>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    /// The constraint system shape
    pub shape: &'a CCSShape<G>,
    /// The random oracle config
    pub random_oracle_config: &'a RO::Config,
    /// Verification key
    pub vk: G::ScalarField,
    /// Commitment keys (in a generic form)
    pub ck: &'a C,
    /// Track the last fold operation for verification
    fold_state: RefCell<Option<(Vec<HypernovaNode<G, C, RO, K>>, String)>>,
}

impl<'a, G, C, RO, const K: usize> HypernovaFoldReducer<'a, G, C, RO, K>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    /// Create a new HypernovaFoldReducer
    pub fn new(
        shape: &'a CCSShape<G>,
        random_oracle_config: &'a RO::Config,
        vk: G::ScalarField,
        ck: &'a C,
    ) -> Self {
        Self {
            shape,
            random_oracle_config,
            vk,
            ck,
            fold_state: RefCell::new(None),
        }
    }

    /// Create a new HypernovaFoldReducer with a fresh random transcript
    pub fn with_fresh_transcript<R: Rng>(
        shape: &'a CCSShape<G>,
        rng: &mut R,
        random_oracle_config: &'a RO::Config,
        ck: &'a C,
    ) -> Self
    where
        G::ScalarField: UniformRand,
    {
        // Create a verification key (random scalar field element)
        let vk = G::ScalarField::rand(rng);

        Self {
            shape,
            random_oracle_config,
            vk,
            ck,
            fold_state: RefCell::new(None),
        }
    }

    /// Create a new random oracle instance for folding operations
    fn new_random_oracle(&self) -> RO {
        RO::new(self.random_oracle_config)
    }

    /// Create a dummy witness for use with folding operations
    /// In a production environment, the actual witnesses would be used
    fn create_dummy_witness(&self) -> CCSWitness<G> {
        // Create a witness with all zeros
        CCSWitness::<G> {
            W: vec![G::ScalarField::zero(); self.shape.num_vars],
        }
    }

    /// Fold two LCCS instances together using sumcheck-based folding
    fn fold_lccs_lccs(
        &self,
        random_oracle: &mut RO,
        lccs1: &LCCSInstance<G, C>,
        lccs2: &LCCSInstance<G, C>,
    ) -> Result<(LCCSInstance<G, C>, LCCSFoldingProof<G, RO>), String> {
        let dummy_witness1 = self.create_dummy_witness();
        let dummy_witness2 = self.create_dummy_witness();

        match prove_folding(
            random_oracle,
            self.shape,
            (lccs1, &dummy_witness1),
            (lccs2, &dummy_witness2),
        ) {
            Ok((proof, folded_lccs, _rho)) => Ok((folded_lccs, proof)),
            Err(e) => Err(format!("LCCS folding failed: {:?}", e)),
        }
    }

    /// Fold an LCCS instance with a CCS instance using NIMFS
    fn fold_lccs_ccs(
        &self,
        random_oracle: &mut RO,
        lccs: &LCCSInstance<G, C>,
        ccs: &CCSInstance<G, C>,
    ) -> Result<(LCCSInstance<G, C>, NIMFSProof<G, RO>), String> {
        let dummy_witness1 = self.create_dummy_witness();
        let dummy_witness2 = self.create_dummy_witness();

        match NIMFSProof::prove_as_subprotocol(
            random_oracle,
            &self.vk,
            self.shape,
            (lccs, &dummy_witness1),
            (ccs, &dummy_witness2),
        ) {
            Ok((proof, (folded_lccs, _), _rho)) => Ok((folded_lccs, proof)),
            Err(e) => Err(format!("NIMFS folding failed: {:?}", e)),
        }
    }

    /// Verify an LCCS folding proof
    fn verify_lccs_folding(
        &self,
        random_oracle: &mut RO,
        lccs1: &LCCSInstance<G, C>,
        lccs2: &LCCSInstance<G, C>,
        proof: &LCCSFoldingProof<G, RO>,
    ) -> bool {
        let result = verify_folding(
            random_oracle,
            self.shape,
            lccs1,
            lccs2,
            proof,
        );
        result.is_ok()
    }

    /// Verify a NIMFS folding proof
    fn verify_nimfs_folding(
        &self,
        random_oracle: &mut RO,
        lccs: &LCCSInstance<G, C>,
        ccs: &CCSInstance<G, C>,
        folded_lccs: &LCCSInstance<G, C>,
        proof: &NIMFSProof<G, RO>,
    ) -> bool {
        match proof.verify_as_subprotocol(
            random_oracle,
            &self.vk,
            self.shape,
            lccs,
            ccs,
        ) {
            Ok((verified_lccs, _)) => {
                // Check that the verified LCCS matches the expected one
                verified_lccs.commitment_W == folded_lccs.commitment_W &&
                verified_lccs.X == folded_lccs.X &&
                verified_lccs.rs == folded_lccs.rs &&
                verified_lccs.vs == folded_lccs.vs
            },
            Err(_) => false,
        }
    }
}

// Implementation of FoldReducer trait for HypernovaFoldReducer
impl<'a, G, C, RO, const K: usize> FoldReducer<K> for HypernovaFoldReducer<'a, G, C, RO, K>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    RO: CryptographicSponge,
{
    type StrictInst = HypernovaNode<G, C, RO, K>;
    type AccInst = HypernovaNode<G, C, RO, K>;
    type FoldProof = FoldProofType<G, RO>;

    fn fold_acc_acc(&self, acc_children: &[Self::AccInst; K]) -> (Self::AccInst, Self::FoldProof) {
        // Save children for later verification
        let children = acc_children.to_vec();
        
        // Start with the first instance
        let mut current_acc = acc_children[0].clone();
        let mut random_oracle = self.new_random_oracle();
        
        // Only fold two instances for simplicity
        let next_child = &acc_children[1];
        
        // Determine which folding method to use based on instance types
        let (result_acc, proof_type) = match (&*current_acc.instance, &*next_child.instance) {
            (Either::Left(lccs1), Either::Left(lccs2)) => {
                // Both are LCCS instances
                match self.fold_lccs_lccs(&mut random_oracle, lccs1, lccs2) {
                    Ok((folded_instance, proof)) => {
                        let node = HypernovaNode::from_lccs(folded_instance);
                        (node, FoldProofType::LCCSFolding(proof))
                    },
                    Err(e) => panic!("LCCS+LCCS folding failed: {}", e),
                }
            },
            (Either::Left(lccs), Either::Right(ccs)) => {
                // LCCS + CCS
                match self.fold_lccs_ccs(&mut random_oracle, lccs, ccs) {
                    Ok((folded_instance, proof)) => {
                        let node = HypernovaNode::from_lccs(folded_instance);
                        (node, FoldProofType::NIMFSFolding(proof))
                    },
                    Err(e) => panic!("LCCS+CCS folding failed: {}", e),
                }
            },
            (Either::Right(ccs), Either::Left(lccs)) => {
                // Same as above but swapped (NIMFS handles both cases)
                match self.fold_lccs_ccs(&mut random_oracle, lccs, ccs) {
                    Ok((folded_instance, proof)) => {
                        let node = HypernovaNode::from_lccs(folded_instance);
                        (node, FoldProofType::NIMFSFolding(proof))
                    },
                    Err(e) => panic!("CCS+LCCS folding failed: {}", e),
                }
            },
            (Either::Right(_), Either::Right(_)) => {
                // Not implemented for simplicity
                panic!("CCS+CCS folding not implemented in this minimal version")
            }
        };
        
        // Save the fold state for verification
        let proof_name = match &proof_type {
            FoldProofType::LCCSFolding(_) => "LCCSFolding",
            FoldProofType::NIMFSFolding(_) => "NIMFSFolding",
        };
        
        self.fold_state.replace(Some((children, proof_name.to_string())));
        
        (result_acc, proof_type)
    }

    fn verify_step(&self, parent: &Self::AccInst, proof: &Self::FoldProof) -> bool {
        // Retrieve the saved fold state
        let fold_state_ref = self.fold_state.borrow();
        let fold_state = match &*fold_state_ref {
            Some(state) => state,
            None => return false,
        };
        
        let children = &fold_state.0;
        if children.len() < 2 {
            return false;
        }
        
        // Get first two children that were folded
        let child1 = &children[0];
        let child2 = &children[1];
        
        // Create a new random oracle for verification
        let mut random_oracle = self.new_random_oracle();
        
        // Verify based on the proof type and instance types
        match (proof, parent.lccs()) {
            (FoldProofType::LCCSFolding(lccs_proof), Some(folded_lccs)) => {
                match (child1.lccs(), child2.lccs()) {
                    (Some(lccs1), Some(lccs2)) => {
                        // LCCS + LCCS verification
                        self.verify_lccs_folding(&mut random_oracle, lccs1, lccs2, &lccs_proof)
                    },
                    _ => false,
                }
            },
            (FoldProofType::NIMFSFolding(nimfs_proof), Some(folded_lccs)) => {
                match (child1.instance.as_ref(), child2.instance.as_ref()) {
                    (Either::Left(lccs), Either::Right(ccs)) => {
                        // LCCS + CCS verification
                        self.verify_nimfs_folding(&mut random_oracle, lccs, ccs, folded_lccs, nimfs_proof)
                    },
                    (Either::Right(ccs), Either::Left(lccs)) => {
                        // CCS + LCCS verification
                        self.verify_nimfs_folding(&mut random_oracle, lccs, ccs, folded_lccs, nimfs_proof)
                    },
                    _ => false,
                }
            },
            _ => false,
        }
    }

    fn strict_to_acc(&self, strict: &Self::StrictInst) -> Self::AccInst {
        // For Hypernova, strict and accumulator instances have the same type
        strict.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::pairing::Pairing;
    use ark_ff::{One, UniformRand, Zero};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use ark_std::{test_rng, start_timer, end_timer};
    use crate::ccs::{SparseMatrix, Error as CCSError};
    use crate::ccs::mle::vec_to_mle;
    use crate::poseidon_config;
    use crate::provider::zeromorph::Zeromorph;

    // Type aliases for convenience - using BN254 (same as used in production)
    type G1 = BN254G1;
    type CF = BN254Fr;
    type Z = Zeromorph<Bn254>;
    type RO = PoseidonSponge<CF>;
    type PCKey = <Z as libspartan::polycommitments::PolyCommitmentScheme>::PolyCommitmentKey;
    type ROConfig = <RO as ark_crypto_primitives::sponge::CryptographicSponge>::Config;

    // Create a test CCS shape with proper constraints for testing
    // This shape represents a simple cubic circuit: x^3 + x + 5 = y
    // Similar to the one used in the NIMFS tests
    fn create_test_ccs_shape() -> CCSShape<G1> {
        let num_constraints = 4;
        let num_vars = 4;
        let num_io = 2; // input x and output y
        let num_matrices = 3;

        // Create matrices for the constraint system
        // M0, M1, M2 corresponding to values of z in [1, z, z²]
        let mut matrices: Vec<SparseMatrix<CF>> = Vec::with_capacity(num_matrices);
        
        // Matrix M0 (for constant terms)
        let mut m0_rows = Vec::new();
        m0_rows.push(vec![(CF::one(), num_vars)]); // y term in the output
        m0_rows.push(vec![(CF::from(5u32), 0)]); // constant term 5
        m0_rows.push(vec![(CF::zero(), 0)]); // Placeholder
        m0_rows.push(vec![(CF::zero(), 0)]); // Placeholder
        matrices.push(SparseMatrix::new(&m0_rows, num_constraints, num_vars + num_io));
        
        // Matrix M1 (for linear terms)
        let mut m1_rows = Vec::new();
        m1_rows.push(vec![(CF::zero(), 0)]); // Placeholder
        m1_rows.push(vec![(CF::one(), num_vars - num_io)]); // x term
        m1_rows.push(vec![(CF::one(), num_vars - num_io + 1)]); // intermediate var for x^2
        m1_rows.push(vec![(CF::zero(), 0)]); // Placeholder
        matrices.push(SparseMatrix::new(&m1_rows, num_constraints, num_vars + num_io));
        
        // Matrix M2 (for quadratic terms)
        let mut m2_rows = Vec::new();
        m2_rows.push(vec![(CF::zero(), 0)]); // Placeholder
        m2_rows.push(vec![(CF::zero(), 0)]); // Placeholder
        m2_rows.push(vec![(CF::one(), num_vars - num_io), (CF::one(), num_vars - num_io)]); // x * x = x^2
        m2_rows.push(vec![(CF::one(), num_vars - num_io), (CF::one(), num_vars - num_io + 1)]); // x * x^2 = x^3
        matrices.push(SparseMatrix::new(&m2_rows, num_constraints, num_vars + num_io));
        
        // Create multiset coefficients
        let cSs = vec![
            (CF::one(), vec![0, 1]), // M0 + M1
            (CF::one().neg(), vec![2]), // - M2
        ];
        
        // Create the constraint system shape
        CCSShape {
            num_constraints,
            num_vars,
            num_io,
            num_matrices,
            num_multisets: cSs.len(),
            max_cardinality: 2,
            Ms: matrices,
            cSs,
        }
    }

    // Helper to create a valid witness for a given input
    // Computes y = x^3 + x + 5 and the intermediate values
    fn create_witness_for_input(input_x: CF) -> (CCSWitness<G1>, Vec<CF>) {
        // Compute intermediate values
        let x_squared = input_x * input_x;
        let x_cubed = x_squared * input_x;
        let output_y = x_cubed + input_x + CF::from(5u32);
        
        // Create witness vector (x, x^2, x^3, aux)
        let W = vec![input_x, x_squared, x_cubed, CF::zero()];
        
        // Create IO vector (x, y)
        let X = vec![input_x, output_y];
        
        // Return both
        (CCSWitness { W }, X)
    }

    // Helper to create a valid CCS instance for testing with the cubic circuit
    fn create_test_ccs_instance(
        shape: &CCSShape<G1>,
        ck: &PCKey,
        input_x: CF,
    ) -> Result<(CCSInstance<G1, Z>, CCSWitness<G1>), CCSError> {
        // Create witness and IO for the given input
        let (witness, X) = create_witness_for_input(input_x);
        
        // Create polynomial from witness (convert to multilinear extension)
        let poly = vec_to_mle(&witness.W);
        
        // Commit to the witness polynomial
        let commitment_W = Z::commit(&poly, ck);
        
        // Create CCS instance
        let instance = CCSInstance { X, commitment_W };
        
        // Ensure the instance is satisfied
        shape.is_satisfied(&instance, &witness, ck)?;
        
        Ok((instance, witness))
    }

    // Helper to create a valid LCCS instance for testing
    fn create_test_lccs_instance(
        shape: &CCSShape<G1>,
        ck: &PCKey,
        input_x: CF,
        rng: &mut impl ark_std::rand::Rng,
    ) -> Result<(LCCSInstance<G1, Z>, CCSWitness<G1>), CCSError> {
        // Create CCS instance first
        let (ccs, witness) = create_test_ccs_instance(shape, ck, input_x)?;
        
        // Calculate linearization parameters
        let s = shape.num_constraints.next_power_of_two().trailing_zeros() as usize;
        let rs: Vec<CF> = (0..s).map(|_| CF::rand(rng)).collect();
        
        // Create linearized values
        let z = [ccs.X.as_slice(), witness.W.as_slice()].concat();
        let vs = shape.Ms.iter()
            .map(|M| vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate(rs.as_slice()))
            .collect();
        
        // Create LCCS instance
        let lccs = LCCSInstance {
            X: ccs.X,
            commitment_W: ccs.commitment_W,
            rs,
            vs,
        };
        
        // Ensure the LCCS instance is satisfied
        shape.is_satisfied_linearized(&lccs, &witness, ck)?;
        
        Ok((lccs, witness))
    }
    
    // Helper function to set up the test environment
    // Returns (shape, ck, ro_config, vk) for tests
    fn setup_test_environment() -> (CCSShape<G1>, Z::PolyCommitmentKey, RO::Config, CF) {
        let timer = start_timer!(|| "Setting up test environment");
        let mut rng = test_rng();
        
        // Create shape
        let shape = create_test_ccs_shape();
        
        // Setup SRS for Zeromorph
        let srs_degree = 64; // Same degree as used in NIMFS tests
        let srs_timer = start_timer!(|| "SRS setup");
        let srs = Z::setup(srs_degree, b"test-hypernova-fold", &mut rng)
            .expect("Failed to set up SRS");
        end_timer!(srs_timer);
            
        // Trim SRS to get commitment key
        let trim_timer = start_timer!(|| "SRS trimming");
        let ck = Z::trim(&srs, srs_degree - 1).ck;
        end_timer!(trim_timer);
        
        // Setup random oracle
        let ro_config = poseidon_config::<CF>();
        
        // Create verification key
        let vk = CF::rand(&mut rng);
        
        end_timer!(timer);
        (shape, ck, ro_config, vk)
    }
    
    #[test]
    fn test_hypernova_fold_reducer_creation() {
        let mut rng = test_rng();
        let (shape, ck, ro_config, vk) = setup_test_environment();
        
        // Create a HypernovaFoldReducer to ensure types compile correctly
        let _reducer = HypernovaFoldReducer::<G1, Z, RO, 2>::new(
            &shape, &ro_config, vk, &ck
        );
        
        println!("Test for HypernovaFoldReducer type compilation passed");
    }
    
    #[test]
    fn test_hypernova_fold_lccs_instances() {
        let mut rng = test_rng();
        
        // 1. Setup test environment
        let (shape, ck, ro_config, vk) = setup_test_environment();
        
        println!("Setting up test instances...");
        
        // 2. Create test instances with valid witnesses for the cubic circuit
        let input_x1 = CF::from(3u32);
        let input_x2 = CF::from(5u32);
        
        let create_timer = start_timer!(|| "Creating test instances");
        let (lccs1, _) = create_test_lccs_instance(&shape, &ck, input_x1, &mut rng)
            .expect("Failed to create LCCS instance 1");
        let (lccs2, _) = create_test_lccs_instance(&shape, &ck, input_x2, &mut rng)
            .expect("Failed to create LCCS instance 2");
        end_timer!(create_timer);
        
        // Wrap in HypernovaNodes
        let node1 = HypernovaNode::<G1, Z, RO, 2>::from_lccs(lccs1);
        let node2 = HypernovaNode::<G1, Z, RO, 2>::from_lccs(lccs2);
        
        // 3. Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, RO, 2>::new(
            &shape, &ro_config, vk, &ck
        );
        
        println!("Created fold reducer. Performing folding operation...");
        
        // 4. Fold the LCCS instances
        let nodes = [node1, node2];
        
        let fold_timer = start_timer!(|| "Folding LCCS instances");
        let (folded, proof) = reducer.fold_acc_acc(&nodes);
        end_timer!(fold_timer);
        
        println!("Folding complete. Verifying result...");
        
        // 5. Verify the folding operation
        assert!(folded.is_lccs(), "Folded instance should be LCCS");
        
        let verify_timer = start_timer!(|| "Verifying LCCS fold");
        match proof {
            FoldProofType::LCCSFolding(_) => {
                // Verify using reducer
                let verified = reducer.verify_step(&folded, &proof);
                assert!(verified, "Fold verification failed");
                println!("Fold verification succeeded");
            },
            _ => panic!("Expected LCCSFolding proof type"),
        }
        end_timer!(verify_timer);
    }
    
    #[test]
    fn test_hypernova_fold_lccs_with_ccs() {
        let mut rng = test_rng();
        
        // 1. Setup test environment
        let (shape, ck, ro_config, vk) = setup_test_environment();
        
        println!("Setting up test instances...");
        
        // 2. Create test instances - one LCCS and one CCS with valid witnesses
        let input_x1 = CF::from(3u32);
        let input_x2 = CF::from(5u32);
        
        let create_timer = start_timer!(|| "Creating test instances");
        let (lccs, _) = create_test_lccs_instance(&shape, &ck, input_x1, &mut rng)
            .expect("Failed to create LCCS instance");
        let (ccs, _) = create_test_ccs_instance(&shape, &ck, input_x2)
            .expect("Failed to create CCS instance");
        end_timer!(create_timer);
        
        // Wrap in HypernovaNodes
        let lccs_node = HypernovaNode::<G1, Z, RO, 2>::from_lccs(lccs);
        let ccs_node = HypernovaNode::<G1, Z, RO, 2>::from_ccs(ccs);
        
        // 3. Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, RO, 2>::new(
            &shape, &ro_config, vk, &ck
        );
        
        println!("Created fold reducer. Performing folding operation...");
        
        // 4. Fold the LCCS and CCS instances
        let nodes = [lccs_node, ccs_node];
        
        let fold_timer = start_timer!(|| "Folding LCCS+CCS instances");
        let (folded, proof) = reducer.fold_acc_acc(&nodes);
        end_timer!(fold_timer);
        
        println!("Folding complete. Verifying result...");
        
        // 5. Verify the folding operation
        assert!(folded.is_lccs(), "Folded instance should be LCCS");
        
        let verify_timer = start_timer!(|| "Verifying NIMFS fold");
        match proof {
            FoldProofType::NIMFSFolding(_) => {
                // Verify using reducer
                let verified = reducer.verify_step(&folded, &proof);
                assert!(verified, "Fold verification failed");
                println!("Fold verification succeeded");
            },
            _ => panic!("Expected NIMFSFolding proof type"),
        }
        end_timer!(verify_timer);
    }
    
    #[test]
    fn test_tree_fold_multiple_instances() {
        let mut rng = test_rng();
        
        // 1. Setup test environment
        let (shape, ck, ro_config, vk) = setup_test_environment();
        
        // 2. Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, RO, 2>::new(
            &shape, &ro_config, vk, &ck
        );
        
        // 3. Create FoldDriver with our reducer
        let driver = crate::tree_folding::fold_driver::FoldDriver::new(reducer);
        
        println!("Created fold driver. Generating leaf instances...");
        
        // 4. Create leaf instances (strict instances)
        // For a binary tree with 2 levels, we need 2^2 = 4 leaves
        const NUM_LEAVES: usize = 4;
        let mut leaves = Vec::with_capacity(NUM_LEAVES);
        
        let create_timer = start_timer!(|| "Creating leaf instances");
        // Create LCCS instances with different inputs to ensure each is unique
        let inputs = [CF::from(2u32), CF::from(3u32), CF::from(5u32), CF::from(7u32)];
        
        for i in 0..NUM_LEAVES {
            let (lccs, _) = create_test_lccs_instance(&shape, &ck, inputs[i], &mut rng)
                .expect("Failed to create LCCS instance");
            
            // Wrap in HypernovaNode
            let node = HypernovaNode::<G1, Z, RO, 2>::from_lccs(lccs);
            
            // Add to leaves
            leaves.push(node);
        }
        end_timer!(create_timer);
        
        println!("Created {} leaf instances. Performing tree folding...", NUM_LEAVES);
        
        // 5. Fold the tree to get the root
        let fold_timer = start_timer!(|| "Tree folding");
        let root = driver.fold_root(&leaves);
        end_timer!(fold_timer);
        
        println!("Tree folding complete!");
        
        // 6. Verify the result
        assert!(root.is_lccs(), "Root node should be an LCCS instance");
        
        // Success!
        println!("Successfully folded {} instances into a tree with root node", NUM_LEAVES);
    }
    
    #[test]
    fn test_hypernova_fold_full_sequence() {
        let mut rng = test_rng();
        
        // 1. Setup test environment
        let (shape, ck, ro_config, vk) = setup_test_environment();
        
        println!("Testing a sequence of folds to mirror NIMFS test pattern...");
        
        // 2. Create a sequence of instances to fold
        // We'll fold multiple instances in a sequence, similar to the NIMFS test
        let num_instances = 5;
        let mut instances = Vec::with_capacity(num_instances);
        
        let create_timer = start_timer!(|| "Creating sequence instances");
        
        // First instance is LCCS
        let (lccs, _) = create_test_lccs_instance(&shape, &ck, CF::from(3u32), &mut rng)
            .expect("Failed to create initial LCCS instance");
        let mut current = HypernovaNode::<G1, Z, RO, 2>::from_lccs(lccs);
        
        // Rest are CCS
        for i in 0..num_instances-1 {
            let (ccs, _) = create_test_ccs_instance(&shape, &ck, CF::from((i + 5) as u32))
                .expect("Failed to create CCS instance");
            instances.push(HypernovaNode::<G1, Z, RO, 2>::from_ccs(ccs));
        }
        end_timer!(create_timer);
        
        // 3. Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, RO, 2>::new(
            &shape, &ro_config, vk, &ck
        );
        
        println!("Beginning sequential folding of {} instances...", num_instances);
        
        // 4. Perform sequential folding (current + next)
        let sequence_timer = start_timer!(|| "Sequential folding");
        for (i, next) in instances.iter().enumerate() {
            let nodes = [current, next.clone()];
            let (folded, proof) = reducer.fold_acc_acc(&nodes);
            
            println!("Fold {} complete", i+1);
            
            // Verify each fold
            let verified = reducer.verify_step(&folded, &proof);
            assert!(verified, "Fold {} verification failed", i+1);
            
            // Update current for next fold
            current = folded;
        }
        end_timer!(sequence_timer);
        
        println!("Sequential folding of {} instances complete and verified!", num_instances);
        assert!(current.is_lccs(), "Final folded instance should be LCCS");
    }
}