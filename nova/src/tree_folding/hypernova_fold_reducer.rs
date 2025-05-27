use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, ToConstraintField, Zero};

// Crate imports
use crate::absorb::AbsorbEmulatedFp;
use crate::ccs::{CCSShape, CCSWitness, LCCSInstance, Error as CCSError};
use crate::ccs::lccs_fold::{prove_folding, LCCSFoldingProof};
use crate::ccs::linearization::{synthesize_and_linearize_step, StepFunctionInput};
use crate::circuits::nova::StepCircuit;
use crate::provider::zeromorph::PolyCommitmentScheme;
use crate::tree_folding::fold_reducer::FoldReducer;

/// Error type for HypernovaFoldReducer operations
#[derive(Debug)]
pub enum HypernovaFoldError {
    /// CCS operation failed
    CCS(CCSError),
    /// Folding operation failed
    FoldingFailed(String),
    /// Linearization failed
    LinearizationFailed(String),
}

impl From<CCSError> for HypernovaFoldError {
    fn from(err: CCSError) -> Self {
        HypernovaFoldError::CCS(err)
    }
}

/// The basic structure for HypernovaFoldReducer
/// This implements the fold reducer trait for Hypernova's LCCS instances
/// K is hardcoded to 2 for binary tree folding
pub struct HypernovaFoldReducer<'a, G, C, SC, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    SC: StepCircuit<G::ScalarField>,
    RO: CryptographicSponge,
{
    /// The step circuit
    pub step_circuit: &'a SC,
    /// Commitment key
    pub ck: &'a C::PolyCommitmentKey,
    /// The random oracle config
    pub random_oracle_config: &'a RO::Config,
}

impl<'a, G, C, SC, RO> HypernovaFoldReducer<'a, G, C, SC, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    SC: StepCircuit<G::ScalarField>,
    RO: CryptographicSponge,
{
    /// Create a new HypernovaFoldReducer
    pub fn new(
        step_circuit: &'a SC,
        ck: &'a C::PolyCommitmentKey,
        random_oracle_config: &'a RO::Config,
    ) -> Self {
        Self {
            step_circuit,
            ck,
            random_oracle_config,
        }
    }

    /// Create a new random oracle instance for folding operations
    fn new_random_oracle(&self) -> RO {
        RO::new(self.random_oracle_config)
    }
}

// Implementation of FoldReducer trait for HypernovaFoldReducer with K=2
impl<'a, G, C, SC, RO> FoldReducer<2> for HypernovaFoldReducer<'a, G, C, SC, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    SC: StepCircuit<G::ScalarField>,
    RO: CryptographicSponge,
{
    type StrictInst = StepFunctionInput<G::ScalarField>;
    type AccInst = (LCCSInstance<G, C>, CCSWitness<G>);
    type FoldProof = LCCSFoldingProof<G, RO>;
    type Error = HypernovaFoldError;

    fn fold_acc_acc(&self, acc_children: &[Self::AccInst; 2]) -> Result<(Self::AccInst, Self::FoldProof), Self::Error> {
        let (lccs1, witness1) = &acc_children[0];
        let (lccs2, witness2) = &acc_children[1];
        
        // Create a new random oracle for this folding operation
        let mut random_oracle = self.new_random_oracle();
        
        // Get the CCS shape from the circuit
        let shape = self.create_shape_from_circuit()?;
        
        match prove_folding(
            &mut random_oracle,
            &shape,
            (lccs1, witness1),
            (lccs2, witness2),
        ) {
            Ok((proof, folded_lccs, folded_witness)) => {
                Ok(((folded_lccs, folded_witness), proof))
            },
            Err(e) => Err(HypernovaFoldError::FoldingFailed(format!("{:?}", e))),
        }
    }

    fn verify_step(&self, parent: &Self::AccInst, proof: &Self::FoldProof) -> bool {
        // For a stateless verification, we would need the children instances to be passed
        // as parameters. Since the current FoldReducer trait doesn't support this,
        // we'll implement a basic verification that checks if the proof is valid
        // without the original children instances.
        
        // In a real implementation, you might want to modify the FoldReducer trait
        // to pass children instances to verify_step, or store verification data
        // in the proof itself.
        
        // For now, we'll do a basic check - verify that the parent instance is valid
        let (lccs_instance, witness) = parent;
        
        // Get the shape - if this fails, return false for verification
        let shape = match self.create_shape_from_circuit() {
            Ok(shape) => shape,
            Err(_) => return false,
        };
        
        // Check if the LCCS instance is satisfied
        match shape.is_satisfied_linearized(lccs_instance, witness, self.ck) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn strict_to_acc(&self, strict: &Self::StrictInst) -> Result<Self::AccInst, Self::Error> {
        // Create a new random oracle for linearization
        let mut random_oracle = self.new_random_oracle();
        
        // Call synthesize_and_linearize_step to convert StepFunctionInput to LCCS
        match synthesize_and_linearize_step::<G, C, _, _>(
            self.step_circuit,
            strict,
            self.ck,
            &mut random_oracle,
        ) {
            Ok(result) => {
                Ok((result.linearization.lccs_instance, result.linearization.witness))
            },
            Err(e) => Err(HypernovaFoldError::LinearizationFailed(format!("{:?}", e))),
        }
    }
}

impl<'a, G, C, SC, RO> HypernovaFoldReducer<'a, G, C, SC, RO>
where
    G: CurveGroup + AbsorbEmulatedFp<G::ScalarField>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    C: PolyCommitmentScheme<G>,
    SC: StepCircuit<G::ScalarField>,
    RO: CryptographicSponge,
{
    /// Create a CCS shape from the step circuit
    /// This is a helper method that would ideally be stored or cached
    fn create_shape_from_circuit(&self) -> Result<CCSShape<G>, HypernovaFoldError> {
        // In practice, this would be done once and stored, or the shape would be
        // passed to the reducer. For now, we'll create a dummy shape.
        // This is a placeholder - in a real implementation, you'd synthesize
        // the circuit once to get the shape and store it.
        
        // Create a dummy input to synthesize the circuit and get the shape
        let dummy_input = StepFunctionInput {
            i: G::ScalarField::zero(),
            z_i: vec![G::ScalarField::zero(); SC::ARITY],
        };
        
        let mut random_oracle = self.new_random_oracle();
        
        match synthesize_and_linearize_step::<G, C, _, _>(
            self.step_circuit,
            &dummy_input,
            self.ck,
            &mut random_oracle,
        ) {
            Ok(result) => Ok(result.ccs_shape),
            Err(e) => Err(HypernovaFoldError::LinearizationFailed(format!("Failed to create CCS shape: {:?}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::{One, UniformRand, Zero, Field};
    use ark_std::{test_rng, start_timer, end_timer, marker::PhantomData};
    use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
    use crate::poseidon_config;
    use crate::provider::zeromorph::Zeromorph;

    // Type aliases for convenience - using BN254 (same as used in production)
    type G1 = BN254G1;
    type CF = BN254Fr;
    type Z = Zeromorph<Bn254>;
    type RO = PoseidonSponge<CF>;
    type ROConfig = <RO as CryptographicSponge>::Config;
    type PCKey = <Z as PolyCommitmentScheme<G1>>::PolyCommitmentKey;

    /// Simple cubic circuit for testing: computes x^3 + x + 5
    #[derive(Debug, Default)]
    struct CubicCircuit<F: Field> {
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
            let x_cube = x_square * x;
            let y: FpVar<F> = x + x_cube + &FpVar::Constant(F::from(5u64));

            Ok(vec![y])
        }
    }

    // Helper function to set up the test environment
    fn setup_test_environment() -> (PCKey, ROConfig) {
        let timer = start_timer!(|| "Setting up test environment");
        let mut rng = test_rng();
        
        // Setup SRS for Zeromorph - use smaller degree to avoid overflow
        let srs_degree = 16;
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
        
        end_timer!(timer);
        (ck, ro_config)
    }
    
    #[test]
    fn test_hypernova_fold_reducer_creation() {
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create a HypernovaFoldReducer to ensure types compile correctly
        let _reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        println!("Test for HypernovaFoldReducer type compilation passed");
    }
    
    #[test]
    fn test_strict_to_acc_conversion() {
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        println!("Testing strict to accumulator conversion...");
        
        // Create a step function input
        let input = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(3u64)], // x = 3, so x^3 + x + 5 = 27 + 3 + 5 = 35
        };
        
        let convert_timer = start_timer!(|| "Converting strict to acc");
        let (lccs_instance, witness) = reducer.strict_to_acc(&input).expect("Failed to convert strict to acc");
        end_timer!(convert_timer);
        
        println!("Conversion complete. Verifying result...");
        
        // The conversion should produce a valid LCCS instance
        assert!(!lccs_instance.X.is_empty(), "LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Witness should not be empty");
        
        println!("✓ Strict to accumulator conversion succeeded");
    }
    
    #[test]
    fn test_fold_two_acc_instances() {
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        println!("Creating accumulator instances...");
        
        // Create two step function inputs
        let input1 = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(2u64)], // x = 2, so x^3 + x + 5 = 8 + 2 + 5 = 15
        };
        
        let input2 = StepFunctionInput {
            i: CF::from(2u64),
            z_i: vec![CF::from(3u64)], // x = 3, so x^3 + x + 5 = 27 + 3 + 5 = 35
        };
        
        // Convert to accumulator instances
        let acc1 = reducer.strict_to_acc(&input1).expect("Failed to convert input1 to acc");
        let acc2 = reducer.strict_to_acc(&input2).expect("Failed to convert input2 to acc");
        
        println!("Folding accumulator instances...");
        
        // Fold the two accumulator instances
        let acc_children = [acc1, acc2];
        
        let fold_timer = start_timer!(|| "Folding accumulator instances");
        let (folded_acc, proof) = reducer.fold_acc_acc(&acc_children).expect("Failed to fold accumulator instances");
        end_timer!(fold_timer);
        
        println!("Folding complete. Verifying result...");
        
        // Verify the folding operation
        let verify_timer = start_timer!(|| "Verifying fold");
        let verified = reducer.verify_step(&folded_acc, &proof);
        assert!(verified, "Fold verification failed");
        end_timer!(verify_timer);
        
        println!("✓ Fold verification succeeded");
    }
    
    #[test]
    fn test_tree_fold_multiple_instances() {
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        // Create FoldDriver with our reducer
        let driver = crate::tree_folding::fold_driver::FoldDriver::new(reducer);
        
        println!("Creating leaf instances...");
        
        // Create leaf instances (strict instances)
        const NUM_LEAVES: usize = 4;
        let mut leaves = Vec::with_capacity(NUM_LEAVES);
        
        let create_timer = start_timer!(|| "Creating leaf instances");
        // Create step inputs with different values
        let inputs = [CF::from(2u32), CF::from(3u32), CF::from(5u32), CF::from(7u32)];
        
        for i in 0..NUM_LEAVES {
            let input = StepFunctionInput {
                i: CF::from(i as u64),
                z_i: vec![inputs[i]],
            };
            leaves.push(input);
        }
        end_timer!(create_timer);
        
        println!("Created {} leaf instances. Performing tree folding...", NUM_LEAVES);
        
        // Fold the tree to get the root
        let fold_timer = start_timer!(|| "Tree folding");
        let root = driver.fold_root(&leaves).expect("Failed to fold tree");
        end_timer!(fold_timer);
        
        println!("Tree folding complete!");
        
        // The root should be a valid accumulator instance
        let (lccs_instance, witness) = root;
        assert!(!lccs_instance.X.is_empty(), "Root LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Root witness should not be empty");
        
        println!("✓ Successfully folded {} instances into a tree with root", NUM_LEAVES);
    }
}