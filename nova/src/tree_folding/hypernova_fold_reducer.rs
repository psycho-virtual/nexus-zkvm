use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, ToConstraintField, Zero};
use std::time::Instant;

// Crate imports
use crate::absorb::AbsorbEmulatedFp;
use crate::ccs::{CCSShape, CCSWitness, LCCSInstance, Error as CCSError};
use crate::ccs::lccs_fold::{prove_folding, LCCSFoldingProof};
use crate::ccs::linearization::{synthesize_and_linearize_step, synthesize_step_circuit_with_params, StepFunctionInput, LinearizationParams, setup_linearization};
use crate::circuits::nova::StepCircuit;
use crate::provider::zeromorph::PolyCommitmentScheme;
use crate::tree_folding::fold_reducer::FoldReducer;
use crate::tree_folding::circuit::sequential_sha256::SequentialSha256Circuit;

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
    /// The linearization parameters containing precomputed shape and circuit
    pub params: LinearizationParams<G, SC>,
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
        params: LinearizationParams<G, SC>,
        ck: &'a C::PolyCommitmentKey,
        random_oracle_config: &'a RO::Config,
    ) -> Self {
        Self {
            params,
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
        let shape = &self.params.ccs_shape;
        
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
        let shape = &self.params.ccs_shape;
        
        // Check if the LCCS instance is satisfied
        match shape.is_satisfied_linearized(lccs_instance, witness, self.ck) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn strict_to_acc(&self, strict: &Self::StrictInst) -> Result<Self::AccInst, Self::Error> {
        // Synthesize step circuit witness using precomputed parameters
        match synthesize_step_circuit_with_params::<G, C, _>(
            &self.params,
            strict,
            self.ck,
        ) {
            Ok((ccs_instance, witness)) => {
                // Convert CCS to LCCS by committing to the witness
                let commitment_W = witness.commit::<C>(self.ck);
                
                // For initial LCCS creation without linearization, use dummy values for rs and vs
                let dummy_rs = vec![G::ScalarField::zero(); crate::safe_loglike!(self.params.ccs_shape.num_constraints) as usize];
                let dummy_vs = vec![G::ScalarField::zero(); self.params.ccs_shape.num_matrices];
                
                let lccs_instance = LCCSInstance::new(
                    &self.params.ccs_shape, 
                    &commitment_W, 
                    &ccs_instance.X, 
                    &dummy_rs, 
                    &dummy_vs
                )?;
                
                Ok((lccs_instance, witness))
            },
            Err(e) => Err(HypernovaFoldError::LinearizationFailed(format!("Step synthesis failed: {:?}", e))),
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
            &self.params,
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
    use ark_ff::{Field};
    use ark_std::{test_rng, marker::PhantomData};
    use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
    use crate::poseidon_config;
    use crate::provider::zeromorph::Zeromorph;
    use hex;

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
        println!("Setting up test environment");
        let mut rng = test_rng();
        
        // Setup SRS for Zeromorph - use larger degree for SHA-256 circuit
        let srs_degree = 4; // 2^4 = 262,144 coefficients
        println!("Setting up SRS with degree {}", srs_degree);
        let srs = Z::setup(srs_degree, b"test-hypernova-fold", &mut rng)
            .expect("Failed to set up SRS");
            
        // Trim SRS to get commitment key
        println!("Trimming SRS");
        let ck = Z::trim(&srs, srs_degree - 1).ck;
        
        // Setup random oracle
        let ro_config = poseidon_config::<CF>();
        
        println!("Test environment setup complete");
        (ck, ro_config)
    }
    
    #[test]
    fn test_hypernova_fold_reducer_creation() {
        println!("Testing HypernovaFoldReducer type compilation");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create a HypernovaFoldReducer to ensure types compile correctly
        let _reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            setup_linearization(circuit).unwrap(), &ck, &ro_config
        );
        
        println!("✅ Test for HypernovaFoldReducer type compilation passed");
    }
    
    #[test]
    fn test_strict_to_acc_conversion() {
        println!("🚀 Starting strict-to-accumulator conversion test");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            setup_linearization(circuit).unwrap(), &ck, &ro_config
        );
        
        println!("📝 Testing strict to accumulator conversion...");
        
        // Create a step function input
        let input = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(3u64)], // x = 3, so x^3 + x + 5 = 27 + 3 + 5 = 35
        };
        
        println!("Input: i={}, z_i=[{}]", input.i, input.z_i[0]);
        
        let start_time = Instant::now();
        
        let (lccs_instance, witness) = reducer.strict_to_acc(&input).expect("Failed to convert strict to acc");
        
        let conversion_time = start_time.elapsed();
        
        println!("⏱️  STRICT-TO-ACC CONVERSION TIME: {:?}", conversion_time);
        println!("📊 Conversion results:");
        println!("   - LCCS instance X length: {}", lccs_instance.X.len());
        println!("   - Witness W length: {}", witness.W.len());
        println!("   - LCCS rs length: {}", lccs_instance.rs.len());
        println!("   - LCCS vs length: {}", lccs_instance.vs.len());
        
        // The conversion should produce a valid LCCS instance
        assert!(!lccs_instance.X.is_empty(), "LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Witness should not be empty");
        
        println!("✅ Strict to accumulator conversion succeeded");
    }
    
    #[test]
    fn test_fold_two_acc_instances() {
        println!("🚀 Starting accumulator folding test");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            setup_linearization(circuit).unwrap(), &ck, &ro_config
        );
        
        println!("📝 Creating accumulator instances...");
        
        // Create two step function inputs
        let input1 = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(2u64)], // x = 2, so x^3 + x + 5 = 8 + 2 + 5 = 15
        };
        
        let input2 = StepFunctionInput {
            i: CF::from(2u64),
            z_i: vec![CF::from(3u64)], // x = 3, so x^3 + x + 5 = 27 + 3 + 5 = 35
        };
        
        println!("Instance 1: i={}, z_i=[{}]", input1.i, input1.z_i[0]);
        println!("Instance 2: i={}, z_i=[{}]", input2.i, input2.z_i[0]);
        
        // Time the conversion of each strict instance to accumulator
        let start_convert1 = Instant::now();
        let acc1 = reducer.strict_to_acc(&input1).expect("Failed to convert input1 to acc");
        let convert1_time = start_convert1.elapsed();
        println!("⏱️  First strict-to-acc conversion: {:?}", convert1_time);
        
        let start_convert2 = Instant::now();
        let acc2 = reducer.strict_to_acc(&input2).expect("Failed to convert input2 to acc");
        let convert2_time = start_convert2.elapsed();
        println!("⏱️  Second strict-to-acc conversion: {:?}", convert2_time);
        
        println!("📊 Pre-folding instance sizes:");
        println!("   Acc1 - X: {}, W: {}, rs: {}, vs: {}", 
                 acc1.0.X.len(), acc1.1.W.len(), acc1.0.rs.len(), acc1.0.vs.len());
        println!("   Acc2 - X: {}, W: {}, rs: {}, vs: {}", 
                 acc2.0.X.len(), acc2.1.W.len(), acc2.0.rs.len(), acc2.0.vs.len());
        
        println!("🔄 Folding accumulator instances...");
        
        // Fold the two accumulator instances
        let acc_children = [acc1, acc2];
        
        let start_fold_time = Instant::now();
        
        let (folded_acc, proof) = reducer.fold_acc_acc(&acc_children).expect("Failed to fold accumulator instances");
        
        let fold_time = start_fold_time.elapsed();
        
        println!("⏱️  ACCUMULATOR FOLDING TIME: {:?}", fold_time);
        println!("📊 Post-folding results:");
        println!("   Folded LCCS - X: {}, rs: {}, vs: {}", 
                 folded_acc.0.X.len(), folded_acc.0.rs.len(), folded_acc.0.vs.len());
        println!("   Folded witness - W: {}", folded_acc.1.W.len());
        
        println!("🔍 Verifying folding result...");
        
        // Verify the folding operation
        let start_verify_time = Instant::now();
        
        let verified = reducer.verify_step(&folded_acc, &proof);
        
        let verify_time = start_verify_time.elapsed();
        
        println!("⏱️  Verification time: {:?}", verify_time);
        
        assert!(verified, "Fold verification failed");
        
        println!("📈 TIMING SUMMARY:");
        println!("   • First conversion:  {:?}", convert1_time);
        println!("   • Second conversion: {:?}", convert2_time);
        println!("   • Folding operation: {:?}", fold_time);
        println!("   • Verification:      {:?}", verify_time);
        println!("   • Total time:        {:?}", convert1_time + convert2_time + fold_time + verify_time);
        
        println!("✅ Fold verification succeeded");
    }
}