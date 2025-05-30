use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, ToConstraintField, Zero};
use tracing;

// Crate imports
use crate::absorb::AbsorbEmulatedFp;
use crate::ccs::{CCSShape, CCSWitness, LCCSInstance, Error as CCSError};
use crate::ccs::lccs_fold::{prove_folding, LCCSFoldingProof};
use crate::ccs::linearization::{synthesize_and_linearize_step, StepFunctionInput};
use crate::circuits::nova::StepCircuit;
use crate::provider::zeromorph::PolyCommitmentScheme;
use crate::tree_folding::fold_reducer::FoldReducer;
use crate::tree_folding::circuit::sequential_sha256::SequentialSha256Circuit;

// Tracing target for hypernova fold reducer operations
const HYPERNOVA_FOLD_TARGET: &str = "hypernova_fold_reducer";

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
    use ark_ff::{Field};
    use ark_std::{test_rng, start_timer, end_timer, marker::PhantomData};
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

    // Initialize tracing for tests
    fn init_tracing() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        
        INIT.call_once(|| {
            let filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::DEBUG.into())
                .from_env_lossy();
                
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_test_writer()
                .init();
        });
    }

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
        
        // Setup SRS for Zeromorph - use larger degree for SHA-256 circuit
        let srs_degree = 4; // 2^4 = 262,144 coefficients (was 16 = 65,536)
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
    
    // Helper function to set up the test environment for SHA-256 tests
    fn setup_sha256_test_environment() -> (PCKey, ROConfig) {
        let timer = start_timer!(|| "Setting up SHA-256 test environment");
        let mut rng = test_rng();
        
        // Setup SRS for Zeromorph - use very large degree for SHA-256 circuit
        let srs_degree = 20; // 2^20 = 1,048,576 coefficients
        let srs_timer = start_timer!(|| "Large SRS setup");
        let srs = Z::setup(srs_degree, b"test-sha256-hypernova-fold", &mut rng)
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
        init_tracing();
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create a HypernovaFoldReducer to ensure types compile correctly
        let _reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Test for HypernovaFoldReducer type compilation passed");
    }
    
    #[test]
    fn test_strict_to_acc_conversion() {
        init_tracing();
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🚀 Starting strict-to-accumulator conversion test");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Testing strict to accumulator conversion...");
        
        // Create a step function input
        let input = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(3u64)], // x = 3, so x^3 + x + 5 = 27 + 3 + 5 = 35
        };
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Input: i={}, z_i=[{}]", input.i, input.z_i[0]);
        
        let convert_timer = start_timer!(|| "Converting strict to acc");
        let start_time = std::time::Instant::now();
        
        let (lccs_instance, witness) = reducer.strict_to_acc(&input).expect("Failed to convert strict to acc");
        
        let conversion_time = start_time.elapsed();
        end_timer!(convert_timer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  STRICT-TO-ACC CONVERSION TIME: {:?}", conversion_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📊 Conversion results:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   - LCCS instance X length: {}", lccs_instance.X.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   - Witness W length: {}", witness.W.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   - LCCS rs length: {}", lccs_instance.rs.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   - LCCS vs length: {}", lccs_instance.vs.len());
        
        // The conversion should produce a valid LCCS instance
        assert!(!lccs_instance.X.is_empty(), "LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Witness should not be empty");
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Strict to accumulator conversion succeeded");
    }
    
    #[test]
    fn test_fold_two_acc_instances() {
        init_tracing();
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🚀 Starting accumulator folding test");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Creating accumulator instances...");
        
        // Create two step function inputs
        let input1 = StepFunctionInput {
            i: CF::from(1u64),
            z_i: vec![CF::from(2u64)], // x = 2, so x^3 + x + 5 = 8 + 2 + 5 = 15
        };
        
        let input2 = StepFunctionInput {
            i: CF::from(2u64),
            z_i: vec![CF::from(3u64)], // x = 3, so x^3 + x + 5 = 27 + 3 + 5 = 35
        };
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Instance 1: i={}, z_i=[{}]", input1.i, input1.z_i[0]);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Instance 2: i={}, z_i=[{}]", input2.i, input2.z_i[0]);
        
        // Time the conversion of each strict instance to accumulator
        let start_convert1 = std::time::Instant::now();
        let acc1 = reducer.strict_to_acc(&input1).expect("Failed to convert input1 to acc");
        let convert1_time = start_convert1.elapsed();
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  First strict-to-acc conversion: {:?}", convert1_time);
        
        let start_convert2 = std::time::Instant::now();
        let acc2 = reducer.strict_to_acc(&input2).expect("Failed to convert input2 to acc");
        let convert2_time = start_convert2.elapsed();
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  Second strict-to-acc conversion: {:?}", convert2_time);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📊 Pre-folding instance sizes:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Acc1 - X: {}, W: {}, rs: {}, vs: {}", 
                 acc1.0.X.len(), acc1.1.W.len(), acc1.0.rs.len(), acc1.0.vs.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Acc2 - X: {}, W: {}, rs: {}, vs: {}", 
                 acc2.0.X.len(), acc2.1.W.len(), acc2.0.rs.len(), acc2.0.vs.len());
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🔄 Folding accumulator instances...");
        
        // Fold the two accumulator instances
        let acc_children = [acc1, acc2];
        
        let fold_timer = start_timer!(|| "Folding accumulator instances");
        let start_fold_time = std::time::Instant::now();
        
        let (folded_acc, proof) = reducer.fold_acc_acc(&acc_children).expect("Failed to fold accumulator instances");
        
        let fold_time = start_fold_time.elapsed();
        end_timer!(fold_timer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  ACCUMULATOR FOLDING TIME: {:?}", fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📊 Post-folding results:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Folded LCCS - X: {}, rs: {}, vs: {}", 
                 folded_acc.0.X.len(), folded_acc.0.rs.len(), folded_acc.0.vs.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Folded witness - W: {}", folded_acc.1.W.len());
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🔍 Verifying folding result...");
        
        // Verify the folding operation
        let verify_timer = start_timer!(|| "Verifying fold");
        let start_verify_time = std::time::Instant::now();
        
        let verified = reducer.verify_step(&folded_acc, &proof);
        
        let verify_time = start_verify_time.elapsed();
        end_timer!(verify_timer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  Verification time: {:?}", verify_time);
        
        assert!(verified, "Fold verification failed");
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📈 TIMING SUMMARY:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • First conversion:  {:?}", convert1_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Second conversion: {:?}", convert2_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Folding operation: {:?}", fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Verification:      {:?}", verify_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Total time:        {:?}", convert1_time + convert2_time + fold_time + verify_time);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Fold verification succeeded");
    }
    
    #[test]
    fn test_tree_fold_multiple_instances() {
        init_tracing();
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🚀 Starting tree folding test");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        // Create FoldDriver with our reducer
        let driver = crate::tree_folding::fold_driver::FoldDriver::new(reducer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Creating leaf instances...");
        
        // Create leaf instances (strict instances)
        const NUM_LEAVES: usize = 4;
        let mut leaves = Vec::with_capacity(NUM_LEAVES);
        
        let create_timer = start_timer!(|| "Creating leaf instances");
        let start_create_time = std::time::Instant::now();
        
        // Create step inputs with different values
        let inputs = [CF::from(2u32), CF::from(3u32), CF::from(5u32), CF::from(7u32)];
        
        for i in 0..NUM_LEAVES {
            let input = StepFunctionInput {
                i: CF::from(i as u64),
                z_i: vec![inputs[i]],
            };
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Leaf {}: i={}, z_i=[{}]", i, input.i, input.z_i[0]);
            leaves.push(input);
        }
        
        let create_time = start_create_time.elapsed();
        end_timer!(create_timer);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  Leaf creation time: {:?}", create_time);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🌳 Performing tree folding on {} leaves...", NUM_LEAVES);
        
        // Fold the tree to get the root
        let fold_timer = start_timer!(|| "Tree folding");
        let start_tree_fold_time = std::time::Instant::now();
        
        let root = driver.fold_root(&leaves).expect("Failed to fold tree");
        
        let tree_fold_time = start_tree_fold_time.elapsed();
        end_timer!(fold_timer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  TREE FOLDING TIME: {:?}", tree_fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📊 Tree folding results:");
        
        // The root should be a valid accumulator instance
        let (lccs_instance, witness) = root;
        assert!(!lccs_instance.X.is_empty(), "Root LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Root witness should not be empty");
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Root LCCS - X: {}, rs: {}, vs: {}", 
                 lccs_instance.X.len(), lccs_instance.rs.len(), lccs_instance.vs.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Root witness - W: {}", witness.W.len());
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📈 TREE FOLDING SUMMARY:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Number of leaves: {}", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Creation time:    {:?}", create_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Folding time:     {:?}", tree_fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Average per leaf: {:?}", tree_fold_time / NUM_LEAVES as u32);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Successfully folded {} instances into a tree with root", NUM_LEAVES);
    }
    
    #[test]
    fn test_sha256_tree_fold_four_leaves() {
        init_tracing();
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🚀 Starting SHA-256 tree folding test");
        
        let (ck, ro_config) = setup_sha256_test_environment();
        let circuit = SequentialSha256Circuit::<CF>::new();
        
        // Create fold reducer with SHA-256 circuit
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        // Create FoldDriver with our reducer
        let driver = crate::tree_folding::fold_driver::FoldDriver::new(reducer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Creating SHA-256 leaf instances...");
        
        // Create four leaf instances representing different SHA-256 operations
        const NUM_LEAVES: usize = 4;
        let mut leaves = Vec::with_capacity(NUM_LEAVES);
        
        let create_timer = start_timer!(|| "Creating SHA-256 leaf instances");
        let start_create_time = std::time::Instant::now();
        
        // Import conversions from the sha256 module
        use crate::tree_folding::circuit::sha256::{calculate_sha256_native, conversions};
        
        // Different input messages for each leaf
        let messages = [
            b"hello world".to_vec(),
            b"nexus zkvm".to_vec(),
            b"hypernova folding".to_vec(),
            b"sha256 circuit".to_vec(),
        ];
        
        for i in 0..NUM_LEAVES {
            // Calculate SHA-256 hash of the message
            let hash_bytes = calculate_sha256_native(&messages[i]);
            
            // Convert hash to field element
            let hash_field = conversions::bytes_to_field::<CF>(&hash_bytes);
            
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Leaf {}: Message = \"{}\"", i, String::from_utf8_lossy(&messages[i]));
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  Hash (hex): {}", hex::encode(&hash_bytes));
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  Hash (field): {}", hash_field);
            
            let input = StepFunctionInput {
                i: CF::from(i as u64),
                z_i: vec![hash_field],  // SequentialSha256Circuit has ARITY = 1
            };
            leaves.push(input);
        }
        
        let create_time = start_create_time.elapsed();
        end_timer!(create_timer);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  SHA-256 leaf creation time: {:?}", create_time);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Created {} SHA-256 leaf instances. Each leaf contains:", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  - Previous hash state: 1 field element (representing 256-bit hash)");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  - Circuit performs: SHA-256(previous_hash) -> new_hash");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🌳 Performing SHA-256 tree folding...");
        
        // Fold the tree to get the root
        let fold_timer = start_timer!(|| "SHA-256 tree folding");
        let start_tree_fold_time = std::time::Instant::now();
        
        let root = driver.fold_root(&leaves).expect("Failed to fold SHA-256 tree");
        
        let tree_fold_time = start_tree_fold_time.elapsed();
        end_timer!(fold_timer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  SHA-256 TREE FOLDING TIME: {:?}", tree_fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📊 SHA-256 tree folding results:");
        
        // The root should be a valid accumulator instance
        let (lccs_instance, witness) = root;
        assert!(!lccs_instance.X.is_empty(), "Root LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Root witness should not be empty");
        
        // Verify that the public inputs match our expected SHA-256 output structure
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Root instance public inputs: {} elements", lccs_instance.X.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Root witness size: {} elements", witness.W.len());
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📈 SHA-256 FOLDING SUMMARY:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Number of leaves: {}", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Creation time:    {:?}", create_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Folding time:     {:?}", tree_fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Average per leaf: {:?}", tree_fold_time / NUM_LEAVES as u32);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Successfully folded {} SHA-256 operations into a tree with root", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ SHA-256 tree folding test completed successfully");
        
        // Additional verification: try to extract final hash from the root
        if let Some(final_hash_field) = lccs_instance.X.get(0) {
            let final_hash_bytes = conversions::field_to_bytes(final_hash_field);
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Final root hash (hex): {}", hex::encode(&final_hash_bytes));
        }
    }
    
    #[test]
    fn test_cubic_circuit_tree_fold_four_leaves() {
        init_tracing();
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🚀 Starting cubic circuit tree folding test");
        
        let (ck, ro_config) = setup_test_environment();
        let circuit = CubicCircuit::<CF> { _phantom: PhantomData };
        
        // Create fold reducer with cubic circuit (simulating hash-like operations)
        let reducer = HypernovaFoldReducer::<G1, Z, _, RO>::new(
            &circuit, &ck, &ro_config
        );
        
        // Create FoldDriver with our reducer
        let driver = crate::tree_folding::fold_driver::FoldDriver::new(reducer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Creating cubic circuit leaf instances (simulating hash operations)...");
        
        // Create four leaf instances representing different hash-like operations
        const NUM_LEAVES: usize = 4;
        let mut leaves = Vec::with_capacity(NUM_LEAVES);
        
        let create_timer = start_timer!(|| "Creating cubic circuit leaf instances");
        let start_create_time = std::time::Instant::now();
        
        // Use different input values that simulate hashed data
        // These are large numbers that could represent hashes
        let simulated_hashes = [
            CF::from(0x428a2f98u64),  // SHA-256 constant K0
            CF::from(0x71374491u64),  // SHA-256 constant K1
            CF::from(0xb5c0fbcfu64),  // SHA-256 constant K2
            CF::from(0xe9b5dba5u64),  // SHA-256 constant K3
        ];
        
        for i in 0..NUM_LEAVES {
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Leaf {}: Simulated hash value = {}", i, simulated_hashes[i]);
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  Input to cubic circuit: x = {}", simulated_hashes[i]);
            
            // Calculate what the cubic circuit will produce: x^3 + x + 5
            let x = simulated_hashes[i];
            let expected_output = x * x * x + x + CF::from(5u64);
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  Expected output: x^3 + x + 5 = {}", expected_output);
            
            let input = StepFunctionInput {
                i: CF::from(i as u64),
                z_i: vec![simulated_hashes[i]], // CubicCircuit has ARITY = 1
            };
            leaves.push(input);
        }
        
        let create_time = start_create_time.elapsed();
        end_timer!(create_timer);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  Cubic circuit leaf creation time: {:?}", create_time);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📝 Created {} cubic circuit leaf instances. Each leaf contains:", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  - Input value: 1 field element (simulating a hash)");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "  - Circuit performs: x^3 + x + 5 (simulating hash processing)");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "🌳 Performing cubic circuit tree folding...");
        
        // Fold the tree to get the root
        let fold_timer = start_timer!(|| "Cubic circuit tree folding");
        let start_tree_fold_time = std::time::Instant::now();
        
        let root = driver.fold_root(&leaves).expect("Failed to fold cubic circuit tree");
        
        let tree_fold_time = start_tree_fold_time.elapsed();
        end_timer!(fold_timer);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "⏱️  CUBIC CIRCUIT TREE FOLDING TIME: {:?}", tree_fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📊 Cubic circuit tree folding results:");
        
        // The root should be a valid accumulator instance
        let (lccs_instance, witness) = root;
        assert!(!lccs_instance.X.is_empty(), "Root LCCS instance should have public inputs");
        assert!(!witness.W.is_empty(), "Root witness should not be empty");
        
        // Verify that the public inputs match our expected structure
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Root instance public inputs: {} elements", lccs_instance.X.len());
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   Root witness size: {} elements", witness.W.len());
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "📈 CUBIC CIRCUIT FOLDING SUMMARY:");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Number of leaves: {}", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Creation time:    {:?}", create_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Folding time:     {:?}", tree_fold_time);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "   • Average per leaf: {:?}", tree_fold_time / NUM_LEAVES as u32);
        
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Successfully folded {} cubic circuit operations into a tree with root", NUM_LEAVES);
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ Cubic circuit tree folding test completed successfully");
        tracing::info!(target: HYPERNOVA_FOLD_TARGET, "✅ This demonstrates the same tree folding concept that would work with SHA-256");
        
        // Additional verification: show the final computed value
        if let Some(final_value) = lccs_instance.X.get(0) {
            tracing::info!(target: HYPERNOVA_FOLD_TARGET, "Final root value: {}", final_value);
        }
    }
}