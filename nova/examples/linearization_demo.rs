//! Demonstration of CCS to LCCS linearization
//!
//! This example shows how to use the linearization algorithm to convert
//! a CCS instance into an LCCS instance using the sum-check protocol.

use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr, G1Projective as G};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::test_rng;

use nexus_nova::{
    ccs::linearization::{synthesize_and_linearize_step, StepFunctionInput},
    circuits::nova::StepCircuit,
    poseidon_config,
    zeromorph::Zeromorph,
};
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_crypto_primitives::sponge::CryptographicSponge;

type Z = Zeromorph<Bn254>;

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
        let y: FpVar<F> = x + x_cube + &FpVar::Constant(5u64.into());

        Ok(vec![y])
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 CCS to LCCS Linearization Demo");
    println!("==================================");

    let mut rng = test_rng();
    
    // Setup polynomial commitment
    println!("📋 Setting up polynomial commitment scheme...");
    let SRS = Z::setup(20, b"linearization_demo", &mut rng)?;
    let ck = Z::trim(&SRS, 20).ck;
    
    // Setup random oracle
    let config = poseidon_config::<Fr>();
    let mut random_oracle = PoseidonSponge::new(&config);
    
    // Test with a specific input
    let current_state = Fr::from(3u64); // 3 + 3^3 + 5 = 3 + 27 + 5 = 35
    let step_index = Fr::from(1u64);
    
    println!("🔢 Input state: {}", current_state);
    println!("📊 Step index: {}", step_index);
    
    let input = StepFunctionInput {
        i: step_index,
        z_i: vec![current_state],
    };
    
    // Synthesize and linearize
    println!("⚙️  Synthesizing step circuit and running linearization...");
    let result = synthesize_and_linearize_step::<G, Z, _, _>(
        &CubicCircuit::<Fr> { _phantom: PhantomData },
        &input,
        &ck,
        &mut random_oracle,
    )?;
    
    println!("✅ Linearization completed successfully!");
    
    // Verify the original CCS instance is satisfied
    println!("🔍 Verifying original CCS instance...");
    result.ccs_shape.is_satisfied(
        &result.ccs_instance,
        &result.linearization.witness,
        &ck,
    )?;
    println!("✅ Original CCS instance is satisfied");
    
    // Verify the linearized LCCS instance is satisfied
    println!("🔍 Verifying linearized LCCS instance...");
    result.ccs_shape.is_satisfied_linearized(
        &result.linearization.lccs_instance,
        &result.linearization.witness,
        &ck,
    )?;
    println!("✅ Linearized LCCS instance is satisfied");
    
    // Display some statistics
    println!("\n📈 Linearization Statistics:");
    println!("   • Number of constraints: {}", result.ccs_shape.num_constraints);
    println!("   • Number of variables: {}", result.ccs_shape.num_vars);
    println!("   • Number of matrices: {}", result.ccs_shape.num_matrices);
    println!("   • Evaluation point dimension: {}", result.linearization.lccs_instance.rs.len());
    println!("   • Number of evaluation targets: {}", result.linearization.lccs_instance.vs.len());
    println!("   • Sum-check proof elements: {}", result.linearization.sumcheck_proof.len());
    
    // Verify the computational relationship
    let expected_output = current_state + current_state.pow([3]) + Fr::from(5u64);
    println!("   • Expected output: {}", expected_output);
    
    println!("\n🎉 Linearization demo completed successfully!");
    println!("   The CCS instance has been successfully converted to an LCCS instance");
    println!("   using the sum-check protocol, preserving the computational relationship.");
    
    Ok(())
} 