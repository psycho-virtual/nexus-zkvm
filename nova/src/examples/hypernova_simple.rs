use std::marker::PhantomData;

use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ff::{PrimeField, One};
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use nexus_nova::{
    circuits::hypernova::sequential::{IVCProof, PublicParams},
    circuits::hypernova::StepCircuit,
    pedersen::PedersenCommitment,
    poseidon_config,
    zeromorph::Zeromorph,
};

// Define a simple circuit that cubes the input and adds 5
struct CubicCircuit<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
    // Number of state elements
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Make sure we have the right number of inputs
        assert_eq!(z.len(), Self::ARITY);
        
        let x = &z[0];
        
        // Compute x^3 + x + 5
        let x_square = x.square()?;
        let x_cube = x_square * x;
        let y = x + x_cube + &FpVar::Constant(F::from(5u64));
        
        // Return the new state
        Ok(vec![y])
    }
}

// Main function demonstrating how to use HyperNova with the simple cubic circuit
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define curve configurations and commitment schemes
    type G1 = ark_bn254::g1::Config;
    type G2 = ark_grumpkin::GrumpkinConfig;
    type C1 = Zeromorph<ark_bn254::Bn254>;
    type C2 = PedersenCommitment<ark_grumpkin::Projective>;
    type RO = PoseidonSponge<ark_bn254::Fr>;

    // Create a cubic circuit
    let circuit = CubicCircuit::<ark_bn254::Fr>(PhantomData);

    // Initial state
    let z_0 = vec![ark_bn254::Fr::one()];

    println!("Setting up HyperNova parameters...");
    
    // Setup parameters (using test_setup for simplicity)
    let ro_config = poseidon_config();
    let params = PublicParams::<G1, G2, C1, C2, RO, CubicCircuit<ark_bn254::Fr>>::test_setup(ro_config, &circuit)?;

    println!("Creating initial IVC proof...");
    
    // Create an IVC proof with the initial state
    let mut recursive_snark = IVCProof::new(&z_0);

    println!("Running one step of computation...");
    
    // Run one step of the computation
    recursive_snark = recursive_snark.prove_step(&params, &circuit)?;

    println!("Verifying the proof...");
    
    // Verify the proof
    recursive_snark.verify(&params)?;

    // Get the result state
    let result = recursive_snark.z_i()[0];
    println!("Result after 1 step: {}", result);

    // Run multiple additional steps
    let num_steps = 3;
    println!("Running {} additional steps of computation...", num_steps);

    for i in 0..num_steps {
        recursive_snark = recursive_snark.prove_step(&params, &circuit)?;
        println!("Completed step {}", i + 2); // +2 because we already did one step
    }

    // Verify all steps
    println!("Verifying all steps...");
    recursive_snark.verify(&params)?;

    // Show final result
    let final_result = recursive_snark.z_i()[0];
    println!("Final result after {} steps: {}", num_steps + 1, final_result);

    Ok(())
}