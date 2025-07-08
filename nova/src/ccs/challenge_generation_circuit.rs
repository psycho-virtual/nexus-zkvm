//! Circuit-compatible challenge generation utilities for CCS/LCCS folding
//!
//! This module provides circuit gadgets for generating gamma and beta challenges
//! from a random oracle within R1CS constraint systems.

use ark_crypto_primitives::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use ark_std::vec::Vec;

/// Generate a single gamma challenge from the random oracle in-circuit
///
/// # Arguments
/// * `random_oracle` - The cryptographic sponge variable to use for challenge generation
///
/// # Returns
/// * A single field element variable representing the gamma challenge
pub fn generate_gamma_challenge_circuit<G1, RO>(
    random_oracle: &mut RO::Var,
) -> Result<FpVar<G1::ScalarField>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    let gamma_vec = random_oracle.squeeze_field_elements(1)?;
    Ok(gamma_vec[0].clone())
}

/// Generate beta challenges for sumcheck rounds from the random oracle in-circuit
///
/// # Arguments
/// * `random_oracle` - The cryptographic sponge variable to use for challenge generation
/// * `num_rounds` - The number of beta challenges to generate (typically log₂(num_constraints))
///
/// # Returns
/// * A vector of field element variables representing the beta challenges
pub fn generate_beta_challenges_circuit<G1, RO>(
    random_oracle: &mut RO::Var,
    num_rounds: usize,
) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    random_oracle.squeeze_field_elements(num_rounds)
}

/// Generate both gamma and beta challenges from the random oracle in-circuit
///
/// This is a convenience function that generates gamma first, then beta challenges.
/// This ordering is important for protocol consistency.
///
/// # Arguments
/// * `random_oracle` - The cryptographic sponge variable to use for challenge generation
/// * `num_beta_challenges` - The number of beta challenges to generate
///
/// # Returns
/// * A tuple of (gamma, beta_vector) as circuit variables
pub fn generate_gamma_and_beta_challenges_circuit<G1, RO>(
    random_oracle: &mut RO::Var,
    num_beta_challenges: usize,
) -> Result<(FpVar<G1::ScalarField>, Vec<FpVar<G1::ScalarField>>), SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    RO: SpongeWithGadget<G1::ScalarField>,
{
    let gamma = generate_gamma_challenge_circuit::<G1, RO>(random_oracle)?;
    let beta = generate_beta_challenges_circuit::<G1, RO>(random_oracle, num_beta_challenges)?;
    Ok((gamma, beta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{g1::Config as G1Config, Fr};
    use ark_crypto_primitives::sponge::poseidon::{
        constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge,
    };
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    fn test_config() -> PoseidonConfig<Fr> {
        crate::poseidon_config::<Fr>()
    }

    #[test]
    fn test_generate_gamma_challenge_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let config = test_config();
        let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);

        let gamma = generate_gamma_challenge_circuit::<G1Config, PoseidonSponge<Fr>>(
            &mut sponge_var,
        )
        .unwrap();

        // Check that gamma is allocated and has a value
        assert!(gamma.value().is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_generate_beta_challenges_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let config = test_config();
        let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);

        let num_rounds = 10;
        let beta = generate_beta_challenges_circuit::<G1Config, PoseidonSponge<Fr>>(
            &mut sponge_var,
            num_rounds,
        )
        .unwrap();

        assert_eq!(beta.len(), num_rounds);
        for b in &beta {
            assert!(b.value().is_ok());
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_generate_gamma_and_beta_challenges_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let config = test_config();
        let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);

        let num_beta = 8;
        let (gamma, beta) = generate_gamma_and_beta_challenges_circuit::<
            G1Config,
            PoseidonSponge<Fr>,
        >(&mut sponge_var, num_beta)
        .unwrap();

        assert!(gamma.value().is_ok());
        assert_eq!(beta.len(), num_beta);
        for b in &beta {
            assert!(b.value().is_ok());
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_consistency_with_native() {
        let config = test_config();
        
        // Native generation
        let mut native_sponge = PoseidonSponge::new(&config);
        let native_gamma = crate::ccs::challenge_generation::generate_gamma_challenge::<Fr, _>(
            &mut native_sponge,
        );
        let native_beta = crate::ccs::challenge_generation::generate_beta_challenges::<Fr, _>(
            &mut native_sponge,
            5,
        );

        // Circuit generation
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut circuit_sponge_var = PoseidonSpongeVar::new(cs.clone(), &config);
        let circuit_gamma =
            generate_gamma_challenge_circuit::<G1Config, PoseidonSponge<Fr>>(&mut circuit_sponge_var)
                .unwrap();
        let circuit_beta =
            generate_beta_challenges_circuit::<G1Config, PoseidonSponge<Fr>>(&mut circuit_sponge_var, 5)
                .unwrap();

        // Check consistency
        assert_eq!(circuit_gamma.value().unwrap(), native_gamma);
        assert_eq!(
            circuit_beta
                .iter()
                .map(|b| b.value().unwrap())
                .collect::<Vec<_>>(),
            native_beta
        );
        assert!(cs.is_satisfied().unwrap());
    }
}