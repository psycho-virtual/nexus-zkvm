//! Native challenge generation utilities for CCS/LCCS folding
//!
//! This module provides utilities for generating gamma and beta challenges
//! from a random oracle for use in the HyperNova folding scheme.

use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::PrimeField;

/// Generate a single gamma challenge from the random oracle
///
/// # Arguments
/// * `random_oracle` - The cryptographic sponge to use for challenge generation
///
/// # Returns
/// * A single field element gamma challenge
pub fn generate_gamma_challenge<F, RO>(random_oracle: &mut RO) -> F
where
    F: PrimeField,
    RO: CryptographicSponge,
{
    random_oracle.squeeze_field_elements(1)[0]
}

/// Generate beta challenges for sumcheck rounds from the random oracle
///
/// # Arguments
/// * `random_oracle` - The cryptographic sponge to use for challenge generation
/// * `num_rounds` - The number of beta challenges to generate (typically log₂(num_constraints))
///
/// # Returns
/// * A vector of field elements representing the beta challenges
pub fn generate_beta_challenges<F, RO>(random_oracle: &mut RO, num_rounds: usize) -> Vec<F>
where
    F: PrimeField,
    RO: CryptographicSponge,
{
    random_oracle.squeeze_field_elements(num_rounds)
}

/// Generate both gamma and beta challenges from the random oracle
///
/// This is a convenience function that generates gamma first, then beta challenges.
/// This ordering is important for protocol consistency.
///
/// # Arguments
/// * `random_oracle` - The cryptographic sponge to use for challenge generation
/// * `num_beta_challenges` - The number of beta challenges to generate
///
/// # Returns
/// * A tuple of (gamma, beta_vector)
pub fn generate_gamma_and_beta_challenges<F, RO>(
    random_oracle: &mut RO,
    num_beta_challenges: usize,
) -> (F, Vec<F>)
where
    F: PrimeField,
    RO: CryptographicSponge,
{
    let gamma = generate_gamma_challenge(random_oracle);
    let beta = generate_beta_challenges(random_oracle, num_beta_challenges);
    (gamma, beta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
    use ark_crypto_primitives::sponge::CryptographicSponge;
    use ark_ff::Zero;

    fn test_config() -> PoseidonConfig<Fr> {
        crate::poseidon_config::<Fr>()
    }

    #[test]
    fn test_generate_gamma_challenge() {
        let config = test_config();
        let mut sponge = PoseidonSponge::new(&config);
        
        let gamma = generate_gamma_challenge::<Fr, _>(&mut sponge);
        assert_ne!(gamma, Fr::zero());
    }

    #[test]
    fn test_generate_beta_challenges() {
        let config = test_config();
        let mut sponge = PoseidonSponge::new(&config);
        
        let num_rounds = 10;
        let beta = generate_beta_challenges::<Fr, _>(&mut sponge, num_rounds);
        
        assert_eq!(beta.len(), num_rounds);
        // Check that challenges are non-zero (with high probability)
        for b in &beta {
            assert_ne!(*b, Fr::zero());
        }
    }

    #[test]
    fn test_generate_gamma_and_beta_challenges() {
        let config = test_config();
        let mut sponge = PoseidonSponge::new(&config);
        
        let num_beta = 8;
        let (gamma, beta) = generate_gamma_and_beta_challenges::<Fr, _>(&mut sponge, num_beta);
        
        assert_ne!(gamma, Fr::zero());
        assert_eq!(beta.len(), num_beta);
    }

    #[test]
    fn test_deterministic_generation() {
        let config = test_config();
        
        // Two sponges with same initial state should produce same challenges
        let mut sponge1 = PoseidonSponge::new(&config);
        let mut sponge2 = PoseidonSponge::new(&config);
        
        let gamma1 = generate_gamma_challenge::<Fr, _>(&mut sponge1);
        let gamma2 = generate_gamma_challenge::<Fr, _>(&mut sponge2);
        
        assert_eq!(gamma1, gamma2);
        
        let beta1 = generate_beta_challenges::<Fr, _>(&mut sponge1, 5);
        let beta2 = generate_beta_challenges::<Fr, _>(&mut sponge2, 5);
        
        assert_eq!(beta1, beta2);
    }
}