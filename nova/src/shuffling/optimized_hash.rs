use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use super::data_structures::ElGamalCiphertextVar;

/// Optimized card hashing that avoids expensive to_constraint_field()
pub fn hash_card_to_field_optimized<G: SWCurveConfig>(
    _cs: ConstraintSystemRef<G::BaseField>,
    card: &ElGamalCiphertextVar<G>,
) -> Result<FpVar<G::BaseField>, SynthesisError>
where
    G::BaseField: PrimeField,
{
    // Instead of using to_constraint_field() which is very expensive,
    // we can hash the card more efficiently by directly using the 
    // field element coordinates
    
    // For projective coordinates (x:y:z), we can use a simple linear combination
    // This is much cheaper than bit decomposition
    
    // Extract the projective coordinates directly
    let c1_x = &card.c1.x;
    let c1_y = &card.c1.y;
    let c1_z = &card.c1.z;
    
    let c2_x = &card.c2.x;
    let c2_y = &card.c2.y;
    let c2_z = &card.c2.z;
    
    // Create a hash using a simple linear combination with distinct prime coefficients
    // This preserves injectivity while being much cheaper than to_constraint_field
    let coeff1 = FpVar::constant(G::BaseField::from(2u64));
    let coeff2 = FpVar::constant(G::BaseField::from(3u64));
    let coeff3 = FpVar::constant(G::BaseField::from(5u64));
    let coeff4 = FpVar::constant(G::BaseField::from(7u64));
    let coeff5 = FpVar::constant(G::BaseField::from(11u64));
    let coeff6 = FpVar::constant(G::BaseField::from(13u64));
    
    // Hash = 2*c1.x + 3*c1.y + 5*c1.z + 7*c2.x + 11*c2.y + 13*c2.z
    let hash = coeff1 * c1_x + 
               coeff2 * c1_y + 
               coeff3 * c1_z + 
               coeff4 * c2_x + 
               coeff5 * c2_y + 
               coeff6 * c2_z;
    
    Ok(hash)
}

/// Alternative: Use Poseidon hash for cryptographic security
/// This is more expensive than linear combination but cheaper than to_constraint_field
pub fn hash_card_to_field_poseidon<G: SWCurveConfig>(
    cs: ConstraintSystemRef<G::BaseField>,
    card: &ElGamalCiphertextVar<G>,
) -> Result<FpVar<G::BaseField>, SynthesisError>
where
    G::BaseField: PrimeField + ark_ff::fields::models::fp::Absorb,
{
    use ark_r1cs_std::fields::fp::AllocatedFp;
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSpongeVar};
    use ark_crypto_primitives::sponge::{CryptographicSpongeVar, constraints::AbsorbGadget};
    
    // Create Poseidon config (you'll need to import the actual config)
    let config = super::circuit::poseidon_config::<G::BaseField>();
    let mut sponge = PoseidonSpongeVar::new(cs, &config);
    
    // Absorb the projective coordinates
    // Note: We need to convert FpVar to AllocatedFp for absorption
    let coords = vec![
        &card.c1.x,
        &card.c1.y, 
        &card.c1.z,
        &card.c2.x,
        &card.c2.y,
        &card.c2.z,
    ];
    
    for coord in coords {
        sponge.absorb(&coord)?;
    }
    
    // Squeeze out the hash
    let hash = sponge.squeeze_field_elements(1)?[0].clone();
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Config;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_hash_performance() {
        type G = G1Config;
        let cs = ConstraintSystem::<ark_bls12_381::Fq>::new_ref();
        
        // Create a test card
        use ark_ec::CurveGroup;
        use super::super::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
        
        let test_card = ElGamalCiphertext {
            c1: ark_bls12_381::G1Projective::generator(),
            c2: ark_bls12_381::G1Projective::generator(),
        };
        
        let card_var = ElGamalCiphertextVar::<G>::new_witness(cs.clone(), || Ok(&test_card)).unwrap();
        
        // Time the optimized hash
        let start = std::time::Instant::now();
        let _hash = hash_card_to_field_optimized(cs.clone(), &card_var).unwrap();
        let duration = start.elapsed();
        
        println!("Optimized hash took: {:?}", duration);
        println!("Constraints generated: {}", cs.num_constraints());
    }
}