use crate::data_structures::*;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    Group,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    prelude::*,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use std::marker::PhantomData;

/// ElGamal encryption operations for the two-curve system
pub struct ElGamalEncryption<G1, G2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
{
    _phantom: PhantomData<(G1, G2)>,
}

impl<G1, G2> ElGamalEncryption<G1, G2>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::ScalarField: PrimeField,
    G1::BaseField: PrimeField,
{
    /// ElGamal encryption circuit for a single card
    /// Implements: c1 = m0 + R, c2 = m1 + P where R = r*g, P = r*pk
    #[tracing::instrument(target = "elgamal::encrypt", skip_all)]
    pub fn encrypt_card(
        cs: ConstraintSystemRef<G1::ScalarField>,
        m0: &ProjectiveVar<G2, FpVar<G1::ScalarField>>,
        m1: &ProjectiveVar<G2, FpVar<G1::ScalarField>>,
        pk: &ProjectiveVar<G2, FpVar<G1::ScalarField>>,
        r: &FpVar<G1::ScalarField>,
    ) -> Result<
        (
            ProjectiveVar<G2, FpVar<G1::ScalarField>>,
            ProjectiveVar<G2, FpVar<G1::ScalarField>>,
        ),
        SynthesisError,
    > {
        let cs = ns!(cs, "encrypt_card");

        // Fixed-base multiplication: R = r * g
        let generator = ProjectiveVar::<G2, FpVar<G1::ScalarField>>::new_constant(
            cs.clone(),
            Projective::<G2>::generator(),
        )?;
        let r_point = generator.scalar_mul_le(r.to_bits_le()?.iter())?;

        // c1 = m0 + R
        let c1 = m0.clone() + r_point;

        // Variable-base multiplication: P = r * pk
        let p_point = pk.scalar_mul_le(r.to_bits_le()?.iter())?;

        // c2 = m1 + P
        let c2 = m1.clone() + p_point;

        Ok((c1, c2))
    }

    /// Single-share partial decryption circuit
    /// Implements: c2' = c2 - s_i * c1
    #[tracing::instrument(target = "elgamal::decrypt", skip_all)]
    pub fn partial_decrypt(
        cs: ConstraintSystemRef<G1::BaseField>,
        c1: &ProjectiveVar<G2, FpVar<G2::BaseField>>,
        c2: &ProjectiveVar<G2, FpVar<G2::BaseField>>,
        secret_share: &FpVar<G1::BaseField>,
    ) -> Result<ProjectiveVar<G2, FpVar<G2::BaseField>>, SynthesisError> {
        // Variable-base multiplication: S = s_i * c1
        let s_point = c1.scalar_mul_le(secret_share.to_bits_le()?.iter())?;

        // c2' = c2 - S
        let c2_prime = c2.clone() - s_point;

        Ok(c2_prime)
    }

    /// Re-randomization circuit for shuffling
    /// Implements: c1' = c1 + r' * g, c2' = c2 + r' * pk_shuffler
    #[tracing::instrument(target = "elgamal::rerandomize", skip_all)]
    pub fn rerandomize_ciphertext(
        cs: ConstraintSystemRef<G1::BaseField>,
        ciphertext: &ElGamalCiphertextVar<G2>,
        rerandomization: &FpVar<G1::BaseField>,
        shuffler_pk: &ProjectiveVar<G2, FpVar<G2::BaseField>>,
    ) -> Result<ElGamalCiphertextVar<G2>, SynthesisError> {
        let cs = ns!(cs, "rerandomize");

        // Fixed-base multiplication: r' * g
        let generator = ProjectiveVar::<G2, FpVar<G2::BaseField>>::new_constant(
            cs.clone(),
            Projective::<G2>::generator(),
        )?;
        let r_g = generator.scalar_mul_le(rerandomization.to_bits_le()?.iter())?;

        // Variable-base multiplication: r' * pk_shuffler
        let r_pk = shuffler_pk.scalar_mul_le(rerandomization.to_bits_le()?.iter())?;

        // c1' = c1 + r' * g
        let c1_prime = ciphertext.c1.clone() + r_g;

        // c2' = c2 + r' * pk_shuffler
        let c2_prime = ciphertext.c2.clone() + r_pk;

        Ok(ElGamalCiphertextVar::new(c1_prime, c2_prime))
    }

    /// Verify that a deck has been correctly re-randomized
    #[tracing::instrument(target = "elgamal::verify_rerandomization", skip_all)]
    pub fn verify_rerandomization(
        cs: ConstraintSystemRef<G1::BaseField>,
        input_deck: Vec<ElGamalCiphertextVar<G2>>,
        output_deck: Vec<ElGamalCiphertextVar<G2>>,
        rerandomizations: Vec<FpVar<G1::BaseField>>,
        shuffler_pk: &ProjectiveVar<G2, FpVar<G2::BaseField>>,
        permutation: Vec<usize>,
    ) -> Result<(), SynthesisError> {
        if input_deck.len() != output_deck.len() || input_deck.len() != rerandomizations.len() {
            tracing::error!("Input and output decks have different lengths");
            return Err(SynthesisError::Unsatisfiable);
        }

        // For each card, verify that output[i] = rerandomize(input[perm[i]], r[i])
        for (i, perm_idx) in permutation.iter().enumerate() {
            // Compute expected re-randomization
            let expected = Self::rerandomize_ciphertext(
                cs.clone(),
                &input_deck[*perm_idx],
                &rerandomizations[i],
                shuffler_pk,
            )?;

            // Verify c1 matches
            expected.c1.enforce_equal(&output_deck[i].c1)?;

            // Verify c2 matches
            expected.c2.enforce_equal(&output_deck[i].c2)?;
        }

        Ok(())
    }
}
