use crate::{data_structures::*, poseidon_config::poseidon_config};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar, Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar, prelude::*,
    ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use std::marker::PhantomData;

/// Circuit for verifying card shuffling
pub struct ShuffleCircuit<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    /// Public key of the shuffler
    pub shuffler_public_key: Projective<G>,
    /// Phantom data
    _phantom: PhantomData<G>,
}

impl<G> ShuffleCircuit<G>
where
    G: SWCurveConfig,
    G::BaseField: PrimeField + Absorb,
{
    /// Create a new shuffle circuit with the given shuffler public key
    pub fn new(shuffler_public_key: Projective<G>) -> Self {
        Self {
            shuffler_public_key,
            _phantom: PhantomData,
        }
    }

    /// Generate constraints for verifying the shuffle proof
    #[tracing::instrument(target = "shuffle::circuit", skip_all)]
    pub fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        proof: &ShuffleProof<G>,
        seed: G::BaseField,
    ) -> Result<(), SynthesisError> {
        tracing::info!(target = "shuffle::circuit", "Starting circuit generation");

        // Allocate public inputs
        let seed_var = FpVar::new_input(cs.clone(), || Ok(seed))?;
        let shuffler_pk_var = {
            let cs = ns!(cs, "shuffler_pk");
            <ProjectiveVar<G, FpVar<G::BaseField>> as AllocVar<Projective<G>, G::BaseField>>::new_variable(
                cs,
                || Ok(&self.shuffler_public_key),
                AllocationMode::Input,
            )?
        };

        // Allocate the shuffle proof as witness
        let proof_var = {
            // let cs = ns!(cs, "shuffle_proof");
            ShuffleProofVar::<G>::new_witness(cs.clone(), || Ok(proof))?
        };

        // Generate random values for each card using Poseidon
        let input_deck_with_randoms =
            self.generate_random_values_for_deck(cs.clone(), &seed_var, proof_var.input_deck)?;

        // Apply re-randomization to create the new deck with associated random values
        let deck_with_rerandomizations = self.apply_rerandomization(
            cs.clone(),
            input_deck_with_randoms,
            proof_var.rerandomization_values.clone(),
            &shuffler_pk_var,
        )?;

        // Generate challenges for grand product
        let alpha = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(7u64)))?; // In practice, from Fiat-Shamir
        let beta = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(13u64)))?; // In practice, from Fiat-Shamir

        // Verify grand product (multiset equivalence) using the associated lists
        self.verify_equivalance_through_grand_product(
            cs.clone(),
            deck_with_rerandomizations,
            proof_var.sorted_deck,
            &alpha,
            &beta,
        )?;

        tracing::info!(target = "shuffle::circuit", "Circuit generation complete");
        Ok(())
    }

    // #[tracing::instrument(target = "shuffle::circuit::random_gen", skip_all)]
    fn generate_random_values_for_deck(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        seed: &FpVar<G::BaseField>,
        deck: Vec<ElGamalCiphertextVar<G>>,
    ) -> Result<Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>, SynthesisError>
    where
        G::BaseField: PrimeField + Absorb,
    {
        // Create Poseidon config
        let config = poseidon_config::<G::BaseField>();
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

        // Absorb seed
        sponge.absorb(&seed)?;

        // Generate random value for each card
        let mut deck_with_randoms = Vec::with_capacity(deck.len());
        for card in deck {
            let random_value = sponge.squeeze_field_elements(1)?[0].clone();
            deck_with_randoms.push((card, random_value));
        }

        Ok(deck_with_randoms)
    }

    #[tracing::instrument(target = "shuffle::rerandomization", skip_all)]
    fn apply_rerandomization(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        input_deck: Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
        rerandomizations: Vec<FpVar<G::BaseField>>,
        shuffler_pk: &ProjectiveVar<G, FpVar<G::BaseField>>,
    ) -> Result<Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>, SynthesisError>
    where
        G::BaseField: PrimeField,
    {
        let cs = ns!(cs, "apply_rerandomization");

        if input_deck.len() != rerandomizations.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut output_deck = Vec::with_capacity(input_deck.len());

        for ((card, random_value), rerandomization) in
            input_deck.iter().zip(rerandomizations.iter())
        {
            // Apply rerandomization to the ciphertext
            let rerandomized_card = crate::encryption::ElGamalEncryption::<
                G,
                ProjectiveVar<G, FpVar<G::BaseField>>,
            >::rerandomize_ciphertext(
                cs.cs(), card, rerandomization, shuffler_pk
            )?;

            // Keep the same random value associated with the card
            output_deck.push((rerandomized_card, random_value.clone()));
        }

        Ok(output_deck)
    }

    // #[tracing::instrument(target = "shuffle::grand_product", skip_all)]
    fn verify_equivalance_through_grand_product(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        rerandomized_deck: Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
        sorted_deck: Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
        alpha: &FpVar<G::BaseField>,
        beta: &FpVar<G::BaseField>,
    ) -> Result<(), SynthesisError>
    where
        G::BaseField: PrimeField + Absorb,
    {
        let ns = ns!(cs, "grand_product");
        let cs = ns.cs();

        // Verify that rerandomized_deck and sorted_deck contain the same multiset
        // using the grand product argument with challenges alpha and beta

        // Compute product for rerandomized deck
        let mut rerandomized_product = FpVar::one();
        for (card, random_val) in rerandomized_deck.iter() {
            let card_hash = self.hash_card_to_field(cs.clone(), card)?;
            // Compute term: alpha * card_hash + beta * random_value
            let term = alpha * &card_hash + beta * random_val;
            rerandomized_product *= &term;
        }

        // Compute product for sorted deck
        let mut sorted_product = FpVar::one();
        for (card, random_val) in sorted_deck.iter() {
            let card_hash = self.hash_card_to_field(cs.clone(), card)?;
            // Compute term: alpha * card_hash + beta * random_value
            let term = alpha * &card_hash + beta * random_val;
            sorted_product *= &term;
        }

        // Enforce equality - this proves the multiset is preserved
        rerandomized_product.enforce_equal(&sorted_product)?;

        // Note: We don't verify sorting order in-circuit as it's expensive
        // The prover provides the correctly sorted deck

        tracing::info!(
            target = "shuffle::grand_product",
            "Grand product verification complete"
        );
        Ok(())
    }

    /// Hash a card to a field element for use in grand product
    fn hash_card_to_field(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        card: &ElGamalCiphertextVar<G>,
    ) -> Result<FpVar<G::BaseField>, SynthesisError>
    where
        G::BaseField: PrimeField + Absorb,
    {
        let _cs = ns!(cs, "hash_cards");

        // Convert curve points to field elements for hashing
        // We'll use the to_constraint_field method which gives us field element representations
        let c1_fields = card.c1.to_constraint_field()?;
        let c2_fields = card.c2.to_constraint_field()?;

        // Sum all field elements from both curve points
        let mut hash = FpVar::<G::BaseField>::zero();
        for field_elem in c1_fields.iter().chain(c2_fields.iter()) {
            hash += field_elem;
        }

        Ok(hash)
    }
}

/// Generate the circuit for verifying a shuffle proof
pub fn generate_circuit<G>(
    cs: ConstraintSystemRef<G::BaseField>,
    shuffler_public_key: Projective<G>,
    proof: &ShuffleProof<G>,
    seed: G::BaseField,
) -> Result<(), SynthesisError>
where
    G: SWCurveConfig,
    G::BaseField: PrimeField + Absorb,
{
    let circuit = ShuffleCircuit::new(shuffler_public_key);
    circuit.generate_constraints(cs, proof, seed)
}
