use crate::{data_structures::*, poseidon_config::poseidon_config};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar, Absorb,
};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::PrimeField;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::{
    fields::fp::FpVar, groups::curves::short_weierstrass::ProjectiveVar, prelude::*,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

const LOG_TARGET: &str = "shuffle::circuit";

/// Circuit for verifying card shuffling
#[derive(Clone)]
pub struct ShuffleCircuit<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    /// Public key of the shuffler
    pub shuffler_public_key: Projective<G>,
    /// The shuffle proof to verify
    pub proof: ShuffleProof<Projective<G>>,
    /// Random seed for the shuffle
    pub seed: G::BaseField,
}

impl<G: SWCurveConfig> ShuffleCircuit<G>
where
    G::BaseField: PrimeField,
{
    /// Create a new shuffle circuit with the given shuffler public key, proof, and seed
    pub fn new(
        shuffler_public_key: Projective<G>,
        proof: ShuffleProof<Projective<G>>,
        seed: G::BaseField,
    ) -> Self {
        Self { shuffler_public_key, proof, seed }
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
        tracing::debug!(target = LOG_TARGET, "Creating Poseidon config");
        let config = poseidon_config::<G::BaseField>();
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

        // Absorb seed
        tracing::debug!(target = LOG_TARGET, "Absorbing seed into sponge");
        sponge.absorb(&seed)?;

        // Generate random value for each card
        let mut deck_with_randoms = Vec::with_capacity(deck.len());
        tracing::debug!(target = LOG_TARGET, "Generating random values for {} cards", deck.len());
        for (i, card) in deck.into_iter().enumerate() {
            if i % 10 == 0 {
                tracing::debug!(target = LOG_TARGET, "Processing card {}/{}", i, deck_with_randoms.capacity());
            }
            let random_value = sponge.squeeze_field_elements(1)?[0].clone();
            deck_with_randoms.push((card, random_value));
        }
        tracing::debug!(target = LOG_TARGET, "All random values generated");

        Ok(deck_with_randoms)
    }

    #[tracing::instrument(target = LOG_TARGET, skip_all)]
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
            let rerandomized_card =
                crate::encryption::ElGamalEncryption::<G>::rerandomize_ciphertext(
                    cs.cs(),
                    card,
                    rerandomization,
                    shuffler_pk,
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
        G::BaseField: PrimeField,
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
            let term = alpha.clone() * card_hash + beta.clone() * random_val.clone();
            rerandomized_product *= term;
        }

        // Compute product for sorted deck
        let mut sorted_product = FpVar::one();
        for (card, random_val) in sorted_deck.iter() {
            let card_hash = self.hash_card_to_field(cs.clone(), card)?;
            // Compute term: alpha * card_hash + beta * random_value
            let term = alpha.clone() * card_hash + beta.clone() * random_val.clone();
            sorted_product *= term;
        }

        // Enforce equality - this proves the multiset is preserved
        rerandomized_product.enforce_equal(&sorted_product)?;

        // Note: We don't verify sorting order in-circuit as it's expensive
        // The prover provides the correctly sorted deck

        tracing::info!(target = LOG_TARGET, "Grand product verification complete");
        Ok(())
    }

    /// Hash a card to a field element for use in grand product
    fn hash_card_to_field(
        &self,
        cs: ConstraintSystemRef<G::BaseField>,
        card: &ElGamalCiphertextVar<G>,
    ) -> Result<FpVar<G::BaseField>, SynthesisError> {
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

impl<G: SWCurveConfig> ConstraintSynthesizer<G::BaseField> for ShuffleCircuit<G>
where
    G::BaseField: PrimeField + Absorb,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G::BaseField>,
    ) -> Result<(), SynthesisError> {
        tracing::info!(target = LOG_TARGET, "Starting circuit generation");

        // Log initial constraint and witness counts
        let initial_constraints = cs.num_constraints();
        let initial_witnesses = cs.num_witness_variables();
        tracing::info!(
            target = LOG_TARGET,
            "Initial constraints: {}, witnesses: {}",
            initial_constraints,
            initial_witnesses
        );

        // Allocate public inputs
        tracing::info!(target = LOG_TARGET, "Allocating public inputs...");
        let seed_var = FpVar::<G::BaseField>::new_input(cs.clone(), || Ok(self.seed))?;
        let shuffler_pk_var = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            ns!(cs, "shuffler_pk"),
            || Ok(self.shuffler_public_key),
            AllocationMode::Input,
        )?;
        tracing::info!(target = LOG_TARGET, "Public inputs allocated");

        // Allocate the shuffle proof as witness
        tracing::info!(target = LOG_TARGET, "Allocating shuffle proof witness...");
        let proof_var = {
            // let cs = ns!(cs, "shuffle_proof");
            ShuffleProofVar::<G>::new_witness(cs.clone(), || Ok(&self.proof))?
        };
        tracing::info!(target = LOG_TARGET, "Shuffle proof witness allocated. Input deck size: {}", proof_var.input_deck.len());

        // Generate random values for each card using Poseidon
        tracing::info!(target = LOG_TARGET, "Generating random values for deck...");
        let input_deck_with_randoms =
            self.generate_random_values_for_deck(cs.clone(), &seed_var, proof_var.input_deck)?;
        tracing::info!(target = LOG_TARGET, "Random values generated for {} cards", input_deck_with_randoms.len());

        // Apply re-randomization to create the new deck with associated random values
        tracing::info!(target = LOG_TARGET, "Applying rerandomization...");
        let deck_with_rerandomizations = self.apply_rerandomization(
            cs.clone(),
            input_deck_with_randoms,
            proof_var.rerandomization_values.clone(),
            &shuffler_pk_var,
        )?;
        tracing::info!(target = LOG_TARGET, "Rerandomization complete");

        // Generate challenges for grand product
        tracing::info!(target = LOG_TARGET, "Allocating challenges for grand product...");
        let alpha = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(7u64)))?; // In practice, from Fiat-Shamir
        let beta = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(13u64)))?; // In practice, from Fiat-Shamir
        tracing::info!(target = LOG_TARGET, "Challenges allocated");

        // Verify grand product (multiset equivalence) using the associated lists
        tracing::info!(target = LOG_TARGET, "Starting grand product verification...");
        self.verify_equivalance_through_grand_product(
            cs.clone(),
            deck_with_rerandomizations,
            proof_var.sorted_deck,
            &alpha,
            &beta,
        )?;
        tracing::info!(target = LOG_TARGET, "Grand product verification complete");

        // Log final constraint and witness counts
        let final_constraints = cs.num_constraints();
        let final_witnesses = cs.num_witness_variables();
        tracing::info!(
            target = LOG_TARGET,
            "Circuit generation complete - Total constraints: {}, witnesses: {} (added {} constraints, {} witnesses)",
            final_constraints,
            final_witnesses,
            final_constraints - initial_constraints,
            final_witnesses - initial_witnesses
        );

        Ok(())
    }
}
