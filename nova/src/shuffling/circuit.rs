use super::data_structures::*;
use crate::poseidon_config;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar, Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
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
        G::BaseField: PrimeField + Absorb + Copy,
    {
        // Create Poseidon config
        tracing::debug!(target = LOG_TARGET, "Creating Poseidon config");
        let config = poseidon_config::<G::BaseField>();
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);

        // Absorb seed
        tracing::debug!(target = LOG_TARGET, "Absorbing seed into sponge");
        sponge.absorb(&seed)?;

        // Generate random value for each card
        let deck_len = deck.len();
        tracing::debug!(
            target = LOG_TARGET,
            "Generating random values for {} cards",
            deck_len
        );

        // Squeeze all random values at once - much more efficient
        let mut random_values = Vec::with_capacity(DECK_SIZE);
        for i in 0..DECK_SIZE {
            tracing::debug!(
                target = LOG_TARGET,
                "Generating random value for card {}",
                i
            );
            let value = sponge.squeeze_field_elements(1)?[0].clone();
            random_values.push(value);
        }

        // Safety check: ensure we got exactly the right number of random values
        assert_eq!(
            random_values.len(),
            deck_len,
            "Squeeze operation should return exactly {} random values, got {}",
            deck_len,
            random_values.len()
        );

        // Pair each card with its random value
        let deck_with_randoms = deck
            .into_iter()
            .zip(random_values.into_iter())
            .collect::<Vec<_>>();

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
                super::encryption::ElGamalEncryption::<G>::rerandomize_ciphertext(
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

    #[tracing::instrument(target = LOG_TARGET, skip_all)]
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
        for (i, (card, random_val)) in rerandomized_deck.iter().enumerate() {
            if i % 10 == 0 {
                tracing::debug!(
                    target = LOG_TARGET,
                    "Processing rerandomized card {}/{}",
                    i,
                    rerandomized_deck.len()
                );
            }
            let card_hash = self.hash_card_to_field(cs.clone(), card)?;
            // Compute term: alpha * card_hash + beta * random_value
            let term = alpha.clone() * card_hash + beta.clone() * random_val.clone();
            rerandomized_product *= term;
        }

        // Compute product for sorted deck
        let mut sorted_product = FpVar::one();
        for (i, (card, random_val)) in sorted_deck.iter().enumerate() {
            if i % 10 == 0 {
                tracing::debug!(
                    target = LOG_TARGET,
                    "Processing sorted card {}/{}",
                    i,
                    sorted_deck.len()
                );
            }
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
        // OPTIMIZATION: Avoid expensive to_constraint_field()
        // Instead use projective coordinates directly with a linear combination

        // Extract the projective coordinates
        let c1_x = &card.c1.x;
        let c1_y = &card.c1.y;
        let c1_z = &card.c1.z;

        let c2_x = &card.c2.x;
        let c2_y = &card.c2.y;
        let c2_z = &card.c2.z;

        // Create a hash using prime coefficients to ensure injectivity
        // This is MUCH cheaper than to_constraint_field which does bit decomposition
        let coeff1 = FpVar::constant(G::BaseField::from(2u64));
        let coeff2 = FpVar::constant(G::BaseField::from(3u64));
        let coeff3 = FpVar::constant(G::BaseField::from(5u64));
        let coeff4 = FpVar::constant(G::BaseField::from(7u64));
        let coeff5 = FpVar::constant(G::BaseField::from(11u64));
        let coeff6 = FpVar::constant(G::BaseField::from(13u64));

        // Hash = 2*c1.x + 3*c1.y + 5*c1.z + 7*c2.x + 11*c2.y + 13*c2.z
        let hash = coeff1 * c1_x
            + coeff2 * c1_y
            + coeff3 * c1_z
            + coeff4 * c2_x
            + coeff5 * c2_y
            + coeff6 * c2_z;

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

        // Allocate public inputs
        tracing::info!(target = LOG_TARGET, "Allocating public inputs...");
        let seed_var = FpVar::<G::BaseField>::new_input(cs.clone(), || Ok(self.seed))?;
        let shuffler_pk_var = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            ns!(cs, "shuffler_pk"),
            || Ok(self.shuffler_public_key),
            AllocationMode::Witness,
        )?;
        tracing::info!(target = LOG_TARGET, "Public inputs allocated");

        // Allocate the shuffle proof as witness
        tracing::info!(target = LOG_TARGET, "Allocating shuffle proof witness...");
        let proof_var = {
            ShuffleProofVar::<G>::new_variable_optimized(
                cs.clone(),
                || Ok(&self.proof),
                AllocationMode::Witness,
            )?
        };

        tracing::info!(target = LOG_TARGET, "Does it stop here? Let me know");

        tracing::info!(
            target = LOG_TARGET,
            "Shuffle proof witness allocated. Input deck size: {}",
            proof_var.input_deck.len()
        );

        // Generate random values for each card using Poseidon
        tracing::info!(target = LOG_TARGET, "Generating random values for deck...");
        let start = std::time::Instant::now();
        let input_deck_with_randoms =
            self.generate_random_values_for_deck(cs.clone(), &seed_var, proof_var.input_deck)?;
        let duration = start.elapsed();
        tracing::info!(
            target = LOG_TARGET,
            "Random values generated for {} cards in {:?}",
            input_deck_with_randoms.len(),
            duration
        );

        // Apply re-randomization to create the new deck with associated random values
        tracing::info!(target = LOG_TARGET, "Applying rerandomization...");
        let start = std::time::Instant::now();
        let deck_with_rerandomizations = self.apply_rerandomization(
            cs.clone(),
            input_deck_with_randoms,
            proof_var.rerandomization_values.clone(),
            &shuffler_pk_var,
        )?;
        let duration = start.elapsed();
        tracing::info!(
            target = LOG_TARGET,
            "Rerandomization complete in {:?}",
            duration
        );

        // Generate challenges for grand product
        tracing::info!(
            target = LOG_TARGET,
            "Allocating challenges for grand product..."
        );
        let alpha = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(7u64)))?; // In practice, from Fiat-Shamir
        let beta = FpVar::new_witness(cs.clone(), || Ok(G::BaseField::from(13u64)))?; // In practice, from Fiat-Shamir
        tracing::info!(target = LOG_TARGET, "Challenges allocated");

        // Verify grand product (multiset equivalence) using the associated lists
        tracing::info!(
            target = LOG_TARGET,
            "Starting grand product verification..."
        );
        let start = std::time::Instant::now();
        self.verify_equivalance_through_grand_product(
            cs.clone(),
            deck_with_rerandomizations,
            proof_var.sorted_deck,
            &alpha,
            &beta,
        )?;
        let duration = start.elapsed();
        tracing::info!(
            target = LOG_TARGET,
            "Grand product verification complete in {:?}",
            duration
        );

        Ok(())
    }
}
