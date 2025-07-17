use crate::{data_structures::*, error::ShuffleError, utils::generate_random_values};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup, Group,
};
use ark_ff::PrimeField;
use ark_std::UniformRand;

#[tracing::instrument(target = "shuffle::subprotocol", skip(input_deck, shuffler_keys))]
pub fn prove_as_subprotocol<G1: SWCurveConfig, G2: SWCurveConfig>(
    seed: G1::BaseField,
    input_deck: EncryptedDeck<G2>,
    shuffler_keys: &ElGamalKeys<G2>,
) -> Result<ShuffleProof<G2>, ShuffleError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
{
    tracing::info!(
        target = "shuffle::subprotocol",
        "Starting shuffle proof generation"
    );

    // 1. Generate random values for sorting using Poseidon with seed
    let random_sorting_values = generate_random_values::<G1::BaseField>(seed, DECK_SIZE);
    tracing::debug!(
        target = "shuffle::subprotocol",
        "Generated {} random sorting values",
        DECK_SIZE
    );

    // 2. Generate rerandomization values r'_i (scalars for G1, which is the base field of G2)
    let mut rng = ark_std::test_rng(); // In production, use a secure RNG
    let rerandomization_values: Vec<G1::BaseField> = (0..DECK_SIZE)
        .map(|_| G1::BaseField::rand(&mut rng))
        .collect();
    tracing::debug!(
        target = "shuffle::subprotocol",
        "Generated {} rerandomization values",
        DECK_SIZE
    );

    // 3. Add encryption layer to each card (operations on G2):
    //    - New c1 = c1 + r'_i * G
    //    - New c2 = c2 + r'_i * Y (where Y is shuffler's public key)
    let rerandomized_cards: Vec<ElGamalCiphertext<G2>> = input_deck
        .cards
        .iter()
        .zip(&rerandomization_values)
        .map(|(card, &rerand)| card.add_encryption_layer(rerand, shuffler_keys.public_key))
        .collect();
    tracing::debug!(target = "shuffle::subprotocol", "Re-randomized all cards");

    // 4. Create associated list: [(re_randomized_card_i, random_value_i)]
    let associated_list: Vec<(ElGamalCiphertext<G2>, G2::ScalarField)> = rerandomized_cards
        .into_iter()
        .zip(random_sorting_values)
        .collect();

    // 5. Sort by random values to get the sorted deck
    let mut sorted_associated_list = associated_list;
    sorted_associated_list.sort_by(|a, b| a.1.cmp(&b.1));

    // 6. Return ShuffleProof with all components
    let proof = ShuffleProof::new(input_deck, sorted_associated_list, rerandomization_values)?;

    tracing::info!(
        target = "shuffle::subprotocol",
        "Shuffle proof generation complete"
    );
    Ok(proof)
}
