use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;
use ark_relations::{ns, r1cs};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DECK_SIZE: usize = 52;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalCiphertext<C: CurveGroup> {
    pub c1: C,
    pub c2: C,
}

impl<C: CurveGroup> ElGamalCiphertext<C>
where
    C::BaseField: PrimeField,
{
    pub fn new(c1: C, c2: C) -> Self {
        Self { c1, c2 }
    }

    pub fn add_encryption_layer(&self, randomness: C::BaseField, public_key: C) -> Self {
        let generator = C::generator();
        let randomness_bigint = randomness.into_bigint(); // TODO: Maybe we can optimize this to use the appropriate scalar field

        Self {
            c1: self.c1 + generator.mul_bigint(randomness_bigint),
            c2: self.c2 + public_key.mul_bigint(randomness_bigint),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedDeck<C: CurveGroup> {
    pub cards: Vec<ElGamalCiphertext<C>>,
}

impl<C: CurveGroup> EncryptedDeck<C> {
    pub fn new(cards: Vec<ElGamalCiphertext<C>>) -> Result<Self, crate::ShuffleError> {
        if cards.len() != DECK_SIZE {
            return Err(crate::ShuffleError::InvalidDeckSize(cards.len()));
        }
        Ok(Self { cards })
    }
}

#[derive(Clone, Debug)]
pub struct ElGamalKeys<C: CurveGroup> {
    pub private_key: C::ScalarField,
    pub public_key: C,
}

impl<C: CurveGroup> ElGamalKeys<C> {
    pub fn new(private_key: C::ScalarField) -> Self {
        let generator = C::generator();
        let private_key_bigint = private_key.into_bigint();
        let public_key = generator.mul_bigint(private_key_bigint);
        Self { private_key, public_key }
    }
}

#[derive(Clone, Debug)]
pub struct ShuffleProof<C: CurveGroup> {
    pub input_deck: EncryptedDeck<C>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    pub sorted_deck: Vec<(ElGamalCiphertext<C>, C::BaseField)>,
    pub rerandomization_values: Vec<C::BaseField>,
}

impl<C: CurveGroup> ShuffleProof<C> {
    pub fn new(
        input_deck: EncryptedDeck<C>,
        sorted_deck: Vec<(ElGamalCiphertext<C>, C::BaseField)>,
        rerandomization_values: Vec<C::BaseField>,
    ) -> Result<Self, crate::ShuffleError> {
        if sorted_deck.len() != DECK_SIZE || rerandomization_values.len() != DECK_SIZE {
            return Err(crate::ShuffleError::InvalidDeckSize(sorted_deck.len()));
        }
        Ok(Self {
            input_deck,
            sorted_deck,
            rerandomization_values,
        })
    }
}

// Circuit representation of ElGamal ciphertext
pub struct ElGamalCiphertextVar<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub c1: ProjectiveVar<G, FpVar<G::BaseField>>,
    pub c2: ProjectiveVar<G, FpVar<G::BaseField>>,
}

impl<G: SWCurveConfig> ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    /// Creates a new ElGamal ciphertext variable from two curve variables
    pub fn new(
        c1: ProjectiveVar<G, FpVar<G::BaseField>>,
        c2: ProjectiveVar<G, FpVar<G::BaseField>>,
    ) -> Self {
        Self { c1, c2 }
    }
}

impl<G: SWCurveConfig> AllocVar<ElGamalCiphertext<Projective<G>>, G::BaseField>
    for ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ElGamalCiphertext<Projective<G>>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let _span = tracing::debug_span!(target: "shuffle::alloc", "alloc_elgamal_ciphertext").entered();
        
        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        // Convert projective points to affine
        tracing::trace!(target: "shuffle::alloc", "Converting projective points to affine");
        let c1_affine: Affine<G> = ciphertext.c1.into_affine();
        let c2_affine: Affine<G> = ciphertext.c2.into_affine();

        // Allocate as ProjectiveVar directly
        tracing::trace!(target: "shuffle::alloc", "Allocating c1 ProjectiveVar");
        let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            ns!(cs.clone(), "c1"),
            || Ok(c1_affine),
            mode,
        )?;

        tracing::trace!(target: "shuffle::alloc", "Allocating c2 ProjectiveVar");
        let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            ns!(cs.clone(), "c2"),
            || Ok(c2_affine),
            mode,
        )?;

        Ok(Self { c1, c2 })
    }
}

// Circuit representation of shuffled deck proof
pub struct ShuffleProofVar<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub input_deck: Vec<ElGamalCiphertextVar<G>>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    pub sorted_deck: Vec<(ElGamalCiphertextVar<G>, FpVar<G::BaseField>)>,
    pub rerandomization_values: Vec<FpVar<G::BaseField>>,
}

impl<G: SWCurveConfig> AllocVar<ShuffleProof<Projective<G>>, G::BaseField> for ShuffleProofVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ShuffleProof<Projective<G>>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let value = f()?;
        let proof = value.borrow();

        tracing::debug!(target: "shuffle::alloc", "Allocating ShuffleProofVar with deck size {}", proof.input_deck.cards.len());

        // Allocate input deck
        let input_deck_span = tracing::debug_span!(target: "shuffle::alloc", "input_deck_allocation", deck_size = proof.input_deck.cards.len());
        let _enter = input_deck_span.enter();
        
        tracing::debug!(target: "shuffle::alloc", "Starting input deck allocation");
        let mut input_deck = Vec::with_capacity(proof.input_deck.cards.len());
        for (i, card) in proof.input_deck.cards.iter().enumerate() {
            if i % 10 == 0 {
                tracing::debug!(target: "shuffle::alloc", card_index = i, "Processing batch");
            }
            let card_span = tracing::trace_span!(target: "shuffle::alloc", "alloc_card", index = i);
            let _card_enter = card_span.enter();
            
            let card_var = ElGamalCiphertextVar::<G>::new_variable(cs.clone(), || Ok(card), mode)?;
            input_deck.push(card_var);
        }
        tracing::debug!(target: "shuffle::alloc", "Input deck allocation complete");
        drop(_enter);

        // Allocate sorted deck (associated list of cards and random values)
        let sorted_deck_span = tracing::debug_span!(target: "shuffle::alloc", "sorted_deck_allocation", deck_size = proof.sorted_deck.len());
        let _enter = sorted_deck_span.enter();
        
        tracing::debug!(target: "shuffle::alloc", "Starting sorted deck allocation");
        let mut sorted_deck = Vec::with_capacity(proof.sorted_deck.len());
        for (i, (card, random_val)) in proof.sorted_deck.iter().enumerate() {
            if i % 10 == 0 {
                tracing::debug!(target: "shuffle::alloc", card_index = i, "Processing batch");
            }
            
            let card_span = tracing::trace_span!(target: "shuffle::alloc", "alloc_sorted_entry", index = i);
            let _card_enter = card_span.enter();
            
            let card_var = ElGamalCiphertextVar::<G>::new_variable(cs.clone(), || Ok(card), mode)?;
            let random_var = FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*random_val), mode)?;
            sorted_deck.push((card_var, random_var));
        }
        tracing::debug!(target: "shuffle::alloc", "Sorted deck allocation complete");
        drop(_enter);

        // Allocate rerandomization values
        tracing::debug!(target: "shuffle::alloc", "Allocating rerandomization values...");
        let rerandomization_values = proof
            .rerandomization_values
            .iter()
            .enumerate()
            .map(|(i, val)| {
                if i % 10 == 0 {
                    tracing::debug!(target: "shuffle::alloc", "Allocating rerandomization value {}/{}", i, proof.rerandomization_values.len());
                }
                FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*val), mode)
            })
            .collect::<Result<Vec<_>, _>>()?;
        tracing::debug!(target: "shuffle::alloc", "Rerandomization values allocated");

        Ok(Self {
            input_deck,
            sorted_deck,
            rerandomization_values,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetrics {
    pub setup_time: Option<Duration>,
    pub constraint_generation_time: Duration,
    pub witness_synthesis_time: Duration,
    pub commitment_time: Duration,
    pub polynomial_construction_time: Duration,
    pub proof_generation_time: Duration,
    pub total_time: Duration,
    pub constraint_count: usize,
    pub witness_count: usize,
    pub proof_size_bytes: usize,
}

impl Default for ProofMetrics {
    fn default() -> Self {
        Self {
            setup_time: None,
            constraint_generation_time: Duration::default(),
            witness_synthesis_time: Duration::default(),
            commitment_time: Duration::default(),
            polynomial_construction_time: Duration::default(),
            proof_generation_time: Duration::default(),
            total_time: Duration::default(),
            constraint_count: 0,
            witness_count: 0,
            proof_size_bytes: 0,
        }
    }
}
