use super::error::ShuffleError;
use crate::shuffling::batch_allocate_ciphertexts;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
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
    pub fn new(cards: Vec<ElGamalCiphertext<C>>) -> Result<Self, ShuffleError> {
        if cards.len() != DECK_SIZE {
            return Err(ShuffleError::InvalidDeckSize(cards.len()));
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
    ) -> Result<Self, ShuffleError> {
        if sorted_deck.len() != DECK_SIZE || rerandomization_values.len() != DECK_SIZE {
            return Err(ShuffleError::InvalidDeckSize(sorted_deck.len()));
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
        let _span =
            tracing::debug_span!(target: "shuffle::alloc", "alloc_elgamal_ciphertext").entered();

        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        // Allocate as ProjectiveVar directly
        tracing::trace!(target: "shuffle::alloc", "Allocating c1 ProjectiveVar");
        let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c1),
            mode,
        )?;

        tracing::trace!(target: "shuffle::alloc", "Allocating c2 ProjectiveVar");
        let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
            cs.clone(),
            || Ok(ciphertext.c2),
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

        tracing::debug!(target: "shuffle::alloc", "Starting optimized allocation");

        // Batch allocate input deck
        let input_deck = batch_allocate_ciphertexts(cs.clone(), &proof.input_deck.cards, mode)?;

        tracing::debug!(target: "shuffle::alloc", "Starting optimized for sorted deck");
        // Allocate sorted deck WITHOUT affine conversion
        let mut sorted_deck = Vec::with_capacity(proof.sorted_deck.len());
        for (ct, random_val) in &proof.sorted_deck {
            let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
                cs.clone(),
                || Ok(ct.c1),
                mode,
            )?;

            let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
                cs.clone(),
                || Ok(ct.c2),
                mode,
            )?;

            let random_var =
                FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*random_val), mode)?;

            sorted_deck.push((ElGamalCiphertextVar { c1, c2 }, random_var));
        }

        tracing::debug!(target: "shuffle::alloc", "Starting optimized for rerandomization values");
        // Batch allocate rerandomization values
        let rerandomization_values: Result<Vec<_>, _> = proof
            .rerandomization_values
            .iter()
            .map(|val| FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*val), mode))
            .collect();

        tracing::debug!(target: "shuffle::alloc", "Finished allocating proof");
        Ok(Self {
            input_deck,
            sorted_deck,
            rerandomization_values: rerandomization_values?,
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
