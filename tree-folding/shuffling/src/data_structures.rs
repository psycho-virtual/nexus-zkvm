use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    Group,
};
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
pub struct ElGamalCiphertext<G: SWCurveConfig> {
    pub c1: Projective<G>,
    pub c2: Projective<G>,
}

impl<G: SWCurveConfig> ElGamalCiphertext<G> {
    pub fn new(c1: Projective<G>, c2: Projective<G>) -> Self {
        Self { c1, c2 }
    }

    pub fn add_encryption_layer(&self, randomness: G::BaseField, public_key: Projective<G>) -> Self
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        let generator = <Projective<G> as Group>::generator();
        // Convert BaseField to ScalarField via BigInt
        let randomness_bigint = randomness.into_bigint();

        Self {
            c1: self.c1 + generator.mul_bigint(randomness_bigint),
            c2: self.c2 + public_key.mul_bigint(randomness_bigint),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedDeck<G: SWCurveConfig> {
    pub cards: Vec<ElGamalCiphertext<G>>,
}

impl<G: SWCurveConfig> EncryptedDeck<G> {
    pub fn new(cards: Vec<ElGamalCiphertext<G>>) -> Result<Self, crate::ShuffleError> {
        if cards.len() != DECK_SIZE {
            return Err(crate::ShuffleError::InvalidDeckSize(cards.len()));
        }
        Ok(Self { cards })
    }
}

#[derive(Clone, Debug)]
pub struct ElGamalKeys<G: SWCurveConfig> {
    pub private_key: G::BaseField,
    pub public_key: Projective<G>,
}

impl<G: SWCurveConfig> ElGamalKeys<G> {
    pub fn new(private_key: G::BaseField) -> Self
    where
        G::BaseField: PrimeField,
        G::ScalarField: PrimeField,
    {
        let generator = <Projective<G> as Group>::generator();
        // Convert BaseField to ScalarField via BigInt
        let private_key_bigint = private_key.into_bigint();
        let public_key = generator.mul_bigint(private_key_bigint);
        Self { private_key, public_key }
    }
}

#[derive(Clone, Debug)]
pub struct ShuffleProof<G: SWCurveConfig>
where
    G::BaseField: PrimeField,
{
    pub input_deck: EncryptedDeck<G>,
    /// Sorted list of (encrypted card, random value) pairs, sorted by random value in ascending order
    pub sorted_deck: Vec<(ElGamalCiphertext<G>, G::BaseField)>,
    pub rerandomization_values: Vec<G::BaseField>,
}

impl<G: SWCurveConfig> ShuffleProof<G>
where
    G::BaseField: PrimeField,
{
    pub fn new(
        input_deck: EncryptedDeck<G>,
        sorted_deck: Vec<(ElGamalCiphertext<G>, G::BaseField)>,
        rerandomization_values: Vec<G::BaseField>,
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
#[derive(Clone)]
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

impl<G: SWCurveConfig> AllocVar<ElGamalCiphertext<G>, G::BaseField> for ElGamalCiphertextVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ElGamalCiphertext<G>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let value = f()?;
        let ciphertext = value.borrow();

        let c1 = {
            let cs_c1 = ns!(cs.clone(), "c1");
            <ProjectiveVar<G, FpVar<G::BaseField>> as AllocVar<Projective<G>, G::BaseField>>::new_variable(
                cs_c1,
                || Ok(ciphertext.c1),
                mode,
            )?
        };
        let c2 = {
            let cs_c2 = ns!(cs.clone(), "c2");
            <ProjectiveVar<G, FpVar<G::BaseField>> as AllocVar<Projective<G>, G::BaseField>>::new_variable(
                cs_c2,
                || Ok(ciphertext.c2),
                mode,
            )?
        };

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

impl<G: SWCurveConfig> AllocVar<ShuffleProof<G>, G::BaseField> for ShuffleProofVar<G>
where
    G::BaseField: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<ShuffleProof<G>>>(
        cs: impl Into<r1cs::Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let value = f()?;
        let proof = value.borrow();

        // Allocate input deck
        let input_deck = proof
            .input_deck
            .cards
            .iter()
            .map(|card| ElGamalCiphertextVar::<G>::new_variable(cs.clone(), || Ok(card), mode))
            .collect::<Result<Vec<_>, _>>()?;

        // Allocate sorted deck (associated list of cards and random values)
        let sorted_deck = proof
            .sorted_deck
            .iter()
            .map(|(card, random_val)| {
                let card_var =
                    { ElGamalCiphertextVar::<G>::new_variable(cs.clone(), || Ok(card), mode)? };
                let random_var =
                    { FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*random_val), mode)? };
                Ok((card_var, random_var))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Allocate rerandomization values
        let rerandomization_values = proof
            .rerandomization_values
            .iter()
            .enumerate()
            .map(|(_i, val)| FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*val), mode))
            .collect::<Result<Vec<_>, _>>()?;

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
