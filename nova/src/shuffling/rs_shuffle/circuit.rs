//! Main circuit implementation for RS shuffle with constraint generation

use super::data_structures::{NextRowVar, UnsortedRowVar, WitnessData, WitnessDataVar};
use super::permutation::{check_grand_product, IndexPositionPair, IndexedElGamalCiphertext};
use super::{LEVELS, N};
use crate::shuffling::data_structures::{ElGamalCiphertext, ElGamalCiphertextVar};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::FieldVar,
};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::*;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use std::ops::Add;
use std::ops::Mul;
use std::ops::Not;

/// Main RS Shuffle Circuit
pub struct RSShuffleCircuit<F, C>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
{
    /// Public: Initial ciphertexts
    pub ct_init_pub: Vec<ElGamalCiphertext<C>>,
    /// Public: Random seed for deriving split bits
    pub seed_pub: F,

    /// Private: Witness data for all levels
    pub witness: WitnessData,
    /// Public: Fiat-Shamir challenges (same for all levels)
    pub alpha: F,
    pub beta: F, // beta_2 through beta_6 are computed as powers of beta
    pub ct_after_shuffle: Vec<ElGamalCiphertext<C>>,
}

impl<F, C> RSShuffleCircuit<F, C>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
{
    /// Create a new RS shuffle circuit
    pub fn new(
        ct_init: Vec<ElGamalCiphertext<C>>,
        ct_after_shuffle: Vec<ElGamalCiphertext<C>>,
        seed: F,
        witness: WitnessData,
        alpha: F,
        beta: F,
    ) -> Self {
        Self {
            ct_init_pub: ct_init,
            seed_pub: seed,
            witness,
            alpha,
            beta,
            ct_after_shuffle,
        }
    }

    /// Derive Fiat-Shamir challenges from seed
    pub fn derive_challenges(_seed: &[u8]) -> (F, F) {
        // TODO: Implement actual Fiat-Shamir derivation using Poseidon
        (F::from(2u64), F::from(3u64)) // alpha, beta
    }
}

impl<G> ConstraintSynthesizer<G::BaseField> for RSShuffleCircuit<G::BaseField, Projective<G>>
where
    G: SWCurveConfig,
    G::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G::BaseField>,
    ) -> Result<(), SynthesisError> {
        // 1. Allocate public inputs
        let ct_init_vars: Vec<ElGamalCiphertextVar<G>> = self
            .ct_init_pub
            .iter()
            .map(|ct| {
                ElGamalCiphertextVar::<G>::new_variable(
                    cs.clone(),
                    || Ok(ct),
                    AllocationMode::Input,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Allocate the final shuffled ciphertexts as indexed ciphertexts with their positions
        let ciphertexts_final: Vec<IndexedElGamalCiphertext<G>> = self
            .ct_after_shuffle
            .iter()
            .enumerate()
            .map(|(i, ct)| {
                let ct_var = ElGamalCiphertextVar::<G>::new_variable(
                    cs.clone(),
                    || Ok(ct),
                    AllocationMode::Input,
                )?;
                let idx_var = FpVar::new_constant(cs.clone(), G::BaseField::from(i as u64))?;
                Ok(IndexedElGamalCiphertext::new(idx_var, ct_var))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 2. Allocate witness data using AllocVar
        let witness_var = WitnessDataVar::<G::BaseField>::new_variable(
            cs.clone(),
            || Ok(&self.witness),
            AllocationMode::Witness,
        )?;

        // 3. Allocate challenges
        let alpha_var = FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;
        let beta_var = FpVar::new_variable(cs.clone(), || Ok(self.beta), AllocationMode::Input)?;

        // Compute other challenges as powers of beta
        let beta_2_var = &beta_var * &beta_var; // beta^2 (was gamma)
        let beta_3_var = &beta_2_var * &beta_var; // beta^3 (was delta)
        let beta_4_var = &beta_3_var * &beta_var; // beta^4 (was epsilon)
        let beta_5_var = &beta_4_var * &beta_var; // beta^5 (was zeta)
        let beta_6_var = &beta_5_var * &beta_var; // beta^6 (was eta)

        // 4. Level-by-level verification
        for level in 0..LEVELS {
            let unsorted = &witness_var.uns_levels[level];
            let next_arr = &witness_var.next_levels[level];

            // 4.1 Verify row-local constraints
            let idx_next_pos_pairs = verify_row_constraints(cs.clone(), unsorted)?;

            // 4.2 Build right-side pairs (idx, pos) from next array
            let idx_pos_pairs: Vec<IndexPositionPair<G::BaseField>> = next_arr
                .iter()
                .enumerate()
                .map(|(j, nr)| {
                    IndexPositionPair::new(
                        nr.idx.clone(),
                        FpVar::new_constant(cs.clone(), G::BaseField::from(j as u64)).unwrap(),
                    )
                })
                .collect();

            // 4.3 Check multiset equality for this level using 2 challenges
            check_grand_product::<G::BaseField, IndexPositionPair<G::BaseField>, 2>(
                cs.clone(),
                &idx_next_pos_pairs,
                &idx_pos_pairs,
                &[alpha_var.clone(), beta_var.clone()],
            )?;
        }

        // // 5. Final permutation check using ElGamal ciphertexts (7 challenges)
        // // Note: ciphertexts_final was already allocated above as IndexedElGamalCiphertext

        // // Check that the multisets are equal using 7 challenges for full ElGamal comparison
        // check_grand_product::<G::BaseField, IndexedElGamalCiphertext<G>, 7>(
        //     cs,
        //     &ciphertexts_final,
        //     &ciphertexts_initial,
        //     &[
        //         alpha_var, beta_var, beta_2_var, beta_3_var, beta_4_var, beta_5_var, beta_6_var,
        //     ],
        // )?;

        Ok(())
    }
}

/// Verify row-local constraints for one level using circuit variables
pub fn verify_row_constraints<F>(
    cs: ConstraintSystemRef<F>,
    unsorted: &[UnsortedRowVar<F>; N],
) -> Result<Vec<IndexPositionPair<F>>, SynthesisError>
where
    F: PrimeField,
{
    let mut idx_next_pos_pairs = Vec::new();

    for i in 0..N {
        let u = &unsorted[i];
        let u_next = if i + 1 < N {
            Some(&unsorted[i + 1])
        } else {
            None
        };

        // ============================================================
        // Row-Local Constraint (1): BITNESS
        // Mathematical requirement: b_i * (b_i - 1) = 0
        // This ensures b_i ∈ {0, 1}
        // ============================================================
        let one = FpVar::<F>::one();
        let zero = FpVar::<F>::zero();
        let bit = &u.bit.clone();
        let one_minus_bit = &one - bit;

        // b_i * (b_i - 1) = 0
        let bitness_check = bit * &one_minus_bit;
        bitness_check.enforce_equal(&zero)?;

        // ============================================================
        // Row-Local Constraint (2): PREFIX-COUNTER EVOLUTION
        //
        // Using indicator last_i to handle both internal and tail rows:
        //
        // If last_i = 0 (internal row):
        //   z_{i+1} = z_i + (1 - b_i)  [zeros counter increments if bit=0]
        //   o_{i+1} = o_i + b_i        [ones counter increments if bit=1]
        //
        // If last_i = 1 (final row in bucket):
        //   z_i = Z_i - (1 - b_i)  [final zeros count matches total minus current]
        //   o_i = (L_i - Z_i) - b_i  [final ones count matches total minus current]
        //
        // Combined equations:
        //   z_{i+1} - z_i - (1 - b_i) = last_i * (Z_i - z_i - (1 - b_i))
        //   o_{i+1} - o_i - b_i = last_i * ((L_i - Z_i) - o_i - b_i)
        // ============================================================

        // Determine if this is the last row in its bucket
        let is_last_in_bucket = if let Some(next) = u_next {
            // Check if next row is in a different bucket
            u.bucket_id.is_eq(&next.bucket_id)?.not()
        } else {
            // Last row of entire array is always last in its bucket
            Boolean::constant(true)
        };

        // Process counter evolution and bucket constants for non-final rows
        if let Some(next) = u_next {
            let same_bucket = is_last_in_bucket.clone().not();

            // Counter evolution constraints (when not last in bucket)
            // same_bucket * (z_{i+1} - z_i - (1 - b_i)) = 0
            // When same_bucket is true: enforce z_{i+1} = z_i + (1 - b_i)
            let expected_next_zeros = &u.num_zeros + &one_minus_bit;
            let selected_zeros = same_bucket.select(&expected_next_zeros, &next.num_zeros)?;
            next.num_zeros.enforce_equal(&selected_zeros)?;

            // same_bucket * (o_{i+1} - o_i - b_i) = 0
            // When same_bucket is true: enforce o_{i+1} = o_i + b_i
            let expected_next_ones = &u.num_ones + &u.bit;
            let selected_ones = same_bucket.select(&expected_next_ones, &next.num_ones)?;
            next.num_ones.enforce_equal(&selected_ones)?;

            // ============================================================
            // Row-Local Constraint (3): BUCKET CONSTANTS STAY CONSTANT
            //
            // For internal rows (last_i = 0):
            //   (1 - last_i) * (Z_{i+1} - Z_i) = 0  [total zeros constant]
            //   (1 - last_i) * (L_{i+1} - L_i) = 0  [bucket length constant]
            //
            // Since last_i = 0 for internal rows, (1 - last_i) = 1
            // Therefore: Z_{i+1} = Z_i and L_{i+1} = L_i within same bucket
            // ============================================================

            // same_bucket * (Z_{i+1} - Z_i) = 0
            // When same_bucket is true: enforce Z_{i+1} = Z_i
            let selected_total_zeros =
                same_bucket.select(&u.total_zeros_in_bucket, &next.total_zeros_in_bucket)?;
            next.total_zeros_in_bucket
                .enforce_equal(&selected_total_zeros)?;

            // same_bucket * (L_{i+1} - L_i) = 0
            // When same_bucket is true: enforce L_{i+1} = L_i
            let selected_length = same_bucket.select(&u.bucket_length, &next.bucket_length)?;
            next.bucket_length.enforce_equal(&selected_length)?;
        }

        // ============================================================
        // Final tallies constraint (when last_i = 1):
        //   z_i = Z_i - (1 - b_i)  [final zeros count]
        //   o_i = (L_i - Z_i) - b_i  [final ones count]
        // ============================================================

        // last_i * (Z_i - z_i - (1 - b_i)) = 0
        // When is_last_in_bucket is true: enforce z_i = Z_i - (1 - b_i)
        let expected_final_zeros = &u.total_zeros_in_bucket - &one_minus_bit;
        let selected_final_zeros = is_last_in_bucket
            .clone()
            .select(&expected_final_zeros, &u.num_zeros)?;
        u.num_zeros.enforce_equal(&selected_final_zeros)?;

        // last_i * ((L_i - Z_i) - o_i - b_i) = 0
        // When is_last_in_bucket is true: enforce o_i = (L_i - Z_i) - b_i
        let expected_final_ones = &u.bucket_length - &u.total_zeros_in_bucket - &u.bit;
        let selected_final_ones = is_last_in_bucket.select(&expected_final_ones, &u.num_ones)?;
        u.num_ones.enforce_equal(&selected_final_ones)?;

        // ============================================================
        // Row-Local Constraint (4): DESTINATION SLOT COMPUTATION
        //
        // Define base_i := pos_i - (z_i + o_i) [left edge of bucket]
        //
        // Destination formula:
        //   rhs_i = base_i + z_i + b_i * (Z_i - z_i + o_i)
        //        = pos_i - o_i + b_i * (Z_i - z_i)
        //
        // If b_i = 0 (zero bit):
        //   rhs = pos_i - o_i  [stays in zero zone, preserves order]
        //
        // If b_i = 1 (one bit):
        //   rhs = pos_i - o_i + Z_i - z_i = base_i + Z_i + o_i
        //   [jumps past all zeros, preserves ones order]
        //
        // Invariant: 0 ≤ z_i ≤ Z_i ≤ L_i and 0 ≤ o_i ≤ L_i - Z_i
        // Therefore offset < L_i, ensuring row stays within bucket
        // ============================================================
        let pos = FpVar::new_constant(cs.clone(), F::from(i as u64))?;
        let base = &pos - (&u.num_zeros + &u.num_ones); // base_i = pos_i - (z_i + o_i)

        // Compute offset: z_i + b_i * (Z_i - z_i + o_i)
        let offset =
            &u.num_zeros + &u.bit * (&u.total_zeros_in_bucket - &u.num_zeros + &u.num_ones);
        let expected_dest = base + offset;

        // Enforce: next_pos_i = expected_dest
        u.next_pos.enforce_equal(&expected_dest)?;

        // Collect (idx, next_pos) pairs for multiset equality check
        idx_next_pos_pairs.push(IndexPositionPair::new(u.idx.clone(), u.next_pos.clone()));
    }

    Ok(idx_next_pos_pairs)
}
