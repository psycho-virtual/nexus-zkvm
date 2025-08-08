//! Main circuit implementation for RS shuffle with constraint generation

use super::data_structures::{SortedRowVar, UnsortedRowVar, WitnessData, WitnessDataVar};
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
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::ops::Not;

/// Main RS Shuffle Circuit
pub struct RSShuffleCircuit<F, C>
where
    F: PrimeField,
    C: CurveGroup<BaseField = F>,
{
    /// Public: Initial ciphertexts
    pub ct_init_pub: Vec<ElGamalCiphertext<C>>,
    /// Private: Witness data for all levels
    pub witness: WitnessData<N, LEVELS>,
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
        witness: WitnessData<N, LEVELS>,
        alpha: F,
        beta: F,
    ) -> Self {
        Self {
            ct_init_pub: ct_init,
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
        // 1. Allocate witness data FIRST - this contains the permutation information
        let witness_var = WitnessDataVar::<G::BaseField, N, LEVELS>::new_variable(
            cs.clone(),
            || Ok(&self.witness),
            AllocationMode::Witness,
        )?;

        // 2. Allocate the ElGamal ciphertexts as public inputs
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

        let ct_final_vars: Vec<ElGamalCiphertextVar<G>> = self
            .ct_after_shuffle
            .iter()
            .map(|ct| {
                ElGamalCiphertextVar::<G>::new_variable(
                    cs.clone(),
                    || Ok(ct),
                    AllocationMode::Input,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 3. Create indexed ciphertexts by zipping witness indices with ciphertexts
        // Initial: Use indices from first level unsorted array
        let ciphertexts_initial: Vec<IndexedElGamalCiphertext<G>> = witness_var.uns_levels[0]
            .iter()
            .zip(ct_init_vars.into_iter())
            .map(|(row, ct)| IndexedElGamalCiphertext::new(row.idx.clone(), ct))
            .collect();

        // Final: Use indices from last level sorted array
        let ciphertexts_final: Vec<IndexedElGamalCiphertext<G>> = witness_var.sorted_levels
            [LEVELS - 1]
            .iter()
            .zip(ct_final_vars.into_iter())
            .map(|(row, ct)| IndexedElGamalCiphertext::new(row.idx.clone(), ct))
            .collect();

        // 4. Allocate challenges
        let alpha_var = FpVar::new_variable(cs.clone(), || Ok(self.alpha), AllocationMode::Input)?;
        let beta_var = FpVar::new_variable(cs.clone(), || Ok(self.beta), AllocationMode::Input)?;

        // Compute other challenges as powers of beta
        let beta_2_var = &beta_var * &beta_var; // beta^2 (for c1.x)
        let beta_3_var = &beta_2_var * &beta_var; // beta^3 (for c1.y)
        let beta_4_var = &beta_3_var * &beta_var; // beta^4 (for c1.z)
        let beta_5_var = &beta_4_var * &beta_var; // beta^5 (for c2.x)
        let beta_6_var = &beta_5_var * &beta_var; // beta^6 (for c2.y)

        // 5. Level-by-level verification
        for level in 0..LEVELS {
            let unsorted = &witness_var.uns_levels[level];
            let sorted_arr = &witness_var.sorted_levels[level];

            // Verify this shuffle level (row constraints + permutation check)
            verify_shuffle_level::<_, N>(cs.clone(), unsorted, sorted_arr, &alpha_var, &beta_var)?;
        }

        // 6. Final permutation check using ElGamal ciphertexts (7 challenges)
        // This verifies that initial and final ciphertexts form the same multiset
        // The 7 challenges are: 1 for index + 6 for ElGamal components (c1.x, c1.y, c1.z, c2.x, c2.y, c2.z)
        check_grand_product::<G::BaseField, IndexedElGamalCiphertext<G>, 7>(
            cs,
            &ciphertexts_initial,
            &ciphertexts_final,
            &[
                alpha_var,  // For index
                beta_var,   // For c1.x
                beta_2_var, // For c1.y
                beta_3_var, // For c1.z
                beta_4_var, // For c2.x
                beta_5_var, // For c2.y
                beta_6_var, // For c2.z
            ],
        )?;

        Ok(())
    }
}

/// Verify row-local constraints for one level using circuit variables
pub fn verify_row_constraints<F, const N: usize>(
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

/// Verify one level of the RS shuffle including row constraints and permutation check
///
/// This function encapsulates:
/// 1. Row-local constraint verification (bitness, counter evolution, bucket constants, destination computation)
/// 2. Building the right-side index-position pairs from the next array
/// 3. Checking multiset equality using grand product with provided challenges
///
/// # Type Parameters
/// - `F`: The prime field type
/// - `N`: The size of the arrays (number of elements)
///
/// # Parameters
/// - `cs`: The constraint system reference
/// - `unsorted`: The unsorted row variables for this level
/// - `next_arr`: The next (sorted) row variables for this level
/// - `alpha`: The first challenge for the grand product
/// - `beta`: The second challenge for the grand product
///
/// # Returns
/// - `Ok(())` if all constraints are satisfied
/// - `Err(SynthesisError)` if any constraint fails
pub fn verify_shuffle_level<F, const N: usize>(
    cs: ConstraintSystemRef<F>,
    unsorted_arr: &[UnsortedRowVar<F>; N],
    sorted_arr: &[SortedRowVar<F>; N],
    alpha: &FpVar<F>,
    beta: &FpVar<F>,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
{
    // Step 1: Verify row-local constraints
    let idx_next_pos_pairs = verify_row_constraints::<_, N>(cs.clone(), unsorted_arr)?;

    // Step 2: Build right-side pairs (idx, pos) from next array
    let idx_pos_pairs: Vec<IndexPositionPair<F>> = sorted_arr
        .iter()
        .enumerate()
        .map(|(j, nr)| {
            IndexPositionPair::new(
                nr.idx.clone(),
                FpVar::new_constant(cs.clone(), F::from(j as u64)).unwrap(),
            )
        })
        .collect();

    // Step 3: Check multiset equality for this level using 2 challenges
    check_grand_product::<F, IndexPositionPair<F>, 2>(
        cs,
        &idx_next_pos_pairs,
        &idx_pos_pairs,
        &[alpha.clone(), beta.clone()],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shuffling::rs_shuffle::data_structures::{
        SortedRow, SortedRowVar, UnsortedRow, UnsortedRowVar,
    };
    use crate::shuffling::rs_shuffle::witness_preparation::build_level;
    use ark_bls12_381::Fr as TestField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    const TEST_TARGET: &str = "rs_shuffle::tests";
    const LOG_TARGET: &str = "rs_shuffle::circuit";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG)
            .with_target(LOG_TARGET, tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    /// Helper function to allocate an array of UnsortedRow as UnsortedRowVar in the constraint system
    fn allocate_unsorted_rows<F: PrimeField, const N: usize>(
        cs: ConstraintSystemRef<F>,
        unsorted: &[UnsortedRow; N],
    ) -> Result<[UnsortedRowVar<F>; N], SynthesisError> {
        let vars: Vec<UnsortedRowVar<F>> = unsorted
            .iter()
            .map(|row| {
                UnsortedRowVar::<F>::new_variable(cs.clone(), || Ok(row), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        vars.try_into().map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Helper function to allocate an array of SortedRow as SortedRowVar in the constraint system
    fn allocate_next_rows<F: PrimeField, const N: usize>(
        cs: ConstraintSystemRef<F>,
        next_rows: &[SortedRow; N],
    ) -> Result<[SortedRowVar<F>; N], SynthesisError> {
        let vars: Vec<SortedRowVar<F>> = next_rows
            .iter()
            .map(|row| {
                SortedRowVar::<F>::new_variable(cs.clone(), || Ok(row), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        vars.try_into().map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Helper function to check if constraint system is satisfied and provide detailed error info
    fn check_cs_satisfied<F: PrimeField>(cs: &ConstraintSystemRef<F>) -> Result<(), String> {
        match cs.is_satisfied() {
            Ok(true) => Ok(()),
            Ok(false) => {
                // Try to get which constraint is unsatisfied
                match cs.which_is_unsatisfied() {
                    Ok(Some(unsatisfied_name)) => {
                        // Find the index if we have constraint names
                        let constraint_names = cs.constraint_names().unwrap_or_default();
                        let index = constraint_names
                            .iter()
                            .position(|name| name == &unsatisfied_name)
                            .map(|i| format!(" at index {}", i))
                            .unwrap_or_default();
                        Err(format!(
                            "Constraint '{}'{} is not satisfied",
                            unsatisfied_name, index
                        ))
                    }
                    Ok(None) => Err("Constraint system is not satisfied".to_string()),
                    Err(e) => Err(format!("Error checking unsatisfied constraint: {:?}", e)),
                }
            }
            Err(e) => Err(format!("Error checking constraint satisfaction: {:?}", e)),
        }
    }

    #[test]
    fn test_verify_row_constraints_single_level_alternating() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        // Create a single bucket with all elements
        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Alternating bit pattern [0,1,0,1,0,1,0,1]
        let bits: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness using build_level as oracle
        let (unsorted, next) = build_level::<N>(&prev_rows, &bits);

        // Create constraint system
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Allocate unsorted rows in constraint system
        let unsorted_vars = allocate_unsorted_rows(cs.clone(), &unsorted)
            .expect("Failed to allocate unsorted rows");

        // Run verify_row_constraints
        let idx_next_pos_pairs = verify_row_constraints(cs.clone(), &unsorted_vars)
            .expect("verify_row_constraints failed");

        // Check that constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied for valid witness");

        // Verify we got the expected number of pairs
        assert_eq!(idx_next_pos_pairs.len(), N);

        // Additional checks on the witness data
        // With alternating bits, we should have 4 zeros and 4 ones
        let zero_count = bits.iter().filter(|&&b| !b).count();
        let one_count = N - zero_count;
        assert_eq!(zero_count, 4);
        assert_eq!(one_count, 4);

        // Verify that zeros are placed in positions 0..4 and ones in 4..8
        for i in 0..zero_count {
            assert_eq!(next[i].bucket, 0); // Zeros go to bucket 0
        }
        for i in zero_count..N {
            assert_eq!(next[i].bucket, 1); // Ones go to bucket 1
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Single level with alternating bits");
    }

    #[test]
    fn test_verify_row_constraints_two_successive_levels() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        // Level 0: Single bucket containing all elements
        let prev0: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Level 1: Alternating bits [0,1,0,1,0,1,0,1]
        let bits1: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness for level 1
        let (unsorted1, next1) = build_level::<N>(&prev0, &bits1);

        // Create constraint system for level 1
        let cs1 = ConstraintSystem::<TestField>::new_ref();

        // Allocate and verify level 1
        let unsorted1_vars = allocate_unsorted_rows(cs1.clone(), &unsorted1)
            .expect("Failed to allocate level 1 unsorted rows");

        let idx_next_pos_pairs1 = verify_row_constraints(cs1.clone(), &unsorted1_vars)
            .expect("verify_row_constraints failed for level 1");

        check_cs_satisfied(&cs1)
            .expect("Level 1: Constraint system should be satisfied for valid witness");

        assert_eq!(idx_next_pos_pairs1.len(), N);

        // Verify level 1 produced correct buckets
        assert!(next1[0..4].iter().all(|r| r.bucket == 0));
        assert!(next1[4..8].iter().all(|r| r.bucket == 1));

        tracing::debug!(target: TEST_TARGET, "✓ Level 1 verification passed");

        // Level 2: Different bit pattern to split each bucket
        // For bucket 0 (indices 0,2,4,6): [1,0,0,1]
        // For bucket 1 (indices 1,3,5,7): [0,1,1,0]
        let bits2: [bool; N] = [true, false, false, true, false, true, true, false];

        // Generate witness for level 2
        let (unsorted2, next2) = build_level::<N>(&next1, &bits2);

        // Create constraint system for level 2
        let cs2 = ConstraintSystem::<TestField>::new_ref();

        // Allocate and verify level 2
        let unsorted2_vars = allocate_unsorted_rows(cs2.clone(), &unsorted2)
            .expect("Failed to allocate level 2 unsorted rows");

        let idx_next_pos_pairs2 = verify_row_constraints(cs2.clone(), &unsorted2_vars)
            .expect("verify_row_constraints failed for level 2");

        check_cs_satisfied(&cs2)
            .expect("Level 2: Constraint system should be satisfied for valid witness");

        assert_eq!(idx_next_pos_pairs2.len(), N);

        // Verify level 2 produced 4 buckets (0,1,2,3)
        assert!(next2[0..2].iter().all(|r| r.bucket == 0));
        assert!(next2[2..4].iter().all(|r| r.bucket == 1));
        assert!(next2[4..6].iter().all(|r| r.bucket == 2));
        assert!(next2[6..8].iter().all(|r| r.bucket == 3));

        tracing::debug!(target: TEST_TARGET, "✓ Level 2 verification passed");
        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Two successive levels");
    }

    #[test]
    fn test_verify_row_constraints_edge_cases() {
        let _guard = setup_test_tracing();
        const N: usize = 4;

        // Test case 1: All zeros
        let prev_all_zeros: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));
        let bits_all_zeros: [bool; N] = [false; N];
        let (unsorted_zeros, next_zeros) = build_level::<N>(&prev_all_zeros, &bits_all_zeros);

        let cs_zeros = ConstraintSystem::<TestField>::new_ref();
        let unsorted_zeros_vars = allocate_unsorted_rows(cs_zeros.clone(), &unsorted_zeros)
            .expect("Failed to allocate all-zeros unsorted rows");

        let pairs_zeros = verify_row_constraints(cs_zeros.clone(), &unsorted_zeros_vars)
            .expect("verify_row_constraints failed for all zeros");

        check_cs_satisfied(&cs_zeros).expect("All zeros: Constraint system should be satisfied");

        // All elements should stay in bucket 0
        assert!(next_zeros.iter().all(|r| r.bucket == 0));
        assert_eq!(pairs_zeros.len(), N);

        tracing::debug!(target: TEST_TARGET, "✓ Edge case passed: All zeros");

        // Test case 2: All ones
        let prev_all_ones: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));
        let bits_all_ones: [bool; N] = [true; N];
        let (unsorted_ones, next_ones) = build_level::<N>(&prev_all_ones, &bits_all_ones);

        let cs_ones = ConstraintSystem::<TestField>::new_ref();
        let unsorted_ones_vars = allocate_unsorted_rows(cs_ones.clone(), &unsorted_ones)
            .expect("Failed to allocate all-ones unsorted rows");

        let pairs_ones = verify_row_constraints(cs_ones.clone(), &unsorted_ones_vars)
            .expect("verify_row_constraints failed for all ones");

        check_cs_satisfied(&cs_ones).expect("All ones: Constraint system should be satisfied");

        // All elements should go to bucket 1
        assert!(next_ones.iter().all(|r| r.bucket == 1));
        assert_eq!(pairs_ones.len(), N);

        tracing::debug!(target: TEST_TARGET, "✓ Edge case passed: All ones");
    }

    #[test]
    fn test_verify_row_constraints_multi_bucket() {
        let _guard = setup_test_tracing();
        const N: usize = 6;

        // Create two initial buckets
        let prev_rows: [SortedRow; N] = [
            SortedRow::new_with_bucket(0, 3, 0),
            SortedRow::new_with_bucket(1, 3, 0),
            SortedRow::new_with_bucket(2, 3, 0),
            SortedRow::new_with_bucket(3, 3, 1),
            SortedRow::new_with_bucket(4, 3, 1),
            SortedRow::new_with_bucket(5, 3, 1),
        ];

        // Mixed bit pattern: [0,1,0 | 1,0,1]
        let bits: [bool; N] = [false, true, false, true, false, true];

        // Generate witness
        let (unsorted, next) = build_level::<N>(&prev_rows, &bits);

        // Create constraint system
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Allocate unsorted rows
        let unsorted_vars = allocate_unsorted_rows(cs.clone(), &unsorted)
            .expect("Failed to allocate multi-bucket unsorted rows");

        // Run verify_row_constraints
        let idx_next_pos_pairs = verify_row_constraints(cs.clone(), &unsorted_vars)
            .expect("verify_row_constraints failed for multi-bucket");

        // Check constraint satisfaction
        check_cs_satisfied(&cs).expect("Multi-bucket: Constraint system should be satisfied");

        assert_eq!(idx_next_pos_pairs.len(), N);

        // Verify bucket assignments
        // Bucket 0 splits into buckets 0 (2 zeros) and 1 (1 one)
        assert_eq!(next[0].bucket, 0);
        assert_eq!(next[1].bucket, 0);
        assert_eq!(next[2].bucket, 1);

        // Bucket 1 splits into buckets 2 (1 zero) and 3 (2 ones)
        assert_eq!(next[3].bucket, 2);
        assert_eq!(next[4].bucket, 3);
        assert_eq!(next[5].bucket, 3);

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Multi-bucket configuration");
    }

    #[test]
    fn test_verify_shuffle_level_single() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        tracing::debug!(target: TEST_TARGET, "Starting test_verify_shuffle_level_single");

        // Create a single bucket with all elements
        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Alternating bit pattern [0,1,0,1,0,1,0,1]
        let bits: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness using build_level as oracle
        let (unsorted, next) = build_level::<N>(&prev_rows, &bits);

        // Create constraint system
        let cs = ConstraintSystem::<TestField>::new_ref();

        // Allocate unsorted rows in constraint system
        let unsorted_vars = allocate_unsorted_rows(cs.clone(), &unsorted)
            .expect("Failed to allocate unsorted rows");

        // Allocate next rows in constraint system
        let next_vars =
            allocate_next_rows(cs.clone(), &next).expect("Failed to allocate next rows");

        // Create test challenges
        let alpha =
            FpVar::new_constant(cs.clone(), TestField::from(2u64)).expect("Failed to create alpha");
        let beta =
            FpVar::new_constant(cs.clone(), TestField::from(3u64)).expect("Failed to create beta");

        // Run verify_shuffle_level
        verify_shuffle_level::<_, N>(cs.clone(), &unsorted_vars, &next_vars, &alpha, &beta)
            .expect("verify_shuffle_level failed");

        // Check that constraint system is satisfied
        check_cs_satisfied(&cs).expect("Constraint system should be satisfied for valid shuffle");

        // Verify expected structure
        let zero_count = bits.iter().filter(|&&b| !b).count();
        let one_count = N - zero_count;
        assert_eq!(zero_count, 4);
        assert_eq!(one_count, 4);

        // Verify that zeros are placed in positions 0..4 and ones in 4..8
        for i in 0..zero_count {
            assert_eq!(next[i].bucket, 0); // Zeros go to bucket 0
        }
        for i in zero_count..N {
            assert_eq!(next[i].bucket, 1); // Ones go to bucket 1
        }

        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Single shuffle level verification");
    }

    #[test]
    fn test_verify_shuffle_level_two_successive() {
        let _guard = setup_test_tracing();
        const N: usize = 8;

        tracing::debug!(target: TEST_TARGET, "Starting test_verify_shuffle_level_two_successive");

        // Level 0: Single bucket containing all elements
        let prev0: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Level 1: Alternating bits [0,1,0,1,0,1,0,1]
        let bits1: [bool; N] = [false, true, false, true, false, true, false, true];

        // Generate witness for level 1
        let (unsorted1, next1) = build_level::<N>(&prev0, &bits1);

        // Create constraint system for level 1
        let cs1 = ConstraintSystem::<TestField>::new_ref();

        // Allocate level 1 variables
        let unsorted1_vars = allocate_unsorted_rows(cs1.clone(), &unsorted1)
            .expect("Failed to allocate level 1 unsorted rows");
        let next1_vars =
            allocate_next_rows(cs1.clone(), &next1).expect("Failed to allocate level 1 next rows");

        // Create test challenges for level 1
        let alpha1 = FpVar::new_constant(cs1.clone(), TestField::from(5u64))
            .expect("Failed to create alpha1");
        let beta1 = FpVar::new_constant(cs1.clone(), TestField::from(7u64))
            .expect("Failed to create beta1");

        // Verify level 1
        verify_shuffle_level::<_, N>(cs1.clone(), &unsorted1_vars, &next1_vars, &alpha1, &beta1)
            .expect("verify_shuffle_level failed for level 1");

        check_cs_satisfied(&cs1)
            .expect("Level 1: Constraint system should be satisfied for valid shuffle");

        // Verify level 1 produced correct buckets
        assert!(next1[0..4].iter().all(|r| r.bucket == 0));
        assert!(next1[4..8].iter().all(|r| r.bucket == 1));

        tracing::debug!(target: TEST_TARGET, "✓ Level 1 shuffle verification passed");

        // Level 2: Different bit pattern to split each bucket
        // For bucket 0 (indices 0,2,4,6): [1,0,0,1]
        // For bucket 1 (indices 1,3,5,7): [0,1,1,0]
        let bits2: [bool; N] = [true, false, false, true, false, true, true, false];

        // Generate witness for level 2
        let (unsorted2, next2) = build_level::<N>(&next1, &bits2);

        // Create constraint system for level 2
        let cs2 = ConstraintSystem::<TestField>::new_ref();

        // Allocate level 2 variables
        let unsorted2_vars = allocate_unsorted_rows(cs2.clone(), &unsorted2)
            .expect("Failed to allocate level 2 unsorted rows");
        let next2_vars =
            allocate_next_rows(cs2.clone(), &next2).expect("Failed to allocate level 2 next rows");

        // Create test challenges for level 2
        let alpha2 = FpVar::new_constant(cs2.clone(), TestField::from(11u64))
            .expect("Failed to create alpha2");
        let beta2 = FpVar::new_constant(cs2.clone(), TestField::from(13u64))
            .expect("Failed to create beta2");

        // Verify level 2
        verify_shuffle_level::<_, N>(cs2.clone(), &unsorted2_vars, &next2_vars, &alpha2, &beta2)
            .expect("verify_shuffle_level failed for level 2");

        check_cs_satisfied(&cs2)
            .expect("Level 2: Constraint system should be satisfied for valid shuffle");

        // Verify level 2 produced 4 buckets (0,1,2,3)
        assert!(next2[0..2].iter().all(|r| r.bucket == 0));
        assert!(next2[2..4].iter().all(|r| r.bucket == 1));
        assert!(next2[4..6].iter().all(|r| r.bucket == 2));
        assert!(next2[6..8].iter().all(|r| r.bucket == 3));

        tracing::debug!(target: TEST_TARGET, "✓ Level 2 shuffle verification passed");
        tracing::debug!(target: TEST_TARGET, "✓ Test passed: Two successive shuffle levels verification");
    }
}
