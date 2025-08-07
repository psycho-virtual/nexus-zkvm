//! Witness generation for RS shuffle (prover-side logic)

use super::data_structures::*;
use super::{LEVELS, N};
use crate::shuffling::data_structures::ElGamalCiphertext;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};

/// Main witness preparation function (prover-side)
pub fn prepare_witness_data<F, C>(ct_init: &[ElGamalCiphertext<C>], _seed: &[u8]) -> WitnessData
where
    F: Field + PrimeField + ark_crypto_primitives::sponge::Absorb,
    C: CurveGroup<BaseField = F>,
{
    // Derive split bits from seed
    let bits_mat_vec = derive_split_bits::<F>(_seed);

    // Initialize with level-0 rows (one bucket of full length)
    let prev_vec: Vec<SortedRow> = ct_init
        .iter()
        .enumerate()
        .map(|(i, _ct)| SortedRow::new_with_bucket(i as u16, N as u16, 0))
        .collect();

    let mut prev: [SortedRow; N] = prev_vec
        .try_into()
        .expect("Initial array should have exactly N elements");

    // Process all levels using scan to thread prev through each iteration
    let level_results: Vec<([UnsortedRow; N], [SortedRow; N])> = (0..LEVELS)
        .scan(prev, |prev_state, level| {
            // Convert Vec<bool> to [bool; N]
            let bits_level: [bool; N] = bits_mat_vec[level]
                .clone()
                .try_into()
                .expect("Bits array should have exactly N elements");

            // Build level with current prev state
            let (uns_array, nxt_array) = build_level::<N>(prev_state, &bits_level);

            // Update prev state for next iteration
            *prev_state = nxt_array.clone();

            // Return the result for this level
            Some((uns_array, nxt_array))
        })
        .collect();

    // Convert Vec of tuples to arrays using array::from_fn
    let uns_levels: [[UnsortedRow; N]; LEVELS] =
        std::array::from_fn(|i| level_results[i].0.clone());
    let next_levels: [[SortedRow; N]; LEVELS] = std::array::from_fn(|i| level_results[i].1.clone());

    // Convert bits matrix using array::from_fn
    let bits_mat: [[bool; N]; LEVELS] = std::array::from_fn(|i| {
        bits_mat_vec[i]
            .clone()
            .try_into()
            .expect("Bits array should have exactly N elements")
    });

    WitnessData { bits_mat, uns_levels, next_levels }
}

/// Build witness tables for one level using functional approach
pub fn build_level<const N: usize>(
    prev_rows: &[SortedRow; N],
    bits_lvl: &[bool; N],
) -> ([UnsortedRow; N], [SortedRow; N]) {
    use std::collections::HashMap;

    // Zip prev_rows with bits
    let rows_with_bits: Vec<(&SortedRow, bool)> =
        prev_rows.iter().zip(bits_lvl.iter().copied()).collect();

    // Separate maps for clarity
    let mut bucket_zeros: HashMap<u16, u16> = HashMap::new(); // bucket -> total zeros in bucket
    let mut bucket_ones: HashMap<u16, u16> = HashMap::new(); // bucket -> total ones in bucket
    let mut bucket_starts: HashMap<u16, u16> = HashMap::new(); // bucket -> start position
    let mut bucket_lengths: HashMap<u16, u16> = HashMap::new(); // bucket -> length

    // First pass: compute bucket statistics
    let mut current_pos = 0u16;
    for (row, bit) in &rows_with_bits {
        let bucket = row.bucket;

        // Track start position for each bucket
        bucket_starts.entry(bucket).or_insert(current_pos);

        // Count zeros and ones
        if !bit {
            *bucket_zeros.entry(bucket).or_insert(0) += 1;
        } else {
            *bucket_ones.entry(bucket).or_insert(0) += 1;
        }

        // Track bucket length
        *bucket_lengths.entry(bucket).or_insert(0) += 1;

        current_pos += 1;
    }

    // Create unsorted rows with running counters that reset on bucket change
    let mut unsorted = Vec::new();
    let mut current_bucket = None;
    let mut num_zeros = 0u16;
    let mut num_ones = 0u16;

    for (i, (row, bit)) in rows_with_bits.iter().enumerate() {
        let bucket = row.bucket;

        // Check if we're entering a new bucket
        if current_bucket != Some(bucket) {
            // Reset counters for new bucket
            num_zeros = 0;
            num_ones = 0;
            current_bucket = Some(bucket);
        }

        // Get all the bucket stats from our separate maps
        let num_zeros_in_bucket = *bucket_zeros.get(&bucket).unwrap_or(&0);
        let bucket_length = *bucket_lengths.get(&bucket).unwrap_or(&0);
        let bucket_start = *bucket_starts.get(&bucket).unwrap_or(&0);

        // Compute destination position
        let offset = if !bit {
            num_zeros
        } else {
            num_zeros_in_bucket + num_ones
        };
        let next_pos = bucket_start + offset;

        // Create the unsorted row
        unsorted.push(UnsortedRow::new(
            *bit,
            num_zeros,
            num_ones,
            num_zeros_in_bucket,
            bucket_length,
            row.idx,
            next_pos,
            bucket,
        ));

        // Update counters after processing this element
        if !bit {
            num_zeros += 1;
        } else {
            num_ones += 1;
        }
    }

    // Create indexed tuples for sorting
    let mut sortable: Vec<(u16, u16, bool, u16)> = unsorted
        .iter()
        .zip(&rows_with_bits)
        .map(|(uns, (row, bit))| (uns.next_pos, row.idx, *bit, row.bucket))
        .collect();

    // Stable sort by next_pos
    sortable.sort_by_key(|&(next_pos, _, _, _)| next_pos);

    // Build the next array with correct bucket sizes
    let next_arr: Vec<SortedRow> = sortable
        .into_iter()
        .map(|(_, idx, bit, parent_bucket)| {
            let num_zeros_in_bucket = *bucket_zeros.get(&parent_bucket).unwrap_or(&0);
            let num_ones_in_bucket = *bucket_ones.get(&parent_bucket).unwrap_or(&0);

            // Next level bucket is determined by parent bucket and bit
            let next_bucket = if !bit {
                parent_bucket * 2
            } else {
                parent_bucket * 2 + 1
            };

            // Bucket length for next level is determined by zeros/ones count
            let next_bucket_length = if !bit {
                num_zeros_in_bucket
            } else {
                num_ones_in_bucket
            };

            SortedRow::new_with_bucket(idx, next_bucket_length, next_bucket)
        })
        .collect();

    // Convert to fixed-size arrays
    let unsorted_array: [UnsortedRow; N] = unsorted
        .try_into()
        .expect("Unsorted array should have exactly N elements");
    let next_array: [SortedRow; N] = next_arr
        .try_into()
        .expect("Next array should have exactly N elements");

    (unsorted_array, next_array)
}

/// Derive split bits from random seed using Poseidon hash
pub fn derive_split_bits<F: Field + PrimeField + ark_crypto_primitives::sponge::Absorb>(
    seed: &[u8],
) -> Vec<Vec<bool>> {
    use crate::shuffling::utils::generate_random_values;
    use ark_ff::BigInteger;

    let mut bits_mat = Vec::new();

    for level in 0..LEVELS {
        // Create domain-separated seed for this level
        // Convert seed bytes to field element with domain separation
        let mut level_seed_bytes = Vec::new();
        level_seed_bytes.extend_from_slice(b"rs_shuffle_level");
        level_seed_bytes.extend_from_slice(&(level as u32).to_le_bytes());
        level_seed_bytes.extend_from_slice(seed);

        // Convert to field element (using a simple modular reduction)
        let level_seed = F::from_le_bytes_mod_order(&level_seed_bytes);

        // We need N bits total
        // Each pair of random values will give us their combined bit decomposition
        // minus the MSB from each
        let mut level_bits = Vec::new();
        let mut bits_collected = 0;

        while bits_collected < N {
            // Draw 2 random values from Poseidon
            let random_values =
                generate_random_values(level_seed + F::from(bits_collected as u64), 2);

            // Decompose first value into bits
            let value1_bigint = random_values[0].into_bigint();
            let value1_bytes = value1_bigint.to_bytes_le();
            let value1_bits = bytes_to_bits(&value1_bytes);

            // Decompose second value into bits
            let value2_bigint = random_values[1].into_bigint();
            let value2_bytes = value2_bigint.to_bytes_le();
            let value2_bits = bytes_to_bits(&value2_bytes);

            // Find MSB position and discard it for both values
            // MSB is the highest set bit position
            let msb1_pos = find_msb_position(&value1_bits);
            let msb2_pos = find_msb_position(&value2_bits);

            // Collect bits from first value (excluding MSB)
            for (i, &bit) in value1_bits.iter().enumerate() {
                if i != msb1_pos && bits_collected < N {
                    level_bits.push(bit);
                    bits_collected += 1;
                }
            }

            // Collect bits from second value (excluding MSB)
            for (i, &bit) in value2_bits.iter().enumerate() {
                if i != msb2_pos && bits_collected < N {
                    level_bits.push(bit);
                    bits_collected += 1;
                }
            }
        }

        // Ensure we have exactly N bits
        level_bits.truncate(N);

        bits_mat.push(level_bits);
    }

    bits_mat
}

/// Convert bytes to bit vector (LSB first)
fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for byte in bytes {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// Find the position of the most significant bit (highest set bit)
fn find_msb_position(bits: &[bool]) -> usize {
    for (i, &bit) in bits.iter().enumerate().rev() {
        if bit {
            return i;
        }
    }
    0 // If no bits are set, return 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// Helper function to assert all invariants for build_level
    fn assert_build_level_invariants(
        prev_rows: &[SortedRow],
        bits: &[bool],
        uns: &[UnsortedRow],
        nxt: &[SortedRow],
    ) -> Result<(), String> {
        let n = prev_rows.len();
        assert_eq!(uns.len(), n, "Unsorted array length mismatch");
        assert_eq!(nxt.len(), n, "Next array length mismatch");
        assert_eq!(bits.len(), n, "Bits array length mismatch");

        // Compute contiguous bucket segments: start & length per bucket
        let mut bucket_starts: HashMap<u16, usize> = HashMap::new();
        let mut bucket_lengths: HashMap<u16, usize> = HashMap::new();
        let mut current_bucket: Option<u16> = None;
        let mut run_start = 0usize;

        for (i, row) in prev_rows.iter().enumerate() {
            match current_bucket {
                None => {
                    current_bucket = Some(row.bucket);
                    run_start = i;
                }
                Some(b) if b != row.bucket => {
                    // Close old bucket run
                    bucket_starts.entry(b).or_insert(run_start);
                    *bucket_lengths.entry(b).or_insert(0) += i - run_start;
                    // Start new bucket
                    current_bucket = Some(row.bucket);
                    run_start = i;
                }
                _ => {}
            }
        }
        // Close final bucket
        if let Some(b) = current_bucket {
            bucket_starts.entry(b).or_insert(run_start);
            *bucket_lengths.entry(b).or_insert(0) += n - run_start;
        }

        // Compute zero counts per bucket from bits
        let mut zeros_per_bucket: HashMap<u16, u16> = HashMap::new();
        for (i, row) in prev_rows.iter().enumerate() {
            if !bits[i] {
                *zeros_per_bucket.entry(row.bucket).or_insert(0) += 1;
            }
        }

        // Track positions seen to ensure bijection
        let mut seen_positions = HashSet::new();

        // Running counters per contiguous bucket segment
        let mut current_bucket_check: Option<u16> = None;
        let mut z_prefix = 0u16;
        let mut o_prefix = 0u16;

        for (i, (prev_row, uns_row)) in prev_rows.iter().zip(uns).enumerate() {
            let bit = bits[i];

            // Reset counters on bucket change
            if current_bucket_check != Some(prev_row.bucket) {
                current_bucket_check = Some(prev_row.bucket);
                z_prefix = 0;
                o_prefix = 0;
            }

            // 1. Check prefix counters match
            if uns_row.num_zeros != z_prefix {
                return Err(format!(
                    "Row {}: num_zeros mismatch. Expected {}, got {}",
                    i, z_prefix, uns_row.num_zeros
                ));
            }
            if uns_row.num_ones != o_prefix {
                return Err(format!(
                    "Row {}: num_ones mismatch. Expected {}, got {}",
                    i, o_prefix, uns_row.num_ones
                ));
            }

            // 2. Check bucket constants
            let total_zeros = *zeros_per_bucket.get(&prev_row.bucket).unwrap_or(&0);
            let bucket_len = *bucket_lengths.get(&prev_row.bucket).unwrap_or(&0) as u16;

            if uns_row.num_zeros_in_bucket != total_zeros {
                return Err(format!(
                    "Row {}: total_zeros_in_bucket mismatch. Expected {}, got {}",
                    i, total_zeros, uns_row.num_zeros_in_bucket
                ));
            }
            if uns_row.bucket_length != bucket_len {
                return Err(format!(
                    "Row {}: bucket_length mismatch. Expected {}, got {}",
                    i, bucket_len, uns_row.bucket_length
                ));
            }
            if uns_row.bucket_id != prev_row.bucket {
                return Err(format!(
                    "Row {}: bucket_id mismatch. Expected {}, got {}",
                    i, prev_row.bucket, uns_row.bucket_id
                ));
            }

            // 3. Check destination formula
            let base = *bucket_starts.get(&prev_row.bucket).unwrap_or(&0) as u16;
            let offset = if !bit {
                z_prefix
            } else {
                total_zeros + o_prefix
            };
            let expected_next_pos = base + offset;

            if uns_row.next_pos != expected_next_pos {
                return Err(format!(
                    "Row {}: next_pos mismatch. Expected {}, got {}",
                    i, expected_next_pos, uns_row.next_pos
                ));
            }

            // 4. Check no collisions
            if !seen_positions.insert(expected_next_pos as usize) {
                return Err(format!(
                    "Row {}: Collision at position {}",
                    i, expected_next_pos
                ));
            }

            // 5. Check correct placement in next array
            let next_row = &nxt[expected_next_pos as usize];
            if next_row.idx != prev_row.idx {
                return Err(format!(
                    "Row {}: idx not preserved at dst {}. Expected {}, got {}",
                    i, expected_next_pos, prev_row.idx, next_row.idx
                ));
            }

            // Check next bucket assignment (2*parent + bit)
            let expected_bucket = prev_row.bucket * 2 + (bit as u16);
            if next_row.bucket != expected_bucket {
                return Err(format!(
                    "Row {}: bucket mismatch at dst {}. Expected {}, got {}",
                    i, expected_next_pos, expected_bucket, next_row.bucket
                ));
            }

            // Check next bucket length
            let ones_in_bucket = bucket_len - total_zeros;
            let expected_length = if !bit { total_zeros } else { ones_in_bucket };
            if next_row.length != expected_length {
                return Err(format!(
                    "Row {}: length mismatch at dst {}. Expected {}, got {}",
                    i, expected_next_pos, expected_length, next_row.length
                ));
            }

            // Advance prefix counters
            if !bit {
                z_prefix += 1;
            } else {
                o_prefix += 1;
            }
        }

        // 6. Check full coverage (permutation)
        if seen_positions.len() != n {
            return Err(format!(
                "Not a full permutation. Only {} positions covered out of {}",
                seen_positions.len(),
                n
            ));
        }

        // 7. Check stability within each bucket
        for (&bucket, &bucket_len) in bucket_lengths.iter() {
            let base = bucket_starts[&bucket];
            let total_zeros = *zeros_per_bucket.get(&bucket).unwrap_or(&0) as usize;

            // Collect indices in this bucket in original order
            let mut bucket_indices = Vec::new();
            let mut bucket_bits = Vec::new();
            for i in base..base + bucket_len {
                if prev_rows[i].bucket == bucket {
                    bucket_indices.push(prev_rows[i].idx);
                    bucket_bits.push(bits[i]);
                }
            }

            // Expected order: zeros first (stable), then ones (stable)
            let zeros_expected: Vec<u16> = bucket_indices
                .iter()
                .zip(bucket_bits.iter())
                .filter_map(|(&idx, &b)| if !b { Some(idx) } else { None })
                .collect();

            let ones_expected: Vec<u16> = bucket_indices
                .iter()
                .zip(bucket_bits.iter())
                .filter_map(|(&idx, &b)| if b { Some(idx) } else { None })
                .collect();

            // Actual order in next array
            let zeros_actual: Vec<u16> = (0..total_zeros).map(|j| nxt[base + j].idx).collect();

            let ones_actual: Vec<u16> = (total_zeros..bucket_len)
                .map(|j| nxt[base + j].idx)
                .collect();

            if zeros_actual != zeros_expected {
                return Err(format!(
                    "Bucket {}: Zeros not stable. Expected {:?}, got {:?}",
                    bucket, zeros_expected, zeros_actual
                ));
            }
            if ones_actual != ones_expected {
                return Err(format!(
                    "Bucket {}: Ones not stable. Expected {:?}, got {:?}",
                    bucket, ones_expected, ones_actual
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn test_build_level_single_bucket_split() {
        const N: usize = 8;

        // Single bucket containing all elements
        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Mixed bits pattern: [0,1,0,1,1,0,0,1]
        // This gives us 4 zeros and 4 ones
        let bits_lvl: [bool; N] = [false, true, false, true, true, false, false, true];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        // Run comprehensive invariant checks
        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("Single bucket split test failed");

        // Additional specific checks for this test case
        let zero_count = bits_lvl.iter().filter(|&&b| !b).count();
        let one_count = N - zero_count;
        assert_eq!(zero_count, 4);
        assert_eq!(one_count, 4);

        // Zeros should be in positions 0..4, ones in 4..8
        // Check that first 4 elements are zeros (bucket 0)
        for i in 0..zero_count {
            assert_eq!(
                nxt[i].bucket, 0,
                "First {} should be in bucket 0",
                zero_count
            );
            assert_eq!(nxt[i].length, zero_count as u16);
        }

        // Check that last 4 elements are ones (bucket 1)
        for i in zero_count..N {
            assert_eq!(nxt[i].bucket, 1, "Last {} should be in bucket 1", one_count);
            assert_eq!(nxt[i].length, one_count as u16);
        }

        // Verify stability: zeros should be [0,2,5,6], ones should be [1,3,4,7]
        let expected_zero_indices = vec![0, 2, 5, 6];
        let expected_one_indices = vec![1, 3, 4, 7];

        let actual_zero_indices: Vec<u16> = (0..zero_count).map(|i| nxt[i].idx).collect();
        let actual_one_indices: Vec<u16> = (zero_count..N).map(|i| nxt[i].idx).collect();

        assert_eq!(
            actual_zero_indices, expected_zero_indices,
            "Zero indices not stable"
        );
        assert_eq!(
            actual_one_indices, expected_one_indices,
            "One indices not stable"
        );
    }

    #[test]
    fn test_build_level_two_successive_layers() {
        const N: usize = 8;

        // Level 0: Single bucket
        let prev0: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // Level 1 bits: [0,1,0,1,0,1,0,1] - perfectly alternating
        let bits1: [bool; N] = [false, true, false, true, false, true, false, true];

        let (uns1, nxt1) = build_level::<N>(&prev0, &bits1);

        // Verify level 1
        assert_build_level_invariants(&prev0[..], &bits1[..], &uns1[..], &nxt1[..])
            .expect("Level 1 failed");

        // After level 1: nxt1 should have bucket 0 (zeros) and bucket 1 (ones)
        assert_eq!(nxt1[0..4].iter().all(|r| r.bucket == 0), true);
        assert_eq!(nxt1[4..8].iter().all(|r| r.bucket == 1), true);

        // Level 2 bits: split each bucket again
        // For bucket 0 (indices 0,2,4,6): [1,0,0,1]
        // For bucket 1 (indices 1,3,5,7): [0,1,1,0]
        let bits2: [bool; N] = [true, false, false, true, false, true, true, false];

        let (uns2, nxt2) = build_level::<N>(&nxt1, &bits2);

        // Verify level 2
        assert_build_level_invariants(&nxt1[..], &bits2[..], &uns2[..], &nxt2[..])
            .expect("Level 2 failed");

        // After level 2: should have 4 buckets (0,1,2,3)
        // Bucket 0: parent=0, bit=0 -> positions 0..2
        // Bucket 1: parent=0, bit=1 -> positions 2..4
        // Bucket 2: parent=1, bit=0 -> positions 4..6
        // Bucket 3: parent=1, bit=1 -> positions 6..8
        assert_eq!(nxt2[0..2].iter().all(|r| r.bucket == 0), true);
        assert_eq!(nxt2[2..4].iter().all(|r| r.bucket == 1), true);
        assert_eq!(nxt2[4..6].iter().all(|r| r.bucket == 2), true);
        assert_eq!(nxt2[6..8].iter().all(|r| r.bucket == 3), true);

        // Verify the final permutation matches expected
        // Level 1 placed: [0,2,4,6] then [1,3,5,7]
        // Level 2 with bits2=[1,0,0,1,0,1,1,0]:
        //   Bucket 0 zeros: [2,4], ones: [0,6]
        //   Bucket 1 zeros: [1,7], ones: [3,5]
        let expected_final_indices = vec![2, 4, 0, 6, 1, 7, 3, 5];
        let actual_final_indices: Vec<u16> = nxt2.iter().map(|r| r.idx).collect();
        assert_eq!(
            actual_final_indices, expected_final_indices,
            "Final permutation after 2 layers doesn't match expected"
        );
    }

    #[test]
    fn test_build_level_multi_bucket() {
        const N: usize = 12;

        // Three buckets: bucket 0 (size 3), bucket 1 (size 5), bucket 2 (size 4)
        let prev_rows: [SortedRow; N] = [
            SortedRow::new_with_bucket(0, 3, 0),
            SortedRow::new_with_bucket(1, 3, 0),
            SortedRow::new_with_bucket(2, 3, 0),
            SortedRow::new_with_bucket(3, 5, 1),
            SortedRow::new_with_bucket(4, 5, 1),
            SortedRow::new_with_bucket(5, 5, 1),
            SortedRow::new_with_bucket(6, 5, 1),
            SortedRow::new_with_bucket(7, 5, 1),
            SortedRow::new_with_bucket(8, 4, 2),
            SortedRow::new_with_bucket(9, 4, 2),
            SortedRow::new_with_bucket(10, 4, 2),
            SortedRow::new_with_bucket(11, 4, 2),
        ];

        // Mixed pattern: [0,1,0 | 1,1,0,0,1 | 0,0,1,1]
        let bits_lvl: [bool; N] = [
            false, true, false, // bucket 0: 2 zeros, 1 one
            true, true, false, false, true, // bucket 1: 2 zeros, 3 ones
            false, false, true, true, // bucket 2: 2 zeros, 2 ones
        ];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        // Run comprehensive invariant checks
        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("Multi-bucket test failed");

        // Verify bucket assignments and sizes
        // Bucket 0 splits into buckets 0 (2 zeros) and 1 (1 one)
        assert_eq!(nxt[0].bucket, 0);
        assert_eq!(nxt[0].length, 2);
        assert_eq!(nxt[1].bucket, 0);
        assert_eq!(nxt[1].length, 2);
        assert_eq!(nxt[2].bucket, 1);
        assert_eq!(nxt[2].length, 1);

        // Bucket 1 splits into buckets 2 (2 zeros) and 3 (3 ones)
        assert_eq!(nxt[3].bucket, 2);
        assert_eq!(nxt[3].length, 2);
        assert_eq!(nxt[4].bucket, 2);
        assert_eq!(nxt[4].length, 2);
        assert_eq!(nxt[5].bucket, 3);
        assert_eq!(nxt[5].length, 3);
        assert_eq!(nxt[6].bucket, 3);
        assert_eq!(nxt[6].length, 3);
        assert_eq!(nxt[7].bucket, 3);
        assert_eq!(nxt[7].length, 3);

        // Bucket 2 splits into buckets 4 (2 zeros) and 5 (2 ones)
        assert_eq!(nxt[8].bucket, 4);
        assert_eq!(nxt[8].length, 2);
        assert_eq!(nxt[9].bucket, 4);
        assert_eq!(nxt[9].length, 2);
        assert_eq!(nxt[10].bucket, 5);
        assert_eq!(nxt[10].length, 2);
        assert_eq!(nxt[11].bucket, 5);
        assert_eq!(nxt[11].length, 2);
    }

    #[test]
    fn test_build_level_all_zeros() {
        const N: usize = 6;

        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // All zeros
        let bits_lvl: [bool; N] = [false; N];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("All zeros test failed");

        // All elements should go to bucket 0
        for i in 0..N {
            assert_eq!(nxt[i].bucket, 0);
            assert_eq!(nxt[i].length, N as u16);
            assert_eq!(nxt[i].idx, i as u16); // Should maintain order
            assert_eq!(uns[i].next_pos, i as u16); // Should stay in place
        }
    }

    #[test]
    fn test_build_level_all_ones() {
        const N: usize = 6;

        let prev_rows: [SortedRow; N] =
            std::array::from_fn(|i| SortedRow::new_with_bucket(i as u16, N as u16, 0));

        // All ones
        let bits_lvl: [bool; N] = [true; N];

        let (uns, nxt) = build_level::<N>(&prev_rows, &bits_lvl);

        assert_build_level_invariants(&prev_rows[..], &bits_lvl[..], &uns[..], &nxt[..])
            .expect("All ones test failed");

        // All elements should go to bucket 1
        for i in 0..N {
            assert_eq!(nxt[i].bucket, 1);
            assert_eq!(nxt[i].length, N as u16);
            assert_eq!(nxt[i].idx, i as u16); // Should maintain order
            assert_eq!(uns[i].next_pos, i as u16); // Should stay in place (Z=0, so offset=o_i)
        }
    }
}
