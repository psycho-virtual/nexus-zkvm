use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::vec::Vec;

/// Convert a slice of integers to a vector of field elements
/// This is made public for benchmarking purposes
pub fn to_field_elements<G: CurveGroup>(x: &[i64]) -> Vec<G::ScalarField> {
    x.iter()
        .map(|&x| {
            if x >= 0 {
                G::ScalarField::from(x as u64)
            } else {
                -G::ScalarField::from((-x) as u64)
            }
        })
        .collect()
}

/// Create sparse matrix entries from integers
/// This is made public for benchmarking purposes
pub fn to_field_sparse<G: CurveGroup>(matrix: &[&[i64]]) -> Vec<(usize, usize, G::ScalarField)> {
    let mut entries = Vec::new();
    for (i, row) in matrix.iter().enumerate() {
        for (j, &value) in row.iter().enumerate() {
            if value != 0 {
                let element = if value > 0 {
                    G::ScalarField::from(value as u64)
                } else {
                    -G::ScalarField::from((-value) as u64)
                };
                entries.push((i, j, element));
            }
        }
    }
    entries
}