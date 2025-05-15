//! Folding benchmarks for comparing ACCS and NIMFS folding protocols

// Basic metrics for benchmarking

/// Helper functions for creating test instances
pub mod test_utils {
    use ark_ec::CurveGroup;
    use ark_std::One;
    use std::ops::Neg;

    use nexus_nova::ccs::{CCSShape, SparseMatrix};

    /// Creates a test CCS shape for benchmarking
    pub fn create_test_ccs_shape<G: CurveGroup>(num_constraints: usize) -> CCSShape<G> {
        // Create a simple shape for testing
        let num_vars = num_constraints; // Equal size for simplicity
        let num_io = 2;
        let num_matrices = 3;

        // Create matrices with format expected by SparseMatrix::new
        let matrices: Vec<SparseMatrix<G::ScalarField>> = (0..num_matrices)
            .map(|_| {
                // MatrixRef<'a, F> = &'a [Vec<(F, usize)>]
                // We need to supply rows as Vec<(value, column)> for each row
                let mut matrix: Vec<Vec<(G::ScalarField, usize)>> = Vec::new();
                for i in 0..num_constraints {
                    let mut row = Vec::new();
                    // Add 3 entries per row
                    row.push((G::ScalarField::one(), i % num_vars));
                    row.push((G::ScalarField::one(), (i + 1) % num_vars));
                    row.push((G::ScalarField::one(), (i + 2) % num_vars));

                    // Ensure entries are sorted by column index
                    row.sort_by_key(|entry| entry.1);

                    matrix.push(row);
                }
                SparseMatrix::new(&matrix, num_constraints, num_vars + num_io)
            })
            .collect();

        CCSShape {
            num_constraints,
            num_vars,
            num_io,
            num_matrices,
            num_multisets: 2,
            max_cardinality: 2,
            Ms: matrices,
            cSs: vec![
                (G::ScalarField::one(), vec![0, 1]),
                (G::ScalarField::one().neg(), vec![2]),
            ],
        }
    }
}

