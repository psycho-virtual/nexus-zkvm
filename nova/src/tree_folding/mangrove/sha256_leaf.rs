use crate::tree_folding::circuit::sha256::calculate_sha256_native;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SHA256LeafJob {
    pub input: Vec<u8>,
    pub expected_output: Option<Vec<u8>>,
    pub num_iterations: usize,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SHA256LeafData {
    pub initial_input: Vec<u8>,
    pub final_output: Vec<u8>,
    pub intermediate_hashes: Vec<Vec<u8>>,
    pub num_iterations: usize,
}

impl SHA256LeafJob {
    pub fn new(input: Vec<u8>, num_iterations: usize) -> Self {
        Self {
            input,
            expected_output: None,
            num_iterations,
        }
    }

    pub fn with_expected_output(mut self, output: Vec<u8>) -> Self {
        self.expected_output = Some(output);
        self
    }
}

impl SHA256LeafData {
    pub fn new(
        initial_input: Vec<u8>,
        final_output: Vec<u8>,
        intermediate_hashes: Vec<Vec<u8>>,
        num_iterations: usize,
    ) -> Self {
        Self {
            initial_input,
            final_output,
            intermediate_hashes,
            num_iterations,
        }
    }

    pub fn verify(&self) -> bool {
        if self.intermediate_hashes.len() != self.num_iterations {
            return false;
        }

        // Verify the chain of hashes
        let mut current = self.initial_input.clone();
        for (i, expected_hash) in self.intermediate_hashes.iter().enumerate() {
            let computed = calculate_sha256_native(&current);
            
            if &computed != expected_hash {
                return false;
            }
            
            if i < self.intermediate_hashes.len() - 1 {
                current = computed;
            }
        }

        // Verify final output matches
        self.intermediate_hashes.last() == Some(&self.final_output)
    }
}