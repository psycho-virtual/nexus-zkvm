use crate::tree_folding::circuit::sha256::calculate_sha256_native;
use tracing::{debug, info, instrument};

const LOG_TARGET: &str = "nexus-nova::tree_folding::mangrove::sha256_chain";

/// Generate a chain of SHA256 hashes
/// 
/// Takes an initial input and computes num_iterations of SHA256 hashes,
/// where each iteration uses the output of the previous hash as input.
/// Returns all intermediate hashes (not including the initial input).
#[instrument(target = LOG_TARGET, skip(input))]
pub fn generate_sha256_chain(input: &[u8], num_iterations: usize) -> Vec<Vec<u8>> {
    info!(
        target: LOG_TARGET,
        "Generating SHA256 chain with {} iterations, input length: {} bytes",
        num_iterations,
        input.len()
    );
    
    let mut hashes = Vec::with_capacity(num_iterations);
    let mut current = input.to_vec();
    
    debug!(
        target: LOG_TARGET,
        "Starting with input: {}",
        hex::encode(&current)
    );
    
    // Compute and store each hash in the chain
    for i in 0..num_iterations {
        let hash = calculate_sha256_native(&current);
        debug!(
            target: LOG_TARGET,
            "Iteration {}: input {} -> hash {}",
            i + 1,
            hex::encode(&current),
            hex::encode(&hash)
        );
        hashes.push(hash.clone());
        current = hash;
    }
    
    info!(
        target: LOG_TARGET,
        "SHA256 chain generation complete, produced {} hashes",
        hashes.len()
    );
    
    hashes
}

/// Generate SHA256 leaf data for a given input
#[instrument(target = LOG_TARGET, skip(input))]
pub fn generate_sha256_leaf_data(input: Vec<u8>, num_iterations: usize) -> super::SHA256LeafData {
    info!(
        target: LOG_TARGET,
        "Generating SHA256 leaf data with {} iterations",
        num_iterations
    );
    
    let hashes = generate_sha256_chain(&input, num_iterations);
    let final_output = hashes.last().unwrap().clone();
    
    debug!(
        target: LOG_TARGET,
        "Final output hash: {}",
        hex::encode(&final_output)
    );
    
    super::SHA256LeafData::new(input, final_output, hashes, num_iterations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target("nexus-nova", tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer()
                    .without_time()
                    .with_line_number(true),
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn test_sha256_chain_single_iteration() {
        let _guard = setup_test_tracing();
        let input = b"hello world";
        let chain = generate_sha256_chain(input, 1);
        
        assert_eq!(chain.len(), 1);
        
        // Verify the hash matches expected value
        let expected = calculate_sha256_native(input);
        assert_eq!(chain[0], expected);
    }

    #[test]
    fn test_sha256_chain_multiple_iterations() {
        let _guard = setup_test_tracing();
        let input = b"test input";
        let iterations = 3;
        let chain = generate_sha256_chain(input, iterations);
        
        assert_eq!(chain.len(), iterations);
        
        // Verify each hash is the SHA256 of the previous
        let mut current = input.to_vec();
        for hash in &chain {
            let expected = calculate_sha256_native(&current);
            assert_eq!(hash, &expected);
            current = hash.clone();
        }
    }

    #[test]
    fn test_generate_sha256_leaf_data() {
        let _guard = setup_test_tracing();
        let input = b"leaf data".to_vec();
        let iterations = 2;
        let leaf_data = generate_sha256_leaf_data(input.clone(), iterations);
        
        assert_eq!(leaf_data.initial_input, input);
        assert_eq!(leaf_data.num_iterations, iterations);
        assert_eq!(leaf_data.intermediate_hashes.len(), iterations);
        assert_eq!(leaf_data.final_output, leaf_data.intermediate_hashes.last().unwrap().clone());
        
        // Verify the data is valid
        assert!(leaf_data.verify());
    }

    #[test]
    fn test_sha256_chain_matches_sequential_implementation() {
        let _guard = setup_test_tracing();
        // Test that our implementation matches the pattern used in sha256_chain_folder.rs
        let input = b"test message";
        let chain = generate_sha256_chain(input, 2);
        
        // Manually verify the chain
        let hash1 = calculate_sha256_native(input);
        let hash2 = calculate_sha256_native(&hash1);
        
        assert_eq!(chain[0], hash1);
        assert_eq!(chain[1], hash2);
    }
}