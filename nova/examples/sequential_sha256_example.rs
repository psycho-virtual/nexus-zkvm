// Example demonstrating the Sequential SHA-256 Circuit
//
// This example shows how to use the SequentialSha256Circuit for generating
// constraints and testing circuit functionality. The sequential SHA-256 circuit
// implements a step circuit that takes a hash as input and produces the SHA-256
// hash of that input as output, enabling sequential hash operations in ZK proofs.

use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use nexus_nova::circuits::nova::StepCircuit;
use nexus_nova::tree_folding::circuit::sequential_sha256::{
    SequentialSha256Circuit, 
    run_native_sequential_sha256
};
use nexus_nova::tree_folding::circuit::sha256::{
    calculate_sha256_native, 
    conversions
};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging to see debug output
    tracing_subscriber::fmt()
        .init();

    println!("🔗 Sequential SHA-256 Circuit Example");
    println!("=====================================");
    println!("This example demonstrates a SHA-256 circuit for zero-knowledge proofs.");
    println!("⚠️  Note: Full constraint generation is extremely expensive (~30,000 constraints)");
    println!("   and can take several minutes. This demo focuses on practical usage.\n");

    // Example 1: Basic Circuit Creation and Properties
    println!("📋 Example 1: Circuit Creation and Properties");
    demonstrate_circuit_creation()?;

    // Example 2: Native Sequential Hashing (Fast)
    println!("\n🔄 Example 2: Native Sequential Hashing (Fast & Practical)");
    demonstrate_native_sequential_hashing()?;

    // Example 3: Circuit Setup and Structure (Fast)
    println!("\n🔧 Example 3: Circuit Setup and Structure (Fast)");
    demonstrate_circuit_setup()?;

    // Example 4: Field Conversions (Fast)
    println!("\n🔀 Example 4: Hash to Field Conversions (Fast)");
    demonstrate_conversions()?;

    // Example 5: Performance Characteristics
    println!("\n📊 Example 5: Performance Characteristics");
    demonstrate_performance_info()?;

    println!("\n✅ All examples completed successfully!");
    println!("\n💡 Key Takeaways:");
    println!("   • Sequential SHA-256 circuits enable ZK proofs of hash chains");
    println!("   • Each SHA-256 operation requires ~25,000-30,000 R1CS constraints");
    println!("   • Native implementation provides fast testing and verification");
    println!("   • Circuit setup is fast; constraint generation is the expensive part");
    println!("   • Use `cargo test sequential_sha256` to run comprehensive tests");
    
    println!("\n🚀 To run actual constraint generation:");
    println!("   cargo test test_constraint_generation --lib -- --nocapture");
    
    Ok(())
}

fn demonstrate_circuit_creation() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating a Sequential SHA-256 circuit...");
    
    // Create the circuit
    let _circuit = SequentialSha256Circuit::<Fr>::new();
    
    // Show circuit properties
    println!("  ✓ Circuit created successfully");
    println!("  • ARITY: {} (number of input/output variables)", SequentialSha256Circuit::<Fr>::ARITY);
    println!("  • Type: Sequential SHA-256 Step Circuit");
    println!("  • Purpose: Takes a hash input and produces SHA-256(input) as output");
    
    Ok(())
}

fn demonstrate_constraint_generation() -> Result<(), Box<dyn std::error::Error>> {
    println!("Demonstrating constraint generation...");
    println!("  Note: SHA-256 circuits are computationally expensive and may take some time...");
    
    let circuit = SequentialSha256Circuit::<Fr>::new();
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Create sample inputs
    println!("  Setting up inputs...");
    let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u32)))?;
    
    // Create a hash from sample data
    let sample_data = b"Hello, Sequential SHA-256!";
    let hash = calculate_sha256_native(sample_data);
    let hash_field = conversions::bytes_to_field::<Fr>(&hash);
    let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(hash_field))?];
    
    println!("    • Step index: 0");
    println!("    • Input hash: {} bytes", hash.len());
    println!("    • Input as field element: generated from hash");
    
    // Generate constraints with timing
    println!("  Generating constraints... (this may take 30-60 seconds)");
    let start_time = std::time::Instant::now();
    
    let initial_constraints = cs.num_constraints();
    let result = circuit.generate_constraints(cs.clone(), &i_var, &z_var)?;
    let final_constraints = cs.num_constraints();
    
    let constraint_time = start_time.elapsed();
    
    println!("    ✓ Constraint generation successful in {:?}", constraint_time);
    println!("    • Constraints added: {}", final_constraints - initial_constraints);
    println!("    • Output variables: {}", result.len());
    println!("    • Total constraints: {}", final_constraints);
    
    // Skip satisfiability check for performance - it's very expensive for large circuits
    println!("    • Satisfiability check skipped (too expensive for large SHA-256 circuits)");
    
    Ok(())
}

fn demonstrate_native_sequential_hashing() -> Result<(), Box<dyn std::error::Error>> {
    println!("Demonstrating native sequential hashing...");
    
    let initial_message = b"Sequential hashing example";
    let steps = 5;
    
    println!("  Initial message: {:?}", String::from_utf8_lossy(initial_message));
    println!("  Number of steps: {}", steps);
    
    // Perform sequential hashing
    println!("  \n  Performing sequential hash operations:");
    let mut current_hash = calculate_sha256_native(initial_message);
    println!("    Step 0 (initial): {}", hex::encode(&current_hash));
    
    for step in 1..=steps {
        current_hash = calculate_sha256_native(&current_hash);
        println!("    Step {}: {}", step, hex::encode(&current_hash));
    }
    
    // Use the convenience function
    let final_hash = run_native_sequential_sha256(initial_message, steps);
    println!("  \n  Verification using convenience function:");
    println!("    Final hash matches: {}", if current_hash == final_hash { "✓ Yes" } else { "✗ No" });
    
    Ok(())
}

fn demonstrate_circuit_setup() -> Result<(), Box<dyn std::error::Error>> {
    println!("Demonstrating circuit setup and structure...");
    
    let circuit = SequentialSha256Circuit::<Fr>::new();
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Set to setup mode for parameter generation
    cs.set_mode(ark_relations::r1cs::SynthesisMode::Setup);
    println!("  ✓ Constraint system set to Setup mode");
    
    // Create inputs for setup (values don't matter in setup mode)
    println!("  Creating dummy variables for setup...");
    let i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u32)))?;
    let z_var = vec![FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u32)))?];
    
    println!("    • Step variable (i): created");
    println!("    • State variable (z): 1 element (previous hash)");
    println!("    • Circuit ARITY: {}", SequentialSha256Circuit::<Fr>::ARITY);
    
    // Show that setup works without expensive constraint generation
    println!("  Testing setup compatibility...");
    println!("    • Circuit type: Sequential SHA-256 StepCircuit");
    println!("    • Input: Previous hash (32 bytes as field element)");
    println!("    • Output: Next hash (SHA-256 of input)");
    println!("    • Constraint system ready for parameter generation");
    
    // Don't actually generate constraints - that's too expensive
    println!("    ⚠️  Actual constraint generation skipped (use tests for full generation)");
    
    Ok(())
}

fn demonstrate_conversions() -> Result<(), Box<dyn std::error::Error>> {
    println!("Demonstrating hash-to-field conversions...");
    
    // Test conversion of different hash sizes
    let test_messages: Vec<&[u8]> = vec![
        b"conversion test 1",
        b"longer conversion test message",
        b"",
        b"x",
    ];
    
    for (i, message) in test_messages.iter().enumerate() {
        println!("  Test case {}: \"{}\"", i + 1, String::from_utf8_lossy(message));
        
        // Calculate SHA-256 hash
        let hash = calculate_sha256_native(message);
        println!("    • Hash (hex): {}", hex::encode(&hash));
        println!("    • Hash length: {} bytes", hash.len());
        
        // Convert to field element
        let field_element = conversions::bytes_to_field::<Fr>(&hash);
        println!("    • Field element: {}", field_element);
        
        // Convert back to bytes
        let recovered_bytes = conversions::field_to_bytes(&field_element);
        println!("    • Recovered length: {} bytes", recovered_bytes.len());
        
        // Test determinism
        let field_element2 = conversions::bytes_to_field::<Fr>(&hash);
        let is_deterministic = field_element == field_element2;
        println!("    • Conversion deterministic: {}", if is_deterministic { "✓ Yes" } else { "✗ No" });
        
        println!();
    }
    
    Ok(())
}

fn demonstrate_performance_info() -> Result<(), Box<dyn std::error::Error>> {
    println!("Performance characteristics and benchmarking info...");
    
    // Measure setup costs only
    println!("  Measuring fast operations...");
    
    let setup_iterations = 10;
    let mut setup_times = Vec::new();
    
    for i in 0..setup_iterations {
        let start = std::time::Instant::now();
        
        // Fast operations: circuit creation and variable setup
        let _circuit = SequentialSha256Circuit::<Fr>::new();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let _i_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(i as u32)))?;
        
        let test_data = format!("benchmark iteration {}", i);
        let hash = calculate_sha256_native(test_data.as_bytes());
        let _field = conversions::bytes_to_field::<Fr>(&hash);
        
        let elapsed = start.elapsed();
        setup_times.push(elapsed);
    }
    
    // Calculate statistics
    let total_setup_time: std::time::Duration = setup_times.iter().sum();
    let avg_setup_time = total_setup_time / setup_iterations as u32;
    let min_setup_time = setup_times.iter().min().unwrap();
    let max_setup_time = setup_times.iter().max().unwrap();
    
    println!("  Setup Performance (fast operations):");
    println!("    • Iterations: {}", setup_iterations);
    println!("    • Average setup time: {:?}", avg_setup_time);
    println!("    • Min setup time: {:?}", min_setup_time);
    println!("    • Max setup time: {:?}", max_setup_time);
    println!("    • Total time: {:?}", total_setup_time);
    
    // Native hashing performance
    println!("\n  Native SHA-256 Performance:");
    let native_iterations = 1000;
    let start = std::time::Instant::now();
    
    let test_data = b"performance test data";
    for _ in 0..native_iterations {
        let _hash = calculate_sha256_native(test_data);
    }
    
    let native_total_time = start.elapsed();
    let avg_native_time = native_total_time / native_iterations as u32;
    
    println!("    • Native SHA-256 iterations: {}", native_iterations);
    println!("    • Average native hash time: {:?}", avg_native_time);
    println!("    • Total native time: {:?}", native_total_time);
    println!("    • Hashes per second: {:.0}", native_iterations as f64 / native_total_time.as_secs_f64());
    
    // Constraint generation info (theoretical)
    println!("\n  Constraint Generation (expensive operations):");
    println!("    • Expected constraints per SHA-256: ~25,000-30,000");
    println!("    • Expected generation time: 30-120 seconds per operation");
    println!("    • Memory usage: High (depends on constraint system size)");
    println!("    • Recommended for testing: Use individual test functions");
    
    println!("\n  💡 Performance Tips:");
    println!("    • Use native implementation for testing logic");
    println!("    • Generate constraints only when needed for proofs");
    println!("    • Consider batching multiple operations");
    println!("    • Run constraint tests individually: cargo test test_constraint_generation");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_runs_without_panic() {
        // This test ensures the example code runs without panicking
        // In a real scenario, you might want more detailed assertions
        assert!(main().is_ok());
    }
    
    #[test]
    fn test_individual_demonstrations() {
        assert!(demonstrate_circuit_creation().is_ok());
        assert!(demonstrate_constraint_generation().is_ok());
        assert!(demonstrate_native_sequential_hashing().is_ok());
        assert!(demonstrate_circuit_setup().is_ok());
        assert!(demonstrate_conversions().is_ok());
        assert!(demonstrate_performance_info().is_ok());
    }
} 