use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::UniformRand;
use ark_poly::polynomial::Polynomial;
use nexus_nova::provider::PolyCommitmentScheme;
use ark_std::{test_rng, One, Zero};

mod shared;
use shared::{DEFAULT_CONSTRAINT_SIZES, utils, calculate_srs_degree};

use folding_benches::test_utils::create_test_ccs_shape;

use nexus_nova::{
    bench_utils::to_field_elements,
    ccs::{
        CCSInstance, CCSWitness, ACCSInstance,
    },
    folding::hypernova::{
        accs_folding::{ACCSFoldingProof, Error},
    },
    zeromorph::Zeromorph,
};

type G1 = BN254G1;
type CF = BN254Fr;
type Z = Zeromorph<Bn254>;

fn main() {
    // Run benchmarks
    bench_accs_folding();
}

// Simple benchmark results struct
struct BenchResult {
    constraints: usize,
    operation: &'static str,
    time_ms: f64,
}

/// Benchmark function for ACCS folding protocol
fn bench_accs_folding() {
    let ro_config = utils::create_ro_config::<CF>();
    
    let mut rng = test_rng();
    
    // Results collection
    let mut results = Vec::new();
    
    // Create a custom format for our output
    println!("ACCS-Folding Benchmark Results");
    println!("----------------------------");
    println!("| Constraints | Operation | Time (ms) |");
    println!("----------------------------");
    
    for &num_constraints in DEFAULT_CONSTRAINT_SIZES.iter() {
        if num_constraints == 0 {
            continue; // Skip 0 constraint case
        }
        
        // Calculate appropriate SRS degree for this constraint size
        let srs_degree = calculate_srs_degree(num_constraints);
        // Setup SRS with appropriate degree
        let SRS = Z::setup(srs_degree, b"test-accs", &mut rng).unwrap();
        // Create commitment key with appropriate degree
        let ck = Z::trim(&SRS, srs_degree - 1).ck;

        // === PROVE BENCHMARK ===
        let mut prove_times = Vec::new();
        
        // Run each test 10 times to get an average
        for _ in 0..10 {
            // Create a new shape for this iteration
            let shape = create_test_ccs_shape::<G1>(num_constraints);

            // Create verification key
            let vk = CF::zero();

            // Create witness and instance for first ACCS instance
            let w_values1 = vec![CF::one(); shape.num_vars];
            let witness1 = CCSWitness::<G1>::new(&shape, &w_values1).unwrap();
            let commitment_W1 = witness1.commit::<Z>(&ck);
            
            // Create the first ACCS instance
            let v0 = CF::one();
            let io = to_field_elements::<G1>(&[1, 35]);
            let s_x = ark_std::log2(shape.num_constraints) as usize;
            let r_x: Vec<CF> = (0..s_x).map(|_| CF::rand(&mut rng)).collect();
            let s_y = ark_std::log2(shape.num_vars) as usize;
            let r_y: Vec<CF> = (0..s_y).map(|_| CF::rand(&mut rng)).collect();
            
            // Compute correct evaluations of M_j(z) at point r_x for the first instance
            let z_test1 = [&[v0], &io[1..], &witness1.W].concat();
            let vs1: Vec<CF> = shape.Ms.iter()
                .map(|M| {
                    nexus_nova::ccs::mle::vec_to_ark_mle(
                        M.multiply_vec(&z_test1).as_slice()
                    ).evaluate(&r_x)
                })
                .collect();
            
            // Compute correct evaluation of z at point r_y for the first instance
            let v_z1 = nexus_nova::ccs::mle::vec_to_ark_mle(
                witness1.W.as_slice()
            ).evaluate(&r_y);
            
            // Create the first ACCS instance
            let accs1 = ACCSInstance::<G1, Z>::new(
                &commitment_W1,
                &v0,
                &io,
                &r_x,
                &r_y,
                &vs1,
                &v_z1,
            ).unwrap();
            
            // Create witness and instance for second instance (CCS)
            let w_values2 = vec![CF::one(); shape.num_vars];
            let witness2 = CCSWitness::<G1>::new(&shape, &w_values2).unwrap();
            let commitment_W2 = witness2.commit::<Z>(&ck);
            
            // Create the CCS instance
            let ccs = CCSInstance::<G1, Z>::new(
                &shape,
                &commitment_W2,
                &io,
            ).unwrap();
            
            // Initialize random oracle with the config
            let mut random_oracle = PoseidonSponge::<CF>::new(&ro_config);
            
            // Measure proving time
            let start = Instant::now();
            
            let proof_result = ACCSFoldingProof::<G1, PoseidonSponge<CF>>::prove_as_subprotocol(
                &mut random_oracle,
                &vk,
                &shape,
                (&accs1, &witness1),
                (&ccs, &witness2),
            );

            // Record time regardless of success or failure
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            
            // Skip this iteration if proving fails
            if proof_result.is_err() {
                eprintln!("Warning: Proof generation failed for circuit size {}", num_constraints);
                continue;
            }
            
            prove_times.push(elapsed_ms);
        }
        
        // Calculate average prove time if we have any successful runs
        if !prove_times.is_empty() {
            let avg_prove_time = prove_times.iter().sum::<f64>() / prove_times.len() as f64;
            results.push(BenchResult {
                constraints: num_constraints,
                operation: "Prove",
                time_ms: avg_prove_time,
            });
            
            println!("| {} | Prove | {:.2} ms |", num_constraints, avg_prove_time);
        }
        
        // === VERIFY BENCHMARK ===
        // Only run verification benchmark if we could generate a proof
        if prove_times.is_empty() {
            continue;
        }
        
        // Setup for verification benchmark
        let shape = create_test_ccs_shape::<G1>(num_constraints);
        let vk = CF::zero();
        
        // Create witness and instance for first ACCS instance
        let w_values1 = vec![CF::one(); shape.num_vars];
        let witness1 = CCSWitness::<G1>::new(&shape, &w_values1).unwrap();
        let commitment_W1 = witness1.commit::<Z>(&ck);
        
        // Create the first ACCS instance
        let v0 = CF::one();
        let io = to_field_elements::<G1>(&[1, 35]);
        let s_x = ark_std::log2(shape.num_constraints) as usize;
        let r_x: Vec<CF> = (0..s_x).map(|_| CF::rand(&mut rng)).collect();
        let s_y = ark_std::log2(shape.num_vars) as usize;
        let r_y: Vec<CF> = (0..s_y).map(|_| CF::rand(&mut rng)).collect();
        
        // Compute correct evaluations of M_j(z) at point r_x for the first instance
        let z_test1 = [&[v0], &io[1..], &witness1.W].concat();
        let vs1: Vec<CF> = shape.Ms.iter()
            .map(|M| {
                nexus_nova::ccs::mle::vec_to_ark_mle(
                    M.multiply_vec(&z_test1).as_slice()
                ).evaluate(&r_x)
            })
            .collect();
        
        // Compute correct evaluation of z at point r_y for the first instance
        let v_z1 = nexus_nova::ccs::mle::vec_to_ark_mle(
            witness1.W.as_slice()
        ).evaluate(&r_y);
        
        // Create the first ACCS instance
        let accs1 = ACCSInstance::<G1, Z>::new(
            &commitment_W1,
            &v0,
            &io,
            &r_x,
            &r_y,
            &vs1,
            &v_z1,
        ).unwrap();
        
        // Create witness and instance for second instance (CCS)
        let w_values2 = vec![CF::one(); shape.num_vars];
        let witness2 = CCSWitness::<G1>::new(&shape, &w_values2).unwrap();
        let commitment_W2 = witness2.commit::<Z>(&ck);
        
        // Create the CCS instance
        let ccs = CCSInstance::<G1, Z>::new(
            &shape,
            &commitment_W2,
            &io,
        ).unwrap();
        
        // Generate proof for verification benchmarks
        let mut random_oracle = PoseidonSponge::<CF>::new(&ro_config);
        // Attempt to generate a proof
        let proof_result = ACCSFoldingProof::<G1, PoseidonSponge<CF>>::prove_as_subprotocol(
            &mut random_oracle,
            &vk,
            &shape,
            (&accs1, &witness1),
            (&ccs, &witness2),
        );

        // If proof generation fails, we can't continue with verification
        if proof_result.is_err() {
            eprintln!("Warning: Proof generation failed for verification benchmark with circuit size {}", num_constraints);
            continue;
        }

        let (proof, _folded_instance, _eta) = proof_result.unwrap();
        
        let mut verify_times = Vec::new();
        
        // Run each test 10 times to get an average
        for _ in 0..10 {
            // Initialize new random oracle for verification
            let mut random_oracle = PoseidonSponge::<CF>::new(&ro_config);
            
            // Measure verification time
            let start = Instant::now();

            let result = proof.verify_as_subprotocol::<Z>(
                &mut random_oracle,
                &vk,
                &shape,
                &accs1,
                &ccs,
            );

            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            
            // Skip this iteration if verification fails
            if result.is_err() {
                eprintln!("Warning: Verification failed for circuit size {}", num_constraints);
                continue;
            }
            
            verify_times.push(elapsed_ms);
        }
        
        // Calculate average verify time if we have any successful runs
        if !verify_times.is_empty() {
            let avg_verify_time = verify_times.iter().sum::<f64>() / verify_times.len() as f64;
            results.push(BenchResult {
                constraints: num_constraints,
                operation: "Verify",
                time_ms: avg_verify_time,
            });
            
            println!("| {} | Verify | {:.2} ms |", num_constraints, avg_verify_time);
        }
    }
    
    println!("----------------------------");
    println!("Benchmark completed");
}