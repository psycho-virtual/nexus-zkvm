use std::time::Instant;

use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::{Field, UniformRand, Zero};
use ark_std::test_rng;

mod shared;
use shared::{DEFAULT_CONSTRAINT_SIZES};

// Import the benchmark utils
use nexus_nova::{
    bench_utils::to_field_elements,
    ccs::{
        mle::vec_to_mle,
        CCSInstance, CCSWitness, LCCSInstance,
    },
    folding::hypernova::{
        nimfs::NIMFSProof,
    },
    poseidon_config,
    zeromorph::Zeromorph,
    provider::PolyCommitmentScheme, // Import the trait
    safe_loglike,
};

// Import our local test utils
use folding_benches::test_utils;

type G1 = BN254G1;
type CF = BN254Fr;
type Z = Zeromorph<Bn254>;

fn main() {
    // Run benchmarks
    bench_nimfs_folding();
}

/// Benchmark function for NIMFS folding protocol with verification
/// This implementation exactly follows the test version in Nova that works
fn bench_nimfs_folding() {
    // Use the exact same poseidon config as in the tests
    let ro_config = poseidon_config::<CF>();
    
    // Create a custom format for our output
    println!("NIMFS-Folding Benchmark Results");
    println!("----------------------------");
    println!("| Constraints | Operation | Time (ms) |");
    println!("----------------------------");
    
    for &num_constraints in DEFAULT_CONSTRAINT_SIZES.iter() {
        if num_constraints == 0 {
            continue; // Skip 0 constraint case
        }

        // === PROVE BENCHMARK ===
        let mut prove_times = Vec::new();
        let mut verify_times = Vec::new();
        
        // Run each test multiple times to get an average
        for _ in 0..5 {
            let mut rng = test_rng();

            // First, create a proper SRS for the commitment scheme
            let srs_degree = num_constraints.next_power_of_two() * 4; // Ensure sufficient size
            let srs = Z::setup(srs_degree, b"test-nimfs", &mut rng).unwrap();
            let ck = Z::trim(&srs, srs_degree - 1).ck;
            
            // Global verification key
            let vk = CF::zero();
            
            // --- Set up second instance (CCS) with our test_utils ---
            // Use our custom setup function that mirrors the Nova test setup
            let (shape, u2, w2, _) = test_utils::setup_small_ccs::<G1, Z>(num_constraints, Some(&ck), Some(&mut rng));
            
            // --- Set up first instance (LCCS) with zero witness ---
            // Just like in the tests
            let io1 = to_field_elements::<G1>(&vec![0; shape.num_io]);
            let w1 = CCSWitness::zero(&shape);
            
            // Commit to the witness
            let commitment_w1 = w1.commit::<Z>(&ck);
            
            // Create random values for rs - SAME as test
            let s = safe_loglike!(shape.num_constraints);
            let rs: Vec<CF> = (0..s).map(|_| CF::rand(&mut rng)).collect();
            
            // Compute z vector (concatenation of input and witness)
            let z = [io1.as_slice(), w1.W.as_slice()].concat();
            
            // Compute vs vector (evaluate MLEs on rs)
            let vs: Vec<CF> = shape.Ms.iter()
                .map(|m| {
                    vec_to_mle(
                        m.multiply_vec(&z).as_slice()
                    ).evaluate::<G1>(rs.as_slice())
                })
                .collect();
            
            // Create LCCS instance
            let lccs = LCCSInstance::<G1, Z>::new(
                &shape,
                &commitment_w1,
                &io1,
                rs.as_slice(), // Pass slice directly
                vs.as_slice(),
            ).unwrap();
            
            // --- Run proving benchmark ---
            // Fresh random oracle for proving
            let mut prover_ro = PoseidonSponge::<CF>::new(&ro_config);
            
            let start = Instant::now();
            
            let proof_result = NIMFSProof::<G1, PoseidonSponge<CF>>::prove_as_subprotocol(
                &mut prover_ro,
                &vk,
                &shape,
                (&lccs, &w1),
                (&u2, &w2),
            );
            
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            
            // Skip if proving fails
            if proof_result.is_err() {
                println!("Proof generation failed: {:?}", proof_result.err());
                continue;
            }
            
            prove_times.push(elapsed_ms);
            
            // --- Run verification benchmark ---
            let (proof, (folded_u, folded_w), _rho) = proof_result.unwrap();
            
            // Completely fresh random oracle for verification
            let mut verifier_ro = PoseidonSponge::<CF>::new(&ro_config);
            
            let verify_start = Instant::now();
            let verification_result = proof.verify_as_subprotocol::<Z>(
                &mut verifier_ro,
                &vk,
                &shape,
                &lccs,
                &u2,
            );
            
            let verify_elapsed = verify_start.elapsed();
            let verify_ms = verify_elapsed.as_secs_f64() * 1000.0;
            
            if verification_result.is_ok() {
                verify_times.push(verify_ms);
                
                // Double check that the folded instance satisfies constraints
                let satisfaction_result = shape.is_satisfied_linearized::<Z>(&folded_u, &folded_w, &ck);
                if satisfaction_result.is_ok() {
                    println!("✓ Folded instance satisfaction check: PASSED");
                } else {
                    println!("✗ Folded instance satisfaction check: FAILED - {:?}", satisfaction_result.err());
                }
            } else {
                println!("Verification failed: {:?}", verification_result.err());
            }
        }
        
        // Calculate and display average prove time
        if !prove_times.is_empty() {
            let avg_prove_time = prove_times.iter().sum::<f64>() / prove_times.len() as f64;
            println!("| {:^11} | {:^9} | {:^8.2} |", num_constraints, "Prove", avg_prove_time);
        }
        
        // Calculate and display average verify time
        if !verify_times.is_empty() {
            let avg_verify_time = verify_times.iter().sum::<f64>() / verify_times.len() as f64;
            println!("| {:^11} | {:^9} | {:^8.2} |", num_constraints, "Verify", avg_verify_time);
        } else if !prove_times.is_empty() {
            println!("| {:^11} | {:^9} | {:^8} |", num_constraints, "Verify", "FAILED");
        }
    }
    
    println!("----------------------------");
    println!("Benchmark completed");
}