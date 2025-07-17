use std::time::Instant;
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::bn::G1Affine;
use structopt::StructOpt;
use nexus_shuffling::*;
use serde_json;

#[derive(StructOpt)]
struct Cli {
    /// Proof system to use
    #[structopt(long, default_value = "groth16")]
    proof_system: String,
    
    /// Number of iterations for averaging
    #[structopt(long, default_value = "10")]
    iterations: usize,
    
    /// Include setup time in measurements
    #[structopt(long)]
    include_setup: bool,
    
    /// Output format (json or human)
    #[structopt(long, default_value = "human")]
    format: String,
}

fn main() {
    let args = Cli::from_args();
    
    // Initialize logger
    tracing_subscriber::fmt::init();
    
    // Generate test deck and keys
    let deck = generate_random_deck::<G1Projective>();
    let shuffler_keys = generate_shuffler_keys::<G1Projective>();
    let seed = Fr::from(42u64);
    
    // Determine proof system
    let proof_system = match args.proof_system.as_str() {
        "spartan" => ProofSystem::Spartan,
        "both" => ProofSystem::Both,
        _ => ProofSystem::Groth16,
    };
    
    // Run setup once
    let setup_start = Instant::now();
    let setup = setup::<Bn254, G1Projective, G1Affine<ark_bn254::Config>>(proof_system.clone())
        .expect("Setup failed");
    let setup_time = setup_start.elapsed();
    
    tracing::info!(target = "shuffle_bench", 
        "Setup completed in {:?} ({} constraints)", 
        setup_time, setup.constraint_count
    );
    
    let mut all_metrics = Vec::new();
    
    for i in 0..args.iterations {
        tracing::info!(target = "shuffle_bench", "Running iteration {}/{}", i+1, args.iterations);
        
        let start = Instant::now();
        let (_, mut metrics) = prove_with_setup::<Bn254, G1Projective, G1Affine<ark_bn254::Config>>(
            Fr::from((i + 42) as u64), // Vary seed per iteration
            deck.clone(),
            &shuffler_keys,
            &setup,
            proof_system.clone()
        ).expect("Proof generation failed");
        
        if args.include_setup && i == 0 {
            metrics.setup_time = Some(setup_time);
        }
        
        all_metrics.push(metrics);
        
        tracing::info!(target = "shuffle_bench", "Iteration {} took {:?}", i+1, start.elapsed());
    }
    
    // Output results
    match args.format.as_str() {
        "json" => output_json(&all_metrics),
        _ => output_human_readable(&all_metrics),
    }
}

fn generate_random_deck<C: ark_ec::CurveGroup>() -> EncryptedDeck<C> {
    use ark_std::UniformRand;
    let mut rng = ark_std::test_rng();
    let generator = C::generator();
    
    // Generate random encrypted cards
    let cards: Vec<ElGamalCiphertext<C>> = (0..DECK_SIZE)
        .map(|_| {
            let r1 = C::ScalarField::rand(&mut rng);
            let r2 = C::ScalarField::rand(&mut rng);
            ElGamalCiphertext {
                c1: generator * r1,
                c2: generator * r2,
            }
        })
        .collect();
    
    EncryptedDeck::new(cards).unwrap()
}

fn generate_shuffler_keys<C: ark_ec::CurveGroup>() -> ElGamalKeys<C> {
    use ark_std::UniformRand;
    let mut rng = ark_std::test_rng();
    let private_key = C::ScalarField::rand(&mut rng);
    ElGamalKeys::new(private_key)
}

fn output_json(metrics: &[ProofMetrics]) {
    let json = serde_json::to_string_pretty(metrics).unwrap();
    println!("{}", json);
}

fn output_human_readable(metrics: &[ProofMetrics]) {
    tracing::info!(target = "shuffle_bench", "\n=== Shuffle Proof Benchmarks ===\n");
    
    if let Some(setup_time) = metrics.first().and_then(|m| m.setup_time) {
        tracing::info!(target = "shuffle_bench", "Setup Phase:");
        tracing::info!(target = "shuffle_bench", "  One-time setup: {:?}", setup_time);
    }
    
    tracing::info!(target = "shuffle_bench", "Per-Proof Metrics (averaged over {} runs):", metrics.len());
    
    let avg_constraint_gen = average_duration(metrics.iter().map(|m| m.constraint_generation_time));
    let avg_witness_synth = average_duration(metrics.iter().map(|m| m.witness_synthesis_time));
    let avg_proof_gen = average_duration(metrics.iter().map(|m| m.proof_generation_time));
    let avg_total = average_duration(metrics.iter().map(|m| m.total_time));
    
    tracing::info!(target = "shuffle_bench", "  Constraint generation: {:?}", avg_constraint_gen);
    tracing::info!(target = "shuffle_bench", "  Witness synthesis: {:?}", avg_witness_synth);
    tracing::info!(target = "shuffle_bench", "  Proof generation: {:?}", avg_proof_gen);
    tracing::info!(target = "shuffle_bench", "  Total time: {:?}", avg_total);
    
    tracing::info!(target = "shuffle_bench", "Circuit Statistics:");
    tracing::info!(target = "shuffle_bench", "  Constraints: {}", metrics[0].constraint_count);
    tracing::info!(target = "shuffle_bench", "  Witnesses: {}", metrics[0].witness_count);
    tracing::info!(target = "shuffle_bench", "  Proof size: {} bytes", metrics[0].proof_size_bytes);
}

fn average_duration<I: Iterator<Item = std::time::Duration>>(durations: I) -> std::time::Duration {
    let collected: Vec<_> = durations.collect();
    if collected.is_empty() {
        return std::time::Duration::default();
    }
    
    let sum: std::time::Duration = collected.iter().sum();
    sum / collected.len() as u32
}