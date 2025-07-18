use nexus_shuffling::*;
use serde_json;
use structopt::StructOpt;
use tracing_subscriber;
use ark_bn254::Bn254;
use ark_ed_on_bn254::{EdwardsConfig, Fr};
use ark_ec::Group;
use ark_ff::PrimeField;
use ark_std::UniformRand;
use std::time::Instant;

const LOG_TARGET: &str = "shuffling";

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

    println!("Shuffle benchmark temporarily disabled due to curve parameter setup issues.");
    println!("The Spartan integration requires matching arkworks versions.");

    // For now, just create a dummy metrics output
    let dummy_metrics = vec![ProofMetrics {
        constraint_generation_time: std::time::Duration::from_secs(0),
        witness_synthesis_time: std::time::Duration::from_secs(0),
        proof_generation_time: std::time::Duration::from_secs(0),
        total_time: std::time::Duration::from_secs(0),
        constraint_count: 0,
        witness_count: 0,
        proof_size_bytes: 0,
        setup_time: None,
        commitment_time: std::time::Duration::from_secs(0),
        polynomial_construction_time: std::time::Duration::from_secs(0),
    }];

    // Output results
    match args.format.as_str() {
        "json" => output_json(&dummy_metrics),
        _ => output_human_readable(&dummy_metrics),
    }
}

fn output_json(metrics: &[ProofMetrics]) {
    let json = serde_json::to_string_pretty(metrics).unwrap();
    println!("{}", json);
}

fn output_human_readable(metrics: &[ProofMetrics]) {
    tracing::info!(target = LOG_TARGET, "\n=== Shuffle Proof Benchmarks ===\n");

    if let Some(setup_time) = metrics.first().and_then(|m| m.setup_time) {
        tracing::info!(target = LOG_TARGET, "Setup Phase:");
        tracing::info!(target = LOG_TARGET, "  One-time setup: {:?}", setup_time);
    }

    tracing::info!(
        target = LOG_TARGET,
        "Per-Proof Metrics (averaged over {} runs):",
        metrics.len()
    );

    let avg_constraint_gen = average_duration(metrics.iter().map(|m| m.constraint_generation_time));
    let avg_witness_synth = average_duration(metrics.iter().map(|m| m.witness_synthesis_time));
    let avg_proof_gen = average_duration(metrics.iter().map(|m| m.proof_generation_time));
    let avg_total = average_duration(metrics.iter().map(|m| m.total_time));

    tracing::info!(
        target = LOG_TARGET,
        "  Constraint generation: {:?}",
        avg_constraint_gen
    );
    tracing::info!(
        target = LOG_TARGET,
        "  Witness synthesis: {:?}",
        avg_witness_synth
    );
    tracing::info!(
        target = LOG_TARGET,
        "  Proof generation: {:?}",
        avg_proof_gen
    );
    tracing::info!(target = LOG_TARGET, "  Total time: {:?}", avg_total);

    tracing::info!(target = LOG_TARGET, "\nCircuit Statistics:");
    tracing::info!(
        target = LOG_TARGET,
        "  Constraints: {}",
        metrics[0].constraint_count
    );
    tracing::info!(
        target = LOG_TARGET,
        "  Witnesses: {}",
        metrics[0].witness_count
    );
    tracing::info!(
        target = LOG_TARGET,
        "  Proof size: {} bytes",
        metrics[0].proof_size_bytes
    );
}

fn average_duration<I: Iterator<Item = std::time::Duration>>(durations: I) -> std::time::Duration {
    let collected: Vec<_> = durations.collect();
    if collected.is_empty() {
        return std::time::Duration::default();
    }

    let sum: std::time::Duration = collected.iter().sum();
    sum / collected.len() as u32
}
