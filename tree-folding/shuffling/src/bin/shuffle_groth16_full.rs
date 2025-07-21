use structopt::StructOpt;
use tracing_subscriber;

#[allow(unused_imports)]
use nexus_shuffling::*;
#[allow(unused_imports)]
use serde_json;

// For BN254, the constraint system works over Fr (scalar field) but the G1 curve
// operations work over Fq (base field). This creates a mismatch that requires
// non-native field arithmetic to resolve properly.
//
// The shuffle_groth16.rs binary demonstrates a simplified circuit that works around
// this limitation. This file is left as a placeholder to document the issue.

const LOG_TARGET: &str = "shuffle_groth16_full";

#[derive(StructOpt)]
#[allow(dead_code)]
struct Cli {
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
    let _args = Cli::from_args();

    // Initialize logger
    tracing_subscriber::fmt::init();

    tracing::error!(
        target = LOG_TARGET,
        "The full circuit implementation for BN254 is not currently available due to field mismatch issues."
    );
    tracing::error!(
        target = LOG_TARGET,
        "BN254's constraint system works over Fr (scalar field) but G1 curve operations work over Fq (base field)."
    );
    tracing::error!(
        target = LOG_TARGET,
        "This requires non-native field arithmetic which is not implemented."
    );
    tracing::info!(
        target = LOG_TARGET,
        "Please use the shuffle-groth16 binary instead, which demonstrates a simplified circuit."
    );
    
    std::process::exit(1);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn run_groth16_benchmark(_iterations: usize, _include_setup: bool) -> Vec<ProofMetrics> {
    // This function is kept for reference but cannot be implemented for BN254
    // due to the field mismatch issue described above
    vec![]
}


#[allow(dead_code)]
fn output_json(_metrics: &[ProofMetrics]) {
    // Kept for reference
}

#[allow(dead_code)]
fn output_human_readable(_metrics: &[ProofMetrics]) {
    // Kept for reference
}
