use ark_bn254::Fr as Bn254Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
    poseidon::PoseidonSponge, Absorb, CryptographicSponge,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use nexus_nova::poseidon_config;
use std::collections::HashMap;
use std::time::Instant;
use structopt::StructOpt;
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

const LOG_TARGET: &str = "poseidon_perf";

#[derive(Debug, StructOpt)]
#[structopt(name = "poseidon_performance", about = "Benchmark Poseidon hash performance")]
struct Opt {
    /// Number of rounds to perform
    #[structopt(short, long, default_value = "10")]
    rounds: usize,
    
    /// Enable verbose logging
    #[structopt(short, long)]
    verbose: bool,
}

fn init_tracing(verbose: bool) {
    let filter = if verbose {
        EnvFilter::new("")
            .add_directive("poseidon_perf=debug".parse().unwrap())
            .add_directive("gr1cs=info".parse().unwrap())
            .add_directive("r1cs=info".parse().unwrap())
            .add_directive(tracing::Level::WARN.into())
    } else {
        EnvFilter::new("")
            .add_directive("poseidon_perf=info".parse().unwrap())
            .add_directive(tracing::Level::WARN.into())
    };

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_line_number(true)
                .with_file(true)
                .with_timer(fmt::time::uptime()),
        )
        .with(filter)
        .init();
}

fn test_poseidon_performance_generic<F: PrimeField + Absorb>(
    num_rounds: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(target: LOG_TARGET, "Testing Poseidon performance for field: {} with {} rounds", std::any::type_name::<F>(), num_rounds);

    // Create a timing tracker
    let mut timings = HashMap::new();

    // First, let's run the native Poseidon operations to see expected performance
    tracing::info!(target: LOG_TARGET, "\n=== Native Poseidon Operations (no constraints) ===");

    // Profile config generation separately
    let config_start = Instant::now();
    let config = poseidon_config::<F>();
    let config_time = config_start.elapsed();
    timings.insert("poseidon_config_generation", config_time);
    tracing::info!(target: LOG_TARGET, "Config generation took: {:?}", config_time);

    let native_ops_start = Instant::now();
    let mut native_sponge = PoseidonSponge::new(&config);
    let seed_value = F::from(42u64);
    native_sponge.absorb(&seed_value);

    let mut native_random_values = Vec::new();

    for round in 0..num_rounds {
        // Absorb dummy evaluations
        let dummy_eval1 = F::from((round * 2) as u64);
        let dummy_eval2 = F::from((round * 2 + 1) as u64);
        native_sponge.absorb(&vec![dummy_eval1, dummy_eval2]);

        // Squeeze random value
        let random_value: F = native_sponge.squeeze_field_elements(1)[0];
        native_sponge.absorb(&random_value);

        native_random_values.push(random_value);
    }

    let native_ops_time = native_ops_start.elapsed();
    tracing::info!(target: LOG_TARGET, "Native operations for {} rounds took: {:?}", num_rounds, native_ops_time);
    tracing::info!(target: LOG_TARGET, "Average per round: {:?}", native_ops_time / num_rounds as u32);

    // Now let's do the constraint generation version
    tracing::info!(target: LOG_TARGET, "\n=== Constraint Generation Version ===");

    // Create constraint system
    let cs = ConstraintSystemRef::new(ConstraintSystem::new());

    // Create seed as public input
    let seed_var = FpVar::<F>::new_input(cs.clone(), || Ok(seed_value))?;

    // Measure constraint generation time
    let start = Instant::now();
    let initial_constraints = cs.num_constraints();

    // Profile sponge creation
    let sponge_start = Instant::now();
    tracing::debug!(target: LOG_TARGET, "Creating Poseidon sponge variable");
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &config);
    let sponge_creation_time = sponge_start.elapsed();
    timings.insert("sponge_var_creation", sponge_creation_time);
    tracing::info!(target: LOG_TARGET, "Sponge variable creation took: {:?}", sponge_creation_time);

    // Initial absorb of seed
    tracing::debug!(target: LOG_TARGET, "Absorbing seed into sponge");
    sponge.absorb(&seed_var)?;

    let mut all_random_values = Vec::new();
    let mut round_constraints = Vec::new();

    tracing::info!(target: LOG_TARGET, "Starting {} rounds of absorb/squeeze", num_rounds);

    let constraints_after_init = cs.num_constraints();
    tracing::info!(
        target: LOG_TARGET,
        "Constraints after Poseidon init: {} (init cost: {})",
        constraints_after_init,
        constraints_after_init - initial_constraints
    );

    for round in 0..num_rounds {
        let round_start_constraints = cs.num_constraints();

        // Create some dummy data to absorb (simulating sumcheck evaluations)
        let dummy_evals = vec![
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from((round * 2) as u64)))?,
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from((round * 2 + 1) as u64)))?,
        ];

        let after_witness_alloc = cs.num_constraints();

        // Absorb evaluations (like sumcheck does)
        tracing::debug!(target: LOG_TARGET, "Round {}: Absorbing evaluations", round);
        sponge.absorb(&dummy_evals)?;

        let after_absorb = cs.num_constraints();

        // Squeeze one field element per round (like sumcheck)
        tracing::debug!(target: LOG_TARGET, "Round {}: Squeezing field element", round);
        let random_value = sponge.squeeze_field_elements(1)?;

        let after_squeeze = cs.num_constraints();

        // Absorb the squeezed value back (like sumcheck does with r_k)
        sponge.absorb(&random_value[0])?;

        let round_end_constraints = cs.num_constraints();
        let round_total = round_end_constraints - round_start_constraints;
        round_constraints.push(round_total);

        tracing::info!(
            target: LOG_TARGET,
            "Round {}: {} constraints (witness: {}, absorb1: {}, squeeze: {}, absorb2: {})",
            round,
            round_total,
            after_witness_alloc - round_start_constraints,
            after_absorb - after_witness_alloc,
            after_squeeze - after_absorb,
            round_end_constraints - after_squeeze
        );

        all_random_values.push(random_value[0].clone());
    }

    let constraint_gen_time = start.elapsed();
    let final_constraints = cs.num_constraints();
    let constraints_added = final_constraints - initial_constraints;

    // Verify we got all random values
    assert_eq!(
        all_random_values.len(),
        num_rounds,
        "Should get exactly {} random values",
        num_rounds
    );

    // Log results
    tracing::info!(
        target: LOG_TARGET,
        "Poseidon hash for {} rounds completed in {:?}",
        num_rounds,
        constraint_gen_time
    );

    // Print round-by-round summary
    tracing::info!(target: LOG_TARGET, "\n=== Round-by-round constraint summary ===");
    for (i, &count) in round_constraints.iter().enumerate() {
        tracing::info!(target: LOG_TARGET, "Round {}: {} constraints", i, count);
    }

    // Calculate statistics
    let min_round = round_constraints.iter().min().unwrap_or(&0);
    let max_round = round_constraints.iter().max().unwrap_or(&0);
    let avg_round = if num_rounds > 0 { constraints_added / num_rounds } else { 0 };

    tracing::info!(target: LOG_TARGET, "\n=== Statistics ===");
    tracing::info!(target: LOG_TARGET, "Min constraints per round: {}", min_round);
    tracing::info!(target: LOG_TARGET, "Max constraints per round: {}", max_round);
    tracing::info!(target: LOG_TARGET, "Avg constraints per round: {}", avg_round);
    tracing::info!(
        target: LOG_TARGET,
        "Constraints added: {} (from {} to {})",
        constraints_added,
        initial_constraints,
        final_constraints
    );
    tracing::info!(
        target: LOG_TARGET,
        "Constraints per round: {}",
        avg_round
    );
    tracing::info!(
        target: LOG_TARGET,
        "Average time per round: {:?}",
        constraint_gen_time / num_rounds as u32
    );

    // Check if the constraint system is satisfied
    let is_satisfied = cs.is_satisfied()?;
    tracing::info!(
        target: LOG_TARGET,
        satisfied = is_satisfied,
        "Constraint system satisfaction check"
    );
    assert!(is_satisfied, "Constraint system should be satisfied");

    // Compare with native execution
    tracing::info!(target: LOG_TARGET, "\n=== Comparison ===");
    tracing::info!(
        target: LOG_TARGET,
        "Native operations: {:?} total, {:?} per round",
        native_ops_time,
        native_ops_time / num_rounds as u32
    );
    tracing::info!(
        target: LOG_TARGET,
        "Constraint generation: {:?} total, {:?} per round",
        constraint_gen_time,
        constraint_gen_time / num_rounds as u32
    );
    tracing::info!(
        target: LOG_TARGET,
        "Overhead factor: {:.2}x",
        constraint_gen_time.as_secs_f64() / native_ops_time.as_secs_f64()
    );

    // Verify the random values match between native and circuit
    for (i, (native_val, circuit_val)) in native_random_values
        .iter()
        .zip(all_random_values.iter())
        .enumerate()
    {
        let circuit_value = circuit_val.value()?;
        assert_eq!(
            *native_val, circuit_value,
            "Round {} random values should match",
            i
        );
    }
    tracing::info!(target: LOG_TARGET, "✅ All random values match between native and circuit execution");

    // Print profiling summary
    tracing::info!(target: LOG_TARGET, "\n=== Profiling Summary ===");
    let mut sorted_timings: Vec<_> = timings.iter().collect();
    sorted_timings.sort_by(|a, b| b.1.cmp(a.1));

    for (name, duration) in sorted_timings {
        tracing::info!(
            target: LOG_TARGET,
            "{}: {:?} ({:.2}% of total)",
            name,
            duration,
            (duration.as_secs_f64() / constraint_gen_time.as_secs_f64()) * 100.0
        );
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    
    init_tracing(opt.verbose);
    
    tracing::info!(target: LOG_TARGET, "Starting Poseidon performance benchmark");
    tracing::info!(target: LOG_TARGET, "Field: BN254::Fr");
    tracing::info!(target: LOG_TARGET, "Rounds: {}", opt.rounds);
    
    test_poseidon_performance_generic::<Bn254Fr>(opt.rounds)?;
    
    tracing::info!(target: LOG_TARGET, "\n✅ Benchmark completed successfully");
    
    Ok(())
}