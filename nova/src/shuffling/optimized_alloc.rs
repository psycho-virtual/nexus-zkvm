use super::data_structures::{
    ElGamalCiphertext, ElGamalCiphertextVar, ShuffleProof, ShuffleProofVar,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    groups::curves::short_weierstrass::ProjectiveVar,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

const LOG_TARGET: &str = "shuffle::circuit";

/// Optimized batch allocation for ElGamal ciphertexts
pub fn batch_allocate_ciphertexts<G: SWCurveConfig>(
    cs: impl Into<Namespace<G::BaseField>>,
    ciphertexts: &[ElGamalCiphertext<Projective<G>>],
    mode: AllocationMode,
) -> Result<Vec<ElGamalCiphertextVar<G>>, SynthesisError>
where
    G::BaseField: PrimeField,
{
    let ns = cs.into();
    let cs = ns.cs();

    // Allocate all points without individual namespaces
    // DO NOT convert to affine - it's extremely expensive!
    let mut result = Vec::with_capacity(ciphertexts.len());

    for ct in ciphertexts {
        // Allocate projective points directly
        let c1 =
            ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(cs.clone(), || Ok(ct.c1), mode)?;

        let c2 =
            ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(cs.clone(), || Ok(ct.c2), mode)?;

        result.push(ElGamalCiphertextVar { c1, c2 });
    }

    Ok(result)
}

/// Optimized ShuffleProofVar allocation
impl<G: SWCurveConfig> ShuffleProofVar<G>
where
    G::BaseField: PrimeField,
{
    pub fn new_variable_optimized<T: std::borrow::Borrow<ShuffleProof<Projective<G>>>>(
        cs: impl Into<Namespace<G::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let value = f()?;
        let proof = value.borrow();

        tracing::debug!(target: "shuffle::alloc", "Starting optimized allocation");

        // Batch allocate input deck
        let input_deck = batch_allocate_ciphertexts(cs.clone(), &proof.input_deck.cards, mode)?;

        tracing::debug!(target: "shuffle::alloc", "sorted deck allocation");
        // Allocate sorted deck with minimal overhead
        // DO NOT convert to affine - extremely expensive!
        let mut sorted_deck = Vec::with_capacity(proof.sorted_deck.len());
        for (ct, random_val) in &proof.sorted_deck {
            let c1 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
                cs.clone(),
                || Ok(ct.c1),
                mode,
            )?;

            let c2 = ProjectiveVar::<G, FpVar<G::BaseField>>::new_variable(
                cs.clone(),
                || Ok(ct.c2),
                mode,
            )?;

            let random_var =
                FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*random_val), mode)?;

            sorted_deck.push((ElGamalCiphertextVar { c1, c2 }, random_var));
        }

        tracing::debug!(target: "shuffle::alloc", "randomization values allocation");
        // Batch allocate rerandomization values
        let rerandomization_values: Result<Vec<_>, _> = proof
            .rerandomization_values
            .iter()
            .map(|val| FpVar::<G::BaseField>::new_variable(cs.clone(), || Ok(*val), mode))
            .collect();

        tracing::debug!(target: "shuffle::alloc", "done allocation");
        Ok(Self {
            input_deck,
            sorted_deck,
            rerandomization_values: rerandomization_values?,
        })
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::{
        filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    };

    const TEST_TARGET: &str = "shuffling";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new().with_target(TEST_TARGET, tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(), // This ensures output goes to test stdout
            )
            .with(filter)
            .set_default()
    }

    use super::*;
    use ark_bn254::{g1::Config, Fq};
    use ark_ec::PrimeGroup;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_batch_allocation_performance() {
        type G = Config;
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Create test data
        let mut ciphertexts = vec![];
        for _ in 0..52 {
            let ct = ElGamalCiphertext {
                c1: Projective::<G>::default(),
                c2: Projective::<G>::default(),
            };
            ciphertexts.push(ct);
        }

        // Time the batch allocation
        let start = std::time::Instant::now();
        let result = batch_allocate_ciphertexts(cs.clone(), &ciphertexts, AllocationMode::Witness);
        let duration = start.elapsed();

        assert!(result.is_ok());
        println!("Batch allocation took: {:?}", duration);
    }

    #[test]
    fn test_new_variable_optimized_performance() {
        use super::super::data_structures::{EncryptedDeck, ShuffleProof};
        use ark_bn254::{Fq as BN254Fq, Fr as BN254Fr};
        use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};

        let _ = setup_test_tracing();
        type G = GrumpkinConfig;
        // Grumpkin's base field is BN254's scalar field (Fr)
        let cs = ConstraintSystem::<BN254Fr>::new_ref();

        // Create test shuffle proof with realistic data
        let gen = GrumpkinProjective::generator();

        // Create input deck
        let mut cards = vec![];
        for i in 0..52 {
            // For Grumpkin, scalar field is BN254's Fq
            let scalar = BN254Fq::from(i as u64);
            let ct = ElGamalCiphertext {
                c1: gen * scalar,
                c2: gen * scalar * BN254Fq::from(2u64),
            };
            cards.push(ct);
        }
        let input_deck = EncryptedDeck { cards };

        // Create sorted deck with random values
        let mut sorted_deck = vec![];
        for i in 0..52 {
            let scalar = BN254Fq::from((51 - i) as u64); // Reverse order for testing
            let ct = ElGamalCiphertext {
                c1: gen * scalar,
                c2: gen * scalar * BN254Fq::from(3u64),
            };
            // Random values are in the base field (BN254's Fr)
            let random_val = BN254Fr::from((i * 7) as u64);
            sorted_deck.push((ct, random_val));
        }

        // Create rerandomization values (in base field)
        let mut rerandomization_values = vec![];
        for i in 0..52 {
            rerandomization_values.push(BN254Fr::from((i * 11) as u64));
        }

        let proof = ShuffleProof {
            input_deck,
            sorted_deck,
            rerandomization_values,
        };

        // Time the new_variable_optimized implementation from data_structures.rs
        let start = std::time::Instant::now();
        let result = ShuffleProofVar::<G>::new_variable_optimized(
            cs.clone(),
            || Ok(&proof),
            AllocationMode::Witness,
        );
        let duration = start.elapsed();

        assert!(result.is_ok());
        let proof_var = result.unwrap();

        tracing::info!(target = LOG_TARGET, "Does it stop here? Let me know");

        tracing::info!(
            target = LOG_TARGET,
            "Shuffle proof witness allocated. Input deck size: {}",
            proof_var.input_deck.len()
        );

        println!("new_variable_optimized took: {:?}", duration);
        println!("Input deck size: {}", proof_var.input_deck.len());
        println!("Sorted deck size: {}", proof_var.sorted_deck.len());
        println!(
            "Rerandomization values: {}",
            proof_var.rerandomization_values.len()
        );
        println!("Total witness variables: {}", cs.num_witness_variables());
        println!("Total constraints: {}", cs.num_constraints());
    }
}
