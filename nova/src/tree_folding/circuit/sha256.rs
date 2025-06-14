use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    uint8::UInt8,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use tracing::instrument;
use std::marker::PhantomData;

// Import the StepCircuit trait
use crate::circuits::nova::StepCircuit;

// Import the SHA-256 gadget
use ark_crypto_primitives::crh::{
    sha256::{constraints::Sha256Gadget, Sha256},
    CRHScheme, CRHSchemeGadget,
};

/// Define a SHA-256 circuit using arkworks crypto-primitives
#[derive(Debug)]
pub struct Sha256Circuit<F: PrimeField> {
    pub message: Vec<u8>,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> Sha256Circuit<F> {
    pub fn new(message: &[u8]) -> Self {
        Self {
            message: message.to_vec(),
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit<F> for Sha256Circuit<F> {
    // Set ARITY to 1 (one input state variable)
    const ARITY: usize = 1;

    #[instrument(level = "debug")]
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: &FpVar<F>,
        _z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Record the initial number of constraints
        let initial_constraints = cs.num_constraints();

        // Convert message bytes to UInt8 variables
        let message_vars = UInt8::new_witness_vec(cs.clone(), &self.message)?;

        // Create a unit parameter for the SHA-256 gadget (SHA-256 doesn't need parameters)
        let unit_var = ark_crypto_primitives::crh::sha256::constraints::UnitVar::<F>::default();

        // Use the SHA-256 gadget to compute the hash
        let digest_var = <Sha256Gadget<F> as CRHSchemeGadget<Sha256, F>>::evaluate(
            &unit_var,
            &message_vars
        )?;

        // Pack bytes into a field element using constraint variables (not witness values)
        let mut result_var = FpVar::zero();
        let mut power = F::one();

        // Use as many bytes as we can fit in the field
        let max_bytes = (F::MODULUS_BIT_SIZE as usize - 1) / 8;
        for byte_var in digest_var.0.iter().take(max_bytes) {
            // Convert UInt8 constraint variable to FpVar and add to result
            let byte_as_fp = byte_var.to_fp()?;
            result_var += &byte_as_fp * power;
            // Multiply by 256 for the next byte
            power *= F::from(256u32);
        }

        // Record the final number of constraints
        let final_constraints = cs.num_constraints();
        tracing::debug!("SHA-256 circuit constraints: {}", final_constraints - initial_constraints);

        // Return the hash as a single field element
        Ok(vec![result_var])
    }
}

/// Helper function to calculate the SHA-256 hash using the native implementation
#[instrument(level = "debug")]
pub fn calculate_sha256_native(message: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256 as NativeSha256};

    let mut hasher = NativeSha256::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

/// Helper function to calculate the SHA-256 hash using the arkworks implementation
pub fn calculate_sha256_arkworks(message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(42);
    let parameters = <Sha256 as CRHScheme>::setup(&mut rng)?;
    let hash = <Sha256 as CRHScheme>::evaluate(&parameters, message)?;

    Ok(hash)
}

/// Utility for converting between bytes and field elements
pub mod conversions {
    use super::*;

    /// Convert a field element to bytes (for SHA-256 hashes)
    pub fn field_to_bytes<F: PrimeField>(field_val: &F) -> Vec<u8> {
        
        // Using API for field serialization
        let mut bytes = Vec::new();
        field_val.serialize_compressed(&mut bytes).unwrap_or_default();
        if bytes.len() >= 32 {
            bytes[0..32].to_vec() // Take first 32 bytes for SHA-256
        } else {
            // Pad with zeros if needed
            let mut padded = vec![0u8; 32];
            for (i, b) in bytes.iter().enumerate().take(32) {
                padded[i] = *b;
            }
            padded
        }
    }

    /// Convert bytes to a field element (for SHA-256 hashes)
    pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> F {
        let mut result = F::zero();
        let mut power = F::from(1u64);

        // Use as many bytes as we can fit in the field
        let max_bytes = (F::MODULUS_BIT_SIZE as usize - 1) / 8;
        for &byte in bytes.iter().take(max_bytes) {
            // Convert byte to field element and add to result
            let byte_as_fe = F::from(byte as u64);
            result += byte_as_fe * power;
            // Multiply by 256 for the next byte
            power *= F::from(256u64);
        }

        result
    }
} 