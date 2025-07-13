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

/// Apply SHA-256 padding to a message
/// SHA-256 padding works as follows:
/// 1. Append a single '1' bit (0x80 byte)
/// 2. Append zeros until length ≡ 448 (mod 512), i.e., 56 bytes (mod 64)
/// 3. Append the original message length as a 64-bit big-endian integer
pub fn sha256_padding(message: &[u8]) -> Vec<u8> {
    let msg_len = message.len();
    let bit_len = (msg_len as u64) * 8;
    
    // Calculate padding length
    // We need to pad to a multiple of 64 bytes (512 bits)
    // The last 8 bytes are for the length, so we pad to 56 bytes (mod 64)
    let padding_len = if msg_len % 64 < 56 {
        56 - (msg_len % 64)
    } else {
        64 + 56 - (msg_len % 64)
    };
    
    // Create padded message
    let mut padded = Vec::with_capacity(msg_len + padding_len + 8);
    padded.extend_from_slice(message);
    
    // Append 0x80 (single '1' bit followed by zeros)
    padded.push(0x80);
    
    // Append zeros
    padded.extend(vec![0u8; padding_len - 1]);
    
    // Append length as 64-bit big-endian
    padded.extend_from_slice(&bit_len.to_be_bytes());
    
    debug_assert_eq!(padded.len() % 64, 0, "Padded message must be multiple of 64 bytes");
    
    padded
}

/// Apply SHA-256 padding in circuit
pub fn sha256_padding_circuit<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    message: &[UInt8<F>],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let msg_len = message.len();
    let bit_len = (msg_len as u64) * 8;
    
    // Calculate padding length (same as native version)
    let padding_len = if msg_len % 64 < 56 {
        56 - (msg_len % 64)
    } else {
        64 + 56 - (msg_len % 64)
    };
    
    // Create padded message
    let mut padded = Vec::with_capacity(msg_len + padding_len + 8);
    padded.extend_from_slice(message);
    
    // Append 0x80
    padded.push(UInt8::constant(0x80));
    
    // Append zeros
    for _ in 0..(padding_len - 1) {
        padded.push(UInt8::constant(0));
    }
    
    // Append length as 64-bit big-endian
    let length_bytes = bit_len.to_be_bytes();
    for &byte in &length_bytes {
        padded.push(UInt8::constant(byte));
    }
    
    Ok(padded)
}

/// Utility for converting between bytes and field elements
pub mod conversions {
    use super::*;
    use ark_ff::BigInteger;

    /// Convert a field element to bytes (for SHA-256 hashes)
    /// This is the inverse of bytes_to_field - uses little-endian unpacking
    pub fn field_to_bytes<F: PrimeField>(field_val: &F) -> Vec<u8> {
        let mut result = vec![0u8; 32];
        
        // Convert field element to BigInt representation for easier manipulation
        let mut bigint = field_val.into_bigint();
        
        // Use as many bytes as we can fit in the field (same as bytes_to_field)
        let max_bytes = (F::MODULUS_BIT_SIZE as usize - 1) / 8;
        let actual_bytes = max_bytes.min(32);
        
        // Extract bytes in little-endian order (inverse of bytes_to_field)
        for i in 0..actual_bytes {
            // Extract the lowest byte from the BigInt
            if !bigint.is_zero() {
                let low_limb = bigint.as_ref()[0]; // Get lowest limb
                result[i] = (low_limb & 0xFF) as u8;
                
                // Shift right by 8 bits (divide by 256)
                let mut carry = 0u64;
                for limb in bigint.as_mut().iter_mut().rev() {
                    let temp = (*limb as u128) + ((carry as u128) << 64);
                    *limb = (temp >> 8) as u64;
                    carry = (temp & 0xFF) as u64;
                }
            } else {
                result[i] = 0;
            }
        }
        
        result
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
    
    /// Test round-trip conversion: bytes -> field -> bytes
    #[cfg(test)]
    pub fn test_round_trip_conversion<F: PrimeField>(original_bytes: &[u8]) -> (F, Vec<u8>) {
        let field_val = bytes_to_field::<F>(original_bytes);
        let recovered_bytes = field_to_bytes(&field_val);
        (field_val, recovered_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use crate::tree_folding::mangrove::circuit::sha256_var::Sha256Var;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_sha256_padding() {
        // Test case 1: Empty message
        let msg = b"";
        let padded = super::sha256_padding(msg);
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[0], 0x80);
        assert_eq!(&padded[56..64], &0u64.to_be_bytes());
        
        // Test case 2: "abc" (3 bytes)
        let msg = b"abc";
        let padded = super::sha256_padding(msg);
        assert_eq!(padded.len(), 64);
        assert_eq!(&padded[0..3], b"abc");
        assert_eq!(padded[3], 0x80);
        assert_eq!(&padded[56..64], &24u64.to_be_bytes()); // 3 * 8 = 24 bits
        
        // Test case 3: 55 bytes (will fit in 64 bytes)
        let msg = vec![b'a'; 55];
        let padded = super::sha256_padding(&msg);
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[55], 0x80);
        assert_eq!(&padded[56..64], &440u64.to_be_bytes()); // 55 * 8 = 440 bits
        
        // Test case 4: 56 bytes (will need to pad to 128 bytes)
        let msg = vec![b'a'; 56];
        let padded = super::sha256_padding(&msg);
        assert_eq!(padded.len(), 128);
        assert_eq!(padded[56], 0x80);
        assert_eq!(&padded[120..128], &448u64.to_be_bytes()); // 56 * 8 = 448 bits
        
        // Test case 5: 32 bytes (common case for SHA256 output)
        let msg = vec![0u8; 32];
        let padded = super::sha256_padding(&msg);
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[32], 0x80);
        assert_eq!(&padded[56..64], &256u64.to_be_bytes()); // 32 * 8 = 256 bits
    }

    #[test]
    fn test_field_conversion_consistency() {
        // Test with a real SHA256 hash
        let input = b"test conversion consistency";
        let hash_bytes = calculate_sha256_native(input);
        assert_eq!(hash_bytes.len(), 32);
        
        // Method 1: Direct conversion using conversions functions
        let field_from_bytes = conversions::bytes_to_field::<Fr>(&hash_bytes);
        let bytes_from_field = conversions::field_to_bytes(&field_from_bytes);
        
        // Method 2: Via Sha256Var
        let cs = ConstraintSystem::<Fr>::new_ref();
        let sha256_var = Sha256Var::<Fr>::new_variable(
            cs.clone(),
            || Ok(hash_bytes.clone()),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        let field_from_sha256var = sha256_var.to_field_var().unwrap().value().unwrap();
        
        println!("Original bytes: {:?}", hex::encode(&hash_bytes));
        println!("Field from bytes_to_field: {:?}", field_from_bytes);
        println!("Field from Sha256Var: {:?}", field_from_sha256var);
        println!("Bytes from field_to_bytes: {:?}", hex::encode(&bytes_from_field));
        
        // The key assertion: field values must be equal
        assert_eq!(
            field_from_bytes, 
            field_from_sha256var,
            "conversions::bytes_to_field and Sha256Var::to_field_var must produce the same result"
        );
        
        // Round-trip test: Original -> Field -> Bytes should preserve the original data
        // (at least for the used bytes)
        let max_bytes = (Fr::MODULUS_BIT_SIZE as usize - 1) / 8;
        let usable_bytes = max_bytes.min(32);
        assert_eq!(
            &hash_bytes[..usable_bytes],
            &bytes_from_field[..usable_bytes],
            "Round-trip conversion should preserve original bytes"
        );
    }
} 