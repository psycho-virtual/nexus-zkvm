use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar}, 
    uint8::UInt8, 
    alloc::AllocVar, 
    R1CSVar
};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef, Namespace};
use std::borrow::Borrow;

use super::IntoFpVarVec;

/// A variable representing a SHA-256 hash value in the constraint system
#[derive(Clone)]
pub struct Sha256Var<F: PrimeField> {
    /// The 32-byte hash value represented as UInt8 variables
    pub bytes: Vec<UInt8<F>>,
}

impl<F: PrimeField> Sha256Var<F> {
    /// Create a new Sha256Var from UInt8 variables
    pub fn new(bytes: Vec<UInt8<F>>) -> Result<Self, SynthesisError> {
        if bytes.len() != 32 {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self { bytes })
    }

    /// Convert to a SINGLE field element by packing bytes (little-endian)
    /// This is the packed representation: bytes[0] + bytes[1]*256 + bytes[2]*256^2 + ...
    /// 
    /// Note: This is different from into_fp_var_vec() which returns 32 separate field elements.
    /// Use this when you need a compressed representation for efficiency (e.g., Merkle trees).
    /// Use into_fp_var_vec() when you need individual bytes as field elements (e.g., permutations).
    pub fn to_field_var(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut result = FpVar::<F>::zero();
        let mut power = F::one();

        // Use as many bytes as we can fit in the field
        let max_bytes = (F::MODULUS_BIT_SIZE as usize - 1) / 8;
        for byte_var in self.bytes.iter().take(max_bytes) {
            let byte_as_fp = byte_var.to_fp()?;
            result += &byte_as_fp * power;
            power *= F::from(256u32);
        }

        Ok(result)
    }
}

impl<F: PrimeField> IntoFpVarVec<F> for Sha256Var<F> {
    fn into_fp_var_vec(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Convert each byte to its own field element
        // This gives us 32 field elements for SHA-256
        let mut result = Vec::with_capacity(32);
        for byte_var in &self.bytes {
            let byte_as_fp = byte_var.to_fp()?;
            result.push(byte_as_fp);
        }
        Ok(result)
    }
}

// Implement R1CSVar for Sha256Var
impl<F: PrimeField> R1CSVar<F> for Sha256Var<F> {
    type Value = Vec<u8>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.bytes[0].cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut result = Vec::with_capacity(32);
        for byte_var in &self.bytes {
            result.push(byte_var.value()?);
        }
        Ok(result)
    }
}

// Implement AllocVar for Sha256Var
impl<F: PrimeField> AllocVar<Vec<u8>, F> for Sha256Var<F> {
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let bytes = f()?.borrow().clone();
        
        if bytes.len() != 32 {
            return Err(SynthesisError::Unsatisfiable);
        }
        
        let byte_vars: Result<Vec<_>, _> = bytes
            .iter()
            .map(|&b| UInt8::new_variable(cs.clone(), || Ok(b), mode))
            .collect();
        Ok(Self { bytes: byte_vars? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::{uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_into_fp_var_vec_no_new_witnesses() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Create a SHA256Var from bytes
        let bytes = vec![42u8; 32];
        let sha_var = Sha256Var::<Fr>::new_variable(
            cs.clone(),
            || Ok(bytes),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        
        // Record witness count before calling into_fp_var_vec
        let witness_count_before = cs.num_witness_variables();
        
        // Call into_fp_var_vec
        let fp_vars = sha_var.into_fp_var_vec().unwrap();
        
        // Record witness count after conversion
        let witness_count_after = cs.num_witness_variables();
        
        // Verify no new witness variables were created
        assert_eq!(
            witness_count_before, 
            witness_count_after,
            "IntoFpVarVec should not create new witness variables"
        );
        
        // Verify we got 32 FpVars (one for each byte)
        assert_eq!(fp_vars.len(), 32, "Should return 32 FpVars (one per byte)");
        
        // Verify the conversion itself works by checking constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_sha256_var_to_field_var() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Create known bytes
        let mut bytes = vec![0u8; 32];
        bytes[0] = 1;  // Least significant byte
        bytes[1] = 2;
        
        let byte_vars = UInt8::new_witness_vec(cs.clone(), &bytes).unwrap();
        let sha_var = Sha256Var::new(byte_vars).unwrap();
        
        // Convert to field
        let field_var = sha_var.to_field_var().unwrap();
        let field_value = field_var.value().unwrap();
        
        // Expected value: 1 + 2*256 = 513
        let expected = Fr::from(1u64) + Fr::from(2u64) * Fr::from(256u64);
        assert_eq!(field_value, expected);
    }

    #[test]
    fn test_sha256_var_invalid_length() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Try to create with wrong length
        let bytes = vec![0u8; 31]; // Wrong length
        let byte_vars = UInt8::new_witness_vec(cs, &bytes).unwrap();
        
        let result = Sha256Var::new(byte_vars);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_var_field_conversion_consistency() {
        use crate::tree_folding::circuit::sha256::{calculate_sha256_native, conversions};
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Test with a real SHA256 hash
        let input = b"test conversion consistency";
        let hash_bytes = calculate_sha256_native(input);
        assert_eq!(hash_bytes.len(), 32);
        
        // Method 1: Create Sha256Var and convert to field via to_field_var()
        let sha256_var = Sha256Var::<Fr>::new_variable(
            cs.clone(),
            || Ok(hash_bytes.clone()),
            ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        let field_from_sha256_var = sha256_var.to_field_var().unwrap();
        let value_from_sha256_var = field_from_sha256_var.value().unwrap();
        
        // Method 2: Convert bytes directly to field using conversions::bytes_to_field
        let field_from_direct_conversion = conversions::bytes_to_field::<Fr>(&hash_bytes);
        
        // These MUST be equal for circuit consistency
        assert_eq!(
            value_from_sha256_var, 
            field_from_direct_conversion,
            "Sha256Var field conversion must match direct bytes_to_field conversion. \
            This is critical for circuit output consistency. \
            Sha256Var result: {:?}, Direct conversion: {:?}",
            value_from_sha256_var,
            field_from_direct_conversion
        );
        
        // Method 3: Verify via into_fp_var_vec() (used in circuit comparisons)
        let fp_var_vec = sha256_var.into_fp_var_vec().unwrap();
        assert_eq!(fp_var_vec.len(), 32, "Sha256Var should convert to 32 FpVars");
        
        // Verify that each byte is correctly represented as a field element
        for (i, fp_var) in fp_var_vec.iter().enumerate() {
            let byte_as_field = fp_var.value().unwrap();
            let expected_byte_value = Fr::from(hash_bytes[i] as u64);
            assert_eq!(
                byte_as_field,
                expected_byte_value,
                "Byte {} should be correctly represented as field element",
                i
            );
        }
    }
}