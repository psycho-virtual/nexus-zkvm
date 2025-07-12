use ark_ff::PrimeField;
use ark_r1cs_std::{fields::{fp::FpVar, FieldVar}, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

use super::IntoFpVarVec;

/// A variable representing a SHA-256 hash value in the constraint system
#[derive(Clone)]
pub struct Sha256Var<F: PrimeField> {
    /// The 32-byte hash value represented as UInt8 variables
    pub bytes: Vec<UInt8<F>>,
}

impl<F: PrimeField> Sha256Var<F> {
    /// Create a new Sha256Var from bytes
    pub fn new(bytes: Vec<UInt8<F>>) -> Result<Self, SynthesisError> {
        if bytes.len() != 32 {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self { bytes })
    }

    /// Convert to a field element by packing bytes
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
        // Convert to a single field element
        Ok(vec![self.to_field_var()?])
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
        
        // Create a SHA256Var with witness bytes
        let bytes = vec![42u8; 32];
        let byte_vars = UInt8::new_witness_vec(cs.clone(), &bytes).unwrap();
        
        // Record witness count after creating the SHA256Var
        let witness_count_before = cs.num_witness_variables();
        
        let sha_var = Sha256Var::new(byte_vars).unwrap();
        
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
        
        // Verify we got exactly one FpVar
        assert_eq!(fp_vars.len(), 1, "Should return exactly one FpVar");
        
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
}