//! Helper definitions for quaternary circuit.
//!
//! Quaternary circuit accepts `g1`, `g2`, `g3`, `g4`, `g_out`, `r2`, `r3`, `r4` (in this exact order) as its public input, where
//! `g1`, `g2`, `g3`, `g4`, `g_out` are points on the curve G, `r2`, `r3`, `r4` are elements from the scalar field, and enforces
//! `g_out = g1 + r2*g2 + r3*g3 + r4*g4`, while having circuit satisfying witness as a trace of this computation.

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use tracing::instrument;

use crate::commitment::CommitmentScheme;

use super::{R1CSInstance, R1CSShape, R1CSWitness};

/// Leading `Variable::One` + 5 curve points + 3 scalars.
const QUATERNARY_NUM_IO: usize = 19;

/// Public input of quaternary circuit.
pub struct Circuit<G1: SWCurveConfig> {
    pub(crate) g1: Projective<G1>,
    pub(crate) g2: Projective<G1>,
    pub(crate) g3: Projective<G1>,
    pub(crate) g4: Projective<G1>,
    pub(crate) g_out: Projective<G1>,

    /// Scalars for elliptic curve points multiplication are part of the public
    /// input and hence should fit into the base field of G1.
    ///
    /// See [`super::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE`].
    pub(crate) r2: G1::BaseField,
    pub(crate) r3: G1::BaseField,
    pub(crate) r4: G1::BaseField,
}

impl<G1: SWCurveConfig> Circuit<G1> {
    pub const NUM_IO: usize = QUATERNARY_NUM_IO;
}

impl<G: SWCurveConfig> Default for Circuit<G> {
    fn default() -> Self {
        Self {
            g1: Projective::zero(),
            g2: Projective::zero(),
            g3: Projective::zero(),
            g4: Projective::zero(),
            g_out: Projective::zero(),
            r2: G::BaseField::ZERO,
            r3: G::BaseField::ZERO,
            r4: G::BaseField::ZERO,
        }
    }
}

const LOG_TARGET: &str = "nexus-nova::folding::cyclefold::quaternary";

impl<G1: SWCurveConfig> ConstraintSynthesizer<G1::BaseField> for Circuit<G1>
where
    G1::BaseField: PrimeField,
{
    #[instrument(target = LOG_TARGET, level = "debug", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::BaseField>,
    ) -> Result<(), SynthesisError> {
        tracing::debug!(target: LOG_TARGET, "Starting quaternary circuit constraint generation");

        let g1 = ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g1))?;
        let g2 = ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g2))?;
        let g3 = ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g3))?;
        let g4 = ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g4))?;
        let g_out =
            ProjectiveVar::<G1, FpVar<G1::BaseField>>::new_input(cs.clone(), || Ok(self.g_out))?;

        tracing::debug!(target: LOG_TARGET, "Allocated curve points as variables");

        let r2 = FpVar::<G1::BaseField>::new_input(cs.clone(), || Ok(self.r2))?;
        let r3 = FpVar::<G1::BaseField>::new_input(cs.clone(), || Ok(self.r3))?;
        let r4 = FpVar::<G1::BaseField>::new_input(cs.clone(), || Ok(self.r4))?;

        tracing::debug!(target: LOG_TARGET, "Allocated scalar multipliers as variables");

        let r2_bits = r2.to_bits_le()?;
        let r3_bits = r3.to_bits_le()?;
        let r4_bits = r4.to_bits_le()?;

        tracing::debug!(target: LOG_TARGET, "Converted scalars to bit representations");

        // Compute g_out = g1 + r2*g2 + r3*g3 + r4*g4
        let term2 = g2.scalar_mul_le(r2_bits.iter())?;
        let term3 = g3.scalar_mul_le(r3_bits.iter())?;
        let term4 = g4.scalar_mul_le(r4_bits.iter())?;

        tracing::debug!(target: LOG_TARGET, "Computed scalar multiplications");

        let out = g1 + term2 + term3 + term4;
        out.enforce_equal(&g_out)?;

        // Log constraint system statistics
        let cs_info = cs.borrow().unwrap();
        tracing::debug!(
            target: LOG_TARGET,
            "Quaternary circuit constraints generated - num_constraints: {}, num_instance_variables: {}, num_witness_variables: {}",
            cs_info.num_constraints,
            cs_info.instance_assignment.len(),
            cs_info.witness_assignment.len()
        );

        Ok(())
    }
}

/// Setup [`R1CSShape`] for a quaternary circuit, defined over `G2::BaseField`.
pub fn setup_shape<G1, G2>() -> Result<R1CSShape<G2>, SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
{
    let cs = ConstraintSystem::<G1::BaseField>::new_ref();
    cs.set_mode(SynthesisMode::Setup);

    Circuit::<G1>::default().generate_constraints(cs.clone())?;

    cs.finalize();
    Ok(R1CSShape::from(cs.clone()))
}

/// Synthesize public input and a witness-trace.
pub fn synthesize<G1, G2, C2>(
    circuit: Circuit<G1>,
    pp_secondary: &C2::PP,
) -> Result<(R1CSInstance<G2, C2>, R1CSWitness<G2>), SynthesisError>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    C2: CommitmentScheme<Projective<G2>>,
{
    let cs = ConstraintSystem::<G1::BaseField>::new_ref();
    cs.set_mode(SynthesisMode::Prove { construct_matrices: false });

    circuit.generate_constraints(cs.clone())?;

    cs.finalize();
    let cs_borrow = cs.borrow().unwrap();

    let witness = cs_borrow.witness_assignment.clone();
    let pub_io = cs_borrow.instance_assignment.clone();

    let W = R1CSWitness::<G2> { W: witness };

    let commitment_W = W.commit::<C2>(pp_secondary);
    let U = R1CSInstance::<G2, C2> { commitment_W, X: pub_io };

    Ok((U, W))
}

/// Folding scheme proof for a quaternary circuit.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<G2: SWCurveConfig, C2: CommitmentScheme<Projective<G2>>> {
    pub(crate) U: R1CSInstance<G2, C2>,
    pub(crate) commitment_T: C2::Commitment,
}

impl<G2, C2> Clone for Proof<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            U: self.U.clone(),
            commitment_T: self.commitment_T,
        }
    }
}

impl<G2, C2> Default for Proof<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn default() -> Self {
        let U = R1CSInstance {
            commitment_W: Projective::zero().into(),
            X: vec![G2::ScalarField::ZERO; QUATERNARY_NUM_IO],
        };
        Self {
            U,
            commitment_T: Projective::zero().into(),
        }
    }
}

macro_rules! parse_projective {
    ($X:expr) => {
        {
            if $X.len() < 3 {
                return None;
            }
            match &$X[..3] {
                &[x, y, z, ..] => {
                    let point = ark_ec::CurveGroup::into_affine(Projective::<G1> { x, y, z });
                    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
                        return None;
                    }
                    $X = &$X[3..];
                    point.into()
                }
                _ => return None,
            }
        }
    };
}

impl<G2, C2> R1CSInstance<G2, C2>
where
    G2: SWCurveConfig,
    C2: CommitmentScheme<Projective<G2>>,
{
    pub(crate) fn parse_quaternary_io<G1>(&self) -> Option<Circuit<G1>>
    where
        G2::BaseField: PrimeField,
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        let mut X = &self.X[1..];

        let g1 = parse_projective!(X);
        let g2 = parse_projective!(X);
        let g3 = parse_projective!(X);
        let g4 = parse_projective!(X);
        let g_out = parse_projective!(X);

        let r2 = *X.get(0)?;
        let r3 = *X.get(1)?;
        let r4 = *X.get(2)?;

        Some(Circuit { g1, g2, g3, g4, g_out, r2, r3, r4 })
    }
}

#[cfg(test)]
mod tests {
    use crate::{pedersen::PedersenCommitment, utils::cast_field_element};

    use super::*;

    use ark_ff::Field;
    use ark_pallas::{Fq, Fr, PallasConfig, Projective};
    use ark_std::UniformRand;
    use ark_vesta::VestaConfig;
    use tracing_subscriber::{
        filter,
        fmt::format::FmtSpan,
        layer::SubscriberExt,
        util::SubscriberInitExt,
    };

    // Tracing target for quaternary circuit tests
    const TEST_TARGET: &str = "nexus-nova::folding::cyclefold::quaternary::tests";

    fn setup_test_tracing() -> tracing::subscriber::DefaultGuard {
        let filter = filter::Targets::new()
            .with_target(TEST_TARGET, tracing::Level::DEBUG)
            .with_target(LOG_TARGET, tracing::Level::DEBUG);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                    .with_test_writer(),
            )
            .with(filter)
            .set_default()
    }

    #[test]
    fn parse_pub_input() {
        let _guard = setup_test_tracing();
        tracing::debug!(target: TEST_TARGET, "Starting parse_pub_input test");

        let mut rng = ark_std::test_rng();
        let g1 = Projective::rand(&mut rng);
        let g2 = Projective::rand(&mut rng);
        let g3 = Projective::rand(&mut rng);
        let g4 = Projective::rand(&mut rng);
        
        tracing::debug!(target: TEST_TARGET, "Generated random curve points");
        
        let val2 = u64::rand(&mut rng);
        let val3 = u64::rand(&mut rng);
        let val4 = u64::rand(&mut rng);
        
        let r2 = <Fq as PrimeField>::BigInt::from(val2).into();
        let r3 = <Fq as PrimeField>::BigInt::from(val3).into();
        let r4 = <Fq as PrimeField>::BigInt::from(val4).into();
        
        tracing::debug!(target: TEST_TARGET, "Generated random scalar values: r2={}, r3={}, r4={}", val2, val3, val4);
        
        let r2_scalar = unsafe { cast_field_element::<Fq, Fr>(&r2) };
        let r3_scalar = unsafe { cast_field_element::<Fq, Fr>(&r3) };
        let r4_scalar = unsafe { cast_field_element::<Fq, Fr>(&r4) };
        
        let g_out = g1 + g2 * r2_scalar + g3 * r3_scalar + g4 * r4_scalar;
        tracing::debug!(target: TEST_TARGET, "Computed g_out using scalar multiplication");

        let expected_pub_io = Circuit::<PallasConfig> { g1, g2, g3, g4, g_out, r2, r3, r4 };
        let X = [
            Fq::ONE,
            g1.x, g1.y, g1.z,
            g2.x, g2.y, g2.z,
            g3.x, g3.y, g3.z,
            g4.x, g4.y, g4.z,
            g_out.x, g_out.y, g_out.z,
            unsafe { cast_field_element(&r2) },
            unsafe { cast_field_element(&r3) },
            unsafe { cast_field_element(&r4) },
        ];
        assert_eq!(X.len(), QUATERNARY_NUM_IO);
        tracing::debug!(target: TEST_TARGET, "Created public input array with {} elements", X.len());

        let r1cs = R1CSInstance::<VestaConfig, PedersenCommitment<ark_vesta::Projective>> {
            commitment_W: Default::default(),
            X: X.into(),
        };

        let pub_io = r1cs.parse_quaternary_io().unwrap();
        tracing::debug!(target: TEST_TARGET, "Successfully parsed quaternary IO");

        assert_eq!(pub_io.g1, expected_pub_io.g1);
        assert_eq!(pub_io.g2, expected_pub_io.g2);
        assert_eq!(pub_io.g3, expected_pub_io.g3);
        assert_eq!(pub_io.g4, expected_pub_io.g4);
        assert_eq!(pub_io.g_out, expected_pub_io.g_out);
        assert_eq!(pub_io.r2, expected_pub_io.r2);
        assert_eq!(pub_io.r3, expected_pub_io.r3);
        assert_eq!(pub_io.r4, expected_pub_io.r4);
        tracing::debug!(target: TEST_TARGET, "All public IO values match expected values");

        // incorrect length
        let _X = &X[..10];
        let r1cs = R1CSInstance::<VestaConfig, PedersenCommitment<ark_vesta::Projective>> {
            commitment_W: Default::default(),
            X: _X.into(),
        };
        assert!(r1cs.parse_quaternary_io::<PallasConfig>().is_none());
        tracing::debug!(target: TEST_TARGET, "Correctly handled incorrect length case");

        // not on curve
        let mut _X = X.to_vec();
        _X[1] -= Fq::ONE;
        let r1cs = R1CSInstance::<VestaConfig, PedersenCommitment<ark_vesta::Projective>> {
            commitment_W: Default::default(),
            X: _X,
        };
        assert!(r1cs.parse_quaternary_io::<PallasConfig>().is_none());
        tracing::debug!(target: TEST_TARGET, "Correctly handled invalid curve point case");
    }

    #[test]
    fn parse_synthesized() {
        let _guard = setup_test_tracing();
        tracing::debug!(target: TEST_TARGET, "Starting parse_synthesized test");

        let shape = setup_shape::<PallasConfig, VestaConfig>().unwrap();
        let mut rng = ark_std::test_rng();
        let g1 = Projective::rand(&mut rng);
        let g2 = Projective::rand(&mut rng);
        let g3 = Projective::rand(&mut rng);
        let g4 = Projective::rand(&mut rng);
        
        tracing::debug!(target: TEST_TARGET, "Generated random curve points");
        
        let val2 = u64::rand(&mut rng);
        let val3 = u64::rand(&mut rng);
        let val4 = u64::rand(&mut rng);
        
        let r2 = <Fq as PrimeField>::BigInt::from(val2).into();
        let r3 = <Fq as PrimeField>::BigInt::from(val3).into();
        let r4 = <Fq as PrimeField>::BigInt::from(val4).into();
        
        tracing::debug!(target: TEST_TARGET, "Generated random scalar values: r2={}, r3={}, r4={}", val2, val3, val4);
        
        let r2_scalar = unsafe { cast_field_element::<Fq, Fr>(&r2) };
        let r3_scalar = unsafe { cast_field_element::<Fq, Fr>(&r3) };
        let r4_scalar = unsafe { cast_field_element::<Fq, Fr>(&r4) };
        
        let g_out = g1 + g2 * r2_scalar + g3 * r3_scalar + g4 * r4_scalar;
        tracing::debug!(target: TEST_TARGET, "Computed g_out using scalar multiplication");

        let pp = PedersenCommitment::<ark_vesta::Projective>::setup(shape.num_vars, b"test", &());
        tracing::debug!(target: TEST_TARGET, "Set up Pedersen commitment with {} variables", shape.num_vars);

        let (U, _) = synthesize::<
            PallasConfig,
            VestaConfig,
            PedersenCommitment<ark_vesta::Projective>,
        >(Circuit { g1, g2, g3, g4, g_out, r2, r3, r4 }, &pp)
        .unwrap();

        let pub_io = U.parse_quaternary_io::<PallasConfig>().unwrap();
        tracing::debug!(target: TEST_TARGET, "Successfully parsed synthesized quaternary IO");

        assert_eq!(pub_io.g1, g1);
        assert_eq!(pub_io.g2, g2);
        assert_eq!(pub_io.g3, g3);
        assert_eq!(pub_io.g4, g4);
        assert_eq!(pub_io.g_out, g_out);
        assert_eq!(pub_io.r2, r2);
        assert_eq!(pub_io.r3, r3);
        assert_eq!(pub_io.r4, r4);
        tracing::debug!(target: TEST_TARGET, "All synthesized values match expected values");
    }
} 