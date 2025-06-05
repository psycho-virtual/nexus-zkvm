use crate::ccs::{CCSShape, Error as CCSError};

pub struct Sha256Constraint;

impl Sha256Constraint {
    pub fn setupSHA256Matrices() -> Result<CCSShape, CCSError> {
        todo!()
    }
    pub fn synthesizeWitness<G: CurveGroup>(X: Vec<G::ScalarField>) -> Result<(Vec<G::ScalarField>, C::Commitment)> {
        todo!()
    }
}