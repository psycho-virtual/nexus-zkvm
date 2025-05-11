use std::collections::HashMap;
use crate::circuits::nova::{
    pcd::{PCDNode, PublicParams},
    StepCircuit,
};
use ark_crypto_primitives::sponge::{constraints::SpongeWithGadget, Absorb, CryptographicSponge};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{commitment::CommitmentScheme, folding::nova::cyclefold};


/// Builds a PCD tree for a sequence of n steps using the binary tree structure
/// where leaves represent even-indexed steps and inner nodes combine computations.
/// 
/// # Arguments
/// * `params` - Nova public parameters
/// * `step_circuit` - Circuit representing the computation step
/// * `initial_input` - Initial input to the computation
/// * `n` - Number of steps to compute
/// * `compute_step` - Function that computes one step of the computation
/// 
/// # Returns
/// * The root node of the PCD tree
pub fn build_binary_pcd_tree<G1, G2, C1, C2, RO, SC, F>(
    params: &PublicParams<G1, G2, C1, C2, RO, SC>,
    step_circuit: &SC,
    initial_input: &[G1::ScalarField],
    n: usize,
    mut compute_step: F,
) -> Result<PCDNode<G1, G2, C1, C2, RO, SC>, cyclefold::Error>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
    RO::Var: ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    F: FnMut(&[G1::ScalarField]) -> Vec<G1::ScalarField>,
{
    // Calculate required padding for the number of steps
    let padded_n = n.next_power_of_two();
    
    // Compute all intermediate states
    // We need states for all steps 0 through 2*padded_n-1
    let mut states: Vec<Vec<G1::ScalarField>> = Vec::with_capacity(2 * padded_n);
    states.push(initial_input.to_vec());
    
    // Compute all states up to 2*padded_n-1 or n, whichever is smaller
    for _ in 0..n.min(2 * padded_n - 1) {
        let next_state = compute_step(states.last().unwrap());
        states.push(next_state);
    }
    
    // Pad with final state if needed to get to 2*padded_n states
    while states.len() < 2 * padded_n {
        let next_state = states.last().unwrap().clone();
        states.push(next_state);
    }
    
    // Store all nodes in a HashMap indexed by their tree position
    let mut nodes: HashMap<usize, PCDNode<G1, G2, C1, C2, RO, SC>> = HashMap::new();
    
    // Create leaf nodes for even-indexed steps (0, 2, 4, ...)
    let mut level_indices: Vec<usize> = Vec::with_capacity(padded_n);
    
    for i in 0..padded_n {
        // Create a leaf node for step 2*i
        let step_index = 2 * i;
        
        let leaf_node = PCDNode::prove_leaf(
            params,
            step_circuit,
            step_index,
            &states[step_index],
        )?;
        
        // In the binary tree, store this at index 2*i
        let leaf_index = 2 * i;
        nodes.insert(leaf_index, leaf_node);
        level_indices.push(leaf_index);
    }
    
    // Build the tree bottom-up
    while level_indices.len() > 1 {
        let mut next_level_indices = Vec::new();
        
        // Process pairs of nodes
        for i in 0..(level_indices.len() / 2) {
            let left_idx = level_indices[2 * i];
            let right_idx = level_indices[2 * i + 1];
            
            // Create a parent node by folding the two children
            let parent_node = PCDNode::prove_parent(
                params,
                step_circuit,
                nodes.get(&left_idx).unwrap(),
                nodes.get(&right_idx).unwrap(),
            )?;
            
            // The parent's index is the average of its children's indices
            let parent_idx = (left_idx + right_idx) / 2;
            nodes.insert(parent_idx, parent_node);
            next_level_indices.push(parent_idx);
        }
        
        // If there's an odd node out, promote it to the next level
        if level_indices.len() % 2 == 1 {
            next_level_indices.push(level_indices[level_indices.len() - 1]);
        }
        
        // Move to the next level
        level_indices = next_level_indices;
    }
    
    // The last remaining node is the root
    Ok(nodes.remove(&level_indices[0]).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::nova::sequential::tests::CubicCircuit, pedersen::PedersenCommitment,
        poseidon_config,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;

    #[test]
    fn test_binary_pcd_tree() {
        test_binary_pcd_tree_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn test_binary_pcd_tree_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let ro_config = poseidon_config();

        // Create a cubic circuit for testing
        let circuit = CubicCircuit::<G1::ScalarField>::default();
        
        // Initial input for the circuit
        let initial_input = vec![G1::ScalarField::ONE];
        
        // Number of steps to compute
        let steps = 7;
        
        // Create public parameters
        let params = crate::circuits::nova::pcd::PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;
        
        // Compute step function that computes f(x) = x³ - x + 5
        let compute_step = |z: &[G1::ScalarField]| {
            let x = z[0];
            let result = x.cube() - x + G1::ScalarField::from(5);
            vec![result]
        };
        
        // Build the binary PCD tree
        let root = build_binary_pcd_tree(
            &params,
            &circuit,
            &initial_input,
            steps,
            compute_step,
        )?;
        
        // Verify the root
        root.verify(&params)?;
        
        // Calculate expected final state manually
        let mut state = initial_input[0];
        for _ in 0..steps {
            state = state.cube() - state + G1::ScalarField::from(5);
        }
        
        // Check that the root's final state matches expected
        assert_eq!(root.z_j[0], state);
        
        Ok(())
    }
} 