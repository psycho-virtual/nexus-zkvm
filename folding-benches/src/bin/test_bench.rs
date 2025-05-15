use ark_bn254::{Bn254, Fr as BN254Fr, G1Projective as BN254G1};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_std::test_rng;

// Import PolyCommitmentScheme trait through nexus-nova
use nexus_nova::provider::PolyCommitmentScheme;

use nexus_nova::{
    poseidon_config,
    zeromorph::Zeromorph,
};

type G1 = BN254G1;
type CF = BN254Fr;
type Z = Zeromorph<Bn254>;

fn main() {
    println!("Testing benchmark setup");
    
    let mut rng = test_rng();
    
    // Create Poseidon config
    let poseidon_cfg = poseidon_config::<CF>();
    
    // Initialize random oracle
    let mut random_oracle = PoseidonSponge::new(&poseidon_cfg);
    
    // Setup SRS for polynomial commitment
    let SRS = Z::setup(10, b"test", &mut rng).unwrap();
    let ck = Z::trim(&SRS, 10).ck;
    
    println!("Setup completed successfully");
}