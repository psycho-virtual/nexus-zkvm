use super::chaum_pedersen::ChaumPedersenProof;
use super::data_structures::ElGamalCiphertext;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::Zero;

/// Encryption share from a single shuffler targeted to a specific player
/// Each shuffler contributes their secret δ_j to the player-specific encryption
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShufflerEncryptionShareForPlayer<C: CurveGroup> {
    /// α_j = g^δ_j - shuffler's contribution to A_u and D
    pub alpha: C,
    /// β_j = (aggregated_public_key·player_public_key)^δ_j - shuffler's contribution to B_u
    pub beta: C,
    /// Proof that the same δ_j was used for both α and β
    pub proof: ChaumPedersenProof<C>,
}

impl<C: CurveGroup> ShufflerEncryptionShareForPlayer<C>
where
    C::ScalarField: PrimeField + ark_crypto_primitives::sponge::Absorb,
{
    /// Generate a player-specific encryption share with a Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `secret_share` - The shuffler's secret share δ_j
    /// * `aggregated_public_key` - The aggregated public key from all shufflers (pk)
    /// * `player_public_key` - The target player's public key (y_u)
    pub fn generate(
        secret_share: C::ScalarField,
        aggregated_public_key: C,
        player_public_key: C,
    ) -> Self {
        let generator = C::generator();

        // Compute public values
        // α_j = g^secret_share_j
        let alpha = generator * secret_share;

        // H = aggregated_public_key · player_public_key (combined base)
        let h = aggregated_public_key + player_public_key;

        // β_j = H^secret_share_j = (aggregated_public_key · player_public_key)^secret_share_j
        let beta = h * secret_share;

        // Generate the non-interactive Chaum-Pedersen proof (deterministic)
        let proof = ChaumPedersenProof::generate(secret_share, generator, h, alpha, beta);

        Self { alpha, beta, proof }
    }

    /// Verify a shuffler's encryption share Chaum-Pedersen proof
    ///
    /// # Arguments
    /// * `aggregated_public_key` - The aggregated public key from all shufflers
    /// * `player_public_key` - The target player's public key
    pub fn verify(&self, aggregated_public_key: C, player_public_key: C) -> bool {
        let generator = C::generator();
        let h = aggregated_public_key + player_public_key;

        // Verify the non-interactive proof
        self.proof.verify(generator, h, self.alpha, self.beta)
    }
}

/// Represents an encrypted card targeted to a specific player
/// This is the complete public transcript C_u = (A_u, B_u, D, {π_j})
/// that gets posted on-chain or in the game log
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlayerEncryptedCard<C: CurveGroup> {
    /// A_u = g^(r+Δ) where r is initial randomness and Δ = Σδ_j
    pub a_u: C,
    /// B_u = pk^(r+Δ) * g^m_i * y_u^Δ where m_i is the card value
    pub b_u: C,
    /// D = g^Δ = g^(Σδ_j) - allows player to remove blinding with their secret
    pub d: C,
    /// All Schnorr proofs from each shuffler, proving correct encryption
    pub shuffler_proofs: Vec<ChaumPedersenProof<C>>,
}

/// Aggregates shuffler encryption shares to create the final encrypted card for a player
///
/// This creates the complete public transcript that gets posted on-chain.
/// All proofs are included so anyone can verify the encryption was done correctly.
///
/// # Arguments
/// * `initial_ciphertext` - The ElGamal ciphertext (A*, B*) from the shuffled deck
/// * `shuffler_shares` - Encryption shares from each committee member
/// * `aggregated_public_key` - The aggregated public key from all shufflers
/// * `player_public_key` - The target player's public key
pub fn aggregate_player_encryptions<C: CurveGroup>(
    initial_ciphertext: &ElGamalCiphertext<C>,
    shuffler_shares: &[ShufflerEncryptionShareForPlayer<C>],
    aggregated_public_key: C,
    player_public_key: C,
) -> Result<PlayerEncryptedCard<C>, &'static str>
where
    C::ScalarField: PrimeField + Absorb,
{
    // First verify all shares
    for (i, share) in shuffler_shares.iter().enumerate() {
        if !share.verify(aggregated_public_key, player_public_key) {
            return Err("Invalid shuffler encryption share");
        }
    }

    // Start with the shuffled deck ciphertext
    let mut a_u = initial_ciphertext.c1; // g^r
    let mut b_u = initial_ciphertext.c2; // pk^r * g^m_i
    let mut d = C::zero(); // Will accumulate g^Δ
    let mut proofs = Vec::new();

    // Aggregate all shuffler contributions
    for share in shuffler_shares {
        a_u = a_u + share.alpha; // Add g^δ_j
        b_u = b_u + share.beta; // Add (pk·y_u)^δ_j
        d = d + share.alpha; // Accumulate g^δ_j for D
        proofs.push(share.proof.clone()); // Collect proof for transcript
    }

    Ok(PlayerEncryptedCard { a_u, b_u, d, shuffler_proofs: proofs })
}

/// Batch verification for multiple shuffler encryption shares
/// Note: This assumes all shares use the same aggregated_public_key
pub fn batch_verify_shuffler_shares<C, R>(
    shares: &[ShufflerEncryptionShareForPlayer<C>],
    aggregated_public_key: C,
    player_public_key: C,
    rng: &mut R,
) -> bool
where
    C: CurveGroup,
    C::ScalarField: PrimeField + Absorb,
    R: Rng,
{
    if shares.is_empty() {
        return false;
    }

    // Verify each share individually since they use context-based proofs
    // In the future, this could be optimized with a custom batch verification
    for share in shares {
        if !share.verify(aggregated_public_key, player_public_key) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_grumpkin::Projective as GrumpkinProjective;
    use ark_std::test_rng;

    #[test]
    fn test_shuffler_encryption_share_proof() {
        let mut rng = test_rng();

        // Setup - Generate keys for committee and player
        let committee_secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let aggregated_public_key = GrumpkinProjective::generator() * committee_secret;

        let player_secret = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Create a ShufflerEncryptionShareForPlayer with proof
        let secret_share = <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        let share = ShufflerEncryptionShareForPlayer::generate(
            secret_share,
            aggregated_public_key,
            player_public_key,
        );

        // Verify the proof is valid
        assert!(
            share.verify(aggregated_public_key, player_public_key),
            "Valid proof should verify successfully"
        );

        // Test that tampering with alpha makes verification fail
        let mut bad_share = share.clone();
        bad_share.alpha = GrumpkinProjective::generator()
            * <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        assert!(
            !bad_share.verify(aggregated_public_key, player_public_key),
            "Tampered alpha should fail verification"
        );

        // Test that tampering with beta makes verification fail
        let mut bad_share = share.clone();
        bad_share.beta = GrumpkinProjective::generator()
            * <GrumpkinProjective as PrimeGroup>::ScalarField::rand(&mut rng);
        assert!(
            !bad_share.verify(aggregated_public_key, player_public_key),
            "Tampered beta should fail verification"
        );
    }

    #[test]
    fn test_complete_encryption_and_dealing_protocol() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // ============ SETUP PHASE ============
        // Three shufflers with their own keys
        let shuffler1_secret = ScalarField::rand(&mut rng);
        let shuffler1_pk = GrumpkinProjective::generator() * shuffler1_secret;

        let shuffler2_secret = ScalarField::rand(&mut rng);
        let shuffler2_pk = GrumpkinProjective::generator() * shuffler2_secret;

        let shuffler3_secret = ScalarField::rand(&mut rng);
        let shuffler3_pk = GrumpkinProjective::generator() * shuffler3_secret;

        // Aggregated public key for the committee
        let aggregated_pk = shuffler1_pk + shuffler2_pk + shuffler3_pk;
        let aggregated_secret = shuffler1_secret + shuffler2_secret + shuffler3_secret;

        // Target player with their own key
        let player_secret = ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // ============ STAGE 1: SEQUENTIAL ENCRYPTION ============
        // Initial message/card
        let message = ScalarField::from(42u64); // Card value
        let message_point = GrumpkinProjective::generator() * message;

        // Start with initial ciphertext (0, M)
        let mut ciphertext = ElGamalCiphertext::new(
            GrumpkinProjective::zero(), // c1 = 0
            message_point,              // c2 = g^m
        );

        // Shuffler 1 encrypts with randomness r1
        let r1 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r1, aggregated_pk);
        // Now: c1 = g^r1, c2 = pk^r1 * g^m

        // Shuffler 2 re-encrypts with randomness r2
        let r2 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r2, aggregated_pk);
        // Now: c1 = g^(r1+r2), c2 = pk^(r1+r2) * g^m

        // Shuffler 3 re-encrypts with randomness r3
        let r3 = ScalarField::rand(&mut rng);
        ciphertext = ciphertext.add_encryption_layer(r3, aggregated_pk);
        // Now: c1 = g^(r1+r2+r3), c2 = pk^(r1+r2+r3) * g^m

        let total_r = r1 + r2 + r3;

        // ============ STAGE 2: PLAYER-SPECIFIC ENCRYPTION ============
        // Each shuffler creates their encryption share for the target player

        // Shuffler 1's contribution
        let delta1 = ScalarField::rand(&mut rng);
        let share1 =
            ShufflerEncryptionShareForPlayer::generate(delta1, aggregated_pk, player_public_key);
        assert_eq!(share1.alpha, GrumpkinProjective::generator() * delta1);
        assert_eq!(share1.beta, (aggregated_pk + player_public_key) * delta1);

        // Shuffler 2's contribution
        let delta2 = ScalarField::rand(&mut rng);
        let share2 =
            ShufflerEncryptionShareForPlayer::generate(delta2, aggregated_pk, player_public_key);

        // Shuffler 3's contribution
        let delta3 = ScalarField::rand(&mut rng);
        let share3 =
            ShufflerEncryptionShareForPlayer::generate(delta3, aggregated_pk, player_public_key);

        let total_delta = delta1 + delta2 + delta3;

        // ============ STAGE 3: AGGREGATION ============
        let shares = vec![share1, share2, share3];
        let encrypted_card =
            aggregate_player_encryptions(&ciphertext, &shares, aggregated_pk, player_public_key)
                .unwrap();

        // ============ VERIFICATION ============
        // Verify A_u = g^(r + Δ)
        let expected_a_u = GrumpkinProjective::generator() * (total_r + total_delta);
        assert_eq!(
            encrypted_card.a_u, expected_a_u,
            "A_u should equal g^(r + Δ)"
        );

        // Verify B_u = pk^(r + Δ) * g^m * y_u^Δ
        let expected_b_u = aggregated_pk * (total_r + total_delta) // pk^(r + Δ)
            + message_point // g^m
            + player_public_key * total_delta; // y_u^Δ
        assert_eq!(
            encrypted_card.b_u, expected_b_u,
            "B_u should equal pk^(r+Δ) * g^m * y_u^Δ"
        );

        // Verify D = g^Δ
        let expected_d = GrumpkinProjective::generator() * total_delta;
        assert_eq!(encrypted_card.d, expected_d, "D should equal g^Δ");

        // Verify all proofs are included
        assert_eq!(encrypted_card.shuffler_proofs.len(), 3);

        // ============ PLAYER DECRYPTION (for completeness) ============
        // Player can decrypt using their secret and D
        // Step 1: Compute S = D^s_u = g^(Δ * s_u) = y_u^Δ
        let s = encrypted_card.d * player_secret;

        // Step 2: Get decryption shares from committee (simulated)
        // Each member provides A_u^x_j where x_j is their secret share
        let mu = encrypted_card.a_u * aggregated_secret; // pk^(r+Δ)

        // Step 3: Recover message
        // g^m = B_u / (μ * S) = B_u / (pk^(r+Δ) * y_u^Δ)
        let recovered = encrypted_card.b_u - mu - s;
        assert_eq!(
            recovered, message_point,
            "Player should recover original message"
        );
    }

    #[test]
    fn test_batch_verification() {
        let mut rng = test_rng();
        type ScalarField = <GrumpkinProjective as PrimeGroup>::ScalarField;

        // Setup multiple shufflers with a shared aggregated key
        let num_shufflers = 3;
        let mut shares = Vec::new();

        // Create individual shuffler keys and compute aggregated key
        let shuffler1_secret = ScalarField::rand(&mut rng);
        let shuffler1_pk = GrumpkinProjective::generator() * shuffler1_secret;

        let shuffler2_secret = ScalarField::rand(&mut rng);
        let shuffler2_pk = GrumpkinProjective::generator() * shuffler2_secret;

        let shuffler3_secret = ScalarField::rand(&mut rng);
        let shuffler3_pk = GrumpkinProjective::generator() * shuffler3_secret;

        // This is the aggregated public key all shufflers use
        let aggregated_public_key = shuffler1_pk + shuffler2_pk + shuffler3_pk;

        let player_secret = ScalarField::rand(&mut rng);
        let player_public_key = GrumpkinProjective::generator() * player_secret;

        // Generate shares from each shuffler using the same aggregated key
        for _ in 0..num_shufflers {
            let secret_share = ScalarField::rand(&mut rng);
            let share = ShufflerEncryptionShareForPlayer::generate(
                secret_share,
                aggregated_public_key,
                player_public_key,
            );
            shares.push(share);
        }

        // Batch verify all shares
        assert!(
            batch_verify_shuffler_shares(
                &shares,
                aggregated_public_key,
                player_public_key,
                &mut rng
            ),
            "Batch verification of valid shares should succeed"
        );

        // Tamper with one share and verify batch fails
        shares[1].alpha = GrumpkinProjective::generator() * ScalarField::rand(&mut rng);
        assert!(
            !batch_verify_shuffler_shares(
                &shares,
                aggregated_public_key,
                player_public_key,
                &mut rng
            ),
            "Batch verification with tampered share should fail"
        );
    }
}
