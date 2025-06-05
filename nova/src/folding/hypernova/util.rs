use ark_ff::Field;
use merlin::Transcript;

/// Creates a fresh transcript for folding operations.
/// Allows specifying a label for domain separation.
pub fn create_folding_transcript(label: &'static [u8]) -> Transcript {
    Transcript::new(label)
}

/// Updates an existing transcript with new data for domain separation.
/// Useful when you need to reuse a transcript but with additional context.
pub fn update_transcript(transcript: &mut Transcript, label: &'static [u8], data: &[u8]) {
    transcript.append_message(label, data);
}

/// Helper function to finalize a transcript and get a challenge for the next step.
/// This can be used to generate deterministic random values for protocols.
pub fn get_challenge_from_transcript<F: Field>(
    transcript: &mut Transcript, 
    label: &'static [u8]
) -> F {
    let mut bytes = [0u8; 64];
    transcript.challenge_bytes(label, &mut bytes);
    F::from_random_bytes(&bytes).unwrap_or_else(|| F::zero())
}