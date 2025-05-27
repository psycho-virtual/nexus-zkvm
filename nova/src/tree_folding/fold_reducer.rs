/// A trait that supports folding operations in two distinct contexts:
///
/// 1.  **Strict → Accumulator:**  Combine a strict instance into an existing
///     accumulator instance, returning a new accumulator.
/// 2.  **Accumulator → Accumulator:**  Combine two accumulator instances into a
///     new accumulator.
///
/// Implementations must also be able to produce a *zero* accumulator – the
/// identity element with respect to the accumulator‐accumulator fold – so that
/// callers can build folds incrementally.
pub trait FoldReducer<const K: usize> {
    /// The type that represents *strict* (i.e. already verified) instances –
    /// these normally live at the leaves of the folding tree.
    type StrictInst;

    /// The *accumulator* instance type that lives at internal nodes and the
    /// root of the folding tree.
    type AccInst;

    /// The type of proof material returned by the folding operations and
    /// consumed by `verify_step`.
    type FoldProof;

    /// Error type for folding operations
    type Error;

    /// Fold K accumulator instances into a new accumulator instance and
    /// return the result together with a proof.
    fn fold_acc_acc(&self, acc_children: &[Self::AccInst; K]) -> Result<(Self::AccInst, Self::FoldProof), Self::Error>;

    /// Verify that `parent` was correctly derived from its (implicit) children
    /// using the supplied proof.
    fn verify_step(&self, parent: &Self::AccInst, proof: &Self::FoldProof) -> bool;

    /// Return an accumulator instance that corresponds to a single strict instance.
    ///
    /// This is a convenience helper that allows callers (such as [`FoldDriver`]) to
    /// convert a batch of strict leaf instances into accumulator form before
    /// proceeding with higher‐level accumulator folds.
    fn strict_to_acc(&self, strict: &Self::StrictInst) -> Result<Self::AccInst, Self::Error>;
}
