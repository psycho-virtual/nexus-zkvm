use crate::tree_folding::fold_reducer::FoldReducer;
use ark_std::vec::Vec;

/// Batch helper that folds a full set of `K^d` leaf instances level-by-level
/// using a single `FoldReducer` implementation that distinguishes between
/// *strict* and *accumulator* instances.
pub struct FoldDriver<R, const K: usize>
where
    R: FoldReducer<K>,
{
    reducer: R,
}

impl<R, const K: usize> FoldDriver<R, K>
where
    R: FoldReducer<K>,
    R::StrictInst: core::fmt::Debug,
    R::AccInst: core::fmt::Debug,
{
    // Compile-time assertion that K must be at least 2
    const ENSURE_K_GREATER_THAN_ONE: () = assert!(K > 1, "K must be at least 2");

    /// Create a new `FoldDriver` with the supplied reducer.
    pub fn new(reducer: R) -> Self {
        Self { reducer }
    }

    /// Checks if the length is a power of K.
    fn len_is_power_of_k(len: usize) -> bool {
        if len == 0 {
            return false;
        }

        let mut n = len;
        while n > 1 {
            if n % K != 0 {
                return false;
            }
            n /= K;
        }
        true
    }

    /// Convert the strict leaf instances into their accumulator form using
    /// `FoldReducer::strict_to_acc`.
    fn strict_to_acc_level(&self, leaves: &[R::StrictInst]) -> Result<Vec<R::AccInst>, R::Error> {
        debug_assert!(!leaves.is_empty());

        leaves
            .iter()
            .map(|strict| self.reducer.strict_to_acc(strict))
            .collect()
    }

    /// Fold one **accumulator** level into its parent level.
    fn fold_next_level(&self, current: &[R::AccInst]) -> Result<Vec<R::AccInst>, R::Error> {
        debug_assert!(!current.is_empty());
        debug_assert!(current.len() % K == 0);

        let mut next = Vec::with_capacity(current.len() / K);

        // Use chunks_exact which is available on all Rust versions
        for chunk in current.chunks_exact(K) {
            // Safety: chunks_exact guarantees that each chunk has exactly K elements
            let acc_array =
                <&[R::AccInst; K]>::try_from(chunk).expect("chunks_exact guarantees len == K");
            let (parent, _proof) = self.reducer.fold_acc_acc(acc_array)?;
            next.push(parent);
        }

        Ok(next)
    }

    /// Compute the root accumulator of a full batched fold.
    /// This function keeps only the current level in memory.
    pub fn fold_root(&self, leaves: &[R::StrictInst]) -> Result<R::AccInst, R::Error> {
        assert!(!leaves.is_empty(), "Input must not be empty");
        assert!(
            Self::len_is_power_of_k(leaves.len()),
            "leaf count ({}) is not a power of {}",
            leaves.len(),
            K
        );

        // First level: strict → accumulator (one-to-one conversion)
        let mut current_level = self.strict_to_acc_level(leaves)?;

        // Higher levels: accumulator → accumulator
        while current_level.len() > 1 {
            current_level = self.fold_next_level(&current_level)?;
        }

        debug_assert_eq!(current_level.len(), 1);
        Ok(current_level.pop().unwrap())
    }
}
