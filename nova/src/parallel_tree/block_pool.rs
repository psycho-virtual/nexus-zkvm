use std::sync::{Arc, Mutex};
use std::cell::Cell;

use crossbeam_queue::SegQueue;

/// Dense handle that indexes a [`BlockPool`] page.  We keep this a `u32`
/// because the slab is capped at 4 GiB (≈ 8192 pages on a 64-core machine).
pub type BufId = u32;

/// Pool of fixed-size blocks backed by a single anonymous mmap of a contiguous
/// slab.  The type parameter `P` fixes the payload type stored in each
/// allocated block, allowing the API to omit the `<P>` annotation on every
/// call to [`BlockPool::alloc`] or [`BufHandle::write`].
pub struct BlockPool<P> {
    /// Storage for live values. Each slot is protected by a mutex so multiple
    /// threads can claim/release different buffers concurrently.
    blocks: Vec<Mutex<Option<P>>>,
    /// Free-list implemented as a lock-free queue.
    free: Arc<SegQueue<BufId>>, // cheap to clone across threads
}

impl<P: Send + Sync> BlockPool<P> {
    /// Create a new block pool sized for the given number of *logical cores*.
    /// We reserve two buffers per core – identical behaviour to the previous
    /// page-based implementation but without relying on OS-backed memory
    /// mappings.
    pub fn new(num_cores: usize) -> anyhow::Result<Self> {
        let num_blocks = num_cores * 2; // 2 × cores

        // Allocate an empty slot for every buffer ID.
        let blocks = (0..num_blocks)
            .map(|_| Mutex::new(None))
            .collect::<Vec<_>>();

        // Initialise free list with all IDs so the first pop gets 0 (nicer for debugging).
        let free = Arc::new(SegQueue::new());
        for id in (0..num_blocks as BufId).rev() {
            free.push(id);
        }

        Ok(Self { blocks, free })
    }

    /// Access to the free stack, only used in tests
    #[cfg(test)]
    pub fn free_stack(&self) -> Arc<SegQueue<BufId>> {
        self.free.clone()
    }

    /// Allocate a free block and return a typed [`BufHandle`].  Returns
    /// `None` when the slab is exhausted.
    pub fn alloc<'a>(&'a self) -> Option<BufHandle<'a, P>> {
        self.free.pop().map(|id| BufHandle::new(self, id))
    }

    /// Return `true` if `id` refers to a block that falls inside this pool's
    /// address range.  This is a *pure* bounds check – it does **not** verify
    /// whether the block is currently allocated or free, merely that the
    /// computed offset is within the underlying slab.  Clients can use this
    /// as a quick guard before attempting to obtain a mutable view through a
    /// [`BufHandle`].
    #[inline]
    fn can_edit(&self, id: BufId) -> bool {
        (id as usize) < self.blocks.len()
    }

    /// Check whether the block identified by `id` is currently *free* (i.e.
    /// available for allocation).  This operates by linearly scanning the
    /// internal free list – it is therefore *O(n)* in the number of free
    /// blocks and **should only be used from tests or debugging code**.  The
    /// method is *lock-free* but **not** wait‐free: if other threads keep
    /// pushing/popping concurrently it may spin for a while.  In practise we
    /// only invoke it from single-threaded unit tests, so that is fine.
    pub fn is_free(&self, id: BufId) -> bool {
        // Fast reject if the ID is out of range.
        if !self.can_edit(id) {
            return false;
        }

        // Crossbeam's `SegQueue` does not expose an iterator, so we perform
        // a destructive scan: pop everything into a temporary buffer, record
        // whether we saw `id`, and finally push the elements back in the
        // *same* order.  This is fine for testing purposes.

        let mut found = false;
        let mut tmp = Vec::new();
        while let Some(x) = self.free.pop() {
            if x == id {
                found = true;
            }
            tmp.push(x);
        }
        // Push back in *reverse* so the original FIFO/LIFO order is
        // preserved (we popped from the head, push back in reverse to end up
        // with the same sequence).
        for x in tmp.into_iter().rev() {
            self.free.push(x);
        }
        found
    }

    /// Return a block to the pool.  Meant to be called from
    /// [`BufHandle::release`].
    pub(crate) fn free(&self, id: BufId) {
        if self.can_edit(id) {
            // Clear the stored value so the next owner sees a clean slot.
            let mut guard = self.blocks[id as usize].lock().expect("mutex poisoned");
            *guard = None;
            self.free.push(id);
        } else {
            panic!("BufId {} is out of range", id);
        }
    }

    /// Claim ownership of an **existing** live buffer given its `id` and obtain
    /// a typed handle.  This is used by worker threads when traversing the
    /// tree upward: child nodes publish their `BufId`s to the parent which
    /// then *claims* those buffers for reading / further processing.
    ///
    /// The method performs a fast bounds check via [`Self::can_edit`].  It
    /// does **not** verify that the buffer is currently allocated – callers
    /// must uphold that contract by only passing `id`s they have received
    /// from other, trusted components of the engine.
    pub fn claim<'a>(&'a self, id: BufId) -> Option<BufHandle<'a, P>> {
        if self.can_edit(id) {
            Some(BufHandle::new(self, id))
        } else {
            None
        }
    }

    /// Return the current number of free blocks available.  This is an
    /// O(1) call on the underlying `SegQueue` and therefore cheap enough to
    /// poll from tight back‐pressure loops.
    pub fn free_count(&self) -> usize {
        self.free.len()
    }
}

/// Typed view on a buffer slot.
pub struct BufHandle<'a, P: Send + Sync> {
    pool: &'a BlockPool<P>,
    id: BufId,
    released: Cell<bool>,
}

impl<'a, P: Send + Sync> BufHandle<'a, P> {
    /// Construct a new handle from `(pool, id)`.
    pub fn new(pool: &'a BlockPool<P>, id: BufId) -> Self {
        Self { 
            pool, 
            id, 
            released: Cell::new(false), 
        }
    }

    /// Store a value in the underlying buffer slot, overwriting any previous content.
    pub fn write(&mut self, value: P) {
        let mut guard = self.pool.blocks[self.id as usize]
            .lock()
            .expect("mutex poisoned");
        *guard = Some(value);
    }

    /// Consume the handle and return the underlying [`BufId`] **without**
    /// freeing it back to the pool.  Use this when the buffer must stay live
    /// after the handle goes out of scope (e.g. when publishing to a parent
    /// tree node).
    pub fn into_id(self) -> BufId {
        self.released.set(true); // Mark as released so Drop doesn't free it
        self.id
    }

    /// Explicitly release the buffer back to the [`BlockPool`], consuming the
    /// handle in the process.
    pub fn release(self) {
        self.released.set(true); // Prevent double-free in Drop
        self.pool.free(self.id);
    }

    /// Consume the stored value and return it. Panics if the slot is empty.
    ///
    /// The buffer slot is cleared (set to `None`) after the value is moved
    /// out, allowing subsequent writes without leftover data.
    pub fn read(&self) -> P {
        let mut guard = self.pool.blocks[self.id as usize]
            .lock()
            .expect("mutex poisoned");
        guard.take().expect("attempted to read from an uninitialised buffer")
    }
}

impl<'a, P: Send + Sync> Drop for BufHandle<'a, P> {
    fn drop(&mut self) {
        // Only free if not explicitly released already
        if !self.released.get() {
            self.pool.free(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;


    /// Buffer-ID bookkeeping: every ID is unique, in-range, and the stack empties.
    #[test]
    fn block_pool_buffer_id_management() {
        let num_cores = 3;
        let pool = BlockPool::<Dummy>::new(num_cores).unwrap();
        let num_blocks = num_cores * 2;

        let mut seen = HashSet::with_capacity(num_blocks);

        // Allocate until exhaustion.
        while let Some(handle) = pool.alloc() {
            let id = handle.into_id();
            assert!(seen.insert(id), "duplicate BufId {id}");
            assert!((id as usize) < num_blocks, "BufId out of range");
            // Keep the buffer allocated (do not free) to ensure we really exhaust the pool.
        }

        // We must have obtained exactly `num_blocks` unique IDs.
        assert_eq!(seen.len(), num_blocks);

        // Pool must now be exhausted – another alloc returns None.
        assert!(pool.alloc().is_none());

        // Clean-up: return the buffers so other tests are unaffected.
        for id in seen {
            pool.free(id);
        }
    }

    /// End-to-end: allocate via `BufHandle`, write bytes, read them back.
    #[test]
    fn block_pool_bufhandle_write_read_roundtrip() {
        // Simple payload containing 32 distinct bytes.
        #[derive(Clone, PartialEq, Eq, Debug)]
        struct Pattern([u8; 32]);

        let pool = BlockPool::<Pattern>::new(1).unwrap();

        let pattern = Pattern({
            let mut a = [0u8; 32];
            for i in 0..32 { a[i] = i as u8; }
            a
        });

        let mut handle = pool.alloc().expect("allocation failed");
        handle.write(pattern.clone());

        // Read back the value via a freshly claimed handle.
        let id = handle.into_id();
        let read_back = pool.claim(id).unwrap().read();
        assert_eq!(read_back, pattern);

        // Explicitly free the block.
        pool.free(id);

        // The pool should report the block as free again.
        assert!(pool.is_free(id));
    }

    // ---------------------------------------------------------------------
    // Helper payload for tests
    // ---------------------------------------------------------------------

    #[derive(Clone, Copy, Debug)]
    struct Dummy;
} 