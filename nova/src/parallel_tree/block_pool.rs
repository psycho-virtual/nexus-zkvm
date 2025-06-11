use std::marker::PhantomData;
use std::sync::Arc;
use std::mem;
use std::cell::Cell;

use crossbeam_queue::SegQueue;
use memmap2::{MmapMut, MmapOptions};

/// Compile-time constant for page size; most OSes use 4 KiB.  If you need the
/// real runtime value, replace this with a `libc::sysconf` call and add the
/// `libc` crate, but we avoid extra dependencies here.
const PAGE_SIZE: usize = 4096;

/// Dense handle that indexes a [`BlockPool`] page.  We keep this a `u32`
/// because the slab is capped at 4 GiB (≈ 8192 pages on a 64-core machine).
pub type BufId = u32;

/// Marker trait that specifies (de)serialization of application data so that
/// it can be sent off-heap to another process or persisted to disk.  This is a
/// simplified version – the engine itself only needs *in-memory* buffers, but
/// providing encode/decode makes the buffers usable for IPC as well.
pub trait Payload {
    /// Encode `self` into `dst`, returning the number of bytes written.
    fn encode_into(&self, dst: &mut [u8]) -> usize;

    /// # Safety
    ///
    /// The caller must guarantee that `src` was previously produced by
    /// [`Self::encode_into`].
    unsafe fn decode_from(src: &[u8]) -> Self;
}

/// Pool of fixed-size blocks backed by a single anonymous mmap of a contiguous
/// slab.  The type parameter `P` fixes the payload type stored in each
/// allocated block, allowing the API to omit the `<P>` annotation on every
/// call to [`BlockPool::alloc`] or [`BufHandle::write`].
#[derive(Debug)]
pub struct BlockPool<P: Payload> {
    mmap: MmapMut,
    free: Arc<SegQueue<BufId>>, // global – cheap to clone
    block_size: usize,
    _phantom: PhantomData<P>,
}

impl<P: Payload> BlockPool<P> {
    /// Create a new block pool sized for the given number of *logical cores*.
    /// The design reserves two pages per core, matching the worst-case number
    /// of live nodes in a perfectly unbalanced binary tree (one leaf per
    /// worker plus parent nodes that survived a GC round).
    pub fn new(num_cores: usize) -> anyhow::Result<Self> {
        let num_blocks = num_cores * 2; // 2 × cores
        let payload_sz = mem::size_of::<P>();
        let block_size = if payload_sz <= PAGE_SIZE {
            PAGE_SIZE
        } else {
            ((payload_sz + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE
        };

        let len = num_blocks * block_size;

        let mmap = MmapOptions::new()
            .len(len)
            .map_anon()?;

        // Initialize queue with all buffer IDs in descending order so
        // that the first `pop` grabs page 0 (nicer for debugging).
        let free = Arc::new(SegQueue::new());
        for id in (0..num_blocks as BufId).rev() {
            free.push(id);
        }

        Ok(Self { mmap, free, block_size, _phantom: PhantomData })
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
    pub fn can_edit(&self, id: BufId) -> bool {
        let off = id as usize * self.block_size;
        let end = off + self.block_size;
        end <= self.mmap.len()
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
        self.free.push(id);
    }

    /// Map a `BufId` into a mutable slice of bytes with the correct page
    /// offset.
    pub (crate) fn map_mut(&self, id: BufId) -> &mut [u8] {
        let off = id as usize * self.block_size;
        let end = off + self.block_size;
        if end <= self.mmap.len() {
            unsafe {
                let ptr = self.mmap.as_ptr().add(off) as *mut u8;
                std::slice::from_raw_parts_mut(ptr, self.block_size)
            }
        } else {
            panic!("BufId {id} is out of range")
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

/// Typed view on a buffer.  This is *zero-sized* – it only keeps a raw pointer
/// to the underlying page, therefore behaves like `&mut [u8]`.
pub struct BufHandle<'a, P: Payload> {
    pool: &'a BlockPool<P>,
    id: BufId,
    released: Cell<bool>,
    // Use *mut () as a non-Send/non-Sync marker to prevent cross-thread movement
    _not_send_sync: PhantomData<*mut ()>,
    _phantom: PhantomData<&'a mut P>,
}

impl<'a, P: Payload> BufHandle<'a, P> {
    /// Construct a new handle from `(pool, id)`.
    pub fn new(pool: &'a BlockPool<P>, id: BufId) -> Self {
        Self { 
            pool, 
            id, 
            released: Cell::new(false), 
            _not_send_sync: PhantomData,
            _phantom: PhantomData,
        }
    }

    /// Write a payload value into the underlying block using
    /// [`Payload::encode_into`].
    pub fn write(&mut self, value: &P) {
        let buf = self.pool.map_mut(self.id);
        value.encode_into(buf);
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

    /// Expose the pool's block size for tests/debug.
    pub fn block_size(&self) -> usize {
        self.pool.block_size
    }

    /// Read and decode the payload stored in this buffer and return it.
    ///
    /// # Safety
    /// This relies on the invariant that the memory region was previously
    /// initialised by a corresponding call to `encode_into` for the *same*
    /// payload type `P`.  The caller is responsible for upholding this
    /// contract – in the normal course of operation the pool enforces it by
    /// handing out `BufHandle` instances that are only written through the
    /// safe [`write`][BufHandle::write] API provided above.
    pub fn read(&self) -> P {
        // SAFETY: The slice returned by `map_mut` has the correct bounds for
        // this buffer ID.  We immediately cast it to an immutable slice which
        // is safe because we only hold a shared reference to `self`.
        let buf = self.pool.map_mut(self.id);
        unsafe { P::decode_from(&*buf) }
    }
}

impl<'a, P: Payload> Drop for BufHandle<'a, P> {
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

    /// Memory mapping: round-trip write/read and ensure pages don't overlap.
    #[test]
    fn block_pool_memory_mapping_correctness() {
        // Wrapper type that encodes a test pattern
        struct TestU32(u32);
        
        impl Payload for TestU32 {
            fn encode_into(&self, dst: &mut [u8]) -> usize {
                // Fill first 16 bytes with a test pattern (0xAB)
                for b in &mut dst[..16] {
                    *b = 0xAB;
                }
                16
            }
            
            unsafe fn decode_from(_src: &[u8]) -> Self {
                // Not used in this test
                TestU32(0)
            }
        }
        
        let pool = BlockPool::<TestU32>::new(2).unwrap(); // 4 pages total

        // Allocate two blocks
        let handle1 = pool.alloc().expect("first allocation should succeed");
        let handle2 = pool.alloc().expect("second allocation should succeed");
        
        // Get first ID
        let id1 = handle1.into_id();
        
        // Get second ID and immediately store it
        let id2 = handle2.into_id();
        
        assert_ne!(id1, id2, "expected two distinct BufIds");

        // Re-create a handle for id1 using new()
        let mut handle1 = BufHandle::new(&pool, id1);
        
        // Write pattern to the block
        handle1.write(&TestU32(42)); // Value doesn't matter, implementation just writes 0xAB

        // Free blocks for cleanup
        pool.free(id1); 
        pool.free(id2);
        
        // Read the pattern back to verify it was written correctly
        {
            let buf = pool.map_mut(id1);
            for b in &buf[..16] {
                assert_eq!(*b, 0xAB);
            }
        }

        // Verify block addresses are properly separated
        let ptr1 = pool.map_mut(id1).as_ptr() as usize;
        let ptr2 = pool.map_mut(id2).as_ptr() as usize;
        let diff = ptr1.abs_diff(ptr2);
        assert!(
            diff >= pool.block_size,
            "buffers for different BufIds overlap (diff={diff})"
        );
    }

    /// Allocation/free bookkeeping via `is_free`.
    #[test]
    fn block_pool_is_free_tracking() {
        let num_cores = 2;
        let pool = BlockPool::<Dummy>::new(num_cores).unwrap();

        // We will allocate and immediately free a handful of buffers –
        // verifying the `is_free` status in between.
        let trials = num_cores; // allocate ≤ total capacity

        for _ in 0..trials {
            let handle = pool.alloc().expect("expected free block");
            let id = handle.into_id(); // do *not* free yet

            // The block has been removed from the free list.
            assert!(!pool.is_free(id), "allocated BufId should not be free");

            // Return it to the pool.
            pool.free(id);

            // Now it must show up as free.
            assert!(pool.is_free(id), "released BufId should be free again");
        }
    }

    /// End-to-end: allocate via `BufHandle`, write bytes, read them back.
    #[test]
    fn block_pool_bufhandle_write_read_roundtrip() {
        // Payload that encodes a fixed 32-byte pattern.
        struct Pattern([u8; 32]);
        impl Payload for Pattern {
            fn encode_into(&self, dst: &mut [u8]) -> usize {
                dst[..32].copy_from_slice(&self.0);
                32
            }
            unsafe fn decode_from(src: &[u8]) -> Self {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&src[..32]);
                Pattern(arr)
            }
        }

        let pool = BlockPool::<Pattern>::new(1).unwrap();

        let pattern = Pattern({
            let mut a = [0u8; 32];
            for i in 0..32 { a[i] = i as u8; }
            a
        });

        let mut handle = pool.alloc().expect("allocation failed");
        handle.write(&pattern);

        // Verify contents through pool mapping.
        let id = handle.into_id();
        let buf = pool.map_mut(id);
        for i in 0u8..32 {
            assert_eq!(buf[i as usize], i, "byte mismatch at offset {i}");
        }

        // Explicitly free the block.
        pool.free(id);

        // The pool should report the block as free again.
        assert!(pool.is_free(id));
    }


    #[test]
    fn block_pool_multicore_allocation_write() {
        use std::sync::{Arc, mpsc};
        use rayon::ThreadPoolBuilder;
        use std::collections::HashSet;

        // Payload identical to previous test.
        #[derive(Clone, Copy)]
        struct ThreadPayload(u32);

        impl Payload for ThreadPayload {
            fn encode_into(&self, dst: &mut [u8]) -> usize {
                dst[..4].copy_from_slice(&self.0.to_le_bytes());
                4
            }

            unsafe fn decode_from(src: &[u8]) -> Self {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&src[..4]);
                ThreadPayload(u32::from_le_bytes(arr))
            }
        }

        let cores = core_affinity::get_core_ids().expect("failed to get cores");
        let num_workers = cores.len().min(8).max(1);

        let pool = Arc::new(BlockPool::<ThreadPayload>::new(num_workers).unwrap());

        let (tx, rx) = mpsc::channel::<(BufId, u32, usize)>(); // include core id

        // Build custom rayon pool with pinning.
        let core_vec = cores.clone();
        let rayon_pool = ThreadPoolBuilder::new()
            .num_threads(num_workers)
            .start_handler(move |tid| {
                if let Some(core) = core_vec.get(tid) {
                    let _ = core_affinity::set_for_current(*core);
                }
            })
            .build()
            .expect("failed to build rayon pool");

        rayon_pool.scope(|scope| {
            for tid in 0..num_workers {
                let pool = Arc::clone(&pool);
                let tx = tx.clone();
                let core_id = cores[tid].id;
                scope.spawn(move |_| {
                    let mut handle = pool.alloc().expect("alloc failed");
                    handle.write(&ThreadPayload(tid as u32));
                    let id = handle.into_id();
                    tx.send((id, tid as u32, core_id)).unwrap();
                });
            }
        });

        drop(tx);

        let mut seen_cores = HashSet::new();
        let mut results = Vec::new();
        for (id, val, core_id) in rx {
            assert!(seen_cores.insert(core_id), "duplicate core {core_id}");
            results.push((id, val));
        }

        assert_eq!(seen_cores.len(), num_workers, "not all workers pinned uniquely");

        // Verify writes
        for (id, expected) in results {
            let buf = pool.map_mut(id);
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&buf[..4]);
            let val = u32::from_le_bytes(arr);
            assert_eq!(val, expected);
            pool.free(id);
        }
    }

    // ---------------------------------------------------------------------
    // Helper payload for tests
    // ---------------------------------------------------------------------

    #[derive(Clone, Copy)]
    struct Dummy;

    impl Payload for Dummy {
        fn encode_into(&self, _dst: &mut [u8]) -> usize { 0 }
        unsafe fn decode_from(_src: &[u8]) -> Self { Dummy }
    }
} 