use alloc::{boxed::Box, vec::Vec};
use core::{fmt, mem::MaybeUninit};

use ntcp_buffer::{ChunkArena, ChunkRef, ChunkSlice, HeapChunkSource, TxChunkSource, TxPart};

/// Stack-inline buffer for borrowed `TxPart` slices with heap overflow only
/// when a segment spans more than `N` parts. `TxPart` is `Copy`, so the
/// inline `[MaybeUninit<TxPart<'a>>; N]` array needs no element drop.
pub(crate) struct TxPartsBuf<'a, const N: usize = 8> {
    inline: [MaybeUninit<TxPart<'a>>; N],
    len: usize,
    overflow: Vec<TxPart<'a>>,
}

impl<'a, const N: usize> TxPartsBuf<'a, N> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inline: [const { MaybeUninit::uninit() }; N],
            len: 0,
            overflow: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, part: TxPart<'a>) {
        if !self.overflow.is_empty() {
            self.overflow.push(part);
        } else if self.len < N {
            self.inline[self.len].write(part);
            self.len += 1;
        } else {
            self.overflow.reserve(N.saturating_mul(2).max(1));
            // SAFETY: `self.inline[..self.len]` are initialized when overflow is empty.
            let inline = unsafe {
                core::slice::from_raw_parts(self.inline.as_ptr().cast::<TxPart<'a>>(), self.len)
            };
            self.overflow.extend_from_slice(inline);
            self.overflow.push(part);
            self.len = 0;
        }
    }

    #[inline]
    pub(crate) fn push_merged(&mut self, part: TxPart<'a>) {
        if part.is_empty() {
            return;
        }
        if let TxPart::Chunk(slice) = part
            && let Some(TxPart::Chunk(prev)) = self.last_mut()
            && core::ptr::eq(prev.chunk(), slice.chunk())
            && prev.offset() + prev.len() == slice.offset()
        {
            *prev = ChunkSlice::new(
                prev.chunk(),
                prev.offset()..prev.offset() + prev.len() + slice.len(),
            )
            .expect("merged chunk slice within filled prefix");
            return;
        }
        self.push(part);
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[TxPart<'a>] {
        if !self.overflow.is_empty() {
            &self.overflow
        } else {
            // SAFETY: `self.inline[..self.len]` are initialized by `push`.
            unsafe { core::slice::from_raw_parts(self.inline.as_ptr().cast(), self.len) }
        }
    }

    #[inline]
    fn last_mut(&mut self) -> Option<&mut TxPart<'a>> {
        if !self.overflow.is_empty() {
            self.overflow.last_mut()
        } else if self.len > 0 {
            // SAFETY: `self.inline[self.len - 1]` was initialized by `push`.
            Some(unsafe { self.inline[self.len - 1].assume_init_mut() })
        } else {
            None
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        if !self.overflow.is_empty() {
            self.overflow.len()
        } else {
            self.len
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.len = 0;
        self.overflow.clear();
    }
}

// ChunkArena allocates slots in 64-entry pages.
const ARENA_PAGE_SLOTS: usize = 64;

enum TxSource {
    Heap(HeapChunkSource),
    Custom(Box<dyn TxChunkSource>),
}

impl TxSource {
    #[inline]
    fn chunk_size(&self) -> usize {
        match self {
            Self::Heap(s) => s.chunk_size(),
            Self::Custom(s) => s.chunk_size(),
        }
    }

    #[inline]
    fn allocate(&mut self) -> Option<ntcp_buffer::TxChunk> {
        match self {
            Self::Heap(s) => s.allocate(),
            Self::Custom(s) => s.allocate(),
        }
    }
}

/// Per-owner transmit chunk pool: one `ChunkArena`, one `TxChunkSource`, and
/// the current shared tail chunk that copying writes across all connections of
/// the owner append into.
///
/// Safety invariant (two-level refcount on `TxChunk`):
/// The filled prefix `0..chunk.len()` of a `TxChunk` is frozen forever once
/// written and MUST NEVER be reset or overwritten even when
/// `arena.references(&tail) == 1` (a backend/device may still hold a DMA
/// reference to the prefix). Writes only append past `filled`, and `tail` is
/// released when full, idle under shrink, or at teardown.
pub(crate) struct TxPool {
    arena: ChunkArena,
    source: TxSource,
    tail: Option<ChunkRef>,
    // Cached remaining writable bytes in `tail` (0 when `tail.is_none()`).
    tail_remaining: u32,
    // Sum of `chunk.capacity()` for every live chunk currently in `arena`.
    chunk_bytes: usize,
    // Cached `arena.storage_bytes() + chunk_bytes`, updated only when chunks or
    // arena pages are allocated, freed, or shrunk.
    storage_bytes: usize,
}

impl fmt::Debug for TxPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxPool")
            .field("live", &self.arena.live())
            .field("chunk_bytes", &self.chunk_bytes)
            .field("tail_remaining", &self.tail_remaining())
            .field("chunk_size", &self.source.chunk_size())
            .finish()
    }
}

impl TxPool {
    pub(crate) fn new(source: Box<dyn TxChunkSource>) -> Self {
        Self {
            arena: ChunkArena::new(),
            source: TxSource::Custom(source),
            tail: None,
            tail_remaining: 0,
            chunk_bytes: 0,
            storage_bytes: 0,
        }
    }

    pub(crate) fn heap_default() -> Self {
        Self {
            arena: ChunkArena::new(),
            source: TxSource::Heap(HeapChunkSource::default()),
            tail: None,
            tail_remaining: 0,
            chunk_bytes: 0,
            storage_bytes: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn heap(chunk_size: usize) -> Self {
        Self {
            arena: ChunkArena::new(),
            source: TxSource::Heap(HeapChunkSource::new(chunk_size)),
            tail: None,
            tail_remaining: 0,
            chunk_bytes: 0,
            storage_bytes: 0,
        }
    }

    #[inline]
    pub(crate) fn arena(&self) -> &ChunkArena {
        &self.arena
    }

    #[inline]
    pub(crate) fn chunk_size(&self) -> usize {
        self.source.chunk_size()
    }

    #[inline]
    pub(crate) fn live(&self) -> usize {
        self.arena.live()
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    /// Exact heap bytes held by this pool (arena pages/tables plus all live
    /// chunks' capacities).
    #[inline]
    pub(crate) fn storage_bytes(&self) -> usize {
        debug_assert_eq!(
            self.storage_bytes,
            self.arena.storage_bytes() + self.chunk_bytes
        );
        self.storage_bytes
    }

    /// Remaining writable bytes in the shared tail chunk (`0` if there is no
    /// tail chunk or it is full).
    #[inline]
    pub(crate) fn tail_remaining(&self) -> usize {
        debug_assert_eq!(
            self.tail_remaining as usize,
            self.tail
                .as_ref()
                .map_or(0, |handle| self.arena.get(handle).remaining())
        );
        self.tail_remaining as usize
    }

    /// Whether `handle` points to the current shared tail chunk and its filled
    /// prefix ends at `end`.
    #[inline]
    pub(crate) fn tail_continues(&self, handle: &ChunkRef, end: u32) -> bool {
        self.tail.as_ref().is_some_and(|tail| {
            self.arena.same_chunk(handle, tail) && self.arena.get(tail).len() as u32 == end
        })
    }

    /// Whether two handles reference the same chunk in this pool's arena.
    #[inline]
    pub(crate) fn same_chunk(&self, a: &ChunkRef, b: &ChunkRef) -> bool {
        self.arena.same_chunk(a, b)
    }

    /// Whether a tail chunk is held only by the pool itself (no connection's
    /// send queue references it).
    #[inline]
    pub(crate) fn has_idle_tail(&self) -> bool {
        self.tail
            .as_ref()
            .is_some_and(|handle| self.arena.references(handle) == 1)
    }

    /// Fast O(1) check for whether the arena has grown past a single page.
    #[inline]
    pub(crate) fn has_multiple_arena_pages(&self) -> bool {
        self.arena.page_count() > 1
    }

    /// Whether the arena grew past a single page during a burst and now holds
    /// no connection-referenced chunks (only empty slots or an idle tail chunk).
    #[inline]
    pub(crate) fn has_excess_arena_pages(&self) -> bool {
        self.arena.capacity() > ARENA_PAGE_SLOTS
            && (self.arena.live() == 0 || (self.arena.live() == 1 && self.has_idle_tail()))
    }

    /// Peak additional bytes needed to append `copy_bytes` into this pool.
    /// Exact for single-page growths (including `copy_bytes == 1`) and a tight
    /// upper bound for multi-page growths.
    pub(crate) fn growth_bytes(&self, copy_bytes: usize) -> usize {
        let extra = copy_bytes.saturating_sub(self.tail_remaining());
        if extra == 0 {
            return 0;
        }
        let chunk_size = self.chunk_size();
        if chunk_size == 0 {
            return usize::MAX;
        }
        let new_chunks = extra.div_ceil(chunk_size);
        let Some(chunk_cost) = new_chunks.checked_mul(chunk_size) else {
            return usize::MAX;
        };
        let free_slots = self.arena.capacity().saturating_sub(self.arena.live());
        let deficit = new_chunks.saturating_sub(free_slots);
        let arena_cost = if deficit == 0 {
            0
        } else if free_slots == 0 && deficit <= ARENA_PAGE_SLOTS {
            self.arena.growth_bytes()
        } else {
            let pages = deficit.div_ceil(ARENA_PAGE_SLOTS);
            let single_page = ChunkArena::new().growth_bytes();
            let first = if free_slots == 0 {
                self.arena.growth_bytes()
            } else {
                single_page
            };
            let rest = pages.saturating_sub(1).saturating_mul(single_page);
            let total_pages = self.arena.page_count().saturating_add(pages);
            let table_bound = if total_pages > 4 {
                total_pages
                    .checked_next_power_of_two()
                    .map_or(usize::MAX, |cap| cap.saturating_mul(32))
            } else {
                0
            };
            first.saturating_add(rest).saturating_add(table_bound)
        };
        chunk_cost.saturating_add(arena_cost)
    }

    /// Copy as much of `bytes` as fits into the tail chunk and freshly
    /// allocated chunks, invoking `emit(&mut arena, tail_ref, offset, len)`
    /// for each appended slice.
    ///
    /// Passing `&mut ChunkArena` and `&ChunkRef` lets callers extend an
    /// existing `TxSeg` pointing at the same chunk in place with zero
    /// `dup`/`release` traffic, and call `arena.dup(tail_ref)` only when
    /// creating a new `TxSeg`.
    ///
    /// Stops cleanly and returns the prefix length copied so far if the
    /// chunk source runs dry (`allocate() -> None`) or arena page growth fails
    /// (`try_insert() -> Err`).
    /// Fast path for a copying write that fits completely inside the current
    /// shared tail chunk and needs a new `ChunkRef` for the caller's entry:
    /// copies bytes and increments the refcount in a single arena slot lookup.
    #[inline]
    pub(crate) fn append_to_tail_and_dup(&mut self, bytes: &[u8]) -> (ChunkRef, u32, usize) {
        debug_assert!(!bytes.is_empty() && bytes.len() <= self.tail_remaining as usize);
        let tail = self.tail.as_ref().expect("tail chunk present");
        let (offset, taken, full, dup) = self.arena.append_and_dup(tail, bytes);
        self.tail_remaining -= taken as u32;
        if full {
            debug_assert_eq!(self.tail_remaining, 0);
            let tail = self.tail.take().unwrap();
            self.release(tail);
        }
        (dup, offset, taken)
    }

    /// Fast path for a copying write that fits completely inside the current
    /// shared tail chunk and extends an existing entry pointing to `tail`.
    #[inline]
    pub(crate) fn append_to_tail_no_dup(&mut self, bytes: &[u8]) -> (u32, usize) {
        debug_assert!(!bytes.is_empty() && bytes.len() <= self.tail_remaining as usize);
        let tail = self.tail.as_ref().expect("tail chunk present");
        let chunk = self.arena.get_mut(tail);
        let offset = chunk.len() as u32;
        let taken = chunk.append(bytes);
        let full = chunk.is_full();
        self.tail_remaining -= taken as u32;
        if full {
            debug_assert_eq!(self.tail_remaining, 0);
            let tail = self.tail.take().unwrap();
            self.release(tail);
        }
        (offset, taken)
    }

    pub(crate) fn append_into(
        &mut self,
        mut bytes: &[u8],
        mut emit: impl FnMut(&mut ChunkArena, &ChunkRef, u32, u32),
    ) -> usize {
        let mut total = 0;
        while !bytes.is_empty() {
            if self.tail.is_none() {
                let Some(chunk) = self.source.allocate() else {
                    break;
                };
                let rem = chunk.remaining() as u32;
                if rem == 0 {
                    break;
                }
                let cap = chunk.capacity();
                let Ok(handle) = self.arena.try_insert(chunk) else {
                    break;
                };
                self.chunk_bytes += cap;
                self.storage_bytes = self.arena.storage_bytes() + self.chunk_bytes;
                self.tail_remaining = rem;
                self.tail = Some(handle);
            }
            let tail = self.tail.take().unwrap();
            let chunk = self.arena.get_mut(&tail);
            let offset = chunk.len() as u32;
            let taken = chunk.append(bytes);
            let full = chunk.is_full();
            debug_assert!(taken > 0);
            self.tail_remaining -= taken as u32;
            emit(&mut self.arena, &tail, offset, taken as u32);
            if full {
                debug_assert_eq!(self.tail_remaining, 0);
                self.release(tail);
            } else {
                self.tail = Some(tail);
            }
            bytes = &bytes[taken..];
            total += taken;
        }
        total
    }

    #[inline]
    pub(crate) fn dup(&mut self, handle: &ChunkRef) -> ChunkRef {
        self.arena.dup(handle)
    }

    #[inline]
    pub(crate) fn release(&mut self, handle: ChunkRef) {
        let freed = self.arena.release_drop(handle);
        if freed != 0 {
            self.finish_release(freed);
        }
    }

    #[cold]
    #[inline(never)]
    fn finish_release(&mut self, freed: usize) {
        self.chunk_bytes -= freed;
        self.storage_bytes = self.arena.storage_bytes() + self.chunk_bytes;
    }

    /// Release the shared tail chunk if no connection holds a reference to it
    /// (`references == 1`), returning its memory to the allocator / `Budget`.
    /// Never resets or overwrites the chunk's filled prefix.
    pub(crate) fn release_idle_tail(&mut self) -> bool {
        if self.has_idle_tail() {
            let tail = self.tail.take().unwrap();
            self.tail_remaining = 0;
            self.release(tail);
            return true;
        }
        false
    }

    /// Ensures `self.tail` holds at least `min_bytes.min(self.chunk_size())`
    /// writable bytes so an immediately following prepared write can copy into
    /// the tail without allocating. Returns `false` if chunk allocation or
    /// arena insertion failed (leaving existing state untouched).
    pub(crate) fn ensure_tail_for(&mut self, min_bytes: usize) -> bool {
        let needed = min_bytes.min(self.chunk_size());
        if needed == 0 || self.tail_remaining() >= needed {
            return true;
        }
        let Some(chunk) = self.source.allocate() else {
            return false;
        };
        let rem = chunk.remaining();
        if rem < needed {
            return false;
        }
        let cap = chunk.capacity();
        let Ok(handle) = self.arena.try_insert(chunk) else {
            return false;
        };
        self.chunk_bytes += cap;
        self.tail_remaining = rem as u32;
        if let Some(old_tail) = self.tail.replace(handle) {
            self.release(old_tail);
        }
        self.storage_bytes = self.arena.storage_bytes() + self.chunk_bytes;
        true
    }

    /// Release an idle tail chunk (if any) and free empty arena pages.
    /// Returns the number of storage bytes freed.
    pub(crate) fn shrink(&mut self) -> usize {
        let before = self.storage_bytes();
        self.release_idle_tail();
        if self.arena.live() == 0 {
            self.arena = ChunkArena::new();
        } else {
            self.arena.shrink();
        }
        self.storage_bytes = self.arena.storage_bytes() + self.chunk_bytes;
        before.saturating_sub(self.storage_bytes())
    }

    /// Unconditionally release the pool's tail reference (used at teardown).
    pub(crate) fn release_tail(&mut self) {
        if let Some(tail) = self.tail.take() {
            self.tail_remaining = 0;
            self.release(tail);
        }
    }
}

impl Drop for TxPool {
    fn drop(&mut self) {
        self.release_tail();
        #[cfg(test)]
        {
            extern crate std;
            if !std::thread::panicking() {
                debug_assert_eq!(self.arena.live(), 0, "TxPool dropped with live ChunkRefs");
            }
        }
        #[cfg(not(test))]
        debug_assert_eq!(self.arena.live(), 0, "TxPool dropped with live ChunkRefs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use ntcp_buffer::TxChunk;

    struct LimitedSource {
        chunk_size: usize,
        remaining: usize,
    }

    impl TxChunkSource for LimitedSource {
        fn chunk_size(&self) -> usize {
            self.chunk_size
        }

        fn allocate(&mut self) -> Option<TxChunk> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            TxChunk::try_heap(self.chunk_size)
        }
    }

    #[test]
    fn shared_tail_append_extends_in_place_and_releases_on_full() {
        let mut pool = TxPool::heap(16);
        assert_eq!(pool.storage_bytes(), 0);
        assert_eq!(pool.tail_remaining(), 0);
        assert_eq!(pool.live(), 0);

        let mut segs: Vec<(ChunkRef, u32, u32)> = Vec::new();
        let append = |pool: &mut TxPool, segs: &mut Vec<(ChunkRef, u32, u32)>, data: &[u8]| {
            pool.append_into(data, |arena, tail, off, len| {
                if let Some((last_ref, last_off, last_len)) = segs.last_mut()
                    && core::ptr::eq(arena.get(last_ref), arena.get(tail))
                    && *last_off + *last_len == off
                {
                    *last_len += len;
                } else {
                    segs.push((arena.dup(tail), off, len));
                }
            })
        };

        // First write allocates 1 chunk (16 bytes) and 1 arena page.
        let est = pool.growth_bytes(6);
        let before = pool.storage_bytes();
        assert_eq!(append(&mut pool, &mut segs, b"abcdef"), 6);
        assert_eq!(pool.storage_bytes() - before, est);
        assert_eq!(segs.len(), 1);
        assert_eq!(pool.live(), 1);
        assert_eq!(pool.tail_remaining(), 10);
        assert!(pool.tail_continues(&segs[0].0, 6));
        assert!(!pool.has_idle_tail());

        // Second write fits in tail: zero growth, extends segs[0] in place.
        assert_eq!(pool.growth_bytes(4), 0);
        assert_eq!(append(&mut pool, &mut segs, b"ghij"), 4);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].2, 10);
        assert_eq!(pool.tail_remaining(), 6);

        // Third write fills tail (6 bytes) and spills 5 bytes into a new chunk.
        let est2 = pool.growth_bytes(11);
        let before2 = pool.storage_bytes();
        assert_eq!(append(&mut pool, &mut segs, b"klmnopqrstu"), 11);
        assert_eq!(pool.storage_bytes() - before2, est2);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].2, 16);
        assert_eq!(segs[1].2, 5);
        assert_eq!(pool.live(), 2);
        assert_eq!(pool.tail_remaining(), 11);

        // Verify exact bytes.
        let mut out = Vec::new();
        for (h, off, len) in &segs {
            out.extend_from_slice(
                pool.arena()
                    .get(h)
                    .bytes(*off as usize..(*off + *len) as usize),
            );
        }
        assert_eq!(&out, b"abcdefghijklmnopqrstu");

        // Releasing all segment handles leaves only the idle tail.
        for (h, _, _) in segs.drain(..) {
            pool.release(h);
        }
        assert_eq!(pool.live(), 1);
        assert!(pool.has_idle_tail());
        let freed = pool.shrink();
        assert!(freed >= 16);
        assert_eq!(pool.live(), 0);
        assert_eq!(pool.chunk_bytes(), 0);
        assert_eq!(pool.tail_remaining(), 0);
    }

    #[test]
    fn dry_source_and_oom_return_partial_prefix_cleanly() {
        let mut pool = TxPool::new(Box::new(LimitedSource {
            chunk_size: 8,
            remaining: 2,
        }));
        let mut refs = Vec::new();
        let n = pool.append_into(&[7u8; 25], |arena, tail, off, len| {
            refs.push((arena.dup(tail), off, len));
        });
        assert_eq!(n, 16);
        assert_eq!(refs.len(), 2);
        assert_eq!(pool.tail_remaining(), 0);
        // Source is dry: next append copies 0 bytes without panicking.
        assert_eq!(
            pool.append_into(b"more", |arena, tail, off, len| {
                refs.push((arena.dup(tail), off, len));
            }),
            0
        );
        for (h, _, _) in refs {
            pool.release(h);
        }
        assert_eq!(pool.live(), 0);

        // OOM via fail_after(0) returns 0 cleanly.
        let mut oom_pool = TxPool::heap(64);
        let mut oom_refs = Vec::new();
        let taken = crate::allocation_tests::fail_after(0, || {
            oom_pool.append_into(&[1u8; 32], |arena, tail, off, len| {
                oom_refs.push((arena.dup(tail), off, len));
            })
        });
        assert_eq!(taken, 0);
        assert!(oom_refs.is_empty());
        assert_eq!(oom_pool.live(), 0);
    }

    #[test]
    fn growth_bytes_bounds_multi_page_allocation() {
        let mut pool = TxPool::heap(16);
        let mut refs = Vec::new();
        // Force allocation across 5 arena pages (> 256 chunks).
        let bytes = alloc::vec![3u8; 300 * 16];
        let est = pool.growth_bytes(bytes.len());
        let before = pool.storage_bytes();
        let n = pool.append_into(&bytes, |arena, tail, off, len| {
            refs.push((arena.dup(tail), off, len));
        });
        assert_eq!(n, bytes.len());
        let actual = pool.storage_bytes() - before;
        assert!(
            est >= actual,
            "growth_bytes estimate {est} < actual {actual}"
        );
        for (h, _, _) in refs {
            pool.release(h);
        }
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn tx_parts_buf_inline_spill_merge_and_clear() {
        let mut c1 = TxChunk::heap(16);
        c1.append(b"0123456789abcdef");
        let mut c2 = TxChunk::heap(8);
        c2.append(b"ABCDEFGH");

        let mut buf: TxPartsBuf<'_, 2> = TxPartsBuf::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(buf.as_slice().is_empty());

        // Adjacent slices in same chunk merge inline.
        buf.push_merged(TxPart::Chunk(ChunkSlice::new(&c1, 0..4).unwrap()));
        buf.push_merged(TxPart::Chunk(ChunkSlice::new(&c1, 4..8).unwrap()));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.as_slice()[0].bytes(), b"01234567");

        // Non-adjacent slice in same chunk and different chunk spill to overflow.
        buf.push_merged(TxPart::Chunk(ChunkSlice::new(&c1, 10..12).unwrap()));
        assert_eq!(buf.len(), 2);
        buf.push_merged(TxPart::Chunk(ChunkSlice::new(&c2, 0..3).unwrap()));
        assert_eq!(buf.len(), 3);
        // Merge also works after spilling into overflow.
        buf.push_merged(TxPart::Chunk(ChunkSlice::new(&c2, 3..6).unwrap()));
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_slice()[0].bytes(), b"01234567");
        assert_eq!(buf.as_slice()[1].bytes(), b"ab");
        assert_eq!(buf.as_slice()[2].bytes(), b"ABCDEF");

        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        buf.push(TxPart::Chunk(ChunkSlice::new(&c1, 0..1).unwrap()));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.as_slice()[0].bytes(), b"0");
    }
}
