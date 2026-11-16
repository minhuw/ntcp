use alloc::vec::Vec;
use core::{fmt, mem::ManuallyDrop, ops::Range, ptr::NonNull, slice};

/// How a backend takes a transmit chunk's memory back.
#[derive(Debug)]
pub struct TxChunkVtable {
    /// Runs exactly once, when the chunk's owner drops it, with the context
    /// and token the chunk was built with. A backend that gave the device
    /// references into the chunk keeps the memory until the device lets go
    /// of them as well (the chunk's device reference count, separate from
    /// its holders' `ChunkRef` count): release gives up only the owner's
    /// share. It may run on any thread (`TxChunk` is `Send`) and after the
    /// source that allocated the chunk is gone; it must be bounded,
    /// nonblocking and nonpanicking.
    pub release: unsafe fn(context: *mut (), token: usize),
}

/// A fixed-size block of transmit memory that copying writes fill and
/// queue entries reference by range (`ChunkSlice`), as Linux's sockets fill
/// a page fragment (`sk_page_frag`).
///
/// Invariant: the bytes below `len()` (the filled prefix) are never written
/// again; the bytes from `len()` to `capacity()` are written only by
/// `append`, which takes `&mut self`, and are never covered by a slice.
/// Slices form references only over the range they cover, never over the
/// whole block, so a device may read a filled range while the owner appends
/// past it. That is why a chunk is not a `Payload`, whose `as_slice` borrows
/// its whole storage.
pub struct TxChunk {
    data: NonNull<u8>,
    capacity: u32,
    filled: u32,
    vtable: &'static TxChunkVtable,
    context: *mut (),
    token: usize,
}

// SAFETY: the chunk owns its memory alone, its filled bytes are immutable,
// and `from_raw_parts` requires its release to be callable from any thread.
unsafe impl Send for TxChunk {}

static HEAP: TxChunkVtable = TxChunkVtable {
    release: release_heap,
};

// SAFETY (caller): context and token are a `Vec<u8>`'s pointer and
// capacity, given up by `TxChunk::heap`.
unsafe fn release_heap(context: *mut (), token: usize) {
    drop(unsafe { Vec::from_raw_parts(context.cast::<u8>(), 0, token) });
}

impl TxChunk {
    /// An empty chunk over memory a backend owns.
    ///
    /// # Safety
    /// - `data..data + capacity` is valid for reads and writes, may be
    ///   uninitialized, and nothing else reads or writes it until the chunk
    ///   hands out ranges of it (and the device reads only those ranges).
    /// - `vtable.release(context, token)` gives up the owner's share of the
    ///   memory and is sound when called once from any thread at any later
    ///   time, including after the source and backend are gone.
    pub unsafe fn from_raw_parts(
        data: NonNull<u8>,
        capacity: u32,
        vtable: &'static TxChunkVtable,
        context: *mut (),
        token: usize,
    ) -> Self {
        Self {
            data,
            capacity,
            filled: 0,
            vtable,
            context,
            token,
        }
    }

    /// An empty heap chunk of `capacity` bytes, left uninitialized: only
    /// `append` writes it.
    pub fn heap(capacity: usize) -> Self {
        let capacity = u32::try_from(capacity).expect("a chunk is below 4 GiB");
        let mut memory = ManuallyDrop::new(Vec::<u8>::with_capacity(capacity as usize));
        let data = memory.as_mut_ptr();
        // SAFETY: a Vec's pointer is never null and its capacity is
        // writable; the chunk now owns the allocation, which only
        // release_heap frees.
        unsafe {
            Self::from_raw_parts(
                NonNull::new_unchecked(data),
                capacity,
                &HEAP,
                data.cast(),
                memory.capacity(),
            )
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// Bytes filled so far: the frozen prefix.
    pub fn len(&self) -> usize {
        self.filled as usize
    }

    pub fn is_empty(&self) -> bool {
        self.filled == 0
    }

    /// Room left past the filled prefix.
    pub fn remaining(&self) -> usize {
        (self.capacity - self.filled) as usize
    }

    /// Copies as much of `bytes` as fits past the filled prefix and freezes
    /// it; returns how many bytes it took.
    pub fn append(&mut self, bytes: &[u8]) -> usize {
        let count = bytes.len().min(self.remaining());
        // SAFETY: filled + count <= capacity, and those bytes are past the
        // filled prefix, which no slice covers. A raw copy forms no
        // reference over the block, so a device reading the prefix is not
        // aliased.
        unsafe {
            self.data
                .as_ptr()
                .add(self.filled as usize)
                .copy_from_nonoverlapping(bytes.as_ptr(), count);
        }
        self.filled += count as u32;
        count
    }

    /// The filled bytes in `range`.
    ///
    /// # Panics
    /// If `range` is not inside the filled prefix.
    pub fn bytes(&self, range: Range<usize>) -> &[u8] {
        assert!(
            range.start <= range.end && range.end <= self.len(),
            "chunk range outside the filled prefix"
        );
        // SAFETY: inside the filled prefix, initialized and never written
        // again.
        unsafe {
            slice::from_raw_parts(self.data.as_ptr().add(range.start), range.end - range.start)
        }
    }

    /// The start of the chunk's memory, for its backend (a device address
    /// lookup); reading through it is sound only below `len()`.
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    /// The release this chunk was built with: a backend compares it to its
    /// own (`core::ptr::eq`) before it reads `context` and `token` as its
    /// own memory's.
    pub fn vtable(&self) -> &'static TxChunkVtable {
        self.vtable
    }

    pub fn context(&self) -> *mut () {
        self.context
    }

    pub fn token(&self) -> usize {
        self.token
    }
}

impl Drop for TxChunk {
    fn drop(&mut self) {
        // SAFETY: from_raw_parts' contract; Drop runs once.
        unsafe { (self.vtable.release)(self.context, self.token) }
    }
}

impl fmt::Debug for TxChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxChunk")
            .field("len", &self.filled)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// A filled range of one chunk, as a packet references it: what a backend
/// copies, or takes a device reference on.
#[derive(Clone, Copy)]
pub struct ChunkSlice<'a> {
    chunk: &'a TxChunk,
    offset: u32,
    len: u32,
}

impl<'a> ChunkSlice<'a> {
    /// `range` of `chunk`'s filled prefix; None outside it.
    pub fn new(chunk: &'a TxChunk, range: Range<usize>) -> Option<Self> {
        (range.start <= range.end && range.end <= chunk.len()).then(|| Self {
            chunk,
            offset: range.start as u32,
            len: (range.end - range.start) as u32,
        })
    }

    pub fn chunk(&self) -> &'a TxChunk {
        self.chunk
    }

    /// Where the range starts in its chunk.
    pub fn offset(&self) -> usize {
        self.offset as usize
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.chunk
            .bytes(self.offset as usize..(self.offset + self.len) as usize)
    }
}

impl fmt::Debug for ChunkSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkSlice")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Where an owner gets transmit chunks: memory its backend can hand to the
/// device by reference (EAL memory, UMEM frames), or the heap for a backend
/// that copies.
pub trait TxChunkSource: Send {
    /// Capacity of every chunk `allocate` returns.
    fn chunk_size(&self) -> usize;
    /// An empty chunk, or None when the source has none free now (a device
    /// pool ran dry); nothing was taken.
    fn allocate(&mut self) -> Option<TxChunk>;
}

/// Heap chunks: the source for every backend that copies on transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapChunkSource {
    chunk_size: usize,
}

impl HeapChunkSource {
    /// 16 KiB, a few full-size segments and room for many small writes.
    pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024;

    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }
}

impl Default for HeapChunkSource {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CHUNK_SIZE)
    }
}

impl TxChunkSource for HeapChunkSource {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }
    fn allocate(&mut self) -> Option<TxChunk> {
        Some(TxChunk::heap(self.chunk_size))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn append_freezes_a_prefix_and_slices_stay_inside_it() {
        let mut chunk = TxChunk::heap(8);
        assert_eq!(
            (chunk.len(), chunk.capacity(), chunk.remaining()),
            (0, 8, 8)
        );
        assert!(chunk.is_empty());
        assert_eq!(chunk.append(&[1, 2, 3]), 3);
        let base = chunk.as_ptr();
        assert_eq!(chunk.bytes(0..3), &[1, 2, 3]);
        assert_eq!(chunk.append(&[4, 5, 6, 7, 8, 9, 10]), 5);
        assert_eq!(chunk.append(&[11]), 0);
        assert_eq!(chunk.remaining(), 0);
        assert_eq!(chunk.as_ptr(), base, "a chunk never moves");
        assert_eq!(chunk.bytes(2..8), &[3, 4, 5, 6, 7, 8]);
        let slice = ChunkSlice::new(&chunk, 1..4).unwrap();
        assert_eq!((slice.offset(), slice.len()), (1, 3));
        assert_eq!(slice.bytes(), &[2, 3, 4]);
        assert_eq!(slice.bytes().as_ptr(), base.wrapping_add(1));
        assert!(core::ptr::eq(slice.chunk(), &chunk));
        assert!(ChunkSlice::new(&chunk, 4..4).unwrap().is_empty());
        assert!(ChunkSlice::new(&chunk, 7..9).is_none());
        #[allow(clippy::reversed_empty_ranges)]
        let reversed = ChunkSlice::new(&chunk, 3..2);
        assert!(reversed.is_none());
        assert!(core::ptr::eq(TxChunk::heap(1).vtable(), chunk.vtable()));
        std::thread::spawn(move || drop(chunk)).join().unwrap();
    }

    #[test]
    #[should_panic(expected = "chunk range outside the filled prefix")]
    fn bytes_past_the_filled_prefix_panic() {
        let mut chunk = TxChunk::heap(16);
        chunk.append(&[1, 2]);
        let _ = chunk.bytes(0..3);
    }

    #[test]
    fn heap_source_allocates_empty_chunks_of_its_size() {
        let mut source = HeapChunkSource::default();
        assert_eq!(source.chunk_size(), 16 * 1024);
        let chunk = source.allocate().unwrap();
        assert_eq!((chunk.len(), chunk.capacity()), (0, 16 * 1024));
        let mut small = HeapChunkSource::new(4);
        assert_eq!(small.allocate().unwrap().capacity(), 4);
        let boxed: alloc::boxed::Box<dyn TxChunkSource> = alloc::boxed::Box::new(small);
        assert_eq!(boxed.chunk_size(), 4);
    }
}
