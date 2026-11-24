//! Packet buffer ownership: payloads the application shares for
//! transmission (`Payload`), frames received from a device (`RxFrame`), and
//! transmit chunks that copying writes fill (`TxChunk`), held through one
//! owner's `ChunkArena`.
//!
//! The arena's stale-handle check is a `debug_assert!` only, by the user's
//! deliberate choice (D3, 2026-11-15) against a release assert: in a
//! release build a stale `ChunkRef` is not detected and can put another
//! connection's bytes on the wire. The safeguards are the debug check,
//! which runs in every test profile, and the release-path property test of
//! the arena. `ChunkRef` states the handle invariant.
#![no_std]

extern crate alloc;

mod arena;
mod chunk;
mod count;
mod frame;

pub use arena::{ChunkArena, ChunkRef};
pub use chunk::{ChunkSlice, HeapChunkSource, TxChunk, TxChunkSource, TxChunkVtable};
pub use count::RxFrameCount;
pub use frame::{RxFrame, RxFrameVtable};

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{any::Any, fmt, ops::Range};

/// Storage frozen for the lifetime of all owning references.
///
/// # Safety
/// `as_ref()` must always return the same address, length and immutable bytes.
/// Any DMA mapping must remain valid until the storage itself is dropped.
pub unsafe trait StablePayloadStorage: AsRef<[u8]> + Send + Sync + Any {}
unsafe impl StablePayloadStorage for Vec<u8> {}

trait Storage: Send + Sync {
    fn bytes(&self) -> &[u8];
    fn as_any(&self) -> &dyn Any;
}
impl<T: StablePayloadStorage> Storage for T {
    fn bytes(&self) -> &[u8] {
        self.as_ref()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Release {
    callback: Box<dyn Fn() + Send + Sync>,
    _parent: Option<Arc<Release>>,
}
impl Drop for Release {
    fn drop(&mut self) {
        (self.callback)();
    }
}

/// Immutable storage and a checked byte range. Cloning and slicing only clone
/// references; they never copy payload. A release lease is independent of the
/// application's base storage handle and survives every backend/core clone.
#[derive(Clone)]
pub struct Payload {
    storage: Arc<dyn Storage>,
    range: Range<usize>,
    release: Option<Arc<Release>>,
}
impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}
impl Payload {
    pub fn new<T: StablePayloadStorage>(storage: T) -> Self {
        let len = storage.as_ref().len();
        Self {
            storage: Arc::new(storage),
            range: 0..len,
            release: None,
        }
    }
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.storage.bytes()[self.range.clone()]
    }
    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
    pub fn offset(&self) -> usize {
        self.range.start
    }
    pub fn storage<T: Any>(&self) -> Option<&T> {
        self.storage.as_any().downcast_ref()
    }
    pub fn slice(&self, range: Range<usize>) -> Option<Self> {
        if range.start > range.end || range.end > self.len() {
            return None;
        }
        Some(Self {
            storage: self.storage.clone(),
            range: self.range.start + range.start..self.range.start + range.end,
            release: self.release.clone(),
        })
    }
    /// One reference to `self` followed by `next`, when `next` starts where
    /// `self` ends in the same storage and holds the same release lease (or
    /// neither holds one), as Linux merges a zerocopy fragment into the one
    /// before it (zerocopy_fill_skb_from_iter). Otherwise None: the joined
    /// reference would have to cover bytes outside both, or end one lease
    /// together with another.
    pub fn join(&self, next: &Self) -> Option<Self> {
        let same_lease = match (&self.release, &next.release) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if !Arc::ptr_eq(&self.storage, &next.storage)
            || !same_lease
            || self.range.end != next.range.start
        {
            return None;
        }
        Some(Self {
            storage: self.storage.clone(),
            range: self.range.start..next.range.end,
            release: self.release.clone(),
        })
    }
    /// Called after the last clone/slice of this lease is released. The callback
    /// can run in ACK processing or a backend reclaim context: it must be bounded,
    /// nonblocking, nonpanicking and must not reenter the owning TCP endpoint.
    /// The original base Payload (if separately retained) does not hold this lease.
    pub fn with_release<F: Fn() + Send + Sync + 'static>(mut self, callback: F) -> Self {
        self.release = Some(Arc::new(Release {
            callback: Box::new(callback),
            _parent: self.release.take(),
        }));
        self
    }
}

/// A range of a `Payload`, borrowed for one call, as a packet references
/// it without taking a reference count: a backend that keeps the bytes past
/// the call takes its own (`to_payload`).
#[derive(Clone, Copy)]
pub struct PayloadSlice<'a> {
    payload: &'a Payload,
    offset: usize,
    len: usize,
}
impl<'a> PayloadSlice<'a> {
    /// `range` of `payload`'s bytes; None outside them.
    pub fn new(payload: &'a Payload, range: Range<usize>) -> Option<Self> {
        (range.start <= range.end && range.end <= payload.len()).then(|| Self {
            payload,
            offset: range.start,
            len: range.end - range.start,
        })
    }
    pub fn payload(&self) -> &'a Payload {
        self.payload
    }
    /// The range, in the payload's bytes.
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.len
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn bytes(&self) -> &'a [u8] {
        &self.payload.as_slice()[self.range()]
    }
    /// An owning reference to the same bytes, holding the payload's lease.
    pub fn to_payload(&self) -> Payload {
        self.payload.slice(self.range()).unwrap()
    }
}
impl fmt::Debug for PayloadSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadSlice")
            .field("range", &self.range())
            .finish_non_exhaustive()
    }
}

/// One packet to transmit, borrowed for the call: the header bytes the
/// caller built, then the payload in order, as ranges of transmit chunks
/// and shared payloads. A backend copies what it sends before it returns,
/// or takes its own reference on a part's memory (a device reference on a
/// chunk, `PayloadSlice::to_payload`) and keeps it until the device is done
/// with it; it keeps no borrow.
#[derive(Clone, Copy, Debug)]
pub struct TxPacket<'a> {
    pub header: &'a [u8],
    pub payload: &'a [TxPart<'a>],
}
impl TxPacket<'_> {
    pub fn checked_len(&self) -> Option<usize> {
        self.payload
            .iter()
            .try_fold(self.header.len(), |n, p| n.checked_add(p.len()))
    }
}

/// A payload range of a `TxPacket`.
#[derive(Clone, Copy, Debug)]
pub enum TxPart<'a> {
    /// Bytes a copying write put in a transmit chunk.
    Chunk(ChunkSlice<'a>),
    /// Bytes of a payload the application shared.
    Shared(PayloadSlice<'a>),
}
impl<'a> TxPart<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Self::Chunk(slice) => slice.bytes(),
            Self::Shared(slice) => slice.bytes(),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Chunk(slice) => slice.len(),
            Self::Shared(slice) => slice.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::vec;

    #[test]
    fn owned_storage_is_never_relocated_and_release_waits_for_all_ranges() {
        let bytes = vec![1, 2, 3, 4, 5];
        let original = bytes.as_ptr();
        let base = Payload::from_vec(bytes);
        assert_eq!(base.as_slice().as_ptr(), original);
        let released = Arc::new(AtomicUsize::new(0));
        let state = released.clone();
        let lease = base.clone().with_release(move || {
            state.fetch_add(1, Ordering::SeqCst);
        });
        let backend = lease.slice(1..4).unwrap();
        assert_eq!(backend.as_slice().as_ptr(), original.wrapping_add(1));
        assert!(lease.slice(0..6).is_none());
        drop(lease);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        std::thread::spawn(move || drop(backend)).join().unwrap();
        assert_eq!(released.load(Ordering::SeqCst), 1);
        assert_eq!(base.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn join_merges_only_contiguous_ranges_of_one_storage_and_lease() {
        let base = Payload::from_vec(vec![1, 2, 3, 4, 5, 6]);
        let pointer = base.as_slice().as_ptr();
        let first = base.slice(0..2).unwrap();
        let joined = first.join(&base.slice(2..5).unwrap()).unwrap();
        assert_eq!(joined.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!(joined.as_slice().as_ptr(), pointer);
        assert_eq!(joined.offset(), 0);
        assert_eq!(first.join(&base.slice(2..2).unwrap()).unwrap().len(), 2);
        // A gap, an overlap, the wrong order, other storage.
        assert!(first.join(&base.slice(3..5).unwrap()).is_none());
        assert!(first.join(&base.slice(1..5).unwrap()).is_none());
        assert!(base.slice(2..5).unwrap().join(&first).is_none());
        let other = Payload::from_vec(vec![1, 2, 3, 4, 5, 6]);
        assert!(first.join(&other.slice(2..5).unwrap()).is_none());

        let released = Arc::new(AtomicUsize::new(0));
        let state = released.clone();
        let lease = base.clone().with_release(move || {
            state.fetch_add(1, Ordering::SeqCst);
        });
        let leased = lease.slice(0..2).unwrap();
        // A lease never joins an unleased range or another lease.
        assert!(leased.join(&base.slice(2..4).unwrap()).is_none());
        assert!(first.join(&lease.slice(2..4).unwrap()).is_none());
        let other_lease = base.clone().with_release(|| {});
        assert!(leased.join(&other_lease.slice(2..4).unwrap()).is_none());
        let joined = leased.join(&lease.slice(2..6).unwrap()).unwrap();
        assert_eq!(joined.as_slice(), &[1, 2, 3, 4, 5, 6]);
        drop((lease, leased));
        assert_eq!(released.load(Ordering::SeqCst), 0);
        drop(joined);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    // A queue holds frames and chunks inline: keep them five words.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn frames_and_chunks_are_five_words() {
        assert_eq!(size_of::<RxFrame>(), 40);
        assert_eq!(size_of::<Option<RxFrame>>(), 40);
        assert_eq!(size_of::<TxChunk>(), 40);
        assert_eq!(
            size_of::<ChunkRef>(),
            if cfg!(debug_assertions) { 12 } else { 8 }
        );
    }

    #[test]
    fn payload_slices_borrow_a_checked_range() {
        let base = Payload::from_vec(vec![1, 2, 3, 4, 5, 6])
            .slice(1..6)
            .unwrap();
        let slice = PayloadSlice::new(&base, 1..4).unwrap();
        assert_eq!(slice.bytes(), &[3, 4, 5]);
        assert_eq!((slice.range(), slice.len()), (1..4, 3));
        assert!(core::ptr::eq(slice.payload(), &base));
        let owned = slice.to_payload();
        assert_eq!(owned.as_slice(), &[3, 4, 5]);
        assert_eq!(owned.as_slice().as_ptr(), slice.bytes().as_ptr());
        assert!(PayloadSlice::new(&base, 5..5).unwrap().is_empty());
        assert!(PayloadSlice::new(&base, 2..6).is_none());
    }

    #[test]
    fn nested_leases_do_not_release_the_parent_early() {
        let count = Arc::new(AtomicUsize::new(0));
        let a = count.clone();
        let first = Payload::from_vec(vec![9]).with_release(move || {
            a.fetch_add(1, Ordering::SeqCst);
        });
        let a = count.clone();
        let second = first.clone().with_release(move || {
            a.fetch_add(10, Ordering::SeqCst);
        });
        drop(first);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        drop(second);
        assert_eq!(count.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn tx_packet_and_tx_parts_expose_borrowed_ranges_and_checked_len() {
        let mut chunk = TxChunk::heap(16);
        chunk.append(&[10, 11, 12, 13]);
        let shared = Payload::from_vec(vec![20, 21, 22]);
        let chunk_part = TxPart::Chunk(ChunkSlice::new(&chunk, 1..3).unwrap());
        let shared_part = TxPart::Shared(PayloadSlice::new(&shared, 0..2).unwrap());
        let empty_chunk = TxPart::Chunk(ChunkSlice::new(&chunk, 4..4).unwrap());
        let empty_shared = TxPart::Shared(PayloadSlice::new(&shared, 3..3).unwrap());

        assert_eq!((chunk_part.bytes(), chunk_part.len(), chunk_part.is_empty()), (&[11, 12][..], 2, false));
        assert_eq!((shared_part.bytes(), shared_part.len(), shared_part.is_empty()), (&[20, 21][..], 2, false));
        assert!(empty_chunk.is_empty());
        assert!(empty_shared.is_empty());
        assert_eq!(empty_chunk.bytes(), &[]);
        assert_eq!(empty_shared.bytes(), &[]);

        let parts = [chunk_part, empty_chunk, shared_part, empty_shared];
        let packet = TxPacket {
            header: &[1, 2, 3],
            payload: &parts,
        };
        assert_eq!(packet.checked_len(), Some(7));

        let header_only = TxPacket {
            header: &[9; 5],
            payload: &[],
        };
        assert_eq!(header_only.checked_len(), Some(5));
    }
}
