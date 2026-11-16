use alloc::vec::Vec;
use core::{fmt, mem::ManuallyDrop, ops::Deref, ptr::NonNull, slice};

/// How a backend takes a received frame's memory back.
#[derive(Debug)]
pub struct RxFrameVtable {
    /// Runs exactly once, when the frame is dropped, with the context and
    /// token the frame was built with. It may run on any thread (`RxFrame`
    /// is `Send`) and after the backend that built the frame is gone; it
    /// must be bounded, nonblocking and nonpanicking.
    pub release: unsafe fn(context: *mut (), token: usize),
}

/// One received frame, uniquely owned: a byte range the device (or a
/// copying backend) wrote, its truesize, and the release that gives the
/// memory back. It is moved, never shared: a queue holds it inline, and
/// only the frame's owner trims it. It carries no reference count, as an RX
/// frame is held by one queue entry at a time.
///
/// Backends build frames over their own memory with `from_raw_parts` (a
/// DPDK mbuf, an AF_XDP UMEM frame); every other backend copies into a heap
/// frame (`from_vec`, `copy_from_slice`).
pub struct RxFrame {
    data: NonNull<u8>,
    len: u32,
    truesize: u32,
    vtable: &'static RxFrameVtable,
    context: *mut (),
    token: usize,
}

// SAFETY: the bytes are immutable for the frame's life and owned by it
// alone, and `from_raw_parts` requires its release to be callable from any
// thread.
unsafe impl Send for RxFrame {}

static HEAP: RxFrameVtable = RxFrameVtable {
    release: release_heap,
};

// SAFETY (caller): context and token are a `Vec<u8>`'s pointer and
// capacity, given up by `from_vec`.
unsafe fn release_heap(context: *mut (), token: usize) {
    drop(unsafe { Vec::from_raw_parts(context.cast::<u8>(), 0, token) });
}

impl RxFrame {
    /// A frame over memory a backend owns.
    ///
    /// `truesize` is the memory the frame keeps from being reused while it
    /// is held (a DPDK pool element, a UMEM frame), what its holder charges.
    /// It does not change over the frame's life, trimming included, so what
    /// a holder charges when it takes the frame is what it gives back when
    /// it drops it.
    ///
    /// # Safety
    /// - `data..data + len` is initialized and stays valid and unchanged
    ///   until `vtable.release` runs: the device has finished writing it,
    ///   and nothing writes it again while the frame lives.
    /// - `vtable.release(context, token)` gives the memory back, and is
    ///   sound when called once from any thread at any later time, including
    ///   after the backend that built the frame has been dropped.
    pub unsafe fn from_raw_parts(
        data: NonNull<u8>,
        len: u32,
        truesize: u32,
        vtable: &'static RxFrameVtable,
        context: *mut (),
        token: usize,
    ) -> Self {
        debug_assert!(truesize >= len, "a frame's truesize covers its bytes");
        Self {
            data,
            len,
            truesize,
            vtable,
            context,
            token,
        }
    }

    /// A heap frame over `bytes`, without copying. Its truesize is the
    /// vector's capacity: the allocation the frame keeps.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let mut bytes = ManuallyDrop::new(bytes);
        let (len, capacity) = (bytes.len(), bytes.capacity());
        let truesize = u32::try_from(capacity).expect("a frame is below 4 GiB");
        let data = bytes.as_mut_ptr();
        // SAFETY: a Vec's pointer is never null, its first len bytes are
        // initialized, and the frame now owns the allocation, which only
        // release_heap frees.
        unsafe {
            Self::from_raw_parts(
                NonNull::new_unchecked(data),
                len as u32,
                truesize,
                &HEAP,
                data.cast(),
                capacity,
            )
        }
    }

    /// A heap frame holding a copy of `bytes`, allocated to their length.
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self::from_vec(bytes.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: from_raw_parts' contract; advance and truncate keep
        // data..data + len inside the frame's bytes.
        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len as usize) }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The memory this frame holds, charged by whoever holds it; unchanged
    /// by trimming.
    pub fn truesize(&self) -> usize {
        self.truesize as usize
    }

    /// Drops the first `count` bytes, as a holder trims data it already has
    /// or no longer wants.
    ///
    /// # Panics
    /// If `count` exceeds the frame's length.
    pub fn advance(&mut self, count: usize) {
        assert!(count <= self.len(), "advance past the frame's end");
        // SAFETY: count <= len, so the result stays inside the frame's
        // bytes or one past their end.
        self.data = unsafe { self.data.add(count) };
        self.len -= count as u32;
    }

    /// Keeps only the first `len` bytes; no effect when the frame is
    /// already that short.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.len = len as u32;
        }
    }
}

impl Drop for RxFrame {
    fn drop(&mut self) {
        // SAFETY: from_raw_parts' contract; Drop runs once.
        unsafe { (self.vtable.release)(self.context, self.token) }
    }
}

impl Deref for RxFrame {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for RxFrame {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for RxFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RxFrame")
            .field("len", &self.len)
            .field("truesize", &self.truesize)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::vec;

    #[test]
    fn heap_frames_keep_their_allocation_and_trim_in_place() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        let pointer = bytes.as_ptr();
        let mut frame = RxFrame::from_vec(bytes);
        assert_eq!(frame.as_slice(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(frame.as_slice().as_ptr(), pointer);
        assert_eq!(frame.truesize(), 64);
        frame.advance(2);
        assert_eq!(&frame[..], &[3, 4, 5, 6]);
        assert_eq!(frame.as_ptr(), pointer.wrapping_add(2));
        frame.truncate(9);
        assert_eq!(frame.len(), 4);
        frame.truncate(3);
        assert_eq!(frame.as_ref(), &[3, 4, 5]);
        frame.advance(3);
        assert!(frame.is_empty());
        assert_eq!(frame.truesize(), 64, "trimming keeps the charge");
        // Moved to another thread and dropped there.
        std::thread::spawn(move || drop(frame)).join().unwrap();

        let copied = RxFrame::copy_from_slice(&[9; 71]);
        assert_eq!(copied.len(), 71);
        assert_eq!(copied.truesize(), 71);
        let empty = RxFrame::from_vec(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.truesize(), 0);
    }

    #[test]
    #[should_panic(expected = "advance past the frame's end")]
    fn advance_past_the_end_panics() {
        RxFrame::copy_from_slice(&[1, 2]).advance(3);
    }

    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static COUNTING: RxFrameVtable = RxFrameVtable {
        release: release_counting,
    };
    // The token is the address of a byte array the test leaked (a device
    // pool element); release takes it back.
    unsafe fn release_counting(context: *mut (), token: usize) {
        assert_eq!(context as usize, token);
        drop(unsafe { std::boxed::Box::from_raw(context.cast::<[u8; 32]>()) });
        RELEASED.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn backend_frames_release_exactly_once_with_their_token() {
        let element = std::boxed::Box::into_raw(std::boxed::Box::new([7u8; 32]));
        let before = RELEASED.load(Ordering::SeqCst);
        // A 20-byte packet 4 bytes into a 32-byte element.
        let mut frame = unsafe {
            RxFrame::from_raw_parts(
                NonNull::new(element.cast::<u8>().add(4)).unwrap(),
                20,
                32,
                &COUNTING,
                element.cast(),
                element as usize,
            )
        };
        assert_eq!(frame.as_slice(), &[7; 20]);
        assert_eq!(frame.truesize(), 32);
        frame.advance(20);
        assert!(frame.is_empty());
        assert_eq!(RELEASED.load(Ordering::SeqCst), before);
        let moved = vec![frame];
        drop(moved);
        assert_eq!(RELEASED.load(Ordering::SeqCst), before + 1);
    }
}
