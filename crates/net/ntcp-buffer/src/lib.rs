#![no_std]

extern crate alloc;

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
}
