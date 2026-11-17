use core::sync::atomic::{AtomicU64, Ordering};

// Set in `count` once the backend has gone.
const GONE: u64 = 1 << 63;

/// How many frames a backend handed out (`RxFrame::from_raw_parts`) have
/// been released, for a backend whose frames' releases share a block with
/// it, and whose block is freed by the last of the backend and its frames:
/// a frame may outlive the backend that built it.
///
/// The backend counts what it hands out itself (a plain integer: only it
/// hands out); each release calls `release`, from any thread, and the
/// backend calls `leave` once as it goes, with that count. Exactly one of
/// those calls returns true, the last: the caller frees the block. One
/// atomic read-modify-write per release, none per frame handed out.
#[derive(Debug, Default)]
pub struct RxFrameCount {
    // Frames released, plus GONE once the backend has left.
    count: AtomicU64,
    // Frames handed out in all, published by `leave` before it sets GONE.
    taken: AtomicU64,
}

impl RxFrameCount {
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            taken: AtomicU64::new(0),
        }
    }

    /// Frames released so far (a relaxed load): what the backend handed out
    /// less this is what it has outstanding.
    pub fn released(&self) -> u64 {
        self.count.load(Ordering::Relaxed) & !GONE
    }

    /// One frame released; true when it was the last of a backend that has
    /// left, and the caller frees the block.
    pub fn release(&self) -> bool {
        // AcqRel: what the releaser did with the frame happens before
        // whoever frees the block, and a release after `leave` sees its
        // `taken`.
        let count = self.count.fetch_add(1, Ordering::AcqRel) + 1;
        count & GONE != 0 && count & !GONE == self.taken.load(Ordering::Relaxed)
    }

    /// The backend goes, having handed out `taken` frames; true when every
    /// one has been released, and the caller frees the block.
    ///
    /// # Panics
    /// If called twice.
    pub fn leave(&self, taken: u64) -> bool {
        self.taken.store(taken, Ordering::Relaxed);
        let before = self.count.fetch_add(GONE, Ordering::AcqRel);
        assert!(before & GONE == 0, "a backend leaves once");
        debug_assert!(before <= taken, "more frames released than handed out");
        before == taken
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{sync::Arc, vec::Vec};

    #[test]
    fn the_last_of_the_backend_and_its_frames_frees() {
        // Released before the backend leaves: leave frees.
        let count = RxFrameCount::new();
        assert!(!count.release());
        assert!(!count.release());
        assert_eq!(count.released(), 2);
        assert!(count.leave(2));
        // Outstanding when it leaves: the last release frees.
        let count = RxFrameCount::new();
        assert!(!count.release());
        assert!(!count.leave(3));
        assert_eq!(count.released(), 1);
        assert!(!count.release());
        assert!(count.release());
        // Nothing handed out at all.
        assert!(RxFrameCount::new().leave(0));
    }

    // Releases racing the backend's leave free the block exactly once.
    #[test]
    fn exactly_one_frees_when_releases_race_the_leave() {
        let rounds = if cfg!(miri) { 8 } else { 2000 };
        for _ in 0..rounds {
            let count = Arc::new(RxFrameCount::new());
            let threads: Vec<_> = (0..4)
                .map(|_| {
                    let count = count.clone();
                    std::thread::spawn(move || (0..3).filter(|_| count.release()).count())
                })
                .collect();
            let mut frees = usize::from(count.leave(12));
            for thread in threads {
                frees += thread.join().unwrap();
            }
            assert_eq!(frees, 1);
            assert_eq!(count.released(), 12);
        }
    }
}
