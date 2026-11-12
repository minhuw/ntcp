// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Managed-descriptor tables, indexed by fd number like Linux's fdtable.
// Check: cargo test -p ntcp-socket --lib fd_table
//
// Every intercepted call asks "is this fd ours?" from any thread, including
// a signal handler, so a lookup is two atomic loads: no lock, allocation or
// TLS. Each entry counts the claims on that fd number (a token being replaced
// and its replacement may claim one number briefly).
//
// Growth follows fs/file.c expand_files/alloc_fdtable: capacity doubles, to
// the power of two covering the fd, and only on the open path. Linux copies
// into a new table, publishes it with rcu_assign_pointer and frees the old
// one after a grace period (call_rcu -> free_fdtable_rcu). Readers here have
// no grace period to wait for: a signal handler can hold an old table for an
// unbounded time and cannot register as a reader. So the table never copies:
// segment k (k >= 1) covers [BASE << (k - 1), BASE << k) and each growth
// publishes one more segment by compare-and-swap. A published segment never
// moves and lives as long as the table, so nothing needs reclaiming; a racing
// grower that loses the swap frees its own unpublished segment. Capacity is
// the same doubling sequence as Linux's, and the memory is 4 bytes per fd
// below the next power of two above the highest managed fd.
use crate::Result;
use libc::{EBADF, EMFILE, ENOMEM, RLIMIT_NOFILE, SYS_getrlimit, rlim_t, rlimit, syscall};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};

// NR_OPEN_DEFAULT (BITS_PER_LONG): the fds Linux's embedded fdtab covers.
const BASE: usize = 64;
// Segments 0..=25 cover every non-negative i32.
const SEGMENTS: usize = (i32::MAX as usize / BASE).ilog2() as usize + 2;

pub(crate) struct FdTable {
    segments: [AtomicPtr<AtomicU32>; SEGMENTS],
    // Claims per segment, so "any managed fd below n" skips empty segments.
    live: [AtomicUsize; SEGMENTS],
}

// (segment, offset, segment length) of fd.
fn locate(fd: usize) -> (usize, usize, usize) {
    let block = fd / BASE;
    if block == 0 {
        return (0, fd, BASE);
    }
    let k = block.ilog2() as usize + 1;
    let start = BASE << (k - 1);
    (k, fd - start, start)
}
fn start(segment: usize) -> usize {
    if segment == 0 {
        0
    } else {
        BASE << (segment - 1)
    }
}

// The soft limit, as alloc_fd checks it (fs/file.c __get_unused_fd_flags).
fn nofile_limit() -> Result<rlim_t> {
    let mut limit: rlimit = unsafe { std::mem::zeroed() };
    if unsafe { syscall(SYS_getrlimit, RLIMIT_NOFILE, &mut limit) } < 0 {
        return Err(crate::errno());
    }
    Ok(limit.rlim_cur)
}

impl FdTable {
    pub(crate) const fn new() -> Self {
        Self {
            segments: [const { AtomicPtr::new(ptr::null_mut()) }; SEGMENTS],
            live: [const { AtomicUsize::new(0) }; SEGMENTS],
        }
    }
    fn entry(&self, fd: usize) -> Option<&AtomicU32> {
        let (segment, offset, _) = locate(fd);
        let base = self.segments[segment].load(Ordering::Acquire);
        // SAFETY: a published segment is zero-initialized, never moves, and
        // lives as long as the table; offset is within its length.
        (!base.is_null()).then(|| unsafe { &*base.add(offset) })
    }
    // Lock-free and async-signal-safe: no allocation, lock, TLS or syscall.
    pub(crate) fn contains(&self, fd: i32) -> bool {
        fd >= 0
            && self
                .entry(fd as usize)
                .is_some_and(|e| e.load(Ordering::Acquire) != 0)
    }
    pub(crate) fn any(&self) -> bool {
        self.live.iter().any(|n| n.load(Ordering::Acquire) != 0)
    }
    // Calls f with each claimed fd below n, in order, until it returns
    // Some. Like select's own pass over its sets, this is O(n) at worst.
    pub(crate) fn find_below<T>(&self, n: i32, mut f: impl FnMut(i32) -> Option<T>) -> Option<T> {
        let n = n.max(0) as usize;
        for segment in 0..SEGMENTS {
            let first = start(segment);
            if first >= n {
                break;
            }
            if self.live[segment].load(Ordering::Acquire) == 0 {
                continue;
            }
            for fd in first..n.min(first + locate(first).2) {
                if self.contains(fd as i32)
                    && let Some(found) = f(fd as i32)
                {
                    return Some(found);
                }
            }
        }
        None
    }
    // Claim fd, growing the table to cover it. Open paths only.
    pub(crate) fn reserve(&self, fd: i32) -> Result<usize> {
        if fd >= 0 && self.entry(fd as usize).is_some() {
            return self.reserve_within(fd, rlim_t::MAX);
        }
        self.reserve_within(fd, nofile_limit()?)
    }
    fn grow_within(&self, fd: i32, limit: rlim_t) -> Result<()> {
        if fd < 0 {
            return Err(EBADF);
        }
        let (segment, _, len) = locate(fd as usize);
        if !self.segments[segment].load(Ordering::Acquire).is_null() {
            return Ok(());
        }
        // expand_files never grows past what the caller may open.
        if fd as rlim_t >= limit {
            return Err(EMFILE);
        }
        let layout = Layout::array::<AtomicU32>(len).map_err(|_| ENOMEM)?;
        // SAFETY: layout is non-zero; all-zero bytes are valid AtomicU32s.
        let fresh = unsafe { alloc_zeroed(layout) }.cast::<AtomicU32>();
        if fresh.is_null() {
            return Err(ENOMEM);
        }
        if self.segments[segment]
            .compare_exchange(ptr::null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // SAFETY: never published, so no reader can hold it.
            unsafe { dealloc(fresh.cast(), layout) };
        }
        Ok(())
    }
    fn reserve_within(&self, fd: i32, limit: rlim_t) -> Result<usize> {
        self.grow_within(fd, limit)?;
        let fd = fd as usize;
        // Count the segment first: whoever sees the entry also sees the count.
        self.live[locate(fd).0].fetch_add(1, Ordering::AcqRel);
        self.entry(fd).unwrap().fetch_add(1, Ordering::AcqRel);
        Ok(fd)
    }
    pub(crate) fn release(&self, fd: usize) {
        let entry = self.entry(fd).expect("released fd was never reserved");
        let claims = entry.fetch_sub(1, Ordering::AcqRel);
        assert_ne!(claims, 0, "released fd {fd} has no claim");
        self.live[locate(fd).0].fetch_sub(1, Ordering::AcqRel);
    }
}
impl Drop for FdTable {
    fn drop(&mut self) {
        for (segment, base) in self.segments.iter_mut().enumerate() {
            let base = *base.get_mut();
            if !base.is_null() {
                let layout = Layout::array::<AtomicU32>(locate(start(segment)).2).unwrap();
                // SAFETY: &mut self: no reader remains; allocated with layout.
                unsafe { dealloc(base.cast(), layout) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn locate_tiles_every_fd_once_in_doubling_segments() {
        let mut expected = 0;
        for segment in 0..SEGMENTS {
            let (k, offset, len) = locate(start(segment));
            assert_eq!((k, offset, start(segment)), (segment, 0, expected));
            let last = start(segment) + len - 1;
            assert_eq!(locate(last), (segment, len - 1, len));
            expected = last + 1;
            // Capacity after this segment doubles, as expand_files' does.
            assert_eq!(expected, BASE << segment);
        }
        assert!(expected > i32::MAX as usize);
        assert_eq!(locate(i32::MAX as usize).0, SEGMENTS - 1);
    }

    #[test]
    fn fds_above_512_are_claimed_and_released_by_number() {
        let table = FdTable::new();
        for fd in [0, 63, 64, 511, 512, 513, 4095, 65_536, 1 << 20] {
            assert!(!table.contains(fd));
            assert_eq!(table.reserve_within(fd, rlim_t::MAX), Ok(fd as usize));
            assert!(table.contains(fd));
            assert!(!table.contains(fd + 1));
        }
        // A replaced claim and its replacement overlap on one number.
        table.reserve_within(513, rlim_t::MAX).unwrap();
        table.release(513);
        assert!(table.contains(513));
        assert_eq!(table.find_below(4096, Some), Some(0));
        assert_eq!(
            table.find_below(4096, |fd| (fd > 512).then_some(fd)),
            Some(513)
        );
        assert_eq!(table.find_below(4095, |fd| (fd > 513).then_some(fd)), None);
        for fd in [0, 63, 64, 511, 512, 513, 4095, 65_536, 1 << 20] {
            table.release(fd as usize);
            assert!(!table.contains(fd));
        }
        assert!(!table.any());
        assert_eq!(table.find_below(i32::MAX, Some), None);
        assert!(!table.contains(-1));
        assert_eq!(table.reserve_within(-1, rlim_t::MAX), Err(EBADF));
    }

    #[test]
    fn growth_stops_at_the_descriptor_limit() {
        let table = FdTable::new();
        // As alloc_fd: an fd at or above RLIMIT_NOFILE is EMFILE.
        assert_eq!(table.reserve_within(1000, 1000), Err(EMFILE));
        assert!(!table.contains(1000));
        assert_eq!(table.reserve_within(999, 1000), Ok(999));
        // The segment holding 999 also covers 1000..1023: once grown, a
        // later lowered limit does not take capacity back (nor does Linux's).
        assert_eq!(table.reserve_within(1000, 1000), Ok(1000));
        assert_eq!(table.reserve_within(1024, 1000), Err(EMFILE));
        // The process's own limit governs the public path.
        let fresh = FdTable::new();
        let limit = nofile_limit().unwrap();
        if limit < i32::MAX as rlim_t {
            assert_eq!(fresh.reserve(limit as i32), Err(EMFILE));
            assert!(!fresh.contains(limit as i32));
        }
        assert_eq!(fresh.reserve(1), Ok(1));
    }

    #[test]
    fn concurrent_growth_publishes_each_segment_once() {
        const THREADS: usize = 8;
        const TOP: i32 = 1 << 17;
        let table = Arc::new(FdTable::new());
        let start = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|t| {
                let table = table.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    // Every thread races to create every segment, high first.
                    let mine: Vec<i32> = (0..TOP)
                        .rev()
                        .filter(|fd| *fd as usize % THREADS == t)
                        .collect();
                    for &fd in &mine {
                        table.reserve_within(fd, rlim_t::MAX).unwrap();
                        assert!(table.contains(fd));
                    }
                    for &fd in &mine {
                        table.release(fd as usize);
                    }
                    mine.len()
                })
            })
            .collect();
        let total: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
        assert_eq!(total, TOP as usize);
        assert!(!table.any());
        assert!((0..TOP).all(|fd| !table.contains(fd)));
        // Each segment is published once and stays where readers found it.
        let first: Vec<_> = table
            .segments
            .iter()
            .map(|s| s.load(Ordering::Acquire))
            .collect();
        table.reserve_within(TOP - 1, rlim_t::MAX).unwrap();
        let again: Vec<_> = table
            .segments
            .iter()
            .map(|s| s.load(Ordering::Acquire))
            .collect();
        assert_eq!(first, again);
        let segments = locate(TOP as usize - 1).0 + 1;
        assert!(first[..segments].iter().all(|p| !p.is_null()));
        assert!(first[segments..].iter().all(|p| p.is_null()));
    }

    #[test]
    fn readers_see_claims_while_others_grow() {
        let table = Arc::new(FdTable::new());
        table.reserve_within(7, rlim_t::MAX).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Growth starts only once every reader is reading, so they overlap.
        let reading = Arc::new(Barrier::new(4));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let table = table.clone();
                let stop = stop.clone();
                let reading = reading.clone();
                std::thread::spawn(move || {
                    let mut reads = 0u64;
                    loop {
                        assert!(table.contains(7));
                        assert!(!table.contains(8));
                        reads += 1;
                        if reads == 1 {
                            reading.wait();
                        }
                        if stop.load(Ordering::Acquire) {
                            return reads;
                        }
                    }
                })
            })
            .collect();
        reading.wait();
        for fd in (64..1 << 20).step_by(4093) {
            table.reserve_within(fd, rlim_t::MAX).unwrap();
            assert!(table.contains(fd));
        }
        stop.store(true, Ordering::Release);
        for reader in readers {
            assert!(reader.join().unwrap() > 0);
        }
    }

    // Lookup cost does not depend on the fd number or the table size: the
    // best of many timed batches stays within a small factor between fd 3 in
    // a one-segment table and fd 2^20 in a 21-segment table.
    #[test]
    fn lookup_cost_is_independent_of_fd_and_table_size() {
        let small = FdTable::new();
        small.reserve_within(3, rlim_t::MAX).unwrap();
        let large = FdTable::new();
        for fd in (0..=1 << 20).step_by(64) {
            large.reserve_within(fd, rlim_t::MAX).unwrap();
        }
        let best = |table: &FdTable, fd: i32| {
            (0..30)
                .map(|_| {
                    let t = std::time::Instant::now();
                    for _ in 0..20_000 {
                        assert!(table.contains(std::hint::black_box(fd)));
                    }
                    t.elapsed()
                })
                .min()
                .unwrap()
        };
        let low = best(&small, 3);
        let high = best(&large, 1 << 20);
        assert!(
            high < low * 4 && low < high * 4,
            "fd 3: {low:?}, fd 2^20: {high:?}"
        );
    }
}
