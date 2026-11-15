// The owner's timer wheel, after Linux's kernel/time/timer.c (4.8 and
// later): levels of `slots` buckets each, level n eight times coarser than
// level n-1 (LVL_CLK_SHIFT 3), no cascading. A timer is filed once, in the
// level its remaining time selects, at that level's granularity rounded up,
// so it is never early and at most one granule of its level late: under
// 8/(slots-1) of the time it had left when it was filed. The next expiry is
// the earliest occupied bucket, kept from the occupancy bitmaps, not a
// minimum over the timers.
//
// Timers are intrusive: each owner of a timer keeps a `TimerLink` in its own
// storage and reaches it through `TimerLinks`, so the wheel holds only the
// bucket heads (fixed by its geometry) and nothing per timer.
//
// Re-arming is lazy, as Linux's __mod_timer and icsk_pending are: a timer
// moved later stays in its bucket, and when that bucket expires its owner
// finds the exact deadline still ahead and files it again, once. The wheel's
// next expiry is therefore never later than any armed timer's bucket, and
// may be earlier than every exact deadline by one such postponed timer.
//
// Time is the caller's: nothing here reads a clock. Every instant is the
// `now` the caller passes, in its caller units.
// Nothing files timers in the wheel yet: TIME-WAIT records move to it next.
#![allow(dead_code)]

use alloc::vec::Vec;
use core::cell::Cell;

pub(crate) const NONE: u32 = u32::MAX;
// Linux's LVL_CLK_SHIFT: each level's granule is eight of the one below.
const LEVEL_SHIFT: u32 = 3;

/// The geometry of an owner's timer wheel (`EndpointConfig::timer_wheel`).
/// Every preset has a level 0 of one microsecond, fine enough to pace
/// packets and to wake for the next timestamp tick; they differ in how
/// precisely the coarser levels keep longer timers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TimerWheel {
    /// 256 buckets per level, 12 levels: a timer is late by under 3.2% of
    /// the time it had left (a 40 ms delayed ACK by under 0.52 ms, a 200 ms
    /// RTO by under 4.1 ms), covering 25.4 days.
    Datacenter,
    /// Linux's geometry, 64 buckets per level, 13 levels: late by under
    /// 12.7% (a 200 ms RTO by under 4.1 ms, a 40 ms delayed ACK by under
    /// 4.1 ms), covering 50.1 days, in a quarter of the memory.
    #[default]
    Internet,
    /// `tick_ns` rounded up to a power of two of caller units, `slots` a
    /// power of two from 64 to 4096, `levels` from 1 to 16.
    Custom {
        tick_ns: u64,
        slots: u16,
        levels: u8,
    },
}

/// A resolved `TimerWheel`, in caller units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerWheelGeometry {
    /// Level 0's granule, a power of two of caller units.
    pub tick: u64,
    pub slots: u16,
    pub levels: u8,
    /// The longest delay a timer can be filed for: (slots - 1) times the
    /// last level's granule.
    pub coverage: u64,
}

impl TimerWheel {
    /// The geometry in a timebase of `units_per_second` caller units.
    /// InvalidArgument for a custom geometry out of range.
    pub fn geometry(self, units_per_second: u64) -> Result<TimerWheelGeometry, crate::Error> {
        let (tick_ns, slots, levels) = match self {
            Self::Datacenter => (1_000, 256, 12),
            Self::Internet => (1_000, 64, 13),
            Self::Custom {
                tick_ns,
                slots,
                levels,
            } => (tick_ns, slots, levels),
        };
        if tick_ns == 0
            || !slots.is_power_of_two()
            || !(64..=4096).contains(&slots)
            || !(1..=16).contains(&levels)
            || !matches!(units_per_second, 1_000_000 | 1_000_000_000)
        {
            return Err(crate::Error::InvalidArgument);
        }
        let units = (u128::from(tick_ns) * u128::from(units_per_second)).div_ceil(1_000_000_000);
        let tick = u64::try_from(units)
            .ok()
            .and_then(u64::checked_next_power_of_two)
            .ok_or(crate::Error::InvalidArgument)?;
        let span = u128::from(slots - 1) << (LEVEL_SHIFT * u32::from(levels - 1));
        Ok(TimerWheelGeometry {
            tick,
            slots,
            levels,
            coverage: u64::try_from(span * u128::from(tick)).unwrap_or(u64::MAX),
        })
    }
}

impl TimerWheelGeometry {
    /// The most a timer filed `delay` caller units ahead can be late: the
    /// granule of the level its delay selects (strictly less than this).
    pub fn lateness_bound(&self, delay: u64) -> u64 {
        let delay = delay.div_ceil(self.tick);
        let level = level_of(delay, u64::from(self.slots), u32::from(self.levels));
        sat_shl(self.tick, LEVEL_SHIFT * level)
    }
}

// The level for `delta` ticks ahead: level n holds deltas from
// (slots - 1) << 3(n - 1) up to (slots - 1) << 3n (Linux's LVL_START).
fn level_of(delta: u64, slots: u64, levels: u32) -> u32 {
    if delta < slots - 1 {
        return 0;
    }
    ((63 - (delta / (slots - 1)).leading_zeros()) / LEVEL_SHIFT + 1).min(levels - 1)
}

fn sat_shl(value: u64, shift: u32) -> u64 {
    if shift >= 64 || value > u64::MAX >> shift {
        u64::MAX
    } else {
        value << shift
    }
}

/// A timer's place in the wheel, kept by whoever owns the timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimerLink {
    previous: u32,
    next: u32,
    bucket: u32,
}

impl TimerLink {
    pub(crate) const UNLINKED: Self = Self {
        previous: NONE,
        next: NONE,
        bucket: NONE,
    };

    pub(crate) fn linked(&self) -> bool {
        self.bucket != NONE
    }
}

/// The storage of the timers a wheel files: the link of timer `id`.
pub(crate) trait TimerLinks {
    fn timer(&mut self, id: u32) -> &mut TimerLink;
}

pub(crate) struct Wheel {
    geometry: TimerWheelGeometry,
    tick_shift: u32,
    slot_bits: u32,
    levels: u32,
    // Every bucket expiring at or before this tick has run.
    clk: u64,
    // The first timer of each bucket, level by level, then the due list:
    // timers filed at or before `clk`, due at the next run.
    heads: Vec<u32>,
    // One bit per bucket: whether it holds a timer.
    occupied: Vec<u64>,
    // The earliest exact deadline filed in the due list since it was last
    // empty (caller units).
    due_min: u64,
    // The earliest occupied bucket's expiry tick and the bucket (Linux's
    // next_expiry), found again from the bitmaps when `stale`.
    next: Cell<u64>,
    next_bucket: Cell<u32>,
    stale: Cell<bool>,
}

impl Wheel {
    pub(crate) fn new(geometry: TimerWheelGeometry) -> Result<Self, ()> {
        let slot_bits = geometry.slots.trailing_zeros();
        let levels = u32::from(geometry.levels);
        let buckets = ((levels as usize) << slot_bits) + 1;
        let mut heads = Vec::new();
        heads.try_reserve_exact(buckets).map_err(|_| ())?;
        heads.resize(buckets, NONE);
        let mut occupied = Vec::new();
        let words = (levels as usize) << (slot_bits - 6);
        occupied.try_reserve_exact(words).map_err(|_| ())?;
        occupied.resize(words, 0);
        Ok(Self {
            geometry,
            tick_shift: geometry.tick.trailing_zeros(),
            slot_bits,
            levels,
            clk: 0,
            heads,
            occupied,
            due_min: u64::MAX,
            next: Cell::new(u64::MAX),
            next_bucket: Cell::new(NONE),
            stale: Cell::new(false),
        })
    }

    pub(crate) fn geometry(&self) -> TimerWheelGeometry {
        self.geometry
    }

    /// The table's heap bytes, fixed by the geometry.
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.heads.capacity() * 4 + self.occupied.capacity() * 8
    }

    fn mask(&self) -> u64 {
        (1 << self.slot_bits) - 1
    }

    fn due_list(&self) -> u32 {
        self.levels << self.slot_bits
    }

    // The tick a deadline is due at, rounded up: never before it.
    fn ticks(&self, deadline: u64) -> u64 {
        (deadline >> self.tick_shift) + u64::from(deadline & ((1 << self.tick_shift) - 1) != 0)
    }

    // The bucket a deadline is filed in now, and its expiry tick.
    fn place(&self, deadline: u64) -> (u32, u64) {
        let t = self.ticks(deadline);
        if t <= self.clk {
            return (self.due_list(), self.clk);
        }
        let level = level_of(t - self.clk, 1 << self.slot_bits, self.levels);
        let shift = LEVEL_SHIFT * level;
        let c = self.clk >> shift;
        // Beyond the last level only its farthest bucket, a lower bound
        // filed again when it expires; configuration keeps every timer of
        // the endpoint within reach.
        let position = (t >> shift)
            .saturating_add(u64::from(t & ((1 << shift) - 1) != 0))
            .min(c.saturating_add(1 << self.slot_bits));
        (
            (level << self.slot_bits) | (position & self.mask()) as u32,
            sat_shl(position, shift),
        )
    }

    // The expiry tick of a level bucket: the next time after `clk` that its
    // level reaches its position.
    fn bucket_expiry(&self, bucket: u32) -> u64 {
        let level = bucket >> self.slot_bits;
        let position = u64::from(bucket) & self.mask();
        let shift = LEVEL_SHIFT * level;
        let c = self.clk >> shift;
        let ahead = position.wrapping_sub(c.wrapping_add(1)) & self.mask();
        sat_shl(c.saturating_add(1).saturating_add(ahead), shift)
    }

    // When the timer in `bucket` runs, in caller units.
    fn expiry_units(&self, bucket: u32) -> u64 {
        if bucket == self.due_list() {
            return sat_shl(self.clk, self.tick_shift);
        }
        sat_shl(self.bucket_expiry(bucket), self.tick_shift)
    }

    fn link(
        &mut self,
        links: &mut impl TimerLinks,
        id: u32,
        bucket: u32,
        deadline: u64,
        expiry: u64,
    ) {
        let head = core::mem::replace(&mut self.heads[bucket as usize], id);
        *links.timer(id) = TimerLink {
            previous: NONE,
            next: head,
            bucket,
        };
        if head != NONE {
            links.timer(head).previous = id;
        }
        if bucket == self.due_list() {
            self.due_min = self.due_min.min(deadline);
            return;
        }
        self.occupied[(bucket >> 6) as usize] |= 1 << (bucket & 63);
        if expiry < self.next.get() {
            self.next.set(expiry);
            self.next_bucket.set(bucket);
            self.stale.set(false);
        }
    }

    fn unlink(&mut self, links: &mut impl TimerLinks, id: u32) {
        let link = core::mem::replace(links.timer(id), TimerLink::UNLINKED);
        if link.previous == NONE {
            self.heads[link.bucket as usize] = link.next;
        } else {
            links.timer(link.previous).next = link.next;
        }
        if link.next != NONE {
            links.timer(link.next).previous = link.previous;
        }
        if self.heads[link.bucket as usize] != NONE {
            return;
        }
        if link.bucket == self.due_list() {
            self.due_min = u64::MAX;
            return;
        }
        self.occupied[(link.bucket >> 6) as usize] &= !(1 << (link.bucket & 63));
        if link.bucket == self.next_bucket.get() {
            self.stale.set(true);
        }
    }

    /// Arm timer `id` for `deadline`. A timer already filed to run at or
    /// before it stays where it is (Linux's lazy re-arm): when its bucket
    /// expires its owner files it again. A timer moved earlier is filed now.
    pub(crate) fn arm(&mut self, links: &mut impl TimerLinks, id: u32, deadline: u64) {
        let bucket = links.timer(id).bucket;
        if bucket != NONE && self.expiry_units(bucket) <= deadline {
            if bucket == self.due_list() {
                self.due_min = self.due_min.min(deadline);
            }
            return;
        }
        let (to, expiry) = self.place(deadline);
        if bucket == to {
            return;
        }
        if bucket != NONE {
            self.unlink(links, id);
        }
        self.link(links, id, to, deadline, expiry);
    }

    /// Take timer `id` out of the wheel, if it is in it: the owner's
    /// storage of the timer is about to go.
    pub(crate) fn cancel(&mut self, links: &mut impl TimerLinks, id: u32) {
        if links.timer(id).linked() {
            self.unlink(links, id);
        }
    }

    // The earliest occupied bucket of `level`: its expiry tick and index.
    fn earliest(&self, level: u32) -> Option<(u64, u32)> {
        let words = 1usize << (self.slot_bits - 6);
        let base = level as usize * words;
        let shift = LEVEL_SHIFT * level;
        let c = self.clk >> shift;
        let start = (c.wrapping_add(1) & self.mask()) as usize;
        let (first, bit) = (start / 64, start % 64);
        for i in 0..=words {
            let word = (first + i) % words;
            let mut bits = self.occupied[base + word];
            if i == 0 {
                bits &= !0 << bit;
            } else if i == words {
                bits &= (1u64 << bit).wrapping_sub(1);
            }
            if bits != 0 {
                let position = (word * 64 + bits.trailing_zeros() as usize) as u64;
                let ahead = position.wrapping_sub(start as u64) & self.mask();
                let expiry = sat_shl(c.saturating_add(1).saturating_add(ahead), shift);
                return Some((expiry, (level << self.slot_bits) | position as u32));
            }
        }
        None
    }

    // The earliest occupied bucket: its expiry tick and index.
    fn first_bucket(&self) -> Option<(u64, u32)> {
        if self.stale.get() {
            let found = (0..self.levels)
                .filter_map(|level| self.earliest(level))
                .min_by_key(|&(expiry, _)| expiry);
            let (expiry, bucket) = found.unwrap_or((u64::MAX, NONE));
            self.next.set(expiry);
            self.next_bucket.set(bucket);
            self.stale.set(false);
        }
        (self.next_bucket.get() != NONE).then(|| (self.next.get(), self.next_bucket.get()))
    }

    /// When the wheel's owner must next run: the due list's earliest
    /// deadline, else the earliest bucket's expiry, in caller units. Never
    /// after an armed timer's bucket; earlier than every exact deadline only
    /// by a timer re-armed later and not yet filed again.
    pub(crate) fn next_expiry(&self) -> Option<u64> {
        if self.heads[self.due_list() as usize] != NONE {
            return Some(self.due_min);
        }
        self.first_bucket()
            .map(|(expiry, _)| sat_shl(expiry, self.tick_shift))
    }

    /// A timer to run at `now`: the first of the due list, else the first of
    /// the earliest bucket expired by `now`, with the bucket's expiry in
    /// caller units. It stays filed: its owner either ends it (`cancel`) or,
    /// its exact deadline still ahead, files it again (`arm`), which lands
    /// after `now`, so a run files each timer again at most once.
    pub(crate) fn due(&mut self, now: u64) -> Option<(u32, u64)> {
        let due = self.heads[self.due_list() as usize];
        if due != NONE {
            return Some((due, self.due_min));
        }
        let (expiry, bucket) = self.first_bucket()?;
        if sat_shl(expiry, self.tick_shift) > now {
            return None;
        }
        // Every earlier bucket is empty: time moves to this one, so a timer
        // filed again is placed against it.
        self.clk = self.clk.max(expiry - 1);
        Some((
            self.heads[bucket as usize],
            sat_shl(expiry, self.tick_shift),
        ))
    }

    /// Nothing more is due at `now` (`due` returned None): every bucket up
    /// to it has run, and timers filed from now on are placed against it.
    pub(crate) fn finish(&mut self, now: u64) {
        debug_assert!(self.heads[self.due_list() as usize] == NONE);
        debug_assert!(
            self.first_bucket()
                .is_none_or(|(expiry, _)| sat_shl(expiry, self.tick_shift) > now)
        );
        self.clk = self.clk.max(now >> self.tick_shift);
    }

    /// Move time to `now` while no bucket is due by then (Linux's
    /// forward_timer_base), so timers armed now are placed against it.
    pub(crate) fn forward(&mut self, now: u64) {
        let t = now >> self.tick_shift;
        if t > self.clk
            && self.heads[self.due_list() as usize] == NONE
            && self.first_bucket().is_none_or(|(expiry, _)| expiry > t)
        {
            self.clk = t;
        }
    }

    /// When the bucket of timer `id` runs (caller units), if it is filed.
    pub(crate) fn filed(&self, link: &TimerLink) -> Option<u64> {
        link.linked().then(|| self.expiry_units(link.bucket))
    }

    /// The tick time stands at, every bucket up to it having run.
    #[cfg(test)]
    pub(crate) fn clock(&self) -> u64 {
        sat_shl(self.clk, self.tick_shift)
    }

    // Every bucket's chain links both ways, holds only timers filed in it,
    // and its occupancy bit says so; `ids` are every filed timer; the cached
    // next expiry is the earliest bucket's.
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn check(&self, links: &mut impl TimerLinks, ids: impl Iterator<Item = u32>) {
        let mut chained = 0usize;
        for (bucket, &head) in self.heads.iter().enumerate() {
            let mut previous = NONE;
            let mut id = head;
            while id != NONE {
                let link = *links.timer(id);
                assert_eq!(link.bucket as usize, bucket);
                assert_eq!(link.previous, previous);
                previous = id;
                id = link.next;
                chained += 1;
            }
            if bucket < self.due_list() as usize {
                let bit = self.occupied[bucket >> 6] >> (bucket & 63) & 1;
                assert_eq!(bit == 1, head != NONE, "bucket {bucket}");
            }
        }
        let mut filed = 0usize;
        for id in ids {
            assert!(links.timer(id).linked(), "timer {id} lost");
            filed += 1;
        }
        assert_eq!(chained, filed);
        let earliest = (0..self.levels)
            .filter_map(|level| self.earliest(level))
            .map(|(expiry, _)| expiry)
            .min();
        assert_eq!(self.first_bucket().map(|(expiry, _)| expiry), earliest);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{collections::BTreeMap, vec, vec::Vec};

    struct Links(Vec<TimerLink>);
    impl TimerLinks for Links {
        fn timer(&mut self, id: u32) -> &mut TimerLink {
            &mut self.0[id as usize]
        }
    }

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x % n.max(1)
        }
    }

    fn geometries() -> [TimerWheelGeometry; 4] {
        [
            TimerWheel::Datacenter.geometry(1_000_000).unwrap(),
            TimerWheel::Internet.geometry(1_000_000).unwrap(),
            TimerWheel::Internet.geometry(1_000_000_000).unwrap(),
            TimerWheel::Custom {
                tick_ns: 4_000,
                slots: 128,
                levels: 4,
            }
            .geometry(1_000_000)
            .unwrap(),
        ]
    }

    #[test]
    fn presets_resolve_to_the_documented_geometry() {
        let dc = TimerWheel::Datacenter.geometry(1_000_000).unwrap();
        assert_eq!((dc.tick, dc.slots, dc.levels), (1, 256, 12));
        assert_eq!(dc.coverage, 255 << 33);
        let int = TimerWheel::Internet.geometry(1_000_000).unwrap();
        assert_eq!((int.tick, int.slots, int.levels), (1, 64, 13));
        assert_eq!(int.coverage, 63 << 36);
        // A microsecond in nanoseconds rounds up to 1024.
        let ns = TimerWheel::Internet.geometry(1_000_000_000).unwrap();
        assert_eq!((ns.tick, ns.coverage), (1024, (63 << 36) * 1024));
        // Both cover Linux's longest TCP_USER_TIMEOUT, INT_MAX ms.
        for g in [dc, int] {
            assert!(g.coverage >= i32::MAX as u64 * 1_000);
        }
        // A 40 ms delayed ACK, a 200 ms RTO.
        assert_eq!(dc.lateness_bound(40_000), 512);
        assert_eq!(int.lateness_bound(40_000), 4_096);
        assert_eq!(dc.lateness_bound(200_000), 4_096);
        assert_eq!(int.lateness_bound(200_000), 4_096);
        for (tick_ns, slots, levels) in [
            (0, 64, 4),
            (1000, 32, 4),
            (1000, 96, 4),
            (1000, 64, 0),
            (1000, 64, 17),
            (1000, 8192, 4),
        ] {
            assert!(
                TimerWheel::Custom {
                    tick_ns,
                    slots,
                    levels
                }
                .geometry(1_000_000)
                .is_err()
            );
        }
    }

    // A timer at the boundary of each level is filed in it, at most one of
    // its granules late and never early.
    #[test]
    fn each_level_keeps_its_bound() {
        for g in geometries() {
            let mut wheel = Wheel::new(g).unwrap();
            let mut links = Links(vec![TimerLink::UNLINKED; 1]);
            let now = 12_345 * g.tick;
            wheel.forward(now);
            for level in 0..u32::from(g.levels) {
                let start = if level == 0 {
                    1
                } else {
                    u64::from(g.slots - 1) << (3 * (level - 1))
                };
                let end = (u64::from(g.slots - 1) << (3 * level)) - 1;
                for delay in [start, start + 1, (start + end) / 2, end] {
                    for offset in [0, 1, g.tick - 1] {
                        let deadline = now + delay * g.tick - offset.min(delay * g.tick - 1);
                        wheel.arm(&mut links, 0, deadline);
                        let filed = wheel.filed(&links.0[0]).unwrap();
                        let bound = g.lateness_bound(deadline - now);
                        assert!(filed >= deadline, "{g:?} {level} {delay}");
                        assert!(filed - deadline < bound, "{g:?} {level} {delay} {filed}");
                        assert!(bound <= sat_shl(g.tick, 3 * level));
                        wheel.cancel(&mut links, 0);
                    }
                }
            }
        }
    }

    // Randomized arms (earlier, later, unchanged), cancels and runs, on
    // time or late, against an oracle of exact deadlines: every timer runs
    // once, never before its deadline, and its bucket expires within its
    // level's bound of the deadline it was filed for; a run files a timer
    // again at most once; nothing is lost.
    #[test]
    fn randomized_against_an_oracle() {
        for g in geometries() {
            for seed in 1..=24u64 {
                let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
                let ids = 64 + 64 * (seed % 3) as usize;
                let mut wheel = Wheel::new(g).unwrap();
                let mut links = Links(vec![TimerLink::UNLINKED; ids]);
                // id -> (exact deadline, deadline it was filed for, time filed)
                let mut armed: BTreeMap<u32, (u64, u64, u64)> = BTreeMap::new();
                let mut now = rng.below(1 << 40);
                wheel.forward(now);
                let span =
                    [g.tick * 60, g.tick * 3000, g.tick << 20, g.coverage / 4][seed as usize % 4];
                let mut fired = 0u64;
                for _ in 0..3000 {
                    for _ in 0..rng.below(4) {
                        let id = rng.below(ids as u64) as u32;
                        match rng.below(8) {
                            0 => {
                                wheel.cancel(&mut links, id);
                                armed.remove(&id);
                            }
                            roll => {
                                let deadline = match (roll, armed.get(&id)) {
                                    (1, Some(&(exact, ..))) => exact,
                                    (2, Some(&(exact, ..))) => exact + rng.below(span),
                                    _ => now + 1 + rng.below(span),
                                };
                                let before = wheel.filed(&links.0[id as usize]);
                                wheel.arm(&mut links, id, deadline);
                                let after = wheel.filed(&links.0[id as usize]).unwrap();
                                // Kept where it is: still the deadline and
                                // the time it was filed for.
                                let kept = before.is_some_and(|b| b <= deadline);
                                let (filed, since) = match before {
                                    Some(b) if b <= deadline => {
                                        assert_eq!(after, b);
                                        let a = armed[&id];
                                        (a.1, a.2)
                                    }
                                    _ => {
                                        // Beyond reach it waits in the last
                                        // bucket, a lower bound.
                                        if deadline.saturating_sub(wheel.clock()) + g.tick
                                            <= g.coverage
                                        {
                                            assert!(after >= deadline);
                                        }
                                        (deadline, wheel.clock())
                                    }
                                };
                                assert!(!kept || after <= deadline);
                                armed.insert(id, (deadline, filed, since));
                            }
                        }
                    }
                    wheel.check(&mut links, armed.keys().copied());
                    // On time at the wheel's next expiry, or late. The
                    // wake is never after any timer's bucket.
                    let wake = wheel.next_expiry();
                    let earliest = armed
                        .keys()
                        .map(|&id| wheel.filed(&links.0[id as usize]).unwrap())
                        .min();
                    assert_eq!(wake.is_some(), earliest.is_some());
                    if let (Some(wake), Some(earliest)) = (wake, earliest) {
                        assert!(wake <= earliest);
                    }
                    let target = match (wake, rng.below(10)) {
                        (Some(w), 0..=6) => w.max(now),
                        (_, 7) => now + rng.below(span * 4),
                        _ => now + rng.below(g.tick * 8),
                    };
                    now = target;
                    let mut refiled = Vec::new();
                    while let Some((id, expiry)) = wheel.due(now) {
                        let (exact, filed, since) = armed[&id];
                        if exact > now {
                            // Filed again in reach, it runs after `now`, so
                            // once per run. Only a drive later than the
                            // wheel's reach brings a lower bound back.
                            assert!(!refiled.contains(&id), "filed twice in one run");
                            let clock = wheel.clock();
                            wheel.cancel(&mut links, id);
                            wheel.arm(&mut links, id, exact);
                            if wheel.filed(&links.0[id as usize]).unwrap() > now {
                                refiled.push(id);
                            } else {
                                assert!(exact - clock + g.tick > g.coverage);
                            }
                            armed.insert(id, (exact, exact, clock));
                            continue;
                        }
                        // Never early, and within the bound of its level
                        // (in reach: its tick within coverage of the clock;
                        // a deadline already due went to the due list, one
                        // beyond reach to the last bucket, a lower bound).
                        assert!(now >= exact);
                        if filed > since && filed - since + g.tick <= g.coverage {
                            assert!(expiry >= filed, "{g:?} early bucket");
                            assert!(
                                expiry - filed < g.lateness_bound(filed - since),
                                "{g:?} seed {seed}: {expiry} {filed} {since}"
                            );
                        }
                        wheel.cancel(&mut links, id);
                        armed.remove(&id);
                        fired += 1;
                    }
                    wheel.finish(now);
                }
                // Nothing is lost: running far enough ends every timer.
                while !armed.is_empty() {
                    now = wheel.next_expiry().unwrap().max(now);
                    while let Some((id, _)) = wheel.due(now) {
                        let exact = armed[&id].0;
                        wheel.cancel(&mut links, id);
                        if exact > now {
                            wheel.arm(&mut links, id, exact);
                        } else {
                            armed.remove(&id);
                        }
                    }
                    wheel.finish(now);
                }
                assert_eq!(wheel.next_expiry(), None);
                assert!(fired > 0);
            }
        }
    }

    // A deadline past the last level waits in its farthest bucket and is
    // filed again from there until it is in reach: never early.
    #[test]
    fn beyond_coverage_is_filed_again_never_early() {
        let g = TimerWheel::Custom {
            tick_ns: 1_000,
            slots: 64,
            levels: 2,
        }
        .geometry(1_000_000)
        .unwrap();
        let mut wheel = Wheel::new(g).unwrap();
        let mut links = Links(vec![TimerLink::UNLINKED; 1]);
        let deadline = g.coverage * 5 + 3;
        wheel.arm(&mut links, 0, deadline);
        let mut runs = 0;
        let now = loop {
            let now = wheel.next_expiry().unwrap();
            let (id, _) = wheel.due(now).unwrap();
            wheel.cancel(&mut links, id);
            runs += 1;
            if deadline <= now {
                break now;
            }
            wheel.arm(&mut links, id, deadline);
            assert!(wheel.due(now).is_none());
            wheel.finish(now);
        };
        assert!(now >= deadline && now - deadline < g.lateness_bound(g.coverage));
        // Five refilings at most a last-level span apart reach 5x coverage.
        assert!(runs >= 5);
    }

    // The end of the clock saturates: a deadline at u64::MAX runs at it.
    #[test]
    fn end_of_clock_deadlines_saturate() {
        for g in geometries() {
            let mut wheel = Wheel::new(g).unwrap();
            let mut links = Links(vec![TimerLink::UNLINKED; 2]);
            let now = u64::MAX - 1000;
            wheel.forward(now);
            wheel.arm(&mut links, 0, u64::MAX);
            wheel.arm(&mut links, 1, now + 500);
            assert!(wheel.next_expiry().is_some());
            let mut ran = 0;
            while let Some((id, _)) = wheel.due(u64::MAX) {
                wheel.cancel(&mut links, id);
                ran += 1;
            }
            assert_eq!(ran, 2);
        }
    }
}
