use super::Interval;
use alloc::vec::Vec;
use core::{
    mem::size_of,
    ops::{Index, IndexMut},
};

// Bound replacement of a partially populated block to 64 KiB. Full blocks
// stay in place across growth; descriptor overhead is below 0.04% per record.
const BLOCK: usize = 64 * 1024 / size_of::<Interval>();

// The live intervals occupy slots [head, head + len). Removing a prefix
// (cumulative ACK) only advances head; a push at the last slot first moves
// the live intervals back to slot 0, so with far fewer intervals than slots
// that copy is rare. Slots below the blocks' lengths are initialized; the
// rest are reserved but untouched.
#[derive(Debug)]
pub(super) struct Intervals {
    blocks: Blocks,
    head: usize,
    len: usize,
    // Leading untouched, contiguous, individually committed originals,
    // ordered by departure. Any edit to an interval retracts this bound.
    pub(super) originals: usize,
    capacity: usize,
    // The allocated bytes in `blocks`, which change only with growth:
    // the connection's charge reads it per packet.
    allocation: usize,
}

pub(crate) struct Growth {
    blocks: Blocks,
    capacity: usize,
}
// A small ledger needs just its interval allocation. Give it a block table
// when it outgrows one block, preserving initialized blocks across growth.
#[derive(Debug)]
enum Blocks {
    Single(Vec<Interval>),
    Multiple(Vec<Vec<Interval>>),
}

impl Blocks {
    fn table(&self) -> &[Vec<Interval>] {
        match self {
            Self::Single(block) => core::slice::from_ref(block),
            Self::Multiple(table) => table,
        }
    }

    fn table_mut(&mut self) -> &mut [Vec<Interval>] {
        match self {
            Self::Single(block) => core::slice::from_mut(block),
            Self::Multiple(table) => table,
        }
    }

    fn allocation(&self) -> usize {
        match self {
            Self::Single(block) => block.capacity() * size_of::<Interval>(),
            Self::Multiple(table) => {
                table.capacity() * size_of::<Vec<Interval>>()
                    + table
                        .iter()
                        .map(|b| b.capacity() * size_of::<Interval>())
                        .sum::<usize>()
            }
        }
    }

    fn at(&self, slot: usize) -> &Interval {
        match self {
            Self::Single(block) => &block[slot],
            Self::Multiple(table) => &table[slot / BLOCK][slot % BLOCK],
        }
    }

    fn at_mut(&mut self, slot: usize) -> &mut Interval {
        match self {
            Self::Single(block) => &mut block[slot],
            Self::Multiple(table) => &mut table[slot / BLOCK][slot % BLOCK],
        }
    }
}

fn table_bytes(blocks: usize) -> Option<usize> {
    if blocks <= 1 {
        Some(0)
    } else {
        blocks.checked_mul(size_of::<Vec<Interval>>())
    }
}

impl Growth {
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.blocks.allocation()
    }
}
impl Intervals {
    pub(super) fn new(capacity: usize) -> Result<Self, ()> {
        let mut result = Self {
            blocks: Blocks::Single(Vec::new()),
            head: 0,
            len: 0,
            originals: 0,
            capacity: 0,
            allocation: 0,
        };
        let growth = result.prepare_growth(capacity)?;
        result.commit_growth(growth);
        Ok(result)
    }
    pub(super) fn storage_bytes(capacity: usize) -> Option<usize> {
        capacity
            .checked_mul(size_of::<Interval>())?
            .checked_add(table_bytes(capacity.div_ceil(BLOCK))?)
    }
    pub(super) fn allocation_bytes(&self) -> usize {
        debug_assert_eq!(self.allocation, self.blocks.allocation());
        self.allocation
    }
    pub(super) fn growth_bytes(&self, capacity: usize) -> Option<usize> {
        if capacity < self.capacity {
            return None;
        }
        let count = capacity.div_ceil(BLOCK);
        let mut bytes = table_bytes(count)?;
        for i in 0..count {
            let needed = (capacity - i * BLOCK).min(BLOCK);
            if self
                .blocks
                .table()
                .get(i)
                .is_some_and(|b| b.capacity() >= needed)
            {
                continue;
            }
            bytes = bytes.checked_add(needed.checked_mul(size_of::<Interval>())?)?;
        }
        Some(bytes)
    }
    pub(super) fn prepare_growth(&self, capacity: usize) -> Result<Growth, ()> {
        if capacity < self.capacity {
            return Err(());
        }
        let count = capacity.div_ceil(BLOCK);
        let grow = |i: usize| -> Result<Vec<Interval>, ()> {
            let needed = (capacity - i * BLOCK).min(BLOCK);
            let mut block = Vec::new();
            if self
                .blocks
                .table()
                .get(i)
                .is_none_or(|b| b.capacity() < needed)
            {
                block.try_reserve_exact(needed).map_err(|_| ())?;
                if let Some(old) = self.blocks.table().get(i) {
                    block.extend_from_slice(old);
                }
            }
            Ok(block)
        };
        let blocks = if count <= 1 {
            Blocks::Single(grow(0)?)
        } else {
            let mut table = Vec::new();
            table.try_reserve_exact(count).map_err(|_| ())?;
            for i in 0..count {
                table.push(grow(i)?);
            }
            Blocks::Multiple(table)
        };
        Ok(Growth { blocks, capacity })
    }
    pub(super) fn commit_growth(&mut self, mut growth: Growth) {
        for (old, new) in self
            .blocks
            .table_mut()
            .iter_mut()
            .zip(growth.blocks.table_mut())
        {
            if new.capacity() == 0 {
                core::mem::swap(old, new);
            }
        }
        self.blocks = growth.blocks;
        self.capacity = growth.capacity;
        self.allocation = self.blocks.allocation();
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[cfg(test)]
    pub(super) fn as_ptr(&self) -> *const Interval {
        self.blocks
            .table()
            .first()
            .map_or(core::ptr::null(), |b| b.as_ptr())
    }
    pub(super) fn iter(&self) -> impl DoubleEndedIterator<Item = &Interval> {
        self.range(0, self.len)
    }
    pub(super) fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut Interval> {
        self.range_mut(0, self.len)
    }
    pub(super) fn range(
        &self,
        start: usize,
        end: usize,
    ) -> impl DoubleEndedIterator<Item = &Interval> {
        assert!(start <= end && end <= self.len);
        Range {
            blocks: self.blocks.table(),
            front: self.head + start,
            back: self.head + end,
        }
    }
    pub(super) fn range_mut(
        &mut self,
        start: usize,
        end: usize,
    ) -> impl DoubleEndedIterator<Item = &mut Interval> {
        assert!(start <= end && end <= self.len);
        if start != end {
            self.originals = self.originals.min(start);
        }
        let (start, end) = (self.head + start, self.head + end);
        let first = start / BLOCK;
        self.blocks.table_mut()[first..end.div_ceil(BLOCK)]
            .iter_mut()
            .enumerate()
            .flat_map(move |(i, b)| {
                let offset = (first + i) * BLOCK;
                let last = end.saturating_sub(offset).min(b.len());
                b[start.saturating_sub(offset)..last].iter_mut()
            })
    }
    pub(super) fn first(&self) -> Option<&Interval> {
        (!self.is_empty()).then(|| &self[0])
    }
    pub(super) fn last(&self) -> Option<&Interval> {
        self.len.checked_sub(1).map(|i| &self[i])
    }
    fn slot(&self, slot: usize) -> Interval {
        *self.blocks.at(slot)
    }
    // Writing the first never-initialized slot extends its block.
    #[inline]
    fn set_slot(&mut self, slot: usize, value: Interval) {
        let (block, offset) = match &mut self.blocks {
            Blocks::Single(block) => (block, slot),
            Blocks::Multiple(table) => (&mut table[slot / BLOCK], slot % BLOCK),
        };
        if offset == block.len() {
            block.push(value);
        } else {
            block[offset] = value;
        }
    }
    #[inline(never)]
    fn compact(&mut self) {
        for i in 0..self.len {
            let value = self.slot(self.head + i);
            self.set_slot(i, value);
        }
        self.head = 0;
    }
    #[inline]
    pub(super) fn push(&mut self, value: Interval) {
        assert!(self.len < self.capacity);
        if self.head + self.len == self.capacity {
            self.compact();
        }
        self.set_slot(self.head + self.len, value);
        self.len += 1;
    }
    // Moves the shorter side: an edge near either end of the flight costs
    // only the intervals between it and that end.
    pub(super) fn insert(&mut self, index: usize, value: Interval) {
        assert!(index <= self.len && self.len < self.capacity);
        self.originals = self.originals.min(index);
        let room_after = self.head + self.len < self.capacity;
        if self.head > 0 && (index < self.len - index || !room_after) {
            for slot in self.head..self.head + index {
                let moved = self.slot(slot);
                self.set_slot(slot - 1, moved);
            }
            self.head -= 1;
        } else {
            if !room_after {
                self.compact();
            }
            for slot in (self.head + index..self.head + self.len).rev() {
                let moved = self.slot(slot);
                self.set_slot(slot + 1, moved);
            }
        }
        self.len += 1;
        self.set_slot(self.head + index, value);
    }
    pub(super) fn remove_prefix(&mut self, count: usize) {
        assert!(count <= self.len);
        self.originals = self.originals.saturating_sub(count);
        self.len -= count;
        self.head = if self.len == 0 { 0 } else { self.head + count };
    }
    pub(super) fn clear(&mut self) {
        self.originals = 0;
        self.head = 0;
        self.len = 0;
    }
    // Frees every slot of an empty ledger; growth allocates them again.
    pub(super) fn release(&mut self) {
        assert!(self.len == 0);
        self.blocks = Blocks::Single(Vec::new());
        self.head = 0;
        self.capacity = 0;
        self.allocation = 0;
    }
}
// The intervals in slots [front, back), one slot lookup each: most ranges
// hold an interval or two, for which a flattened walk over blocks costs
// more than the intervals.
struct Range<'a> {
    blocks: &'a [Vec<Interval>],
    front: usize,
    back: usize,
}
impl<'a> Iterator for Range<'a> {
    type Item = &'a Interval;
    fn next(&mut self) -> Option<&'a Interval> {
        if self.front == self.back {
            return None;
        }
        let slot = self.front;
        self.front += 1;
        Some(&self.blocks[slot / BLOCK][slot % BLOCK])
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.back - self.front;
        (len, Some(len))
    }
}
impl DoubleEndedIterator for Range<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(&self.blocks[self.back / BLOCK][self.back % BLOCK])
    }
}
impl Index<usize> for Intervals {
    type Output = Interval;
    fn index(&self, index: usize) -> &Interval {
        assert!(index < self.len);
        let slot = self.head + index;
        self.blocks.at(slot)
    }
}
impl IndexMut<usize> for Intervals {
    fn index_mut(&mut self, index: usize) -> &mut Interval {
        assert!(index < self.len);
        self.originals = self.originals.min(index);
        let slot = self.head + index;
        self.blocks.at_mut(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Interval, Ptb, Rack, Seq};
    use super::{BLOCK, Blocks, Intervals};

    fn dummy_interval(start: u32) -> Interval {
        let s = Seq(start);
        let e = Seq(start.wrapping_add(1));
        Interval {
            start: s,
            end: e,
            original_start: s,
            original_end: e,
            original_wire_start: s,
            original_wire_end: e,
            original_sent: 1,
            originally_in_window: true,
            successful_retries: 0,
            transmission_start: s,
            transmission_end: e,
            sent: 1,
            timestamp_eligible: true,
            retransmitted: false,
            departure_committed: true,
            original_retransmitted: false,
            delivered: false,
            stats_flags: 0,
            sacked: false,
            original_lost: false,
            needs_retransmit: false,
            loss_response_pending: false,
            ptb: Ptb::None,
        }
    }

    #[test]
    fn growth_from_one_full_block_keeps_live_intervals_and_charges_only_new_storage() {
        let mut rack = Rack::with_capacity(BLOCK).unwrap();
        let base = Seq(u32::MAX - 7);
        for i in 0..BLOCK as u32 {
            rack.transmit(base.wrapping_add(i), base.wrapping_add(i + 1), 10, false);
        }
        rack.trim_cumulative(base.wrapping_add(5));
        let first = rack.intervals.as_ptr();
        let prior_charge = rack.intervals.allocation_bytes();
        let capacity = BLOCK + 2;
        let growth = rack.prepare_growth(capacity).unwrap();
        let extra = growth.allocation_bytes();
        assert_eq!(rack.intervals.growth_bytes(capacity), Some(extra));
        crate::allocation_tests::fail_after(0, || {
            rack.commit_growth(growth, capacity);
            for i in BLOCK as u32..capacity as u32 {
                rack.transmit(base.wrapping_add(i), base.wrapping_add(i + 1), 11, false);
            }
        });
        assert_eq!(rack.intervals.as_ptr(), first);
        assert_eq!(rack.intervals.allocation_bytes(), prior_charge + extra);
        for (i, r) in (5..capacity as u32).zip(rack.intervals.iter()) {
            assert_eq!(
                (r.start, r.end),
                (base.wrapping_add(i), base.wrapping_add(i + 1))
            );
        }
        assert_eq!(rack.intervals.len(), capacity - 5);
    }

    #[test]
    fn single_to_multiple_release_and_regrow_match_storage_bytes() {
        let mut ivs = Intervals::new(4).unwrap();
        assert!(matches!(ivs.blocks, Blocks::Single(_)));
        assert_eq!(ivs.allocation_bytes(), Intervals::storage_bytes(4).unwrap());

        for i in 0..4u32 {
            ivs.push(dummy_interval(i));
        }

        // Grow within Single, then into Multiple across two blocks.
        for &cap in &[16, BLOCK, BLOCK + 5, 2 * BLOCK + 3] {
            let growth = ivs.prepare_growth(cap).unwrap();
            assert_eq!(ivs.growth_bytes(cap), Some(growth.allocation_bytes()));
            ivs.commit_growth(growth);
            assert_eq!(ivs.capacity(), cap);
            assert_eq!(
                ivs.allocation_bytes(),
                Intervals::storage_bytes(cap).unwrap()
            );
            if cap <= BLOCK {
                assert!(matches!(ivs.blocks, Blocks::Single(_)));
            } else {
                assert!(matches!(ivs.blocks, Blocks::Multiple(_)));
            }
            // Verify live intervals survived intact.
            assert_eq!(ivs.len(), 4);
            for i in 0..4u32 {
                assert_eq!(ivs[i as usize].start, Seq(i));
            }
        }

        // Fill past one block, trim prefix, then drain and release.
        for i in 4..(BLOCK + 5) as u32 {
            ivs.push(dummy_interval(i));
        }
        ivs.remove_prefix(10);
        assert_eq!(ivs[0].start, Seq(10));
        ivs.clear();
        ivs.release();
        assert_eq!(ivs.capacity(), 0);
        assert_eq!(ivs.allocation_bytes(), 0);
        assert_eq!(Intervals::storage_bytes(0), Some(0));
        assert!(matches!(ivs.blocks, Blocks::Single(_)));

        // Regrow to Single, then to Multiple, then release, then regrow directly to Multiple.
        for &cap in &[12, BLOCK + 4] {
            let growth = ivs.prepare_growth(cap).unwrap();
            assert_eq!(ivs.growth_bytes(cap), Some(growth.allocation_bytes()));
            ivs.commit_growth(growth);
            assert_eq!(
                ivs.allocation_bytes(),
                Intervals::storage_bytes(cap).unwrap()
            );
            if cap <= BLOCK {
                assert!(matches!(ivs.blocks, Blocks::Single(_)));
            } else {
                assert!(matches!(ivs.blocks, Blocks::Multiple(_)));
            }
        }

        ivs.release();
        assert_eq!(ivs.allocation_bytes(), 0);
        assert!(matches!(ivs.blocks, Blocks::Single(_)));

        let cap = 2 * BLOCK + 1;
        let growth = ivs.prepare_growth(cap).unwrap();
        assert_eq!(ivs.growth_bytes(cap), Some(growth.allocation_bytes()));
        ivs.commit_growth(growth);
        assert!(matches!(ivs.blocks, Blocks::Multiple(_)));
        assert_eq!(
            ivs.allocation_bytes(),
            Intervals::storage_bytes(cap).unwrap()
        );
    }

    #[test]
    fn originals_retracted_by_every_mutator() {
        for capacity in [16, BLOCK + 8] {
            let mut ivs = Intervals::new(capacity).unwrap();
            let count = if capacity > BLOCK { BLOCK + 4 } else { 8 };
            for i in 0..count as u32 {
                ivs.push(dummy_interval(i));
            }
            ivs.originals = count;

            // index_mut retracts originals to the mutated index (and never increases it).
            ivs[count - 2].sent = 2;
            assert_eq!(ivs.originals, count - 2);
            ivs[count - 1].sent = 3;
            assert_eq!(ivs.originals, count - 2);
            ivs[2].sent = 4;
            assert_eq!(ivs.originals, 2);

            // Empty range_mut leaves originals unchanged; non-empty retracts to start.
            ivs.originals = count;
            assert_eq!(ivs.range_mut(3, 3).count(), 0);
            assert_eq!(ivs.originals, count);
            for r in ivs.range_mut(4, 6) {
                r.sent = 5;
            }
            assert_eq!(ivs.originals, 4);
            for r in ivs.range_mut(1, 2) {
                r.sent = 6;
            }
            assert_eq!(ivs.originals, 1);

            // iter_mut retracts originals to 0.
            ivs.originals = count;
            for r in ivs.iter_mut() {
                r.sent = 7;
            }
            assert_eq!(ivs.originals, 0);

            // insert retracts originals to the insertion index.
            ivs.originals = count;
            ivs.insert(count - 3, dummy_interval(99_000));
            assert_eq!(ivs.originals, count - 3);
            ivs.insert(0, dummy_interval(99_001));
            assert_eq!(ivs.originals, 0);

            // remove_prefix subtracts count with saturation at 0.
            ivs.originals = 5;
            ivs.remove_prefix(2);
            assert_eq!(ivs.originals, 3);
            ivs.remove_prefix(5);
            assert_eq!(ivs.originals, 0);

            // clear resets originals to 0.
            ivs.originals = ivs.len();
            assert!(ivs.originals > 0);
            ivs.clear();
            assert_eq!(ivs.originals, 0);
        }
    }
}
