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
    blocks: Vec<Vec<Interval>>,
    head: usize,
    len: usize,
    capacity: usize,
    // blocks_allocation_bytes(&blocks), which changes only with growth:
    // the connection's charge reads it per packet.
    allocation: usize,
}

pub(crate) struct Growth {
    blocks: Vec<Vec<Interval>>,
    capacity: usize,
}
// Takes the Vec itself because its own capacity is part of the allocation.
fn blocks_allocation_bytes(blocks: &Vec<Vec<Interval>>) -> usize {
    blocks.capacity() * size_of::<Vec<Interval>>()
        + blocks
            .iter()
            .map(|b| b.capacity() * size_of::<Interval>())
            .sum::<usize>()
}
impl Growth {
    pub(crate) fn allocation_bytes(&self) -> usize {
        blocks_allocation_bytes(&self.blocks)
    }
}
impl Intervals {
    pub(super) fn new(capacity: usize) -> Result<Self, ()> {
        let mut result = Self {
            blocks: Vec::new(),
            head: 0,
            len: 0,
            capacity: 0,
            allocation: 0,
        };
        let growth = result.prepare_growth(capacity)?;
        result.commit_growth(growth);
        Ok(result)
    }
    pub(super) fn storage_bytes(capacity: usize) -> Option<usize> {
        capacity.checked_mul(size_of::<Interval>())?.checked_add(
            capacity
                .div_ceil(BLOCK)
                .checked_mul(size_of::<Vec<Interval>>())?,
        )
    }
    pub(super) fn allocation_bytes(&self) -> usize {
        debug_assert_eq!(self.allocation, blocks_allocation_bytes(&self.blocks));
        self.allocation
    }
    pub(super) fn growth_bytes(&self, capacity: usize) -> Option<usize> {
        if capacity < self.capacity {
            return None;
        }
        let count = capacity.div_ceil(BLOCK);
        let mut bytes = count.checked_mul(size_of::<Vec<Interval>>())?;
        for i in 0..count {
            let needed = (capacity - i * BLOCK).min(BLOCK);
            if self.blocks.get(i).is_some_and(|b| b.capacity() >= needed) {
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
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(count).map_err(|_| ())?;
        for i in 0..count {
            let needed = (capacity - i * BLOCK).min(BLOCK);
            let mut block = Vec::new();
            if self.blocks.get(i).is_none_or(|b| b.capacity() < needed) {
                block.try_reserve_exact(needed).map_err(|_| ())?;
                if let Some(old) = self.blocks.get(i) {
                    block.extend_from_slice(old);
                }
            }
            blocks.push(block);
        }
        Ok(Growth { blocks, capacity })
    }
    pub(super) fn commit_growth(&mut self, mut growth: Growth) {
        for (old, new) in self.blocks.iter_mut().zip(&mut growth.blocks) {
            if new.capacity() == 0 {
                core::mem::swap(old, new);
            }
        }
        self.blocks = growth.blocks;
        self.capacity = growth.capacity;
        self.allocation = blocks_allocation_bytes(&self.blocks);
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[cfg(test)]
    pub(super) fn as_ptr(&self) -> *const Interval {
        self.blocks
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
            blocks: &self.blocks,
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
        let (start, end) = (self.head + start, self.head + end);
        let first = start / BLOCK;
        self.blocks[first..end.div_ceil(BLOCK)]
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
        self.blocks[slot / BLOCK][slot % BLOCK]
    }
    // Writing the first never-initialized slot extends its block.
    fn set_slot(&mut self, slot: usize, value: Interval) {
        let block = &mut self.blocks[slot / BLOCK];
        if slot % BLOCK == block.len() {
            block.push(value);
        } else {
            block[slot % BLOCK] = value;
        }
    }
    fn compact(&mut self) {
        for i in 0..self.len {
            let value = self.slot(self.head + i);
            self.set_slot(i, value);
        }
        self.head = 0;
    }
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
        self.len -= count;
        self.head = if self.len == 0 { 0 } else { self.head + count };
    }
    pub(super) fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
    // Frees every slot of an empty ledger; growth allocates them again.
    pub(super) fn release(&mut self) {
        assert!(self.len == 0);
        self.blocks = Vec::new();
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
        &self.blocks[slot / BLOCK][slot % BLOCK]
    }
}
impl IndexMut<usize> for Intervals {
    fn index_mut(&mut self, index: usize) -> &mut Interval {
        assert!(index < self.len);
        let slot = self.head + index;
        &mut self.blocks[slot / BLOCK][slot % BLOCK]
    }
}
