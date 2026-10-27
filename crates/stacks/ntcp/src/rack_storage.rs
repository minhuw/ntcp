use super::Interval;
use alloc::vec::Vec;
use core::{
    mem::size_of,
    ops::{Index, IndexMut},
};

// Bound replacement of a partially populated block to 64 KiB. Full blocks
// stay in place across growth; descriptor overhead is below 0.04% per record.
const BLOCK: usize = 64 * 1024 / size_of::<Interval>();

#[derive(Debug)]
pub(super) struct Intervals {
    blocks: Vec<Vec<Interval>>,
    len: usize,
    capacity: usize,
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
            len: 0,
            capacity: 0,
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
        blocks_allocation_bytes(&self.blocks)
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
        self.blocks[..self.len.div_ceil(BLOCK)]
            .iter()
            .flat_map(|b| b.iter())
    }
    pub(super) fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut Interval> {
        self.blocks[..self.len.div_ceil(BLOCK)]
            .iter_mut()
            .flat_map(|b| b.iter_mut())
    }
    pub(super) fn range(
        &self,
        start: usize,
        end: usize,
    ) -> impl DoubleEndedIterator<Item = &Interval> {
        assert!(start <= end && end <= self.len);
        let first = start / BLOCK;
        self.blocks[first..end.div_ceil(BLOCK)]
            .iter()
            .enumerate()
            .flat_map(move |(i, b)| {
                let offset = (first + i) * BLOCK;
                b[start.saturating_sub(offset)..end.saturating_sub(offset).min(b.len())].iter()
            })
    }
    pub(super) fn range_mut(
        &mut self,
        start: usize,
        end: usize,
    ) -> impl DoubleEndedIterator<Item = &mut Interval> {
        assert!(start <= end && end <= self.len);
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
    pub(super) fn push(&mut self, value: Interval) {
        assert!(self.len < self.capacity);
        let i = self.len / BLOCK;
        self.blocks[i].push(value);
        self.len += 1;
    }
    pub(super) fn insert(&mut self, index: usize, value: Interval) {
        assert!(index <= self.len);
        self.push(value);
        for i in (index + 1..self.len).rev() {
            self[i] = self[i - 1];
        }
        self[index] = value;
    }
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&Interval) -> bool) {
        self.retain_mut(|r| keep(r));
    }
    pub(super) fn retain_mut(&mut self, mut keep: impl FnMut(&mut Interval) -> bool) {
        let mut write = 0;
        for read in 0..self.len {
            if keep(&mut self[read]) {
                if write != read {
                    self[write] = self[read];
                }
                write += 1;
            }
        }
        self.len = write;
        for (i, block) in self.blocks.iter_mut().enumerate() {
            block.truncate(write.saturating_sub(i * BLOCK).min(BLOCK));
        }
    }
    pub(super) fn clear(&mut self) {
        self.len = 0;
        for block in &mut self.blocks {
            block.clear();
        }
    }
}
impl Index<usize> for Intervals {
    type Output = Interval;
    fn index(&self, index: usize) -> &Interval {
        assert!(index < self.len);
        &self.blocks[index / BLOCK][index % BLOCK]
    }
}
impl IndexMut<usize> for Intervals {
    fn index_mut(&mut self, index: usize) -> &mut Interval {
        assert!(index < self.len);
        &mut self.blocks[index / BLOCK][index % BLOCK]
    }
}
impl<'a> IntoIterator for &'a mut Intervals {
    type Item = &'a mut Interval;
    type IntoIter = core::iter::FlatMap<
        core::slice::IterMut<'a, Vec<Interval>>,
        core::slice::IterMut<'a, Interval>,
        fn(&'a mut Vec<Interval>) -> core::slice::IterMut<'a, Interval>,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.blocks[..self.len.div_ceil(BLOCK)]
            .iter_mut()
            .flat_map(|b| b.iter_mut())
    }
}
