//! The occupied slots of a fixed table, kept in ascending order, so that
//! passes made on every service call visit live entries rather than the
//! configured capacity.

use crate::Error;
use alloc::vec::Vec;

pub(crate) struct Live(Vec<usize>);

impl Live {
    /// Room for every slot of a `capacity`-slot table is allocated once, so
    /// that `insert` never allocates.
    pub fn new(capacity: usize) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        Ok(Self(slots))
    }
    pub fn insert(&mut self, slot: usize) {
        let at = self.0.partition_point(|&s| s < slot);
        debug_assert!(self.0.get(at) != Some(&slot) && self.0.len() < self.0.capacity());
        self.0.insert(at, slot);
    }
    pub fn remove(&mut self, slot: usize) {
        let at = self.0.partition_point(|&s| s < slot);
        debug_assert_eq!(self.0.get(at), Some(&slot));
        self.0.remove(at);
    }
    /// The first occupied slot at or after `from`. Stepping with it visits
    /// what a pass over every slot in order would find occupied, also when
    /// the pass frees the slots it visits.
    pub fn next(&self, from: usize) -> Option<usize> {
        self.0.get(self.0.partition_point(|&s| s < from)).copied()
    }
    pub fn contains(&self, slot: usize) -> bool {
        self.0.binary_search(&slot).is_ok()
    }
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().copied()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether these are exactly the occupied slots of `table`: the full
    /// scan the index replaces, for debug assertions.
    pub fn matches<T>(&self, table: &[Option<T>]) -> bool {
        self.iter()
            .eq((0..table.len()).filter(|&i| table[i].is_some()))
    }
}
