//! The path cache's lookups, none of them a pass over the cached paths:
//! the incarnations of each flow by a keyed hash, the lowest free slot and
//! the lowest-index idle slot.
//!
//! A destination is chosen by the peer, so the hash is keyed with a secret
//! the embedding supplies (`PathService::new`): without the key, peers
//! cannot steer their paths into one chain. Linux keys its next-hop
//! exception hashes the same way (SipHash under a boot-random key,
//! `fnhe_hashfun` and `rt6_exception_hash`).

use super::*;
use core::hash::Hasher;

// The end of a chain.
const NONE: u32 = u32::MAX;

pub(in crate::service) struct PathIndex {
    // SipHash key of `bucket`.
    key: [u8; 16],
    // The first path slot of each bucket's chain, a power of two in number,
    // and the next slot of the chain each path slot is on: every cached
    // incarnation is on the chain of its flow's bucket.
    heads: Vec<u32>,
    next: Vec<u32>,
    // Path slots ever occupied. A path slot is never vacated (an idle path
    // stays until its slot is reused), so this is the lowest free slot.
    used: usize,
    // A bit per path slot that holds an idle path (level 0), and per
    // nonzero word of each level a bit in the level above, up to a level
    // of one word: the lowest idle slot is found in one word per level.
    idle: Vec<Vec<u64>>,
}

impl PathIndex {
    // Buckets for `paths` path slots, and the words of each level of the
    // idle bitmap, lowest level first.
    fn buckets(paths: usize) -> Result<usize, Error> {
        paths
            .max(1)
            .checked_next_power_of_two()
            .ok_or(Error::Capacity)
    }
    fn levels(paths: usize) -> impl Iterator<Item = usize> {
        let mut words = Some(paths.div_ceil(64));
        core::iter::from_fn(move || {
            let current = words?;
            words = (current > 1).then(|| current.div_ceil(64));
            Some(current)
        })
    }

    /// What `new` allocates for `paths` path slots, as (count, element
    /// size) pairs for the service's accounting.
    pub(in crate::service) fn accounting(paths: usize) -> Result<[(usize, usize); 3], Error> {
        // Slot numbers and the chain end are u32.
        if paths >= NONE as usize {
            return Err(Error::Capacity);
        }
        Ok([
            (Self::buckets(paths)?, size_of::<u32>()),
            (paths, size_of::<u32>()),
            (Self::levels(paths).sum(), size_of::<u64>()),
        ])
    }

    pub(in crate::service) fn new(paths: usize, key: [u8; 16]) -> Result<Self, Error> {
        Self::accounting(paths)?;
        let mut idle = Vec::new();
        idle.try_reserve_exact(Self::levels(paths).count())
            .map_err(|_| Error::Allocation)?;
        for words in Self::levels(paths) {
            idle.push(filled(words, 0)?);
        }
        Ok(Self {
            key,
            heads: filled(Self::buckets(paths)?, NONE)?,
            next: filled(paths, NONE)?,
            used: 0,
            idle,
        })
    }

    // The bucket of `key`'s flow: a hash of the fields `same_flow`
    // compares, so that every incarnation of a flow, whatever its first
    // hop, is on one chain. Handles contribute their slots (truncated: equal
    // flows need only hash equally), and an address its family.
    pub(super) fn bucket(&self, key: &PathKey) -> usize {
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&self.key);
        for address in [key.destination, key.forwarding_destination] {
            match address.address {
                IpAddr::V4(ip) => {
                    hash.write_u8(4);
                    hash.write(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    hash.write_u8(6);
                    hash.write(&ip.octets());
                }
            }
            hash.write_u32(address.zone.map_or(NONE, |zone| zone.0.slot as u32));
        }
        hash.write_u32(key.source.0.slot as u32);
        hash.write_u32(key.route.0.slot as u32);
        hash.write_u8(key.dscp.value());
        hash.finish() as usize & (self.heads.len() - 1)
    }

    /// The path slots on `bucket`'s chain.
    pub(super) fn chain(&self, bucket: usize) -> impl Iterator<Item = usize> + '_ {
        let mut at = self.heads[bucket];
        core::iter::from_fn(move || {
            let slot = (at != NONE).then_some(at as usize)?;
            at = self.next[slot];
            Some(slot)
        })
    }

    pub(super) fn link(&mut self, slot: usize, bucket: usize) {
        self.next[slot] = self.heads[bucket];
        self.heads[bucket] = slot as u32;
    }

    pub(super) fn unlink(&mut self, slot: usize, bucket: usize) {
        let after = self.next[slot];
        if self.heads[bucket] == slot as u32 {
            self.heads[bucket] = after;
            return;
        }
        // The slot is on this chain: its predecessor is found before the end.
        let mut at = self.heads[bucket] as usize;
        while self.next[at] != slot as u32 {
            at = self.next[at] as usize;
        }
        self.next[at] = after;
    }

    /// The lowest never occupied path slot, if any is left.
    pub(super) fn free(&self) -> Option<usize> {
        (self.used < self.next.len()).then_some(self.used)
    }

    /// Record that `slot` is occupied.
    pub(super) fn occupy(&mut self, slot: usize) {
        self.used = self.used.max(slot + 1);
    }

    pub(super) fn set_idle(&mut self, slot: usize, idle: bool) {
        let mut position = slot;
        for level in &mut self.idle {
            let word = &mut level[position / 64];
            let was = *word != 0;
            let bit = 1 << (position % 64);
            if idle {
                *word |= bit;
            } else {
                *word &= !bit;
            }
            // The levels above change only when this word's emptiness does.
            if was == (*word != 0) {
                return;
            }
            position /= 64;
        }
    }

    /// The lowest-index idle path slot.
    pub(super) fn lowest_idle(&self) -> Option<usize> {
        let mut position = 0;
        for level in self.idle.iter().rev() {
            let word = *level.get(position)?;
            if word == 0 {
                return None;
            }
            position = position * 64 + word.trailing_zeros() as usize;
        }
        Some(position)
    }

    /// Whether the idle bitmap holds exactly `idle` per path slot: the full
    /// scan it replaces, for debug assertions.
    pub(super) fn lists_idle(&self, mut idle: impl FnMut(usize) -> bool) -> bool {
        let mut levels = self.idle.iter();
        let Some(bits) = levels.next() else {
            return true;
        };
        let mut below = bits;
        (0..self.next.len()).all(|slot| idle(slot) == (bits[slot / 64] >> (slot % 64) & 1 != 0))
            && levels.all(|level| {
                let summarized = (0..below.len())
                    .all(|word| (below[word] != 0) == (level[word / 64] >> (word % 64) & 1 != 0));
                below = level;
                summarized
            })
    }

    /// One bucket for every flow, so that every path is on one chain.
    /// Only before any path is linked.
    #[cfg(test)]
    pub(super) fn collide(&mut self) {
        assert!(self.heads.iter().all(|&head| head == NONE));
        self.heads.truncate(1);
    }

    /// Whether the chains hold each slot `bucket` names a bucket for once,
    /// on that bucket's chain, and nothing else.
    #[cfg(test)]
    pub(super) fn lists_chains(&self, bucket: impl Fn(usize) -> Option<usize>) -> bool {
        let mut seen = alloc::vec![false; self.next.len()];
        (0..self.heads.len()).all(|b| {
            self.chain(b)
                .take(self.next.len() + 1)
                .all(|slot| bucket(slot) == Some(b) && !core::mem::replace(&mut seen[slot], true))
        }) && (0..self.next.len()).all(|slot| seen[slot] == bucket(slot).is_some())
    }
}

pub(super) fn filled<T: Clone>(count: usize, value: T) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    values.resize(count, value);
    Ok(values)
}
