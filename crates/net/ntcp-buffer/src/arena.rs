use crate::TxChunk;
use alloc::{boxed::Box, vec::Vec};

const SHIFT: u32 = 6;
const PAGE: usize = 1 << SHIFT;
const NIL: u32 = u32::MAX;

/// A counted reference to a chunk in one owner's `ChunkArena`: a slab
/// index and the generation the slot had when the reference was taken.
///
/// # Handle invariant
/// - Only the owner of the arena that issued a `ChunkRef` holds it, inside
///   that owner's state (a send-queue entry of one of its connections), and
///   uses it only with that arena. A `ChunkRef` never reaches a backend or
///   another owner: the device holds its own references to chunk memory
///   (`TxChunkVtable`), and a backend sees chunk bytes only as a
///   `ChunkSlice` borrowed for one call.
/// - Each `ChunkRef` is one count on its chunk. It is not `Clone`: `dup`
///   takes another count, and `release` gives one back, consuming the
///   handle. Every path that discards what holds a `ChunkRef` (an ACK that
///   frees a queue entry, abort, reset, reclaim, TIME-WAIT) releases it
///   first. A dropped `ChunkRef` leaks its count, keeping its chunk until
///   the arena is dropped; it is never undefined behaviour.
/// - After `release` or the arena's drop the handle is gone; a copy of its
///   index and generation must not survive anywhere.
///
/// # Stale handles are checked in debug builds only (user decision, D3)
/// Every use compares the handle's generation with its slot's in a
/// `debug_assert!`, which also checks that the handle came from this arena.
/// Release builds do not check, by the user's deliberate choice (2026-11-15)
/// against the study's recommendation of a release assert (+2.4 ns per
/// send). The consequence: in a release build a stale handle is not
/// detected, and can read, extend the life of, or free another chunk, which
/// can put another connection's bytes on the wire. It cannot cause undefined
/// behaviour: the arena has no unsafe code, every index is bounds-checked,
/// and a handle into an empty slot panics. The safeguards are the debug
/// check, which runs in every test profile, and the release-path property
/// test of allocate/release/reuse.
#[must_use = "a ChunkRef holds a count on its chunk: give it back with ChunkArena::release"]
#[derive(Debug)]
pub struct ChunkRef {
    index: u32,
    generation: u32,
    #[cfg(debug_assertions)]
    arena: u32,
}

enum Slot {
    Free { next: u32 },
    Live { count: u32, chunk: TxChunk },
}

struct Entry {
    generation: u32,
    slot: Slot,
}

struct Page {
    entries: Option<Box<[Entry; PAGE]>>,
    // The generation a page recreated in this slot starts at: above every
    // generation a handle into the freed page can hold.
    next_generation: u32,
    // Free entries counted during shrink.
    scratch: u32,
}

/// One owner's transmit chunks, each with the count of `ChunkRef`s held on
/// it: a slab of pages of 64 entries, allocated as needed, with one LIFO
/// free list, so a released slot is the next one reused while its page is
/// still cached. Not thread-safe and not shared: the counts are plain
/// integers, as an owner's connections all run on its thread.
pub struct ChunkArena {
    pages: Vec<Page>,
    // Page slots shrink emptied, refilled before the table grows.
    empty: Vec<u32>,
    free: u32,
    live: usize,
    present: usize,
    #[cfg(debug_assertions)]
    id: u32,
}

#[cfg(debug_assertions)]
static ARENAS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

impl Default for ChunkArena {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkArena {
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            empty: Vec::new(),
            free: NIL,
            live: 0,
            present: 0,
            #[cfg(debug_assertions)]
            id: ARENAS.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Chunks with at least one reference.
    pub fn live(&self) -> usize {
        self.live
    }

    /// Bytes the arena itself holds (its pages and tables), not the chunks'
    /// memory, which their owner charges per chunk.
    pub fn held_bytes(&self) -> usize {
        self.present * size_of::<[Entry; PAGE]>()
            + self.pages.capacity() * size_of::<Page>()
            + self.empty.capacity() * size_of::<u32>()
    }

    #[inline]
    fn entry(&self, index: u32) -> &Entry {
        let page = self.pages[(index >> SHIFT) as usize]
            .entries
            .as_ref()
            .expect("handle into a freed page");
        &page[index as usize & (PAGE - 1)]
    }

    #[inline]
    fn entry_mut(&mut self, index: u32) -> &mut Entry {
        let page = self.pages[(index >> SHIFT) as usize]
            .entries
            .as_mut()
            .expect("handle into a freed page");
        &mut page[index as usize & (PAGE - 1)]
    }

    #[inline]
    fn check(&self, entry: &Entry, handle: &ChunkRef) {
        #[cfg(debug_assertions)]
        assert_eq!(handle.arena, self.id, "ChunkRef from another arena");
        debug_assert_eq!(entry.generation, handle.generation, "stale ChunkRef");
    }

    /// Stores `chunk` with one reference, the returned handle.
    pub fn insert(&mut self, chunk: TxChunk) -> ChunkRef {
        if self.free == NIL {
            self.grow();
        }
        let index = self.free;
        let entry = self.entry_mut(index);
        let Slot::Free { next } = entry.slot else {
            unreachable!("free list through a live slot")
        };
        entry.slot = Slot::Live { count: 1, chunk };
        let generation = entry.generation;
        self.free = next;
        self.live += 1;
        ChunkRef {
            index,
            generation,
            #[cfg(debug_assertions)]
            arena: self.id,
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self) {
        let slot = match self.empty.pop() {
            Some(slot) => slot as usize,
            None => {
                self.pages.push(Page {
                    entries: None,
                    next_generation: 0,
                    scratch: 0,
                });
                self.pages.len() - 1
            }
        };
        assert!(slot < (NIL >> SHIFT) as usize, "chunk arena index space");
        let base = (slot << SHIFT) as u32;
        let generation = self.pages[slot].next_generation;
        let free = self.free;
        let entries = Box::new(core::array::from_fn(|k| Entry {
            generation,
            slot: Slot::Free {
                next: if k + 1 < PAGE {
                    base + k as u32 + 1
                } else {
                    free
                },
            },
        }));
        self.pages[slot].entries = Some(entries);
        self.present += 1;
        self.free = base;
    }

    /// The chunk `handle` references.
    #[inline]
    pub fn get(&self, handle: &ChunkRef) -> &TxChunk {
        let entry = self.entry(handle.index);
        self.check(entry, handle);
        match &entry.slot {
            Slot::Live { chunk, .. } => chunk,
            Slot::Free { .. } => panic!("ChunkRef into a free slot"),
        }
    }

    /// The chunk `handle` references, to append to its unfilled part while
    /// other references cover its filled prefix.
    #[inline]
    pub fn get_mut(&mut self, handle: &ChunkRef) -> &mut TxChunk {
        let entry = self.entry(handle.index);
        self.check(entry, handle);
        match &mut self.entry_mut(handle.index).slot {
            Slot::Live { chunk, .. } => chunk,
            Slot::Free { .. } => panic!("ChunkRef into a free slot"),
        }
    }

    /// References held on `handle`'s chunk.
    #[inline]
    pub fn references(&self, handle: &ChunkRef) -> u32 {
        let entry = self.entry(handle.index);
        self.check(entry, handle);
        match entry.slot {
            Slot::Live { count, .. } => count,
            Slot::Free { .. } => panic!("ChunkRef into a free slot"),
        }
    }

    /// Another reference to `handle`'s chunk.
    #[inline]
    pub fn dup(&mut self, handle: &ChunkRef) -> ChunkRef {
        let entry = self.entry(handle.index);
        self.check(entry, handle);
        match &mut self.entry_mut(handle.index).slot {
            Slot::Live { count, .. } => *count += 1,
            Slot::Free { .. } => panic!("ChunkRef into a free slot"),
        }
        ChunkRef {
            index: handle.index,
            generation: handle.generation,
            #[cfg(debug_assertions)]
            arena: handle.arena,
        }
    }

    /// Gives `handle`'s reference back. The last one frees the slot and
    /// returns the chunk, for the owner to keep for reuse or drop.
    #[inline]
    pub fn release(&mut self, handle: ChunkRef) -> Option<TxChunk> {
        let entry = self.entry(handle.index);
        self.check(entry, &handle);
        let free = self.free;
        let entry = self.entry_mut(handle.index);
        match &mut entry.slot {
            Slot::Live { count, .. } if *count > 1 => {
                *count -= 1;
                return None;
            }
            Slot::Live { .. } => {}
            Slot::Free { .. } => panic!("ChunkRef into a free slot"),
        }
        let Slot::Live { chunk, .. } =
            core::mem::replace(&mut entry.slot, Slot::Free { next: free })
        else {
            unreachable!()
        };
        entry.generation = entry.generation.wrapping_add(1);
        self.free = handle.index;
        self.live -= 1;
        Some(chunk)
    }

    /// Frees the pages with no live entry, as an owner gives memory back
    /// under pressure; returns how many. Linear in free entries and pages:
    /// never on a per-packet path.
    #[cold]
    pub fn shrink(&mut self) -> usize {
        for page in &mut self.pages {
            page.scratch = 0;
        }
        let mut index = self.free;
        while index != NIL {
            self.pages[(index >> SHIFT) as usize].scratch += 1;
            index = self.next_free(index);
        }
        let mut head = NIL;
        let mut index = self.free;
        while index != NIL {
            let next = self.next_free(index);
            if self.pages[(index >> SHIFT) as usize].scratch as usize != PAGE {
                self.entry_mut(index).slot = Slot::Free { next: head };
                head = index;
            }
            index = next;
        }
        self.free = head;
        let mut freed = 0;
        for (slot, page) in self.pages.iter_mut().enumerate() {
            if page.scratch as usize == PAGE {
                let entries = page.entries.take().unwrap();
                // Each entry's generation moved past its last handle's when
                // it was released, so no handle holds the page's maximum.
                page.next_generation = entries.iter().map(|e| e.generation).max().unwrap();
                self.empty.push(slot as u32);
                freed += 1;
            }
        }
        self.present -= freed;
        freed
    }

    fn next_free(&self, index: u32) -> u32 {
        match self.entry(index).slot {
            Slot::Free { next } => next,
            Slot::Live { .. } => unreachable!("free list through a live slot"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn chunk(bytes: &[u8]) -> TxChunk {
        let mut chunk = TxChunk::heap(32);
        chunk.append(bytes);
        chunk
    }

    #[test]
    fn references_count_and_the_last_release_returns_the_chunk() {
        let mut arena = ChunkArena::new();
        assert_eq!((arena.live(), arena.held_bytes()), (0, 0));
        let a = arena.insert(chunk(&[1, 2, 3]));
        let b = arena.dup(&a);
        assert_eq!(arena.references(&a), 2);
        assert_eq!(arena.get(&b).bytes(0..3), &[1, 2, 3]);
        assert_eq!(arena.get_mut(&b).append(&[4]), 1);
        assert_eq!(arena.get(&a).bytes(0..4), &[1, 2, 3, 4]);
        assert!(arena.release(a).is_none());
        assert_eq!(arena.live(), 1);
        let back = arena.release(b).unwrap();
        assert_eq!(back.bytes(0..4), &[1, 2, 3, 4]);
        assert_eq!(arena.live(), 0);
        // The slot is reused first, under a new generation.
        let c = arena.insert(back);
        assert_eq!(c.index, 0);
        assert_eq!(c.generation, 1);
        assert!(arena.held_bytes() >= PAGE * size_of::<Entry>());
        let _ = arena.release(c);
    }

    #[test]
    fn shrink_frees_empty_pages_and_their_handles_stay_stale() {
        let mut arena = ChunkArena::new();
        let handles: Vec<ChunkRef> = (0..3 * PAGE as u8)
            .map(|k| arena.insert(chunk(&[k])))
            .collect();
        let held = arena.held_bytes();
        let mut kept = Vec::new();
        for (k, handle) in handles.into_iter().enumerate() {
            // Keep one entry of the middle page live.
            if k == PAGE + 5 {
                kept.push(handle);
            } else {
                assert!(arena.release(handle).is_some());
            }
        }
        assert_eq!(arena.shrink(), 2);
        assert!(arena.held_bytes() < held);
        assert_eq!(arena.get(&kept[0]).bytes(0..1), &[PAGE as u8 + 5]);
        // Refilled: the middle page's free entries first, then a recreated
        // page whose generations start past every old handle's.
        let again: Vec<ChunkRef> = (0..3 * PAGE - 1)
            .map(|_| arena.insert(chunk(&[0])))
            .collect();
        assert!(again.iter().all(|h| h.generation >= 1));
        assert_eq!(arena.shrink(), 0);
        for handle in again.into_iter().chain(kept) {
            assert!(arena.release(handle).is_some());
        }
        assert_eq!(arena.live(), 0);
        assert_eq!(arena.shrink(), 3);
        assert_eq!(arena.shrink(), 0);
    }

    #[test]
    fn dropping_the_arena_drops_every_chunk() {
        let mut arena = ChunkArena::new();
        let handles: Vec<ChunkRef> = (0..100).map(|_| arena.insert(chunk(&[7; 32]))).collect();
        drop(arena);
        // The handles are stale now; they hold nothing to release.
        drop(handles);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "stale ChunkRef")]
    fn a_stale_handle_panics_in_debug_builds() {
        let mut arena = ChunkArena::new();
        let a = arena.insert(chunk(&[1]));
        let stale = ChunkRef {
            index: a.index,
            generation: a.generation,
            arena: a.arena,
        };
        let _ = arena.release(a);
        let _b = arena.insert(chunk(&[2]));
        let _ = arena.get(&stale);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "ChunkRef from another arena")]
    fn a_handle_from_another_arena_panics_in_debug_builds() {
        let mut first = ChunkArena::new();
        let mut second = ChunkArena::new();
        let _a = second.insert(chunk(&[2]));
        let b = first.insert(chunk(&[1]));
        let _ = second.get(&b);
    }

    // The consequence the user accepted (D3): in release a stale handle
    // reaches whatever chunk now holds its slot.
    #[test]
    #[cfg(not(debug_assertions))]
    fn a_stale_handle_reads_the_slots_new_chunk_in_release_builds() {
        let mut arena = ChunkArena::new();
        let a = arena.insert(chunk(&[1]));
        let stale = ChunkRef {
            index: a.index,
            generation: a.generation,
        };
        let _ = arena.release(a);
        let b = arena.insert(chunk(&[2]));
        assert_eq!(arena.get(&stale).bytes(0..1), &[2]);
        let _ = arena.release(b);
    }

    #[test]
    #[should_panic(expected = "ChunkRef into a free slot")]
    fn a_handle_into_a_free_slot_panics_in_every_build() {
        let mut arena = ChunkArena::new();
        let a = arena.insert(chunk(&[1]));
        let stale = ChunkRef {
            index: a.index,
            generation: a.generation.wrapping_add(1),
            #[cfg(debug_assertions)]
            arena: a.arena,
        };
        let _ = arena.release(a);
        let _ = arena.get(&stale);
    }

    // Allocate/release/reuse against a model, run in release builds as in
    // debug (`cargo test --release -p ntcp-buffer`): correct use of handles
    // keeps every chunk's bytes and count, returns a chunk exactly at its
    // last release, and reuses slots, through shrink and regrowth.
    #[test]
    fn handles_through_random_allocate_release_reuse_match_a_model() {
        struct Held {
            handle: ChunkRef,
            id: u32,
        }
        let (seeds, steps) = if cfg!(miri) { (2, 300) } else { (64, 5000) };
        let (mut pages_freed, mut most_live) = (0, 0);
        for seed in 0..seeds {
            let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ (seed as u64 + 1);
            let mut next = move |bound: usize| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state % bound as u64) as usize
            };
            let mut arena = ChunkArena::new();
            let mut held: Vec<Held> = Vec::new();
            // Model: per chunk id, its expected bytes and reference count.
            let mut model: Vec<(Vec<u8>, u32)> = Vec::new();
            let mut slots_seen = std::collections::BTreeSet::new();
            let mut last_freed: Option<u32> = None;
            for step in 0..steps {
                // Alternate phases that mostly allocate and mostly release,
                // so pages fill, empty, shrink and regrow.
                let growing = (step / (steps / 10)) % 2 == 0;
                let op = match (growing, next(10)) {
                    (_, 0) | (true, 1..=3) => 0,
                    (false, 1..=3) => 2,
                    (_, 4) => 1,
                    (_, 5..=7) => 2,
                    (_, 8) => 5,
                    _ => 6,
                };
                match op {
                    0 => {
                        let id = model.len() as u32;
                        let bytes = vec![(id % 251) as u8; 1 + next(8)];
                        let mut new = TxChunk::heap(16);
                        new.append(&bytes);
                        let handle = arena.insert(new);
                        if let Some(freed) = last_freed.take() {
                            assert_eq!(handle.index, freed, "LIFO reuse");
                        }
                        slots_seen.insert(handle.index);
                        model.push((bytes, 1));
                        held.push(Held { handle, id });
                    }
                    1 if !held.is_empty() => {
                        let k = next(held.len());
                        let id = held[k].id;
                        let handle = arena.dup(&held[k].handle);
                        model[id as usize].1 += 1;
                        held.push(Held { handle, id });
                    }
                    2..=4 if !held.is_empty() => {
                        let Held { handle, id } = held.swap_remove(next(held.len()));
                        let index = handle.index;
                        let expected = &mut model[id as usize];
                        expected.1 -= 1;
                        match arena.release(handle) {
                            Some(chunk) => {
                                assert_eq!(expected.1, 0, "returned before the last release");
                                assert_eq!(chunk.bytes(0..chunk.len()), &expected.0[..]);
                                last_freed = Some(index);
                            }
                            None => assert_ne!(expected.1, 0, "kept after the last release"),
                        }
                    }
                    5 if !held.is_empty() => {
                        let k = next(held.len());
                        let id = held[k].id as usize;
                        let chunk = arena.get_mut(&held[k].handle);
                        let byte = next(256) as u8;
                        if chunk.append(&[byte]) == 1 {
                            model[id].0.push(byte);
                        }
                    }
                    6 if next(8) == 0 => {
                        pages_freed += arena.shrink();
                        last_freed = None;
                    }
                    _ => {}
                }
                for Held { handle, id } in &held {
                    let (bytes, count) = &model[*id as usize];
                    let chunk = arena.get(handle);
                    assert_eq!(chunk.bytes(0..chunk.len()), &bytes[..]);
                    assert_eq!(arena.references(handle), *count);
                }
                let live = model.iter().filter(|(_, count)| *count > 0).count();
                assert_eq!(arena.live(), live);
                most_live = most_live.max(live);
            }
            assert!(slots_seen.len() < model.len(), "slots were reused");
            for Held { handle, .. } in held {
                let _ = arena.release(handle);
            }
            assert_eq!(arena.live(), 0);
        }
        assert!(pages_freed > 0, "shrink freed pages");
        assert!(cfg!(miri) || most_live > PAGE, "more than one page in use");
    }
}
