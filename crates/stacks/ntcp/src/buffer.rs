extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use core::mem::size_of;

use ntcp_buffer::{ChunkArena, ChunkRef, ChunkSlice, PayloadSlice, TxPart};

use crate::{
    Payload,
    output_reservation::OwnedTxPart,
    tx_pool::{TxPartsBuf, TxPool},
};

#[path = "send_marks.rs"]
mod send_marks;
use send_marks::PtbMarks;

// Per-entry flag bits, carried on the last byte of a `TxSeg` (D5).
// Interior bytes never carry PUSH or EOR; setting a flag mid-entry splits it.
const FLAG_PUSH: u8 = 1 << 0;
const FLAG_EOR: u8 = 1 << 1;
const FLAG_MARK_MASK: u8 = FLAG_PUSH | FLAG_EOR;
// Set on a `TxSegData::Shared` entry when it continues the immediately
// preceding `TxSegData::Shared` entry in the same storage and lease (e.g.
// separated only by a PUSH/EOR boundary or an interior split).
const FLAG_CONTIGUOUS_SHARED: u8 = 1 << 2;

/// Initial entry-deque reservation on first write.
pub(crate) const SEND_ENTRY_RESERVE: usize = 8;

/// Spare entry slots kept beyond what a write adds so `collapse_push` and
/// `finish_send` do not allocate on the output/shutdown path.
pub(crate) const ENTRY_SPLIT_SPARE: usize = 2;

#[derive(Debug)]
enum TxSegData {
    Chunk {
        chunk: ChunkRef,
        offset: u32,
        len: u32,
    },
    Shared(Payload),
    // Shared payload dropped eagerly on `release_shared()` at connection
    // termination while preserving `SendBuffer::len()` until an abort's
    // purge or reclaim.
    Released(u32),
}

#[derive(Debug)]
struct TxSeg {
    // A connection admits less than 2^30 queued bytes. Every live entry's
    // position relative to `head` is unambiguous across a u32 wrap.
    start: u32,
    data: TxSegData,
    // Bit 0 = PUSH on last byte of this entry, bit 1 = EOR on last byte.
    flags: u8,
}

impl TxSeg {
    #[inline]
    fn len(&self) -> usize {
        match &self.data {
            TxSegData::Chunk { len, .. } => *len as usize,
            TxSegData::Shared(payload) => payload.len(),
            TxSegData::Released(len) => *len as usize,
        }
    }
}

#[cold]
#[inline(never)]
fn drop_payload_cold(_: Payload) {}

#[derive(Debug)]
pub(crate) struct SendBuffer {
    entries: VecDeque<TxSeg>,
    len: usize,
    chunk_bytes: usize,
    capacity: usize,
    head: u32,
    shared_entries: usize,
    // Discontiguous shared Payload spans (Shared entries without
    // `FLAG_CONTIGUOUS_SHARED`), bounded by `MAX_SHARED_SEGMENTS`.
    shared_spans: usize,
    shared_output: Option<usize>,
    // Queue offsets immediately after the last PUSH and EOR, zero if absent.
    // A prefix ACK subtracts its byte count from both boundaries.
    push_end: usize,
    // Bytes ending at push_end known to carry only that final PUSH.
    single_push_len: usize,
    eor_end: usize,
    // True once any PTB or retransmission mark has been inserted into `ptb`
    // since the last clear; keeps the common non-PTB ACK/clear path off the
    // 120-byte `PtbMarks` storage.
    has_ptb: bool,
    ptb: PtbMarks,
}

impl SendBuffer {
    // Entry deque reserved up front for tests that write directly into
    // `SendBuffer` without going through `Connection::grow_send_storage`.
    #[cfg(test)]
    pub(crate) fn new(capacity: usize) -> Result<Self, ()> {
        if capacity > (1 << 30) {
            return Err(());
        }
        let mut entries = VecDeque::new();
        if capacity > 0 {
            entries
                .try_reserve_exact(SEND_ENTRY_RESERVE)
                .map_err(|_| ())?;
        }
        Ok(Self {
            entries,
            len: 0,
            chunk_bytes: 0,
            capacity,
            head: 0,
            shared_entries: 0,
            shared_spans: 0,
            shared_output: None,
            push_end: 0,
            single_push_len: 0,
            eor_end: 0,
            has_ptb: false,
            ptb: PtbMarks::default(),
        })
    }

    // A logical capacity limit with zero heap storage allocated: entries are
    // allocated on the first write, as Linux allocates a socket's skbs in
    // sendmsg and none at socket creation.
    pub(crate) fn unallocated(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            len: 0,
            chunk_bytes: 0,
            capacity,
            head: 0,
            shared_entries: 0,
            shared_spans: 0,
            shared_output: None,
            push_end: 0,
            single_push_len: 0,
            eor_end: 0,
            has_ptb: false,
            ptb: PtbMarks::default(),
        }
    }

    #[inline]
    pub(crate) fn entries_storage_bytes(&self) -> usize {
        self.entries.capacity() * size_of::<TxSeg>()
    }

    #[inline]
    pub(crate) fn ptb_storage_bytes(&self) -> usize {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return 0;
        }
        self.ptb.storage_bytes()
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn storage_bytes(&self) -> usize {
        self.entries_storage_bytes() + self.ptb_storage_bytes()
    }

    #[inline]
    pub(crate) fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub(crate) fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.len)
    }

    pub(crate) fn set_limit(&mut self, capacity: usize) {
        self.capacity = capacity;
    }

    /// Whether no `TxSegData::Chunk` handles remain in this buffer.
    #[cfg(test)]
    pub(crate) fn has_no_chunks(&self) -> bool {
        self.entries
            .iter()
            .all(|seg| !matches!(seg.data, TxSegData::Chunk { .. }))
    }

    /// Releases every live `ChunkRef` back to `pool` and empties the queue.
    #[inline]
    pub(crate) fn clear_chunks(&mut self, pool: &mut TxPool) {
        if self.entries.len() == 1 && self.shared_entries == 0 && !self.has_ptb {
            let seg = self.entries.pop_front().unwrap();
            match seg.data {
                TxSegData::Chunk { chunk, .. } => pool.release(chunk),
                TxSegData::Shared(payload) => drop_payload_cold(payload),
                TxSegData::Released(_) => {}
            }
            debug_assert_eq!(self.ptb, PtbMarks::default());
            self.len = 0;
            self.chunk_bytes = 0;
            self.push_end = 0;
            self.single_push_len = 0;
            self.eor_end = 0;
            return;
        }
        self.clear_chunks_slow(pool);
    }

    #[cold]
    #[inline(never)]
    fn clear_chunks_slow(&mut self, pool: &mut TxPool) {
        while let Some(seg) = self.entries.pop_front() {
            if let TxSegData::Chunk { chunk, .. } = seg.data {
                pool.release(chunk);
            }
        }
        if self.has_ptb {
            self.ptb.clear();
            self.has_ptb = false;
        }
        debug_assert_eq!(self.ptb, PtbMarks::default());
        self.len = 0;
        self.chunk_bytes = 0;
        self.shared_entries = 0;
        self.shared_spans = 0;
        self.push_end = 0;
        self.single_push_len = 0;
        self.eor_end = 0;
    }

    // Frees the entry deque and PTB storage of an empty queue.
    pub(crate) fn release(&mut self) {
        assert!(self.entries.is_empty());
        debug_assert_eq!(self.len, 0);
        debug_assert_eq!(self.chunk_bytes, 0);
        debug_assert_eq!(self.shared_entries, 0);
        debug_assert_eq!(self.shared_spans, 0);
        debug_assert!(self.push_end == 0 && self.eor_end == 0);
        self.entries = VecDeque::new();
        if self.has_ptb {
            self.ptb.clear();
            self.has_ptb = false;
        }
        debug_assert_eq!(self.ptb, PtbMarks::default());
        self.push_end = 0;
        self.single_push_len = 0;
        self.eor_end = 0;
    }

    pub(crate) fn admission_room(&self, notsent: usize, lowat: Option<u32>) -> usize {
        let remaining = self.remaining();
        let Some(lowat) = lowat.filter(|&value| value != u32::MAX) else {
            return remaining;
        };
        remaining.min((lowat as usize).saturating_sub(notsent))
    }

    /// Whether a copying append into `pool`'s current tail chunk can extend
    /// `self.entries.back()` in place without creating a new `TxSeg`.
    #[inline]
    pub(crate) fn can_extend_tail(&self, pool: &TxPool) -> bool {
        let Some(back) = self.entries.back() else {
            return false;
        };
        if back.flags != 0 {
            return false;
        }
        match &back.data {
            TxSegData::Chunk { chunk, offset, len } => pool.tail_continues(chunk, *offset + *len),
            _ => false,
        }
    }

    /// Worst-case number of new `TxSeg` entries a copying write of `copy_bytes`
    /// will append into `pool`.
    pub(crate) fn needed_entries_for_copy(&self, pool: &TxPool, copy_bytes: usize) -> usize {
        if copy_bytes == 0 {
            return 0;
        }
        let tail_rem = pool.tail_remaining();
        if copy_bytes <= tail_rem {
            return usize::from(!self.can_extend_tail(pool));
        }
        let chunk_size = pool.chunk_size().max(1);
        let first = usize::from(tail_rem > 0 && !self.can_extend_tail(pool));
        first + (copy_bytes - tail_rem).div_ceil(chunk_size)
    }

    /// Target entry-deque capacity to accommodate `new_entries` plus split
    /// headroom.
    fn entry_target(&self, new_entries: usize) -> usize {
        let needed = self
            .entries
            .len()
            .saturating_add(new_entries)
            .saturating_add(ENTRY_SPLIT_SPARE);
        if self.entries.capacity() >= needed {
            return self.entries.capacity();
        }
        needed
            .max(SEND_ENTRY_RESERVE)
            .max(self.entries.capacity().saturating_mul(2))
            .checked_next_power_of_two()
            .unwrap_or(needed)
    }

    /// Whether `self.entries` already has capacity for `new_entries` plus
    /// `ENTRY_SPLIT_SPARE` spare slots without reallocating.
    #[inline]
    pub(crate) fn has_entry_room(&self, new_entries: usize) -> bool {
        new_entries
            .checked_add(ENTRY_SPLIT_SPARE)
            .is_some_and(|needed| self.entries.capacity() - self.entries.len() >= needed)
    }

    /// Peak additional bytes reallocating `self.entries` for `new_entries`
    /// plus `ENTRY_SPLIT_SPARE` would allocate, or `0` if already reserved.
    pub(crate) fn entry_growth_bytes(&self, new_entries: usize) -> Option<usize> {
        let needed = self
            .entries
            .len()
            .checked_add(new_entries)?
            .checked_add(ENTRY_SPLIT_SPARE)?;
        if self.entries.capacity() >= needed {
            return Some(0);
        }
        let target = self.entry_target(new_entries);
        target.checked_mul(size_of::<TxSeg>())
    }

    /// Ensures `self.entries` holds at least `new_entries + ENTRY_SPLIT_SPARE`
    /// free slots without mutating any queued bytes on failure.
    pub(crate) fn reserve_entries(&mut self, new_entries: usize) -> Result<(), ()> {
        let needed = self
            .entries
            .len()
            .checked_add(new_entries)
            .and_then(|n| n.checked_add(ENTRY_SPLIT_SPARE))
            .ok_or(())?;
        if self.entries.capacity() >= needed {
            return Ok(());
        }
        let target = self.entry_target(new_entries);
        let additional = target.saturating_sub(self.entries.len());
        self.entries.try_reserve_exact(additional).map_err(|_| ())
    }

    /// Appends up to `input.len()` bytes by copying into `pool`'s tail and
    /// freshly allocated chunks. Extends `entries.back_mut()` in place when
    /// `back.flags == 0` and it continues the tail chunk (zero `dup`/`release`).
    ///
    /// Returns the number of bytes actually copied (`< input.len()` only if the
    /// chunk source ran dry or arena page allocation failed).
    #[inline]
    pub(crate) fn append(&mut self, pool: &mut TxPool, input: &[u8]) -> usize {
        debug_assert!(input.len() <= self.remaining());
        let n = input.len();
        if n == 0 {
            return 0;
        }
        if n <= pool.tail_remaining() {
            let can_extend = if let Some(back) = self.entries.back()
                && back.flags == 0
                && let TxSegData::Chunk {
                    chunk,
                    offset: back_off,
                    len: back_len,
                } = &back.data
            {
                pool.tail_continues(chunk, *back_off + *back_len)
            } else {
                false
            };
            if can_extend {
                let (_off, taken) = pool.append_to_tail_no_dup(input);
                debug_assert_eq!(taken, n);
                if let Some(back) = self.entries.back_mut()
                    && let TxSegData::Chunk { len: back_len, .. } = &mut back.data
                {
                    *back_len += taken as u32;
                }
            } else {
                assert!(
                    self.entries.len() < self.entries.capacity(),
                    "TxSeg entries not reserved before append"
                );
                let (chunk, off, taken) = pool.append_to_tail_and_dup(input);
                debug_assert_eq!(taken, n);
                let start = self.head.wrapping_add(self.len as u32);
                self.entries.push_back(TxSeg {
                    start,
                    data: TxSegData::Chunk {
                        chunk,
                        offset: off,
                        len: taken as u32,
                    },
                    flags: 0,
                });
            }
            self.len += n;
            self.chunk_bytes += n;
            return n;
        }
        self.append_slow(pool, input)
    }

    #[cold]
    #[inline(never)]
    fn append_slow(&mut self, pool: &mut TxPool, input: &[u8]) -> usize {
        let entries = &mut self.entries;
        let head = self.head;
        let len_ref = &mut self.len;
        let chunk_bytes_ref = &mut self.chunk_bytes;
        pool.append_into(input, |arena, tail, off, taken| {
            if let Some(back) = entries.back_mut()
                && back.flags == 0
                && let TxSegData::Chunk {
                    chunk,
                    offset: back_off,
                    len: back_len,
                } = &mut back.data
                && arena.same_chunk(chunk, tail)
                && *back_off + *back_len == off
            {
                *back_len += taken;
            } else {
                assert!(
                    entries.len() < entries.capacity(),
                    "TxSeg entries not reserved before append"
                );
                let start = head.wrapping_add(*len_ref as u32);
                entries.push_back(TxSeg {
                    start,
                    data: TxSegData::Chunk {
                        chunk: arena.dup(tail),
                        offset: off,
                        len: taken,
                    },
                    flags: 0,
                });
            }
            *len_ref += taken as usize;
            *chunk_bytes_ref += taken as usize;
        })
    }

    #[cfg(test)]
    pub(crate) fn write(&mut self, pool: &mut TxPool, input: &[u8]) -> usize {
        let count = input.len().min(self.remaining());
        if count == 0 {
            return 0;
        }
        let needed = self.needed_entries_for_copy(pool, count);
        self.reserve_entries(needed)
            .expect("test SendBuffer::write entry reservation failed");
        self.append(pool, &input[..count])
    }

    #[inline]
    fn seg_start(&self, seg: &TxSeg) -> usize {
        seg.start.wrapping_sub(self.head) as usize
    }

    /// Index of the entry containing byte `offset`, or `None` if `offset >= self.len`.
    /// O(1) when hitting the front or back entry; O(log E) otherwise.
    #[inline]
    fn entry_at(&self, offset: usize) -> Option<usize> {
        if offset >= self.len {
            return None;
        }
        debug_assert!(!self.entries.is_empty());
        if offset < self.entries[0].len() {
            return Some(0);
        }
        let last = self.entries.len() - 1;
        if offset >= self.seg_start(&self.entries[last]) {
            return Some(last);
        }
        let head = self.head;
        // Every entry starts immediately after its predecessor. Compare only
        // the starts, independent of whether an entry owns or borrows data.
        let past = self
            .entries
            .partition_point(|seg| seg.start.wrapping_sub(head) as usize <= offset);
        let idx = past - 1;
        debug_assert!(idx < self.entries.len());
        Some(idx)
    }

    /// Sets `bits` (subset of `FLAG_PUSH | FLAG_EOR`) on byte `offset`,
    /// splitting its `TxSeg` only when `offset` is an interior byte.
    fn set_flags_at(&mut self, pool: &mut TxPool, offset: usize, bits: u8) -> bool {
        if offset >= self.len {
            return false;
        }
        if bits == 0 {
            return true;
        }
        let idx = self.entry_at(offset).unwrap();
        let seg_start = self.seg_start(&self.entries[idx]);
        let seg_len = self.entries[idx].len();
        let seg_end = seg_start + seg_len;
        if offset + 1 == seg_end {
            self.entries[idx].flags |= bits;
            return true;
        }
        let left_len = offset + 1 - seg_start;
        let right_len = seg_len - left_len;
        let left_contig = self.entries[idx].flags & FLAG_CONTIGUOUS_SHARED;
        let old_marks = self.entries[idx].flags & FLAG_MARK_MASK;
        let right_start = self.entries[idx].start.wrapping_add(left_len as u32);
        let mut right_flags = old_marks;
        let right_data = match &mut self.entries[idx].data {
            TxSegData::Chunk {
                chunk,
                offset: chunk_off,
                len,
            } => {
                let right_off = *chunk_off + left_len as u32;
                *len = left_len as u32;
                TxSegData::Chunk {
                    chunk: pool.dup(chunk),
                    offset: right_off,
                    len: right_len as u32,
                }
            }
            TxSegData::Shared(payload) => {
                let right = payload.slice(left_len..seg_len).unwrap();
                *payload = payload.slice(0..left_len).unwrap();
                self.shared_entries += 1;
                right_flags |= FLAG_CONTIGUOUS_SHARED;
                TxSegData::Shared(right)
            }
            TxSegData::Released(len) => {
                *len = left_len as u32;
                TxSegData::Released(right_len as u32)
            }
        };
        self.entries[idx].flags = left_contig | bits;
        self.entries.insert(
            idx + 1,
            TxSeg {
                start: right_start,
                data: right_data,
                flags: right_flags,
            },
        );
        true
    }

    /// Try to coalesce `entries[idx]` (which must have no PUSH/EOR flags) with
    /// `entries[idx + 1]` when both reference contiguous storage.
    fn try_coalesce_with_next(&mut self, pool: &mut TxPool, idx: usize) -> bool {
        if idx + 1 >= self.entries.len() || (self.entries[idx].flags & FLAG_MARK_MASK) != 0 {
            return false;
        }
        let can_merge = match (&self.entries[idx].data, &self.entries[idx + 1].data) {
            (
                TxSegData::Chunk {
                    chunk: c1,
                    offset: o1,
                    len: l1,
                },
                TxSegData::Chunk {
                    chunk: c2,
                    offset: o2,
                    ..
                },
            ) => pool.same_chunk(c1, c2) && *o1 + *l1 == *o2,
            (TxSegData::Shared(p1), TxSegData::Shared(p2)) => p1.join(p2).is_some(),
            (TxSegData::Released(_), TxSegData::Released(_)) => true,
            _ => false,
        };
        if !can_merge {
            return false;
        }
        let next = self.entries.remove(idx + 1).unwrap();
        let cur = &mut self.entries[idx];
        let left_contig = cur.flags & FLAG_CONTIGUOUS_SHARED;
        let next_contig = next.flags & FLAG_CONTIGUOUS_SHARED;
        cur.flags = left_contig | (next.flags & FLAG_MARK_MASK);
        match (&mut cur.data, next.data) {
            (
                TxSegData::Chunk { len: l1, .. },
                TxSegData::Chunk {
                    chunk: c2,
                    len: l2,
                    ..
                },
            ) => {
                *l1 += l2;
                pool.release(c2);
            }
            (TxSegData::Shared(p1), TxSegData::Shared(p2)) => {
                *p1 = p1.join(&p2).unwrap();
                self.shared_entries -= 1;
                if next_contig == 0 {
                    self.shared_spans -= 1;
                }
            }
            (TxSegData::Released(l1), TxSegData::Released(l2)) => {
                *l1 += l2;
            }
            _ => unreachable!(),
        }
        true
    }

    pub(crate) fn mark_push(&mut self) {
        if let Some(back) = self.entries.back_mut() {
            back.flags |= FLAG_PUSH;
            self.note_push(self.len - 1);
        }
    }

    // Offset of the last queued byte carrying PUSH.
    #[inline]
    fn push_offset(&self) -> Option<usize> {
        self.push_end.checked_sub(1)
    }

    #[inline]
    pub(crate) fn push_after(&self, offset: usize) -> bool {
        self.push_end > offset
    }

    // Records a PUSH mark at `offset`, where none is past the last one.
    fn note_push(&mut self, offset: usize) {
        match self.push_offset() {
            Some(last) if offset < last => {
                self.single_push_len = self.single_push_len.min(last - offset);
            }
            Some(last) if offset == last => {}
            previous => {
                self.single_push_len = previous.map_or(offset + 1, |last| offset - last);
                self.push_end = offset + 1;
            }
        }
    }

    fn find_last_flag(&self, flag: u8) -> usize {
        for seg in self.entries.iter().rev() {
            if seg.flags & flag != 0 {
                return self.seg_start(seg) + seg.len();
            }
        }
        0
    }

    // Finds the last PUSH mark again after marks at or past it went away.
    fn find_last_push(&mut self) {
        self.push_end = self.find_last_flag(FLAG_PUSH);
        self.single_push_len = 1;
    }

    // Whether a byte of the range carries PUSH (D5 entry walk fallback).
    #[inline]
    pub(crate) fn pushed(&self, offset: usize, count: usize) -> bool {
        let Some(last) = self.push_offset() else {
            return false;
        };
        if last < offset {
            return false;
        }
        let distance = last - offset;
        if distance < count {
            return true;
        }
        if distance < self.single_push_len {
            return false;
        }
        self.pushed_slow(offset, count)
    }

    #[cold]
    #[inline(never)]
    fn pushed_slow(&self, offset: usize, count: usize) -> bool {
        let range_end = offset.saturating_add(count).min(self.len);
        if offset >= range_end {
            return false;
        }
        let Some(mut idx) = self.entry_at(offset) else {
            return false;
        };
        while idx < self.entries.len() {
            let seg = &self.entries[idx];
            let seg_end = self.seg_start(seg) + seg.len();
            if seg_end > range_end {
                return false;
            }
            if seg.flags & FLAG_PUSH != 0 {
                return true;
            }
            idx += 1;
        }
        false
    }

    // Index of the first of `segments` consecutive `size`-byte ranges from
    // `offset` holding a PUSH mark (D5 entry walk fallback).
    pub(crate) fn first_pushed_segment(
        &self,
        offset: usize,
        size: usize,
        segments: usize,
    ) -> Option<usize> {
        let last = self.push_offset().filter(|&last| last >= offset)?;
        let distance = last - offset;
        let holding_last = distance / size;
        if distance < self.single_push_len {
            return (holding_last < segments).then_some(holding_last);
        }
        let scan_len = holding_last.min(segments).saturating_mul(size);
        let scan_end = offset.saturating_add(scan_len).min(self.len);
        if offset < scan_end
            && let Some(mut idx) = self.entry_at(offset)
        {
            while idx < self.entries.len() {
                let seg = &self.entries[idx];
                let seg_end = self.seg_start(seg) + seg.len();
                if seg_end > scan_end {
                    break;
                }
                if seg.flags & FLAG_PUSH != 0 {
                    return Some((seg_end - 1 - offset) / size);
                }
                idx += 1;
            }
        }
        (holding_last < segments).then_some(holding_last)
    }

    // Only the last byte of this nonempty range carries PUSH. Selecting
    // it leaves its persisted retransmission boundary unchanged.
    #[inline]
    pub(crate) fn push_at_end(&self, offset: usize, count: usize) -> bool {
        count != 0
            && offset.checked_add(count) == Some(self.push_end)
            && count <= self.single_push_len
    }

    pub(crate) fn collapse_push(&mut self, pool: &mut TxPool, offset: usize, count: usize) {
        if count == 0 || self.push_at_end(offset, count) {
            return;
        }
        let range_end = offset.saturating_add(count).min(self.len);
        let mut cleared_last = false;
        if offset < range_end
            && let Some(mut idx) = self.entry_at(offset)
        {
            while idx < self.entries.len() {
                let seg_end = self.seg_start(&self.entries[idx]) + self.entries[idx].len();
                if seg_end > range_end {
                    break;
                }
                if self.entries[idx].flags & FLAG_PUSH != 0 {
                    if Some(seg_end - 1) == self.push_offset() {
                        cleared_last = true;
                    }
                    self.entries[idx].flags &= !FLAG_PUSH;
                    if (self.entries[idx].flags & FLAG_MARK_MASK) == 0
                        && self.try_coalesce_with_next(pool, idx)
                    {
                        // Re-inspect merged entry at `idx` (its new end may still be <= range_end).
                        continue;
                    }
                }
                idx += 1;
            }
        }
        let end = offset + count - 1;
        if self.set_flags_at(pool, end, FLAG_PUSH) {
            self.note_push(end);
        } else if cleared_last {
            self.find_last_push();
        }
    }

    pub(crate) fn finish_send(
        &mut self,
        pool: &mut TxPool,
        offset: usize,
        push: bool,
        end_of_record: bool,
    ) {
        let bits = u8::from(push) | (u8::from(end_of_record) << 1);
        if self.set_flags_at(pool, offset, bits) {
            if push {
                self.note_push(offset);
            }
            if end_of_record {
                self.note_end_of_record(offset);
            }
        }
    }

    // A nonempty append puts its last byte strictly past all old marks.
    #[inline]
    pub(crate) fn finish_append(&mut self, push: bool, end_of_record: bool) {
        if push || end_of_record {
            let end = self.len;
            let back = self
                .entries
                .back_mut()
                .expect("finish_append requires a nonempty buffer");
            back.flags |= u8::from(push) | (u8::from(end_of_record) << 1);
            if push {
                debug_assert!(end > self.push_end);
                self.single_push_len = end - self.push_end;
                self.push_end = end;
            }
            if end_of_record {
                self.eor_end = end;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn mark_end_of_record(&mut self) {
        if let Some(back) = self.entries.back_mut() {
            back.flags |= FLAG_EOR;
            self.eor_end = self.len;
        }
    }

    // Records an EOR mark at `offset`, where none is past the last one.
    fn note_end_of_record(&mut self, offset: usize) {
        if self.eor_end <= offset {
            self.eor_end = offset + 1;
        }
    }

    // Whether the last queued byte carries EOR: the queue's tail ends a
    // record, and nothing written later joins it.
    pub(crate) fn ends_record(&self) -> bool {
        self.len != 0 && self.record_ends_after(self.len - 1)
    }

    // Whether a byte at or past `offset` carries EOR.
    #[inline]
    fn record_ends_after(&self, offset: usize) -> bool {
        self.eor_end > offset
    }

    // EOR is a local coalescing boundary, not a TCP wire flag or framing
    // guarantee (RFC 9293 section 3.7.1). PUSH may collapse; EOR never does.
    #[inline]
    pub(crate) fn record_len(&self, offset: usize, limit: usize) -> usize {
        self.record_len_within(offset, limit.min(self.len.saturating_sub(offset)))
    }

    // The selector already bounded this range by its unsent bytes.
    #[inline]
    pub(crate) fn record_len_within(&self, offset: usize, limit: usize) -> usize {
        debug_assert!(limit <= self.len.saturating_sub(offset));
        if !self.record_ends_after(offset) || limit == 0 {
            return limit;
        }
        self.record_len_eor(offset, limit)
    }

    #[cold]
    #[inline(never)]
    fn record_len_eor(&self, offset: usize, limit: usize) -> usize {
        let range_end = offset + limit;
        let Some(mut idx) = self.entry_at(offset) else {
            return limit;
        };
        while idx < self.entries.len() {
            let seg = &self.entries[idx];
            let seg_end = self.seg_start(seg) + seg.len();
            if seg_end > range_end {
                break;
            }
            if seg.flags & FLAG_EOR != 0 {
                return seg_end - offset;
            }
            idx += 1;
        }
        limit
    }

    // A tail rescue must contain the highest selected byte. Start after the
    // last intervening EOR, rather than clipping a prefix and losing the tail.
    pub(crate) fn tail_record_offset(&self, offset: usize, count: usize) -> usize {
        let count = count.min(self.len.saturating_sub(offset));
        if count <= 1 || !self.record_ends_after(offset) {
            return offset;
        }
        let search_end = offset + count - 1;
        let Some(mut idx) = self.entry_at(search_end - 1) else {
            return offset;
        };
        loop {
            let seg = &self.entries[idx];
            let seg_end = self.seg_start(seg) + seg.len();
            if seg_end <= offset {
                break;
            }
            if seg_end <= search_end && seg.flags & FLAG_EOR != 0 {
                return seg_end;
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
        offset
    }

    // Mark eligible bytes (never retransmitted, not already pending) of one
    // range as PTB repair work; returns how many became pending.
    pub(crate) fn mark_ptb(&mut self, offset: usize, count: usize) -> usize {
        if count == 0 || offset >= self.len {
            return 0;
        }
        self.has_ptb = true;
        self.ptb.mark_ptb(offset, count, self.len)
    }

    // Delivery or abandonment of one range: withdraw its PTB work and its
    // outstanding PTB copies. Returns (pending, copies) cleared.
    pub(crate) fn release_ptb(&mut self, offset: usize, count: usize) -> (usize, usize) {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return (0, 0);
        }
        self.ptb.release_ptb(offset, count, self.len)
    }

    // Mark an outstanding PTB copy on one range; returns how many bytes were
    // newly marked.
    pub(crate) fn mark_ptb_copy(&mut self, offset: usize, count: usize) -> usize {
        if count == 0 || offset >= self.len {
            return 0;
        }
        self.has_ptb = true;
        self.ptb.mark_ptb_copy(offset, count, self.len)
    }

    // HighRxt moved over one range: SetPipe's retransmission term now counts
    // its outstanding PTB copies. Returns how many marks were cleared.
    pub(crate) fn clear_ptb_copy(&mut self, offset: usize, count: usize) -> usize {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return 0;
        }
        self.ptb.clear_ptb_copy(offset, count, self.len)
    }

    // Record a (possibly) submitted retransmitted copy: those bytes lose any
    // PTB work and never become eligible again. Returns the pending bytes it
    // withdrew.
    pub(crate) fn mark_retransmitted(&mut self, offset: usize, count: usize) -> usize {
        if count == 0 || offset >= self.len {
            return 0;
        }
        self.has_ptb = true;
        self.ptb.mark_retransmitted(offset, count, self.len)
    }

    // First contiguous run of PTB work in [offset, end): (offset, length),
    // its length counted to at most `limit`.
    pub(crate) fn next_ptb(
        &self,
        offset: usize,
        end: usize,
        limit: usize,
    ) -> Option<(usize, usize)> {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return None;
        }
        self.ptb.next_ptb(offset, end, limit, self.len)
    }

    // First contiguous run of outstanding PTB copies in [offset, end).
    pub(crate) fn next_ptb_copy(&self, offset: usize, end: usize) -> Option<(usize, usize)> {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return None;
        }
        self.ptb.next_ptb_copy(offset, end, self.len)
    }

    // Bytes of one range that carry PTB work.
    pub(crate) fn count_ptb(&self, offset: usize, count: usize) -> usize {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return 0;
        }
        self.ptb.count_ptb(offset, count, self.len)
    }

    #[cfg(test)]
    pub(crate) fn ptb_pending(&self, offset: usize) -> bool {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return false;
        }
        self.ptb.ptb_pending(offset, self.len)
    }

    #[cfg(test)]
    pub(crate) fn ptb_copy(&self, offset: usize) -> bool {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return false;
        }
        self.ptb.ptb_copy(offset, self.len)
    }

    #[cfg(test)]
    pub(crate) fn retransmitted(&self, offset: usize) -> bool {
        if !self.has_ptb {
            debug_assert_eq!(self.ptb, PtbMarks::default());
            return false;
        }
        self.ptb.retransmitted(offset, self.len)
    }

    pub(crate) fn truncate(&mut self, pool: &mut TxPool, len: usize) {
        if len >= self.len {
            return;
        }
        if len == 0 {
            self.clear_chunks(pool);
            return;
        }
        let mut drop_bytes = self.len - len;
        while drop_bytes > 0 {
            let back_len = self.entries.back().unwrap().len();
            if drop_bytes >= back_len {
                let seg = self.entries.pop_back().unwrap();
                match seg.data {
                    TxSegData::Chunk { chunk, len: n, .. } => {
                        self.chunk_bytes -= n as usize;
                        pool.release(chunk);
                    }
                    TxSegData::Shared(_) => {
                        self.shared_entries -= 1;
                        if seg.flags & FLAG_CONTIGUOUS_SHARED == 0 {
                            self.shared_spans -= 1;
                        }
                    }
                    TxSegData::Released(_) => {}
                }
                drop_bytes -= back_len;
            } else {
                let back = self.entries.back_mut().unwrap();
                let keep = back_len - drop_bytes;
                // Truncating drops the entry's old last byte and any PUSH/EOR
                // flags on it while preserving its contiguity with the entry
                // before it.
                back.flags &= !FLAG_MARK_MASK;
                match &mut back.data {
                    TxSegData::Chunk { len: n, .. } => {
                        self.chunk_bytes -= drop_bytes;
                        *n = keep as u32;
                    }
                    TxSegData::Shared(payload) => {
                        *payload = payload.slice(0..keep).unwrap();
                    }
                    TxSegData::Released(n) => {
                        *n = keep as u32;
                    }
                }
                drop_bytes = 0;
            }
        }
        self.len = len;
        if self.has_ptb {
            self.ptb.truncate(len);
        }
        if self.push_end > len {
            self.find_last_push();
        }
        if self.eor_end > len {
            self.eor_end = self.find_last_flag(FLAG_EOR);
        }
    }

    // Storage only: the caller validates SEG.ACK and converts its advance into a data-byte
    // count.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    #[inline]
    pub(crate) fn acknowledge(&mut self, pool: &mut TxPool, count: usize) -> Result<(), ()> {
        if count > self.len {
            return Err(());
        }
        if count == 0 {
            return Ok(());
        }
        if count == self.len {
            if self.entries.len() == 1 && self.shared_entries == 0 && !self.has_ptb {
                let seg = self.entries.pop_front().unwrap();
                match seg.data {
                    TxSegData::Chunk { chunk, .. } => pool.release(chunk),
                    TxSegData::Shared(payload) => drop_payload_cold(payload),
                    TxSegData::Released(_) => {}
                }
                debug_assert_eq!(self.ptb, PtbMarks::default());
                self.len = 0;
                self.chunk_bytes = 0;
                self.push_end = 0;
                self.single_push_len = 0;
                self.eor_end = 0;
            } else {
                self.clear_chunks_slow(pool);
            }
            self.head = self.head.wrapping_add(count as u32);
            return Ok(());
        }
        self.acknowledge_partial(pool, count);
        Ok(())
    }

    fn acknowledge_partial(&mut self, pool: &mut TxPool, count: usize) {
        let mut rem = count;
        while rem > 0 {
            let front_len = self.entries.front().unwrap().len();
            if rem >= front_len {
                let seg = self.entries.pop_front().unwrap();
                match seg.data {
                    TxSegData::Chunk { chunk, len: n, .. } => {
                        self.chunk_bytes -= n as usize;
                        pool.release(chunk);
                    }
                    TxSegData::Shared(_) => {
                        self.shared_entries -= 1;
                        if seg.flags & FLAG_CONTIGUOUS_SHARED == 0 {
                            self.shared_spans -= 1;
                        }
                    }
                    TxSegData::Released(_) => {}
                }
                rem -= front_len;
            } else {
                let front = self.entries.front_mut().unwrap();
                front.start = front.start.wrapping_add(rem as u32);
                match &mut front.data {
                    TxSegData::Chunk { offset, len: n, .. } => {
                        *offset += rem as u32;
                        *n -= rem as u32;
                        self.chunk_bytes -= rem;
                    }
                    TxSegData::Shared(payload) => {
                        *payload = payload.slice(rem..payload.len()).unwrap();
                    }
                    TxSegData::Released(n) => {
                        *n -= rem as u32;
                    }
                }
                rem = 0;
            }
        }
        if self.shared_entries != 0
            && let Some(front) = self.entries.front_mut()
            && front.flags & FLAG_CONTIGUOUS_SHARED != 0
        {
            front.flags &= !FLAG_CONTIGUOUS_SHARED;
            self.shared_spans += 1;
        }
        self.len -= count;
        self.head = self.head.wrapping_add(count as u32);
        if self.has_ptb {
            self.ptb.drop_prefix(count);
        }
        self.push_end = self.push_end.saturating_sub(count);
        self.eor_end = self.eor_end.saturating_sub(count);
    }

    // Borrow a scalar payload directly when the selected bytes all come
    // from one chunk entry and no shared payloads are queued.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn contiguous<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        limit: usize,
    ) -> Option<&'a [u8]> {
        self.selected_slice(arena, offset, self.record_len(offset, limit))
    }

    // The caller has already clipped these bytes to the record boundary.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn selected_slice<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        count: usize,
    ) -> Option<&'a [u8]> {
        debug_assert_eq!(self.record_len(offset, count), count);
        if self.shared_entries != 0 {
            return None;
        }
        if count == 0 {
            return (offset <= self.len).then_some(&[][..]);
        }
        let idx = self.entry_at(offset)?;
        let seg = &self.entries[idx];
        let rel = offset - self.seg_start(seg);
        match &seg.data {
            TxSegData::Chunk {
                chunk,
                offset: chunk_off,
                len,
            } => {
                if rel.checked_add(count)? > *len as usize {
                    return None;
                }
                let start = *chunk_off as usize + rel;
                Some(arena.get(chunk).bytes(start..start + count))
            }
            TxSegData::Shared(_) | TxSegData::Released(_) => None,
        }
    }

    /// Length of the next output span at `offset` bounded by `limit`,
    /// respecting record boundaries and shared-output segmentation.
    #[inline]
    pub(crate) fn plan_len(&self, offset: usize, limit: usize) -> usize {
        self.selection_len(offset, self.record_len(offset, limit))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn copy(&self, arena: &ChunkArena, offset: usize, out: &mut [u8]) -> usize {
        let count = self.plan_len(offset, out.len());
        if count == 0 {
            return 0;
        }
        if self.shared_output.is_some() && self.shared_prefix(offset, count, usize::MAX) == count {
            return count;
        }
        let Some(mut idx) = self.entry_at(offset) else {
            return 0;
        };
        let mut at = offset;
        let mut written = 0;
        while written < count {
            let seg = &self.entries[idx];
            let rel = at - self.seg_start(seg);
            let take = (seg.len() - rel).min(count - written);
            match &seg.data {
                TxSegData::Chunk {
                    chunk,
                    offset: chunk_off,
                    ..
                } => {
                    let start = *chunk_off as usize + rel;
                    out[written..written + take]
                        .copy_from_slice(arena.get(chunk).bytes(start..start + take));
                }
                TxSegData::Shared(payload) => {
                    out[written..written + take]
                        .copy_from_slice(&payload.as_slice()[rel..rel + take]);
                }
                TxSegData::Released(_) => {
                    debug_assert!(false, "copy from released shared segment");
                    out[written..written + take].fill(0);
                }
            }
            at += take;
            written += take;
            idx += 1;
        }
        count
    }

    /// Borrow a range in the front chunk without building a scatter list.
    /// Other ranges use the indexed walk in `tx_parts`.
    #[inline]
    pub(crate) fn front_tx_part<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        count: usize,
    ) -> Option<TxPart<'a>> {
        let front = self.entries.front()?;
        let TxSegData::Chunk { chunk, offset: start, len } = &front.data else {
            return None;
        };
        if offset.checked_add(count)? > *len as usize {
            return None;
        }
        let start = *start as usize + offset;
        ChunkSlice::new(arena.get(chunk), start..start + count).map(TxPart::Chunk)
    }

    /// Borrow a contiguous byte slice covering `[offset, offset + count)` when
    /// all requested bytes lie inside one `TxSeg` (used by TCP header checksum
    /// and gather encoding without constructing `ChunkSlice` or `TxPartsBuf`).
    #[inline(always)]
    pub(crate) fn single_tx_slice<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        count: usize,
    ) -> Option<&'a [u8]> {
        if count == 0 {
            return None;
        }
        let front = self.entries.front()?;
        if let TxSegData::Chunk {
            chunk,
            offset: chunk_off,
            len,
        } = &front.data
            && offset
                .checked_add(count)
                .is_some_and(|end| end <= *len as usize)
        {
            let start = *chunk_off as usize + offset;
            return Some(arena.get(chunk).bytes(start..start + count));
        }
        self.single_tx_slice_slow(arena, offset, count)
    }

    #[inline(never)]
    fn single_tx_slice_slow<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        count: usize,
    ) -> Option<&'a [u8]> {
        let idx = self.entry_at(offset)?;
        let seg = &self.entries[idx];
        let rel = offset - self.seg_start(seg);
        if rel.checked_add(count)? > seg.len() {
            return None;
        }
        match &seg.data {
            TxSegData::Chunk {
                chunk,
                offset: chunk_off,
                ..
            } => {
                let start = *chunk_off as usize + rel;
                Some(arena.get(chunk).bytes(start..start + count))
            }
            TxSegData::Shared(payload) => Some(&payload.as_slice()[rel..rel + count]),
            TxSegData::Released(_) => None,
        }
    }

    /// Borrow covering `TxPart` slices for `[offset, offset + count)` directly
    /// from the queue's chunks and shared payloads (zero copy), merging
    /// adjacent contiguous slices from the same `TxChunk`.
    pub(crate) fn tx_parts<'a>(
        &'a self,
        arena: &'a ChunkArena,
        offset: usize,
        count: usize,
        out: &mut TxPartsBuf<'a>,
    ) -> usize {
        let count = count.min(self.len.saturating_sub(offset));
        if count == 0 {
            return 0;
        }
        let Some(first) = self.entry_at(offset) else {
            return 0;
        };
        let mut relative = offset - self.seg_start(&self.entries[first]);
        let mut covered = 0;
        for seg in self.entries.range(first..) {
            let take = (seg.len() - relative).min(count - covered);
            match &seg.data {
                TxSegData::Chunk { chunk, offset, .. } => {
                    let start = *offset as usize + relative;
                    let slice = ChunkSlice::new(arena.get(chunk), start..start + take)
                        .expect("chunk slice within filled prefix");
                    out.push_merged(TxPart::Chunk(slice));
                }
                TxSegData::Shared(payload) => {
                    let slice = PayloadSlice::new(payload, relative..relative + take)
                        .expect("payload slice within bounds");
                    out.push(TxPart::Shared(slice));
                }
                TxSegData::Released(_) => {
                    debug_assert!(false, "tx_parts from released shared segment");
                    break;
                }
            }
            covered += take;
            if covered == count {
                break;
            }
            relative = 0;
        }
        covered
    }

    /// Clone/dup owning `OwnedTxPart` references covering `[offset, offset + count)`,
    /// merging adjacent contiguous ranges of the same `TxChunk` before dup'ing.
    pub(crate) fn dup_tx_parts(
        &self,
        pool: &mut TxPool,
        offset: usize,
        count: usize,
        out: &mut Vec<OwnedTxPart>,
    ) -> usize {
        let count = count.min(self.len.saturating_sub(offset));
        if count == 0 {
            return 0;
        }
        let Some(mut idx) = self.entry_at(offset) else {
            return 0;
        };
        let mut at = offset;
        let mut covered = 0;
        while covered < count {
            let seg = &self.entries[idx];
            let rel = at - self.seg_start(seg);
            let take = (seg.len() - rel).min(count - covered);
            match &seg.data {
                TxSegData::Chunk {
                    chunk,
                    offset: chunk_off,
                    ..
                } => {
                    let start = *chunk_off + rel as u32;
                    let len = take as u32;
                    if let Some(OwnedTxPart::Chunk {
                        chunk: prev_chunk,
                        offset: prev_off,
                        len: prev_len,
                    }) = out.last_mut()
                        && pool.same_chunk(prev_chunk, chunk)
                        && *prev_off + *prev_len == start
                    {
                        *prev_len += len;
                    } else {
                        out.push(OwnedTxPart::Chunk {
                            chunk: pool.dup(chunk),
                            offset: start,
                            len,
                        });
                    }
                }
                TxSegData::Shared(payload) => {
                    let sliced = payload.slice(rel..rel + take).unwrap();
                    if let Some(OwnedTxPart::Shared(prev)) = out.last_mut()
                        && let Some(joined) = prev.join(&sliced)
                    {
                        *prev = joined;
                    } else {
                        out.push(OwnedTxPart::Shared(sliced));
                    }
                }
                TxSegData::Released(_) => {
                    debug_assert!(false, "dup_tx_parts from released shared segment");
                    break;
                }
            }
            at += take;
            covered += take;
            idx += 1;
        }
        covered
    }

    #[cfg(test)]
    pub(crate) fn shared_spans(&self) -> usize {
        self.shared_spans
    }

    // Whether `payload` continues the back entry in the same storage and lease
    // (regardless of any PUSH/EOR mark on the back entry's last byte).
    fn continues_shared(&self, payload: &Payload) -> bool {
        matches!(
            self.entries.back(),
            Some(TxSeg {
                data: TxSegData::Shared(existing),
                ..
            }) if existing.join(payload).is_some()
        )
    }

    // Whether `payload` fits beside at most `max_spans` discontiguous shared
    // spans: it continues the last span or fewer than `max_spans` spans are held.
    pub(crate) fn shared_room(&self, payload: &Payload, max_spans: usize) -> bool {
        self.shared_spans < max_spans || self.continues_shared(payload)
    }

    // Number of new `TxSeg` entries a shared write of `payload` will add (0 if
    // it merges into the back entry in place, 1 otherwise).
    pub(crate) fn needed_entries_for_shared(&self, payload: &Payload) -> usize {
        if payload.is_empty() || self.joined_shared(payload).is_some() {
            0
        } else {
            1
        }
    }

    // The last entry extended by `payload` in place when it has no PUSH/EOR
    // marks and `payload` continues it in the same storage and lease.
    fn joined_shared(&self, payload: &Payload) -> Option<Payload> {
        let back = self.entries.back()?;
        if (back.flags & FLAG_MARK_MASK) != 0 {
            return None;
        }
        match &back.data {
            TxSegData::Shared(existing) => existing.join(payload),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn prepare_shared(&mut self, payload: &Payload, peak_room: usize) -> Result<(), ()> {
        let needed = self.needed_entries_for_shared(payload);
        let cost = self.entry_growth_bytes(needed).ok_or(())?;
        if cost > peak_room {
            return Err(());
        }
        self.reserve_entries(needed)
    }

    pub(crate) fn write_shared(&mut self, payload: Payload) -> usize {
        let count = payload.len().min(self.remaining());
        if count == 0 {
            return 0;
        }
        let payload = payload.slice(0..count).unwrap();
        if let Some(joined) = self.joined_shared(&payload) {
            self.entries.back_mut().unwrap().data = TxSegData::Shared(joined);
        } else {
            assert!(
                self.entries.len() < self.entries.capacity(),
                "TxSeg entries not reserved before write_shared"
            );
            let contiguous = self.continues_shared(&payload);
            let start = self.head.wrapping_add(self.len as u32);
            self.entries.push_back(TxSeg {
                start,
                data: TxSegData::Shared(payload),
                flags: if contiguous {
                    FLAG_CONTIGUOUS_SHARED
                } else {
                    0
                },
            });
            self.shared_entries += 1;
            if !contiguous {
                self.shared_spans += 1;
            }
        }
        self.len += count;
        count
    }

    pub(crate) fn set_shared_output(&mut self, segments: Option<usize>) {
        self.shared_output = segments;
    }

    fn shared_prefix(&self, offset: usize, count: usize, max_segments: usize) -> usize {
        if self.shared_entries == 0 || count == 0 || max_segments == 0 {
            return 0;
        }
        let Some(mut idx) = self.entry_at(offset) else {
            return 0;
        };
        let mut at = offset;
        let mut used = 0;
        while idx < self.entries.len() && at - offset < count {
            let seg = &self.entries[idx];
            match &seg.data {
                TxSegData::Shared(payload) => {
                    let starts_new = used == 0 || (seg.flags & FLAG_CONTIGUOUS_SHARED) == 0;
                    if starts_new {
                        if used >= max_segments {
                            break;
                        }
                        used += 1;
                    }
                    let end = self.seg_start(seg) + payload.len();
                    let n = (end - at).min(count - (at - offset));
                    at += n;
                    idx += 1;
                }
                _ => break,
            }
        }
        at - offset
    }

    pub(crate) fn selection_len(&self, offset: usize, count: usize) -> usize {
        let Some(max) = self.shared_output else {
            return count;
        };
        if self.shared_entries == 0 || count == 0 {
            return count;
        }
        let shared = self.shared_prefix(offset, count, max);
        if shared != 0 {
            return shared;
        }
        let Some(mut idx) = self.entry_at(offset) else {
            return count;
        };
        let limit = offset.saturating_add(count);
        while idx < self.entries.len() {
            let seg = &self.entries[idx];
            let start = self.seg_start(seg);
            if start >= limit {
                break;
            }
            if matches!(seg.data, TxSegData::Shared(_)) {
                return start - offset;
            }
            idx += 1;
        }
        count
    }

    pub(crate) fn shared_slices(
        &self,
        offset: usize,
        count: usize,
        out: &mut Vec<Payload>,
    ) -> bool {
        if count == 0 || self.shared_prefix(offset, count, out.capacity()) != count {
            return false;
        }
        let Some(mut idx) = self.entry_at(offset) else {
            return false;
        };
        let mut at = offset;
        while at - offset < count {
            let seg = &self.entries[idx];
            let start = self.seg_start(seg);
            let TxSegData::Shared(payload) = &seg.data else {
                unreachable!("shared_prefix already verified covering Shared entries");
            };
            let rel = at - start;
            let n = (payload.len() - rel).min(count - (at - offset));
            let slice = payload.slice(rel..rel + n).unwrap();
            if (seg.flags & FLAG_CONTIGUOUS_SHARED) != 0
                && let Some(last) = out.last_mut()
            {
                *last = last
                    .join(&slice)
                    .expect("contiguous shared entries must join");
            } else {
                out.push(slice);
            }
            at += n;
            idx += 1;
        }
        true
    }

    pub(crate) fn release_shared(&mut self) {
        if self.shared_entries == 0 {
            return;
        }
        for seg in &mut self.entries {
            if let TxSegData::Shared(payload) = &seg.data {
                let len = payload.len() as u32;
                seg.data = TxSegData::Released(len);
                seg.flags &= !FLAG_CONTIGUOUS_SHARED;
            }
        }
        self.shared_entries = 0;
        self.shared_spans = 0;
    }

    #[cfg(test)]
    fn debug_check_invariants(&self) {
        let mut pos = 0usize;
        let mut chunk_sum = 0usize;
        let mut shared_count = 0usize;
        let mut span_count = 0usize;
        for (i, seg) in self.entries.iter().enumerate() {
            assert!(seg.len() > 0, "empty TxSeg");
            assert_eq!(self.seg_start(seg), pos, "non-contiguous TxSeg");
            match &seg.data {
                TxSegData::Chunk { len, .. } => {
                    assert_eq!(seg.flags & FLAG_CONTIGUOUS_SHARED, 0);
                    chunk_sum += *len as usize;
                }
                TxSegData::Shared(cur) => {
                    shared_count += 1;
                    if (seg.flags & FLAG_CONTIGUOUS_SHARED) == 0 {
                        span_count += 1;
                    } else {
                        assert!(i > 0, "front entry cannot be FLAG_CONTIGUOUS_SHARED");
                        match &self.entries[i - 1].data {
                            TxSegData::Shared(prev) => {
                                assert!(
                                    prev.join(cur).is_some(),
                                    "FLAG_CONTIGUOUS_SHARED entry does not join predecessor"
                                );
                            }
                            _ => panic!("FLAG_CONTIGUOUS_SHARED must follow Shared entry"),
                        }
                    }
                }
                TxSegData::Released(_) => {
                    assert_eq!(seg.flags & FLAG_CONTIGUOUS_SHARED, 0);
                }
            }
            pos += seg.len();
        }
        assert_eq!(pos, self.len);
        assert_eq!(chunk_sum, self.chunk_bytes);
        assert_eq!(shared_count, self.shared_entries);
        assert_eq!(span_count, self.shared_spans);
        assert_eq!(self.push_end, self.find_last_flag(FLAG_PUSH));
        assert_eq!(self.eor_end, self.find_last_flag(FLAG_EOR));
    }
}

#[cfg(test)]
#[path = "buffer_receive_reference.rs"]
mod receive_reference;

#[cfg(test)]
#[path = "buffer_receive_differential.rs"]
pub(crate) mod receive_differential;

#[cfg(test)]
mod tests {
    use super::*;

    const PTB_PENDING: u8 = 1 << 2;
    const RETRANSMITTED: u8 = 1 << 3;
    const PTB_COPY: u8 = 1 << 4;

    #[test]
    fn send_shrink_saturates_and_failed_growth_preserves_data() {
        let mut pool = TxPool::heap(16);
        let mut send = SendBuffer::new(8).unwrap();
        send.write(&mut pool, b"abcdef");
        send.mark_push();
        send.set_limit(2);
        assert_eq!(send.remaining(), 0);
        assert_eq!(send.write(&mut pool, b"!"), 0);
        assert!(send.reserve_entries(usize::MAX).is_err());
        send.set_limit(16);
        let mut out = [0; 6];
        assert_eq!(send.copy(pool.arena(), 0, &mut out), 6);
        assert_eq!(&out, b"abcdef");
        assert!(send.pushed(0, 6));
        send.acknowledge(&mut pool, 5).unwrap();
        send.set_limit(2);
        assert_eq!(send.write(&mut pool, b"xy"), 1);
        send.clear_chunks(&mut pool);
    }

    #[test]
    // Checks prefix removal by byte count, not wire ACK validation.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.4
    //= type=test
    //# The acknowledgment mechanism employed is cumulative so that an acknowledgment of
    //# sequence number X indicates that all octets up to but not including X have been
    //# received.
    fn send_retains_partial_copy_and_acknowledges_without_growth() {
        let mut pool = TxPool::heap(16);
        let mut send = SendBuffer::new(4).unwrap();
        assert_eq!(send.capacity(), 4);
        assert_eq!(send.remaining(), 4);
        assert_eq!(send.write(&mut pool, b"abcdef"), 4);
        assert_eq!(send.write(&mut pool, b"x"), 0);
        assert_eq!(send.acknowledge(&mut pool, 5), Err(()));
        let mut out = [b'!'; 6];
        assert_eq!(send.copy(pool.arena(), 1, &mut out), 3);
        assert_eq!(&out, b"bcd!!!");
        assert_eq!(send.copy(pool.arena(), usize::MAX, &mut out), 0);
        assert_eq!(send.len(), 4);
        assert_eq!(send.acknowledge(&mut pool, 2), Ok(()));
        assert_eq!(send.write(&mut pool, b"efg"), 2);
        assert_eq!(send.copy(pool.arena(), 0, &mut out[..4]), 4);
        assert_eq!(&out[..4], b"cdef");
        assert_eq!(send.acknowledge(&mut pool, 4), Ok(()));
        assert_eq!(send.acknowledge(&mut pool, 0), Ok(()));
        assert_eq!(send.remaining(), 4);
        let mut empty = SendBuffer::new(0).unwrap();
        assert_eq!(empty.write(&mut pool, b"a"), 0);
        assert!(SendBuffer::new(usize::MAX).is_err());
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn send_payload_and_marks_match_a_byte_model_across_chunks() {
        let mut pool = TxPool::heap(32);
        let mut send = SendBuffer::new(300).unwrap();
        let mut model: VecDeque<(u8, u8)> = VecDeque::new();
        let mut state = 0x9e37_79b9_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        for step in 0..4000 {
            match next(7) {
                0 | 1 => {
                    let input: Vec<u8> = (0..next(48)).map(|i| (step + i) as u8).collect();
                    let count = send.write(&mut pool, &input);
                    assert_eq!(count, input.len().min(send.capacity() - model.len()));
                    model.extend(input[..count].iter().map(|&b| (b, 0)));
                }
                2 => {
                    send.mark_push();
                    if let Some(last) = model.back_mut() {
                        last.1 |= FLAG_PUSH;
                    }
                }
                3 => {
                    let count = next(model.len() + 1);
                    send.acknowledge(&mut pool, count).unwrap();
                    model.drain(..count);
                }
                4 if !model.is_empty() => {
                    let offset = next(model.len());
                    let count = 1 + next(model.len() - offset);
                    let needed = 1;
                    send.reserve_entries(needed).unwrap();
                    send.collapse_push(&mut pool, offset, count);
                    for entry in model.range_mut(offset..offset + count) {
                        entry.1 &= !FLAG_PUSH;
                    }
                    model[offset + count - 1].1 |= FLAG_PUSH;
                }
                5 => {
                    let len = next(model.len() + 1);
                    send.truncate(&mut pool, len);
                    model.truncate(len);
                }
                _ if !model.is_empty() => {
                    let offset = next(model.len());
                    let (push, end_of_record) = (next(2) == 0, next(3) == 0);
                    send.reserve_entries(1).unwrap();
                    send.finish_send(&mut pool, offset, push, end_of_record);
                    model[offset].1 |= u8::from(push) | (u8::from(end_of_record) << 1);
                }
                _ => {}
            }
            send.debug_check_invariants();
            let offset = next(model.len() + 4);
            let limit = next(64);
            let tail: Vec<(u8, u8)> = model.iter().skip(offset).take(limit).copied().collect();
            let record = tail
                .iter()
                .position(|(_, mark)| mark & FLAG_EOR != 0)
                .map_or(tail.len(), |n| n + 1);
            assert_eq!(send.record_len(offset, limit), record);
            assert_eq!(
                send.tail_record_offset(offset, limit),
                tail.iter()
                    .take(tail.len().saturating_sub(1))
                    .rposition(|(_, mark)| mark & FLAG_EOR != 0)
                    .map_or(offset, |n| offset + n + 1)
            );
            assert_eq!(
                send.pushed(offset, limit),
                tail.iter().any(|(_, mark)| mark & FLAG_PUSH != 0)
            );
            let mut out = [0; 64];
            assert_eq!(send.copy(pool.arena(), offset, &mut out[..limit]), record);
            assert!(
                out[..record]
                    .iter()
                    .copied()
                    .eq(tail[..record].iter().map(|&(byte, _)| byte))
            );
            if let Some(slice) = send.contiguous(pool.arena(), offset, limit) {
                assert_eq!(slice, &out[..record]);
            }
        }
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn first_pushed_segment_matches_segment_scan() {
        let mut pool = TxPool::heap(4096);
        let mut send = SendBuffer::new(20_000).unwrap();
        let mut marks: VecDeque<bool> = VecDeque::new();
        let mut state = 0x51a7_9b23_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };
        for _ in 0..400 {
            match next(5) {
                0..=2 => {
                    let count = send.write(&mut pool, &alloc::vec![0; next(4000)]);
                    marks.extend(core::iter::repeat_n(false, count));
                }
                3 => {
                    let count = next(marks.len() + 1);
                    send.acknowledge(&mut pool, count).unwrap();
                    marks.drain(..count);
                }
                _ => {
                    send.mark_push();
                    if let Some(last) = marks.back_mut() {
                        *last = true;
                    }
                }
            }
            let offset = next(marks.len() + 1);
            let size = 1 + next(1500);
            let segments = next(16);
            let expected = (0..segments).find(|&segment| {
                let start = offset + segment * size;
                let end = (start + size).min(marks.len());
                start < end && marks.range(start..end).any(|&push| push)
            });
            assert_eq!(send.first_pushed_segment(offset, size, segments), expected);
        }
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn eor_boundaries_survive_push_collapse_ack_and_truncation() {
        let mut pool = TxPool::heap(16);
        let mut send = SendBuffer::new(8).unwrap();
        assert_eq!(send.write(&mut pool, b"abc"), 3);
        send.mark_end_of_record();
        send.mark_push();
        send.write(&mut pool, b"defgh");
        send.mark_end_of_record();
        send.collapse_push(&mut pool, 0, 5); // PUSH collapse never moves EOR.
        assert_eq!(send.record_len(0, 8), 3);
        assert_eq!(send.tail_record_offset(0, 8), 3);
        assert_eq!(send.tail_record_offset(0, 3), 0);
        let mut bytes = [0; 8];
        assert_eq!(send.copy(pool.arena(), 0, &mut bytes), 3);
        assert_eq!(&bytes[..3], b"abc");
        send.set_limit(16);
        send.acknowledge(&mut pool, 2).unwrap();
        assert_eq!(send.copy(pool.arena(), 0, &mut bytes), 1);
        assert_eq!(bytes[0], b'c');
        send.acknowledge(&mut pool, 1).unwrap();
        send.truncate(&mut pool, 3); // Discarded EOR cannot affect later writes.
        send.write(&mut pool, b"ij");
        assert_eq!(send.copy(pool.arena(), 0, &mut bytes), 5);
        assert_eq!(&bytes[..5], b"defij");
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn live_entry_offsets_survive_stream_position_wrap() {
        let mut pool = TxPool::heap(64);
        let mut send = SendBuffer::new(64).unwrap();
        send.head = u32::MAX - 4;
        let data = b"abcdefghijklmnopqr";
        for part in [&data[..3], &data[3..7], &data[7..12], &data[12..]] {
            assert_eq!(send.write(&mut pool, part), part.len());
            send.mark_push();
        }
        assert_eq!(send.entry_at(6), Some(1));
        assert_eq!(send.entry_at(8), Some(2));
        send.acknowledge(&mut pool, 5).unwrap();
        assert_eq!(send.entry_at(2), Some(1));
        let mut bytes = [0; 8];
        assert_eq!(send.copy(pool.arena(), 1, &mut bytes), bytes.len());
        assert_eq!(&bytes, &data[6..14]);
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn lowat_byte_admission_preserves_capacity_across_resize_discard_and_ack() {
        let mut pool = TxPool::heap(64);
        for capacity in [0, 1, 6, 16384, 32768, 65536] {
            let mut send = SendBuffer::new(capacity).unwrap();
            let charge = send.storage_bytes();
            assert_eq!(send.admission_room(0, Some(0)), 0);
            assert_eq!(send.admission_room(0, None), capacity);
            assert_eq!(send.admission_room(0, Some(u32::MAX)), capacity);
            send.write(&mut pool, &alloc::vec![1; capacity.min(3)]);
            for notsent in [0, 3, 4, 5, usize::MAX] {
                assert_eq!(
                    send.admission_room(notsent, Some(4)),
                    send.remaining().min(4usize.saturating_sub(notsent))
                );
            }
            assert_eq!(send.storage_bytes(), charge);
            send.clear_chunks(&mut pool);
        }
        let mut send = SendBuffer::new(32).unwrap();
        send.write(&mut pool, &[1; 8]);
        send.mark_end_of_record();
        send.mark_push();
        assert_eq!(send.admission_room(8, Some(10)), 2);
        send.set_limit(64);
        assert_eq!(send.admission_room(8, Some(10)), 2);
        send.truncate(&mut pool, 5);
        assert_eq!(send.admission_room(5, Some(10)), 5);
        send.set_limit(6);
        assert_eq!(send.admission_room(5, Some(10)), 1);
        send.set_limit(4);
        assert_eq!(send.admission_room(5, Some(10)), 0);
        send.acknowledge(&mut pool, 5).unwrap();
        assert_eq!(send.admission_room(0, Some(10)), 4);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn release_and_reuse_preserve_empty_invariants() {
        let mut pool = TxPool::heap(32);
        let mut send = SendBuffer::new(16).unwrap();
        send.write(&mut pool, b"0123456789abcd");
        send.acknowledge(&mut pool, 8).unwrap();
        send.write(&mut pool, b"efghijkl");
        send.mark_push();
        send.finish_send(&mut pool, 2, true, true);
        send.acknowledge(&mut pool, 14).unwrap();
        send.release();
        assert_eq!(send.storage_bytes(), 0);

        send.write(&mut pool, b"xyz");
        send.finish_send(&mut pool, 0, false, true);
        send.mark_push();
        send.acknowledge(&mut pool, 1).unwrap();
        let mut out = [0; 8];
        assert_eq!(send.copy(pool.arena(), 0, &mut out), 2);
        assert_eq!(&out[..2], b"yz");
        send.acknowledge(&mut pool, 2).unwrap();
        send.release();
        assert_eq!(send.storage_bytes(), 0);

        let payload = Payload::from_vec(alloc::vec![9; 5]);
        send.prepare_shared(&payload, usize::MAX).unwrap();
        assert_eq!(send.write_shared(payload.clone()), 5);
        let mut parts = Vec::with_capacity(4);
        assert!(send.shared_slices(0, 5, &mut parts));
        send.acknowledge(&mut pool, 5).unwrap();
        send.release();
        assert_eq!(send.storage_bytes(), 0);

        send.prepare_shared(&payload, usize::MAX).unwrap();
        assert_eq!(send.write_shared(payload), 5);
        assert_eq!(send.copy(pool.arena(), 0, &mut out), 5);
        assert_eq!(&out[..5], &[9; 5]);
        assert!(send.shared_slices(0, 5, &mut Vec::with_capacity(4)));
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn failed_entry_reservation_leaves_queue_unchanged() {
        use crate::allocation_tests::fail_after;
        let mut pool = TxPool::heap(16);
        let mut send = SendBuffer::new(64).unwrap();
        send.write(&mut pool, &[1; 12]);
        send.acknowledge(&mut pool, 8).unwrap();
        send.write(&mut pool, b"abcdefghij");
        send.mark_push();
        let storage = send.storage_bytes();
        // Already fits 1 new entry without allocating.
        assert_eq!(fail_after(0, || send.reserve_entries(1)), Ok(()));
        // Growing past current capacity fails cleanly under fail_after(0).
        assert_eq!(fail_after(0, || send.reserve_entries(64)), Err(()));
        assert_eq!(send.storage_bytes(), storage);
        assert!(fail_after(0, || SendBuffer::new(1).is_err()));
        // Succeeds once allocation is allowed, preserving existing bytes and marks.
        assert_eq!(send.reserve_entries(64), Ok(()));
        assert!(send.storage_bytes() > storage);
        let mut out = [0; 14];
        assert_eq!(send.copy(pool.arena(), 0, &mut out), 14);
        assert_eq!(&out, b"\x01\x01\x01\x01abcdefghij");
        assert!(send.pushed(13, 1) && !send.pushed(0, 13));
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn collapse_push_early_return_and_multi_chunk_contiguous_and_shared() {
        let mut pool = TxPool::heap(16);
        let mut send = SendBuffer::new(32).unwrap();
        // Single PUSH at index 5 -> single_push_len == 6.
        assert_eq!(send.write(&mut pool, b"abcdef"), 6);
        send.mark_push();
        assert_eq!(send.single_push_len, 6);
        send.collapse_push(&mut pool, 0, 6);
        assert!(send.pushed(5, 1) && !send.pushed(0, 5));

        // Adding an earlier PUSH via finish_send narrows single_push_len to 5 - 2 = 3.
        send.finish_send(&mut pool, 2, true, false);
        assert_eq!(send.single_push_len, 3);
        send.collapse_push(&mut pool, 3, 3);
        assert!(send.pushed(2, 1) && send.pushed(5, 1) && !send.pushed(3, 2));
        send.collapse_push(&mut pool, 2, 4);
        assert!(!send.pushed(0, 5) && send.pushed(5, 1));

        // After acknowledge keeping last_push, collapse_push still preserves correctness.
        send.acknowledge(&mut pool, 3).unwrap();
        send.finish_send(&mut pool, 0, true, false);
        send.collapse_push(&mut pool, 1, 2);
        assert!(send.pushed(0, 1) && send.pushed(2, 1));
        send.collapse_push(&mut pool, 0, 3);
        assert!(!send.pushed(0, 2) && send.pushed(2, 1));

        // After truncate drops last_push, find_last_push resets single_push_len = 1.
        send.finish_send(&mut pool, 0, true, false);
        send.truncate(&mut pool, 2);
        assert_eq!(send.single_push_len, 1);
        send.collapse_push(&mut pool, 0, 1);
        assert!(send.pushed(0, 1) && !send.pushed(1, 1));

        send.acknowledge(&mut pool, 2).unwrap();
        send.release();
        pool.release_tail();

        // Span two 16-byte chunks cleanly.
        assert_eq!(send.write(&mut pool, b"0123456789abcdef"), 16);
        assert_eq!(send.write(&mut pool, b"ABCDEFGHIJ"), 10);
        let mut out = [0; 26];
        let first_slice = send.contiguous(pool.arena(), 0, 16).unwrap();
        assert_eq!(first_slice, b"0123456789abcdef");
        let second_slice = send.contiguous(pool.arena(), 16, 10).unwrap();
        assert_eq!(second_slice, b"ABCDEFGHIJ");
        // Spanning chunk boundary returns None, while copy succeeds.
        assert!(send.contiguous(pool.arena(), 15, 2).is_none());
        assert_eq!(send.copy(pool.arena(), 15, &mut out[..2]), 2);
        assert_eq!(&out[..2], b"fA");

        // EOR inside the first chunk limits contiguous to the record end.
        send.finish_send(&mut pool, 0, false, true);
        assert_eq!(send.contiguous(pool.arena(), 0, send.len()), Some(&b"0"[..]));

        // Non-empty shared payloads make contiguous return None.
        send.set_shared_output(Some(4));
        let payload = Payload::from_vec(alloc::vec![b'Z'; 4]);
        send.prepare_shared(&payload, usize::MAX).unwrap();
        assert_eq!(send.write_shared(payload), 4);
        assert!(send.contiguous(pool.arena(), 0, 1).is_none());
        assert!(send.contiguous(pool.arena(), send.len() - 4, 4).is_none());

        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn send_buffer_chunk_shared_and_marks_match_oracle_6000_steps() {
        let mut pool = TxPool::heap(32);
        let mut send = SendBuffer::new(256).unwrap();
        // Oracle stores (byte, mark_bits) per queued byte.
        let mut oracle: VecDeque<(u8, u8)> = VecDeque::new();
        let mut state = 0x7319_a5c1_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound.max(1)
        };

        let shared_backing = Payload::from_vec((0..256u16).map(|i| (i ^ 0x5a) as u8).collect());
        let mut saw_shared = false;
        let mut saw_multi_chunk = false;
        let mut saw_ptb = false;
        let mut saw_tx_parts = false;

        for step in 0..6000 {
            match next(16) {
                0..=2 => {
                    let room = send.remaining();
                    if room != 0 {
                        let len = 1 + next(room.min(48));
                        let input: Vec<u8> = (0..len).map(|i| (step + i) as u8).collect();
                        let needed = send.needed_entries_for_copy(&pool, len);
                        send.reserve_entries(needed).unwrap();
                        let taken = send.append(&mut pool, &input);
                        assert_eq!(taken, len);
                        oracle.extend(input.into_iter().map(|b| (b, 0)));
                        let push = next(3) == 0;
                        let eor = next(4) == 0;
                        send.finish_append(push, eor);
                        if push || eor {
                            oracle.back_mut().unwrap().1 |= u8::from(push) | (u8::from(eor) << 1);
                        }
                        if pool.live() >= 2 {
                            saw_multi_chunk = true;
                        }
                    }
                }
                3 => {
                    // Shared write (sometimes contiguous with previous shared slice).
                    let room = send.remaining();
                    if room != 0 {
                        let start = next(200);
                        let len = 1 + next(room.min(32).min(256 - start));
                        let slice = shared_backing.slice(start..start + len).unwrap();
                        let needed = send.needed_entries_for_shared(&slice);
                        send.reserve_entries(needed).unwrap();
                        let taken = send.write_shared(slice.clone());
                        assert_eq!(taken, len);
                        oracle.extend(slice.as_slice().iter().map(|&b| (b, 0)));
                        let push = next(3) == 0;
                        let eor = next(5) == 0;
                        send.finish_append(push, eor);
                        if push || eor {
                            oracle.back_mut().unwrap().1 |= u8::from(push) | (u8::from(eor) << 1);
                        }
                        saw_shared = true;
                    }
                }
                4 => {
                    send.mark_push();
                    if let Some(last) = oracle.back_mut() {
                        last.1 |= FLAG_PUSH;
                    }
                }
                5 => {
                    send.mark_end_of_record();
                    if let Some(last) = oracle.back_mut() {
                        last.1 |= FLAG_EOR;
                    }
                }
                6 if !oracle.is_empty() => {
                    let offset = next(oracle.len());
                    let count = 1 + next(oracle.len() - offset);
                    send.reserve_entries(1).unwrap();
                    send.collapse_push(&mut pool, offset, count);
                    for entry in oracle.range_mut(offset..offset + count) {
                        entry.1 &= !FLAG_PUSH;
                    }
                    oracle[offset + count - 1].1 |= FLAG_PUSH;
                }
                7 => {
                    let offset = next(oracle.len() + 2);
                    let push = next(2) == 0;
                    let eor = next(3) == 0;
                    send.reserve_entries(1).unwrap();
                    send.finish_send(&mut pool, offset, push, eor);
                    if let Some(entry) = oracle.get_mut(offset) {
                        entry.1 |= u8::from(push) | (u8::from(eor) << 1);
                    }
                }
                8 => {
                    let count = if next(3) == 0 {
                        oracle.len()
                    } else {
                        next(oracle.len() + 1)
                    };
                    send.acknowledge(&mut pool, count).unwrap();
                    oracle.drain(..count);
                }
                9 => {
                    let len = next(oracle.len() + 1);
                    send.truncate(&mut pool, len);
                    oracle.truncate(len);
                }
                10 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let start = offset.min(oracle.len());
                    let end = (start + count).min(oracle.len());
                    let mut expected = 0;
                    for (_, m) in oracle.range_mut(start..end) {
                        if *m & (PTB_PENDING | RETRANSMITTED) == 0 {
                            *m |= PTB_PENDING;
                            expected += 1;
                        }
                    }
                    assert_eq!(send.mark_ptb(offset, count), expected);
                    if expected > 0 {
                        saw_ptb = true;
                    }
                }
                11 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let start = offset.min(oracle.len());
                    let end = (start + count).min(oracle.len());
                    let (mut pending, mut copies) = (0, 0);
                    for (_, m) in oracle.range_mut(start..end) {
                        pending += usize::from(*m & PTB_PENDING != 0);
                        copies += usize::from(*m & PTB_COPY != 0);
                        *m &= !(PTB_PENDING | PTB_COPY);
                    }
                    assert_eq!(send.release_ptb(offset, count), (pending, copies));
                }
                12 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let start = offset.min(oracle.len());
                    let end = (start + count).min(oracle.len());
                    let mut expected = 0;
                    for (_, m) in oracle.range_mut(start..end) {
                        expected += usize::from(*m & PTB_COPY == 0);
                        *m |= PTB_COPY;
                    }
                    assert_eq!(send.mark_ptb_copy(offset, count), expected);
                }
                13 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let start = offset.min(oracle.len());
                    let end = (start + count).min(oracle.len());
                    let mut expected = 0;
                    for (_, m) in oracle.range_mut(start..end) {
                        expected += usize::from(*m & PTB_COPY != 0);
                        *m &= !PTB_COPY;
                    }
                    assert_eq!(send.clear_ptb_copy(offset, count), expected);
                }
                14 => {
                    let offset = next(oracle.len() + 2);
                    let count = next(oracle.len().saturating_sub(offset) + 4);
                    let start = offset.min(oracle.len());
                    let end = (start + count).min(oracle.len());
                    let mut expected = 0;
                    for (_, m) in oracle.range_mut(start..end) {
                        expected += usize::from(*m & PTB_PENDING != 0);
                        *m = (*m & !PTB_PENDING) | RETRANSMITTED;
                    }
                    assert_eq!(send.mark_retransmitted(offset, count), expected);
                }
                _ => {
                    if oracle.is_empty() {
                        send.release();
                        pool.shrink();
                    }
                }
            }

            send.debug_check_invariants();
            assert_eq!(send.len(), oracle.len());

            let offset = next(oracle.len() + 3);
            let count = next(oracle.len() + 5);
            let available = oracle.len().saturating_sub(offset);
            let bounded = count.min(available);
            let tail: Vec<(u8, u8)> = oracle.iter().skip(offset).take(bounded).copied().collect();

            let expected_record = tail
                .iter()
                .position(|&(_, m)| m & FLAG_EOR != 0)
                .map_or(tail.len(), |n| n + 1);
            assert_eq!(send.record_len(offset, count), expected_record);
            assert_eq!(send.record_len_within(offset, bounded), expected_record);
            assert_eq!(
                send.tail_record_offset(offset, count),
                tail.iter()
                    .take(tail.len().saturating_sub(1))
                    .rposition(|&(_, m)| m & FLAG_EOR != 0)
                    .map_or(offset, |n| offset + n + 1)
            );
            assert_eq!(
                send.pushed(offset, count),
                tail.iter().any(|&(_, m)| m & FLAG_PUSH != 0)
            );
            assert_eq!(
                send.push_after(offset),
                oracle.iter().skip(offset).any(|&(_, m)| m & FLAG_PUSH != 0)
            );
            if send.push_at_end(offset, count) {
                assert!(count != 0 && offset + count == send.push_end);
                assert!(oracle[offset + count - 1].1 & FLAG_PUSH != 0);
                assert!(
                    oracle
                        .range(offset..offset + count - 1)
                        .all(|&(_, m)| m & FLAG_PUSH == 0)
                );
            }
            let size = 1 + next(16);
            let segments = next(12);
            let expected_seg = (0..segments).find(|&s| {
                let start = offset + s * size;
                let end = (start + size).min(oracle.len());
                start < end && oracle.range(start..end).any(|&(_, m)| m & FLAG_PUSH != 0)
            });
            assert_eq!(
                send.first_pushed_segment(offset, size, segments),
                expected_seg
            );

            // PTB queries.
            let end = offset + count;
            let limit = 1 + next(16);
            let expected_next_flag = |flag: u8, lim: usize| -> Option<(usize, usize)> {
                let hi = end.min(oracle.len());
                let start = (offset..hi).find(|&i| oracle[i].1 & flag != 0)?;
                let run = (start..hi)
                    .take(lim)
                    .take_while(|&i| oracle[i].1 & flag != 0)
                    .count();
                Some((start, run))
            };
            assert_eq!(
                send.next_ptb(offset, end, limit),
                expected_next_flag(PTB_PENDING, limit)
            );
            assert_eq!(
                send.next_ptb_copy(offset, end),
                expected_next_flag(PTB_COPY, usize::MAX)
            );
            let expected_count_ptb = oracle
                .range(offset.min(oracle.len())..)
                .take(count)
                .filter(|&&(_, m)| m & PTB_PENDING != 0)
                .count();
            assert_eq!(send.count_ptb(offset, count), expected_count_ptb);
            assert_eq!(
                send.ptb_pending(offset),
                oracle.get(offset).is_some_and(|&(_, m)| m & PTB_PENDING != 0)
            );
            assert_eq!(
                send.ptb_copy(offset),
                oracle.get(offset).is_some_and(|&(_, m)| m & PTB_COPY != 0)
            );
            assert_eq!(
                send.retransmitted(offset),
                oracle
                    .get(offset)
                    .is_some_and(|&(_, m)| m & RETRANSMITTED != 0)
            );

            // Verify copy, selected_slice, contiguous, and tx_parts byte-for-byte.
            let mut out = alloc::vec![0u8; bounded];
            let copied = send.copy(pool.arena(), offset, &mut out);
            assert_eq!(copied, expected_record);
            assert!(
                out[..copied]
                    .iter()
                    .copied()
                    .eq(tail[..copied].iter().map(|&(b, _)| b))
            );
            assert_eq!(
                send.selected_slice(pool.arena(), offset, expected_record),
                send.contiguous(pool.arena(), offset, count)
            );
            if let Some(slice) = send.selected_slice(pool.arena(), offset, expected_record) {
                assert_eq!(slice, &out[..copied]);
            }
            let mut parts = TxPartsBuf::new();
            let covered = send.tx_parts(pool.arena(), offset, expected_record, &mut parts);
            assert_eq!(covered, expected_record);
            assert_eq!(send.plan_len(offset, bounded), expected_record);
            let mut flattened = Vec::with_capacity(covered);
            for part in parts.as_slice() {
                flattened.extend_from_slice(part.bytes());
            }
            assert_eq!(flattened, &out[..copied]);
            if !parts.is_empty() {
                saw_tx_parts = true;
            }
            let mut owned = Vec::new();
            let owned_covered = send.dup_tx_parts(&mut pool, offset, expected_record, &mut owned);
            assert_eq!(owned_covered, expected_record);
            let mut owned_bytes = Vec::with_capacity(owned_covered);
            for part in owned.drain(..) {
                match part {
                    OwnedTxPart::Chunk {
                        chunk,
                        offset: c_off,
                        len,
                    } => {
                        owned_bytes.extend_from_slice(
                            pool.arena()
                                .get(&chunk)
                                .bytes(c_off as usize..(c_off + len) as usize),
                        );
                        pool.release(chunk);
                    }
                    OwnedTxPart::Shared(p) => owned_bytes.extend_from_slice(p.as_slice()),
                }
            }
            assert_eq!(owned_bytes, &out[..copied]);
        }

        assert!(saw_shared);
        assert!(saw_multi_chunk);
        assert!(saw_ptb);
        assert!(saw_tx_parts);
        send.clear_chunks(&mut pool);
        pool.release_tail();
        assert_eq!(pool.live(), 0);
    }
}
